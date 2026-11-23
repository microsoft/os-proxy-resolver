/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Runtime-loaded GIO access for the Linux proxy configuration.

use libloading::Library;
use std::ffi::{c_char, c_int, c_uint, c_ulong, c_void, CStr};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};

const PROXY_SCHEMA: &[u8] = b"org.gnome.system.proxy\0";
const HTTP_CHILD: &[u8] = b"http\0";
const HTTPS_CHILD: &[u8] = b"https\0";
const SOCKS_CHILD: &[u8] = b"socks\0";
const CHANGED_SIGNAL: &[u8] = b"changed\0";
const MODE_KEY: &[u8] = b"mode\0";
const AUTOCONFIG_URL_KEY: &[u8] = b"autoconfig-url\0";
const IGNORE_HOSTS_KEY: &[u8] = b"ignore-hosts\0";
const HOST_KEY: &[u8] = b"host\0";
const PORT_KEY: &[u8] = b"port\0";

#[repr(C)]
struct GMainContext {
    _private: [u8; 0],
}

#[repr(C)]
struct GSettings {
    _private: [u8; 0],
}

#[repr(C)]
struct GSettingsSchema {
    _private: [u8; 0],
}

#[repr(C)]
struct GSettingsSchemaSource {
    _private: [u8; 0],
}

type SettingsChangedCallback = unsafe extern "C" fn(*mut GSettings, *mut c_char, *mut c_void);
type ClosureNotify = unsafe extern "C" fn(*mut c_void, *mut c_void);

struct GioApi {
    _glib: Library,
    _gobject: Library,
    _gio: Library,
    main_context_new: unsafe extern "C" fn() -> *mut GMainContext,
    main_context_push_thread_default: unsafe extern "C" fn(*mut GMainContext),
    main_context_pop_thread_default: unsafe extern "C" fn(*mut GMainContext),
    main_context_iteration: unsafe extern "C" fn(*mut GMainContext, c_int) -> c_int,
    main_context_wakeup: unsafe extern "C" fn(*mut GMainContext),
    main_context_unref: unsafe extern "C" fn(*mut GMainContext),
    free: unsafe extern "C" fn(*mut c_void),
    strfreev: unsafe extern "C" fn(*mut *mut c_char),
    object_unref: unsafe extern "C" fn(*mut c_void),
    signal_connect_data: unsafe extern "C" fn(
        *mut c_void,
        *const c_char,
        Option<SettingsChangedCallback>,
        *mut c_void,
        Option<ClosureNotify>,
        c_uint,
    ) -> c_ulong,
    settings_schema_source_get_default: unsafe extern "C" fn() -> *mut GSettingsSchemaSource,
    settings_schema_source_lookup: unsafe extern "C" fn(
        *mut GSettingsSchemaSource,
        *const c_char,
        c_int,
    ) -> *mut GSettingsSchema,
    settings_schema_unref: unsafe extern "C" fn(*mut GSettingsSchema),
    settings_new_full:
        unsafe extern "C" fn(*mut GSettingsSchema, *mut c_void, *const c_char) -> *mut GSettings,
    settings_get_child: unsafe extern "C" fn(*mut GSettings, *const c_char) -> *mut GSettings,
    settings_get_string: unsafe extern "C" fn(*mut GSettings, *const c_char) -> *mut c_char,
    settings_get_int: unsafe extern "C" fn(*mut GSettings, *const c_char) -> c_int,
    settings_get_strv: unsafe extern "C" fn(*mut GSettings, *const c_char) -> *mut *mut c_char,
}

impl GioApi {
    fn load() -> Result<Self, String> {
        Self::load_from("libglib-2.0.so.0", "libgobject-2.0.so.0", "libgio-2.0.so.0")
    }

    fn load_from(glib_name: &str, gobject_name: &str, gio_name: &str) -> Result<Self, String> {
        // SAFETY: the handles remain owned by GioApi for at least as long as
        // every copied function pointer and every GObject created through them.
        unsafe {
            let glib = Library::new(glib_name)
                .map_err(|error| format!("failed to load {glib_name}: {error}"))?;
            let gobject = Library::new(gobject_name)
                .map_err(|error| format!("failed to load {gobject_name}: {error}"))?;
            let gio = Library::new(gio_name)
                .map_err(|error| format!("failed to load {gio_name}: {error}"))?;

            Ok(Self {
                main_context_new: load_symbol(&glib, b"g_main_context_new\0")?,
                main_context_push_thread_default: load_symbol(
                    &glib,
                    b"g_main_context_push_thread_default\0",
                )?,
                main_context_pop_thread_default: load_symbol(
                    &glib,
                    b"g_main_context_pop_thread_default\0",
                )?,
                main_context_iteration: load_symbol(&glib, b"g_main_context_iteration\0")?,
                main_context_wakeup: load_symbol(&glib, b"g_main_context_wakeup\0")?,
                main_context_unref: load_symbol(&glib, b"g_main_context_unref\0")?,
                free: load_symbol(&glib, b"g_free\0")?,
                strfreev: load_symbol(&glib, b"g_strfreev\0")?,
                object_unref: load_symbol(&gobject, b"g_object_unref\0")?,
                signal_connect_data: load_symbol(&gobject, b"g_signal_connect_data\0")?,
                settings_schema_source_get_default: load_symbol(
                    &gio,
                    b"g_settings_schema_source_get_default\0",
                )?,
                settings_schema_source_lookup: load_symbol(
                    &gio,
                    b"g_settings_schema_source_lookup\0",
                )?,
                settings_schema_unref: load_symbol(&gio, b"g_settings_schema_unref\0")?,
                settings_new_full: load_symbol(&gio, b"g_settings_new_full\0")?,
                settings_get_child: load_symbol(&gio, b"g_settings_get_child\0")?,
                settings_get_string: load_symbol(&gio, b"g_settings_get_string\0")?,
                settings_get_int: load_symbol(&gio, b"g_settings_get_int\0")?,
                settings_get_strv: load_symbol(&gio, b"g_settings_get_strv\0")?,
                _glib: glib,
                _gobject: gobject,
                _gio: gio,
            })
        }
    }
}

unsafe fn load_symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
    // SAFETY: callers provide the exact C ABI signature for each named symbol,
    // and GioApi keeps the library loaded while the copied pointer is usable.
    unsafe {
        library
            .get::<T>(name)
            .map(|symbol| *symbol)
            .map_err(|error| {
                format!(
                    "failed to load {}: {error}",
                    String::from_utf8_lossy(name).trim_end_matches('\0')
                )
            })
    }
}

static GIO_API: OnceLock<Option<GioApi>> = OnceLock::new();

fn gio_api() -> Option<&'static GioApi> {
    GIO_API
        .get_or_init(|| match GioApi::load() {
            Ok(api) => Some(api),
            Err(error) => {
                log::debug!("proxy settings: GIO unavailable: {error}");
                None
            }
        })
        .as_ref()
}

struct Settings<'a> {
    api: &'a GioApi,
    ptr: *mut GSettings,
}

impl<'a> Settings<'a> {
    fn proxy(api: &'a GioApi) -> Option<Self> {
        Self::with_schema(api, PROXY_SCHEMA)
    }

    fn with_schema(api: &'a GioApi, schema_id: &[u8]) -> Option<Self> {
        // SAFETY: all symbols have their documented GIO signatures. The
        // schema is checked before creating GSettings because a missing schema
        // is fatal when passed directly to g_settings_new.
        unsafe {
            let source = (api.settings_schema_source_get_default)();
            if source.is_null() {
                return None;
            }
            let schema = (api.settings_schema_source_lookup)(source, c_ptr(schema_id), 1);
            if schema.is_null() {
                return None;
            }
            let settings = (api.settings_new_full)(schema, ptr::null_mut(), ptr::null());
            (api.settings_schema_unref)(schema);
            (!settings.is_null()).then_some(Self { api, ptr: settings })
        }
    }

    fn child(&self, name: &[u8]) -> Option<Self> {
        // SAFETY: self.ptr is a live GSettings and name is NUL-terminated.
        let child = unsafe { (self.api.settings_get_child)(self.ptr, c_ptr(name)) };
        (!child.is_null()).then_some(Self {
            api: self.api,
            ptr: child,
        })
    }

    fn string(&self, key: &[u8]) -> String {
        // SAFETY: self.ptr is live and the schema defines key as a string.
        let value = unsafe { (self.api.settings_get_string)(self.ptr, c_ptr(key)) };
        if value.is_null() {
            return String::new();
        }
        // SAFETY: GSettings returns a NUL-terminated UTF-8 string allocated by
        // GLib. Copy it before releasing the allocation with g_free.
        let result = unsafe { CStr::from_ptr(value) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: value was returned with transfer-full ownership.
        unsafe { (self.api.free)(value.cast()) };
        result
    }

    fn int(&self, key: &[u8]) -> c_int {
        // SAFETY: self.ptr is live and the schema defines key as an integer.
        unsafe { (self.api.settings_get_int)(self.ptr, c_ptr(key)) }
    }

    fn string_list(&self, key: &[u8]) -> Vec<String> {
        // SAFETY: self.ptr is live and the schema defines key as a string array.
        let values = unsafe { (self.api.settings_get_strv)(self.ptr, c_ptr(key)) };
        if values.is_null() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let mut cursor = values;
        // SAFETY: g_settings_get_strv returns a NUL-terminated array of
        // NUL-terminated UTF-8 strings.
        unsafe {
            while !(*cursor).is_null() {
                result.push(CStr::from_ptr(*cursor).to_string_lossy().into_owned());
                cursor = cursor.add(1);
            }
            (self.api.strfreev)(values);
        }
        result
    }

    fn connect_changed(&self, state: &ChangeState) -> bool {
        // SAFETY: state outlives this Settings and therefore every connected
        // signal handler. The callback has the documented "changed" ABI.
        unsafe {
            (self.api.signal_connect_data)(
                self.ptr.cast(),
                c_ptr(CHANGED_SIGNAL),
                Some(settings_changed),
                (state as *const ChangeState).cast_mut().cast(),
                None,
                0,
            ) != 0
        }
    }
}

impl Drop for Settings<'_> {
    fn drop(&mut self) {
        // SAFETY: ptr owns one live GObject reference.
        unsafe { (self.api.object_unref)(self.ptr.cast()) };
    }
}

struct ProxySettings<'a> {
    root: Settings<'a>,
    http: Settings<'a>,
    https: Settings<'a>,
    socks: Settings<'a>,
}

impl<'a> ProxySettings<'a> {
    fn new(api: &'a GioApi) -> Option<Self> {
        let root = Settings::proxy(api)?;
        let http = root.child(HTTP_CHILD)?;
        let https = root.child(HTTPS_CHILD)?;
        let socks = root.child(SOCKS_CHILD)?;
        Some(Self {
            root,
            http,
            https,
            socks,
        })
    }

    fn values(&self) -> Values {
        Values {
            mode: self.root.string(MODE_KEY),
            autoconfig_url: self.root.string(AUTOCONFIG_URL_KEY),
            ignore_hosts: self.root.string_list(IGNORE_HOSTS_KEY),
            http_host: self.http.string(HOST_KEY),
            http_port: self.http.int(PORT_KEY),
            https_host: self.https.string(HOST_KEY),
            https_port: self.https.int(PORT_KEY),
            socks_host: self.socks.string(HOST_KEY),
            socks_port: self.socks.int(PORT_KEY),
        }
    }

    fn connect_changed(&self, state: &ChangeState) -> bool {
        self.root.connect_changed(state)
            && self.http.connect_changed(state)
            && self.https.connect_changed(state)
            && self.socks.connect_changed(state)
    }
}

#[derive(Default)]
pub(super) struct Values {
    pub(super) mode: String,
    pub(super) autoconfig_url: String,
    pub(super) ignore_hosts: Vec<String>,
    pub(super) http_host: String,
    pub(super) http_port: c_int,
    pub(super) https_host: String,
    pub(super) https_port: c_int,
    pub(super) socks_host: String,
    pub(super) socks_port: c_int,
}

pub(super) fn read_values() -> Option<Values> {
    let api = gio_api()?;
    ProxySettings::new(api).map(|settings| settings.values())
}

struct ChangeState {
    changed: AtomicBool,
}

unsafe extern "C" fn settings_changed(
    _settings: *mut GSettings,
    _key: *mut c_char,
    user_data: *mut c_void,
) {
    // SAFETY: connect_changed passes a live ChangeState pointer which remains
    // valid until all connected Settings objects are dropped.
    let state = unsafe { &*(user_data.cast::<ChangeState>()) };
    state.changed.store(true, Ordering::Release);
}

struct WatcherControl {
    stop: AtomicBool,
    context: Mutex<Option<usize>>,
}

impl WatcherControl {
    fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
            context: Mutex::new(None),
        }
    }
}

pub(crate) struct Watcher {
    api: Option<&'static GioApi>,
    control: Option<Arc<WatcherControl>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Watcher {
    fn unavailable() -> Self {
        Self {
            api: None,
            control: None,
            thread: None,
        }
    }
}

pub(super) fn spawn_watcher(on_change: Arc<dyn Fn() + Send + Sync>) -> Watcher {
    let Some(api) = gio_api() else {
        return Watcher::unavailable();
    };

    let control = Arc::new(WatcherControl::new());
    let thread_control = control.clone();
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let thread = match std::thread::Builder::new()
        .name("os-proxy-watch".into())
        .spawn(move || run_watcher(api, thread_control, started_tx, on_change))
    {
        Ok(thread) => thread,
        Err(error) => {
            log::warn!("proxy watcher: failed to spawn GIO thread: {error}");
            return Watcher::unavailable();
        }
    };

    match started_rx.recv() {
        Ok(true) => {}
        Ok(false) => log::debug!("proxy watcher: GSettings proxy schema unavailable"),
        Err(error) => log::warn!("proxy watcher: GIO thread stopped during startup: {error}"),
    }
    Watcher {
        api: Some(api),
        control: Some(control),
        thread: Some(thread),
    }
}

fn run_watcher(
    api: &'static GioApi,
    control: Arc<WatcherControl>,
    started_tx: mpsc::SyncSender<bool>,
    on_change: Arc<dyn Fn() + Send + Sync>,
) {
    let Some(context) = MainContext::new(api, control.clone()) else {
        let _ = started_tx.send(false);
        return;
    };
    let changes = ChangeState {
        changed: AtomicBool::new(false),
    };
    let Some(settings) = ProxySettings::new(api) else {
        let _ = started_tx.send(false);
        return;
    };
    if !settings.connect_changed(&changes) {
        let _ = started_tx.send(false);
        return;
    }

    // GSettings only emits "changed" for keys read after a handler is
    // connected. Prime every key before reporting that startup is complete.
    let _ = settings.values();
    if started_tx.send(true).is_err() {
        return;
    }

    while !control.stop.load(Ordering::Acquire) {
        // SAFETY: context belongs to this thread and remains live for the loop.
        unsafe { (api.main_context_iteration)(context.ptr, 1) };
        if control.stop.load(Ordering::Acquire) {
            break;
        }
        if changes.changed.swap(false, Ordering::AcqRel) {
            // This runs after GLib has returned to Rust, so a user callback
            // panic cannot unwind through a C signal frame.
            on_change();
        }
    }
}

struct MainContext<'a> {
    api: &'a GioApi,
    control: Arc<WatcherControl>,
    ptr: *mut GMainContext,
}

impl<'a> MainContext<'a> {
    fn new(api: &'a GioApi, control: Arc<WatcherControl>) -> Option<Self> {
        // SAFETY: the loaded function has the documented GLib ABI.
        let ptr = unsafe { (api.main_context_new)() };
        if ptr.is_null() {
            return None;
        }
        // SAFETY: ptr is a newly-created context owned by this thread.
        unsafe { (api.main_context_push_thread_default)(ptr) };
        *control
            .context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ptr as usize);
        Some(Self { api, control, ptr })
    }
}

impl Drop for MainContext<'_> {
    fn drop(&mut self) {
        *self
            .control
            .context
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        // SAFETY: ptr is this thread's pushed default context and owns one
        // reference from g_main_context_new.
        unsafe {
            (self.api.main_context_pop_thread_default)(self.ptr);
            (self.api.main_context_unref)(self.ptr);
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let (Some(api), Some(control)) = (self.api, self.control.as_ref()) {
            control.stop.store(true, Ordering::Release);
            let context = control
                .context
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(context) = *context {
                // SAFETY: MainContext clears context while holding the same
                // mutex before unref, so this pointer is live while locked.
                unsafe { (api.main_context_wakeup)(context as *mut GMainContext) };
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn c_ptr(value: &[u8]) -> *const c_char {
    debug_assert_eq!(value.last(), Some(&0));
    value.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_schema_is_reported_without_creating_settings() {
        let Some(api) = gio_api() else {
            return;
        };
        assert!(Settings::with_schema(api, b"com.microsoft.os-proxy-resolver.missing\0").is_none());
    }

    #[test]
    fn missing_library_is_reported_without_linking_gio() {
        assert!(GioApi::load_from(
            "libglib-os-proxy-resolver-missing.so",
            "libgobject-os-proxy-resolver-missing.so",
            "libgio-os-proxy-resolver-missing.so"
        )
        .is_err());
    }
}
