/**
 * The connection method for a resolved proxy entry.
 *
 * `http` covers both HTTP proxies and HTTPS proxies (TLS to the proxy). For an
 * HTTPS proxy, {@link Proxy.host} is prefixed with `https://`.
 */
export type ProxyKind = 'direct' | 'http' | 'socks';

/** A single entry in an ordered proxy resolution result. */
export interface Proxy {
	/** How to connect to the destination. */
	kind: ProxyKind;

	/**
	 * The proxy endpoint. Omitted when {@link kind} is `direct`.
	 *
	 * HTTP and SOCKS endpoints normally use `host:port`. An HTTPS proxy uses
	 * `https://host:port` to distinguish TLS to the proxy from a plain HTTP
	 * proxy. The SOCKS4/SOCKS5 distinction is not preserved; consumers should
	 * try SOCKS5 first.
	 */
	host?: string;
}

/** How a PAC script was selected. */
export type PacScriptSource = 'wpad-dns' | 'wpad-dhcp' | 'configured' | 'unknown';

/** A PAC script loaded from an OS setting or WPAD, but not evaluated. */
export interface PacScript {
	/** The configured or discovered URL from which {@link content} was loaded. */
	url: string;
	/** The PAC JavaScript source. */
	content: string;
	/** Whether the script came from DNS/DHCP WPAD or an explicit OS setting. */
	source: PacScriptSource;
}

/** Result of inspecting one possible PAC source. */
export type PacSourceState =
	| 'disabled'
	| 'unsupported'
	| 'unconfigured'
	| 'not-found'
	| 'available'
	| 'error-discovery'
	| 'error-download'
	| 'unknown';

/** Diagnostics for one possible PAC source. */
export interface PacSourceStatus {
	state: PacSourceState;
	/** Discovered or configured URL, when known. */
	url?: string;
	/** Discovery or download error detail. May contain platform/network data. */
	error?: string;
}

/** Diagnostics for one effective proxy environment variable. */
export interface EnvironmentVariableStatus {
	/** Effective spelling, for example `https_proxy` or `HTTPS_PROXY`. */
	variable: string;
	/** Raw environment value. May contain credentials. */
	value: string;
	/** Present when the raw value cannot be used as a proxy setting. */
	error?: string;
}

/**
 * Supported proxy environment variables captured when the resolver was
 * constructed. Unset variables are omitted. Windows matches names
 * case-insensitively; Unix prefers lowercase names over uppercase aliases.
 */
export interface EnvironmentProxyConfig {
	httpProxy?: EnvironmentVariableStatus;
	httpsProxy?: EnvironmentVariableStatus;
	allProxy?: EnvironmentVariableStatus;
	noProxy?: EnvironmentVariableStatus;
}

/** Normalized static proxy settings read from the operating system. */
export interface StaticProxyRules {
	/** Proxy for HTTP and WebSocket requests. */
	http?: Proxy;
	/** Proxy for HTTPS and secure WebSocket requests. */
	https?: Proxy;
	/** SOCKS fallback for schemes without a specific proxy. */
	socks?: Proxy;
}

/** Raw Windows WinINET/WinHTTP proxy settings. */
export interface WindowsProxyConfig {
	kind: 'windows';
	proxy?: string;
	proxyBypass?: string;
}

/** Additional macOS SystemConfiguration proxy settings. */
export interface MacosProxyConfig {
	kind: 'macos';
	exceptions: string[];
	excludeSimpleHostnames: boolean;
}

/** Additional GNOME GSettings proxy settings on Linux. */
export interface LinuxProxyConfig {
	kind: 'linux';
	mode?: string;
	ignoreHosts: string[];
}

/** A future platform configuration not recognized by this package version. */
export interface UnknownPlatformProxyConfig {
	kind: 'unknown';
}

/** Source-specific settings retained where the operating system exposes them. */
export type PlatformProxyConfig = WindowsProxyConfig | MacosProxyConfig | LinuxProxyConfig | UnknownPlatformProxyConfig;

/** A snapshot of the current operating-system proxy configuration. */
export interface ProxyConfig {
	/** Captured `http_proxy`, `https_proxy`, `all_proxy`, and `no_proxy` settings. */
	environment: EnvironmentProxyConfig;
	/** Whether the operating system requested automatic proxy discovery. */
	autoDetect: boolean;
	/** The configured PAC URL, even if the script could not be loaded. */
	pacUrl?: string;
	/** The first PAC script available by resolution precedence. */
	pac?: PacScript;
	/** DHCP WPAD status. Unsupported on non-Windows platforms. */
	wpadDhcp: PacSourceStatus;
	/** DNS WPAD status. */
	wpadDns: PacSourceStatus;
	/** Explicitly configured PAC status. */
	configuredPac: PacSourceStatus;
	/** Normalized static proxy settings, if configured. */
	staticRules?: StaticProxyRules;
	/** Raw source-specific settings, if the native source was available. */
	platform?: PlatformProxyConfig;
}

/**
 * Resolves the proxy configuration for multiple URLs while retaining proxy
 * configuration caches, change notifications, and failed-proxy state.
 *
 * Environment variables such as `HTTPS_PROXY` and `NO_PROXY` are captured
 * when the resolver is constructed. Operating-system proxy settings remain
 * dynamic and are watched for changes.
 */
export declare class ProxyResolver {
	constructor();

	/**
	 * Resolves the ordered proxy fallback list for an absolute URL.
	 *
	 * Try entries in array order until one succeeds. Resolution considers proxy
	 * environment variables first, then the operating-system configuration
	 * (including PAC and WPAD), and finally a direct connection. Potentially
	 * blocking native work runs outside the JavaScript event loop.
	 *
	 * @throws If `url` is invalid, has no host, or an operating-system API fails.
	 */
	resolve(url: string): Promise<Proxy[]>;

	/**
	 * Reads the operating-system proxy configuration without evaluating PAC.
	 *
	 * Includes proxy environment variables captured when this resolver was
	 * constructed. DHCP WPAD, DNS WPAD, and the configured PAC URL are inspected
	 * independently. {@link ProxyConfig.pac} contains the first available script
	 * by precedence (DHCP before DNS on Windows, then configured PAC).
	 * Potentially blocking OS, DNS, and network work runs outside the JavaScript
	 * event loop.
	 */
	readProxyConfig(): Promise<ProxyConfig>;

	/**
	 * A monotonically increasing value that changes when the operating-system
	 * proxy configuration may have changed. Cache consumers can store this with
	 * a resolution and compare it before reusing that result.
	 */
	readonly configGeneration: number;

	/**
	 * Reports that a connection through `proxy` failed.
	 *
	 * Subsequent resolutions demote that proxy to the end of the fallback list
	 * for a cooldown period. Reporting a direct entry has no effect.
	 */
	reportProxyFailed(proxy: Proxy): void;

	/**
	 * Registers a callback for operating-system proxy configuration changes.
	 *
	 * The callback runs on the JavaScript event loop and receives no payload;
	 * read {@link configGeneration} or resolve affected URLs again. The
	 * subscription does not keep the Node.js process alive.
	 *
	 * @returns A subscription identifier for {@link offChange}.
	 */
	onChange(callback: () => void): number;

	/** Unregisters a callback previously registered with {@link onChange}. */
	offChange(subscription: number): void;

	/**
	 * Unregisters all change callbacks owned by this resolver.
	 *
	 * The resolver remains usable for resolution after it is closed.
	 */
	close(): void;
}

/**
 * Resolves an absolute URL using a process-wide {@link ProxyResolver}.
 *
 * The returned array is an ordered fallback list. Use an explicit resolver
 * when change notifications or failed-proxy reporting are needed.
 */
export declare function resolveProxy(url: string): Promise<Proxy[]>;

/**
 * Reads proxy environment and operating-system configuration using a
 * process-wide {@link ProxyResolver}. PAC scripts are loaded but never evaluated.
 */
export declare function readProxyConfig(): Promise<ProxyConfig>;