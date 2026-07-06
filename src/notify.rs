/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Change-notification plumbing shared by all platforms: a generation counter
//! for cheap synchronous polling, a callback list for push, and (behind the
//! `tokio` feature) a `tokio::sync::watch` channel. Platform watchers call
//! [`Notifier::bump`] whenever the OS proxy configuration may have changed.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};

type Callbacks = Mutex<HashMap<u64, Box<dyn Fn() + Send>>>;

pub(crate) struct Notifier {
    generation: Arc<AtomicU64>,
    callbacks: Arc<Callbacks>,
    next_id: AtomicU64,
    #[cfg(feature = "tokio")]
    watch_tx: tokio::sync::watch::Sender<u64>,
}

impl Notifier {
    pub fn new() -> Self {
        Notifier {
            generation: Arc::new(AtomicU64::new(0)),
            callbacks: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            #[cfg(feature = "tokio")]
            watch_tx: tokio::sync::watch::channel(0).0,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Called from platform watcher threads on every (possible) config change.
    ///
    /// Callbacks run while the map lock is held — the `on_change` contract
    /// forbids callbacks from registering/unregistering subscriptions.
    pub fn bump(&self) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        #[cfg(feature = "tokio")]
        let _ = self.watch_tx.send(generation);
        #[cfg(not(feature = "tokio"))]
        let _ = generation;
        let callbacks = lock(&self.callbacks);
        for f in callbacks.values() {
            f();
        }
    }

    pub fn subscribe(&self, f: impl Fn() + Send + 'static) -> Subscription {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        lock(&self.callbacks).insert(id, Box::new(f));
        Subscription {
            id,
            callbacks: Arc::downgrade(&self.callbacks),
        }
    }

    #[cfg(feature = "tokio")]
    pub fn watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.watch_tx.subscribe()
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Guard returned by [`ProxyResolver::on_change`](crate::ProxyResolver::on_change).
/// Dropping it unregisters the callback.
#[must_use = "dropping the Subscription unregisters the callback"]
pub struct Subscription {
    id: u64,
    callbacks: Weak<Callbacks>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        if let Some(callbacks) = self.callbacks.upgrade() {
            lock(&callbacks).remove(&self.id);
        }
    }
}

impl std::fmt::Debug for Subscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subscription")
            .field("id", &self.id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn bump_generation_and_callbacks() {
        let n = Notifier::new();
        assert_eq!(n.generation(), 0);
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        let sub = n.subscribe(move || {
            h.fetch_add(1, Ordering::SeqCst);
        });
        n.bump();
        n.bump();
        assert_eq!(n.generation(), 2);
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        drop(sub);
        n.bump();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[cfg(feature = "tokio")]
    #[test]
    fn watch_channel_tracks_generation() {
        let n = Notifier::new();
        let mut rx = n.watch();
        n.bump();
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), 1);
    }
}
