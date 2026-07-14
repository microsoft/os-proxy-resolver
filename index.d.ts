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