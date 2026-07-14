'use strict';

const assert = require('assert');
const path = require('path');

const platformPackage = `${process.platform}-${process.arch === 'arm' ? 'arm-gnueabihf' : process.arch}${process.platform === 'linux' && process.arch !== 'arm' ? '-gnu' : process.platform === 'win32' ? '-msvc' : ''}`;
const binding = require(path.resolve(__dirname, '..', 'platforms', platformPackage, 'os_proxy_resolver.node'));

async function main() {
	assert.strictEqual(typeof binding.resolveProxy, 'function');
	assert.strictEqual(typeof binding.ProxyResolver, 'function');

	const proxies = await binding.resolveProxy('https://example.com/');
	assert.ok(Array.isArray(proxies));
	assert.ok(proxies.length > 0);
	for (const proxy of proxies) {
		assert.ok(['direct', 'http', 'socks'].includes(proxy.kind));
	}

	const resolver = new binding.ProxyResolver();
	assert.strictEqual(typeof resolver.configGeneration, 'number');
	resolver.reportProxyFailed({ kind: 'direct' });
	resolver.close();
}

main().catch(error => {
	console.error(error);
	process.exit(1);
});