'use strict';

const assert = require('assert');
const path = require('path');
const { getPlatformPackage } = require('../../platform');

const platformPackage = getPlatformPackage()
	.replace('linux-arm-glibc', 'linux-arm-gnueabihf')
	.replace(/-glibc$/, '-gnu')
	.concat(process.platform === 'win32' ? '-msvc' : '');
const binding = require(path.resolve(__dirname, '..', 'platforms', platformPackage, 'os_proxy_resolver.node'));

async function main() {
	assert.strictEqual(typeof binding.resolveProxy, 'function');
	assert.strictEqual(typeof binding.readProxyConfig, 'function');
	assert.strictEqual(typeof binding.ProxyResolver, 'function');

	const proxies = await binding.resolveProxy('https://example.com/');
	assert.ok(Array.isArray(proxies));
	assert.ok(proxies.length > 0);
	for (const proxy of proxies) {
		assert.ok(['direct', 'http', 'socks'].includes(proxy.kind));
	}

	const resolver = new binding.ProxyResolver();
	assert.strictEqual(typeof resolver.readProxyConfig, 'function');
	assert.strictEqual(typeof resolver.configGeneration, 'number');
	const config = await resolver.readProxyConfig();
	assert.strictEqual(typeof config.autoDetect, 'boolean');
	if (config.pac) {
		assert.strictEqual(typeof config.pac.url, 'string');
		assert.strictEqual(typeof config.pac.content, 'string');
		assert.ok(['wpad-dns', 'wpad-dhcp', 'configured', 'unknown'].includes(config.pac.source));
	}
	if (config.platform) {
		assert.ok(['windows', 'macos', 'linux', 'unknown'].includes(config.platform.kind));
	}
	resolver.reportProxyFailed({ kind: 'direct' });
	resolver.close();
}

main().catch(error => {
	console.error(error);
	process.exit(1);
});