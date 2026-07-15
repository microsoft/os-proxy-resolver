'use strict';

const packages = {
	'darwin-arm64': '@vscode/os-proxy-resolver-darwin-arm64',
	'darwin-x64': '@vscode/os-proxy-resolver-darwin-x64',
	'linux-arm': '@vscode/os-proxy-resolver-linux-arm-gnueabihf',
	'linux-arm64': '@vscode/os-proxy-resolver-linux-arm64-gnu',
	'linux-x64': '@vscode/os-proxy-resolver-linux-x64-gnu',
	'win32-arm64': '@vscode/os-proxy-resolver-win32-arm64-msvc',
	'win32-x64': '@vscode/os-proxy-resolver-win32-x64-msvc',
};

const platform = `${process.platform}-${process.arch}`;
const packageName = packages[platform];

if (!packageName) {
	throw new Error(`@vscode/os-proxy-resolver does not support ${platform}`);
}

try {
	require.resolve(packageName);
} catch (error) {
	if (error && error.code === 'MODULE_NOT_FOUND') {
		throw new Error(
			`The native package ${packageName} is not installed. ` +
			'Ensure optional dependencies are enabled and npm_config_arch matches the target architecture.',
			{ cause: error }
		);
	}
	throw error;
}

const binding = require(packageName);
exports.ProxyResolver = binding.ProxyResolver;
exports.resolveProxy = binding.resolveProxy;
exports.readProxyConfig = binding.readProxyConfig;