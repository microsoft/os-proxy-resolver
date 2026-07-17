'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const targets = {
	'aarch64-apple-darwin': ['darwin-arm64', 'libos_proxy_resolver_node.dylib'],
	'x86_64-apple-darwin': ['darwin-x64', 'libos_proxy_resolver_node.dylib'],
	'armv7-unknown-linux-gnueabihf': ['linux-arm-gnueabihf', 'libos_proxy_resolver_node.so'],
	'aarch64-unknown-linux-gnu': ['linux-arm64-gnu', 'libos_proxy_resolver_node.so'],
	'aarch64-unknown-linux-musl': ['linux-arm64-musl', 'libos_proxy_resolver_node.so'],
	'x86_64-unknown-linux-gnu': ['linux-x64-gnu', 'libos_proxy_resolver_node.so'],
	'x86_64-unknown-linux-musl': ['linux-x64-musl', 'libos_proxy_resolver_node.so'],
	'aarch64-pc-windows-msvc': ['win32-arm64-msvc', 'os_proxy_resolver_node.dll'],
	'x86_64-pc-windows-msvc': ['win32-x64-msvc', 'os_proxy_resolver_node.dll'],
};

const target = process.argv[2];
if (!targets[target]) {
	console.error(`Usage: node npm/scripts/build-native.js <target>\nTargets: ${Object.keys(targets).join(', ')}`);
	process.exit(2);
}

const cargo = process.env.CARGO_BUILD_COMMAND || 'cargo';
const useCross = path.basename(cargo) === 'cross';
const cwd = useCross ? path.join(root, 'npm', 'native') : root;
// Cargo appends the target triple below --target-dir. Prefixing the target dir
// with the triple isolates host build scripts created by incompatible cross
// images, so cross artifacts intentionally contain the triple twice.
const targetDirectory = useCross ? path.join('target', target) : path.join('target', 'npm');
const env = { ...process.env };
if (useCross) {
	env.CROSS_CONFIG ??= path.join(root, 'Cross.toml');
}
if (target.endsWith('-musl')) {
	const rustflags = `CARGO_TARGET_${target.toUpperCase().replaceAll('-', '_')}_RUSTFLAGS`;
	env[rustflags] = [env[rustflags], '-C target-feature=-crt-static'].filter(Boolean).join(' ');
}
const result = spawnSync(cargo, [
	'build',
	'--manifest-path', useCross ? 'Cargo.toml' : path.join('npm', 'native', 'Cargo.toml'),
	'--target-dir', targetDirectory,
	'--locked',
	'--target', target,
	'--release',
], { cwd, env, stdio: 'inherit', shell: process.platform === 'win32' });

if (result.error) {
	throw result.error;
}
if (result.status !== 0) {
	process.exit(result.status ?? 1);
}

const [packageDirectory, library] = targets[target];
const source = useCross
	? path.join(root, 'npm', 'native', targetDirectory, target, 'release', library)
	: path.join(root, 'target', 'npm', target, 'release', library);
const packagePath = path.join(root, 'npm', 'platforms', packageDirectory);
const destination = path.join(packagePath, 'os_proxy_resolver.node');
fs.rmSync(destination, { force: true });
fs.copyFileSync(source, destination);
fs.copyFileSync(path.join(root, 'LICENSE.txt'), path.join(packagePath, 'LICENSE.txt'));
fs.copyFileSync(path.join(root, 'npm', 'ThirdPartyNotices.txt'), path.join(packagePath, 'ThirdPartyNotices.txt'));
console.log(`Staged ${path.relative(root, destination)}`);