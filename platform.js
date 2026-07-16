'use strict';

const fs = require('fs');

function getLinuxLibc(report = process.report, versions = process.versions, readFile = fs.readFileSync) {
	try {
		if (report?.getReport?.().header?.glibcVersionRuntime) {
			return 'glibc';
		}
	} catch {
		// Reports can be disabled by the Node host.
	}
	if (versions?.musl) {
		return 'musl';
	}
	if (versions?.glibc) {
		return 'glibc';
	}
	try {
		return readFile('/usr/bin/ldd', 'utf8').includes('musl') ? 'musl' : 'glibc';
	} catch {
		return 'glibc';
	}
}

function getPlatformPackage(platform = process.platform, arch = process.arch, options = {}) {
	if (platform !== 'linux') {
		return `${platform}-${arch}`;
	}
	const libc = getLinuxLibc(options.report, options.versions, options.readFile);
	return `${platform}-${arch}-${libc}`;
}

exports.getPlatformPackage = getPlatformPackage;
