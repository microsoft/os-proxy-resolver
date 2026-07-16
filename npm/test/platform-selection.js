'use strict';

const assert = require('assert');
const { getPlatformPackage } = require('../../platform');

const glibc = { report: { getReport: () => ({ header: { glibcVersionRuntime: '2.28' } }) } };
const musl = { report: { getReport: () => ({ header: {} }) }, readFile: () => 'musl libc' };
const disabledReportMusl = {
	report: { getReport: () => { throw new Error('reports disabled'); } },
	versions: { musl: '1.2.5' },
};

assert.strictEqual(getPlatformPackage('linux', 'x64', glibc), 'linux-x64-glibc');
assert.strictEqual(getPlatformPackage('linux', 'x64', musl), 'linux-x64-musl');
assert.strictEqual(getPlatformPackage('linux', 'arm64', glibc), 'linux-arm64-glibc');
assert.strictEqual(getPlatformPackage('linux', 'arm64', musl), 'linux-arm64-musl');
assert.strictEqual(getPlatformPackage('linux', 'arm', glibc), 'linux-arm-glibc');
assert.strictEqual(getPlatformPackage('linux', 'x64', disabledReportMusl), 'linux-x64-musl');
assert.strictEqual(getPlatformPackage('darwin', 'arm64', musl), 'darwin-arm64');
assert.strictEqual(getPlatformPackage('win32', 'x64', glibc), 'win32-x64');

console.log('Verified platform package selection');
