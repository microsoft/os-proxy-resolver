'use strict';

const { spawnSync } = require('child_process');
const fs = require('fs');

const MAX_GLIBC = '2.28';
const files = process.argv.slice(2);

if (files.length === 0) {
	console.error('Usage: node npm/scripts/verify-glibc.js <addon.node> [...]');
	process.exit(2);
}

function compareVersions(left, right) {
	const leftParts = left.split('.').map(Number);
	const rightParts = right.split('.').map(Number);
	const length = Math.max(leftParts.length, rightParts.length);
	for (let index = 0; index < length; index++) {
		const difference = (leftParts[index] ?? 0) - (rightParts[index] ?? 0);
		if (difference !== 0) {
			return difference;
		}
	}
	return 0;
}

for (const file of files) {
	if (!fs.statSync(file).isFile()) {
		throw new Error(`${file} is not a file`);
	}

	const result = spawnSync(process.env.OBJDUMP || 'objdump', ['-T', file], {
		encoding: 'utf8',
		maxBuffer: 16 * 1024 * 1024,
	});
	if (result.error) {
		throw result.error;
	}
	if (result.status !== 0) {
		throw new Error(`objdump failed for ${file}: ${result.stderr.trim()}`);
	}

	const versions = [...result.stdout.matchAll(/\bGLIBC_(\d+(?:\.\d+)+)\b/g)].map(match => match[1]);
	if (versions.length === 0) {
		throw new Error(`${file} has no versioned GLIBC imports; is it a GNU/Linux ELF binary?`);
	}
	versions.sort(compareVersions);
	const required = versions.at(-1);
	if (compareVersions(required, MAX_GLIBC) > 0) {
		throw new Error(`${file} requires GLIBC_${required}; maximum supported is GLIBC_${MAX_GLIBC}`);
	}
	console.log(`${file}: maximum required GLIBC version is ${required} (limit ${MAX_GLIBC})`);
}