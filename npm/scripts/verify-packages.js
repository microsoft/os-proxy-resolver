'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..', '..');
const facade = require(path.join(root, 'package.json'));
const platformRoot = path.join(root, 'npm', 'platforms');
const packageDirectories = fs.readdirSync(platformRoot).sort();
const expectedDependencies = new Map(Object.entries(facade.optionalDependencies));

for (const directory of packageDirectories) {
	const manifest = require(path.join(platformRoot, directory, 'package.json'));
	if (manifest.version !== facade.version) {
		throw new Error(`${manifest.name} has version ${manifest.version}; expected ${facade.version}`);
	}
	if (expectedDependencies.get(manifest.name) !== facade.version) {
		throw new Error(`${manifest.name} is missing from optionalDependencies at ${facade.version}`);
	}
	expectedDependencies.delete(manifest.name);
}

if (expectedDependencies.size !== 0) {
	throw new Error(`Missing platform package directories: ${[...expectedDependencies.keys()].join(', ')}`);
}

console.log(`Verified facade and ${packageDirectories.length} platform package manifests at ${facade.version}`);