#!/usr/bin/env bash

set -euo pipefail

target=${1:-}
case "$target" in
	x86_64-unknown-linux-gnu)
		sysroot_arch=amd64
		toolchain=x86_64-linux-gnu
		library_arch=x86_64-linux-gnu
		package_directory=linux-x64-gnu
		;;
	aarch64-unknown-linux-gnu)
		sysroot_arch=arm64
		toolchain=aarch64-linux-gnu
		library_arch=aarch64-linux-gnu
		package_directory=linux-arm64-gnu
		;;
	armv7-unknown-linux-gnueabihf)
		sysroot_arch=armhf
		toolchain=arm-rpi-linux-gnueabihf
		library_arch=arm-linux-gnueabihf
		package_directory=linux-arm-gnueabihf
		;;
	*)
		echo "Usage: $0 <x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|armv7-unknown-linux-gnueabihf>" >&2
		exit 2
		;;
esac

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
toolchain_root="/tmp/vscode-${sysroot_arch}-sysroot/${toolchain}"
sysroot="${toolchain_root}/${toolchain}/sysroot"
compiler="${toolchain_root}/bin/${toolchain}-gcc"
objdump="${toolchain_root}/${toolchain}/bin/objdump"

if [[ ! -x "$compiler" || ! -d "$sysroot" || ! -x "$objdump" ]]; then
	echo "VS Code glibc 2.28 sysroot for ${sysroot_arch} is not installed" >&2
	exit 1
fi

target_env=$(printf '%s' "$target" | tr '[:lower:]-' '[:upper:]_')
cc_env="CC_$(printf '%s' "$target" | tr '-' '_')"
cflags_env="CFLAGS_$(printf '%s' "$target" | tr '-' '_')"
linker_env="CARGO_TARGET_${target_env}_LINKER"
rustflags_env="CARGO_TARGET_${target_env}_RUSTFLAGS"

export "$cc_env=$compiler"
export "$cflags_env=--sysroot=$sysroot"
export "$linker_env=$compiler"
export "$rustflags_env=-C link-arg=--sysroot=$sysroot -C link-arg=-L${sysroot}/usr/lib/${library_arch} -C link-arg=-L${sysroot}/lib/${library_arch}"

cd "$root"
node npm/scripts/build-native.js "$target"
OBJDUMP="$objdump" node npm/scripts/verify-glibc.js "npm/platforms/${package_directory}/os_proxy_resolver.node"