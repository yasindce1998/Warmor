#!/usr/bin/env bash
# build-ci-kernel.sh VERSION OUTDIR
#
# Build an x86_64 kernel for the vimto LSM integration tests: the ci-kernels
# configuration plus IMA (see ci/kernel/README.md). Writes OUTDIR/vmlinuz and
# OUTDIR/config.
#
# Needs: gcc, make, flex, bison, bc, cpio, libelf-dev, libssl-dev, pahole
# (dwarves) and curl. WORKDIR (default /tmp/warmor-kernel-build) holds the
# downloaded tarball and the build tree.

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 VERSION OUTDIR" >&2
	exit 2
fi

version=$1
outdir=$(realpath -m "$2")
repo=$(cd "$(dirname "$0")/.." && pwd)
confdir=$repo/ci/kernel
workdir=${WORKDIR:-/tmp/warmor-kernel-build}
jobs=${NPROC:-$(nproc)}

# Default LSM order. vimto cannot pass lsm= on the kernel command line, so the
# list is compiled in. Since 6.9 IMA and EVM are LSMs of their own; older
# kernels know them as "integrity". Unknown names are ignored by the kernel.
lsm_list="landlock,lockdown,yama,integrity,ima,evm,bpf"

# Options the integrity tests cannot run without. A version where any of these
# doesn't take effect fails the build instead of producing a kernel on which
# the tests silently skip.
required=(CONFIG_BPF_LSM CONFIG_DEBUG_INFO_BTF CONFIG_IMA CONFIG_IMA_DEFAULT_HASH_SHA256 CONFIG_SECURITYFS)

mkdir -p "$workdir" "$outdir"

major=${version%%.*}
tarball=$workdir/linux-$version.tar.xz
if [[ ! -s $tarball ]]; then
	echo "==> Downloading linux-$version"
	curl --fail --location --retry 3 -o "$tarball.part" \
		"https://cdn.kernel.org/pub/linux/kernel/v$major.x/linux-$version.tar.xz"
	mv "$tarball.part" "$tarball"
fi

src=$workdir/linux-$version
if [[ ! -d $src ]]; then
	echo "==> Extracting"
	mkdir -p "$src.part"
	tar -xf "$tarball" --strip-components=1 -C "$src.part"
	mv "$src.part" "$src"
fi
cd "$src"

# Snippets use CONFIG_X=n; .config spells that "# CONFIG_X is not set".
snippets() {
	sed -E -e 's/^(CONFIG_[A-Za-z0-9_]+)=n$/# \1 is not set/' -e '/^#( |$)[^C]/d' -e '/^$/d' \
		"$confdir/ci-kernels-config" "$confdir/ci-kernels-config-x86_64" "$confdir/config-warmor"
}

echo "==> Configuring"
make -s defconfig
# Build everything in: vimto boots the image without an initramfs or modules.
sed -i -E 's/^(CONFIG_[A-Za-z0-9_]+)=m$/# \1 is not set/' .config
# Later assignments override earlier ones when Kconfig reads .config.
snippets >> .config
make -s olddefconfig
scripts/config --set-str LSM "$lsm_list"
make -s olddefconfig
sed -i -E 's/^(CONFIG_[A-Za-z0-9_]+)=m$/# \1 is not set/' .config
make -s olddefconfig

echo "==> Verifying configuration"
status=0
is_required() {
	local opt
	for opt in "${required[@]}"; do [[ $opt == "$1" ]] && return 0; done
	return 1
}
while IFS='=' read -r opt want; do
	have=$(grep -E "^$opt=|^# $opt is not set" .config || true)
	if [[ -z $have ]]; then
		# Not a symbol in this kernel version (renamed or removed).
		if is_required "$opt"; then
			echo "error: required $opt does not exist in linux-$version"
			status=1
		else
			echo "note: $opt is not an option in linux-$version, ignored"
		fi
		continue
	fi
	case $want in
	y) [[ $have == "$opt=y" ]] || { echo "error: $opt: want y, have '$have'"; status=1; } ;;
	n) [[ $have == "# $opt is not set" ]] || { echo "error: $opt: want n, have '$have'"; status=1; } ;;
	*) echo "error: $opt: unsupported value '$want' in snippet"; status=1 ;;
	esac
done < <(sed -E -e '/^#/d' -e '/^$/d' "$confdir/ci-kernels-config" "$confdir/ci-kernels-config-x86_64" "$confdir/config-warmor")
for opt in "${required[@]}"; do
	grep -qx "$opt=y" .config || { echo "error: required $opt is not enabled"; status=1; }
done
if ! grep -qx "CONFIG_LSM=\"$lsm_list\"" .config; then
	echo "error: CONFIG_LSM was not set to $lsm_list"
	status=1
fi
if [[ $status -ne 0 ]]; then
	echo "Configuration check failed for linux-$version" >&2
	exit 1
fi

echo "==> Building with $jobs jobs"
make -s -j"$jobs" bzImage

cp arch/x86/boot/bzImage "$outdir/vmlinuz"
cp .config "$outdir/config"
echo "==> $outdir/vmlinuz ($(du -h "$outdir/vmlinuz" | cut -f1))"
