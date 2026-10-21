#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Build the KVM live update tests that need a kexec reboot and run each of
# them with tools/testing/selftests/liveupdate/vmtest.sh, in a QEMU guest
# whose kernel has KVM enabled. Under TCG, the guest runs KVM on an emulated
# CPU with virtualization support: AMD SVM on x86_64, EL2 on arm64.

set -ue

kvm_dir=$(realpath "$(dirname "$0")")
kernel_dir=$(realpath "$kvm_dir/../../../..")
vmtest="$kvm_dir/../liveupdate/vmtest.sh"

TESTS=(
	kvm_luo_kexec_test
)

function usage() {
	cat <<EOF
$0 [-d build_dir] [-j jobs] [-t target_arch] [-x timeout] [-k] [-h]
Options:
	-d)	path to the kernel build directory (see vmtest.sh)
	-j)	number of jobs for compilation
	-t)	run tests for target_arch (aarch64, x86_64)
	-x)	timeout of each test run in seconds (default: 300)
	-k)	keep the workspace directories
	-h)	display this help
EOF
}

function main() {
	local target="$(uname -m)"
	local jobs=$(nproc)
	local timeout=300
	local build_dir=""
	local keep=""
	local arch rc failed=0

	while getopts 'hd:j:t:x:k' opt; do
		case $opt in
		d) build_dir="$OPTARG" ;;
		j) jobs="$OPTARG" ;;
		t) target="$OPTARG" ;;
		x) timeout="$OPTARG" ;;
		k) keep=1 ;;
		h) usage; exit 0 ;;
		*) usage; exit 1 ;;
		esac
	done

	[[ "$target" == "arm64" ]] && target="aarch64"
	case "$target" in
	x86_64) arch=x86 ;;
	aarch64) arch=arm64 ;;
	*) echo "Unsupported architecture: $target"; exit 1 ;;
	esac

	if [[ "$target" != "$(uname -m)" && -z "${CROSS_COMPILE:-}" ]]; then
		export CROSS_COMPILE="$target-linux-gnu-"
	fi

	local ws=$(mktemp -d /tmp/kvm-luo-test.XXXXXXXX)
	[ -z "$keep" ] && trap 'rm -rf "$ws"' EXIT
	echo "# Workspace: $ws"

	# The tests link against the uAPI headers of this tree.
	make -s -C "$kernel_dir" O="$ws/obj" ARCH="$arch" \
		headers_install INSTALL_HDR_PATH="$ws/usr" < /dev/null

	# KVM in the guest kernel, on top of the live update test config.
	cat > "$ws/kvm.config" <<EOF
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=y
CONFIG_TRANSPARENT_HUGEPAGE=y
CONFIG_EVENTFD=y
EOF
	if [[ "$arch" == "x86" ]]; then
		cat >> "$ws/kvm.config" <<EOF
CONFIG_KVM_AMD=y
CONFIG_KVM_INTEL=y
CONFIG_EXPERT=y
CONFIG_KVM_SW_PROTECTED_VM=y
EOF
	fi

	mkdir -p "$ws/kvm_objdir/tools"
	for test in "${TESTS[@]}"; do
		make -s -C "$kvm_dir" ARCH="$arch" OUTPUT="$ws/kvm" \
			abs_objdir="$ws/kvm_objdir" \
			KHDR_INCLUDES="-isystem $ws/usr/include" \
			LINUX_HDR_PATH="$ws/usr/include/" \
			EXTRA_CFLAGS="-static" -j"$jobs" "$ws/kvm/$test" < /dev/null

		rc=0
		"$vmtest" ${build_dir:+-d "$build_dir"} -j "$jobs" \
			-t "$target" -T "$test" -b "$ws/kvm/$test" \
			-c "$ws/kvm.config" -x "$timeout" ${keep:+-k} || rc=$?
		case $rc in
		0) echo "# $target $test: PASS" ;;
		4) echo "# $target $test: SKIP" ;;
		*) echo "# $target $test: FAIL"; failed=1 ;;
		esac
	done

	exit $failed
}

main "$@"
