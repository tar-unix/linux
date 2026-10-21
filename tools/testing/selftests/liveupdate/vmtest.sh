#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

set -ue

CROSS_COMPILE="${CROSS_COMPILE:-""}"

test_dir=$(realpath "$(dirname "$0")")
kernel_dir=$(realpath "$test_dir/../../../..")

workspace_dir=""
headers_dir=""
initrd=""
test_binary=""
extra_configs=()
test_timeout=30
KEEP_WORKSPACE=0

source "$test_dir/../kselftest/ktap_helpers.sh"

function get_arch_conf() {
	local arch=$1
	if [[ "$arch" == "arm64" ]]; then
		if [[ -n "$test_binary" ]]; then
			QEMU_CMD="qemu-system-aarch64 -M virt,virtualization=on,gic-version=3 -cpu max"
		else
			QEMU_CMD="qemu-system-aarch64 -M virt -cpu max"
		fi
		KERNEL_IMAGE="Image"
		KERNEL_CMDLINE="console=ttyAMA0"
	elif [[ "$arch" == "x86" ]]; then
		QEMU_CMD="qemu-system-x86_64 -cpu max"
		KERNEL_IMAGE="bzImage"
		KERNEL_CMDLINE="console=ttyS0"
	else
		echo "Unsupported architecture: $arch"
		exit 1
	fi
}

function usage() {
	cat <<EOF
$0 [-d build_dir] [-j jobs] [-t target_arch] [-T test_name] [-b test_binary]
   [-c config] [-x timeout] [-w workspace_dir] [-k] [-h]
Options:
	-d)	path to the kernel build directory (default: .luo_test_build.<arch>)
	-j)	number of jobs for compilation
	-t)	run test for target_arch (aarch64, x86_64)
	-T)	test name to run (default: luo_kexec_simple)
	-b)	run this prebuilt, statically linked test binary instead of
		building test_name
	-c)	additional kernel config fragment, can be given more than once
	-x)	timeout of the test run in seconds (default: 30)
	-w)	custom workspace directory (default: creates temp dir)
	-k)	keep workspace directory after successful test
	-h)	display this help
EOF
}

function cleanup() {
	if [ "$KEEP_WORKSPACE" -eq 1 ]; then
		echo "# Workspace preserved at: $workspace_dir"
	else
		rm -fr "$workspace_dir"
	fi

	ktap_finished
}

function skip() {
	local msg=${1:-""}
	ktap_test_skip "$msg"
	exit "$KSFT_SKIP"
}

function fail() {
	local msg=${1:-""}
	ktap_test_fail "$msg"
	exit "$KSFT_FAIL"
}

function detect_cross_compile() {
	local target=$1
	local host=$(uname -m)

	[[ "$host" == "arm64" ]] && host="aarch64"
	[[ "$target" == "arm64" ]] && target="aarch64"

	if [[ "$host" == "$target" ]]; then
		CROSS_COMPILE=""
		return
	fi

	if [[ -n "$CROSS_COMPILE" ]]; then
		return
	fi

	local candidate=""
	case "$target" in
		aarch64) candidate="aarch64-linux-gnu-" ;;
		x86_64)  candidate="x86_64-linux-gnu-" ;;
		*)       skip "Auto-detection for target '$target' not supported. Please set CROSS_COMPILE manually." ;;
	esac

	if command -v "${candidate}gcc" &> /dev/null; then
		CROSS_COMPILE="$candidate"
	else
		skip "Compiler '${candidate}gcc' not found. Please install it (e.g., 'apt install gcc-aarch64-linux-gnu') or set CROSS_COMPILE."
	fi
}

function build_kernel() {
	local build_dir=$1
	local make_cmd=$2
	local kimage=$3
	local target_arch=$4

	local luo_config="$build_dir/luo.config"
	local kconfig="$build_dir/.config"
	local common_conf="$test_dir/config"
	local arch_conf="$test_dir/config.$target_arch"

	echo "# Building kernel in: $build_dir"

	cat "$arch_conf" "$common_conf" \
		${extra_configs[@]+"${extra_configs[@]}"} | \
		tee "$kconfig" > "$luo_config"
	$make_cmd olddefconfig

	# verify that kernel confiration has all necessary options
	while read -r opt ; do
		grep "$opt" "$kconfig" &>/dev/null || skip "$opt is missing"
	done < "$luo_config"

	$make_cmd "$kimage"
	$make_cmd headers_install INSTALL_HDR_PATH="$headers_dir"
}

function mkinitrd() {
	local build_dir=$1
	local kernel_path=$2
	local test_name=$3

	# Compile the test binary and the init process
	if [ -n "$test_binary" ]; then
		cp "$test_binary" "$workspace_dir/test_binary"
	else
		"$CROSS_COMPILE"gcc -static -O2 -nostdinc -nostdlib \
			-I "$headers_dir/include" \
			-I "$kernel_dir/tools/include/nolibc" \
			-I "$test_dir/lib/include" \
			-o "$workspace_dir/test_binary" \
			"$test_dir/$test_name.c" "$test_dir/lib/lu_utils.c"
	fi

	"$CROSS_COMPILE"gcc -s -static -Os -nostdinc -nostdlib		\
			-fno-asynchronous-unwind-tables -fno-ident	\
			-fno-stack-protector				\
			-I "$headers_dir/include"			\
			-I "$kernel_dir/tools/include/nolibc"		\
			-o "$workspace_dir/init" "$test_dir/init.c"

	cat > "$workspace_dir/cpio_list_inner" <<EOF
dir /dev 0755 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /debugfs 0755 0 0
nod /dev/console 0600 0 0 c 5 1
file /init $workspace_dir/init 0755 0 0
file /test_binary $workspace_dir/test_binary 0755 0 0
EOF

	# Generate inner_initrd.cpio
	"$build_dir/usr/gen_init_cpio" "$workspace_dir/cpio_list_inner" > "$workspace_dir/inner_initrd.cpio"

	cat > "$workspace_dir/cpio_list" <<EOF
dir /dev 0755 0 0
dir /proc 0755 0 0
dir /sys 0755 0 0
dir /debugfs 0755 0 0
nod /dev/console 0600 0 0 c 5 1
file /init $workspace_dir/init 0755 0 0
file /kernel $kernel_path 0644 0 0
file /test_binary $workspace_dir/test_binary 0755 0 0
file /initrd.img $workspace_dir/inner_initrd.cpio 0644 0 0
EOF

	# Generate the final initrd
	"$build_dir/usr/gen_init_cpio" "$workspace_dir/cpio_list" > "$initrd"
}

function run_qemu() {
	local qemu_cmd=$1
	local cmdline=$2
	local kernel_path=$3
	local serial="$workspace_dir/qemu.serial"

	cmdline="$cmdline liveupdate=on panic=-1"

	echo "# Serial Log: $serial"
	timeout "${test_timeout}s" \
	$qemu_cmd -m 1G -smp 2 -no-reboot -nographic -nodefaults \
		  -accel kvm -accel hvf -accel tcg \
		  -serial file:"$serial" \
		  -append "$cmdline" \
		  -kernel "$kernel_path" \
		  -initrd "$initrd"

	grep "TEST PASSED" "$serial" &> /dev/null || fail "Liveupdate failed"
}

function target_to_arch() {
	local target=$1
	case $target in
	     aarch64) echo "arm64" ;;
	     x86_64) echo "x86" ;;
	     *) skip "architecture $target is not supported"
	esac
}

function main() {
	local build_dir=""
	local jobs=$(nproc)
	local target="$(uname -m)"
	local test_name="luo_kexec_simple"
	local workspace_arg=""

	set -o errtrace
	trap fail ERR

	while getopts 'hd:j:t:T:b:c:x:w:k' opt; do
		case $opt in
		d) build_dir="$OPTARG" ;;
		j) jobs="$OPTARG" ;;
		t) target="$OPTARG" ;;
		T) test_name="$OPTARG" ;;
		b) test_binary="$(realpath -e "$OPTARG")" ;;
		c) extra_configs+=("$(realpath -e "$OPTARG")") ;;
		x) test_timeout="$OPTARG" ;;
		w) workspace_arg="$OPTARG" ;;
		k) KEEP_WORKSPACE=1 ;;
		h) usage; exit 0 ;;
		*) echo "Unknown argument $opt"; usage; exit 1 ;;
		esac
	done

	ktap_print_header
	ktap_set_plan 1
	trap cleanup EXIT

	if [ -n "$workspace_arg" ]; then
		workspace_dir="$(realpath -m "$workspace_arg")"
		mkdir -p "$workspace_dir"
	else
		workspace_dir=$(mktemp -d /tmp/luo-test.XXXXXXXX)
	fi

	echo "# Workspace created at: $workspace_dir"
	headers_dir="$workspace_dir/usr"
	initrd="$workspace_dir/initrd.cpio"

	detect_cross_compile "$target"

	local arch=$(target_to_arch "$target")

	if [ -z "$build_dir" ]; then
		build_dir="$kernel_dir/.luo_test_build.$arch"
	fi

	mkdir -p "$build_dir"
	build_dir=$(realpath "$build_dir")
	get_arch_conf "$arch"

	local make_cmd="make -s ARCH=$arch CROSS_COMPILE=$CROSS_COMPILE -j$jobs"
	local make_cmd_build="$make_cmd -C $kernel_dir O=$build_dir"

	build_kernel "$build_dir" "$make_cmd_build" "$KERNEL_IMAGE" "$target"

	local final_kernel="$build_dir/arch/$arch/boot/$KERNEL_IMAGE"
	mkinitrd "$build_dir" "$final_kernel" "$test_name"

	run_qemu "$QEMU_CMD" "$KERNEL_CMDLINE" "$final_kernel"
	ktap_test_pass "$test_name succeeded"
}

main "$@"
