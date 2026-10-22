// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * Intel TDX KVM VM, vCPU, Secure-EPT mirror, and guest_memfd live update
 * kexec selftest.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/kvm.h>
#include <linux/liveupdate.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"

#include <libliveupdate.h>

#define SESSION_NAME		"tdx_luo_kexec_test"
#define STATE_SESSION_NAME	"tdx_luo_kexec_test_state"
#define STATE_TOKEN		1

#define TOKEN_TD_VM		0x100
#define TOKEN_TD_VCPU		0x101
#define TOKEN_TD_GMEM		0x102
#define TOKEN_ABORT_TD_VM	0x200
#define TOKEN_ABORT_TD_VCPU	0x201

#define TD_GMEM_GPA		0x100000ULL
#define TD_GMEM_SLOT		1
#define TD_GMEM_SIZE		SZ_2M
#define TD_MAX_CPUID_ENTRIES	256

struct tdx_test_ctx {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	int gmem_fd;
};

static int tdx_cmd(int fd, __u32 id, __u32 flags, void *data)
{
	struct kvm_tdx_cmd cmd = {
		.id = id,
		.flags = flags,
		.data = (__u64)(unsigned long)data,
	};

	if (ioctl(fd, KVM_MEMORY_ENCRYPT_OP, &cmd))
		return -errno;
	return 0;
}

static void setup_finalized_td(struct tdx_test_ctx *ctx, bool with_gmem)
{
	struct {
		struct kvm_tdx_capabilities caps;
		struct kvm_cpuid_entry2 entries[TD_MAX_CPUID_ENTRIES];
	} cap_buf;
	struct {
		struct kvm_tdx_init_vm init_vm;
		struct kvm_cpuid_entry2 entries[TD_MAX_CPUID_ENTRIES];
	} init_buf;
	struct {
		struct kvm_cpuid2 cpuid;
		struct kvm_cpuid_entry2 entries[TD_MAX_CPUID_ENTRIES];
	} host_cpuid;
	struct kvm_enable_cap split_irqchip = {
		.cap = KVM_CAP_SPLIT_IRQCHIP,
		.args[0] = 24,
	};

	memset(ctx, -1, sizeof(*ctx));

	ctx->kvm_fd = open_kvm_dev_path_or_exit();
	ctx->vm_fd = ioctl(ctx->kvm_fd, KVM_CREATE_VM,
			   (unsigned long)KVM_X86_TDX_VM);
	TEST_ASSERT(ctx->vm_fd >= 0, "KVM_CREATE_VM(KVM_X86_TDX_VM) failed: %d",
		    errno);

	TEST_ASSERT_EQ(ioctl(ctx->vm_fd, KVM_ENABLE_CAP, &split_irqchip), 0);

	memset(&cap_buf, 0, sizeof(cap_buf));
	cap_buf.caps.cpuid.nent = TD_MAX_CPUID_ENTRIES;
	TEST_ASSERT_EQ(tdx_cmd(ctx->vm_fd, KVM_TDX_CAPABILITIES, 0,
			       &cap_buf.caps), 0);

	memset(&host_cpuid, 0, sizeof(host_cpuid));
	host_cpuid.cpuid.nent = TD_MAX_CPUID_ENTRIES;
	TEST_ASSERT_EQ(ioctl(ctx->kvm_fd, KVM_GET_SUPPORTED_CPUID,
			     &host_cpuid.cpuid), 0);

	memset(&init_buf, 0, sizeof(init_buf));
	init_buf.init_vm.xfam = XFEATURE_MASK_FP | XFEATURE_MASK_SSE;
	for (uint32_t i = 0; i < host_cpuid.cpuid.nent; i++) {
		const struct kvm_cpuid_entry2 *src = &host_cpuid.entries[i];
		const struct kvm_cpuid_entry2 *conf = NULL;
		struct kvm_cpuid_entry2 *dst;

		for (uint32_t j = 0; j < cap_buf.caps.cpuid.nent; j++) {
			if (cap_buf.entries[j].function == src->function &&
			    cap_buf.entries[j].index == src->index) {
				conf = &cap_buf.entries[j];
				break;
			}
		}
		if (!conf)
			continue;

		dst = &init_buf.entries[init_buf.init_vm.cpuid.nent++];
		*dst = *src;
		dst->eax &= conf->eax;
		dst->ebx &= conf->ebx;
		dst->ecx &= conf->ecx;
		dst->edx &= conf->edx;
		if (dst->function == 0x80000008)
			dst->eax = (dst->eax & ~0xff0000u) | (48u << 16);
	}

	{
		int ret, tries = 0;

		do {
			ret = tdx_cmd(ctx->vm_fd, KVM_TDX_INIT_VM, 0,
				      &init_buf.init_vm);
		} while (ret == -EAGAIN && ++tries < 16);
		TEST_ASSERT_EQ(ret, 0);
	}

	ctx->vcpu_fd = ioctl(ctx->vm_fd, KVM_CREATE_VCPU, 0UL);
	TEST_ASSERT(ctx->vcpu_fd >= 0, "KVM_CREATE_VCPU failed: %d", errno);
	TEST_ASSERT_EQ(ioctl(ctx->vcpu_fd, KVM_SET_CPUID2, &host_cpuid.cpuid),
		       0);
	TEST_ASSERT_EQ(tdx_cmd(ctx->vcpu_fd, KVM_TDX_INIT_VCPU, 0, NULL), 0);

	if (with_gmem) {
		struct kvm_create_guest_memfd gmem_create = {
			.size = TD_GMEM_SIZE,
		};
		struct kvm_userspace_memory_region2 region = {
			.slot = TD_GMEM_SLOT,
			.flags = KVM_MEM_GUEST_MEMFD,
			.guest_phys_addr = TD_GMEM_GPA,
			.memory_size = TD_GMEM_SIZE,
		};
		struct kvm_tdx_init_mem_region mem_region = {
			.gpa = TD_GMEM_GPA,
			.nr_pages = 1,
		};
		void *src_page, *userspace_mem;

		ctx->gmem_fd = ioctl(ctx->vm_fd, KVM_CREATE_GUEST_MEMFD,
				     &gmem_create);
		TEST_ASSERT(ctx->gmem_fd >= 0,
			    "KVM_CREATE_GUEST_MEMFD failed: %d", errno);

		userspace_mem = mmap(NULL, TD_GMEM_SIZE, PROT_READ | PROT_WRITE,
				     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		TEST_ASSERT(userspace_mem != MAP_FAILED, "mmap failed");

		region.userspace_addr = (unsigned long)userspace_mem;
		region.guest_memfd = ctx->gmem_fd;
		TEST_ASSERT_EQ(ioctl(ctx->vm_fd,
				     KVM_SET_USER_MEMORY_REGION2, &region), 0);
		gmem_set_private(ctx->gmem_fd, 0, TD_GMEM_SIZE);

		src_page = mmap(NULL, SZ_4K, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		TEST_ASSERT(src_page != MAP_FAILED, "mmap src_page failed");
		memset(src_page, 0x5a, SZ_4K);
		mem_region.source_addr = (unsigned long)src_page;
		TEST_ASSERT_EQ(tdx_cmd(ctx->vcpu_fd, KVM_TDX_INIT_MEM_REGION,
				       KVM_TDX_MEASURE_MEMORY_REGION,
				       &mem_region), 0);
		munmap(src_page, SZ_4K);
	}

	TEST_ASSERT_EQ(tdx_cmd(ctx->vm_fd, KVM_TDX_FINALIZE_VM, 0, NULL), 0);
}

static void cleanup_td(struct tdx_test_ctx *ctx)
{
	if (ctx->gmem_fd >= 0)
		close(ctx->gmem_fd);
	if (ctx->vcpu_fd >= 0)
		close(ctx->vcpu_fd);
	if (ctx->vm_fd >= 0)
		close(ctx->vm_fd);
	if (ctx->kvm_fd >= 0)
		close(ctx->kvm_fd);
}

static void run_single_kernel_test(void)
{
	struct tdx_test_ctx ctx;
	int luo_fd, session_fd, uninit_kvm_fd, uninit_vm_fd;

	luo_fd = luo_open_device();
	if (luo_fd < 0)
		ksft_exit_skip("%s is not available\n", LUO_DEVICE);

	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "luo_create_session failed: %d",
		    session_fd);

	/* Preserving an uninitialized TD VM must fail with -EINVAL. */
	uninit_kvm_fd = open_kvm_dev_path_or_exit();
	uninit_vm_fd = ioctl(uninit_kvm_fd, KVM_CREATE_VM,
			     (unsigned long)KVM_X86_TDX_VM);
	TEST_ASSERT(uninit_vm_fd >= 0, "KVM_CREATE_VM(KVM_X86_TDX_VM) failed");
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, uninit_vm_fd, 1),
		       -EINVAL);
	close(uninit_vm_fd);
	close(uninit_kvm_fd);

	setup_finalized_td(&ctx, true);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, ctx.vm_fd,
					       TOKEN_TD_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, ctx.vcpu_fd,
					 TOKEN_TD_VCPU), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, ctx.gmem_fd,
					       TOKEN_TD_GMEM), 0);

	/* Punching holes on a preserved TD's guest_memfd must fail. */
	TEST_ASSERT_EQ(fallocate(ctx.gmem_fd,
				 FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
				 0, SZ_4K), -1);
	TEST_ASSERT_EQ(errno, EPERM);

	/* Closing the session exercises unpreserve on TD VM, S-EPT, and vCPU. */
	close(session_fd);
	cleanup_td(&ctx);
	close(luo_fd);

	ksft_print_header();
	ksft_set_plan(1);
	ksft_test_result_pass("tdx_luo_preserve_unpreserve\n");
	ksft_finished();
}

static void stage1(int luo_fd)
{
	struct tdx_test_ctx td_ctx, abort_ctx;
	int session_fd;

	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_TOKEN, 2);

	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "luo_create_session failed: %d",
		    session_fd);

	setup_finalized_td(&td_ctx, true);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, td_ctx.vm_fd,
					       TOKEN_TD_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, td_ctx.vcpu_fd,
					 TOKEN_TD_VCPU), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, td_ctx.gmem_fd,
					       TOKEN_TD_GMEM), 0);

	setup_finalized_td(&abort_ctx, false);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, abort_ctx.vm_fd,
					       TOKEN_ABORT_TD_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, abort_ctx.vcpu_fd,
					 TOKEN_ABORT_TD_VCPU), 0);

	close(luo_fd);
	daemonize_and_wait();
}

static void stage2(int luo_fd, int state_session_fd)
{
	struct kvm_guest_memfd_luo_retrieve gmem_arg = {
		.size = sizeof(gmem_arg),
	};
	struct kvm_userspace_memory_region2 region = {
		.slot = TD_GMEM_SLOT,
		.flags = KVM_MEM_GUEST_MEMFD,
		.guest_phys_addr = TD_GMEM_GPA,
		.memory_size = TD_GMEM_SIZE,
	};
	int session_fd, stage, vm_fd, vcpu_fd, gmem_fd;
	struct kvm_vm *default_vm;
	struct kvm_run *run;
	void *userspace_mem;

	restore_and_read_stage(state_session_fd, STATE_TOKEN, &stage);
	TEST_ASSERT_EQ(stage, 2);

	session_fd = luo_retrieve_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "luo_retrieve_session failed: %d",
		    session_fd);

	ksft_print_header();
	ksft_set_plan(2);

	/* Cross-type retrieve against a default non-TDX VM must fail. */
	default_vm = vm_create_barebones();
	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, TOKEN_TD_VCPU,
					 default_vm->fd), -EINVAL);
	gmem_arg.vm_fd = default_vm->fd;
	TEST_ASSERT_EQ(luo_session_retrieve_fd_arg(session_fd, TOKEN_TD_GMEM,
						   (unsigned long)&gmem_arg),
		       -EINVAL);
	kvm_vm_free(default_vm);

	vm_fd = luo_session_retrieve_fd(session_fd, TOKEN_TD_VM);
	TEST_ASSERT(vm_fd >= 0, "Retrieving TD VM failed: %d", vm_fd);

	vcpu_fd = luo_retrieve_vcpu(session_fd, TOKEN_TD_VCPU, vm_fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving TD vCPU failed: %d", vcpu_fd);

	gmem_arg.vm_fd = vm_fd;
	gmem_fd = luo_session_retrieve_fd_arg(session_fd, TOKEN_TD_GMEM,
					      (unsigned long)&gmem_arg);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving TD guest_memfd failed: %d",
		    gmem_fd);
	if (kvm_has_gmem_attributes) {
		u64 err_off = 0;

		TEST_ASSERT_EQ(__gmem_set_shared(gmem_fd, 0, SZ_4K, &err_off), -1);
		TEST_ASSERT_EQ(errno, EBUSY);
	}

	userspace_mem = mmap(NULL, TD_GMEM_SIZE, PROT_READ | PROT_WRITE,
			     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(userspace_mem != MAP_FAILED, "mmap failed");
	region.userspace_addr = (unsigned long)userspace_mem;
	region.guest_memfd = gmem_fd;
	TEST_ASSERT_EQ(ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region), 0);

	run = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		   vcpu_fd, 0);
	TEST_ASSERT(run != MAP_FAILED, "mmap kvm_run failed");
	run->immediate_exit = 1;
	TEST_ASSERT_EQ(ioctl(vcpu_fd, KVM_RUN, 0), -1);
	TEST_ASSERT_EQ(errno, EINTR);
	munmap(run, PAGE_SIZE);

	ksft_test_result_pass("tdx_luo_retrieve\n");

	/*
	 * TOKEN_ABORT_TD_VM and TOKEN_ABORT_TD_VCPU are left unretrieved so
	 * luo_session_finish() exercises unretrieved TD/VP SEAMCALL teardown.
	 */
	TEST_ASSERT_EQ(luo_session_finish(session_fd), 0);
	ksft_test_result_pass("tdx_luo_abort_teardown\n");

	close(gmem_fd);
	close(vcpu_fd);
	close(vm_fd);
	munmap(userspace_mem, TD_GMEM_SIZE);
	close(session_fd);
	TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
	close(state_session_fd);

	ksft_print_msg("TDX LIVE UPDATE TEST PASSED\n");
	ksft_finished();
}

int main(int argc, char *argv[])
{
	int luo_fd;

	luo_fd = luo_open_device();
	if (luo_fd < 0)
		ksft_exit_skip("%s is not available\n", LUO_DEVICE);
	close(luo_fd);

	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_TDX_VM)))
		ksft_exit_skip("KVM_X86_TDX_VM is not supported\n");
	if (!kvm_has_gmem_attributes)
		ksft_exit_skip("KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES is not supported\n");

	if (argc == 1) {
		run_single_kernel_test();
		return 0;
	}

	return luo_test(argc, argv, STATE_SESSION_NAME, stage1, stage2);
}
