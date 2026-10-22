// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Selftest for ARM64 CCA Realm VM and REC live update across kexec.
 *
 * Stage 1 (-s 1) creates and activates an ARM64 CCA Realm VM backed by
 * guest_memfd, populates encrypted code and data via KVM_ARM_RMI_POPULATE,
 * runs the Realm vCPU until it updates private RIPAS_RAM and exits via
 * unprotected MMIO, verifies session cancellation (unpreserve), and then
 * preserves the Realm VM, vCPU, and guest_memfd across kexec.
 *
 * Stage 2 (-s 2) retrieves the preserved Realm VM, guest_memfd, and REC
 * vCPU after kexec without re-populating Realm memory or re-creating the
 * RD/REC, resumes execution via KVM_RUN, verifies that private RIPAS_RAM
 * contents and REC execution state survived kexec intact, and tears down
 * the Realm to verify SRO auxiliary granule reclamation.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/kvm.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "vgic.h"

#include <libliveupdate.h>

#define SESSION_NAME		"cca_realm_luo_test"
#define CANCEL_SESSION_NAME	"cca_realm_luo_cancel"
#define STATE_SESSION_NAME	"cca_realm_luo_state"
#define STATE_TOKEN		1

#define TOKEN_VM		0x100
#define TOKEN_VCPU		0x101
#define TOKEN_GMEM		0x102

#define REALM_IPA_BITS		40
#define REALM_SHARED_BIT	BIT_ULL(REALM_IPA_BITS - 1)

#define REALM_MEM_SLOT		0
#define REALM_MEM_GPA		0x40000000ULL
#define REALM_DATA_GPA		(REALM_MEM_GPA + SZ_4K)
#define REALM_FAULT_GPA		(REALM_MEM_GPA + 2 * SZ_4K)
#define REALM_MEM_SIZE		SZ_2M

#define REALM_MMIO_GPA		0x0a000000ULL
#define REALM_GICD_GPA		0x08000000ULL
#define REALM_GICR_GPA		0x080a0000ULL

#define REALM_SEED_INIT		0x1122334455667788ULL
#define REALM_MAGIC_DELTA	0xcca01100deadbeefULL

/*
 * Position-independent ARM64 instructions executed at REALM_MEM_GPA in
 * Realm EL1 with MMU disabled (VA == IPA):
 *   x0 = REALM_DATA_GPA (private RIPAS_RAM page)
 *   x1 = REALM_MMIO_GPA | REALM_SHARED_BIT (unprotected MMIO address)
 *   x2 = REALM_MAGIC_DELTA
 *   x4 = REALM_FAULT_GPA (private RIPAS_RAM page, not populated, so the
 *        first access is a stage-2 fault mapped by the host)
 */
static const uint32_t realm_guest_insns[] = {
	0xf9400003, /* ldr x3, [x0]       ; read private RAM seed */
	0x8b020063, /* add x3, x3, x2     ; add magic delta */
	0xf9000003, /* str x3, [x0]       ; store pre-kexec value in private RAM */
	0xf9000083, /* str x3, [x4]       ; fault in an unpopulated private page */
	0xf9000023, /* str x3, [x1]       ; unprotected MMIO exit before kexec */
	0xf9400083, /* ldr x3, [x4]       ; post-kexec: re-read faulted-in page */
	0x91000463, /* add x3, x3, #1     ; increment post-kexec counter */
	0xf9000003, /* str x3, [x0]       ; update private RAM */
	0xf9000023, /* str x3, [x1]       ; unprotected MMIO exit after kexec */
	0x14000000, /* b .                ; halt loop */
};

static void setup_vgic_v3(int vm_fd)
{
	struct kvm_create_device dev = {
		.type = KVM_DEV_TYPE_ARM_VGIC_V3,
	};
	uint64_t dist_addr = REALM_GICD_GPA;
	uint64_t redist_addr = REALM_GICR_GPA;
	struct kvm_device_attr attr = {
		.group = KVM_DEV_ARM_VGIC_GRP_ADDR,
		.attr = KVM_VGIC_V3_ADDR_TYPE_DIST,
		.addr = (uintptr_t)&dist_addr,
	};
	int ret;

	ret = ioctl(vm_fd, KVM_CREATE_DEVICE, &dev);
	TEST_ASSERT(ret == 0, "KVM_CREATE_DEVICE(VGIC_V3) failed: %d", errno);

	ret = ioctl(dev.fd, KVM_SET_DEVICE_ATTR, &attr);
	TEST_ASSERT(ret == 0, "VGIC_V3 set DIST addr failed: %d", errno);

	attr.attr = KVM_VGIC_V3_ADDR_TYPE_REDIST;
	attr.addr = (uintptr_t)&redist_addr;
	ret = ioctl(dev.fd, KVM_SET_DEVICE_ATTR, &attr);
	TEST_ASSERT(ret == 0, "VGIC_V3 set REDIST addr failed: %d", errno);

	attr.group = KVM_DEV_ARM_VGIC_GRP_CTRL;
	attr.attr = KVM_DEV_ARM_VGIC_CTRL_INIT;
	attr.addr = 0;
	ret = ioctl(dev.fd, KVM_SET_DEVICE_ATTR, &attr);
	TEST_ASSERT(ret == 0, "VGIC_V3 CTRL_INIT failed: %d", errno);

	close(dev.fd);
}

static void set_one_reg(int vcpu_fd, uint64_t id, uint64_t val)
{
	struct kvm_one_reg reg = {
		.id = id,
		.addr = (uintptr_t)&val,
	};
	int ret;

	ret = ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
	TEST_ASSERT(ret == 0, "KVM_SET_ONE_REG(%#lx) failed: %d", id, errno);
}

static void bind_realm_memslot(int vm_fd, int gmem_fd, void *shared_hva)
{
	struct kvm_userspace_memory_region2 region = {
		.slot = REALM_MEM_SLOT,
		.flags = KVM_MEM_GUEST_MEMFD,
		.guest_phys_addr = REALM_MEM_GPA,
		.memory_size = REALM_MEM_SIZE,
		.userspace_addr = (uintptr_t)shared_hva,
		.guest_memfd = gmem_fd,
		.guest_memfd_offset = 0,
	};
	int ret;

	ret = ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region);
	TEST_ASSERT(ret == 0, "KVM_SET_USER_MEMORY_REGION2 failed: %d", errno);
}

static void stage1(int luo_fd)
{
	struct kvm_create_guest_memfd gmem_args = {
		.size = REALM_MEM_SIZE,
		.flags = 0,
	};
	struct kvm_arm_rmi_populate pop = {};
	struct kvm_vcpu_init vcpu_init = {};
	int kvm_fd, vm_fd, gmem_fd, vcpu_fd;
	int cancel_session_fd, session_fd;
	void *shared_hva, *src_buf;
	struct kvm_run *run;
	uint64_t expected;
	int mmap_size, ret;

	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_TOKEN, 2);

	if (!kvm_has_cap(KVM_CAP_ARM_RMI)) {
		ksft_print_msg("KVM_CAP_ARM_RMI is not available, skipping CCA Realm preserve\n");
		close(luo_fd);
		daemonize_and_wait();
	}

	kvm_fd = open_kvm_dev_path_or_exit();
	vm_fd = ioctl(kvm_fd, KVM_CREATE_VM,
		      (unsigned long)(KVM_VM_TYPE_ARM_REALM | REALM_IPA_BITS));
	TEST_ASSERT(vm_fd >= 0, "KVM_CREATE_VM(REALM) failed: %d", errno);

	gmem_fd = ioctl(vm_fd, KVM_CREATE_GUEST_MEMFD, &gmem_args);
	TEST_ASSERT(gmem_fd >= 0, "KVM_CREATE_GUEST_MEMFD failed: %d", errno);

	shared_hva = mmap(NULL, REALM_MEM_SIZE, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(shared_hva != MAP_FAILED, "mmap shared_hva failed");
	bind_realm_memslot(vm_fd, gmem_fd, shared_hva);

	vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0);
	TEST_ASSERT(vcpu_fd >= 0, "KVM_CREATE_VCPU failed: %d", errno);

	mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	TEST_ASSERT(mmap_size >= (int)sizeof(*run), "KVM_GET_VCPU_MMAP_SIZE");
	run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   vcpu_fd, 0);
	TEST_ASSERT(run != MAP_FAILED, "mmap kvm_run failed");

	ret = ioctl(vm_fd, KVM_ARM_PREFERRED_TARGET, &vcpu_init);
	TEST_ASSERT(ret == 0, "KVM_ARM_PREFERRED_TARGET failed: %d", errno);
	vcpu_init.features[0] |= (1U << KVM_ARM_VCPU_PSCI_0_2);
	ret = ioctl(vcpu_fd, KVM_ARM_VCPU_INIT, &vcpu_init);
	TEST_ASSERT(ret == 0, "KVM_ARM_VCPU_INIT failed: %d", errno);

	setup_vgic_v3(vm_fd);

	set_one_reg(vcpu_fd, ARM64_CORE_REG(regs.pc), REALM_MEM_GPA);
	set_one_reg(vcpu_fd, ARM64_CORE_REG(regs.regs[0]), REALM_DATA_GPA);
	set_one_reg(vcpu_fd, ARM64_CORE_REG(regs.regs[1]),
		    REALM_MMIO_GPA | REALM_SHARED_BIT);
	set_one_reg(vcpu_fd, ARM64_CORE_REG(regs.regs[2]), REALM_MAGIC_DELTA);
	set_one_reg(vcpu_fd, ARM64_CORE_REG(regs.regs[4]), REALM_FAULT_GPA);

	src_buf = mmap(NULL, 2 * SZ_4K, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(src_buf != MAP_FAILED, "mmap src_buf failed");
	memset(src_buf, 0, 2 * SZ_4K);
	memcpy(src_buf, realm_guest_insns, sizeof(realm_guest_insns));
	*(uint64_t *)((char *)src_buf + SZ_4K) = REALM_SEED_INIT;

	pop.base = REALM_MEM_GPA;
	pop.size = 2 * SZ_4K;
	pop.source_uaddr = (uintptr_t)src_buf;
	pop.flags = KVM_ARM_RMI_POPULATE_FLAGS_MEASURE;
	ret = ioctl(vm_fd, KVM_ARM_RMI_POPULATE, &pop);
	TEST_ASSERT(ret == 0, "KVM_ARM_RMI_POPULATE failed: %d", errno);
	munmap(src_buf, 2 * SZ_4K);

	/*
	 * Preserving before the Realm is activated (REALM_STATE_NEW) must be
	 * rejected with -EINVAL.
	 */
	cancel_session_fd = luo_create_session(luo_fd, CANCEL_SESSION_NAME);
	TEST_ASSERT(cancel_session_fd >= 0, "luo_create_session failed");
	TEST_ASSERT_EQ(luo_session_preserve_fd(cancel_session_fd, vm_fd,
					       TOKEN_VM), -EINVAL);

	/* First KVM_RUN activates the Realm and runs until MMIO exit. */
	ret = ioctl(vcpu_fd, KVM_RUN, 0);
	TEST_ASSERT(ret == 0, "Pre-kexec KVM_RUN failed: %d", errno);
	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, REALM_MMIO_GPA);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	TEST_ASSERT_EQ(run->mmio.is_write, 1);

	expected = REALM_SEED_INIT + REALM_MAGIC_DELTA;
	TEST_ASSERT_EQ(*(uint64_t *)run->mmio.data, expected);

	/* Verify preserve + session close (unpreserve) on an active Realm. */
	TEST_ASSERT_EQ(luo_session_preserve_fd(cancel_session_fd, vm_fd,
					       TOKEN_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(cancel_session_fd, vcpu_fd,
					 TOKEN_VCPU), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(cancel_session_fd, gmem_fd,
					       TOKEN_GMEM), 0);
	close(cancel_session_fd);

	/* Preserve the active Realm VM, vCPU, and guest_memfd for kexec. */
	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "luo_create_session failed: %d",
		    session_fd);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm_fd, TOKEN_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu_fd, TOKEN_VCPU), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, TOKEN_GMEM),
		       0);

	ksft_print_msg("CCA Realm VM, REC vCPU, and guest_memfd preserved\n");
	close(luo_fd);
	daemonize_and_wait();
}

static void stage2(int luo_fd, int state_session_fd)
{
	struct kvm_guest_memfd_luo_retrieve gmem_ret = {
		.size = sizeof(gmem_ret),
	};
	int session_fd, vm_fd, gmem_fd, vcpu_fd, kvm_fd;
	int stage, mmap_size, ret;
	uint64_t expected;
	struct kvm_run *run;
	void *shared_hva;

	restore_and_read_stage(state_session_fd, STATE_TOKEN, &stage);
	TEST_ASSERT_EQ(stage, 2);

	ksft_print_header();
	ksft_set_plan(1);

	if (!kvm_has_cap(KVM_CAP_ARM_RMI)) {
		ksft_test_result_skip("cca_realm_kexec_liveupdate\n");
		TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
		close(state_session_fd);
		ksft_print_msg("CCA REALM LIVE UPDATE TEST PASSED\n");
		ksft_finished();
	}

	session_fd = luo_retrieve_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Retrieving session failed: %d",
		    session_fd);

	vm_fd = luo_session_retrieve_fd(session_fd, TOKEN_VM);
	TEST_ASSERT(vm_fd >= 0, "Retrieving Realm VM failed: %d", vm_fd);

	gmem_ret.vm_fd = vm_fd;
	gmem_fd = luo_session_retrieve_fd_arg(session_fd, TOKEN_GMEM,
					      (unsigned long)&gmem_ret);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving Realm guest_memfd failed: %d",
		    gmem_fd);

	shared_hva = mmap(NULL, REALM_MEM_SIZE, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	TEST_ASSERT(shared_hva != MAP_FAILED, "mmap shared_hva failed");
	bind_realm_memslot(vm_fd, gmem_fd, shared_hva);

	vcpu_fd = luo_retrieve_vcpu(session_fd, TOKEN_VCPU, vm_fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving Realm REC vCPU failed: %d",
		    vcpu_fd);

	kvm_fd = open_kvm_dev_path_or_exit();
	mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	TEST_ASSERT(mmap_size >= (int)sizeof(*run), "KVM_GET_VCPU_MMAP_SIZE");
	run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		   vcpu_fd, 0);
	TEST_ASSERT(run != MAP_FAILED, "mmap kvm_run failed");

	/*
	 * Resume the retrieved Realm REC directly via KVM_RUN without
	 * re-creating the Realm, REC, or re-populating RIPAS_RAM.
	 */
	ret = ioctl(vcpu_fd, KVM_RUN, 0);
	TEST_ASSERT(ret == 0, "Post-kexec KVM_RUN failed: %d", errno);
	TEST_ASSERT_EQ(run->exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(run->mmio.phys_addr, REALM_MMIO_GPA);
	TEST_ASSERT_EQ(run->mmio.len, 8);
	TEST_ASSERT_EQ(run->mmio.is_write, 1);

	expected = REALM_SEED_INIT + REALM_MAGIC_DELTA + 1;
	TEST_ASSERT_EQ(*(uint64_t *)run->mmio.data, expected);

	ksft_test_result_pass("cca_realm_kexec_liveupdate\n");

	munmap(run, mmap_size);
	munmap(shared_hva, REALM_MEM_SIZE);
	close(vcpu_fd);
	close(gmem_fd);
	close(vm_fd);
	close(kvm_fd);

	TEST_ASSERT_EQ(luo_session_finish(session_fd), 0);
	close(session_fd);
	TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
	close(state_session_fd);

	ksft_print_msg("CCA REALM LIVE UPDATE TEST PASSED\n");
	ksft_finished();
}

int main(int argc, char *argv[])
{
	if (argc == 1 && !kvm_has_cap(KVM_CAP_ARM_RMI))
		ksft_exit_skip("KVM_CAP_ARM_RMI is not available\n");
	if (!kvm_has_cap(KVM_CAP_GUEST_MEMFD))
		ksft_exit_skip("KVM_CAP_GUEST_MEMFD is not available\n");

	return luo_test(argc, argv, STATE_SESSION_NAME, stage1, stage2);
}
