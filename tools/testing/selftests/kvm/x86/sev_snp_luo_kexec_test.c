// SPDX-License-Identifier: GPL-2.0-only
/*
 * Live update of AMD SEV-SNP KVM VMs, vCPUs, and private guest_memfd across
 * a kexec reboot.
 *
 * Stage 1 (-s 1) runs before the reboot:
 *   1. Exercises pre-kexec preserve + unpreserve rollback on an active
 *      KVM_X86_SNP_VM and verifies the guest continues execution and tears
 *      down cleanly without leaking RMP entries.
 *   2. Launches an active KVM_X86_SNP_VM, runs the vCPU until its first GHCB
 *      MSR sync point after writing to encrypted private memory, preserves the
 *      VM, vCPU, and backing guest_memfd in a live update session, and leaves
 *      a daemonized child holding the session open across kexec.
 *   3. Preserves a second KVM_X86_SNP_VM that is left unretrieved in Stage 2
 *      to exercise abort teardown (VMSA RMP reclaim + SNP_DECOMMISSION).
 *
 * Stage 2 (-s 2) runs after the kexec reboot:
 *   1. Retrieves the preserved KVM_X86_SNP_VM, its backing guest_memfd, and
 *      its vCPU.
 *   2. Rebinds the preserved guest_memfd memslot and runs the vCPU to verify
 *      lazy NPT reconstruction and private guest memory integrity across kexec.
 *   3. Finishes the live update session to trigger abort cleanup of the
 *      unretrieved SNP VM and finish the sev-snp-v1 FLB.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/sizes.h>

#include "kvm_util.h"
#include "processor.h"
#include "sev.h"
#include "svm_util.h"
#include "test_util.h"

#include <libliveupdate.h>

#define SESSION_NAME		"sev_snp_luo_kexec_test"
#define CANCEL_SESSION_NAME	"sev_snp_luo_cancel_test"
#define STATE_SESSION_NAME	"sev_snp_luo_kexec_test_state"
#define STATE_TOKEN		1

#define TOKEN_SNP_VM		0x100
#define TOKEN_SNP_VCPU		0x101
#define TOKEN_SNP_GMEM		0x102
#define TOKEN_SNP_META		0x103

#define TOKEN_ABORT_VM		0x200
#define TOKEN_ABORT_VCPU	0x201
#define TOKEN_ABORT_GMEM	0x202

#define GHCB_MSR_SYNC_STAGE1	(GHCB_MSR_TERM_REQ | (1ULL << 16))
#define GHCB_MSR_SYNC_STAGE2	(GHCB_MSR_TERM_REQ | (2ULL << 16))

static u64 snp_private_cookie;

static void guest_snp_luo_code(void)
{
	u64 sev_msr = rdmsr(MSR_AMD64_SEV);

	GUEST_ASSERT(sev_msr & MSR_AMD64_SEV_ENABLED);
	GUEST_ASSERT(sev_msr & MSR_AMD64_SEV_ES_ENABLED);
	GUEST_ASSERT(sev_msr & MSR_AMD64_SEV_SNP_ENABLED);

	WRITE_ONCE(snp_private_cookie, 0x534e504c554f3031ULL);

	/* Pause at Stage 1 sync point before live update preservation. */
	wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_SYNC_STAGE1);
	vmgexit();

	/* Verify encrypted private memory and register state after resume. */
	GUEST_ASSERT(READ_ONCE(snp_private_cookie) == 0x534e504c554f3031ULL);
	WRITE_ONCE(snp_private_cookie, 0x534e504c554f3032ULL);

	wrmsr(MSR_AMD64_SEV_ES_GHCB, GHCB_MSR_SYNC_STAGE2);
	vmgexit();
}

static void assert_snp_term_sync(struct kvm_run *run, u64 expected_ghcb)
{
	TEST_ASSERT(run->exit_reason == KVM_EXIT_SYSTEM_EVENT,
		    "Wanted KVM_EXIT_SYSTEM_EVENT, got %s",
		    exit_reason_str(run->exit_reason));
	TEST_ASSERT_EQ(run->system_event.type, KVM_SYSTEM_EVENT_SEV_TERM);
	TEST_ASSERT_EQ(run->system_event.ndata, 1);
	TEST_ASSERT_EQ(run->system_event.data[0], expected_ghcb);
}

static int retrieve_gmem(int session_fd, u64 token, u64 size, int vm_fd)
{
	struct kvm_guest_memfd_luo_retrieve arg = {
		.size = sizeof(arg),
		.vm_fd = vm_fd,
	};

	(void)size;
	return luo_session_retrieve_fd_arg(session_fd, token,
					   (unsigned long)&arg);
}

/*
 * Test pre-kexec preserve + unpreserve rollback on an active SEV-SNP VM.
 * Closing the session before kexec must unpreserve the VM, vCPU, guest_memfd,
 * and sev-snp-v1 FLB cleanly so that the guest can continue running and the
 * VM can be destroyed without RMP page or ASID leaks.
 */
static void test_snp_preserve_cancel(int luo_fd)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int session_fd;
	int gmem_fd;

	session_fd = luo_create_session(luo_fd, CANCEL_SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "luo_create_session failed: %d",
		    session_fd);

	vm = vm_sev_create_with_one_vcpu(KVM_X86_SNP_VM, guest_snp_luo_code,
					 &vcpu);
	vm_sev_launch(vm, snp_default_policy(), NULL);

	vcpu_run(vcpu);
	assert_snp_term_sync(vcpu->run, GHCB_MSR_SYNC_STAGE1);

	gmem_fd = kvm_slot_to_fd(vm, 0);
	TEST_ASSERT(gmem_fd >= 0, "Expected valid slot 0 guest_memfd");

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd,
					       TOKEN_SNP_VM), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu->fd,
					 TOKEN_SNP_VCPU), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd,
					       TOKEN_SNP_GMEM), 0);

	/* Cancel preservation by closing the session. */
	close(session_fd);

	/* Verify the SNP vCPU can still resume and complete Stage 2. */
	vcpu_run(vcpu);
	assert_snp_term_sync(vcpu->run, GHCB_MSR_SYNC_STAGE2);

	kvm_vm_free(vm);
	ksft_print_msg("snp_preserve_cancel: passed\n");
}

static void preserve_one_snp_vm(int session_fd, u64 vm_tok, u64 vcpu_tok,
				u64 gmem_tok, u64 *slot0_size_out)
{
	struct userspace_mem_region *slot0;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = vm_sev_create_with_one_vcpu(KVM_X86_SNP_VM, guest_snp_luo_code,
					 &vcpu);
	vm_sev_launch(vm, snp_default_policy(), NULL);

	vcpu_run(vcpu);
	assert_snp_term_sync(vcpu->run, GHCB_MSR_SYNC_STAGE1);

	slot0 = memslot2region(vm, 0);
	TEST_ASSERT(slot0 && slot0->fd >= 0, "Missing slot 0 guest_memfd");

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, vm_tok), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu->fd, vcpu_tok), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, slot0->fd,
					       gmem_tok), 0);

	if (slot0_size_out)
		*slot0_size_out = slot0->region.memory_size;
}

static void stage1(int luo_fd)
{
	u64 slot0_size = 0;
	char meta_buf[64];
	int session_fd;

	test_snp_preserve_cancel(luo_fd);

	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_TOKEN, 2);

	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Creating session failed: %d", session_fd);

	preserve_one_snp_vm(session_fd, TOKEN_SNP_VM, TOKEN_SNP_VCPU,
			    TOKEN_SNP_GMEM, &slot0_size);
	snprintf(meta_buf, sizeof(meta_buf), "%llu",
		 (unsigned long long)slot0_size);
	TEST_ASSERT_EQ(create_and_preserve_memfd(session_fd, TOKEN_SNP_META,
						 meta_buf), 0);

	/* Second SNP VM left unretrieved in Stage 2 to test abort cleanup. */
	preserve_one_snp_vm(session_fd, TOKEN_ABORT_VM, TOKEN_ABORT_VCPU,
			    TOKEN_ABORT_GMEM, NULL);

	close(luo_fd);
	daemonize_and_wait();
}

static void stage2(int luo_fd, int state_session_fd)
{
	struct kvm_userspace_memory_region2 region = {};
	int session_fd, stage, meta_fd;
	int vm_fd, vcpu_fd, gmem_fd;
	struct kvm_run *run;
	u64 slot0_size = 0;
	char meta_buf[64];
	int kvm_fd, mmap_sz;
	void *slot0_hva;

	restore_and_read_stage(state_session_fd, STATE_TOKEN, &stage);
	TEST_ASSERT_EQ(stage, 2);

	session_fd = luo_retrieve_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Retrieving session failed: %d",
		    session_fd);

	ksft_print_header();
	ksft_set_plan(1);

	meta_fd = restore_and_verify_memfd(session_fd, TOKEN_SNP_META, NULL);
	TEST_ASSERT(meta_fd >= 0, "Retrieving metadata memfd failed: %d",
		    meta_fd);
	memset(meta_buf, 0, sizeof(meta_buf));
	TEST_ASSERT(read(meta_fd, meta_buf, sizeof(meta_buf) - 1) > 0,
		    "Reading metadata memfd failed");
	slot0_size = strtoull(meta_buf, NULL, 10);
	TEST_ASSERT(slot0_size > 0, "Invalid slot0_size: %llu",
		    (unsigned long long)slot0_size);
	close(meta_fd);

	vm_fd = luo_session_retrieve_fd(session_fd, TOKEN_SNP_VM);
	TEST_ASSERT(vm_fd >= 0, "Retrieving SNP VM failed: %d", vm_fd);

	gmem_fd = retrieve_gmem(session_fd, TOKEN_SNP_GMEM, slot0_size, vm_fd);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving SNP guest_memfd failed: %d",
		    gmem_fd);

	slot0_hva = mmap(NULL, slot0_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			 gmem_fd, 0);
	TEST_ASSERT(slot0_hva != MAP_FAILED, "mmap of retrieved gmem failed");

	region.slot = 0;
	region.flags = KVM_MEM_GUEST_MEMFD;
	region.guest_phys_addr = 0;
	region.memory_size = slot0_size;
	region.userspace_addr = (unsigned long)slot0_hva;
	region.guest_memfd = gmem_fd;
	region.guest_memfd_offset = 0;
	TEST_ASSERT_EQ(ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION2, &region), 0);

	vcpu_fd = luo_retrieve_vcpu(session_fd, TOKEN_SNP_VCPU, vm_fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving SNP vCPU failed: %d", vcpu_fd);

	kvm_fd = open_kvm_dev_path_or_exit();
	mmap_sz = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	TEST_ASSERT(mmap_sz >= (int)sizeof(*run), "Invalid vCPU mmap size: %d",
		    mmap_sz);
	close(kvm_fd);

	run = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE, MAP_SHARED,
		   vcpu_fd, 0);
	TEST_ASSERT(run != MAP_FAILED, "mmap vcpu_run failed");

	TEST_ASSERT_EQ(ioctl(vcpu_fd, KVM_RUN, NULL), 0);
	assert_snp_term_sync(run, GHCB_MSR_SYNC_STAGE2);

	munmap(run, mmap_sz);
	munmap(slot0_hva, slot0_size);
	close(vcpu_fd);
	close(gmem_fd);
	close(vm_fd);

	/* Finish session: also triggers abort cleanup of TOKEN_ABORT_* VM. */
	TEST_ASSERT_EQ(luo_session_finish(session_fd), 0);
	close(session_fd);
	TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
	close(state_session_fd);

	ksft_test_result_pass("sev_snp_luo_kexec\n");
	ksft_print_msg("SEV-SNP LIVE UPDATE TEST PASSED\n");
	ksft_finished();
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_cpu_has(X86_FEATURE_SEV_SNP));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD));
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES));

	return luo_test(argc, argv, STATE_SESSION_NAME, stage1, stage2);
}
