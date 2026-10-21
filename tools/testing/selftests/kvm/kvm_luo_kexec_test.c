// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Live update of KVM VMs and guest_memfd across a kexec reboot.
 *
 * Stage 1 (-s 1) runs before the reboot. It preserves the objects of every
 * scenario in a live update session and leaves a child process behind that
 * keeps the session open until the reboot. Stage 2 (-s 2) runs after the
 * reboot, retrieves the objects and checks them. The test can run as the test
 * binary of tools/testing/selftests/liveupdate/vmtest.sh, which performs the
 * reboot.
 */
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <linux/sizes.h>

#include "kvm_util.h"
#include "test_util.h"
#include "ucall_common.h"

#include <libliveupdate.h>

#define SESSION_NAME		"kvm_luo_kexec_test"
#define STATE_SESSION_NAME	"kvm_luo_kexec_test_state"
#define STATE_TOKEN		1

#define GMEM_GPA		SZ_4G
#define GMEM_SLOT		1
#define GMEM_SIZE		SZ_2M
#define GMEM_FLAGS		(GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED)

struct scenario {
	const char *name;
	void (*preserve)(int session_fd, u64 token);
	/* Return KSFT_PASS or KSFT_SKIP, failures abort the test. */
	int (*check)(int session_fd, u64 token);
};

/* Fill or check the first @size bytes of the guest_memfd with a pattern. */
static void guest_code(u64 gpa, u64 size, u64 seed, u64 check)
{
	u64 *mem = (u64 *)gpa;
	u64 i;

	for (i = 0; i < size / sizeof(*mem); i++) {
		if (check)
			__GUEST_ASSERT(mem[i] == (seed ^ i),
				       "mem[%lu] = 0x%lx, expected 0x%lx",
				       i, mem[i], seed ^ i);
		else
			mem[i] = seed ^ i;
	}

	GUEST_DONE();
}

/* Create a VM with one vCPU, or set one up around the VM @vm_fd. */
static struct kvm_vm *create_vm(int vm_fd, struct kvm_vcpu **vcpu)
{
	/* Room for the page tables that map a guest_memfd. */
	u64 extra_pages = GMEM_SIZE / SZ_4K;
	struct kvm_vm *vm;

	if (vm_fd < 0)
		vm = __vm_create(VM_SHAPE_DEFAULT, 1, extra_pages);
	else
		vm = vm_create_from_fd(vm_fd, VM_SHAPE_DEFAULT, 1, extra_pages);

	*vcpu = vm_vcpu_add(vm, 0, guest_code);
	kvm_arch_vm_finalize_vcpus(vm);

	return vm;
}

static void run_guest(struct kvm_vcpu *vcpu, u64 size, u64 seed, bool check)
{
	struct ucall uc;

	vcpu_args_set(vcpu, 4, GMEM_GPA, size, seed, (uint64_t)check);
	vcpu_run(vcpu);

	switch (get_ucall(vcpu, &uc)) {
	case UCALL_DONE:
		break;
	case UCALL_ABORT:
		REPORT_GUEST_ASSERT(uc);
		break;
	default:
		TEST_FAIL("Unexpected exit: %s",
			  exit_reason_str(vcpu->run->exit_reason));
	}
}

/* Use the guest_memfd @gmem_fd as guest memory at GMEM_GPA. */
static void map_gmem(struct kvm_vm *vm, int gmem_fd)
{
	vm_set_user_memory_region2(vm, GMEM_SLOT, KVM_MEM_GUEST_MEMFD, GMEM_GPA,
				   GMEM_SIZE, NULL, gmem_fd, 0);
	virt_map(vm, GMEM_GPA, GMEM_GPA, GMEM_SIZE / vm->page_size);
}

static int retrieve_gmem(int session_fd, u64 token, u32 size, u32 vm_fd)
{
	struct kvm_guest_memfd_luo_retrieve arg = {
		.size = size,
		.vm_fd = vm_fd,
	};

	return luo_session_retrieve_fd_arg(session_fd, token,
					   (unsigned long)&arg);
}

/*
 * Create a VM with a guest_memfd, let the guest fill the guest_memfd with a
 * pattern derived from @token and return the guest_memfd. The VM is returned
 * in @vmp, or freed if @vmp is NULL.
 */
static int create_gmem(u64 token, struct kvm_vm **vmp)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int gmem_fd;

	vm = create_vm(-1, &vcpu);
	gmem_fd = vm_create_guest_memfd(vm, GMEM_SIZE, GMEM_FLAGS);
	map_gmem(vm, gmem_fd);
	run_guest(vcpu, GMEM_SIZE, token, false);

	if (vmp)
		*vmp = vm;
	else
		kvm_vm_free(vm);

	return gmem_fd;
}

/* Bind the retrieved guest_memfd to @vm and check the pattern. */
static void check_gmem(struct kvm_vm *vm, struct kvm_vcpu *vcpu, int gmem_fd,
		       u64 token)
{
	u64 *mem;

	map_gmem(vm, gmem_fd);
	run_guest(vcpu, GMEM_SIZE, token, true);

	mem = kvm_mmap(GMEM_SIZE, PROT_READ, MAP_SHARED, gmem_fd);
	TEST_ASSERT_EQ(mem[0], token);
	TEST_ASSERT_EQ(mem[GMEM_SIZE / sizeof(*mem) - 1],
		       token ^ (GMEM_SIZE / sizeof(*mem) - 1));
	kvm_munmap(mem, GMEM_SIZE);
}

/* Preserve the VM only. Its memory is not preserved. */
static void vm_only_preserve(int session_fd, u64 token)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = create_vm(-1, &vcpu);
	run_guest(vcpu, 0, 0, false);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, token), 0);
}

static int vm_only_check(int session_fd, u64 token)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int vm_fd;

	/* The VM handler takes no argument, and refusing it consumes nothing. */
	TEST_ASSERT_EQ(luo_session_retrieve_fd_arg(session_fd, token, 1),
		       -EOPNOTSUPP);

	vm_fd = luo_session_retrieve_fd(session_fd, token);
	TEST_ASSERT(vm_fd >= 0, "Retrieving the VM failed: %d", vm_fd);

	vm = create_vm(vm_fd, &vcpu);
	run_guest(vcpu, 0, 0, false);
	kvm_vm_free(vm);

	return KSFT_PASS;
}

/*
 * Preserve a guest_memfd only, and close it and its VM. After the reboot, bind
 * it to a new VM.
 */
static void gmem_only_preserve(int session_fd, u64 token)
{
	int gmem_fd = create_gmem(token, NULL);

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token), 0);
	close(gmem_fd);
}

static int gmem_only_check(int session_fd, u64 token)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int gmem_fd;

	vm = create_vm(-1, &vcpu);
	gmem_fd = retrieve_gmem(session_fd, token, sizeof(struct kvm_guest_memfd_luo_retrieve),
				vm->fd);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving the guest_memfd failed: %d",
		    gmem_fd);

	check_gmem(vm, vcpu, gmem_fd, token);
	close(gmem_fd);
	kvm_vm_free(vm);

	return KSFT_PASS;
}

/* Preserve a VM and its guest_memfd, and bind them again after the reboot. */
static void vm_and_gmem_preserve(int session_fd, u64 token)
{
	struct kvm_vm *vm;
	int gmem_fd;

	gmem_fd = create_gmem(token, &vm);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, token), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token + 1),
		       0);
}

static int vm_and_gmem_check(int session_fd, u64 token)
{
	u32 size = sizeof(struct kvm_guest_memfd_luo_retrieve);
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int vm_fd, gmem_fd;

	vm_fd = luo_session_retrieve_fd(session_fd, token);
	TEST_ASSERT(vm_fd >= 0, "Retrieving the VM failed: %d", vm_fd);
	vm = create_vm(vm_fd, &vcpu);

	gmem_fd = retrieve_gmem(session_fd, token + 1, size, vm->fd);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving the guest_memfd failed: %d",
		    gmem_fd);

	/* The argument cannot be applied to a guest_memfd retrieved before. */
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token + 1, size, vm->fd),
		       -EBUSY);

	check_gmem(vm, vcpu, gmem_fd, token);
	close(gmem_fd);
	kvm_vm_free(vm);

	return KSFT_PASS;
}

/*
 * Retrieving a guest_memfd with a missing or unsuitable VM fails without
 * consuming the preserved guest_memfd.
 */
static void retrieve_errors_preserve(int session_fd, u64 token)
{
	int gmem_fd = create_gmem(token, NULL);

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token), 0);
	close(gmem_fd);
}

static int retrieve_errors_check(int session_fd, u64 token)
{
	u32 size = sizeof(struct kvm_guest_memfd_luo_retrieve);
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int gmem_fd, status;
	pid_t pid;

	vm = create_vm(-1, &vcpu);

	/* No VM. */
	TEST_ASSERT_EQ(luo_session_retrieve_fd(session_fd, token), -EINVAL);
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token, sizeof(u32), vm->fd),
		       -EINVAL);

	/* Not a VM. */
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token, size, -1), -EBADF);
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token, size, session_fd),
		       -EINVAL);

#ifdef __x86_64__
	/* A VM that cannot use the guest_memfd. */
	if (kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM)) {
		struct kvm_vm *private_vm;

		private_vm = vm_create_barebones_type(KVM_X86_SW_PROTECTED_VM);
		TEST_ASSERT_EQ(retrieve_gmem(session_fd, token, size,
					     private_vm->fd), -EINVAL);
		kvm_vm_free(private_vm);
	}
#endif

	/* A VM of another process. */
	pid = fork();
	TEST_ASSERT(pid >= 0, "fork() failed");
	if (!pid)
		_exit(retrieve_gmem(session_fd, token, size, vm->fd) != -EIO);
	TEST_ASSERT_EQ(waitpid(pid, &status, 0), pid);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "Retrieving with a VM of another process did not fail with EIO");

	gmem_fd = retrieve_gmem(session_fd, token, size, vm->fd);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving the guest_memfd failed: %d",
		    gmem_fd);

	check_gmem(vm, vcpu, gmem_fd, token);
	close(gmem_fd);
	kvm_vm_free(vm);

	return KSFT_PASS;
}

/* A guest_memfd that is not retrieved is freed when the session finishes. */
static void not_retrieved_preserve(int session_fd, u64 token)
{
	int gmem_fd = create_gmem(token, NULL);

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token), 0);
	close(gmem_fd);
}

static int not_retrieved_check(int session_fd, u64 token)
{
	return KSFT_PASS;
}

#define SCENARIO(_name) { #_name, _name##_preserve, _name##_check }

static const struct scenario scenarios[] = {
	SCENARIO(vm_only),
	SCENARIO(gmem_only),
	SCENARIO(vm_and_gmem),
	SCENARIO(retrieve_errors),
	SCENARIO(not_retrieved),
};

/* Every scenario uses up to two tokens, starting at its own base. */
static u64 scenario_token(int i)
{
	return 0x100 * (i + 1);
}

static void stage1(int luo_fd)
{
	int session_fd, i;

	create_state_file(luo_fd, STATE_SESSION_NAME, STATE_TOKEN, 2);

	session_fd = luo_create_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Creating the session failed: %d",
		    session_fd);

	for (i = 0; i < ARRAY_SIZE(scenarios); i++) {
		scenarios[i].preserve(session_fd, scenario_token(i));
		ksft_print_msg("%s: preserved\n", scenarios[i].name);
	}

	close(luo_fd);
	daemonize_and_wait();
}

static void stage2(int luo_fd, int state_session_fd)
{
	int session_fd, stage, i;

	restore_and_read_stage(state_session_fd, STATE_TOKEN, &stage);
	TEST_ASSERT_EQ(stage, 2);

	session_fd = luo_retrieve_session(luo_fd, SESSION_NAME);
	TEST_ASSERT(session_fd >= 0, "Retrieving the session failed: %d",
		    session_fd);

	ksft_print_header();
	ksft_set_plan(ARRAY_SIZE(scenarios));

	for (i = 0; i < ARRAY_SIZE(scenarios); i++) {
		if (scenarios[i].check(session_fd, scenario_token(i)) == KSFT_SKIP)
			ksft_test_result_skip("%s\n", scenarios[i].name);
		else
			ksft_test_result_pass("%s\n", scenarios[i].name);
	}

	TEST_ASSERT_EQ(luo_session_finish(session_fd), 0);
	close(session_fd);
	TEST_ASSERT_EQ(luo_session_finish(state_session_fd), 0);
	close(state_session_fd);

	ksft_print_msg("KVM LIVE UPDATE TEST PASSED\n");
	ksft_finished();
}

int main(int argc, char *argv[])
{
	TEST_REQUIRE(kvm_has_cap(KVM_CAP_GUEST_MEMFD));
	TEST_REQUIRE((kvm_check_cap(KVM_CAP_GUEST_MEMFD_FLAGS) & GMEM_FLAGS) ==
		     GMEM_FLAGS);

	return luo_test(argc, argv, STATE_SESSION_NAME, stage1, stage2);
}
