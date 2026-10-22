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
 * reboot, see kvm_luo_vmtest.sh.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <linux/falloc.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"
#ifdef __x86_64__
#include "apic.h"
#endif

#include <libliveupdate.h>

#define SESSION_NAME		"kvm_luo_kexec_test"
#define STATE_SESSION_NAME	"kvm_luo_kexec_test_state"
#define STATE_TOKEN		1

#define GMEM_GPA		SZ_4G
#define GMEM_SLOT		1
#define GMEM_SIZE		SZ_2M
#define GMEM_FLAGS		(GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED)

#define VCPU_RESUME_IO_PORT	0x99
#define VCPU_RESUME_MMIO_GPA	0x0a000000ULL
#define VCPU_RESUME_TIMER_CNT	0x1234567800ULL

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

#ifdef __x86_64__
static u64 vcpu_resume_timer_fired;

static void vcpu_resume_timer_handler(struct ex_regs *regs)
{
	WRITE_ONCE(vcpu_resume_timer_fired, 1);
	x2apic_write_reg(APIC_EOI, 0);
}
#endif

static void vcpu_resume_guest_code(u64 gpa, u64 seed)
{
	u64 *mem = (u64 *)gpa;
	u64 local_acc = seed ^ 0x0f0f0f0f0f0f0f0fULL;
	u64 i;

#ifdef __x86_64__
	if (this_cpu_has(X86_FEATURE_XSAVE))
		set_cr4(get_cr4() | X86_CR4_OSXSAVE);
	wrmsr(MSR_KVM_SYSTEM_TIME_NEW, (gpa + SZ_4K) | 1);

	x2apic_enable();
	x2apic_write_reg(APIC_TDCR, 0xb);
	x2apic_write_reg(APIC_LVTT, 0xec);
	x2apic_write_reg(APIC_TMICT, 1);
	sti_nop();
	while (!READ_ONCE(vcpu_resume_timer_fired))
		cpu_relax();
	while (x2apic_read_reg(APIC_TMCCT) != 0)
		cpu_relax();
	cli();
#elif defined(__aarch64__)
	{
		u64 cnt = read_sysreg(cntvct_el0);

		__GUEST_ASSERT(cnt >= VCPU_RESUME_TIMER_CNT,
			       "cntvct_el0 = 0x%lx < 0x%lx",
			       cnt, (u64)VCPU_RESUME_TIMER_CNT);
		write_sysreg(local_acc, tpidr_el0);
	}
#endif

	for (i = 0; i < 64; i++)
		WRITE_ONCE(mem[i], local_acc ^ i);

#ifdef __x86_64__
	outl(VCPU_RESUME_IO_PORT, 0x5a);
#elif defined(__aarch64__)
	WRITE_ONCE(*(u32 *)VCPU_RESUME_MMIO_GPA, 0x5a5a5a5aU);
#else
	GUEST_SYNC(1);
#endif

#ifdef __x86_64__
	__GUEST_ASSERT(x2apic_read_reg(APIC_TMICT) == 1,
		       "APIC_TMICT = 0x%lx, expected 1",
		       x2apic_read_reg(APIC_TMICT));
	__GUEST_ASSERT(!(x2apic_read_reg(APIC_IRR + 0x70) & BIT(12)),
		       "Expired one-shot LAPIC timer re-fired after kexec");
#elif defined(__aarch64__)
	{
		u64 cnt = read_sysreg(cntvct_el0);

		__GUEST_ASSERT(cnt >= VCPU_RESUME_TIMER_CNT,
			       "post-kexec cntvct_el0 = 0x%lx < 0x%lx",
			       cnt, (u64)VCPU_RESUME_TIMER_CNT);
		__GUEST_ASSERT(read_sysreg(tpidr_el0) == local_acc,
			       "post-kexec tpidr_el0 = 0x%lx, expected 0x%lx",
			       read_sysreg(tpidr_el0), local_acc);
	}
#endif

	for (i = 0; i < 64; i++) {
		__GUEST_ASSERT(READ_ONCE(mem[i]) == (local_acc ^ i),
			       "mem[%lu] = 0x%lx, expected 0x%lx",
			       i, READ_ONCE(mem[i]), local_acc ^ i);
		WRITE_ONCE(mem[64 + i], ~local_acc ^ i);
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
 * Run a guest vCPU up to a userspace I/O exit before kexec, preserve the VM,
 * guest_memfd, and vCPU, and resume guest execution from the preserved vCPU
 * state after kexec without re-initializing vCPU registers from userspace.
 */
static void vcpu_resume_preserve(int session_fd, u64 token)
{
	u64 extra_pages = GMEM_SIZE / SZ_4K;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int gmem_fd;

	vm = __vm_create(VM_SHAPE_DEFAULT, 1, extra_pages);
#ifdef __x86_64__
	if (kvm_check_cap(KVM_CAP_EXCEPTION_PAYLOAD))
		vm_enable_cap(vm, KVM_CAP_EXCEPTION_PAYLOAD, 1);
	vm_install_exception_handler(vm, 0xec, vcpu_resume_timer_handler);
#endif
	gmem_fd = vm_create_guest_memfd(vm, GMEM_SIZE, GMEM_FLAGS);
	map_gmem(vm, gmem_fd);
#ifdef __aarch64__
	virt_pg_map(vm, VCPU_RESUME_MMIO_GPA, VCPU_RESUME_MMIO_GPA);
#endif

	vcpu = vm_vcpu_add(vm, 0, vcpu_resume_guest_code);
	kvm_arch_vm_finalize_vcpus(vm);

#ifdef __x86_64__
	{
		struct kvm_regs regs;

		vcpu_regs_get(vcpu, &regs);
		regs.rsp = GMEM_GPA + GMEM_SIZE - 8;
		vcpu_regs_set(vcpu, &regs);
	}
#elif defined(__aarch64__)
	vcpu_set_reg(vcpu, ctxt_reg_alias(vcpu, SYS_SP_EL1),
		     GMEM_GPA + GMEM_SIZE - 16);
	vcpu_set_reg(vcpu, KVM_REG_ARM_TIMER_CNT, VCPU_RESUME_TIMER_CNT);
#endif

	vcpu_args_set(vcpu, 2, GMEM_GPA, token);
	vcpu_run(vcpu);
#ifdef __x86_64__
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(vcpu->run->io.port, VCPU_RESUME_IO_PORT);
	vcpu_run_complete_io(vcpu);
	{
		struct kvm_pit_config pit_config = {};
		struct kvm_pit_state2 pit_state = {};

		vm_ioctl(vm, KVM_CREATE_PIT2, &pit_config);
		vm_ioctl(vm, KVM_GET_PIT2, &pit_state);
		pit_state.channels[0].mode = 2;
		pit_state.channels[0].count = 16;
		vm_ioctl(vm, KVM_SET_PIT2, &pit_state);
	}
#elif defined(__aarch64__)
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_MMIO);
	TEST_ASSERT_EQ(vcpu->run->mmio.phys_addr, VCPU_RESUME_MMIO_GPA);
#else
	{
		struct ucall uc;

		TEST_ASSERT_EQ(get_ucall(vcpu, &uc), UCALL_SYNC);
		TEST_ASSERT_EQ(uc.args[1], 1);
	}
#endif

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, token), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token + 1),
		       0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu->fd, token + 2), 0);
}

static int vcpu_resume_check(int session_fd, u64 token)
{
	u32 size = sizeof(struct kvm_guest_memfd_luo_retrieve);
	u64 local_acc = token ^ 0x0f0f0f0f0f0f0f0fULL;
	u64 extra_pages = GMEM_SIZE / SZ_4K;
	int vm_fd, gmem_fd, vcpu_fd;
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	struct ucall uc;
	u64 *mem;
	u64 i;

	vm_fd = luo_session_retrieve_fd(session_fd, token);
	TEST_ASSERT(vm_fd >= 0, "Retrieving the VM failed: %d", vm_fd);
	vm = vm_create_from_fd(vm_fd, VM_SHAPE_DEFAULT, 1, extra_pages);
#ifdef __x86_64__
	/*
	 * Give any prematurely armed PIT hrtimer a window to fire while
	 * online_vcpus is still 0 before vCPU retrieval.
	 */
	usleep(2000);
#endif

	/*
	 * Retrieve the vCPU before binding guest_memfd memslots to verify
	 * lazy paravirtual GPA activation when memslots are not yet present.
	 */
	vcpu_fd = luo_retrieve_vcpu(session_fd, token + 2, vm->fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving the vCPU failed: %d", vcpu_fd);
#ifdef __x86_64__
	{
		struct kvm_pit_state2 pit_state;

		usleep(2000);
		vm_ioctl(vm, KVM_GET_PIT2, &pit_state);
		TEST_ASSERT_EQ(pit_state.channels[0].mode, 2);
		TEST_ASSERT_EQ(pit_state.channels[0].count, 16);
	}
#endif

	gmem_fd = retrieve_gmem(session_fd, token + 1, size, vm->fd);
	TEST_ASSERT(gmem_fd >= 0, "Retrieving the guest_memfd failed: %d",
		    gmem_fd);
	map_gmem(vm, gmem_fd);

	vcpu = vm_vcpu_add_from_fd(vm, 0, vcpu_fd);
	kvm_arch_vm_finalize_vcpus(vm);

#ifdef __x86_64__
	if (kvm_check_cap(KVM_CAP_EXCEPTION_PAYLOAD)) {
		struct kvm_vcpu_events ev;

		vcpu_events_get(vcpu, &ev);
		ev.exception.injected = 0;
		ev.exception.pending = 1;
		ev.exception.nr = PF_VECTOR;
		ev.exception.has_error_code = 1;
		ev.exception.error_code = 0;
		ev.exception_has_payload = 1;
		ev.exception_payload = 0xdeadbeef00ULL;
		vcpu_events_set(vcpu, &ev);

		memset(&ev, 0, sizeof(ev));
		vcpu_events_get(vcpu, &ev);
		TEST_ASSERT_EQ(ev.exception_has_payload, 1);
		TEST_ASSERT_EQ(ev.exception_payload, 0xdeadbeef00ULL);

		ev.exception.pending = 0;
		ev.exception.injected = 0;
		ev.exception_has_payload = 0;
		ev.exception_payload = 0;
		vcpu_events_set(vcpu, &ev);
	}
#endif

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

	mem = kvm_mmap(GMEM_SIZE, PROT_READ, MAP_SHARED, gmem_fd);
	for (i = 0; i < 64; i++) {
		TEST_ASSERT_EQ(mem[i], local_acc ^ i);
		TEST_ASSERT_EQ(mem[64 + i], ~local_acc ^ i);
	}
	kvm_munmap(mem, GMEM_SIZE);

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

/*
 * Retrieving a vCPU with a missing, invalid, or wrong parent VM fails without
 * consuming the preserved vCPU.
 */
static void vcpu_retrieve_errors_preserve(int session_fd, u64 token)
{
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;

	vm = create_vm(-1, &vcpu);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, token), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu->fd, token + 1), 0);
}

static int vcpu_retrieve_errors_check(int session_fd, u64 token)
{
	struct kvm_vcpu_luo_retrieve bad_size = {
		.size = sizeof(u32),
	};
	struct kvm_vcpu *other_vcpu;
	struct kvm_vm *other_vm;
	int vm_fd, vcpu_fd, status;
	pid_t pid;

	vm_fd = luo_session_retrieve_fd(session_fd, token);
	TEST_ASSERT(vm_fd >= 0, "Retrieving the VM failed: %d", vm_fd);
	bad_size.vm_fd = vm_fd;

	other_vm = create_vm(-1, &other_vcpu);

	/* Missing or malformed argument. */
	TEST_ASSERT_EQ(luo_session_retrieve_fd(session_fd, token + 1), -EINVAL);
	TEST_ASSERT_EQ(luo_session_retrieve_fd_arg(session_fd, token + 1,
						   (unsigned long)&bad_size),
		       -EINVAL);

	/* Invalid or non-VM fd. */
	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1, -1), -EBADF);
	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1, session_fd),
		       -EINVAL);

	/* VM that already has a vCPU with the same vcpu_id. */
	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1, other_vm->fd),
		       -EEXIST);

#ifdef __x86_64__
	if (kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM)) {
		struct kvm_vm *private_vm;

		private_vm = vm_create_barebones_type(KVM_X86_SW_PROTECTED_VM);
		TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1,
						 private_vm->fd), -EINVAL);
		kvm_vm_free(private_vm);
	}
#endif

	/* VM accessed from another process. */
	pid = fork();
	TEST_ASSERT(pid >= 0, "fork() failed");
	if (!pid)
		_exit(luo_retrieve_vcpu(session_fd, token + 1, vm_fd) != -EIO);
	TEST_ASSERT_EQ(waitpid(pid, &status, 0), pid);
	TEST_ASSERT(WIFEXITED(status) && !WEXITSTATUS(status),
		    "Retrieving vCPU in another process did not fail with EIO");

	vcpu_fd = luo_retrieve_vcpu(session_fd, token + 1, vm_fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving the vCPU failed: %d", vcpu_fd);

	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1, vm_fd), -EBUSY);

	close(vcpu_fd);
	close(vm_fd);
	kvm_vm_free(other_vm);

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

#define REQUIRE_UNKNOWN_FEATURE \
	"/sys/module/liveupdate_test/parameters/require_unknown_feature"

static int require_unknown_feature(const char *handler)
{
	int fd, ret;

	fd = open(REQUIRE_UNKNOWN_FEATURE, O_WRONLY);
	if (fd < 0)
		return -errno;

	ret = write(fd, handler, strlen(handler)) < 0 ? -errno : 0;
	close(fd);
	return ret;
}

/*
 * A guest_memfd that requires a feature the kernel does not implement, as if
 * it was preserved by a newer kernel, cannot be retrieved. This needs
 * CONFIG_LIVEUPDATE_TEST.
 */
static void feature_mismatch_preserve(int session_fd, u64 token)
{
	int gmem_fd;

	if (require_unknown_feature("guest_memfd"))
		return;

	gmem_fd = create_gmem(token, NULL);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_fd, token), 0);
	close(gmem_fd);

	TEST_ASSERT_EQ(require_unknown_feature("\n"), 0);
}

static int feature_mismatch_check(int session_fd, u64 token)
{
	u32 size = sizeof(struct kvm_guest_memfd_luo_retrieve);
	struct kvm_vcpu *vcpu;
	struct kvm_vm *vm;
	int ret;

	vm = create_vm(-1, &vcpu);

	ret = retrieve_gmem(session_fd, token, size, vm->fd);
	if (ret == -ENOENT) {
		kvm_vm_free(vm);
		return KSFT_SKIP;
	}
	TEST_ASSERT_EQ(ret, -EOPNOTSUPP);

	/* The failure is permanent. */
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token, size, vm->fd),
		       -EOPNOTSUPP);

	kvm_vm_free(vm);

	return KSFT_PASS;
}

/*
 * Preserve a KVM_X86_SW_PROTECTED_VM, its vCPU, an init-shared guest_memfd
 * whose first page is converted to private, and an init-private guest_memfd
 * whose second page is converted to shared. Verify that private folios, shared
 * folios, and per-page attributes survive kexec.
 */
static void sw_protected_preserve(int session_fd, u64 token)
{
#ifdef __x86_64__
	u64 local_acc = token ^ 0x0f0f0f0f0f0f0f0fULL;
	struct vm_shape shape = VM_SHAPE_DEFAULT;
	u64 extra_pages = GMEM_SIZE / SZ_4K;
	size_t page_size = getpagesize();
	int gmem_conv, gmem_priv;
	struct kvm_vcpu *vcpu;
	struct kvm_regs regs;
	struct kvm_vm *vm;
	u64 *mem, err_off;

	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM)))
		return;
	if (!(kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) &
	      KVM_MEMORY_ATTRIBUTE_PRIVATE))
		return;

	WRITE_ONCE(vcpu_resume_timer_fired, 0);
	shape.type = KVM_X86_SW_PROTECTED_VM;
	vm = __vm_create(shape, 1, extra_pages);
	vm_install_exception_handler(vm, 0xec, vcpu_resume_timer_handler);

	gmem_conv = vm_create_guest_memfd(vm, GMEM_SIZE, GMEM_FLAGS);
	map_gmem(vm, gmem_conv);
	TEST_ASSERT_EQ(__gmem_set_private(gmem_conv, 0, page_size, &err_off), 0);

	vcpu = vm_vcpu_add(vm, 0, vcpu_resume_guest_code);
	kvm_arch_vm_finalize_vcpus(vm);

	vcpu_regs_get(vcpu, &regs);
	regs.rsp = GMEM_GPA + GMEM_SIZE - 8;
	vcpu_regs_set(vcpu, &regs);

	vcpu_args_set(vcpu, 2, GMEM_GPA, token);
	vcpu_run(vcpu);
	TEST_ASSERT_EQ(vcpu->run->exit_reason, KVM_EXIT_IO);
	TEST_ASSERT_EQ(vcpu->run->io.port, VCPU_RESUME_IO_PORT);
	vcpu_run_complete_io(vcpu);

	gmem_priv = vm_create_guest_memfd(vm, GMEM_SIZE, GUEST_MEMFD_FLAG_MMAP);
	TEST_ASSERT_EQ(fallocate(gmem_priv, FALLOC_FL_KEEP_SIZE, 0, page_size),
		       0);
	TEST_ASSERT_EQ(__gmem_set_shared(gmem_priv, page_size, page_size,
					 &err_off), 0);
	mem = kvm_mmap(GMEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED,
		       gmem_priv);
	WRITE_ONCE(mem[page_size / sizeof(*mem)], local_acc);
	kvm_munmap(mem, GMEM_SIZE);

	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, vm->fd, token), 0);
	TEST_ASSERT_EQ(luo_preserve_vcpu(session_fd, vcpu->fd, token + 1), 0);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_conv,
					       token + 2), 0);
	TEST_ASSERT_EQ(__gmem_set_shared(gmem_conv, 0, page_size, &err_off), -1);
	TEST_ASSERT_EQ(errno, EPERM);
	TEST_ASSERT_EQ(luo_session_preserve_fd(session_fd, gmem_priv,
					       token + 3), 0);
#endif
}

static int sw_protected_check(int session_fd, u64 token)
{
#ifdef __x86_64__
	u32 size = sizeof(struct kvm_guest_memfd_luo_retrieve);
	u64 local_acc = token ^ 0x0f0f0f0f0f0f0f0fULL;
	struct vm_shape shape = VM_SHAPE_DEFAULT;
	u64 extra_pages = GMEM_SIZE / SZ_4K;
	int vm_fd, vcpu_fd, gmem_conv, gmem_priv;
	size_t page_size = getpagesize();
	struct kvm_vm *default_vm, *vm;
	struct kvm_vcpu *vcpu;
	struct ucall uc;
	u64 *mem, err_off;
	u64 i;

	if (!(kvm_check_cap(KVM_CAP_VM_TYPES) & BIT(KVM_X86_SW_PROTECTED_VM)))
		return KSFT_SKIP;
	if (!(kvm_check_cap(KVM_CAP_GUEST_MEMFD_MEMORY_ATTRIBUTES) &
	      KVM_MEMORY_ATTRIBUTE_PRIVATE))
		return KSFT_SKIP;

	/* Cross-type retrieve with a default VM must fail with EINVAL. */
	default_vm = vm_create_barebones();
	TEST_ASSERT_EQ(luo_retrieve_vcpu(session_fd, token + 1,
					 default_vm->fd), -EINVAL);
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token + 2, size,
				     default_vm->fd), -EINVAL);
	TEST_ASSERT_EQ(retrieve_gmem(session_fd, token + 3, size,
				     default_vm->fd), -EINVAL);
	kvm_vm_free(default_vm);

	vm_fd = luo_session_retrieve_fd(session_fd, token);
	TEST_ASSERT(vm_fd >= 0, "Retrieving SW_PROTECTED_VM failed: %d", vm_fd);

	shape.type = KVM_X86_SW_PROTECTED_VM;
	vm = vm_create_from_fd(vm_fd, shape, 1, extra_pages);

	vcpu_fd = luo_retrieve_vcpu(session_fd, token + 1, vm->fd);
	TEST_ASSERT(vcpu_fd >= 0, "Retrieving SW_PROTECTED vCPU failed: %d",
		    vcpu_fd);

	gmem_conv = retrieve_gmem(session_fd, token + 2, size, vm->fd);
	TEST_ASSERT(gmem_conv >= 0, "Retrieving gmem_conv failed: %d",
		    gmem_conv);
	map_gmem(vm, gmem_conv);

	gmem_priv = retrieve_gmem(session_fd, token + 3, size, vm->fd);
	TEST_ASSERT(gmem_priv >= 0, "Retrieving gmem_priv failed: %d",
		    gmem_priv);

	vcpu = vm_vcpu_add_from_fd(vm, 0, vcpu_fd);
	kvm_arch_vm_finalize_vcpus(vm);

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

	mem = kvm_mmap(GMEM_SIZE, PROT_READ, MAP_SHARED, gmem_conv);
	TEST_EXPECT_SIGBUS((void)READ_ONCE(mem[0]));
	TEST_ASSERT_EQ(__gmem_set_shared(gmem_conv, 0, page_size, &err_off), 0);
	for (i = 0; i < 64; i++) {
		TEST_ASSERT_EQ(mem[i], local_acc ^ i);
		TEST_ASSERT_EQ(mem[64 + i], ~local_acc ^ i);
	}
	kvm_munmap(mem, GMEM_SIZE);

	mem = kvm_mmap(GMEM_SIZE, PROT_READ, MAP_SHARED, gmem_priv);
	TEST_EXPECT_SIGBUS((void)READ_ONCE(mem[0]));
	TEST_ASSERT_EQ(READ_ONCE(mem[page_size / sizeof(*mem)]), local_acc);
	kvm_munmap(mem, GMEM_SIZE);

	close(gmem_priv);
	close(gmem_conv);
	kvm_vm_free(vm);

	return KSFT_PASS;
#else
	return KSFT_SKIP;
#endif
}

#define SCENARIO(_name) { #_name, _name##_preserve, _name##_check }

static const struct scenario scenarios[] = {
	SCENARIO(vm_only),
	SCENARIO(gmem_only),
	SCENARIO(vm_and_gmem),
	SCENARIO(vcpu_resume),
	SCENARIO(retrieve_errors),
	SCENARIO(vcpu_retrieve_errors),
	SCENARIO(not_retrieved),
	SCENARIO(feature_mismatch),
	SCENARIO(sw_protected),
};

/* Every scenario has its own range of tokens, starting at its base. */
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
