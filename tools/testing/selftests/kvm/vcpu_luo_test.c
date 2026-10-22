// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Tests for preserving KVM vCPUs and VMs for live update that need no reboot.
 * Closing a session before the reboot cancels the preservation of its files,
 * so these tests run on any kernel with live update enabled.
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "kvm_util.h"
#include "processor.h"
#include "test_util.h"
#include "ucall_common.h"
#include "kselftest_harness.h"

#include <libliveupdate.h>

#define VCPU_LUO_HANDLER	"kvm-vcpu"
#define SESSION_NAME		"kvm_vcpu_luo_test"

static void guest_code(void)
{
#ifdef __x86_64__
	if (this_cpu_has(X86_FEATURE_XSAVE))
		set_cr4(get_cr4() | X86_CR4_OSXSAVE);
	wrmsr(MSR_KVM_SYSTEM_TIME_NEW, 0x2000 | 1);
#endif
	GUEST_SYNC(1);
	GUEST_DONE();
}

static int preserve_fd(int session_fd, int fd, __u64 token,
		       const char *handler, __u64 arg)
{
	struct liveupdate_session_preserve_fd args = {
		.size = sizeof(args),
		.fd = fd,
		.token = token,
		.arg = arg,
	};

	if (handler)
		strncpy(args.handler, handler, sizeof(args.handler) - 1);

	if (ioctl(session_fd, LIVEUPDATE_SESSION_PRESERVE_FD, &args))
		return -errno;

	return 0;
}

FIXTURE(vcpu_luo) {
	int luo_fd;
	int session_fd;
	struct kvm_vm *vm;
	struct kvm_vcpu *vcpu;
	struct kvm_vcpu *vcpu2;
};

FIXTURE_SETUP(vcpu_luo)
{
	self->luo_fd = -1;
	self->session_fd = -1;
	self->vm = NULL;
	self->vcpu = NULL;
	self->vcpu2 = NULL;

	self->luo_fd = luo_open_device();
	if (self->luo_fd < 0)
		SKIP(return, "%s is not available", LUO_DEVICE);

	self->session_fd = luo_create_session(self->luo_fd, SESSION_NAME);
	ASSERT_GE(self->session_fd, 0);

	self->vm = __vm_create(VM_SHAPE_DEFAULT, 2, 0);
#ifdef __x86_64__
	if (kvm_check_cap(KVM_CAP_EXCEPTION_PAYLOAD))
		vm_enable_cap(self->vm, KVM_CAP_EXCEPTION_PAYLOAD, 1);
#endif
	self->vcpu = vm_vcpu_add(self->vm, 0, guest_code);
	self->vcpu2 = vm_vcpu_add(self->vm, 1, guest_code);
	kvm_arch_vm_finalize_vcpus(self->vm);
}

FIXTURE_TEARDOWN(vcpu_luo)
{
	/* Closing the session cancels the preservation of its files. */
	if (self->session_fd >= 0)
		close(self->session_fd);
	if (self->vm)
		kvm_vm_free(self->vm);
	if (self->luo_fd >= 0)
		close(self->luo_fd);
}

TEST_F(vcpu_luo, preserve)
{
	struct kvm_vcpu_luo_retrieve arg = { .size = sizeof(arg) };
	int memfd;

	/* The kvm-vcpu handler only preserves KVM vCPU files. */
	memfd = memfd_create("kvm_vcpu_luo_test", 0);
	ASSERT_GE(memfd, 0);
	EXPECT_EQ(preserve_fd(self->session_fd, memfd, 1, VCPU_LUO_HANDLER, 0),
		  -EINVAL);
	close(memfd);

	EXPECT_EQ(preserve_fd(self->session_fd, self->vm->fd, 1,
			      VCPU_LUO_HANDLER, 0), -EINVAL);

	/* The kvm-vcpu handler takes no preserve argument. */
	EXPECT_EQ(preserve_fd(self->session_fd, self->vcpu->fd, 2, NULL,
			      (__u64)&arg), -EOPNOTSUPP);

#ifdef __aarch64__
	{
		struct kvm_vm *raw_vm = __vm_create(VM_SHAPE_DEFAULT, 1, 0);
		struct kvm_vcpu *raw_vcpu = __vm_vcpu_add(raw_vm, 0);

		EXPECT_EQ(luo_preserve_vcpu(self->session_fd, raw_vcpu->fd, 99),
			  -EINVAL);
		kvm_vm_free(raw_vm);
	}
#endif

	EXPECT_EQ(luo_session_preserve_fd(self->session_fd, self->vm->fd, 1), 0);
	EXPECT_EQ(preserve_fd(self->session_fd, self->vcpu->fd, 2,
			      VCPU_LUO_HANDLER, 0), 0);

	/* Multiple vCPUs of the same VM can be preserved in the session. */
	EXPECT_EQ(luo_preserve_vcpu(self->session_fd, self->vcpu2->fd, 3), 0);
}

TEST_F(vcpu_luo, cancel)
{
	struct ucall uc;

	vcpu_run(self->vcpu);
	ASSERT_EQ(get_ucall(self->vcpu, &uc), UCALL_SYNC);
	ASSERT_EQ(uc.args[1], 1);

	ASSERT_EQ(luo_session_preserve_fd(self->session_fd, self->vm->fd, 1), 0);
	ASSERT_EQ(luo_preserve_vcpu(self->session_fd, self->vcpu->fd, 2), 0);

	/* Closing the session cancels the preservation without side effects. */
	close(self->session_fd);
	self->session_fd = -1;

	/* The vCPU continues executing from where it paused. */
	vcpu_run(self->vcpu);
	EXPECT_EQ(get_ucall(self->vcpu, &uc), UCALL_DONE);

	/* Both the VM and vCPU can be preserved again in a new session. */
	self->session_fd = luo_create_session(self->luo_fd, SESSION_NAME);
	ASSERT_GE(self->session_fd, 0);
	EXPECT_EQ(luo_session_preserve_fd(self->session_fd, self->vm->fd, 1), 0);
	EXPECT_EQ(luo_preserve_vcpu(self->session_fd, self->vcpu->fd, 2), 0);
}

TEST_HARNESS_MAIN
