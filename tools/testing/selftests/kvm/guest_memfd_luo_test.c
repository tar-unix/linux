// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 *
 * Tests for preserving a guest_memfd for live update that need no reboot.
 * Closing a session before the reboot cancels the preservation of its files,
 * so these tests run on any kernel with live update enabled.
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/falloc.h>
#include <linux/sizes.h>

#include "kvm_util.h"
#include "test_util.h"
#include "kselftest_harness.h"

#include <libliveupdate.h>

#define GMEM_LUO_HANDLER	"guest_memfd"
#define GMEM_SIZE		SZ_2M
#define GMEM_FLAGS		(GUEST_MEMFD_FLAG_MMAP | GUEST_MEMFD_FLAG_INIT_SHARED)
#define SESSION_NAME		"kvm_gmem_luo_test"

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

FIXTURE(gmem_luo) {
	int luo_fd;
	int session_fd;
	struct kvm_vm *vm;
	int gmem_fd;
	size_t page_size;
};

FIXTURE_SETUP(gmem_luo)
{
	self->luo_fd = -1;
	self->session_fd = -1;
	self->gmem_fd = -1;
	self->page_size = getpagesize();

	if (!kvm_has_cap(KVM_CAP_GUEST_MEMFD))
		SKIP(return, "guest_memfd is not supported");

	self->luo_fd = luo_open_device();
	if (self->luo_fd < 0)
		SKIP(return, "%s is not available", LUO_DEVICE);

	self->session_fd = luo_create_session(self->luo_fd, SESSION_NAME);
	ASSERT_GE(self->session_fd, 0);

	self->vm = vm_create_barebones();
	if ((vm_check_cap(self->vm, KVM_CAP_GUEST_MEMFD_FLAGS) & GMEM_FLAGS) !=
	    GMEM_FLAGS)
		SKIP(return, "guest_memfd flags 0x%llx are not supported",
		     GMEM_FLAGS);

	self->gmem_fd = vm_create_guest_memfd(self->vm, GMEM_SIZE, GMEM_FLAGS);
}

FIXTURE_TEARDOWN(gmem_luo)
{
	/* Closing the session cancels the preservation of its files. */
	if (self->session_fd >= 0)
		close(self->session_fd);
	if (self->gmem_fd >= 0)
		close(self->gmem_fd);
	if (self->vm)
		kvm_vm_free(self->vm);
	if (self->luo_fd >= 0)
		close(self->luo_fd);
}

TEST_F(gmem_luo, preserve)
{
	struct kvm_guest_memfd_luo_retrieve arg = { .size = sizeof(arg) };
	int memfd, session_fd;

	/* The guest_memfd handler only preserves guest_memfd. */
	memfd = memfd_create("kvm_gmem_luo_test", 0);
	ASSERT_GE(memfd, 0);
	EXPECT_EQ(preserve_fd(self->session_fd, memfd, 1, GMEM_LUO_HANDLER, 0),
		  -EINVAL);
	close(memfd);

	/* The guest_memfd handler takes no preserve argument. */
	EXPECT_EQ(preserve_fd(self->session_fd, self->gmem_fd, 2, NULL,
			      (__u64)&arg), -EOPNOTSUPP);

	EXPECT_EQ(preserve_fd(self->session_fd, self->gmem_fd, 2,
			      GMEM_LUO_HANDLER, 0), 0);

	/* A guest_memfd is preserved at most once, in any session. */
	EXPECT_EQ(preserve_fd(self->session_fd, self->gmem_fd, 3, NULL, 0),
		  -EBUSY);

	session_fd = luo_create_session(self->luo_fd, SESSION_NAME "_2");
	ASSERT_GE(session_fd, 0);
	EXPECT_EQ(preserve_fd(session_fd, self->gmem_fd, 2, NULL, 0), -EBUSY);
	close(session_fd);
}

TEST_HARNESS_MAIN
