// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2025, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

#define pr_fmt(fmt) KBUILD_MODNAME " test: " fmt

#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/liveupdate.h>
#include <linux/module.h>
#include <linux/string.h>
#include "../../kernel/liveupdate/luo_internal.h"

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "liveupdate_test."

static const struct liveupdate_flb_ops test_flb_ops;
#define DEFINE_TEST_FLB(i) {						\
	.ops = &test_flb_ops,						\
	.name = LIVEUPDATE_TEST_FLB_NAME(i),				\
}

/* Number of Test FLBs to register with every file handler */
#define TEST_NFLBS 3
static struct liveupdate_flb test_flbs[TEST_NFLBS] = {
	DEFINE_TEST_FLB(0),
	DEFINE_TEST_FLB(1),
	DEFINE_TEST_FLB(2),
};

#define TEST_FLB_MAGIC_BASE 0xFEEDF00DCAFEBEE0ULL

static int test_flb_preserve(struct liveupdate_flb_op_args *argp)
{
	ptrdiff_t index = argp->flb - test_flbs;

	pr_info("%s: preserve was triggered\n", argp->flb->name);
	argp->data = TEST_FLB_MAGIC_BASE + index;

	return 0;
}

static void test_flb_unpreserve(struct liveupdate_flb_op_args *argp)
{
	pr_info("%s: unpreserve was triggered\n", argp->flb->name);
}

static int test_flb_retrieve(struct liveupdate_flb_op_args *argp)
{
	ptrdiff_t index = argp->flb - test_flbs;
	u64 expected_data = TEST_FLB_MAGIC_BASE + index;

	if (argp->data == expected_data) {
		pr_info("%s: found flb data from the previous boot\n",
			argp->flb->name);
		argp->obj = (void *)argp->data;
	} else {
		pr_err("%s: ERROR - incorrect data handle: %llx, expected %llx\n",
		       argp->flb->name, argp->data, expected_data);
		return -EINVAL;
	}

	return 0;
}

static void test_flb_finish(struct liveupdate_flb_op_args *argp)
{
	ptrdiff_t index = argp->flb - test_flbs;
	void *expected_obj = (void *)(TEST_FLB_MAGIC_BASE + index);

	if (argp->obj == expected_obj) {
		pr_info("%s: finish was triggered\n", argp->flb->name);
	} else {
		pr_err("%s: ERROR - finish called with invalid object\n",
		       argp->flb->name);
	}
}

static const struct liveupdate_flb_ops test_flb_ops = {
	.preserve	= test_flb_preserve,
	.unpreserve	= test_flb_unpreserve,
	.retrieve	= test_flb_retrieve,
	.finish		= test_flb_finish,
	.owner		= THIS_MODULE,
};

static void liveupdate_test_init(void)
{
	static DEFINE_MUTEX(init_lock);
	static bool initialized;
	int i;

	guard(mutex)(&init_lock);

	if (initialized)
		return;

	for (i = 0; i < TEST_NFLBS; i++) {
		struct liveupdate_flb *flb = &test_flbs[i];
		void *obj;
		int err;

		err = liveupdate_flb_get_incoming(flb, &obj);
		if (err && err != -ENODATA && err != -ENOENT) {
			pr_err("liveupdate_flb_get_incoming for %s failed: %pe\n",
			       flb->name, ERR_PTR(err));
		}

		if (!err)
			liveupdate_flb_put_incoming(flb);
	}
	initialized = true;
}

void liveupdate_test_register(struct liveupdate_file_handler *fh)
{
	int err, i;

	liveupdate_test_init();

	for (i = 0; i < TEST_NFLBS; i++) {
		struct liveupdate_flb *flb = &test_flbs[i];

		err = liveupdate_register_flb(fh, flb);
		if (err) {
			pr_err("Failed to register %s %pe\n",
			       flb->name, ERR_PTR(err));
		}
	}

	err = liveupdate_register_flb(fh, &test_flbs[0]);
	if (!err || err != -EEXIST) {
		pr_err("Failed: %s should be already registered, but got err: %pe\n",
		       test_flbs[0].name, ERR_PTR(err));
	}

	pr_info("Registered %d FLBs with file handler: [%s]\n",
		TEST_NFLBS, fh->name);
}

/*
 * Name of a file handler. Files preserved by that handler get an unknown
 * required feature in the feature header of their serialized state, as if
 * they had been preserved by a newer kernel. This tests that the next kernel
 * refuses to retrieve them.
 */
static char test_require_unknown_feature[LIVEUPDATE_HNDL_NAME_LENGTH];
module_param_string(require_unknown_feature, test_require_unknown_feature,
		    sizeof(test_require_unknown_feature), 0644);
MODULE_PARM_DESC(require_unknown_feature,
		 "Handler whose preserved files require an unknown feature");

void liveupdate_test_preserve(struct liveupdate_file_handler *fh,
			      u64 serialized_data)
{
	const unsigned int feat = LUO_FEAT_MAX - 1;
	struct luo_feature_hdr *hdr;
	unsigned int idx;
	bool match;

	kernel_param_lock(THIS_MODULE);
	match = sysfs_streq(test_require_unknown_feature, fh->name);
	kernel_param_unlock(THIS_MODULE);
	if (!match)
		return;

	/* The serialized state of every file starts with a feature header. */
	hdr = __va(serialized_data);
	for (idx = 0; idx < LUO_FEAT_FLAGS_IDX(feat); idx++)
		hdr->flags[idx] |= LUO_FEAT_EXT_MASK;
	hdr->flags[idx] |= LUO_FEAT_ACTIVE(feat) | LUO_FEAT_REQ(feat);

	pr_info("Feature %u is required by a file of handler [%s]\n",
		feat, fh->name);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pasha Tatashin <pasha.tatashin@soleen.com>");
MODULE_DESCRIPTION("In-kernel test for LUO mechanism");
