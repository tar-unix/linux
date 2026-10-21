// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 */

/**
 * DOC: KVM VM live update
 *
 * A VM can be kept across a kexec based live update by preserving its file
 * descriptor in a live update session with LIVEUPDATE_SESSION_PRESERVE_FD,
 * optionally naming the "kvm-vm" file handler. Which VMs can be preserved
 * depends on the architecture and on the kind of VM, others are refused with
 * -EOPNOTSUPP. Preserving does not change or stop the VM, and closing the
 * session before the reboot cancels the preservation while the VM keeps
 * working. If a preserved VM is later modified so that it can no longer be
 * preserved, such as enabling SEV on a default x86 VM, the live update fails
 * at freeze time with -EOPNOTSUPP. The VMM stops running vCPUs before the
 * reboot.
 *
 * After the reboot, LIVEUPDATE_SESSION_RETRIEVE_FD creates a new VM of the
 * preserved type. The new VM belongs to the calling process exactly as if
 * that process had issued KVM_CREATE_VM, so the VM must be retrieved by the
 * process that is going to run it. Retrieving the same token again returns
 * the same VM. If retrieving fails because the preserved state is invalid or
 * unsupported, the preserved VM is consumed and further attempts return the
 * same error; transient failures while creating the VM leave the preserved
 * state intact so retrieval can be retried.
 *
 * For now only the VM type is carried over. The VMM creates vCPUs, memory
 * slots, interrupt controllers, devices and capabilities as it does for a new
 * VM. Guest memory is preserved separately, by preserving the files that back
 * it.
 *
 * The file handler is available once KVM is loaded, on x86 together with
 * kvm-intel or kvm-amd. In the new kernel, these modules must be loaded before
 * /dev/liveupdate is opened for the first time, otherwise the preserved
 * sessions cannot be restored.
 */

#include <linux/cleanup.h>
#include <linux/file.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/liveupdate.h>
#include <linux/mutex.h>

#include "kvm_luo.h"
#include "kvm_mm.h"

/*
 * Each preserved VM requires exactly one kind feature. The kinds listed here
 * are implemented, but none of them is required of every VM.
 */
static const u8 kvm_vm_luo_features[KVM_VM_LUO_FEAT_MAX] = {
	[KVM_VM_LUO_FEAT_CORE]		= LUO_FEAT_REQUIRED,
	[KVM_VM_LUO_FEAT_NON_COCO]	= LUO_FEAT_OPTIONAL,
};

static const unsigned int kvm_vm_luo_kinds[] = {
	KVM_VM_LUO_FEAT_NON_COCO,
};

static atomic_t kvm_vm_luo_nr_retrieved = ATOMIC_INIT(0);

/*
 * Return the kind feature of @kvm and store the machine type that creates an
 * equivalent VM in @type, or return -EOPNOTSUPP if @kvm cannot be preserved.
 * Called with kvm->lock held.
 */
int __weak kvm_arch_luo_vm_kind(struct kvm *kvm, u64 *type)
{
	return -EOPNOTSUPP;
}

static int kvm_vm_luo_get_kind(const struct luo_feature_hdr *hdr)
{
	int i, kind = -EINVAL;

	for (i = 0; i < ARRAY_SIZE(kvm_vm_luo_kinds); i++) {
		if (!luo_feature_is_active(hdr, kvm_vm_luo_kinds[i]))
			continue;
		if (kind >= 0 || !luo_feature_is_req(hdr, kvm_vm_luo_kinds[i]))
			return -EINVAL;
		kind = kvm_vm_luo_kinds[i];
	}

	return kind;
}

static bool kvm_vm_luo_can_preserve(struct liveupdate_file_handler *handler,
				    struct file *file)
{
	return file_is_kvm(file);
}

static int kvm_vm_luo_preserve(struct liveupdate_file_op_args *args)
{
	u8 features[KVM_VM_LUO_FEAT_MAX] = {
		[KVM_VM_LUO_FEAT_CORE] = LUO_FEAT_REQUIRED,
	};
	struct kvm *kvm = args->file->private_data;
	struct kvm_vm_luo_state *state;
	u64 type;
	int kind;

	if (kvm->vm_dead)
		return -EIO;

	scoped_guard(mutex, &kvm->lock)
		kind = kvm_arch_luo_vm_kind(kvm, &type);
	if (kind < 0)
		return kind;
	if (WARN_ON_ONCE(kind <= KVM_VM_LUO_FEAT_CORE ||
			 kind >= KVM_VM_LUO_FEAT_MAX))
		return -EINVAL;
	features[kind] = LUO_FEAT_REQUIRED;

	state = kho_alloc_preserve(sizeof(*state));
	if (IS_ERR(state))
		return PTR_ERR(state);

	luo_feature_hdr_init(&state->features, sizeof(*state), features);
	state->type = type;

	args->serialized_data = __pa(state);
	return 0;
}

static int kvm_vm_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state = __va(args->serialized_data);
	struct kvm *kvm = args->file->private_data;
	u64 type;
	int kind;

	if (kvm->vm_dead)
		return -EIO;

	/*
	 * A VM can turn into a kind that cannot be preserved after it was
	 * preserved, e.g. when SEV is enabled on an x86 default VM. Refuse the
	 * live update instead of restoring the VM as something it is not.
	 */
	scoped_guard(mutex, &kvm->lock)
		kind = kvm_arch_luo_vm_kind(kvm, &type);
	if (kind < 0 || !luo_feature_is_req(&state->features, kind) ||
	    type != state->type)
		return -EOPNOTSUPP;

	return 0;
}

static void kvm_vm_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	kho_unpreserve_free(__va(args->serialized_data));
}

static int kvm_vm_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state = __va(args->serialized_data);
	char fdname[16];
	struct file *file;
	struct kvm *kvm;
	int kind, r;
	u64 type;

	r = luo_feature_hdr_validate(&state->features, kvm_vm_luo_features);
	if (r)
		goto out;

	if (state->features.size < sizeof(*state)) {
		r = -EINVAL;
		goto out;
	}

	kind = kvm_vm_luo_get_kind(&state->features);
	if (kind < 0) {
		r = kind;
		goto out;
	}

	/*
	 * The file descriptor is not known yet. Use a name that cannot clash
	 * with the debugfs name of a VM created by KVM_CREATE_VM.
	 */
	snprintf(fdname, sizeof(fdname), "luo-%u",
		 atomic_inc_return(&kvm_vm_luo_nr_retrieved));

	file = kvm_create_vm_file(state->type, fdname);
	if (IS_ERR(file)) {
		args->retryable = true;
		return PTR_ERR(file);
	}

	/* The new VM must be of the same kind and type as the preserved one. */
	kvm = file->private_data;
	mutex_lock(&kvm->lock);
	if (kvm_arch_luo_vm_kind(kvm, &type) != kind ||
	    type != state->type)
		r = -EINVAL;
	mutex_unlock(&kvm->lock);
	if (r) {
		fput(file);
		goto out;
	}

	args->file = file;
out:
	kho_restore_free(state);
	return r;
}

static void kvm_vm_luo_finish(struct liveupdate_file_op_args *args)
{
	/* A non-retryable retrieve attempt has already freed the state. */
	if (args->retrieve_status)
		return;

	kho_restore_free(__va(args->serialized_data));
}

static struct liveupdate_file_ops kvm_vm_luo_file_ops = {
	.can_preserve	= kvm_vm_luo_can_preserve,
	.preserve	= kvm_vm_luo_preserve,
	.freeze		= kvm_vm_luo_freeze,
	.unpreserve	= kvm_vm_luo_unpreserve,
	.retrieve	= kvm_vm_luo_retrieve,
	.finish		= kvm_vm_luo_finish,
};

static struct liveupdate_file_handler kvm_vm_luo_handler = {
	.ops	= &kvm_vm_luo_file_ops,
	.name	= KVM_VM_LUO_FH_NAME,
};

int kvm_vm_luo_init(struct module *module)
{
	int r;

	/*
	 * Pin the module that provides /dev/kvm, i.e. kvm-intel or kvm-amd on
	 * x86, while a VM is preserved or waiting to be retrieved.
	 */
	kvm_vm_luo_file_ops.owner = module;

	r = liveupdate_register_file_handler(&kvm_vm_luo_handler);

	/* Live update is disabled, nothing to do. */
	if (r == -EOPNOTSUPP)
		return 0;

	return r;
}

void kvm_vm_luo_exit(void)
{
	liveupdate_unregister_file_handler(&kvm_vm_luo_handler);
}
