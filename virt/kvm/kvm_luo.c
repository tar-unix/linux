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
 * In addition to the VM type, architecture-specific VM state (such as
 * in-kernel interrupt controller state, timers, and GSI routing) is carried
 * over. Each VM and vCPU records its kind feature (non-CoCo,
 * software-protected private memory, Intel TDX, or AMD SEV-SNP) in its
 * feature header. vCPUs are preserved separately via the "kvm-vcpu" file
 * handler and retrieved against the restored VM file descriptor using struct
 * kvm_vcpu_luo_retrieve. Guest memory is preserved separately by preserving
 * the files that back it, and the VMM re-attaches memory slots after
 * retrieval.
 *
 * The file handlers are available once KVM is loaded, on x86 together with
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
	[KVM_VM_LUO_FEAT_SW_PROTECTED]	= LUO_FEAT_OPTIONAL,
	[KVM_VM_LUO_FEAT_TDX]		= LUO_FEAT_OPTIONAL,
	[KVM_VM_LUO_FEAT_SEV_SNP]	= LUO_FEAT_OPTIONAL,
};

static const unsigned int kvm_vm_luo_kinds[] = {
	KVM_VM_LUO_FEAT_NON_COCO,
	KVM_VM_LUO_FEAT_SW_PROTECTED,
	KVM_VM_LUO_FEAT_TDX,
	KVM_VM_LUO_FEAT_SEV_SNP,
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

int __weak kvm_arch_luo_vm_preserve(struct kvm *kvm, u64 *arch_state_pa)
{
	*arch_state_pa = 0;
	return 0;
}

int __weak kvm_arch_luo_vm_freeze(struct kvm *kvm, u64 arch_state_pa)
{
	return 0;
}

void __weak kvm_arch_luo_vm_unfreeze(struct kvm *kvm, u64 arch_state_pa)
{
}

void __weak kvm_arch_luo_vm_unpreserve(struct kvm *kvm, u64 arch_state_pa)
{
}

int __weak kvm_arch_luo_vm_retrieve(struct kvm *kvm, u64 arch_state_pa)
{
	return 0;
}

void __weak kvm_arch_luo_vm_finish(struct kvm *kvm, u64 arch_state_pa)
{
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

static bool kvm_vm_luo_is_hw_coco(int kind)
{
	return kind == KVM_VM_LUO_FEAT_TDX ||
	       kind == KVM_VM_LUO_FEAT_SEV_SNP;
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
	int kind, r;
	u64 type;

	if (kvm->vm_dead)
		return -EIO;

	state = kho_alloc_preserve(sizeof(*state));
	if (IS_ERR(state))
		return PTR_ERR(state);

	scoped_guard(mutex, &kvm->lock) {
		kind = kvm_arch_luo_vm_kind(kvm, &type);
		if (kind < 0) {
			r = kind;
		} else if (WARN_ON_ONCE(kind <= KVM_VM_LUO_FEAT_CORE ||
					kind >= KVM_VM_LUO_FEAT_MAX)) {
			r = -EINVAL;
		} else {
			r = kvm_arch_luo_vm_preserve(kvm, &state->arch_state_pa);
		}
	}
	if (r) {
		kho_unpreserve_free(state);
		return r;
	}

	features[kind] = LUO_FEAT_REQUIRED;
	luo_feature_hdr_init(&state->features, sizeof(*state), features);
	state->type = type;

	if (kvm_vm_luo_is_hw_coco(kind))
		liveupdate_coco_preserve_enter();

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
	scoped_guard(mutex, &kvm->lock) {
		kind = kvm_arch_luo_vm_kind(kvm, &type);
		if (kind < 0 || !luo_feature_is_req(&state->features, kind) ||
		    type != state->type)
			return -EOPNOTSUPP;

		return kvm_arch_luo_vm_freeze(kvm, state->arch_state_pa);
	}
}

static void kvm_vm_luo_unfreeze(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state = __va(args->serialized_data);
	struct kvm *kvm = args->file->private_data;

	scoped_guard(mutex, &kvm->lock)
		kvm_arch_luo_vm_unfreeze(kvm, state->arch_state_pa);
}

static void kvm_vm_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state = __va(args->serialized_data);
	struct kvm *kvm = args->file->private_data;
	int kind = kvm_vm_luo_get_kind(&state->features);

	if (kind >= 0 && kvm_vm_luo_is_hw_coco(kind))
		liveupdate_coco_preserve_exit();

	scoped_guard(mutex, &kvm->lock)
		kvm_arch_luo_vm_unpreserve(kvm, state->arch_state_pa);

	kho_unpreserve_free(state);
}

static int kvm_vm_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state = __va(args->serialized_data);
	char fdname[16];
	struct file *file;
	struct kvm *kvm;
	int kind, r;
	u64 type;

	if (state->features.size < sizeof(*state)) {
		kho_restore_free(state);
		return -EINVAL;
	}

	r = luo_feature_hdr_validate(&state->features, kvm_vm_luo_features);
	if (r) {
		if (luo_feature_is_active(&state->features,
					  KVM_VM_LUO_FEAT_CORE) &&
		    state->arch_state_pa)
			kvm_arch_luo_vm_finish(NULL, state->arch_state_pa);
		kho_restore_free(state);
		return r;
	}

	kind = kvm_vm_luo_get_kind(&state->features);
	if (kind < 0) {
		r = kind;
		goto out_finish_arch;
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
	else
		r = kvm_arch_luo_vm_retrieve(kvm, state->arch_state_pa);
	mutex_unlock(&kvm->lock);
	if (r) {
		fput(file);
		goto out_finish_arch;
	}

	if (state->arch_state_pa)
		kvm_arch_luo_vm_finish(kvm, state->arch_state_pa);
	kho_restore_free(state);
	args->file = file;
	return 0;

out_finish_arch:
	if (state->arch_state_pa)
		kvm_arch_luo_vm_finish(NULL, state->arch_state_pa);
	kho_restore_free(state);
	return r;
}

static void kvm_vm_luo_finish(struct liveupdate_file_op_args *args)
{
	struct kvm_vm_luo_state *state;

	/* A non-retryable retrieve attempt has already freed the state. */
	if (args->retrieve_status)
		return;

	state = __va(args->serialized_data);
	if (state->features.size >= sizeof(*state) &&
	    luo_feature_is_active(&state->features, KVM_VM_LUO_FEAT_CORE) &&
	    state->arch_state_pa)
		kvm_arch_luo_vm_finish(NULL, state->arch_state_pa);
	kho_restore_free(state);
}

static struct liveupdate_file_ops kvm_vm_luo_file_ops = {
	.can_preserve	= kvm_vm_luo_can_preserve,
	.preserve	= kvm_vm_luo_preserve,
	.freeze		= kvm_vm_luo_freeze,
	.unfreeze	= kvm_vm_luo_unfreeze,
	.unpreserve	= kvm_vm_luo_unpreserve,
	.retrieve	= kvm_vm_luo_retrieve,
	.finish		= kvm_vm_luo_finish,
};

static struct liveupdate_file_handler kvm_vm_luo_handler = {
	.ops	= &kvm_vm_luo_file_ops,
	.name	= KVM_VM_LUO_FH_NAME,
};

static const u8 kvm_vcpu_luo_features[KVM_VCPU_LUO_FEAT_MAX] = {
	[KVM_VCPU_LUO_FEAT_CORE]		= LUO_FEAT_REQUIRED,
	[KVM_VCPU_LUO_FEAT_NON_COCO]		= LUO_FEAT_OPTIONAL,
	[KVM_VCPU_LUO_FEAT_SW_PROTECTED]	= LUO_FEAT_OPTIONAL,
	[KVM_VCPU_LUO_FEAT_TDX]			= LUO_FEAT_OPTIONAL,
	[KVM_VCPU_LUO_FEAT_SEV_SNP]		= LUO_FEAT_OPTIONAL,
};

static const unsigned int kvm_vcpu_luo_kinds[] = {
	KVM_VCPU_LUO_FEAT_NON_COCO,
	KVM_VCPU_LUO_FEAT_SW_PROTECTED,
	KVM_VCPU_LUO_FEAT_TDX,
	KVM_VCPU_LUO_FEAT_SEV_SNP,
};

int __weak kvm_arch_luo_vcpu_preserve(struct kvm_vcpu *vcpu, u64 *arch_state_pa)
{
	return -EOPNOTSUPP;
}

int __weak kvm_arch_luo_vcpu_freeze(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	return -EOPNOTSUPP;
}

void __weak kvm_arch_luo_vcpu_unfreeze(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
}

void __weak kvm_arch_luo_vcpu_unpreserve(struct kvm_vcpu *vcpu,
					 u64 arch_state_pa)
{
}

int __weak kvm_arch_luo_vcpu_retrieve(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	return -EOPNOTSUPP;
}

void __weak kvm_arch_luo_vcpu_finish(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
}

static void kvm_luo_vcpu_load(struct kvm_vcpu *vcpu)
{
	if (!IS_ENABLED(CONFIG_ARM64))
		vcpu_load(vcpu);
}

static void kvm_luo_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (!IS_ENABLED(CONFIG_ARM64))
		vcpu_put(vcpu);
}

static int kvm_vcpu_luo_get_kind(const struct luo_feature_hdr *hdr)
{
	int i, kind = -EINVAL;

	for (i = 0; i < ARRAY_SIZE(kvm_vcpu_luo_kinds); i++) {
		if (!luo_feature_is_active(hdr, kvm_vcpu_luo_kinds[i]))
			continue;
		if (kind >= 0 ||
		    !luo_feature_is_req(hdr, kvm_vcpu_luo_kinds[i]))
			return -EINVAL;
		kind = kvm_vcpu_luo_kinds[i];
	}

	return kind;
}

static bool kvm_vcpu_luo_can_preserve(struct liveupdate_file_handler *handler,
				      struct file *file)
{
	return file_is_kvm_vcpu(file);
}

static int kvm_vcpu_luo_preserve(struct liveupdate_file_op_args *args)
{
	u8 features[KVM_VCPU_LUO_FEAT_MAX] = {
		[KVM_VCPU_LUO_FEAT_CORE] = LUO_FEAT_REQUIRED,
	};
	struct kvm_vcpu *vcpu = args->file->private_data;
	struct kvm *kvm = vcpu->kvm;
	struct kvm_vcpu_luo_state *state;
	int vm_kind, r;
	u64 type;

	if (kvm->vm_dead)
		return -EIO;

	scoped_guard(mutex, &kvm->lock) {
		vm_kind = kvm_arch_luo_vm_kind(kvm, &type);
		if (vm_kind < 0)
			return vm_kind;
		if (WARN_ON_ONCE(vm_kind <= KVM_VCPU_LUO_FEAT_CORE ||
				 vm_kind >= KVM_VCPU_LUO_FEAT_MAX))
			return -EINVAL;
		if (!mutex_trylock(&vcpu->mutex))
			return -EBUSY;
	}

	state = kho_alloc_preserve(sizeof(*state));
	if (IS_ERR(state)) {
		mutex_unlock(&vcpu->mutex);
		return PTR_ERR(state);
	}

	kvm_luo_vcpu_load(vcpu);
	r = kvm_arch_luo_vcpu_preserve(vcpu, &state->arch_state_pa);
	kvm_luo_vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);
	if (r) {
		kho_unpreserve_free(state);
		return r;
	}

	features[vm_kind] = LUO_FEAT_REQUIRED;
	luo_feature_hdr_init(&state->features, sizeof(*state), features);
	state->vcpu_id = vcpu->vcpu_id;
	state->reserved = 0;

	args->serialized_data = __pa(state);
	return 0;
}

static int kvm_vcpu_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_state *state = __va(args->serialized_data);
	struct kvm_vcpu *vcpu = args->file->private_data;
	struct kvm *kvm = vcpu->kvm;
	int vm_kind, r;
	u64 type;

	if (kvm->vm_dead)
		return -EIO;

	scoped_guard(mutex, &kvm->lock) {
		vm_kind = kvm_arch_luo_vm_kind(kvm, &type);
		if (vm_kind < 0 || !luo_feature_is_req(&state->features, vm_kind))
			return -EOPNOTSUPP;
		if (!mutex_trylock(&vcpu->mutex))
			return -EBUSY;
	}

	kvm_luo_vcpu_load(vcpu);
	r = kvm_arch_luo_vcpu_freeze(vcpu, state->arch_state_pa);
	kvm_luo_vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);

	return r;
}

static void kvm_vcpu_luo_unfreeze(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_state *state = __va(args->serialized_data);
	struct kvm_vcpu *vcpu = args->file->private_data;

	mutex_lock(&vcpu->mutex);
	kvm_luo_vcpu_load(vcpu);
	kvm_arch_luo_vcpu_unfreeze(vcpu, state->arch_state_pa);
	kvm_luo_vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);
}

static void kvm_vcpu_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_state *state = __va(args->serialized_data);
	struct kvm_vcpu *vcpu = args->file->private_data;

	scoped_guard(mutex, &vcpu->mutex)
		kvm_arch_luo_vcpu_unpreserve(vcpu, state->arch_state_pa);
	kho_unpreserve_free(state);
}

static int kvm_vcpu_luo_retrieve(struct liveupdate_file_op_args *args)
{
	const struct kvm_vcpu_luo_retrieve *arg = args->arg;
	struct kvm_vcpu_luo_state *state = __va(args->serialized_data);
	struct kvm_vcpu *vcpu;
	struct file *file;
	struct kvm *kvm;
	int kind, vm_kind, r;
	u64 type;

	if (state->features.size < sizeof(*state)) {
		kho_restore_free(state);
		return -EINVAL;
	}

	r = luo_feature_hdr_validate(&state->features, kvm_vcpu_luo_features);
	if (r) {
		if (luo_feature_is_active(&state->features,
					  KVM_VCPU_LUO_FEAT_CORE) &&
		    state->arch_state_pa)
			kvm_arch_luo_vcpu_finish(NULL, state->arch_state_pa);
		kho_restore_free(state);
		return r;
	}

	kind = kvm_vcpu_luo_get_kind(&state->features);
	if (kind < 0 || state->vcpu_id >= KVM_MAX_VCPU_IDS ||
	    state->reserved || !state->arch_state_pa) {
		if (state->arch_state_pa)
			kvm_arch_luo_vcpu_finish(NULL, state->arch_state_pa);
		kho_restore_free(state);
		return kind < 0 ? kind : -EINVAL;
	}

	/*
	 * Until the vCPU is created, nothing has been consumed. Let userspace
	 * retry with a different argument.
	 */
	args->retryable = true;

	if (!arg)
		return -EINVAL;

	CLASS(fd, f)(arg->vm_fd);
	if (fd_empty(f))
		return -EBADF;

	if (!file_is_kvm(fd_file(f)))
		return -EINVAL;

	kvm = fd_file(f)->private_data;
	if (kvm->mm != current->mm || kvm->vm_dead)
		return -EIO;

	scoped_guard(mutex, &kvm->lock)
		vm_kind = kvm_arch_luo_vm_kind(kvm, &type);
	if (vm_kind != kind)
		return -EINVAL;

	file = kvm_create_vcpu_file(kvm, state->vcpu_id);
	if (IS_ERR(file))
		return PTR_ERR(file);

	args->retryable = false;

	vcpu = file->private_data;
	mutex_lock(&vcpu->mutex);
	kvm_luo_vcpu_load(vcpu);
	r = kvm_arch_luo_vcpu_retrieve(vcpu, state->arch_state_pa);
	kvm_luo_vcpu_put(vcpu);
	mutex_unlock(&vcpu->mutex);
	if (r) {
		kvm_vm_dead(kvm);
		fput(file);
		kvm_arch_luo_vcpu_finish(NULL, state->arch_state_pa);
		kho_restore_free(state);
		return r;
	}

	kvm_arch_luo_vcpu_finish(vcpu, state->arch_state_pa);
	kho_restore_free(state);
	args->file = file;
	return 0;
}

static void kvm_vcpu_luo_finish(struct liveupdate_file_op_args *args)
{
	struct kvm_vcpu_luo_state *state;

	/*
	 * Retrieving has freed the state unless it was never attempted or
	 * failed with a retryable error.
	 */
	if (args->retrieve_status)
		return;

	state = __va(args->serialized_data);
	if (state->features.size >= sizeof(*state) &&
	    luo_feature_is_active(&state->features, KVM_VCPU_LUO_FEAT_CORE) &&
	    state->arch_state_pa)
		kvm_arch_luo_vcpu_finish(NULL, state->arch_state_pa);
	kho_restore_free(state);
}

static struct liveupdate_file_ops kvm_vcpu_luo_file_ops = {
	.can_preserve	= kvm_vcpu_luo_can_preserve,
	.preserve	= kvm_vcpu_luo_preserve,
	.freeze		= kvm_vcpu_luo_freeze,
	.unfreeze	= kvm_vcpu_luo_unfreeze,
	.unpreserve	= kvm_vcpu_luo_unpreserve,
	.retrieve	= kvm_vcpu_luo_retrieve,
	.finish		= kvm_vcpu_luo_finish,
	.rarg		= LIVEUPDATE_ARG(struct kvm_vcpu_luo_retrieve, vm_fd),
};

static struct liveupdate_file_handler kvm_vcpu_luo_handler = {
	.ops	= &kvm_vcpu_luo_file_ops,
	.name	= KVM_VCPU_LUO_FH_NAME,
};

#define KVM_LUO_MAX_PENDING_FLBS	4

static DEFINE_MUTEX(kvm_luo_flb_lock);
static struct liveupdate_flb *kvm_luo_pending_flbs[KVM_LUO_MAX_PENDING_FLBS];
static unsigned int kvm_luo_nr_pending_flbs;
static bool kvm_luo_initialized;

int kvm_vm_luo_init(struct module *module)
{
	unsigned int i;
	int r;

	/*
	 * Pin the module that provides /dev/kvm, i.e. kvm-intel or kvm-amd on
	 * x86, while a VM or vCPU is preserved or waiting to be retrieved.
	 */
	kvm_vm_luo_file_ops.owner = module;
	kvm_vcpu_luo_file_ops.owner = module;

	guard(mutex)(&kvm_luo_flb_lock);

	r = liveupdate_register_file_handler(&kvm_vm_luo_handler);
	if (r == -EOPNOTSUPP)
		return 0;
	if (r)
		return r;

	for (i = 0; i < kvm_luo_nr_pending_flbs; i++) {
		r = liveupdate_register_flb(&kvm_vm_luo_handler,
					    kvm_luo_pending_flbs[i]);
		if (r && r != -EOPNOTSUPP) {
			while (i--)
				liveupdate_unregister_flb(&kvm_vm_luo_handler,
							  kvm_luo_pending_flbs[i]);
			liveupdate_unregister_file_handler(&kvm_vm_luo_handler);
			return r;
		}
	}

	r = liveupdate_register_file_handler(&kvm_vcpu_luo_handler);
	if (r) {
		for (i = kvm_luo_nr_pending_flbs; i > 0; i--)
			liveupdate_unregister_flb(&kvm_vm_luo_handler,
						  kvm_luo_pending_flbs[i - 1]);
		liveupdate_unregister_file_handler(&kvm_vm_luo_handler);
		return r;
	}

	kvm_luo_initialized = true;
	return 0;
}

void kvm_vm_luo_exit(void)
{
	unsigned int i;

	guard(mutex)(&kvm_luo_flb_lock);

	if (!kvm_luo_initialized)
		return;

	kvm_luo_initialized = false;
	liveupdate_unregister_file_handler(&kvm_vcpu_luo_handler);
	for (i = kvm_luo_nr_pending_flbs; i > 0; i--)
		liveupdate_unregister_flb(&kvm_vm_luo_handler,
					  kvm_luo_pending_flbs[i - 1]);
	liveupdate_unregister_file_handler(&kvm_vm_luo_handler);
}

int kvm_luo_register_flb(struct liveupdate_flb *flb)
{
	unsigned int i;
	int r = 0;

	if (!liveupdate_enabled())
		return 0;

	guard(mutex)(&kvm_luo_flb_lock);

	for (i = 0; i < kvm_luo_nr_pending_flbs; i++) {
		if (kvm_luo_pending_flbs[i] == flb)
			return 0;
	}
	if (WARN_ON_ONCE(kvm_luo_nr_pending_flbs >= KVM_LUO_MAX_PENDING_FLBS))
		return -ENOSPC;

	if (kvm_luo_initialized) {
		r = liveupdate_register_flb(&kvm_vm_luo_handler, flb);
		if (r && r != -EOPNOTSUPP)
			return r;
	}

	kvm_luo_pending_flbs[kvm_luo_nr_pending_flbs++] = flb;
	return 0;
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_luo_register_flb);

void kvm_luo_unregister_flb(struct liveupdate_flb *flb)
{
	unsigned int i;

	if (!liveupdate_enabled())
		return;

	guard(mutex)(&kvm_luo_flb_lock);

	for (i = 0; i < kvm_luo_nr_pending_flbs; i++) {
		if (kvm_luo_pending_flbs[i] == flb) {
			kvm_luo_nr_pending_flbs--;
			memmove(&kvm_luo_pending_flbs[i],
				&kvm_luo_pending_flbs[i + 1],
				(kvm_luo_nr_pending_flbs - i) *
				sizeof(kvm_luo_pending_flbs[0]));
			if (kvm_luo_initialized)
				liveupdate_unregister_flb(&kvm_vm_luo_handler,
							  flb);
			return;
		}
	}
}
EXPORT_SYMBOL_FOR_KVM_INTERNAL(kvm_luo_unregister_flb);
