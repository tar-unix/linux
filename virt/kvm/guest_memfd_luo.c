// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 */

/**
 * DOC: guest_memfd live update
 *
 * A guest_memfd can be kept across a kexec based live update by preserving
 * its file descriptor in a live update session with
 * LIVEUPDATE_SESSION_PRESERVE_FD, optionally naming the "guest_memfd" file
 * handler. No argument is taken: the VM a guest_memfd belongs to does not
 * need to be preserved, and its file descriptor may already be closed.
 *
 * Both shared and private guest_memfd instances can be preserved. The size,
 * the flags passed to KVM_CREATE_GUEST_MEMFD, all allocated order-0 folios,
 * and for VMs with private memory (%KVM_GMEM_LUO_FEAT_PRIVATE), all non-default
 * memory attribute ranges configured via KVM_SET_MEMORY_ATTRIBUTES2 are
 * preserved. The NUMA memory policy, memory slots, bindings and mappings are
 * not.
 *
 * Preserving freezes the guest_memfd until the reboot: allocating memory, by
 * fallocate() or by touching a hole, PUNCH_HOLE, and changing memory
 * attributes via KVM_SET_MEMORY_ATTRIBUTES2 fail with -EPERM, so touching a
 * hole raises SIGBUS in userspace and fails the guest access like any other
 * failure to allocate guest memory. Memory that is present stays accessible
 * to the guest and to userspace, and the VM keeps running. The VMM therefore
 * allocates all memory and configures memory attributes before preserving.
 * Closing the session before the reboot cancels the preservation and unfreezes
 * the guest_memfd.
 *
 * After the reboot, LIVEUPDATE_SESSION_RETRIEVE_FD needs a struct
 * kvm_guest_memfd_luo_retrieve with the file descriptor of a VM, created with
 * KVM_CREATE_VM or retrieved with the "kvm-vm" file handler, that belongs to
 * the calling process and supports the preserved flags and features. The
 * retrieved guest_memfd is bound to that VM. If the argument is missing or the
 * VM is not suitable, retrieving fails without consuming the preserved
 * guest_memfd and can be retried. The VMM then binds the guest_memfd to memory
 * slots at the same offsets as before. A preserved guest_memfd that is not
 * retrieved is freed when the session is finished.
 */

#include <linux/file.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/liveupdate.h>
#include <linux/magic.h>
#include <linux/pagemap.h>
#include <linux/vmalloc.h>

#include "guest_memfd.h"

struct kvm_gmem_luo_priv {
	struct kvm_gmem_luo_folio *folios;
	struct kvm_gmem_luo_attr_range *attr_ranges;
};

static const u8 kvm_gmem_luo_features[KVM_GMEM_LUO_FEAT_MAX] = {
	[KVM_GMEM_LUO_FEAT_CORE]	= LUO_FEAT_REQUIRED,
	[KVM_GMEM_LUO_FEAT_PRIVATE]	= LUO_FEAT_OPTIONAL,
};

int __weak kvm_arch_gmem_luo_get_vm_id(struct kvm *kvm, u64 *vm_id)
{
	return -EOPNOTSUPP;
}

bool __weak kvm_arch_gmem_luo_validate_vm_id(struct kvm *kvm, u64 vm_id)
{
	return false;
}

static bool kvm_gmem_luo_can_preserve(struct liveupdate_file_handler *handler,
				      struct file *file)
{
	return file_inode(file)->i_sb->s_magic == GUEST_MEMFD_MAGIC;
}

static unsigned long kvm_gmem_luo_get_id(struct file *file)
{
	return (unsigned long)file_inode(file);
}

static void kvm_gmem_luo_unpreserve_folios(const struct kvm_gmem_luo_folio *folios,
					   u64 nr)
{
	u64 i;

	for (i = 0; i < nr; i++)
		kho_unpreserve_folio(pfn_folio(folios[i].pfn));
}

/*
 * Preserve the folios of the frozen guest_memfd @inode and describe them in
 * @folios, which has room for @max entries. Return the number of preserved
 * folios in @nr, also on failure.
 */
static int kvm_gmem_luo_preserve_folios(struct inode *inode,
					struct kvm_gmem_luo_folio *folios,
					u64 max, u64 *nr)
{
	pgoff_t index = 0, end = i_size_read(inode) >> PAGE_SHIFT;
	struct folio_batch fbatch;
	unsigned int i;
	int err = 0;

	*nr = 0;
	folio_batch_init(&fbatch);
	while (!err &&
	       filemap_get_folios(inode->i_mapping, &index, end - 1, &fbatch)) {
		for (i = 0; i < folio_batch_count(&fbatch); i++) {
			struct folio *folio = fbatch.folios[i];

			if (WARN_ON_ONCE(*nr == max || folio_test_large(folio))) {
				err = -EINVAL;
				break;
			}

			if (folio_test_hwpoison(folio)) {
				err = -EHWPOISON;
				break;
			}

			/*
			 * A folio that is not up to date was allocated by
			 * fallocate() and has never been faulted in or
			 * converted to private. Clear it now, so that the next
			 * kernel does not clear it again.
			 */
			folio_lock(folio);
			if (!folio_test_uptodate(folio)) {
				clear_highpage(folio_page(folio, 0));
				folio_mark_uptodate(folio);
			}
			folio_unlock(folio);

			err = kho_preserve_folio(folio);
			if (err)
				break;

			folios[*nr].pfn = folio_pfn(folio);
			folios[*nr].flags = KVM_GMEM_LUO_FOLIO_UPTODATE;
			folios[*nr].index = folio->index;
			(*nr)++;
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}

	return err;
}

static int kvm_gmem_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct kvm *kvm = kvm_gmem_file_kvm(args->file);
	bool has_private = kvm_arch_has_private_mem(kvm);
	u8 features[KVM_GMEM_LUO_FEAT_MAX] = {
		[KVM_GMEM_LUO_FEAT_CORE]	= LUO_FEAT_REQUIRED,
	};
	struct kvm_gmem_luo_attr_range *attr_ranges = NULL;
	struct kvm_gmem_luo_folio *folios = NULL;
	struct inode *inode = file_inode(args->file);
	struct kvm_gmem_luo_state *state;
	struct kvm_gmem_luo_priv *priv;
	u64 flags, max, nr = 0, nr_attr_ranges = 0, vm_id = 0;
	int err;

	flags = kvm_gmem_file_flags(args->file);
	if (flags & ~KVM_GMEM_LUO_ALL_FLAGS)
		return -EOPNOTSUPP;
	if (!has_private && !(flags & GUEST_MEMFD_FLAG_INIT_SHARED))
		return -EOPNOTSUPP;
	if (has_private) {
		if (!gmem_in_place_conversion ||
		    !kvm_arch_supports_gmem_init_shared(kvm))
			return -EOPNOTSUPP;
		scoped_guard(mutex, &kvm->lock) {
			err = kvm_arch_gmem_luo_get_vm_id(kvm, &vm_id);
			if (err)
				return err;
		}
	}

	priv = kzalloc_obj(*priv);
	if (!priv)
		return -ENOMEM;

	state = kho_alloc_preserve(sizeof(*state));
	if (IS_ERR(state)) {
		kfree(priv);
		return PTR_ERR(state);
	}

	/*
	 * Once frozen, the page cache and attributes cannot change, so the
	 * mapping holds exactly nrpages order-0 folios until the reboot or
	 * until unpreserve.
	 */
	kvm_gmem_freeze(args->file, true);

	max = READ_ONCE(inode->i_mapping->nrpages);
	if (max) {
		folios = vcalloc(max, sizeof(*folios));
		if (!folios) {
			err = -ENOMEM;
			goto err_unfreeze;
		}

		err = kvm_gmem_luo_preserve_folios(inode, folios, max, &nr);
		if (!err && WARN_ON_ONCE(nr != max))
			err = -EINVAL;
		if (!err)
			err = kho_preserve_vmalloc(folios, &state->folios);
		if (err)
			goto err_unpreserve_folios;
	}

	if (has_private) {
		features[KVM_GMEM_LUO_FEAT_PRIVATE] = LUO_FEAT_REQUIRED;
		err = kvm_gmem_preserve_attributes(inode, &attr_ranges,
						   &nr_attr_ranges);
		if (err)
			goto err_unpreserve_vmalloc_folios;
		if (nr_attr_ranges) {
			err = kho_preserve_vmalloc(attr_ranges,
						   &state->attr_ranges);
			if (err)
				goto err_free_attr_ranges;
		}
	}

	luo_feature_hdr_init(&state->features, sizeof(*state), features);
	state->size = i_size_read(inode);
	state->flags = flags;
	state->nr_folios = nr;
	state->nr_attr_ranges = nr_attr_ranges;
	state->vm_id = vm_id;

	priv->folios = folios;
	priv->attr_ranges = attr_ranges;
	args->serialized_data = __pa(state);
	args->private_data = priv;
	return 0;

err_free_attr_ranges:
	vfree(attr_ranges);
err_unpreserve_vmalloc_folios:
	if (nr)
		kho_unpreserve_vmalloc(&state->folios);
err_unpreserve_folios:
	kvm_gmem_luo_unpreserve_folios(folios, nr);
	vfree(folios);
err_unfreeze:
	kvm_gmem_freeze(args->file, false);
	kho_unpreserve_free(state);
	kfree(priv);
	return err;
}

static int kvm_gmem_luo_freeze(struct liveupdate_file_op_args *args)
{
	struct kvm_gmem_luo_state *state = __va(args->serialized_data);
	struct kvm *kvm = kvm_gmem_file_kvm(args->file);
	u64 vm_id;

	if (!luo_feature_is_active(&state->features, KVM_GMEM_LUO_FEAT_PRIVATE))
		return 0;

	guard(mutex)(&kvm->lock);
	if (kvm->vm_dead || kvm_arch_gmem_luo_get_vm_id(kvm, &vm_id) ||
	    vm_id != state->vm_id)
		return -EBUSY;

	return 0;
}

static void kvm_gmem_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_gmem_luo_state *state = __va(args->serialized_data);
	struct kvm_gmem_luo_priv *priv = args->private_data;

	if (state->nr_attr_ranges) {
		kho_unpreserve_vmalloc(&state->attr_ranges);
		vfree(priv->attr_ranges);
	}
	if (state->nr_folios) {
		kho_unpreserve_vmalloc(&state->folios);
		kvm_gmem_luo_unpreserve_folios(priv->folios, state->nr_folios);
		vfree(priv->folios);
	}
	kfree(priv);
	kho_unpreserve_free(state);

	kvm_gmem_freeze(args->file, false);
}

static void kvm_gmem_luo_discard_folios(const struct kvm_gmem_luo_folio *folios,
					u64 nr, bool has_private)
{
	u64 i;

	for (i = 0; i < nr; i++) {
		struct folio *folio = kho_restore_folio(PFN_PHYS(folios[i].pfn));

		if (!folio)
			continue;
#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_RECLAIM
		if (has_private)
			kvm_arch_gmem_reclaim(folio_pfn(folio),
					      folio_nr_pages(folio));
#else
		(void)has_private;
#endif
		folio_put(folio);
	}
}

/* Free the folios and the state of a guest_memfd that is not retrieved. */
static void kvm_gmem_luo_discard(struct kvm_gmem_luo_state *state)
{
	bool has_core = luo_feature_is_active(&state->features,
					      KVM_GMEM_LUO_FEAT_CORE);
	bool has_private = luo_feature_is_active(&state->features,
						 KVM_GMEM_LUO_FEAT_PRIVATE);
	struct kvm_gmem_luo_attr_range *ranges;
	struct kvm_gmem_luo_folio *folios;

	if (has_private && state->features.size >= sizeof(*state) &&
	    state->nr_attr_ranges) {
		ranges = kho_restore_vmalloc(&state->attr_ranges);
		vfree(ranges);
	}
	if (has_core &&
	    state->features.size >= offsetofend(struct kvm_gmem_luo_state, folios) &&
	    state->nr_folios) {
		folios = kho_restore_vmalloc(&state->folios);
		if (folios) {
			kvm_gmem_luo_discard_folios(folios, state->nr_folios,
						    has_private);
			vfree(folios);
		}
	}
	kho_restore_free(state);
}

static int kvm_gmem_luo_restore_attributes(struct file *file,
					   const struct kvm_gmem_luo_state *state)
{
	struct kvm_gmem_luo_attr_range *ranges = NULL;
	int err;

	if (state->nr_attr_ranges) {
		ranges = kho_restore_vmalloc(&state->attr_ranges);
		if (!ranges)
			return -ENOMEM;
	}

	err = kvm_gmem_restore_attributes(file, ranges, state->nr_attr_ranges);
	vfree(ranges);
	return err;
}

/*
 * Add the preserved folios to the page cache of @file. On failure, the folios
 * that were added are freed with @file, and the others are freed here.
 */
static int kvm_gmem_luo_restore_folios(struct file *file,
				       const struct kvm_gmem_luo_state *state,
				       bool has_private)
{
	struct address_space *mapping = file->f_mapping;
	struct kvm_gmem_luo_folio *folios;
	int err = 0;
	u64 i;

	if (!state->nr_folios)
		return 0;

	folios = kho_restore_vmalloc(&state->folios);
	if (!folios)
		return -ENOMEM;

	for (i = 0; i < state->nr_folios; i++) {
		struct folio *folio;

		if ((folios[i].flags & ~KVM_GMEM_LUO_FOLIO_UPTODATE) ||
		    folios[i].index >= (state->size >> PAGE_SHIFT)) {
			err = -EINVAL;
			kvm_gmem_luo_discard_folios(folios + i,
						    state->nr_folios - i,
						    has_private);
			break;
		}

		folio = kho_restore_folio(PFN_PHYS(folios[i].pfn));
		if (!folio) {
			err = -EIO;
			kvm_gmem_luo_discard_folios(folios + i + 1,
						    state->nr_folios - i - 1,
						    has_private);
			break;
		}

		err = filemap_add_folio(mapping, folio, folios[i].index,
					mapping_gfp_mask(mapping));
		if (err) {
#ifdef CONFIG_HAVE_KVM_ARCH_GMEM_RECLAIM
			if (has_private)
				kvm_arch_gmem_reclaim(folio_pfn(folio),
						      folio_nr_pages(folio));
#endif
			folio_put(folio);
			kvm_gmem_luo_discard_folios(folios + i + 1,
						    state->nr_folios - i - 1,
						    has_private);
			break;
		}

		if (folios[i].flags & KVM_GMEM_LUO_FOLIO_UPTODATE)
			folio_mark_uptodate(folio);
		folio_unlock(folio);
		folio_put(folio);
	}

	vfree(folios);
	return err;
}

static int kvm_gmem_luo_retrieve(struct liveupdate_file_op_args *args)
{
	const struct kvm_guest_memfd_luo_retrieve *arg = args->arg;
	struct kvm_gmem_luo_state *state = __va(args->serialized_data);
	bool has_private;
	struct file *file;
	struct kvm *kvm;
	int err;

	err = luo_feature_hdr_validate(&state->features, kvm_gmem_luo_features);
	if (err) {
		kvm_gmem_luo_discard(state);
		return err;
	}

	has_private = luo_feature_is_active(&state->features,
					    KVM_GMEM_LUO_FEAT_PRIVATE);
	if (has_private &&
	    !luo_feature_is_req(&state->features, KVM_GMEM_LUO_FEAT_PRIVATE)) {
		kvm_gmem_luo_discard(state);
		return -EINVAL;
	}

	if (state->features.size <
	    (has_private ? sizeof(*state) :
			   offsetofend(struct kvm_gmem_luo_state, folios)) ||
	    (loff_t)state->size <= 0 || !PAGE_ALIGNED(state->size) ||
	    (!has_private && !(state->flags & GUEST_MEMFD_FLAG_INIT_SHARED)) ||
	    (state->flags & ~KVM_GMEM_LUO_ALL_FLAGS) ||
	    state->nr_folios > (state->size >> PAGE_SHIFT)) {
		kvm_gmem_luo_discard(state);
		return -EINVAL;
	}

	/*
	 * Until the new guest_memfd is populated, nothing has been consumed.
	 * Let userspace retry with a different argument.
	 */
	args->retryable = true;

	if (!arg)
		return -EINVAL;

	CLASS(fd, f)(arg->vm_fd);
	if (fd_empty(f))
		return -EBADF;

	if (!file_is_kvm(fd_file(f)))
		return -EINVAL;

	/* Like the VM ioctls, only accept VMs of the calling process. */
	kvm = fd_file(f)->private_data;
	if (kvm->mm != current->mm || kvm->vm_dead)
		return -EIO;

	if (kvm_arch_has_private_mem(kvm) != has_private ||
	    (has_private && (!gmem_in_place_conversion ||
			     !kvm_arch_supports_gmem_init_shared(kvm))) ||
	    state->flags & ~kvm_gmem_get_supported_flags(kvm))
		return -EINVAL;
	if (has_private) {
		scoped_guard(mutex, &kvm->lock) {
			if (!kvm_arch_gmem_luo_validate_vm_id(kvm,
							      state->vm_id))
				return -EINVAL;
		}
	}

	file = kvm_gmem_create_file(kvm, state->size, state->flags);
	if (IS_ERR(file))
		return PTR_ERR(file);

	args->retryable = false;

	if (has_private) {
		err = kvm_gmem_luo_restore_attributes(file, state);
		if (err) {
			state->nr_attr_ranges = 0;
			kvm_gmem_luo_discard(state);
			fput(file);
			return err;
		}
	}

	err = kvm_gmem_luo_restore_folios(file, state, has_private);
	kho_restore_free(state);
	if (err) {
		fput(file);
		return err;
	}

	args->file = file;
	return 0;
}

static void kvm_gmem_luo_finish(struct liveupdate_file_op_args *args)
{
	/*
	 * Retrieving has freed the state unless it was never attempted or
	 * failed with a retryable error.
	 */
	if (args->retrieve_status)
		return;

	kvm_gmem_luo_discard(__va(args->serialized_data));
}

static struct liveupdate_file_ops kvm_gmem_luo_file_ops = {
	.can_preserve	= kvm_gmem_luo_can_preserve,
	.preserve	= kvm_gmem_luo_preserve,
	.freeze		= kvm_gmem_luo_freeze,
	.unpreserve	= kvm_gmem_luo_unpreserve,
	.retrieve	= kvm_gmem_luo_retrieve,
	.finish		= kvm_gmem_luo_finish,
	.get_id		= kvm_gmem_luo_get_id,
	.rarg		= LIVEUPDATE_ARG(struct kvm_guest_memfd_luo_retrieve, vm_fd),
};

static struct liveupdate_file_handler kvm_gmem_luo_handler = {
	.ops	= &kvm_gmem_luo_file_ops,
	.name	= KVM_GMEM_LUO_FH_NAME,
};

int kvm_gmem_luo_init(struct module *module)
{
	int r;

	/* Pin the module that provides guest_memfd, as kvm_gmem_init() does. */
	kvm_gmem_luo_file_ops.owner = module;

	r = liveupdate_register_file_handler(&kvm_gmem_luo_handler);

	/* Live update is disabled, nothing to do. */
	if (r == -EOPNOTSUPP)
		return 0;

	return r;
}

void kvm_gmem_luo_exit(void)
{
	liveupdate_unregister_file_handler(&kvm_gmem_luo_handler);
}
