// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * Guestmemfd Preservation for Live Update Orchestrator (LUO)
 */

/**
 * DOC: Guestmemfd Preservation via LUO
 *
 * Overview
 * ========
 *
 * Guest memory file descriptors (guest_memfd) can be preserved over a kexec
 * reboot using the Live Update Orchestrator (LUO) file preservation. This
 * allows userspace to preserve VM memory across kexec reboots.
 *
 * The preservation is not intended to be transparent. Only select properties
 * of the guest_memfd are preserved, while others are reset to default.
 *
 * .. note::
 *    Currently, only guest_memfd backed by standard system page size (PAGE_SIZE)
 *    is supported. Huge pages are not supported.
 *
 * Preserved Properties
 * ====================
 *
 * The following properties of guest_memfd are preserved across kexec:
 *
 * File Size
 *   The size of the file is preserved.
 *
 * File Contents
 *   All folios present in the page cache are preserved.
 *
 * File-level Flags
 *   The file-level flags (such as MMAP support and INIT_SHARED default mapping)
 *   are preserved.
 *
 * Non-Preserved Properties
 * ========================
 *
 * NUMA Memory Policy
 *   NUMA memory policies associated with the guest_memfd are not preserved.
 */
#include <linux/liveupdate.h>
#include <linux/kvm_host.h>
#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/err.h>
#include <linux/anon_inodes.h>
#include <linux/magic.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include "guest_memfd.h"

static bool kvm_gmem_luo_can_preserve(struct liveupdate_file_handler *handler, struct file *file)
{
	struct inode *inode = file_inode(file);

	if (inode->i_sb->s_magic != GUEST_MEMFD_MAGIC)
		return 0;

	if (mapping_large_folio_support(inode->i_mapping))
		return 0;

	if (GMEM_I(inode)->flags & GUEST_MEMFD_FLAG_INIT_SHARED)
		return 1;

	return 0;
}

static int kvm_gmem_luo_walk_folios(struct address_space *mapping, pgoff_t end_index,
				    struct guest_memfd_luo_folio_ser *folios_ser, u64 *out_count)
{
	pgoff_t index = 0;
	struct folio_batch fbatch;
	u64 count = 0;
	int err = 0;

	folio_batch_init(&fbatch);
	while (index < end_index) {
		unsigned int nr, i;

		nr = filemap_get_folios(mapping, &index, end_index - 1, &fbatch);
		if (nr == 0)
			break;

		for (i = 0; i < nr; i++) {
			struct folio *folio = fbatch.folios[i];

			if (folios_ser) {
				if (folio_test_hwpoison(folio)) {
					err = -EHWPOISON;
					folio_batch_release(&fbatch);
					goto out;
				}
				err = kho_preserve_folio(folio);
				if (err) {
					folio_batch_release(&fbatch);
					goto out;
				}

				folios_ser[count].pfn = folio_pfn(folio);
				folios_ser[count].index = folio->index;
				folios_ser[count].flags = 0; /* TODO: Add flags if needed */
			}
			count++;
		}
		folio_batch_release(&fbatch);
		cond_resched();
	}

out:
	*out_count = count;
	return err;
}

static int kvm_gmem_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct inode *inode = file_inode(args->file);
	struct address_space *mapping = inode->i_mapping;
	struct guest_memfd_luo_ser *ser;
	struct guest_memfd_luo_folio_ser *folios_ser;
	struct gmem_file *gmem_file;
	struct kvm *kvm;
	struct file *kvm_file;
	u64 vm_token;
	u64 count, gmem_flags, abi_flags = 0;
	pgoff_t end_index;
	int err = 0;
	long size;

	size = i_size_read(inode);
	if (!size)
		return 0;

	if (WARN_ON_ONCE(size & (PAGE_SIZE - 1)))
		return -EINVAL;

	gmem_file = args->file->private_data;
	kvm = gmem_file->kvm;

	gmem_flags = READ_ONCE(GMEM_I(inode)->flags);
	if (gmem_flags & ~GUEST_MEMFD_LUO_SUPPORTED_FLAGS)
		return -EOPNOTSUPP;

	if (gmem_flags & GUEST_MEMFD_FLAG_MMAP)
		abi_flags |= GUEST_MEMFD_LUO_FLAG_MMAP;
	if (gmem_flags & GUEST_MEMFD_FLAG_INIT_SHARED)
		abi_flags |= GUEST_MEMFD_LUO_FLAG_INIT_SHARED;

	/*
	 * KVM is preserved before the guest_memfd preserve is called
	 * if not, this will fail here.
	 *
	 * Obtain a strong reference to kvm->vm_file to prevent the SLAB_TYPESAFE_BY_RCU
	 * file memory from being reallocated while it is being processed.
	 */
	kvm_file = get_file_active(&kvm->vm_file);
	if (!kvm_file)
		return -ENOENT;

	err = liveupdate_get_token_outgoing(args->session, kvm_file, &vm_token);
	fput(kvm_file);
	if (err)
		return err;

	end_index = size >> PAGE_SHIFT;

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser))
		return PTR_ERR(ser);

	/*
	 * Freeze the guest_memfd mapping to prevent any concurrent host-side
	 * modifications (such as fallocate, hole punching, or memory pre-population)
	 * during the live update preservation window.
	 */
	kvm_gmem_freeze(inode, true);

	/*
	 * Walk 1: Count the exact number of folios present in the page cache.
	 * This helps in determining the exact memory needed to preserve the
	 * guest memfd pages. The total size guest_memfd might be in TBs, but
	 * the present pages in page cache would be small. Also helps with
	 * guest_memfd file with holes.
	 */
	err = kvm_gmem_luo_walk_folios(mapping, end_index, NULL, &count);
	if (err)
		goto err_free_ser;

	folios_ser = NULL;
	if (count > 0) {
		folios_ser = vcalloc(count, sizeof(*folios_ser));
		if (!folios_ser) {
			err = -ENOMEM;
			goto err_free_ser;
		}

		/* Walk 2: Fill the metadata array */
		err = kvm_gmem_luo_walk_folios(mapping, end_index, folios_ser, &count);
		if (err)
			goto err_unpreserve_unlocked;
	}

	ser->size = size;
	ser->flags = abi_flags;
	ser->nr_folios = count;
	ser->vm_token = vm_token;

	if (count > 0) {
		err = kho_preserve_vmalloc(folios_ser, &ser->folios);
		if (err)
			goto err_unpreserve_unlocked;
	}

	args->serialized_data = virt_to_phys(ser);
	args->private_data = folios_ser;

	return 0;

err_unpreserve_unlocked:
	for (long i = count - 1; i >= 0; i--) {
		struct folio *folio = pfn_folio(folios_ser[i].pfn);

		kho_unpreserve_folio(folio);
	}
	vfree(folios_ser);
err_free_ser:
	kvm_gmem_freeze(inode, false);
	kho_unpreserve_free(ser);
	return err;
}

static void kvm_gmem_luo_discard_folios(const struct guest_memfd_luo_folio_ser *folios_ser,
					u64 nr_folios, u64 start_idx)
{
	long i;

	for (i = start_idx; i < nr_folios; i++) {
		struct folio *folio;
		phys_addr_t phys;

		if (!folios_ser[i].pfn)
			continue;

		phys = PFN_PHYS(folios_ser[i].pfn);
		folio = kho_restore_folio(phys);
		if (folio)
			folio_put(folio);
	}
}

static void kvm_gmem_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct inode *inode = file_inode(args->file);
	struct guest_memfd_luo_folio_ser *folios_ser = args->private_data;
	struct guest_memfd_luo_ser *ser;
	long i;

	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return;

	kvm_gmem_freeze(inode, false);

	if (ser->nr_folios > 0)
		kho_unpreserve_vmalloc(&ser->folios);
	for (i = ser->nr_folios - 1; i >= 0; i--) {
		struct folio *folio;

		if (!folios_ser[i].pfn)
			continue;

		folio = pfn_folio(folios_ser[i].pfn);
		kho_unpreserve_folio(folio);
	}
	vfree(folios_ser);

	kho_unpreserve_free(ser);
}

static int kvm_gmem_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct guest_memfd_luo_folio_ser *folios_ser = NULL;
	struct guest_memfd_luo_ser *ser;
	struct file *file;
	u64 gmem_flags = 0;
	struct inode *inode;
	struct file *vm_file;
	struct kvm *kvm = NULL;
	int err = 0;
	long i = 0;

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return -EINVAL;

	if (ser->flags & ~GUEST_MEMFD_LUO_SUPPORTED_FLAGS) {
		err = -EOPNOTSUPP;
		goto err_free_ser;
	}

	if (ser->flags & GUEST_MEMFD_LUO_FLAG_MMAP)
		gmem_flags |= GUEST_MEMFD_FLAG_MMAP;
	if (ser->flags & GUEST_MEMFD_LUO_FLAG_INIT_SHARED)
		gmem_flags |= GUEST_MEMFD_FLAG_INIT_SHARED;

	/*
	 * Retrieve KVM VM file locklessly to enforce the correct retrieval sequence
	 * (parent must be retrieved before guest_memfd) and avoid nested locking.
	 */
	vm_file = liveupdate_file_get_retrieved(args->session, ser->vm_token);
	if (!vm_file) {
		pr_warn("gmem: VM FD (token %llx) must be retrieved first\n", ser->vm_token);
		return -EAGAIN;
	}

	if (file_is_kvm(vm_file))
		kvm = vm_file->private_data;

	/* Release the temporary reference, LUO still has a reference */
	fput(vm_file);

	if (!kvm) {
		err = -EINVAL;
		goto err_free_ser;
	}

	file = __kvm_gmem_create_file(kvm, ser->size, gmem_flags);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_free_ser;
	}

	inode = file_inode(file);

	if (ser->nr_folios) {
		folios_ser = kho_restore_vmalloc(&ser->folios);
		if (!folios_ser) {
			err = -EINVAL;
			goto err_destroy_file;
		}

		for (i = 0; i < ser->nr_folios; i++) {
			struct folio *folio;
			phys_addr_t phys;

			if (!folios_ser[i].pfn)
				continue;

			phys = PFN_PHYS(folios_ser[i].pfn);
			folio = kho_restore_folio(phys);
			if (!folio) {
				pr_err("gmem: failed to restore folio at %llx\n", phys);
				err = -EIO;
				goto err_put_remaining_folios;
			}

			err = filemap_add_folio(inode->i_mapping, folio, folios_ser[i].index,
						GFP_KERNEL);
			if (err) {
				pr_err("gmem: failed to add folio to page cache\n");
				folio_put(folio);
				goto err_put_remaining_folios;
			}

			folio_mark_uptodate(folio);
			folio_unlock(folio);
			folio_put(folio);
		}
		vfree(folios_ser);
	}

	args->file = file;
	kho_restore_free(ser);
	return 0;

err_put_remaining_folios:
	i++;
err_destroy_file:
	fput(file);
err_free_ser:
	if (ser->nr_folios) {
		if (!folios_ser)
			folios_ser = kho_restore_vmalloc(&ser->folios);
		if (folios_ser) {
			kvm_gmem_luo_discard_folios(folios_ser, ser->nr_folios, i);
			vfree(folios_ser);
		}
	}
	kho_restore_free(ser);
	return err;
}

static void kvm_gmem_luo_finish(struct liveupdate_file_op_args *args)
{
	struct guest_memfd_luo_ser *ser;
	struct guest_memfd_luo_folio_ser *folios_ser;

	/* Nothing to be done here, if retrieve_status was successful or errored,
	 * Cleanup is taken care of in retrieval call.
	 */
	if (args->retrieve_status)
		return;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return;

	if (ser->nr_folios) {
		folios_ser = kho_restore_vmalloc(&ser->folios);
		if (folios_ser) {
			kvm_gmem_luo_discard_folios(folios_ser, ser->nr_folios, 0);
			vfree(folios_ser);
		}
	}

	kho_restore_free(ser);
}

static const struct liveupdate_file_ops kvm_gmem_luo_file_ops = {
	.can_preserve = kvm_gmem_luo_can_preserve,
	.preserve = kvm_gmem_luo_preserve,
	.retrieve = kvm_gmem_luo_retrieve,
	.unpreserve = kvm_gmem_luo_unpreserve,
	.finish = kvm_gmem_luo_finish,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler kvm_gmem_luo_handler = {
	.ops = &kvm_gmem_luo_file_ops,
	.compatible = GUEST_MEMFD_LUO_FH_COMPATIBLE,
};

static int __init kvm_gmem_luo_init(void)
{
	int err = liveupdate_register_file_handler(&kvm_gmem_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register luo filesystem handler: %pe\n", ERR_PTR(err));
		return err;
	}

	return 0;
}
late_initcall(kvm_gmem_luo_init);
