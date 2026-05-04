// SPDX-License-Identifier: GPL-2.0

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM VM Preservation for Live Update Orchestrator (LUO)
 * Currently this preserves only vm type and memory attributes.
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
#include "kvm_mm.h"

static bool kvm_luo_can_preserve(struct liveupdate_file_handler *handler, struct file *file)
{
	return file_is_kvm(file);
}

static int kvm_luo_preserve(struct liveupdate_file_op_args *args)
{
	struct kvm *kvm = args->file->private_data;
	struct kvm_luo_ser *ser;
	struct kvm_luo_mem_attr *mem_attrs = NULL;
	unsigned long index;
	void *attributes;
	u64 count = 0;
	int err = 0;

	if (kvm->vm_dead || kvm->vm_bugged)
		return -EINVAL;

	ser = kho_alloc_preserve(sizeof(*ser));
	if (IS_ERR(ser))
		return PTR_ERR(ser);

	mutex_lock(&kvm->slots_lock);

	xa_for_each(&kvm->mem_attr_array, index, attributes) {
		count++;
	}

	if (count == 0) {
		mutex_unlock(&kvm->slots_lock);
		goto serialize_ser;
	}

	mem_attrs = vcalloc(count, sizeof(*mem_attrs));
	if (!mem_attrs) {
		mutex_unlock(&kvm->slots_lock);
		err = -ENOMEM;
		goto err_free_ser;
	}

	count = 0;
	xa_for_each(&kvm->mem_attr_array, index, attributes) {
		mem_attrs[count].gfn = index;
		mem_attrs[count].attributes = (u64)attributes;
		count++;
	}

	mutex_unlock(&kvm->slots_lock);

serialize_ser:
#ifdef CONFIG_X86
	ser->type = kvm->arch.vm_type;
#else
	ser->type = 0;
#endif
	ser->nr_mem_attrs = count;

	if (count > 0) {
		err = kho_preserve_vmalloc(mem_attrs, &ser->mem_attrs);
		if (err) {
			vfree(mem_attrs);
			goto err_free_ser;
		}
	}

	args->serialized_data = virt_to_phys(ser);
	args->private_data = mem_attrs;

	return 0;

err_free_ser:
	kho_unpreserve_free(ser);
	return err;
}

static atomic_t restored_vm_id = ATOMIC_INIT(0);

static int kvm_luo_retrieve(struct liveupdate_file_op_args *args)
{
	struct kvm_luo_ser *ser;
	struct kvm_luo_mem_attr *mem_attrs = NULL;
	bool mem_attrs_restored = false;
	struct kvm *kvm;
	struct file *file;
	char fdname[ITOA_MAX_LEN + 1];
	int err = 0;
	u64 i;

	if (!args->serialized_data)
		return -EINVAL;

	ser = phys_to_virt(args->serialized_data);

	snprintf(fdname, sizeof(fdname), "%d",
		 atomic_inc_return(&restored_vm_id));

	file = kvm_create_vm_file(ser->type, fdname);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_free_ser;
	}

	kvm = file->private_data;

	if (ser->nr_mem_attrs) {
		mem_attrs = kho_restore_vmalloc(&ser->mem_attrs);
		mem_attrs_restored = true;
		if (!mem_attrs) {
			err = -EINVAL;
			goto err_destroy_file;
		}

		for (i = 0; i < ser->nr_mem_attrs; i++) {
			err = xa_err(xa_store(&kvm->mem_attr_array, mem_attrs[i].gfn,
					      (void *)(unsigned long)mem_attrs[i].attributes,
					      GFP_KERNEL_ACCOUNT));
			if (err)
				break;
		}
		vfree(mem_attrs);
		mem_attrs = NULL;
		if (err)
			goto err_destroy_file;
	}

	args->file = file;
	kho_restore_free(ser);

	kvm_uevent_notify_vm_create(kvm);
	return 0;

err_destroy_file:
	fput(file);
err_free_ser:
	if (ser->nr_mem_attrs && !mem_attrs_restored)
		mem_attrs = kho_restore_vmalloc(&ser->mem_attrs);
	vfree(mem_attrs);
	kho_restore_free(ser);
	return err;
}

static void kvm_luo_unpreserve(struct liveupdate_file_op_args *args)
{
	struct kvm_luo_ser *ser;
	struct kvm_luo_mem_attr *mem_attrs = args->private_data;

	if (mem_attrs)
		vfree(mem_attrs);

	/*
	 * in case preservation failed, args->serialized_data will
	 * be NULL. In case of preservation failure, kvm_luo_preserve
	 * takes care of cleaning up and unlocking.
	 * If preserve succeeds, this condition fails and unpreserve
	 * function takes care of cleaning up and unlocking.
	 */
	if (WARN_ON_ONCE(!args->serialized_data))
		return;

	ser = phys_to_virt(args->serialized_data);

	if (ser->nr_mem_attrs)
		kho_unpreserve_vmalloc(&ser->mem_attrs);
	kho_unpreserve_free(ser);
}

static void kvm_luo_finish(struct liveupdate_file_op_args *args)
{
	struct kvm_luo_ser *ser;
	struct kvm_luo_mem_attr *mem_attrs;

	/*
	 * If retrieve_status is true or set to error, nothing to do here.
	 * Already cleaned up in kvm_luo_retrieve().
	 */
	if (args->retrieve_status)
		return;

	if (!args->serialized_data)
		return;

	ser = phys_to_virt(args->serialized_data);
	if (!ser)
		return;

	if (ser->nr_mem_attrs) {
		mem_attrs = kho_restore_vmalloc(&ser->mem_attrs);
		if (mem_attrs)
			vfree(mem_attrs);
	}

	kho_restore_free(ser);
}

static const struct liveupdate_file_ops kvm_luo_file_ops = {
	.can_preserve = kvm_luo_can_preserve,
	.preserve = kvm_luo_preserve,
	.retrieve = kvm_luo_retrieve,
	.unpreserve = kvm_luo_unpreserve,
	.finish = kvm_luo_finish,
	.owner = THIS_MODULE,
};

static struct liveupdate_file_handler kvm_luo_handler = {
	.ops = &kvm_luo_file_ops,
	.compatible = KVM_LUO_FH_COMPATIBLE,
};

static int __init kvm_luo_init(void)
{
	int err = liveupdate_register_file_handler(&kvm_luo_handler);

	if (err && err != -EOPNOTSUPP) {
		pr_err("Could not register kvm_vm_luo handler: %pe\n", ERR_PTR(err));
		return err;
	}

	return 0;
}
late_initcall(kvm_luo_init);
