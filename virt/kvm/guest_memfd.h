/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_GUEST_MEMFD_H__
#define __KVM_GUEST_MEMFD_H__

#include <linux/kvm_types.h>

struct file;

#ifdef CONFIG_KVM_GUEST_MEMFD
int kvm_gmem_init(struct module *module);
void kvm_gmem_exit(void);
int kvm_gmem_create(struct kvm *kvm, struct kvm_create_guest_memfd *args);
struct file *kvm_gmem_create_file(struct kvm *kvm, loff_t size, u64 flags);
int kvm_gmem_prepare_memory_region(struct kvm *kvm, struct kvm_memory_slot *slot,
				   unsigned int fd, uoff_t offset);
int kvm_gmem_commit_memory_region(struct kvm *kvm, struct kvm_memory_slot *slot);
void kvm_gmem_unbind(struct kvm_memory_slot *slot);
#else
static inline int kvm_gmem_init(struct module *module)
{
	return 0;
}
static inline void kvm_gmem_exit(void) {};

static inline int kvm_gmem_prepare_memory_region(struct kvm *kvm,
						 struct kvm_memory_slot *slot,
						 unsigned int fd, uoff_t offset)
{
	WARN_ON_ONCE(1);
	return -EIO;
}

static inline int kvm_gmem_commit_memory_region(struct kvm *kvm,
						struct kvm_memory_slot *slot)
{
	WARN_ON_ONCE(1);
	return -EIO;
}

static inline void kvm_gmem_unbind(struct kvm_memory_slot *slot)
{
	WARN_ON_ONCE(1);
}
#endif /* CONFIG_KVM_GUEST_MEMFD */

#if defined(CONFIG_KVM_GUEST_MEMFD) && defined(CONFIG_LIVEUPDATE)
struct inode;
struct kvm_gmem_luo_attr_range;

void kvm_gmem_freeze(struct file *file, bool freeze);
struct kvm *kvm_gmem_file_kvm(struct file *file);
u64 kvm_gmem_file_flags(struct file *file);
int kvm_gmem_preserve_attributes(struct inode *inode,
				 struct kvm_gmem_luo_attr_range **ranges_out,
				 u64 *nr_ranges_out);
int kvm_gmem_restore_attributes(struct file *file,
				const struct kvm_gmem_luo_attr_range *ranges,
				u64 nr_ranges);
int kvm_gmem_luo_init(struct module *module);
void kvm_gmem_luo_exit(void);
#else
static inline int kvm_gmem_luo_init(struct module *module)
{
	return 0;
}

static inline void kvm_gmem_luo_exit(void)
{
}
#endif

#endif /* __KVM_GUEST_MEMFD_H__ */
