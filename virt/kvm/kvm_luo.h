/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KVM_LUO_H__
#define __KVM_LUO_H__

#include <linux/types.h>

struct kvm;
struct kvm_vcpu;
struct module;

#ifdef CONFIG_LIVEUPDATE
int kvm_vm_luo_init(struct module *module);
void kvm_vm_luo_exit(void);
#else
static inline int kvm_vm_luo_init(struct module *module)
{
	return 0;
}

static inline void kvm_vm_luo_exit(void)
{
}
#endif /* CONFIG_LIVEUPDATE */

#endif /* __KVM_LUO_H__ */
