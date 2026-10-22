// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * ARM64 KVM VM state preservation across live update.
 */

#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/maple_tree.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/kvm_emulate.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_vgic.h>

#include "vgic/vgic.h"

static void kvm_arm_save_vgic_irq(struct kvm_luo_vgic_irq_state *dst,
				  struct vgic_irq *src)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&src->irq_lock, flags);
	dst->intid = src->intid;
	dst->pending_latch = src->pending_latch;
	if (src->hw && src->intid < VGIC_NR_SGIS) {
		bool pending = false;

		if (!irq_get_irqchip_state(src->host_irq, IRQCHIP_STATE_PENDING,
					   &pending))
			dst->pending_latch = pending;
	}
	dst->active = src->active;
	dst->enabled = src->enabled;
	dst->config = (src->config == VGIC_CONFIG_EDGE) ? 1 : 0;
	dst->priority = src->priority;
	dst->group = src->group;
	dst->source = src->source;
	dst->active_source = src->active_source;
	dst->line_level = src->line_level;
	dst->targets = src->targets;
	if (src->active)
		dst->active_vcpu_id = src->vcpu ?
				      src->vcpu->vcpu_id :
				      src->luo_active_vcpu_id;
	else
		dst->active_vcpu_id = -1;
	dst->mpidr = src->mpidr;
	raw_spin_unlock_irqrestore(&src->irq_lock, flags);
}

static void kvm_arm_restore_vgic_irq(struct vgic_irq *dst,
				     const struct kvm_luo_vgic_irq_state *src)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&dst->irq_lock, flags);
	dst->pending_latch = src->pending_latch;
	dst->active = src->active;
	dst->enabled = src->enabled;
	dst->config = src->config ? VGIC_CONFIG_EDGE : VGIC_CONFIG_LEVEL;
	dst->priority = src->priority;
	dst->group = src->group;
	dst->source = src->source;
	dst->active_source = src->active_source;
	dst->line_level = src->line_level;
	dst->targets = src->targets;
	dst->luo_active_vcpu_id = src->active_vcpu_id;
	dst->mpidr = src->mpidr;
	raw_spin_unlock_irqrestore(&dst->irq_lock, flags);
}

static int kvm_arm_luo_save_vm_state(struct kvm *kvm,
				     struct kvm_luo_vm_arm64_state *s)
{
	unsigned long preserved_flags;

	guard(mutex)(&kvm->slots_lock);
	guard(mutex)(&kvm->arch.config_lock);

	if (kvm_has_mte(kvm) ||
	    test_bit(KVM_ARM_VCPU_PMU_V3, kvm->arch.vcpu_features) ||
	    test_bit(KVM_ARM_VCPU_HAS_EL2, kvm->arch.vcpu_features) ||
	    !mtree_empty(&kvm->arch.smccc_filter))
		return -EOPNOTSUPP;

	memset(s, 0, sizeof(*s));
	s->version = KVM_LUO_ARM64_VM_STATE_VERSION;
	s->psci_version = kvm->arch.psci_version;

	/*
	 * Clear HAS_RAN_ONCE and FGU_INITIALIZED so vCPU retrieval can run
	 * kvm_arch_vcpu_ioctl_vcpu_init() and the first KVM_RUN after kexec
	 * re-executes kvm_arch_vcpu_run_pid_change() and kvm_calculate_traps().
	 */
	preserved_flags = kvm->arch.flags &
			  ~(BIT(KVM_ARCH_FLAG_HAS_RAN_ONCE) |
			    BIT(KVM_ARCH_FLAG_FGU_INITIALIZED));
	s->arch_flags = preserved_flags;
	s->vcpu_features = kvm->arch.vcpu_features[0];
	s->smccc_std_bmap = kvm->arch.smccc_feat.std_bmap;
	s->smccc_std_hyp_bmap = kvm->arch.smccc_feat.std_hyp_bmap;
	s->smccc_vendor_hyp_bmap = kvm->arch.smccc_feat.vendor_hyp_bmap;
	s->smccc_vendor_hyp_bmap_2 = kvm->arch.smccc_feat.vendor_hyp_bmap_2;

	BUILD_BUG_ON(ARRAY_SIZE(s->id_regs) < KVM_ARM_ID_REG_NUM);
	memcpy(s->id_regs, kvm->arch.id_regs, sizeof(kvm->arch.id_regs));
	s->midr_el1 = kvm->arch.midr_el1;
	s->revidr_el1 = kvm->arch.revidr_el1;
	s->aidr_el1 = kvm->arch.aidr_el1;
	s->ctr_el0 = kvm->arch.ctr_el0;

	s->timer_voffset = kvm->arch.timer_data.voffset;
	s->timer_poffset = kvm->arch.timer_data.poffset;
	BUILD_BUG_ON(ARRAY_SIZE(s->timer_ppi) < NR_KVM_TIMERS);
	memcpy(s->timer_ppi, kvm->arch.timer_data.ppi,
	       sizeof(kvm->arch.timer_data.ppi));

	if (irqchip_in_kernel(kvm)) {
		struct vgic_dist *dist = &kvm->arch.vgic;
		struct vgic_redist_region *rdreg;
		u32 idx = 0;
		u32 i;

		if (dist->vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3 ||
		    dist->has_its)
			return -EOPNOTSUPP;
		if (!dist->initialized)
			return -EBUSY;
		if (dist->nr_spis > KVM_LUO_ARM64_MAX_SPIS)
			return -E2BIG;

		s->has_vgic = 1;
		s->vgic_model = dist->vgic_model;
		s->vgic_initialized = dist->initialized;
		s->vgic_enabled = dist->enabled;
		s->vgic_msis_require_devid = dist->msis_require_devid;
		s->vgic_nassgireq = dist->nassgireq;
		s->vgic_nassgicap = dist->nassgicap;
		s->vgic_implementation_rev = dist->implementation_rev;
		s->vgic_nr_spis = dist->nr_spis;
		s->vgic_dist_base = dist->vgic_dist_base;

		list_for_each_entry(rdreg, &dist->rd_regions, list) {
			if (idx >= KVM_LUO_ARM64_MAX_RD_REGIONS)
				return -E2BIG;
			s->rd_regions[idx].base = rdreg->base;
			s->rd_regions[idx].count = rdreg->count;
			s->rd_regions[idx].index = rdreg->index;
			idx++;
		}
		s->nr_rd_regions = idx;

		if (dist->initialized && dist->spis) {
			for (i = 0; i < dist->nr_spis; i++)
				kvm_arm_save_vgic_irq(&s->spis[i],
						      &dist->spis[i]);
		}
	}

	return 0;
}

int kvm_arch_luo_vm_preserve(struct kvm *kvm, u64 *arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;
	int ret;

	if (kvm_vm_is_protected(kvm) || kvm_is_realm(kvm))
		return -EOPNOTSUPP;

	scoped_guard(mutex, &kvm->arch.config_lock) {
		if (kvm_has_mte(kvm) ||
		    test_bit(KVM_ARM_VCPU_PMU_V3, kvm->arch.vcpu_features) ||
		    test_bit(KVM_ARM_VCPU_HAS_EL2, kvm->arch.vcpu_features) ||
		    !mtree_empty(&kvm->arch.smccc_filter))
			return -EOPNOTSUPP;

		if (irqchip_in_kernel(kvm)) {
			struct vgic_dist *dist = &kvm->arch.vgic;

			if (dist->vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3 ||
			    dist->has_its)
				return -EOPNOTSUPP;
			if (!dist->initialized)
				return -EBUSY;
			if (dist->nr_spis > KVM_LUO_ARM64_MAX_SPIS)
				return -E2BIG;
		}
	}

	s = kho_alloc_preserve(sizeof(*s));
	if (IS_ERR(s))
		return PTR_ERR(s);

	ret = kvm_arm_luo_save_vm_state(kvm, s);
	if (ret) {
		kho_unpreserve_free(s);
		return ret;
	}

	*arch_state_pa = __pa(s);
	return 0;
}

int kvm_arch_luo_vm_freeze(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return 0;

	return kvm_arm_luo_save_vm_state(kvm, __va(arch_state_pa));
}

void kvm_arch_luo_vm_unpreserve(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_unpreserve_free(__va(arch_state_pa));
}

int kvm_arch_luo_vm_retrieve(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;
	int ret = 0;
	u32 i;

	if (!arch_state_pa)
		return -EINVAL;

	s = __va(arch_state_pa);
	if (s->version != KVM_LUO_ARM64_VM_STATE_VERSION)
		return -EINVAL;

	scoped_guard(mutex, &kvm->arch.config_lock) {
		kvm->arch.psci_version = s->psci_version;
		kvm->arch.flags = s->arch_flags &
				  ~(BIT(KVM_ARCH_FLAG_MTE_ENABLED) |
				    BIT(KVM_ARCH_FLAG_HAS_RAN_ONCE) |
				    BIT(KVM_ARCH_FLAG_FGU_INITIALIZED));
		kvm->arch.vcpu_features[0] = s->vcpu_features;
		kvm->arch.smccc_feat.std_bmap = s->smccc_std_bmap;
		kvm->arch.smccc_feat.std_hyp_bmap = s->smccc_std_hyp_bmap;
		kvm->arch.smccc_feat.vendor_hyp_bmap = s->smccc_vendor_hyp_bmap;
		kvm->arch.smccc_feat.vendor_hyp_bmap_2 = s->smccc_vendor_hyp_bmap_2;

		memcpy(kvm->arch.id_regs, s->id_regs, sizeof(kvm->arch.id_regs));
		kvm->arch.midr_el1 = s->midr_el1;
		kvm->arch.revidr_el1 = s->revidr_el1;
		kvm->arch.aidr_el1 = s->aidr_el1;
		kvm->arch.ctr_el0 = s->ctr_el0;

		kvm->arch.timer_data.voffset = s->timer_voffset;
		kvm->arch.timer_data.poffset = s->timer_poffset;
		kvm->arch.timer_data.from_liveupdate = true;
		memcpy(kvm->arch.timer_data.ppi, s->timer_ppi,
		       sizeof(kvm->arch.timer_data.ppi));
	}

	if (s->has_vgic) {
		struct vgic_dist *dist = &kvm->arch.vgic;

		if (s->vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3 ||
		    s->vgic_nr_spis > KVM_LUO_ARM64_MAX_SPIS ||
		    s->nr_rd_regions > KVM_LUO_ARM64_MAX_RD_REGIONS)
			return -EINVAL;

		ret = kvm_vgic_create(kvm, s->vgic_model);
		if (ret)
			return ret;

		dist->from_liveupdate = true;
		dist->nr_spis = s->vgic_nr_spis;
		dist->vgic_dist_base = s->vgic_dist_base;
		dist->msis_require_devid = s->vgic_msis_require_devid;
		dist->nassgicap = system_supports_direct_sgis() ?
				  s->vgic_nassgicap : false;
		dist->nassgireq = vgic_supports_direct_sgis(kvm) ?
				  s->vgic_nassgireq : false;
		if (s->vgic_implementation_rev)
			dist->implementation_rev = s->vgic_implementation_rev;

		mutex_lock(&kvm->slots_lock);
		for (i = 0; i < s->nr_rd_regions; i++) {
			ret = vgic_v3_set_redist_base(kvm,
						      s->rd_regions[i].index,
						      s->rd_regions[i].base,
						      s->rd_regions[i].count);
			if (ret) {
				mutex_unlock(&kvm->slots_lock);
				return ret;
			}
		}
		mutex_unlock(&kvm->slots_lock);

		if (s->vgic_initialized) {
			mutex_lock(&kvm->arch.config_lock);
			ret = vgic_init(kvm);
			mutex_unlock(&kvm->arch.config_lock);
			if (ret)
				return ret;

			dist->enabled = s->vgic_enabled;
			for (i = 0; i < dist->nr_spis; i++)
				kvm_arm_restore_vgic_irq(&dist->spis[i],
							 &s->spis[i]);
		}
	}

	return 0;
}

void kvm_arch_luo_vm_finish(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_restore_free(__va(arch_state_pa));
}

