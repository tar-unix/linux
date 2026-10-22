// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * ARM64 KVM VM and vCPU state preservation across live update.
 */

#include <linux/cleanup.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/maple_tree.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_rmi.h>
#include <kvm/arm_arch_timer.h>
#include <kvm/arm_vgic.h>

#include "sys_regs.h"
#include "vgic/vgic.h"

#define KVM_ARM_CSSELR_MAX	14

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

	memset(s, 0, offsetof(struct kvm_luo_vm_arm64_state, cca));
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

	if (kvm_vm_is_protected(kvm))
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

	if (kvm_is_realm(kvm)) {
		ret = kvm_realm_luo_preserve(kvm, &s->cca);
		if (ret) {
			kho_unpreserve_free(s);
			return ret;
		}
	}

	*arch_state_pa = __pa(s);
	return 0;
}

int kvm_arch_luo_vm_freeze(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;
	int ret;

	if (!arch_state_pa)
		return 0;

	s = __va(arch_state_pa);
	ret = kvm_arm_luo_save_vm_state(kvm, s);
	if (ret)
		return ret;

	if (kvm_is_realm(kvm))
		return kvm_realm_luo_freeze(kvm, &s->cca);

	return 0;
}

void kvm_arch_luo_vm_unfreeze(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;

	if (!arch_state_pa)
		return;

	s = __va(arch_state_pa);
	if (s->cca.rd_phys || s->cca.pgd_phys || s->cca.rtt_pfns.total_pages ||
	    (kvm && kvm_is_realm(kvm)))
		kvm_realm_luo_unfreeze(kvm, &s->cca);
}

void kvm_arch_luo_vm_unpreserve(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;

	if (!arch_state_pa)
		return;

	s = __va(arch_state_pa);
	if (s->cca.rd_phys || s->cca.pgd_phys || s->cca.rtt_pfns.total_pages ||
	    (kvm && kvm_is_realm(kvm)))
		kvm_realm_luo_unpreserve(kvm, &s->cca);

	kho_unpreserve_free(s);
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

	if (kvm_is_realm(kvm)) {
		ret = kvm_realm_luo_retrieve(kvm, &s->cca);
		if (ret)
			return ret;
	}

	return 0;
}

void kvm_arch_luo_vm_finish(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_arm64_state *s;

	if (!arch_state_pa)
		return;

	s = __va(arch_state_pa);
	if (s->cca.rd_phys || s->cca.pgd_phys || s->cca.rtt_pfns.total_pages ||
	    (kvm && kvm_is_realm(kvm)))
		kvm_realm_luo_finish(kvm, &s->cca);

	kho_restore_free(s);
}

int kvm_arch_gmem_luo_get_vm_id(struct kvm *kvm, u64 *vm_id)
{
	if (!kvm_is_realm(kvm) ||
	    kvm_realm_state(kvm) != REALM_STATE_ACTIVE ||
	    !READ_ONCE(kvm->arch.realm.luo_preserved) ||
	    !kvm->arch.realm.rd)
		return -EOPNOTSUPP;

	*vm_id = virt_to_phys(kvm->arch.realm.rd) | KVM_VM_LUO_FEAT_ARM_CCA;
	return 0;
}

bool kvm_arch_gmem_luo_validate_vm_id(struct kvm *kvm, u64 vm_id)
{
	if (!kvm_is_realm(kvm) ||
	    kvm_realm_state(kvm) != REALM_STATE_ACTIVE ||
	    !kvm->arch.realm.luo_retrieved ||
	    !kvm->arch.realm.rd)
		return false;

	return (virt_to_phys(kvm->arch.realm.rd) |
		KVM_VM_LUO_FEAT_ARM_CCA) == vm_id;
}

static int kvm_arm_luo_save_vcpu_state(struct kvm_vcpu *vcpu,
				       struct kvm_luo_vcpu_arm64_state *s,
				       bool is_freeze)
{
	unsigned int mp_state;
	u32 i;

	lockdep_assert_held(&vcpu->kvm->arch.config_lock);

	if (kvm_has_mte(vcpu->kvm) ||
	    kvm_vcpu_has_pmu(vcpu) || vcpu_has_nv(vcpu) ||
	    !mtree_empty(&vcpu->kvm->arch.smccc_filter))
		return -EOPNOTSUPP;

	if (irqchip_in_kernel(vcpu->kvm)) {
		if (vcpu->kvm->arch.vgic.vgic_model != KVM_DEV_TYPE_ARM_VGIC_V3 ||
		    vgic_has_its(vcpu->kvm))
			return -EOPNOTSUPP;
		if (!vgic_initialized(vcpu->kvm))
			return -EBUSY;
	}

	memset(s, 0, sizeof(*s));
	s->version = KVM_LUO_ARM64_VCPU_STATE_VERSION;

	BUILD_BUG_ON(NR_SYS_REGS > KVM_LUO_ARM64_MAX_SYS_REGS);
	BUILD_BUG_ON(ARRAY_SIZE(s->ccsidr) < KVM_ARM_CSSELR_MAX);

	/*
	 * Read mp_state before testing KVM_REQ_VCPU_RESET; pairs with the
	 * smp_wmb() in kvm_psci_vcpu_on() so that a RUNNABLE state set by a
	 * concurrent CPU_ON is never saved without its pending reset.
	 */
	mp_state = READ_ONCE(vcpu->arch.mp_state.mp_state);
	smp_rmb();

	if (is_freeze &&
	    (vcpu_get_flag(vcpu, PENDING_EXCEPTION) ||
	     kvm_test_request(KVM_REQ_VCPU_RESET, vcpu) ||
	     ((vcpu->mmio_needed || vcpu_get_flag(vcpu, INCREMENT_PC)) &&
	      vcpu_mode_is_32bit(vcpu))))
		return -EBUSY;

	s->target = KVM_ARM_TARGET_GENERIC_V8;
	s->features = vcpu->kvm->arch.vcpu_features[0];
	s->vcpu_flags = vcpu->arch.cflags;
	s->mp_state = mp_state;
	s->power_off = (s->mp_state == KVM_MP_STATE_STOPPED);
	s->pause = vcpu->arch.pause;
	s->sflags_serror = !!vcpu_get_flag(vcpu, NESTED_SERROR_PENDING);
	s->sflags_host_ss = !!vcpu_get_flag(vcpu, HOST_SS_ACTIVE_PENDING);
	s->hcr_irq_flags = vcpu->arch.hcr_el2 & (HCR_VSE | HCR_VI | HCR_VF);
	s->guest_debug = vcpu->guest_debug;

	s->gp_regs = vcpu->arch.ctxt.regs;
	if (is_freeze) {
		if (vcpu->mmio_needed && !kvm_vcpu_dabt_iswrite(vcpu)) {
			unsigned int len = kvm_vcpu_dabt_get_as(vcpu);
			unsigned long data =
				kvm_mmio_read_buf(vcpu->run->mmio.data, len);
			int rd = kvm_vcpu_dabt_get_rd(vcpu);

			data = vcpu_data_host_to_guest(vcpu, data, len);
			if (kvm_vcpu_dabt_issext(vcpu) &&
			    len < sizeof(unsigned long)) {
				int mask = 1U << ((len * 8) - 1);

				data = (data ^ mask) - mask;
			}
			if (!kvm_vcpu_dabt_issf(vcpu))
				data &= 0xffffffff;
			if (rd >= 0 && rd < 31)
				s->gp_regs.regs[rd] = data;
		}
		if (vcpu->mmio_needed || vcpu_get_flag(vcpu, INCREMENT_PC)) {
			s->gp_regs.pc += 4;
			s->gp_regs.pstate &= ~PSR_BTYPE_MASK;
			if (vcpu->guest_debug & KVM_GUESTDBG_SINGLESTEP)
				s->sflags_host_ss = 1;
			else
				s->gp_regs.pstate &= ~DBG_SPSR_SS;
		}
	}
	s->fp_regs = vcpu->arch.ctxt.fp_regs;
	s->sp_el1 = ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1);
	s->elr_el1 = ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1);
	s->spsr_abi[KVM_SPSR_EL1] = ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1);
	s->spsr_abi[KVM_SPSR_ABT] = vcpu->arch.ctxt.spsr_abt;
	s->spsr_abi[KVM_SPSR_UND] = vcpu->arch.ctxt.spsr_und;
	s->spsr_abi[KVM_SPSR_IRQ] = vcpu->arch.ctxt.spsr_irq;
	s->spsr_abi[KVM_SPSR_FIQ] = vcpu->arch.ctxt.spsr_fiq;

	s->nr_sys_regs = kvm_arm_luo_save_sys_regs(vcpu, s->sys_regs,
						   ARRAY_SIZE(s->sys_regs));

	s->sve_max_vl = vcpu->arch.sve_max_vl;
	s->sve_finalized = kvm_arm_vcpu_sve_finalized(vcpu);
	if (s->sve_finalized && vcpu->arch.sve_state) {
		size_t sz = min_t(size_t, vcpu_sve_state_size(vcpu),
				  sizeof(s->sve_state));

		memcpy(s->sve_state, vcpu->arch.sve_state, sz);
	}

	s->vsesr_el2 = vcpu->arch.vsesr_el2;
	s->mdcr_el2 = vcpu->arch.mdcr_el2;
	s->vcpu_debug_state = vcpu->arch.vcpu_debug_state;
	s->external_debug_state = vcpu->arch.external_debug_state;
	s->steal_base = vcpu->arch.steal.base;
	if (vcpu->arch.ccsidr) {
		s->has_ccsidr = 1;
		memcpy(s->ccsidr, vcpu->arch.ccsidr,
		       KVM_ARM_CSSELR_MAX * sizeof(u32));
	}

	if (irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3) {
		struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
		struct vgic_v3_cpu_if *cpuif = &vgic_cpu->vgic_v3;

		s->has_vgic_v3 = 1;
		s->vgic_hcr = cpuif->vgic_hcr;
		s->vgic_vmcr = cpuif->vgic_vmcr;
		s->vgic_sre = cpuif->vgic_sre;
		s->vgic_used_lrs = cpuif->used_lrs;
		memcpy(s->vgic_ap0r, cpuif->vgic_ap0r, sizeof(s->vgic_ap0r));
		memcpy(s->vgic_ap1r, cpuif->vgic_ap1r, sizeof(s->vgic_ap1r));
		memcpy(s->vgic_lr, cpuif->vgic_lr, sizeof(s->vgic_lr));
		s->vgic_pendbaser = vgic_cpu->pendbaser;
		s->vgic_lpis_enabled = (u8)atomic_read(&vgic_cpu->ctlr);
		s->vgic_num_pri_bits = vgic_cpu->num_pri_bits;
		s->vgic_num_id_bits = vgic_cpu->num_id_bits;
		s->vgic_rd_base = vgic_cpu->rd_iodev.base_addr;

		if (vgic_cpu->private_irqs) {
			for (i = 0; i < VGIC_NR_PRIVATE_IRQS; i++)
				kvm_arm_save_vgic_irq(&s->private_irqs[i],
						      &vgic_cpu->private_irqs[i]);
		}
	}

	return 0;
}

int kvm_arch_luo_vcpu_preserve(struct kvm_vcpu *vcpu, u64 *arch_state_pa)
{
	struct kvm_luo_vcpu_arm64_state *s;
	int ret;

	if (vcpu_is_protected(vcpu) || vcpu_is_rec(vcpu) ||
	    kvm_vcpu_has_pmu(vcpu) || vcpu_has_nv(vcpu) ||
	    !mtree_empty(&vcpu->kvm->arch.smccc_filter))
		return -EOPNOTSUPP;
	if (!kvm_vcpu_initialized(vcpu))
		return -EINVAL;

	s = kho_alloc_preserve(sizeof(*s));
	if (IS_ERR(s))
		return PTR_ERR(s);

	scoped_guard(mutex, &vcpu->kvm->arch.config_lock)
		ret = kvm_arm_luo_save_vcpu_state(vcpu, s, false);
	if (ret) {
		kho_unpreserve_free(s);
		return ret;
	}

	*arch_state_pa = __pa(s);
	return 0;
}

int kvm_arch_luo_vcpu_freeze(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	int ret;

	if (!arch_state_pa)
		return 0;
	if (!kvm_vcpu_initialized(vcpu))
		return -EINVAL;

	scoped_guard(mutex, &vcpu->kvm->arch.config_lock)
		ret = kvm_arm_luo_save_vcpu_state(vcpu, __va(arch_state_pa), true);
	return ret;
}

void kvm_arch_luo_vcpu_unpreserve(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_unpreserve_free(__va(arch_state_pa));
}

int kvm_arch_luo_vcpu_retrieve(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	struct kvm_luo_vcpu_arm64_state *s;
	int ret = 0;
	u32 i;

	if (!arch_state_pa)
		return -EINVAL;

	s = __va(arch_state_pa);
	if (s->version != KVM_LUO_ARM64_VCPU_STATE_VERSION ||
	    s->nr_sys_regs > ARRAY_SIZE(s->sys_regs) ||
	    (s->has_vgic_v3 && s->vgic_used_lrs > ARRAY_SIZE(s->vgic_lr)))
		return -EINVAL;

	if (!!s->has_vgic_v3 !=
	    (irqchip_in_kernel(vcpu->kvm) &&
	     vcpu->kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3 &&
	     vgic_initialized(vcpu->kvm)))
		return -EINVAL;
	if (s->has_vgic_v3 && s->vgic_lpis_enabled && !vgic_has_its(vcpu->kvm))
		return -EINVAL;

	WRITE_ONCE(vcpu->arch.luo_retrieving, true);

	if (s->vcpu_flags & unpack_vcpu_flag(VCPU_INITIALIZED)) {
		struct kvm_vcpu_init init = {
			.target = s->target,
			.features[0] = (u32)s->features,
		};

		if (s->power_off)
			init.features[0] |= BIT(KVM_ARM_VCPU_POWER_OFF);

		ret = kvm_arch_vcpu_ioctl_vcpu_init(vcpu, &init);
		if (ret)
			goto out;
	}

	if (s->sve_finalized) {
		if (!vcpu_has_sve(vcpu) || !sve_vl_valid(s->sve_max_vl) ||
		    s->sve_max_vl > sve_max_virtualisable_vl() ||
		    s->sve_max_vl > VL_ARCH_MAX) {
			ret = -EINVAL;
			goto out;
		}
		vcpu->arch.sve_max_vl = s->sve_max_vl;
		ret = kvm_arm_vcpu_finalize(vcpu, KVM_ARM_VCPU_SVE);
		if (ret)
			goto out;
	} else if (vcpu_has_sve(vcpu) && s->sve_max_vl) {
		if (!sve_vl_valid(s->sve_max_vl) ||
		    s->sve_max_vl > sve_max_virtualisable_vl() ||
		    s->sve_max_vl > VL_ARCH_MAX) {
			ret = -EINVAL;
			goto out;
		}
		vcpu->arch.sve_max_vl = s->sve_max_vl;
	}

	ret = kvm_arm_luo_restore_sys_regs(vcpu, s->sys_regs, s->nr_sys_regs);
	if (ret)
		goto out;

	if (s->has_ccsidr) {
		if (!vcpu->arch.ccsidr) {
			vcpu->arch.ccsidr = kmalloc_array(KVM_ARM_CSSELR_MAX,
							  sizeof(u32),
							  GFP_KERNEL_ACCOUNT);
			if (!vcpu->arch.ccsidr) {
				ret = -ENOMEM;
				goto out;
			}
		}
		memcpy(vcpu->arch.ccsidr, s->ccsidr,
		       KVM_ARM_CSSELR_MAX * sizeof(u32));
	} else {
		kfree(vcpu->arch.ccsidr);
		vcpu->arch.ccsidr = NULL;
	}

	if (s->has_vgic_v3 && irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3) {
		mutex_lock(&vcpu->kvm->slots_lock);
		ret = vgic_register_redist_iodev_at(vcpu, s->vgic_rd_base);
		mutex_unlock(&vcpu->kvm->slots_lock);
		if (ret)
			goto out;
	}

	vcpu->arch.ctxt.regs = s->gp_regs;
	vcpu->arch.ctxt.fp_regs = s->fp_regs;
	ctxt_sys_reg(&vcpu->arch.ctxt, SP_EL1) = s->sp_el1;
	ctxt_sys_reg(&vcpu->arch.ctxt, ELR_EL1) = s->elr_el1;
	ctxt_sys_reg(&vcpu->arch.ctxt, SPSR_EL1) = s->spsr_abi[KVM_SPSR_EL1];
	vcpu->arch.ctxt.spsr_abt = s->spsr_abi[KVM_SPSR_ABT];
	vcpu->arch.ctxt.spsr_und = s->spsr_abi[KVM_SPSR_UND];
	vcpu->arch.ctxt.spsr_irq = s->spsr_abi[KVM_SPSR_IRQ];
	vcpu->arch.ctxt.spsr_fiq = s->spsr_abi[KVM_SPSR_FIQ];

	if (s->sve_finalized && vcpu->arch.sve_state) {
		size_t sz = min_t(size_t, vcpu_sve_state_size(vcpu),
				  sizeof(s->sve_state));

		memcpy(vcpu->arch.sve_state, s->sve_state, sz);
	}

	vcpu->arch.vsesr_el2 = s->vsesr_el2;
	vcpu->arch.mdcr_el2 = s->mdcr_el2;
	vcpu->arch.hcr_el2 &= ~(HCR_VSE | HCR_VI | HCR_VF);
	vcpu->arch.hcr_el2 |= s->hcr_irq_flags & (HCR_VSE | HCR_VI | HCR_VF);
	if (s->sflags_serror)
		vcpu_set_flag(vcpu, NESTED_SERROR_PENDING);
	else
		vcpu_clear_flag(vcpu, NESTED_SERROR_PENDING);
	if (s->sflags_host_ss)
		vcpu_set_flag(vcpu, HOST_SS_ACTIVE_PENDING);
	else
		vcpu_clear_flag(vcpu, HOST_SS_ACTIVE_PENDING);
	vcpu->guest_debug = s->guest_debug;
	vcpu->arch.vcpu_debug_state = s->vcpu_debug_state;
	vcpu->arch.external_debug_state = s->external_debug_state;
	vcpu->arch.steal.base = s->steal_base;

	if (s->has_vgic_v3 && irqchip_in_kernel(vcpu->kvm) &&
	    vcpu->kvm->arch.vgic.vgic_model == KVM_DEV_TYPE_ARM_VGIC_V3) {
		struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
		struct vgic_v3_cpu_if *cpuif = &vgic_cpu->vgic_v3;
		unsigned long flags;

		cpuif->vgic_hcr = s->vgic_hcr;
		cpuif->vgic_vmcr = s->vgic_vmcr;
		cpuif->vgic_sre = s->vgic_sre;
		cpuif->used_lrs = s->vgic_used_lrs;
		memcpy(cpuif->vgic_ap0r, s->vgic_ap0r, sizeof(s->vgic_ap0r));
		memcpy(cpuif->vgic_ap1r, s->vgic_ap1r, sizeof(s->vgic_ap1r));
		memcpy(cpuif->vgic_lr, s->vgic_lr, sizeof(s->vgic_lr));
		vgic_cpu->pendbaser = s->vgic_pendbaser;
		atomic_set(&vgic_cpu->ctlr, s->vgic_lpis_enabled);
		vgic_cpu->num_pri_bits = s->vgic_num_pri_bits;
		vgic_cpu->num_id_bits = s->vgic_num_id_bits;

		if (vgic_cpu->private_irqs) {
			for (i = 0; i < VGIC_NR_PRIVATE_IRQS; i++) {
				struct vgic_irq *irq = &vgic_cpu->private_irqs[i];

				kvm_arm_restore_vgic_irq(irq, &s->private_irqs[i]);
				raw_spin_lock_irqsave(&irq->irq_lock, flags);
				vgic_queue_irq_unlock(vcpu->kvm, irq, flags);
			}
		}
	}

	spin_lock(&vcpu->arch.mp_state_lock);
	WRITE_ONCE(vcpu->arch.mp_state.mp_state, s->mp_state);
	spin_unlock(&vcpu->arch.mp_state_lock);
	vcpu->arch.pause = s->pause;
	if (s->mp_state == KVM_MP_STATE_SUSPENDED)
		kvm_make_request(KVM_REQ_SUSPEND, vcpu);
	if (s->mp_state == KVM_MP_STATE_STOPPED || s->pause)
		kvm_make_request(KVM_REQ_SLEEP, vcpu);

	kvm_destroy_mpidr_data(vcpu->kvm);
	ret = 0;
out:
	WRITE_ONCE(vcpu->arch.luo_retrieving, false);
	return ret;
}

void kvm_arch_luo_vcpu_finish(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_restore_free(__va(arch_state_pa));
}
