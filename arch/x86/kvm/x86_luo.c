// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM x86 VM and vCPU liveupdate state preservation and retrieval.
 */

#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/string.h>

#include "cpuid.h"
#include "fpu.h"
#include "i8254.h"
#include "ioapic.h"
#include "irq.h"
#include "lapic.h"
#include "mmu.h"
#include "msrs.h"
#include "regs.h"
#include "x86.h"

static int kvm_x86_luo_check_vm_supported(struct kvm *kvm)
{
	if (kvm->arch.has_protected_state && !kvm_x86_ops.vm_luo_preserve)
		return -EOPNOTSUPP;
	if (kvm->arch.vm_type == KVM_X86_SW_PROTECTED_VM &&
	    !kvm_arch_supports_gmem_init_shared(kvm))
		return -EOPNOTSUPP;
	if ((kvm->arch.disabled_exits & ~KVM_X86_DISABLE_EXITS_PAUSE) ||
	    kvm->arch.user_space_msr_mask ||
	    rcu_access_pointer(kvm->arch.msr_filter) ||
	    rcu_access_pointer(kvm->arch.pmu_event_filter) ||
	    (READ_ONCE(kvm->arch.disabled_quirks) & ~(u64)U32_MAX) ||
	    kvm->arch.apic_bus_cycle_ns != APIC_BUS_CYCLE_NS_DEFAULT ||
	    (kvm->arch.max_vcpu_ids &&
	     kvm->arch.max_vcpu_ids != KVM_MAX_VCPU_IDS) ||
	    kvm->arch.notify_vmexit_flags ||
	    kvm->arch.disable_nx_huge_pages ||
	    (kvm->arch.hypercall_exit_enabled & ~BIT(KVM_HC_MAP_GPA_RANGE)))
		return -EOPNOTSUPP;
#ifdef CONFIG_X86_SGX_KVM
	if (kvm->arch.sgx_provisioning_allowed)
		return -EOPNOTSUPP;
#endif
#ifdef CONFIG_KVM_HYPERV
	if (kvm->arch.hyperv.hv_guest_os_id)
		return -EOPNOTSUPP;
#endif
#ifdef CONFIG_KVM_XEN
	if (kvm->arch.xen.hvm_config.flags || kvm->arch.xen.hvm_config.msr ||
	    kvm->arch.xen.xen_version || kvm->arch.xen.upcall_vector)
		return -EOPNOTSUPP;
#endif
	return 0;
}

static int kvm_x86_luo_save_vm_state(struct kvm *kvm,
				     struct kvm_luo_vm_x86_state *st)
{
	struct kvm_irq_routing_table *rt;
	u32 gsi, nr_routes = 0;
	int srcu_idx, ret;

	ret = kvm_x86_luo_check_vm_supported(kvm);
	if (ret)
		return ret;

	memset(st, 0, offsetof(struct kvm_luo_vm_x86_state, tdx));
	st->version = KVM_LUO_X86_VM_STATE_VERSION;
	st->irqchip_mode = kvm->arch.irqchip_mode;
	st->nr_ioapic_pins = kvm->arch.nr_reserved_ioapic_pins;
	st->default_tsc_khz = READ_ONCE(kvm->arch.default_tsc_khz);
	st->bsp_vcpu_id = kvm->arch.bsp_vcpu_id;
	st->nr_vcpus = atomic_read(&kvm->online_vcpus);
	st->disabled_quirks = READ_ONCE(kvm->arch.disabled_quirks);

	if (kvm->arch.luo_tss_addr_set) {
		st->flags |= KVM_LUO_X86_VM_FLAG_HAS_TSS;
		st->tss_addr = kvm->arch.luo_tss_addr;
	}
	if (kvm->arch.luo_identity_map_addr_set) {
		st->flags |= KVM_LUO_X86_VM_FLAG_HAS_IDENT;
		st->identity_map_addr = kvm->arch.luo_identity_map_addr;
	}
	if (kvm->arch.wall_clock) {
		st->flags |= KVM_LUO_X86_VM_FLAG_WALL_CLOCK;
		st->wall_clock_gpa = kvm->arch.wall_clock;
	}
	if (kvm->arch.exception_payload_enabled)
		st->flags |= KVM_LUO_X86_VM_FLAG_EXCEPTION_PAYLOAD;
	if (kvm->arch.triple_fault_event)
		st->flags |= KVM_LUO_X86_VM_FLAG_TRIPLE_FAULT_EVENT;
	if (kvm->arch.x2apic_format)
		st->flags |= KVM_LUO_X86_VM_FLAG_X2APIC_FORMAT;
	if (kvm->arch.x2apic_broadcast_quirk_disabled)
		st->flags |= KVM_LUO_X86_VM_FLAG_X2APIC_BC_QUIRK_DIS;
	if (kvm->arch.bus_lock_detection_enabled)
		st->flags |= KVM_LUO_X86_VM_FLAG_BUS_LOCK_DETECTION;
	if (kvm->arch.suppress_eoi_broadcast_mode ==
	    KVM_SUPPRESS_EOI_BROADCAST_ENABLED)
		st->flags |= KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_EN;
	else if (kvm->arch.suppress_eoi_broadcast_mode ==
		 KVM_SUPPRESS_EOI_BROADCAST_DISABLED)
		st->flags |= KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_DIS;
	if (kvm->arch.guest_can_read_msr_platform_info)
		st->flags |= KVM_LUO_X86_VM_FLAG_MSR_PLATFORM_INFO;
	if (kvm->arch.exit_on_emulation_error)
		st->flags |= KVM_LUO_X86_VM_FLAG_EXIT_ON_EMUL_ERR;
	if (kvm->arch.hypercall_exit_enabled & BIT(KVM_HC_MAP_GPA_RANGE))
		st->flags |= KVM_LUO_X86_VM_FLAG_EXIT_HC_MAP_GPA;
	if (kvm->arch.disabled_exits & KVM_X86_DISABLE_EXITS_PAUSE)
		st->flags |= KVM_LUO_X86_VM_FLAG_DISABLE_EXITS_PAUSE;
	if (!kvm->arch.enable_pmu)
		st->flags |= KVM_LUO_X86_VM_FLAG_DISABLE_PMU;

	kvm_luo_save_clock(kvm, &st->clock_ns, &st->clock_realtime_ns);

#ifdef CONFIG_KVM_IOAPIC
	if (irqchip_full(kvm)) {
		st->pic_master.chip_id = KVM_IRQCHIP_PIC_MASTER;
		ret = kvm_vm_ioctl_get_irqchip(kvm, &st->pic_master);
		if (ret)
			return ret;

		st->pic_slave.chip_id = KVM_IRQCHIP_PIC_SLAVE;
		ret = kvm_vm_ioctl_get_irqchip(kvm, &st->pic_slave);
		if (ret)
			return ret;

		st->ioapic.chip_id = KVM_IRQCHIP_IOAPIC;
		kvm_ioapic_luo_save(kvm, &st->ioapic.chip.ioapic,
				    &st->ioapic_irr_delivered);

		if (kvm->arch.vpit) {
			st->flags |= KVM_LUO_X86_VM_FLAG_HAS_PIT;
			if (kvm->arch.vpit->speaker_dev.ops)
				st->flags |= KVM_LUO_X86_VM_FLAG_PIT_SPEAKER_DUMMY;
			if (atomic_read(&kvm->arch.vpit->pit_state.reinject))
				st->flags |= KVM_LUO_X86_VM_FLAG_PIT_REINJECT;
			if (hrtimer_active(&kvm->arch.vpit->pit_state.timer))
				st->flags |= KVM_LUO_X86_VM_FLAG_PIT_TIMER_ACTIVE;
			ret = kvm_vm_ioctl_get_pit2(kvm, &st->pit);
			if (ret)
				return ret;
		}
	}
#endif

	srcu_idx = srcu_read_lock(&kvm->irq_srcu);
	rt = srcu_dereference(kvm->irq_routing, &kvm->irq_srcu);
	if (rt) {
		for (gsi = 0; gsi < rt->nr_rt_entries; gsi++) {
			struct kvm_kernel_irq_routing_entry *e;

			hlist_for_each_entry(e, &rt->map[gsi], link) {
				struct kvm_irq_routing_entry *ue;

				if (nr_routes >= KVM_LUO_X86_MAX_IRQ_ROUTES) {
					srcu_read_unlock(&kvm->irq_srcu,
							 srcu_idx);
					return -E2BIG;
				}
				ue = &st->irq_routes[nr_routes++];
				memset(ue, 0, sizeof(*ue));
				ue->gsi = e->gsi;
				ue->type = e->type;
				switch (e->type) {
				case KVM_IRQ_ROUTING_IRQCHIP:
					ue->u.irqchip.irqchip =
						e->irqchip.irqchip;
					ue->u.irqchip.pin = e->irqchip.pin;
#ifdef CONFIG_KVM_IOAPIC
					if (e->irqchip.irqchip ==
					    KVM_IRQCHIP_PIC_SLAVE)
						ue->u.irqchip.pin -=
							PIC_NUM_PINS / 2;
#endif
					break;
				case KVM_IRQ_ROUTING_MSI:
					ue->u.msi.address_lo =
						e->msi.address_lo;
					ue->u.msi.address_hi =
						e->msi.address_hi;
					ue->u.msi.data = e->msi.data;
					break;
				default:
					srcu_read_unlock(&kvm->irq_srcu,
							 srcu_idx);
					return -EOPNOTSUPP;
				}
			}
		}
	}
	srcu_read_unlock(&kvm->irq_srcu, srcu_idx);
	st->nr_irq_routes = nr_routes;

	return 0;
}

int kvm_arch_luo_vm_preserve(struct kvm *kvm, u64 *arch_state_pa)
{
	struct kvm_luo_vm_x86_state *st;
	int ret;

	ret = kvm_x86_luo_check_vm_supported(kvm);
	if (ret)
		return ret;

	st = kho_alloc_preserve(sizeof(*st));
	if (IS_ERR(st))
		return PTR_ERR(st);

	ret = kvm_x86_luo_save_vm_state(kvm, st);
	if (ret) {
		kho_unpreserve_free(st);
		return ret;
	}

	if (kvm->arch.has_protected_state) {
		u64 retrieved = kvm->arch.luo_gmem_vm_id &
				KVM_X86_LUO_GMEM_RETRIEVED;

		ret = kvm_x86_ops.vm_luo_preserve(kvm, st);
		if (ret) {
			kho_unpreserve_free(st);
			return ret;
		}
		kvm->arch.luo_gmem_vm_id |= KVM_X86_LUO_GMEM_PRESERVED |
					    retrieved;
	}

	*arch_state_pa = __pa(st);
	return 0;
}

int kvm_arch_luo_vm_freeze(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_x86_state *st;
	int ret;

	if (!arch_state_pa)
		return 0;

	st = __va(arch_state_pa);
	ret = kvm_x86_luo_save_vm_state(kvm, st);
	if (ret)
		return ret;

	if (kvm->arch.has_protected_state && kvm_x86_ops.vm_luo_freeze)
		return kvm_x86_ops.vm_luo_freeze(kvm, st);

	return 0;
}

void kvm_arch_luo_vm_unfreeze(struct kvm *kvm, u64 arch_state_pa)
{
	WRITE_ONCE(kvm->arch.luo_frozen, false);
}

void kvm_arch_luo_vm_unpreserve(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_x86_state *st;

	WRITE_ONCE(kvm->arch.luo_frozen, false);
	kvm->arch.luo_gmem_vm_id &= ~KVM_X86_LUO_GMEM_PRESERVED;

	if (!arch_state_pa)
		return;

	st = __va(arch_state_pa);
	if (kvm->arch.has_protected_state && kvm_x86_ops.vm_luo_unpreserve)
		kvm_x86_ops.vm_luo_unpreserve(kvm, st);

	kho_unpreserve_free(st);
}

int kvm_arch_luo_vm_retrieve(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_x86_state *st;
	int ret = 0;

	if (!arch_state_pa)
		return -EINVAL;

	st = __va(arch_state_pa);
	if (st->version != KVM_LUO_X86_VM_STATE_VERSION)
		return -EINVAL;

	if (st->default_tsc_khz)
		WRITE_ONCE(kvm->arch.default_tsc_khz, st->default_tsc_khz);
	kvm->arch.bsp_vcpu_id = st->bsp_vcpu_id;
	WRITE_ONCE(kvm->arch.disabled_quirks,
		   (kvm->arch.disabled_quirks | st->disabled_quirks) &
		   kvm_caps.supported_quirks);
	kvm->arch.x2apic_format =
		!!(st->flags & KVM_LUO_X86_VM_FLAG_X2APIC_FORMAT);
	kvm->arch.x2apic_broadcast_quirk_disabled =
		!!(st->flags & KVM_LUO_X86_VM_FLAG_X2APIC_BC_QUIRK_DIS);
	if (st->flags & KVM_LUO_X86_VM_FLAG_BUS_LOCK_DETECTION) {
		if (!kvm_caps.has_bus_lock_exit)
			return -EINVAL;
		kvm->arch.bus_lock_detection_enabled = true;
	}
	if (st->flags & KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_EN)
		kvm->arch.suppress_eoi_broadcast_mode =
			KVM_SUPPRESS_EOI_BROADCAST_ENABLED;
	else if (st->flags & KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_DIS)
		kvm->arch.suppress_eoi_broadcast_mode =
			KVM_SUPPRESS_EOI_BROADCAST_DISABLED;
	kvm->arch.guest_can_read_msr_platform_info =
		!!(st->flags & KVM_LUO_X86_VM_FLAG_MSR_PLATFORM_INFO);
	kvm->arch.exit_on_emulation_error =
		!!(st->flags & KVM_LUO_X86_VM_FLAG_EXIT_ON_EMUL_ERR);
	if (st->flags & KVM_LUO_X86_VM_FLAG_EXIT_HC_MAP_GPA)
		kvm->arch.hypercall_exit_enabled |= BIT(KVM_HC_MAP_GPA_RANGE);
	if (st->flags & KVM_LUO_X86_VM_FLAG_DISABLE_EXITS_PAUSE)
		kvm_disable_exits(kvm, KVM_X86_DISABLE_EXITS_PAUSE);
	else if (kvm->arch.disabled_exits & KVM_X86_DISABLE_EXITS_PAUSE)
		return -EINVAL;
	if (st->flags & KVM_LUO_X86_VM_FLAG_DISABLE_PMU)
		kvm->arch.enable_pmu = false;
	else if (!kvm->arch.enable_pmu)
		return -EINVAL;

	if (st->flags & KVM_LUO_X86_VM_FLAG_HAS_TSS) {
		ret = kvm_vm_ioctl_set_tss_addr(kvm, st->tss_addr);
		if (ret)
			return ret;
	}
	if (st->flags & KVM_LUO_X86_VM_FLAG_HAS_IDENT) {
		ret = kvm_vm_ioctl_set_identity_map_addr(kvm,
							 st->identity_map_addr);
		if (ret)
			return ret;
	}

	switch (st->irqchip_mode) {
#ifdef CONFIG_KVM_IOAPIC
	case KVM_IRQCHIP_KERNEL: {
		struct kvm_irqchip chip;

		ret = kvm_pic_init(kvm);
		if (ret)
			return ret;

		ret = kvm_ioapic_init(kvm);
		if (ret) {
			kvm_pic_destroy(kvm);
			return ret;
		}

		ret = kvm_setup_default_ioapic_and_pic_routing(kvm);
		if (ret) {
			kvm_ioapic_destroy(kvm);
			kvm_pic_destroy(kvm);
			return ret;
		}
		/* Pairs with smp_rmb() in irqchip_in_kernel(). */
		smp_wmb();
		kvm->arch.irqchip_mode = KVM_IRQCHIP_KERNEL;
		kvm_clear_apicv_inhibit(kvm, APICV_INHIBIT_REASON_ABSENT);

		if (st->nr_irq_routes > KVM_LUO_X86_MAX_IRQ_ROUTES)
			return -EINVAL;
		ret = kvm_set_irq_routing(kvm, st->irq_routes,
					  st->nr_irq_routes, 0);
		if (ret)
			return ret;

		chip = st->pic_master;
		ret = kvm_vm_ioctl_set_irqchip(kvm, &chip);
		if (ret)
			return ret;

		chip = st->pic_slave;
		ret = kvm_vm_ioctl_set_irqchip(kvm, &chip);
		if (ret)
			return ret;

		kvm_ioapic_luo_restore(kvm, &st->ioapic.chip.ioapic,
				       st->ioapic_irr_delivered);

		if (st->flags & KVM_LUO_X86_VM_FLAG_HAS_PIT) {
			struct kvm_reinject_control reinj = {
				.pit_reinject = !!(st->flags &
						   KVM_LUO_X86_VM_FLAG_PIT_REINJECT),
			};
			u32 create_flags = (st->flags &
					    KVM_LUO_X86_VM_FLAG_PIT_SPEAKER_DUMMY) ?
					   KVM_PIT_SPEAKER_DUMMY : 0;

			kvm->arch.vpit = kvm_create_pit(kvm, create_flags);
			if (!kvm->arch.vpit)
				return -ENOMEM;
			ret = kvm_vm_ioctl_reinject(kvm, &reinj);
			if (ret)
				return ret;
			kvm_pit_luo_restore(kvm, &st->pit,
					    !!(st->flags &
					       KVM_LUO_X86_VM_FLAG_PIT_TIMER_ACTIVE),
					    st->nr_vcpus);
		}
		break;
	}
#endif
	case KVM_IRQCHIP_SPLIT:
		if (st->nr_ioapic_pins > KVM_MAX_IRQ_ROUTES)
			return -EINVAL;
		kvm->arch.nr_reserved_ioapic_pins = st->nr_ioapic_pins;
		/* Pairs with smp_rmb() in irqchip_in_kernel(). */
		smp_wmb();
		kvm->arch.irqchip_mode = KVM_IRQCHIP_SPLIT;
		kvm_clear_apicv_inhibit(kvm, APICV_INHIBIT_REASON_ABSENT);

		if (st->nr_irq_routes > KVM_LUO_X86_MAX_IRQ_ROUTES)
			return -EINVAL;
		ret = kvm_set_irq_routing(kvm, st->irq_routes,
					  st->nr_irq_routes, 0);
		if (ret)
			return ret;
		break;
	case KVM_IRQCHIP_NONE:
		if (st->nr_irq_routes) {
			if (st->nr_irq_routes > KVM_LUO_X86_MAX_IRQ_ROUTES)
				return -EINVAL;
			ret = kvm_set_irq_routing(kvm, st->irq_routes,
						  st->nr_irq_routes, 0);
			if (ret)
				return ret;
		}
		break;
	default:
		return -EINVAL;
	}

	if (st->flags & KVM_LUO_X86_VM_FLAG_WALL_CLOCK)
		kvm->arch.wall_clock = st->wall_clock_gpa;
	if (st->flags & KVM_LUO_X86_VM_FLAG_EXCEPTION_PAYLOAD)
		kvm->arch.exception_payload_enabled = true;
	if (st->flags & KVM_LUO_X86_VM_FLAG_TRIPLE_FAULT_EVENT)
		kvm->arch.triple_fault_event = true;

	kvm_luo_restore_clock(kvm, st->clock_ns, st->clock_realtime_ns);

	if (kvm->arch.has_protected_state) {
		if (!kvm_x86_ops.vm_luo_retrieve)
			return -EOPNOTSUPP;
		ret = kvm_x86_ops.vm_luo_retrieve(kvm, st);
		if (ret)
			return ret;
		kvm->arch.luo_gmem_vm_id |= KVM_X86_LUO_GMEM_RETRIEVED;
	}

	return 0;
}

void kvm_arch_luo_vm_finish(struct kvm *kvm, u64 arch_state_pa)
{
	struct kvm_luo_vm_x86_state *st;

	if (!arch_state_pa)
		return;

	st = __va(arch_state_pa);
	if (kvm_x86_ops.vm_luo_finish &&
	    (!kvm || kvm->arch.has_protected_state))
		kvm_x86_ops.vm_luo_finish(st, !!kvm);

	kho_restore_free(st);
}

int kvm_arch_gmem_luo_get_vm_id(struct kvm *kvm, u64 *vm_id)
{
	if (kvm->arch.vm_type == KVM_X86_SW_PROTECTED_VM &&
	    !kvm_x86_call(vm_has_encrypted_memory)(kvm) &&
	    kvm_arch_supports_gmem_init_shared(kvm)) {
		*vm_id = KVM_VM_LUO_FEAT_SW_PROTECTED;
		return 0;
	}
	if (kvm->arch.luo_gmem_vm_id & KVM_X86_LUO_GMEM_PRESERVED) {
		*vm_id = kvm->arch.luo_gmem_vm_id & ~KVM_X86_LUO_GMEM_TAG_MASK;
		return 0;
	}
	return -EOPNOTSUPP;
}

bool kvm_arch_gmem_luo_validate_vm_id(struct kvm *kvm, u64 vm_id)
{
	if (kvm->arch.vm_type == KVM_X86_SW_PROTECTED_VM &&
	    !kvm_x86_call(vm_has_encrypted_memory)(kvm) &&
	    kvm_arch_supports_gmem_init_shared(kvm))
		return vm_id == KVM_VM_LUO_FEAT_SW_PROTECTED;

	if (!(kvm->arch.luo_gmem_vm_id & KVM_X86_LUO_GMEM_RETRIEVED))
		return false;

	return (kvm->arch.luo_gmem_vm_id & ~KVM_X86_LUO_GMEM_TAG_MASK) == vm_id;
}

static int kvm_x86_luo_save_vcpu_state(struct kvm_vcpu *vcpu,
				       struct kvm_luo_vcpu_x86_state *st)
{
	struct kvm_mp_state mp_state = {};
	bool clear_interrupt_shadow = false;
	u32 preserve_flags;
	int ret;

	preserve_flags = st->flags & KVM_LUO_X86_VCPU_FLAG_VENDOR_PRESERVED;
	memset(st, 0, offsetof(struct kvm_luo_vcpu_x86_state, tdx));
	st->version = KVM_LUO_X86_VCPU_STATE_VERSION;
	st->flags = preserve_flags;
	if (vcpu->arch.guest_state_protected)
		st->flags |= KVM_LUO_X86_VCPU_FLAG_PROTECTED;

	ret = kvm_vcpu_ioctl_x86_get_mpstate(vcpu, &mp_state);
	if (ret)
		return ret;
	st->mp_state = mp_state.mp_state;
	st->virtual_tsc_khz = vcpu->arch.virtual_tsc_khz;
	st->l1_tsc_offset = vcpu->arch.l1_tsc_offset;
	st->mcg_cap = vcpu->arch.mcg_cap;

	if (!vcpu->arch.guest_state_protected) {
		kvm_get_regs(vcpu, &st->regs);
		kvm_vcpu_ioctl_x86_get_sregs2(vcpu, &st->sregs2);
		kvm_vcpu_ioctl_x86_get_vcpu_events(vcpu, &st->events);
		kvm_vcpu_ioctl_x86_get_debugregs(vcpu, &st->debugregs);

		ret = kvm_luo_apply_userspace_io(vcpu, &st->regs,
						 &clear_interrupt_shadow);
		if (ret)
			return ret;
		if (clear_interrupt_shadow)
			st->events.interrupt.shadow = 0;

		ret = kvm_vcpu_ioctl_x86_get_xsave(vcpu, &st->xsave);
		if (ret)
			return ret;

		ret = kvm_vcpu_ioctl_x86_get_xcrs(vcpu, &st->xcrs);
		if (ret)
			return ret;
	}

	if (lapic_in_kernel(vcpu)) {
		struct kvm_lapic *apic = vcpu->arch.apic;

		st->events.sipi_vector = apic->sipi_vector;
		st->events.flags |= KVM_VCPUEVENT_VALID_SIPI_VECTOR;
		st->flags |= KVM_LUO_X86_VCPU_FLAG_HAS_LAPIC;
		if (apic->apicv_active)
			kvm_x86_call(sync_pir_to_irr)(vcpu);
		kvm_apic_get_state(vcpu, &st->lapic);
		st->tscdeadline = kvm_get_lapic_tscdeadline_msr(vcpu);
		if (apic->lapic_timer.timer_mode == APIC_LVT_TIMER_ONESHOT &&
		    !apic->lapic_timer.target_expiration &&
		    !atomic_read(&apic->lapic_timer.pending))
			st->flags |= KVM_LUO_X86_VCPU_FLAG_APIC_ONESHOT_EXPIRED;
	}

	ret = kvm_luo_save_cpuid(vcpu, st->cpuid_entries,
				 KVM_LUO_X86_MAX_CPUID_ENTRIES,
				 &st->cpuid_nent);
	if (ret)
		return ret;

	if (!vcpu->arch.guest_state_protected ||
	    vcpu->kvm->arch.vm_type == KVM_X86_TDX_VM) {
		ret = kvm_luo_save_msrs(vcpu, st->msrs,
					KVM_LUO_X86_MAX_MSR_ENTRIES,
					&st->nr_msrs);
		if (ret)
			return ret;
	}

	st->pv_time_msr = vcpu->arch.time;
	if (vcpu->arch.pv_time.active)
		st->flags |= KVM_LUO_X86_VCPU_FLAG_PV_TIME;
	if (vcpu->vcpu_id == 0 && vcpu->kvm->arch.boot_vcpu_runs_old_kvmclock)
		st->flags |= KVM_LUO_X86_VCPU_FLAG_OLD_KVMCLOCK;

	st->pv_eoi_msr = vcpu->arch.pv_eoi.msr_val;
	if (vcpu->arch.pv_eoi.msr_val & KVM_MSR_ENABLED)
		st->flags |= KVM_LUO_X86_VCPU_FLAG_PV_EOI;

	st->steal_msr = vcpu->arch.st.msr_val;
	if (vcpu->arch.st.msr_val & KVM_MSR_ENABLED)
		st->flags |= KVM_LUO_X86_VCPU_FLAG_STEAL;

	st->apf_msr_en = vcpu->arch.apf.msr_en_val;
	st->apf_msr_int = vcpu->arch.apf.msr_int_val;
	st->apf_vec = vcpu->arch.apf.vec;
	st->apf_id = vcpu->arch.apf.id;
	st->apf_pageready_pending = vcpu->arch.apf.pageready_pending;
	if (__kvm_pv_async_pf_enabled(vcpu->arch.apf.msr_en_val))
		st->flags |= KVM_LUO_X86_VCPU_FLAG_APF;

	return 0;
}

int kvm_arch_luo_vcpu_preserve(struct kvm_vcpu *vcpu, u64 *arch_state_pa)
{
	struct kvm_luo_vcpu_x86_state *st;
	int ret;

	if (!!vcpu->arch.guest_state_protected !=
	    !!vcpu->kvm->arch.has_protected_state)
		return -EOPNOTSUPP;
	if (vcpu->arch.guest_state_protected && !kvm_x86_ops.vcpu_luo_preserve)
		return -EOPNOTSUPP;
	if (is_guest_mode(vcpu) || vcpu->arch.nested_run_pending)
		return -EOPNOTSUPP;
	if (!vcpu->arch.guest_state_protected &&
	    (kvm_is_cr4_bit_set(vcpu, X86_CR4_VMXE) ||
	     (vcpu->arch.efer & EFER_SVME)))
		return -EOPNOTSUPP;
	if (!vcpu->arch.guest_state_protected &&
	    vcpu->arch.guest_fpu.uabi_size > sizeof(struct kvm_xsave))
		return -EOPNOTSUPP;
	if (vcpu->arch.cpuid_nent > KVM_LUO_X86_MAX_CPUID_ENTRIES)
		return -E2BIG;
#ifdef CONFIG_KVM_SMM
	if (is_smm(vcpu))
		return -EOPNOTSUPP;
#endif
	if (!vcpu->arch.guest_state_protected && is_pae_paging(vcpu) &&
	    !kvm_register_is_available(vcpu, VCPU_REG_PDPTR)) {
		if (current->mm != vcpu->kvm->mm)
			return -EOPNOTSUPP;
		kvm_vcpu_srcu_read_lock(vcpu);
		(void)kvm_pdptr_read(vcpu, 0);
		kvm_vcpu_srcu_read_unlock(vcpu);
	}

	st = kho_alloc_preserve(sizeof(*st));
	if (IS_ERR(st))
		return PTR_ERR(st);

	memset(st, 0, sizeof(*st));
	st->version = KVM_LUO_X86_VCPU_STATE_VERSION;
	if (vcpu->arch.guest_state_protected) {
		st->flags |= KVM_LUO_X86_VCPU_FLAG_PROTECTED;
		ret = kvm_x86_ops.vcpu_luo_preserve(vcpu, st);
		if (ret) {
			kho_unpreserve_free(st);
			return ret;
		}
		st->flags |= KVM_LUO_X86_VCPU_FLAG_VENDOR_PRESERVED;
	}

	*arch_state_pa = __pa(st);
	return 0;
}

int kvm_arch_luo_vcpu_freeze(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	struct kvm_luo_vcpu_x86_state *st;
	int ret;

	if (!arch_state_pa)
		return 0;
	st = __va(arch_state_pa);
	if (!!vcpu->arch.guest_state_protected !=
	    !!vcpu->kvm->arch.has_protected_state ||
	    !!vcpu->arch.guest_state_protected !=
	    !!(st->flags & KVM_LUO_X86_VCPU_FLAG_PROTECTED))
		return -EOPNOTSUPP;
	if (is_guest_mode(vcpu) || vcpu->arch.nested_run_pending)
		return -EBUSY;
	if (!vcpu->arch.guest_state_protected &&
	    (kvm_is_cr4_bit_set(vcpu, X86_CR4_VMXE) ||
	     (vcpu->arch.efer & EFER_SVME)))
		return -EBUSY;
	if (!vcpu->arch.guest_state_protected &&
	    vcpu->arch.guest_fpu.uabi_size > sizeof(struct kvm_xsave))
		return -EOPNOTSUPP;
#ifdef CONFIG_KVM_SMM
	if (is_smm(vcpu))
		return -EBUSY;
#endif
	if (!vcpu->arch.guest_state_protected && is_pae_paging(vcpu) &&
	    !kvm_register_is_available(vcpu, VCPU_REG_PDPTR) &&
	    current->mm != vcpu->kvm->mm)
		return -EBUSY;

	ret = kvm_x86_luo_save_vcpu_state(vcpu, st);
	if (ret)
		return ret;

	if (vcpu->arch.guest_state_protected && kvm_x86_ops.vcpu_luo_freeze)
		return kvm_x86_ops.vcpu_luo_freeze(vcpu, st);

	return 0;
}

void kvm_arch_luo_vcpu_unpreserve(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	struct kvm_luo_vcpu_x86_state *st;

	if (!arch_state_pa)
		return;

	st = __va(arch_state_pa);
	if ((st->flags & KVM_LUO_X86_VCPU_FLAG_VENDOR_PRESERVED) &&
	    kvm_x86_ops.vcpu_luo_unpreserve)
		kvm_x86_ops.vcpu_luo_unpreserve(vcpu, st);

	kho_unpreserve_free(st);
}

int kvm_arch_luo_vcpu_retrieve(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	struct kvm_luo_vcpu_x86_state *st;
	struct kvm_mp_state mp_state = {};
	struct kvm_vcpu_events events;
	struct kvm_debugregs dbgregs;
	struct kvm_sregs2 sregs2;
	struct kvm_xsave *xsave = NULL;
	struct kvm_xcrs xcrs;
	struct kvm_regs regs;
	bool is_protected;
	int ret;

	if (!arch_state_pa)
		return -EINVAL;

	st = __va(arch_state_pa);
	if (st->version != KVM_LUO_X86_VCPU_STATE_VERSION ||
	    st->cpuid_nent > KVM_LUO_X86_MAX_CPUID_ENTRIES ||
	    st->nr_msrs > KVM_LUO_X86_MAX_MSR_ENTRIES)
		return -EINVAL;

	is_protected = !!(st->flags & KVM_LUO_X86_VCPU_FLAG_PROTECTED);
	if (is_protected != !!vcpu->kvm->arch.has_protected_state)
		return -EINVAL;

	if (!is_protected) {
		xsave = kmalloc_obj(*xsave, GFP_KERNEL_ACCOUNT);
		if (!xsave)
			return -ENOMEM;
	}

	/* 1. Restore CPUID and MCE cap first so guest capabilities are set. */
	ret = kvm_luo_set_cpuid(vcpu, st->cpuid_entries, st->cpuid_nent);
	if (ret)
		goto out_free;

	if (st->mcg_cap) {
		ret = kvm_vcpu_ioctl_x86_setup_mce(vcpu, st->mcg_cap);
		if (ret)
			goto out_free;
	}

	/* 2. Restore virtual TSC frequency. */
	if (st->virtual_tsc_khz) {
		ret = kvm_set_tsc_khz(vcpu, st->virtual_tsc_khz);
		if (ret < 0 && kvm_caps.has_tsc_control) {
			ret = -EINVAL;
			goto out_free;
		}
	}

	if (!is_protected) {
		/* 3. Restore SREGS2 before XCRs so CR4.OSXSAVE is active. */
		sregs2 = st->sregs2;
		ret = kvm_vcpu_ioctl_x86_set_sregs2(vcpu, &sregs2);
		if (ret)
			goto out_free;

		/* 4. Restore XCRs and XSAVE/FPU state. */
		xcrs = st->xcrs;
		if (xcrs.nr_xcrs) {
			ret = kvm_vcpu_ioctl_x86_set_xcrs(vcpu, &xcrs);
			if (ret)
				goto out_free;
		}
		if (vcpu->arch.guest_fpu.uabi_size > sizeof(struct kvm_xsave)) {
			ret = -E2BIG;
			goto out_free;
		}
		*xsave = st->xsave;
		ret = kvm_vcpu_ioctl_x86_set_xsave(vcpu, xsave);
		if (ret)
			goto out_free;
	}

	/* 5. Restore L1 TSC offset without resynchronizing. */
	kvm_luo_restore_tsc(vcpu, st->l1_tsc_offset);

	/* 6. Restore LAPIC state before MSRs so MSR_IA32_TSC_DEADLINE works. */
	if ((st->flags & KVM_LUO_X86_VCPU_FLAG_HAS_LAPIC) &&
	    lapic_in_kernel(vcpu)) {
		struct kvm_lapic_state *lapic;
		bool oneshot_expired;
		u32 tmict = 0;

		lapic = kmemdup(&st->lapic, sizeof(*lapic), GFP_KERNEL_ACCOUNT);
		if (!lapic) {
			ret = -ENOMEM;
			goto out_free;
		}

		oneshot_expired = st->flags &
				  KVM_LUO_X86_VCPU_FLAG_APIC_ONESHOT_EXPIRED;
		if (oneshot_expired) {
			tmict = apic_get_reg(lapic->regs, APIC_TMICT);
			apic_set_reg(lapic->regs, APIC_TMICT, 0);
		}

		if (vcpu->kvm->arch.vm_type == KVM_X86_TDX_VM) {
			u64 apic_base = APIC_DEFAULT_PHYS_BASE |
					LAPIC_MODE_X2APIC |
					(kvm_vcpu_is_reset_bsp(vcpu) ?
					 MSR_IA32_APICBASE_BSP : 0);

			vcpu->arch.apic->vapic_addr = 0;
			if (kvm_apic_set_base(vcpu, apic_base, true)) {
				kfree(lapic);
				ret = -EINVAL;
				goto out_free;
			}
		}

		ret = kvm_apic_set_state(vcpu, lapic);
		if (!ret && oneshot_expired)
			apic_set_reg(vcpu->arch.apic->regs, APIC_TMICT, tmict);
		kfree(lapic);
		if (ret)
			goto out_free;
	}

	/* 7. Restore MSRs and TSC-deadline timer. */
	if (!is_protected || vcpu->kvm->arch.vm_type == KVM_X86_TDX_VM) {
		ret = kvm_luo_restore_msrs(vcpu, st->msrs, st->nr_msrs);
		if (ret)
			goto out_free;
	}

	if ((st->flags & KVM_LUO_X86_VCPU_FLAG_HAS_LAPIC) &&
	    lapic_in_kernel(vcpu))
		kvm_set_lapic_tscdeadline_msr(vcpu, st->tscdeadline);

	/*
	 * 8. Restore paravirtual GPA state lazily so vCPU retrieval succeeds
	 * even before memslots are bound on the retrieved VM.
	 */
	vcpu->arch.time = st->pv_time_msr;
	if (vcpu->vcpu_id == 0) {
		vcpu->kvm->arch.boot_vcpu_runs_old_kvmclock =
			!!(st->flags & KVM_LUO_X86_VCPU_FLAG_OLD_KVMCLOCK);
		kvm_make_request(KVM_REQ_MASTERCLOCK_UPDATE, vcpu);
	}
	if (st->flags & KVM_LUO_X86_VCPU_FLAG_PV_TIME) {
		kvm_vcpu_srcu_read_lock(vcpu);
		ret = kvm_gpc_activate(&vcpu->arch.pv_time,
				       st->pv_time_msr & ~1ULL,
				       sizeof(struct pvclock_vcpu_time_info));
		kvm_vcpu_srcu_read_unlock(vcpu);
		if (ret && ret != -EFAULT)
			goto out_free;
		ret = 0;
		kvm_make_request(KVM_REQ_GLOBAL_CLOCK_UPDATE, vcpu);
	}
	vcpu->arch.pv_eoi.msr_val = st->pv_eoi_msr;
	if (st->flags & KVM_LUO_X86_VCPU_FLAG_PV_EOI) {
		vcpu->arch.pv_eoi.data.gpa =
			st->pv_eoi_msr & ~KVM_MSR_ENABLED;
		vcpu->arch.pv_eoi.data.len = sizeof(u8);
		vcpu->arch.pv_eoi.data.generation = -1ULL;
	}
	vcpu->arch.st.msr_val = st->steal_msr;
	if (st->flags & KVM_LUO_X86_VCPU_FLAG_STEAL)
		kvm_make_request(KVM_REQ_STEAL_UPDATE, vcpu);

	vcpu->arch.apf.msr_en_val = st->apf_msr_en;
	vcpu->arch.apf.msr_int_val = st->apf_msr_int;
	vcpu->arch.apf.vec = st->apf_vec;
	vcpu->arch.apf.id = st->apf_id;
	vcpu->arch.apf.pageready_pending = st->apf_pageready_pending;
	if (st->flags & KVM_LUO_X86_VCPU_FLAG_APF) {
		vcpu->arch.apf.data.gpa = st->apf_msr_en & ~0x3fULL;
		vcpu->arch.apf.data.len = sizeof(u64);
		vcpu->arch.apf.data.generation = -1ULL;
		kvm_async_pf_wakeup_all(vcpu);
	}

	/* 9. Restore debug registers, GPRs, MP state, and vCPU events. */
	if (!is_protected) {
		dbgregs = st->debugregs;
		ret = kvm_vcpu_ioctl_x86_set_debugregs(vcpu, &dbgregs);
		if (ret)
			goto out_free;

		regs = st->regs;
		kvm_set_regs(vcpu, &regs);
	}

	mp_state.mp_state = st->mp_state;
	ret = kvm_vcpu_ioctl_x86_set_mpstate(vcpu, &mp_state);
	if (ret)
		goto out_free;

	if (!is_protected) {
		events = st->events;
		ret = kvm_vcpu_ioctl_x86_set_vcpu_events(vcpu, &events);
		if (ret)
			goto out_free;
	} else {
		if (!kvm_x86_ops.vcpu_luo_retrieve) {
			ret = -EOPNOTSUPP;
			goto out_free;
		}
		ret = kvm_x86_ops.vcpu_luo_retrieve(vcpu, st);
		if (ret)
			goto out_free;
	}

	kvm_mmu_reset_context(vcpu);
	kvm_make_request(KVM_REQ_TLB_FLUSH_GUEST, vcpu);
	kvm_pit_luo_vcpu_retrieved(vcpu->kvm);
	ret = 0;

out_free:
	kfree(xsave);
	return ret;
}

void kvm_arch_luo_vcpu_finish(struct kvm_vcpu *vcpu, u64 arch_state_pa)
{
	struct kvm_luo_vcpu_x86_state *st;

	if (!arch_state_pa)
		return;

	st = __va(arch_state_pa);
	if (kvm_x86_ops.vcpu_luo_finish &&
	    (st->flags & KVM_LUO_X86_VCPU_FLAG_VENDOR_PRESERVED))
		kvm_x86_ops.vcpu_luo_finish(st, !!vcpu);

	kho_restore_free(st);
}
