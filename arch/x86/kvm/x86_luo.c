// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 *
 * KVM x86 VM liveupdate state preservation and retrieval.
 */

#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <linux/string.h>

#include "i8254.h"
#include "ioapic.h"
#include "irq.h"
#include "lapic.h"
#include "x86.h"

static int kvm_x86_luo_check_vm_supported(struct kvm *kvm)
{
	if (kvm_arch_has_private_mem(kvm) || kvm->arch.has_protected_state)
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

	memset(st, 0, sizeof(*st));
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

	*arch_state_pa = __pa(st);
	return 0;
}

int kvm_arch_luo_vm_freeze(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return 0;

	return kvm_x86_luo_save_vm_state(kvm, __va(arch_state_pa));
}

void kvm_arch_luo_vm_unpreserve(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_unpreserve_free(__va(arch_state_pa));
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

	return 0;
}

void kvm_arch_luo_vm_finish(struct kvm *kvm, u64 arch_state_pa)
{
	if (!arch_state_pa)
		return;

	kho_restore_free(__va(arch_state_pa));
}

