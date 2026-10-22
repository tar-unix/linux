/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 */

/**
 * DOC: KVM VM live update ABI
 *
 * A VM preserved by the "kvm-vm" live update file handler is described by
 * struct kvm_vm_luo_state. It starts with a struct luo_feature_hdr and
 * follows the Live Update Orchestrator rules for adding and retiring
 * features and fields.
 *
 * %KVM_VM_LUO_FEAT_CORE covers @type and @arch_state_pa and is required for
 * every VM. In addition, every VM has exactly one "kind" feature, marked
 * required, that states what kind of VM was preserved, and with that which
 * kind specific fields follow. Kinds are mutually exclusive. A kernel that
 * does not implement the kind of a preserved VM refuses to retrieve it, while
 * VMs of the kinds it implements are not affected.
 */

#ifndef _LINUX_KHO_ABI_KVM_H
#define _LINUX_KHO_ABI_KVM_H

#include <linux/kho/abi/kexec_handover.h>
#include <linux/kho/abi/luo.h>
#include <linux/types.h>
#include <uapi/linux/kvm.h>

/**
 * enum kvm_vm_luo_feature - Feature indices for struct kvm_vm_luo_state.
 * @KVM_VM_LUO_FEAT_CORE:     Covers @type and @arch_state_pa. Required for
 *                            every VM.
 * @KVM_VM_LUO_FEAT_NON_COCO: Kind of VM that has neither private memory nor
 *                            protected guest state. No kind specific fields.
 * @KVM_VM_LUO_FEAT_MAX:      Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_VM_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_vm_luo_feature {
	KVM_VM_LUO_FEAT_CORE = 0,
	KVM_VM_LUO_FEAT_NON_COCO = 1,
	KVM_VM_LUO_FEAT_MAX,
};

static_assert((int)KVM_VM_LUO_FEAT_MAX <= LUO_FEAT_MAX);

/**
 * struct kvm_vm_luo_state - Preserved state of a KVM VM.
 * @features:      Feature header.
 * @type:          Machine type, as passed to KVM_CREATE_VM, that creates a VM
 *                 equivalent to the preserved one.
 * @arch_state_pa: Physical address of architecture-specific preserved VM
 *                 state.
 */
struct kvm_vm_luo_state {
	struct luo_feature_hdr features;
	u64 type;
	u64 arch_state_pa;
};

static_assert(offsetof(struct kvm_vm_luo_state, type) == 128);
static_assert(offsetof(struct kvm_vm_luo_state, arch_state_pa) == 136);
static_assert(sizeof(struct kvm_vm_luo_state) == 144);

/* The name of the live update file handler for KVM VM files. */
#define KVM_VM_LUO_FH_NAME	"kvm-vm"

/**
 * DOC: guest_memfd live update ABI
 *
 * A guest_memfd preserved by the "guest_memfd" live update file handler is
 * described by struct kvm_gmem_luo_state. It starts with a struct
 * luo_feature_hdr and follows the Live Update Orchestrator rules for adding
 * and retiring features and fields.
 *
 * %KVM_GMEM_LUO_FEAT_CORE covers all fields defined today and is required for
 * every guest_memfd. It describes a guest_memfd whose memory is always shared
 * with the host and consists of order-0 folios. Support for private memory or
 * for large folios changes what the preserved memory means, and is added as
 * new features that are required by the guest_memfd that use them, so that a
 * kernel without that support refuses to retrieve them.
 */

/**
 * enum kvm_gmem_luo_feature - Feature indices for struct kvm_gmem_luo_state.
 * @KVM_GMEM_LUO_FEAT_CORE: Covers all fields of struct kvm_gmem_luo_state and
 *                          struct kvm_gmem_luo_folio, and
 *                          %KVM_GMEM_LUO_ALL_FLAGS. Required.
 * @KVM_GMEM_LUO_FEAT_MAX:  Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_GMEM_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_gmem_luo_feature {
	KVM_GMEM_LUO_FEAT_CORE = 0,
	KVM_GMEM_LUO_FEAT_MAX,
};

static_assert((int)KVM_GMEM_LUO_FEAT_MAX <= LUO_FEAT_MAX);

/*
 * The guest_memfd flags, as passed to KVM_CREATE_GUEST_MEMFD, that can be
 * preserved. They are uAPI, so their values are stored as they are. Support
 * for other flags is added under a new feature.
 */
#define KVM_GMEM_LUO_ALL_FLAGS	(GUEST_MEMFD_FLAG_MMAP | \
				 GUEST_MEMFD_FLAG_INIT_SHARED)

/* The folio is up to date, i.e. it does not need to be cleared before use. */
#define KVM_GMEM_LUO_FOLIO_UPTODATE	BIT(0)

/**
 * struct kvm_gmem_luo_folio - A preserved folio of a guest_memfd.
 * @pfn:   Page frame number of the folio.
 * @flags: %KVM_GMEM_LUO_FOLIO_* flags.
 * @index: Offset of the folio in the guest_memfd, in pages.
 */
struct kvm_gmem_luo_folio {
	u64 pfn:52;
	u64 flags:12;
	u64 index;
};

static_assert(sizeof(struct kvm_gmem_luo_folio) == 16);

/**
 * struct kvm_gmem_luo_state - Preserved state of a guest_memfd.
 * @features:  Feature header.
 * @size:      Size of the guest_memfd in bytes.
 * @flags:     Flags the guest_memfd was created with, a subset of
 *             %KVM_GMEM_LUO_ALL_FLAGS.
 * @nr_folios: Number of preserved folios.
 * @folios:    Preserved vmalloc area with @nr_folios struct
 *             kvm_gmem_luo_folio entries, valid if @nr_folios is not zero.
 */
struct kvm_gmem_luo_state {
	struct luo_feature_hdr features;
	u64 size;
	u64 flags;
	u64 nr_folios;
	struct kho_vmalloc folios;
};

static_assert(offsetof(struct kvm_gmem_luo_state, size) == 128);

/* The name of the live update file handler for guest_memfd files. */
#define KVM_GMEM_LUO_FH_NAME	"guest_memfd"

#ifdef CONFIG_X86

#define KVM_LUO_X86_MAX_IRQ_ROUTES	1024

#define KVM_LUO_X86_VM_STATE_VERSION	1
#define KVM_LUO_X86_VM_FLAG_HAS_PIT		BIT(0)
#define KVM_LUO_X86_VM_FLAG_HAS_TSS		BIT(1)
#define KVM_LUO_X86_VM_FLAG_HAS_IDENT		BIT(2)
#define KVM_LUO_X86_VM_FLAG_WALL_CLOCK		BIT(3)
#define KVM_LUO_X86_VM_FLAG_EXCEPTION_PAYLOAD	BIT(4)
#define KVM_LUO_X86_VM_FLAG_PIT_SPEAKER_DUMMY	BIT(5)
#define KVM_LUO_X86_VM_FLAG_PIT_REINJECT	BIT(6)
#define KVM_LUO_X86_VM_FLAG_TRIPLE_FAULT_EVENT	BIT(7)
#define KVM_LUO_X86_VM_FLAG_X2APIC_FORMAT	BIT(8)
#define KVM_LUO_X86_VM_FLAG_X2APIC_BC_QUIRK_DIS	BIT(9)
#define KVM_LUO_X86_VM_FLAG_BUS_LOCK_DETECTION	BIT(10)
#define KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_EN	BIT(11)
#define KVM_LUO_X86_VM_FLAG_SUPPRESS_EOI_BC_DIS	BIT(12)
#define KVM_LUO_X86_VM_FLAG_MSR_PLATFORM_INFO	BIT(13)
#define KVM_LUO_X86_VM_FLAG_EXIT_ON_EMUL_ERR	BIT(14)
#define KVM_LUO_X86_VM_FLAG_EXIT_HC_MAP_GPA	BIT(15)
#define KVM_LUO_X86_VM_FLAG_DISABLE_EXITS_PAUSE	BIT(16)
#define KVM_LUO_X86_VM_FLAG_DISABLE_PMU		BIT(17)
#define KVM_LUO_X86_VM_FLAG_PIT_TIMER_ACTIVE	BIT(18)

/**
 * struct kvm_luo_vm_x86_state - Preserved x86 VM architectural state.
 * @version:              Format version (%KVM_LUO_X86_VM_STATE_VERSION).
 * @flags:                %KVM_LUO_X86_VM_FLAG_* flags.
 * @irqchip_mode:         In-kernel irqchip mode (NONE, KERNEL, SPLIT).
 * @nr_ioapic_pins:       Number of split-irqchip IOAPIC pins.
 * @default_tsc_khz:      VM default TSC frequency in kHz.
 * @bsp_vcpu_id:          Boot processor vCPU identifier.
 * @tss_addr:             TSS address set via KVM_SET_TSS_ADDR.
 * @ioapic_irr_delivered: Preserved IOAPIC irr_delivered bitmap.
 * @identity_map_addr:    Identity map address set via KVM_SET_IDENTITY_MAP_ADDR.
 * @clock_ns:             Guest kvmclock value in nanoseconds at freeze.
 * @clock_realtime_ns:    Host CLOCK_REALTIME in nanoseconds at freeze.
 * @wall_clock_gpa:       Guest physical address of pvclock wall_clock.
 * @pic_master:           Master 8259A PIC state.
 * @pic_slave:            Slave 8259A PIC state.
 * @ioapic:               In-kernel IOAPIC state.
 * @pit:                  In-kernel 8254 PIT state.
 * @nr_irq_routes:        Number of preserved GSI routing entries.
 * @nr_vcpus:             Number of online vCPUs at freeze time.
 * @disabled_quirks:      Preserved VM disabled_quirks mask.
 * @irq_routes:           Preserved GSI routing table entries.
 */
struct kvm_luo_vm_x86_state {
	u32 version;
	u32 flags;
	u32 irqchip_mode;
	u32 nr_ioapic_pins;
	u32 default_tsc_khz;
	u32 bsp_vcpu_id;
	u32 tss_addr;
	u32 ioapic_irr_delivered;
	u64 identity_map_addr;
	u64 clock_ns;
	u64 clock_realtime_ns;
	u64 wall_clock_gpa;
	struct kvm_irqchip pic_master;
	struct kvm_irqchip pic_slave;
	struct kvm_irqchip ioapic;
	struct kvm_pit_state2 pit;
	u16 nr_irq_routes;
	u16 nr_vcpus;
	u32 disabled_quirks;
	struct kvm_irq_routing_entry irq_routes[KVM_LUO_X86_MAX_IRQ_ROUTES];
};

static_assert(sizeof(struct kvm_luo_vm_x86_state) == 50896);

#endif /* CONFIG_X86 */

#endif /* _LINUX_KHO_ABI_KVM_H */
