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

/**
 * DOC: KVM vCPU live update ABI
 *
 * A vCPU preserved by the "kvm-vcpu" live update file handler is described by
 * struct kvm_vcpu_luo_state. It starts with a struct luo_feature_hdr and
 * follows the Live Update Orchestrator rules for adding and retiring
 * features and fields.
 *
 * %KVM_VCPU_LUO_FEAT_CORE covers @vcpu_id, @reserved, and @arch_state_pa and
 * is required for every vCPU. In addition, every vCPU has exactly one "kind"
 * feature, marked required, that states what kind of VM the vCPU belongs to.
 */

/**
 * enum kvm_vcpu_luo_feature - Feature indices for struct kvm_vcpu_luo_state.
 * @KVM_VCPU_LUO_FEAT_CORE:     Covers @vcpu_id, @reserved, and @arch_state_pa.
 *                              Required for every vCPU.
 * @KVM_VCPU_LUO_FEAT_NON_COCO: Kind of vCPU belonging to a VM that has neither
 *                              private memory nor protected guest state.
 * @KVM_VCPU_LUO_FEAT_MAX:      Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_VCPU_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_vcpu_luo_feature {
	KVM_VCPU_LUO_FEAT_CORE = 0,
	KVM_VCPU_LUO_FEAT_NON_COCO = 1,
	KVM_VCPU_LUO_FEAT_MAX,
};

static_assert((int)KVM_VCPU_LUO_FEAT_MAX <= LUO_FEAT_MAX);

/**
 * struct kvm_vcpu_luo_state - Preserved state of a KVM vCPU.
 * @features:      Feature header.
 * @vcpu_id:       vCPU identifier as passed to KVM_CREATE_VCPU.
 * @reserved:      Reserved for future use, must be zero.
 * @arch_state_pa: Physical address of architecture-specific preserved vCPU
 *                 state.
 */
struct kvm_vcpu_luo_state {
	struct luo_feature_hdr features;
	u32 vcpu_id;
	u32 reserved;
	u64 arch_state_pa;
};

static_assert(offsetof(struct kvm_vcpu_luo_state, vcpu_id) == 128);
static_assert(offsetof(struct kvm_vcpu_luo_state, arch_state_pa) == 136);
static_assert(sizeof(struct kvm_vcpu_luo_state) == 144);

/* The name of the live update file handler for KVM vCPU files. */
#define KVM_VCPU_LUO_FH_NAME	"kvm-vcpu"

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

#ifdef CONFIG_ARM64

#define KVM_LUO_ARM64_VM_STATE_VERSION		1
#define KVM_LUO_ARM64_MAX_RD_REGIONS		16
#define KVM_LUO_ARM64_MAX_SPIS			988

/**
 * struct kvm_luo_vgic_irq_state - Preserved state of one vGICv3 SGI/PPI/SPI.
 * @intid:         Virtual interrupt identifier.
 * @pending_latch: Software-latched pending state.
 * @active:        Active state.
 * @enabled:       Enable bit.
 * @config:        Trigger configuration (0 = level, 1 = edge).
 * @priority:      Interrupt priority.
 * @group:         Interrupt group (0 or 1).
 * @source:        SGI source CPU mask.
 * @active_source: Active SGI source CPU.
 * @line_level:     Asserted input line level.
 * @targets:        GICv2 target CPU mask.
 * @active_vcpu_id: vCPU ID where the interrupt is active (-1 if none).
 * @mpidr:          GICv3 target affinity (IROUTER).
 */
struct kvm_luo_vgic_irq_state {
	u32 intid;
	u8 pending_latch;
	u8 active;
	u8 enabled;
	u8 config;
	u8 priority;
	u8 group;
	u8 source;
	u8 active_source;
	u8 line_level;
	u8 targets;
	s16 active_vcpu_id;
	u64 mpidr;
};

static_assert(sizeof(struct kvm_luo_vgic_irq_state) == 24);

/**
 * struct kvm_luo_vgic_rd_region - Preserved vGICv3 redistributor region.
 * @base:  Guest physical base address of the redistributor region.
 * @count: Number of redistributors in this region (0 = unbounded).
 * @index: Region index.
 */
struct kvm_luo_vgic_rd_region {
	u64 base;
	u32 count;
	u32 index;
};

static_assert(sizeof(struct kvm_luo_vgic_rd_region) == 16);

/**
 * struct kvm_luo_vm_arm64_state - Preserved arm64 VM architectural state.
 * @version:                 Format version (%KVM_LUO_ARM64_VM_STATE_VERSION).
 * @psci_version:            Configured PSCI version.
 * @arch_flags:              Preserved subset of kvm->arch.flags.
 * @vcpu_features:           Configured VM-wide vCPU feature bitmap.
 * @smccc_std_bmap:          Bitmap of standard secure service calls.
 * @smccc_std_hyp_bmap:      Bitmap of standard hypervisor service calls.
 * @smccc_vendor_hyp_bmap:   Bitmap of vendor hypervisor calls (0-63).
 * @smccc_vendor_hyp_bmap_2: Bitmap of vendor hypervisor calls (64-127).
 * @id_regs:                 Sanitised guest feature ID registers.
 * @midr_el1:                Guest MIDR_EL1 value.
 * @revidr_el1:              Guest REVIDR_EL1 value.
 * @aidr_el1:                Guest AIDR_EL1 value.
 * @ctr_el0:                 Guest CTR_EL0 value.
 * @timer_voffset:           Virtual counter offset.
 * @timer_poffset:           Physical counter offset.
 * @timer_ppi:               Arch timer PPI interrupt numbers.
 * @has_vgic:                Whether an in-kernel vGICv3 is present.
 * @vgic_initialized:        Whether the vGICv3 distributor is initialized.
 * @vgic_enabled:            Whether the vGICv3 distributor is enabled.
 * @vgic_msis_require_devid: Whether MSIs require a device ID.
 * @vgic_nassgireq:          GICD_CTLR.nASSGIreq state.
 * @vgic_nassgicap:          Whether GICD_TYPER2.nASSGIcap is enabled.
 * @vgic_implementation_rev: GICv3 architecture implementation revision.
 * @reserved1:               Reserved for alignment, must be zero.
 * @vgic_model:              vGIC device model (%KVM_DEV_TYPE_ARM_VGIC_V3).
 * @vgic_nr_spis:            Number of configured SPIs.
 * @vgic_dist_base:          Guest physical base address of GICD.
 * @nr_rd_regions:           Number of configured redistributor regions.
 * @reserved2:               Reserved for alignment, must be zero.
 * @rd_regions:              Preserved redistributor regions.
 * @spis:                    Preserved SPI interrupt states.
 */
struct kvm_luo_vm_arm64_state {
	u32 version;
	u32 psci_version;
	u64 arch_flags;
	u64 vcpu_features;
	u64 smccc_std_bmap;
	u64 smccc_std_hyp_bmap;
	u64 smccc_vendor_hyp_bmap;
	u64 smccc_vendor_hyp_bmap_2;
	u64 id_regs[64];
	u64 midr_el1;
	u64 revidr_el1;
	u64 aidr_el1;
	u64 ctr_el0;
	u64 timer_voffset;
	u64 timer_poffset;
	u32 timer_ppi[4];
	u8 has_vgic;
	u8 vgic_initialized;
	u8 vgic_enabled;
	u8 vgic_msis_require_devid;
	u8 vgic_nassgireq;
	u8 vgic_nassgicap;
	u8 vgic_implementation_rev;
	u8 reserved1;
	u32 vgic_model;
	u32 vgic_nr_spis;
	u64 vgic_dist_base;
	u32 nr_rd_regions;
	u32 reserved2;
	struct kvm_luo_vgic_rd_region rd_regions[KVM_LUO_ARM64_MAX_RD_REGIONS];
	struct kvm_luo_vgic_irq_state spis[KVM_LUO_ARM64_MAX_SPIS];
};

static_assert(sizeof(struct kvm_luo_vm_arm64_state) == 24632);

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_H */
