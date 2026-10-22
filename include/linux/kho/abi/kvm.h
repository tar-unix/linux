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
 * @KVM_VM_LUO_FEAT_CORE:         Covers @type and @arch_state_pa. Required for
 *                                every VM.
 * @KVM_VM_LUO_FEAT_NON_COCO:     Kind of VM that has neither private memory nor
 *                                protected guest state. No kind specific
 *                                fields.
 * @KVM_VM_LUO_FEAT_SW_PROTECTED: Kind of VM with software-protected private
 *                                memory (%KVM_X86_SW_PROTECTED_VM).
 * @KVM_VM_LUO_FEAT_TDX:          Kind of Intel TDX confidential VM
 *                                (%KVM_X86_TDX_VM).
 * @KVM_VM_LUO_FEAT_SEV_SNP:      Kind of AMD SEV-SNP confidential VM
 *                                (%KVM_X86_SNP_VM).
 * @KVM_VM_LUO_FEAT_MAX:          Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_VM_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_vm_luo_feature {
	KVM_VM_LUO_FEAT_CORE = 0,
	KVM_VM_LUO_FEAT_NON_COCO = 1,
	KVM_VM_LUO_FEAT_SW_PROTECTED = 2,
	KVM_VM_LUO_FEAT_TDX = 3,
	KVM_VM_LUO_FEAT_SEV_SNP = 4,
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
 * %KVM_GMEM_LUO_FEAT_CORE covers @size, @flags, @nr_folios, and @folios and is
 * required for every guest_memfd. %KVM_GMEM_LUO_FEAT_PRIVATE covers
 * @nr_attr_ranges and @attr_ranges (describing non-default
 * KVM_SET_MEMORY_ATTRIBUTES2 ranges) and is required when preserving a
 * guest_memfd belonging to a VM with private memory, so that a kernel without
 * private memory preservation support refuses to retrieve it.
 */

/**
 * enum kvm_gmem_luo_feature - Feature indices for struct kvm_gmem_luo_state.
 * @KVM_GMEM_LUO_FEAT_CORE:    Covers @size, @flags, @nr_folios, and @folios of
 *                             struct kvm_gmem_luo_state, struct
 *                             kvm_gmem_luo_folio, and %KVM_GMEM_LUO_ALL_FLAGS.
 *                             Required.
 * @KVM_GMEM_LUO_FEAT_PRIVATE: Private memory and maple-tree attribute ranges
 *                             (@nr_attr_ranges, @attr_ranges, and @vm_id of
 *                             struct kvm_gmem_luo_state, and struct
 *                             kvm_gmem_luo_attr_range). Required for
 *                             guest_memfd of VMs with private memory.
 * @KVM_GMEM_LUO_FEAT_MAX:     Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_GMEM_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_gmem_luo_feature {
	KVM_GMEM_LUO_FEAT_CORE = 0,
	KVM_GMEM_LUO_FEAT_PRIVATE = 1,
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
 * struct kvm_gmem_luo_attr_range - A preserved attribute range of a guest_memfd.
 * @pgoff:      Starting page offset in the guest_memfd.
 * @nr_pages:   Number of pages in the range.
 * @attributes: Memory attributes for the range (%KVM_MEMORY_ATTRIBUTE_*).
 * @reserved:   Reserved for future use, must be zero.
 */
struct kvm_gmem_luo_attr_range {
	u64 pgoff;
	u64 nr_pages;
	u64 attributes;
	u64 reserved;
};

static_assert(sizeof(struct kvm_gmem_luo_attr_range) == 32);

/**
 * struct kvm_gmem_luo_state - Preserved state of a guest_memfd.
 * @features:       Feature header.
 * @size:           Size of the guest_memfd in bytes.
 * @flags:          Flags the guest_memfd was created with, a subset of
 *                  %KVM_GMEM_LUO_ALL_FLAGS.
 * @nr_folios:      Number of preserved folios.
 * @folios:         Preserved vmalloc area with @nr_folios struct
 *                  kvm_gmem_luo_folio entries, valid if @nr_folios is not
 *                  zero.
 * @nr_attr_ranges: Number of preserved attribute ranges.
 * @attr_ranges:    Preserved vmalloc area with @nr_attr_ranges struct
 *                  kvm_gmem_luo_attr_range entries, valid if @nr_attr_ranges
 *                  is not zero.
 * @vm_id:          Architecture-specific VM identifier
 *                  (%KVM_GMEM_LUO_FEAT_PRIVATE).
 */
struct kvm_gmem_luo_state {
	struct luo_feature_hdr features;
	u64 size;
	u64 flags;
	u64 nr_folios;
	struct kho_vmalloc folios;
	u64 nr_attr_ranges;
	struct kho_vmalloc attr_ranges;
	u64 vm_id;
};

static_assert(offsetof(struct kvm_gmem_luo_state, size) == 128);
static_assert(sizeof(struct kvm_gmem_luo_state) == 200);

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
 * @KVM_VCPU_LUO_FEAT_CORE:         Covers @vcpu_id, @reserved, and
 *                                  @arch_state_pa. Required for every vCPU.
 * @KVM_VCPU_LUO_FEAT_NON_COCO:     Kind of vCPU belonging to a VM that has
 *                                  neither private memory nor protected guest
 *                                  state.
 * @KVM_VCPU_LUO_FEAT_SW_PROTECTED: Kind of vCPU belonging to a VM with
 *                                  software-protected private memory
 *                                  (%KVM_X86_SW_PROTECTED_VM).
 * @KVM_VCPU_LUO_FEAT_TDX:          Kind of vCPU belonging to an Intel TDX
 *                                  confidential VM (%KVM_X86_TDX_VM).
 * @KVM_VCPU_LUO_FEAT_SEV_SNP:      Kind of vCPU belonging to an AMD SEV-SNP
 *                                  confidential VM (%KVM_X86_SNP_VM).
 * @KVM_VCPU_LUO_FEAT_MAX:          Number of defined features.
 *
 * The values are ABI. New features are added before %KVM_VCPU_LUO_FEAT_MAX,
 * and retired features keep their index.
 */
enum kvm_vcpu_luo_feature {
	KVM_VCPU_LUO_FEAT_CORE = 0,
	KVM_VCPU_LUO_FEAT_NON_COCO = 1,
	KVM_VCPU_LUO_FEAT_SW_PROTECTED = 2,
	KVM_VCPU_LUO_FEAT_TDX = 3,
	KVM_VCPU_LUO_FEAT_SEV_SNP = 4,
	KVM_VCPU_LUO_FEAT_MAX,
};

static_assert((int)KVM_VCPU_LUO_FEAT_MAX <= LUO_FEAT_MAX);
static_assert((int)KVM_VCPU_LUO_FEAT_NON_COCO == (int)KVM_VM_LUO_FEAT_NON_COCO);
static_assert((int)KVM_VCPU_LUO_FEAT_SW_PROTECTED == (int)KVM_VM_LUO_FEAT_SW_PROTECTED);
static_assert((int)KVM_VCPU_LUO_FEAT_TDX == (int)KVM_VM_LUO_FEAT_TDX);
static_assert((int)KVM_VCPU_LUO_FEAT_SEV_SNP == (int)KVM_VM_LUO_FEAT_SEV_SNP);

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

/* Global CoCo FLB handler names. */
#define TDX_HOST_LUO_FLB_NAME	"tdx-host"
#define SEV_SNP_LUO_FLB_NAME	"sev-snp"
#define ARM_RMM_LUO_FLB_NAME	"arm-rmm"

#ifdef CONFIG_X86

#define TDX_LUO_MAX_TDMRS		64
#define TDX_LUO_MAX_LP_CPUS		8192
#define TDX_LUO_LP_BITMAP_U64S		(TDX_LUO_MAX_LP_CPUS / 64)
#define TDX_LUO_MAX_HKIDS		2048
#define TDX_LUO_HKID_BITMAP_U64S	(TDX_LUO_MAX_HKIDS / 64)
#define TDX_LUO_MAX_TDCS_PAGES		16
#define TDX_LUO_MAX_TDCX_PAGES		8

#define TDX_LUO_FLB_MAGIC		0x5444584cU
#define TDX_LUO_FLB_F_ACTIVE_TDS	BIT(0)

/**
 * struct tdx_luo_tdmr_pamt - Preserved PAMT physical ranges for one TDMR.
 * @base:         Physical base address of the TDMR.
 * @size:         Size of the TDMR in bytes.
 * @pamt_1g_base: Physical base address of the 1G PAMT table.
 * @pamt_1g_size: Size of the 1G PAMT table in bytes.
 * @pamt_2m_base: Physical base address of the 2M PAMT table.
 * @pamt_2m_size: Size of the 2M PAMT table in bytes.
 * @pamt_4k_base: Physical base address of the 4K PAMT table.
 * @pamt_4k_size: Size of the 4K PAMT table in bytes.
 */
struct tdx_luo_tdmr_pamt {
	u64 base;
	u64 size;
	u64 pamt_1g_base;
	u64 pamt_1g_size;
	u64 pamt_2m_base;
	u64 pamt_2m_size;
	u64 pamt_4k_base;
	u64 pamt_4k_size;
};

static_assert(sizeof(struct tdx_luo_tdmr_pamt) == 64);

/**
 * struct tdx_luo_flb_state - Preserved global state for "tdx-host" FLB.
 * @magic:           Magic value (%TDX_LUO_FLB_MAGIC).
 * @flags:           %TDX_LUO_FLB_F_* flags.
 * @global_keyid:    Preserved TDX global HKID.
 * @nr_tdmrs:        Number of consumed TDMR entries.
 * @tdmr_list_pa:    Physical address of the preserved tdmr_list pages.
 * @tdmr_list_order: Page allocation order of @tdmr_list_pa.
 * @tdmr_sz:         Size in bytes of one TDMR info entry.
 * @max_tdmrs:       Maximum number of TDMR entries allocated.
 * @reserved0:       Reserved for alignment, must be zero.
 * @lp_init_bitmap:  Bitmap of logical processors initialized via TDH.SYS.LP.INIT.
 * @active_hkids:    Bitmap of preserved active TDX guest HKIDs.
 * @pamts:           Preserved PAMT physical ranges for each TDMR.
 */
struct tdx_luo_flb_state {
	u32 magic;
	u32 flags;
	u32 global_keyid;
	u32 nr_tdmrs;
	u64 tdmr_list_pa;
	u32 tdmr_list_order;
	u32 tdmr_sz;
	u32 max_tdmrs;
	u32 reserved0;
	u64 lp_init_bitmap[TDX_LUO_LP_BITMAP_U64S];
	u64 active_hkids[TDX_LUO_HKID_BITMAP_U64S];
	struct tdx_luo_tdmr_pamt pamts[TDX_LUO_MAX_TDMRS];
};

static_assert(sizeof(struct tdx_luo_flb_state) == 5416);

/**
 * struct kvm_tdx_luo_sept_page - One preserved S-EPT mirror page table node.
 * @gfn:         Base GFN covered by this SP.
 * @spt_pfn:     PFN of KVM software mirror page (sp->spt).
 * @ext_spt_pfn: PFN of SEAM S-EPT page (sp->external_spt; 0 for root level).
 * @role_bits:   Preserved kvm_mmu_page_role word.
 * @level:       Page table level (PG_LEVEL_4K .. root_level).
 * @reserved:    Reserved for alignment, must be zero.
 */
struct kvm_tdx_luo_sept_page {
	u64 gfn;
	u64 spt_pfn;
	u64 ext_spt_pfn;
	u32 role_bits;
	u8 level;
	u8 reserved[3];
};

static_assert(sizeof(struct kvm_tdx_luo_sept_page) == 32);

/**
 * struct kvm_tdx_vm_luo_state - Per-TD VM state embedded in kvm_luo_vm_x86_state.
 * @tdr_pfn:        PFN of the 4KB TDR control page.
 * @tdcs_pfns:      PFNs of the TDCS control pages.
 * @nr_tdcs_pages:  Number of valid entries in @tdcs_pfns.
 * @hkid:           Assigned TDX guest HKID.
 * @tdx_state:      TD lifecycle state at freeze time.
 * @root_level:     S-EPT root page table level.
 * @attributes:     TD attributes.
 * @xfam:           TD extended feature available mask.
 * @tsc_offset:     TD TSC offset.
 * @tsc_multiplier: TD TSC multiplier.
 * @nr_sept_pages:  Number of preserved S-EPT mirror page nodes.
 * @sept_pages:     Preserved vmalloc array of struct kvm_tdx_luo_sept_page.
 */
struct kvm_tdx_vm_luo_state {
	u64 tdr_pfn;
	u64 tdcs_pfns[TDX_LUO_MAX_TDCS_PAGES];
	u32 nr_tdcs_pages;
	s32 hkid;
	u32 tdx_state;
	u32 root_level;
	u64 attributes;
	u64 xfam;
	u64 tsc_offset;
	u64 tsc_multiplier;
	u64 nr_sept_pages;
	struct kho_vmalloc sept_pages;
};

static_assert(sizeof(struct kvm_tdx_vm_luo_state) == 208);

/**
 * struct kvm_tdx_vcpu_luo_state - Per-TD vCPU state embedded in kvm_luo_vcpu_x86_state.
 * @tdr_pfn:       PFN of the owning TD's 4KB TDR control page.
 * @tdvpr_pfn:     PFN of the 4KB TDVPR control page.
 * @tdcx_pfns:     PFNs of the TDCX control pages.
 * @nr_tdcx_pages: Number of valid entries in @tdcx_pfns.
 * @state:         TD vCPU state (enum vcpu_tdx_state).
 * @exit_reason:   Preserved vt->exit_reason.full across liveupdate.
 * @vp_enter_ret:  Last TDH.VP.ENTER return code.
 * @rcx:           Saved hypercall RCX argument.
 * @rdx:           Saved hypercall RDX argument.
 * @r8:            Saved hypercall R8 argument.
 * @r9:            Saved hypercall R9 argument.
 * @r10:           Saved TDG.VP.VMCALL R10 GPR.
 * @r11:           Saved TDG.VP.VMCALL R11 GPR.
 * @r12:           Saved TDG.VP.VMCALL R12 GPR.
 * @r13:           Saved TDG.VP.VMCALL R13 GPR.
 * @r14:           Saved TDG.VP.VMCALL R14 GPR.
 * @r15:           Saved TDG.VP.VMCALL R15 GPR.
 * @rbx:           Saved TDG.VP.VMCALL RBX GPR.
 * @rdi:           Saved TDG.VP.VMCALL RDI GPR.
 * @rsi:           Saved TDG.VP.VMCALL RSI GPR.
 * @map_gpa_next:  Next GPA for in-flight MapGPA hypercall.
 * @map_gpa_end:   End GPA for in-flight MapGPA hypercall.
 * @pi_pir:        Preserved VT-d Posted Interrupt Descriptor PIR bitmap.
 * @pi_control:    Preserved VT-d Posted Interrupt Descriptor control word.
 */
struct kvm_tdx_vcpu_luo_state {
	u64 tdr_pfn;
	u64 tdvpr_pfn;
	u64 tdcx_pfns[TDX_LUO_MAX_TDCX_PAGES];
	u16 nr_tdcx_pages;
	u16 state;
	u32 exit_reason;
	u64 vp_enter_ret;
	u64 rcx;
	u64 rdx;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u64 rbx;
	u64 rdi;
	u64 rsi;
	u64 map_gpa_next;
	u64 map_gpa_end;
	u64 pi_pir[4];
	u64 pi_control;
};

static_assert(sizeof(struct kvm_tdx_vcpu_luo_state) == 256);

#define SEV_SNP_LUO_MAX_IOMMUS		16
#define SEV_SNP_LUO_MAX_HV_FIXED	64
#define SEV_SNP_LUO_MAX_ASIDS		1024

#define SEV_SNP_LUO_FLB_MAGIC		0x534e504cU
#define SEV_SNP_LUO_FLB_F_ACTIVE_VMS	BIT(0)

/**
 * struct amd_iommu_luo_state - Preserved ring/table buffers for one AMD IOMMU.
 * @pci_seg:        PCI segment number of the IOMMU.
 * @devid:          PCI device ID (BDF) of the IOMMU.
 * @dev_table_size: Device table size in bytes (iommu->pci_seg->dev_table_size).
 * @evt_buf_size:   Event log buffer size in bytes.
 * @ppr_log_size:   PPR log buffer size in bytes.
 * @dev_table_pa:   Physical address of the device table.
 * @cmd_buf_pa:     Physical address of the command buffer.
 * @evt_buf_pa:     Physical address of the event log buffer.
 * @ppr_log_pa:     Physical address of the PPR log buffer.
 * @cmd_sem_pa:     Physical address of the 4KB command semaphore page.
 * @ga_log_pa:      Physical address of the guest APIC log buffer.
 * @ga_log_tail_pa: Physical address of the guest APIC log tail page.
 */
struct amd_iommu_luo_state {
	u16 pci_seg;
	u16 devid;
	u32 dev_table_size;
	u32 evt_buf_size;
	u32 ppr_log_size;
	u64 dev_table_pa;
	u64 cmd_buf_pa;
	u64 evt_buf_pa;
	u64 ppr_log_pa;
	u64 cmd_sem_pa;
	u64 ga_log_pa;
	u64 ga_log_tail_pa;
};

static_assert(sizeof(struct amd_iommu_luo_state) == 72);

/**
 * struct sev_snp_luo_flb_state - Preserved global state for "sev-snp" FLB.
 * @magic:             Magic value (%SEV_SNP_LUO_FLB_MAGIC).
 * @flags:             %SEV_SNP_LUO_FLB_F_* flags.
 * @rmp_base:          Physical base address of the RMP table.
 * @rmp_end:           Physical end address of the RMP table.
 * @sev_es_tmr_pa:     Physical address of the SEV-ES TMR buffer.
 * @sev_es_tmr_order:  Page allocation order of @sev_es_tmr_pa.
 * @sev_init_ex_order: Page allocation order of @sev_init_ex_pa.
 * @sev_init_ex_pa:    Physical address of the SEV_INIT_EX NV buffer.
 * @nr_hv_fixed_pages: Number of preserved hypervisor fixed page ranges.
 * @nr_iommus:         Number of preserved AMD IOMMU instances.
 * @active_asids:      Bitmap of preserved active SEV-SNP ASIDs.
 * @hv_fixed_pa:       Physical addresses of HV_FIXED page ranges.
 * @hv_fixed_order:    Page orders of HV_FIXED page ranges.
 * @iommus:            Preserved AMD IOMMU hardware buffer states.
 */
struct sev_snp_luo_flb_state {
	u32 magic;
	u32 flags;
	u64 rmp_base;
	u64 rmp_end;
	u64 sev_es_tmr_pa;
	u32 sev_es_tmr_order;
	u32 sev_init_ex_order;
	u64 sev_init_ex_pa;
	u32 nr_hv_fixed_pages;
	u32 nr_iommus;
	u64 active_asids[16];
	u64 hv_fixed_pa[SEV_SNP_LUO_MAX_HV_FIXED];
	u32 hv_fixed_order[SEV_SNP_LUO_MAX_HV_FIXED];
	struct amd_iommu_luo_state iommus[SEV_SNP_LUO_MAX_IOMMUS];
};

static_assert(sizeof(struct sev_snp_luo_flb_state) == 2104);

/**
 * struct kvm_snp_vm_luo_state - Per-SNP VM state embedded in kvm_luo_vm_x86_state.
 * @gctx_pfn:      PFN of the PSP SNP guest context page.
 * @asid:          Assigned SEV-SNP ASID.
 * @flags:         Preserved SNP VM state flags.
 * @ap_jump_table: Guest physical address of the AP jump table.
 * @policy:        64-bit SEV-SNP guest policy configured at launch.
 */
struct kvm_snp_vm_luo_state {
	u64 gctx_pfn;
	u32 asid;
	u32 flags;
	u64 ap_jump_table;
	u64 policy;
};

static_assert(sizeof(struct kvm_snp_vm_luo_state) == 32);

/**
 * struct kvm_snp_vcpu_luo_state - Per-SNP vCPU state embedded in kvm_luo_vcpu_x86_state.
 * @vmsa_pfn:             PFN of KVM-allocated VMSA page.
 * @vmsa_pa:              Active VMCB control.vmsa_pa physical address.
 * @ghcb_gpa:             Current VMCB control.ghcb_gpa.
 * @ghcb_registered_gpa:  Registered GHCB GPA.
 * @snp_guest_vmsa_gpa:   AP guest_memfd VMSA GPA.
 * @snp_pending_vmsa_gpa: Pending AP VMSA GPA from AP Creation NAE.
 * @sw_scratch:           Saved GHCB software scratch field.
 * @apic_base:            Host-tracked vcpu->arch.apic_base value.
 * @cr0:                  Host-tracked vcpu->arch.cr0 value.
 * @cr4:                  Host-tracked vcpu->arch.cr4 value.
 * @efer:                 Host-tracked vcpu->arch.efer value.
 * @flags:                Preserved SNP vCPU flags.
 * @ap_reset_hold_type:   AP reset hold protocol state.
 * @int_state:            VMCB control.int_state interrupt shadow bits.
 * @asid:                 Owning SEV-SNP guest ASID.
 * @valid_bitmap:         Preserved GHCB valid_bitmap.
 */
struct kvm_snp_vcpu_luo_state {
	u64 vmsa_pfn;
	u64 vmsa_pa;
	u64 ghcb_gpa;
	u64 ghcb_registered_gpa;
	u64 snp_guest_vmsa_gpa;
	u64 snp_pending_vmsa_gpa;
	u64 sw_scratch;
	u64 apic_base;
	u64 cr0;
	u64 cr4;
	u64 efer;
	u32 flags;
	u32 ap_reset_hold_type;
	u32 int_state;
	u32 asid;
	u8 valid_bitmap[16];
};

static_assert(sizeof(struct kvm_snp_vcpu_luo_state) == 120);

#define KVM_LUO_X86_MAX_CPUID_ENTRIES	256
#define KVM_LUO_X86_MAX_MSR_ENTRIES	512
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
 * @tdx:                  Per-TD VM state for %KVM_VM_LUO_FEAT_TDX.
 * @snp:                  Per-SNP VM state for %KVM_VM_LUO_FEAT_SEV_SNP.
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
	struct kvm_tdx_vm_luo_state tdx;
	struct kvm_snp_vm_luo_state snp;
};

static_assert(sizeof(struct kvm_luo_vm_x86_state) == 51136);

#define KVM_LUO_X86_VCPU_STATE_VERSION			1
#define KVM_LUO_X86_VCPU_FLAG_HAS_LAPIC			BIT(0)
#define KVM_LUO_X86_VCPU_FLAG_PV_TIME			BIT(1)
#define KVM_LUO_X86_VCPU_FLAG_PV_EOI			BIT(2)
#define KVM_LUO_X86_VCPU_FLAG_STEAL			BIT(3)
#define KVM_LUO_X86_VCPU_FLAG_APF			BIT(4)
#define KVM_LUO_X86_VCPU_FLAG_APIC_ONESHOT_EXPIRED	BIT(5)
#define KVM_LUO_X86_VCPU_FLAG_OLD_KVMCLOCK		BIT(6)
#define KVM_LUO_X86_VCPU_FLAG_PROTECTED			BIT(7)
#define KVM_LUO_X86_VCPU_FLAG_VENDOR_PRESERVED		BIT(8)

/**
 * struct kvm_luo_vcpu_x86_state - Preserved x86 vCPU architectural state.
 * @version:               Format version (%KVM_LUO_X86_VCPU_STATE_VERSION).
 * @flags:                 %KVM_LUO_X86_VCPU_FLAG_* flags.
 * @mp_state:              vCPU multiprocessing state.
 * @virtual_tsc_khz:       vCPU virtual TSC frequency in kHz.
 * @l1_tsc_offset:         L1 guest TSC offset.
 * @mcg_cap:               Guest IA32_MCG_CAP value set via KVM_X86_SETUP_MCE.
 * @tscdeadline:           LAPIC TSC-deadline timer target value.
 * @pv_time_msr:           Guest MSR_KVM_SYSTEM_TIME / _NEW value.
 * @pv_eoi_msr:            Guest MSR_KVM_PV_EOI_EN value.
 * @steal_msr:             Guest MSR_KVM_STEAL_TIME value.
 * @apf_msr_en:            Guest MSR_KVM_ASYNC_PF_EN value.
 * @apf_msr_int:           Guest MSR_KVM_ASYNC_PF_INT value.
 * @apf_vec:               Async page fault interrupt vector.
 * @apf_id:                Async page fault token counter.
 * @apf_pageready_pending: Whether an async PF page-ready event is pending.
 * @reserved0:             Reserved for alignment, must be zero.
 * @regs:                  General-purpose registers, RIP, and RFLAGS.
 * @sregs2:                Segment/control registers and PAE PDPTRs.
 * @events:                Pending exceptions, interrupts, NMIs, and SMIs.
 * @lapic:                 In-kernel local APIC register page.
 * @xsave:                 FPU/SSE/XSAVE state (4 KiB region).
 * @xcrs:                  Extended control registers (XCR0).
 * @debugregs:             Debug registers DR0-DR3, DR6, DR7.
 * @cpuid_nent:            Number of preserved CPUID entries.
 * @nr_msrs:               Number of preserved MSR entries.
 * @cpuid_entries:         Preserved guest CPUID table.
 * @msrs:                  Preserved guest MSRs.
 * @tdx:                   Per-TD vCPU state for %KVM_VCPU_LUO_FEAT_TDX.
 * @snp:                   Per-SNP vCPU state for %KVM_VCPU_LUO_FEAT_SEV_SNP.
 */
struct kvm_luo_vcpu_x86_state {
	u32 version;
	u32 flags;
	u32 mp_state;
	u32 virtual_tsc_khz;
	u64 l1_tsc_offset;
	u64 mcg_cap;
	u64 tscdeadline;
	u64 pv_time_msr;
	u64 pv_eoi_msr;
	u64 steal_msr;
	u64 apf_msr_en;
	u64 apf_msr_int;
	u32 apf_vec;
	u32 apf_id;
	u8 apf_pageready_pending;
	u8 reserved0[7];
	struct kvm_regs regs;
	struct kvm_sregs2 sregs2;
	struct kvm_vcpu_events events;
	struct kvm_lapic_state lapic;
	struct kvm_xsave xsave;
	struct kvm_xcrs xcrs;
	struct kvm_debugregs debugregs;
	u32 cpuid_nent;
	u32 nr_msrs;
	struct kvm_cpuid_entry2 cpuid_entries[KVM_LUO_X86_MAX_CPUID_ENTRIES];
	struct kvm_msr_entry msrs[KVM_LUO_X86_MAX_MSR_ENTRIES];
	struct kvm_tdx_vcpu_luo_state tdx;
	struct kvm_snp_vcpu_luo_state snp;
};

static_assert(sizeof(struct kvm_luo_vcpu_x86_state) == 25080);

#endif /* CONFIG_X86 */

#ifdef CONFIG_ARM64

/**
 * struct rmi_sro_donated_entry - Preserved RMM SRO donated memory range.
 * @phys_addr: Physical base address of the donated granule range.
 * @nr_pages:  Number of 4KB granules in the range.
 */
struct rmi_sro_donated_entry {
	u64 phys_addr;
	u64 nr_pages;
};

static_assert(sizeof(struct rmi_sro_donated_entry) == 16);

/**
 * struct arm_rmm_luo_flb_state - ARM64 RMM KHO/FLB donation ledger state.
 * @count:      Number of entries in the @entries_pa array.
 * @nr_pages:   Number of KHO-preserved pages holding the @entries_pa array.
 * @entries_pa: Physical address of KHO-preserved page(s) holding
 *              struct rmi_sro_donated_entry[].
 */
struct arm_rmm_luo_flb_state {
	u64 count;
	u64 nr_pages;
	u64 entries_pa;
};

static_assert(sizeof(struct arm_rmm_luo_flb_state) == 24);

#define KVM_LUO_ARM64_VM_STATE_VERSION		1
#define KVM_LUO_ARM64_MAX_RD_REGIONS		16
#define KVM_LUO_ARM64_MAX_SPIS			988

#define KVM_LUO_ARM64_VCPU_STATE_VERSION	1
#define KVM_LUO_ARM64_MAX_SYS_REGS		512
#define KVM_LUO_ARM64_SVE_MAX_BYTES		8768
#define KVM_LUO_ARM64_CSSELR_MAX		14

/**
 * struct kvm_luo_arm64_sys_reg - Preserved arm64 system register entry.
 * @id:  Architectural UAPI KVM_REG_ARM64_SYSREG encoding (Op0/Op1/CRn/CRm/Op2).
 * @val: Register value.
 */
struct kvm_luo_arm64_sys_reg {
	u64 id;
	u64 val;
};

static_assert(sizeof(struct kvm_luo_arm64_sys_reg) == 16);

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

/**
 * struct kvm_luo_vcpu_arm64_state - Preserved arm64 vCPU architectural state.
 * @version:              Format version (%KVM_LUO_ARM64_VCPU_STATE_VERSION).
 * @target:               CPU target type (%KVM_ARM_TARGET_GENERIC_V8).
 * @features:             vCPU feature bitmap.
 * @vcpu_flags:           Preserved subset of vcpu->arch.flags.
 * @mp_state:             vCPU multiprocessing state.
 * @power_off:            Whether the vCPU is powered off.
 * @pause:                Whether the vCPU is paused.
 * @sve_finalized:        Whether SVE state is finalized on this vCPU.
 * @has_vgic_v3:          Whether vGICv3 CPU interface state is valid.
 * @gp_regs:              General-purpose registers, SP_EL0, PC, and PSTATE.
 * @fp_regs:              FPSIMD V0-V31, FPSR, and FPCR registers.
 * @sp_el1:               Guest SP_EL1 register.
 * @elr_el1:              Guest ELR_EL1 register.
 * @spsr_abi:             Guest SPSR_EL1 and AArch32 banked SPSRs.
 * @nr_sys_regs:          Number of preserved entries in @sys_regs.
 * @sve_max_vl:           Maximum SVE vector length in bytes.
 * @sys_regs:             Guest system register array.
 * @sve_state:            Preserved SVE register buffer.
 * @vsesr_el2:            Virtual SError syndrome register.
 * @mdcr_el2:             Monitor debug configuration register.
 * @vcpu_debug_state:     Guest-owned hardware breakpoint/watchpoint registers.
 * @external_debug_state: Host-owned hardware debug registers.
 * @steal_base:           PV steal-time guest physical address.
 * @vgic_hcr:             vGICv3 ICH_HCR_EL2 shadow register.
 * @vgic_vmcr:            vGICv3 ICH_VMCR_EL2 shadow register.
 * @vgic_sre:             vGICv3 ICC_SRE_EL1 shadow register.
 * @vgic_used_lrs:        Number of active list registers.
 * @vgic_ap0r:            vGICv3 ICH_AP0Rn_EL2 active priority registers.
 * @vgic_ap1r:            vGICv3 ICH_AP1Rn_EL2 active priority registers.
 * @vgic_lr:              vGICv3 ICH_LRn_EL2 list registers.
 * @vgic_pendbaser:       vGICv3 GICR_PENDBASER register.
 * @vgic_lpis_enabled:    Whether LPIs are enabled on this redistributor.
 * @vgic_num_pri_bits:    Number of priority bits implemented.
 * @vgic_num_id_bits:     Number of interrupt ID bits implemented.
 * @sflags_serror:        Preserved vcpu->arch.sflags NESTED_SERROR_PENDING state.
 * @hcr_irq_flags:        Preserved HCR_EL2 virtual interrupt flags (VSE/VI/VF).
 * @has_ccsidr:           Whether @ccsidr contains a custom per-vCPU CCSIDR override.
 * @sflags_host_ss:       Preserved vcpu->arch.sflags HOST_SS_ACTIVE_PENDING state.
 * @vgic_rd_base:         Exact redistributor MMIO GPA for this vCPU.
 * @guest_debug:          Preserved vcpu->guest_debug control flags.
 * @reserved1:            Reserved for alignment, must be zero.
 * @ccsidr:               Per-vCPU CCSIDR override values indexed by CSSELR.
 * @private_irqs:         Preserved SGI and PPI interrupt states (0..31).
 */
struct kvm_luo_vcpu_arm64_state {
	u32 version;
	u32 target;
	u64 features;
	u64 vcpu_flags;
	u32 mp_state;
	u8 power_off;
	u8 pause;
	u8 sve_finalized;
	u8 has_vgic_v3;
	struct user_pt_regs gp_regs;
	struct user_fpsimd_state fp_regs;
	u64 sp_el1;
	u64 elr_el1;
	u64 spsr_abi[5];
	u32 nr_sys_regs;
	u32 sve_max_vl;
	struct kvm_luo_arm64_sys_reg sys_regs[KVM_LUO_ARM64_MAX_SYS_REGS];
	u8 sve_state[KVM_LUO_ARM64_SVE_MAX_BYTES];
	u64 vsesr_el2;
	u64 mdcr_el2;
	struct kvm_guest_debug_arch vcpu_debug_state;
	struct kvm_guest_debug_arch external_debug_state;
	u64 steal_base;
	u32 vgic_hcr;
	u32 vgic_vmcr;
	u32 vgic_sre;
	u32 vgic_used_lrs;
	u32 vgic_ap0r[4];
	u32 vgic_ap1r[4];
	u64 vgic_lr[16];
	u64 vgic_pendbaser;
	u8 vgic_lpis_enabled;
	u8 vgic_num_pri_bits;
	u8 vgic_num_id_bits;
	u8 sflags_serror;
	u16 hcr_irq_flags;
	u8 has_ccsidr;
	u8 sflags_host_ss;
	u64 vgic_rd_base;
	u32 guest_debug;
	u32 reserved1;
	u32 ccsidr[KVM_LUO_ARM64_CSSELR_MAX];
	struct kvm_luo_vgic_irq_state private_irqs[32];
};

static_assert(sizeof(struct kvm_luo_vcpu_arm64_state) == 19936);

#endif /* CONFIG_ARM64 */

#endif /* _LINUX_KHO_ABI_KVM_H */
