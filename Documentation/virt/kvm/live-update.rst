.. SPDX-License-Identifier: GPL-2.0

=================================
Live update of KVM guests (LUO)
=================================

A live update replaces the running kernel with a new one through kexec, while
selected resources are handed over to the new kernel intact. The Live Update
Orchestrator (LUO, see Documentation/userspace-api/liveupdate.rst) lets
userspace preserve file descriptors in sessions before the reboot and retrieve
them afterwards. KVM provides three LUO file handlers, so that a VMM can keep a
guest, its vCPUs, and its memory across a live update instead of restarting it:

``kvm-vm``
  Preserves a VM file descriptor and its architecture-specific VM state. The
  new kernel creates an equivalent VM and restores its architectural state.

``kvm-vcpu``
  Preserves a vCPU file descriptor and its architecture-specific vCPU register
  and interrupt state. The new kernel creates the vCPU on the retrieved VM and
  restores its state.

``guest_memfd``
  Preserves a guest_memfd file descriptor and the guest memory in it. The new
  kernel creates a guest_memfd with the same memory.

The handlers can be combined as needed. A guest_memfd or vCPU is bound to a VM
in the new kernel through an explicit argument when it is retrieved.

Preserved state
===============

================================  ==============================================
Object                            Carried over
================================  ==============================================
VM (``kvm-vm``)                   The machine type passed to KVM_CREATE_VM, and
                                  architecture-specific VM state: on x86,
                                  in-kernel 8259A PICs, IOAPIC, 8254 PIT, GSI
                                  routing table, kvmclock, TSS and identity map
                                  addresses, and default TSC frequency; on
                                  arm64, sanitised guest ID registers, VM-wide
                                  vCPU feature bitmap, architected timer virtual
                                  and physical counter offsets and PPI
                                  assignments, and in-kernel vGICv3 distributor,
                                  redistributor regions, and SPI state.
vCPU (``kvm-vcpu``)               The vCPU ID passed to KVM_CREATE_VCPU, and
                                  architecture-specific vCPU state: on x86,
                                  general-purpose, segment, control, debug,
                                  FPU/XSAVE, and XCR registers, pending events,
                                  local APIC, CPUID table, MSRs, MP state, TSC
                                  offset and scaling ratio, and paravirtualized
                                  MSR state; on arm64, general-purpose,
                                  FPSIMD/SVE, system, and debug registers, MP
                                  state, steal-time state, and vGICv3 CPU
                                  interface and private SGI/PPI state.
guest_memfd (``guest_memfd``)     The size, the flags passed to
                                  KVM_CREATE_GUEST_MEMFD, all allocated
                                  order-0 folios (without reading, zeroing, or
                                  modifying folio contents), and for VMs with
                                  private memory, all non-default memory
                                  attribute ranges set via
                                  KVM_SET_MEMORY_ATTRIBUTES2.
================================  ==============================================

Memory slots and their binding to guest_memfd, user mappings of guest_memfd
and ``kvm_run``, and NUMA memory policies are set up again by the VMM in the
new kernel before resuming vCPU execution. Guest memory that is not in a
guest_memfd is preserved by preserving the file that backs it, e.g. a memfd.

Which objects can be preserved depends on the architecture and on the kind of
VM. Each VM and vCPU records its kind feature (``NON_COCO``,
``SW_PROTECTED``, ``TDX``, ``SEV_SNP``, or ``ARM_CCA``) in its feature header,
and a guest_memfd belonging to a VM with private memory records
``KVM_GMEM_LUO_FEAT_PRIVATE``. On x86, both ``KVM_X86_DEFAULT_VM`` and
``KVM_X86_SW_PROTECTED_VM`` are supported, while hardware CoCo VMs
(``KVM_X86_TDX_VM`` and ``KVM_X86_SNP_VM``) dispatch to vendor liveupdate
callbacks when registered.

VMM flow
========

Before the reboot:

1. Allocate all memory the guest is going to use in each guest_memfd, e.g.
   with fallocate().
2. Stop running vCPUs so that no vCPU is inside ``KVM_RUN``.
3. Create a session on ``/dev/liveupdate`` and preserve the guest_memfd, the
   VM, and each vCPU with LIVEUPDATE_SESSION_PRESERVE_FD. The handler name may
   be given in ``handler``, the ``arg`` field must be zero. The guest_memfd
   and the VM may also be preserved while the VM is still running, whereas each
   vCPU must be stopped outside ``KVM_RUN`` before preserving its vCPU fd.
4. Keep the session open and reboot into the new kernel with kexec.

From the moment a guest_memfd is preserved, it is frozen: memory can neither
be allocated in it nor freed from it, and memory attributes cannot be changed.
fallocate(), PUNCH_HOLE, and KVM_SET_MEMORY_ATTRIBUTES2 fail with -EPERM when
frozen, touching a hole through a user mapping raises SIGBUS, and a guest
access to a hole fails like any other failure to allocate guest memory. Memory
that is present stays accessible to the guest and to userspace, and if the
guest_memfd and VM are preserved before stopping the guest, the VM keeps
running until the VMM stops its vCPUs to preserve their vCPU fds. Closing the
session before the reboot cancels the preservation of all files in it, which
unfreezes the guest_memfd. The VMs, vCPUs, and guest_memfd themselves are not
affected by cancelling.

After the reboot:

1. Load ``kvm``, and on x86 ``kvm-intel`` or ``kvm-amd``, before
   ``/dev/liveupdate`` is opened for the first time. The handlers are
   registered by these modules, and sessions with files of a handler that is
   not registered cannot be restored when ``/dev/liveupdate`` is opened.
2. In the process that is going to run the VM, retrieve the session and then
   the VM with LIVEUPDATE_SESSION_RETRIEVE_FD, or create a new VM with
   KVM_CREATE_VM. Like a VM created by KVM_CREATE_VM, a retrieved VM belongs to
   the process that retrieves it and cannot be used from other processes.
3. Retrieve each guest_memfd, passing a struct kvm_guest_memfd_luo_retrieve
   with the file descriptor of the VM in ``arg``. If the argument is missing or
   the VM cannot use the guest_memfd, retrieving fails without consuming the
   preserved guest_memfd and can be retried with a correct argument.
4. Retrieve each vCPU with LIVEUPDATE_SESSION_RETRIEVE_FD, passing a struct
   kvm_vcpu_luo_retrieve with the file descriptor of the retrieved VM in
   ``arg``. If the argument is missing or invalid, retrieving fails without
   consuming the preserved vCPU and can be retried with a correct argument.
5. Create memory slots with KVM_SET_USER_MEMORY_REGION2 at the same guest
   physical addresses and guest_memfd offsets as before, map the guest_memfd
   and each vCPU's ``kvm_run`` page into userspace where needed, and resume
   guest execution with KVM_RUN.
6. Finish the session with LIVEUPDATE_SESSION_FINISH. Preserved files that
   were not retrieved are freed.

A retrieve that fails for any other reason, e.g. because the new kernel does
not support a feature that the preserved state requires, fails permanently:
the preserved object is gone and later attempts return the same error.

Compatibility and plan
======================

The state preserved by all three handlers starts with the LUO feature header
(``struct luo_feature_hdr``). What an object needs from the new kernel is
expressed as required features, and the new kernel refuses to retrieve objects
that require features it does not implement, without affecting other objects.

Support grows in the following layered steps, each governed by explicit feature
flags:

1. The VM and guest_memfd of VMs without private memory.
2. vCPUs and the VM state a guest needs to continue running, preserved by the
   kernel across kexec so guest execution can resume directly with KVM_RUN.
3. Private guest_memfd memory and confidential VMs, with a separate feature per
   architecture (Intel TDX, AMD SEV-SNP, Arm CCA), so that each can be
   supported independently of the others.

Design Rationale and Core Architecture
======================================

Decoupled File Handlers and Explicit Retrieve Arguments
-------------------------------------------------------

``kvm-vm``, ``kvm-vcpu``, and ``guest_memfd`` are independent LUO file
handlers:

- Preserving a ``guest_memfd`` or ``kvm-vcpu`` takes no preserve-time user
  argument (``liveupdate_session_preserve_fd.arg == 0``) and does not store a
  weak ``struct file *`` reference or internal ``vm_token`` back-pointer in
  ``struct kvm``.
- At retrieve time in the new kernel, userspace passes the target ``vm_fd`` in
  ``liveupdate_session_retrieve_fd.arg`` via ``struct
  kvm_guest_memfd_luo_retrieve`` or ``struct kvm_vcpu_luo_retrieve``.
- This decoupling supports preserving a VM alone, preserving a ``guest_memfd``
  alone and binding it to a freshly created ``KVM_CREATE_VM`` instance after
  kexec, or preserving the full VM, vCPU, and ``guest_memfd`` set in any order.
- Early validation failures during retrieve (such as a missing ``retrieve_arg``,
  invalid ``vm_fd`` returning ``-EBADF``, wrong ``mm`` or dead VM returning
  ``-EIO``, VM kind mismatch returning ``-EINVAL``, or duplicate ``vcpu_id``
  returning ``-EEXIST``) set ``args->retryable = true`` so the KHO state is not
  consumed and userspace can retry. Re-retrieving an already-retrieved token
  with a non-zero ``arg`` returns ``-EBUSY``.

Why In-Kernel vCPU Preservation Is Required
-------------------------------------------

For confidential VMs (Intel TDX, AMD SEV-SNP, and Arm CCA Realms), KVM's
userspace register access ioctls (``KVM_GET_REGS``, ``KVM_SET_REGS``,
``KVM_GET_SREGS2``, ``KVM_GET_XSAVE2``, ``KVM_GET_ONE_REG``) return ``-EINVAL``
when ``vcpu->arch.guest_state_protected`` is set because the architectural
register state is encrypted inside hardware/firmware-owned control structures
(TDX ``TDVPR``/``TDCX``, SEV-SNP ``VMSA``, Arm CCA ``REC``). The ``kvm-vcpu``
handler preserves those encrypted control structures in place across kexec
alongside the host-visible vCPU state, while also providing a unified in-kernel
vCPU preservation path for non-CoCo VMs:

- On x86_64 non-CoCo VMs, ``kvm_luo_vcpu_x86_state`` restores vCPU state in a
  strict 12-step dependency order: ``cpuid`` -> ``virtual_tsc_khz`` ->
  ``sregs2`` -> ``xcrs`` -> ``xsave`` -> ``lapic`` -> ``msrs`` /
  ``l1_tsc_offset`` / ``pv_eoi`` / ``apf`` -> ``debugregs`` -> ``regs`` ->
  ``vcpu_events`` -> ``mp_state`` -> ``kvm_mmu_reset_context``, with deferred
  ``gfn_to_hva_cache`` generation invalidation so vCPUs can be retrieved before
  memslots are rebound.
- On arm64 non-CoCo VMs, ``kvm_luo_vm_arm64_state`` clears ``HAS_RAN_ONCE`` and
  ``KVM_ARCH_FLAG_FGU_INITIALIZED``, sets ``vgic.from_liveupdate = true`` so
  ``kvm_arch_vcpu_precreate()`` does not fail with ``-EBUSY`` when vCPUs are
  retrieved or created after ``vgic_init()``, and defers ``vgic.ready = true``
  until ``kvm_vgic_map_resources()`` on the first post-kexec ``KVM_RUN`` (which
  also executes ``kvm_arch_vcpu_run_pid_change()``).

Per-Inode Freeze and Zero-Touch Private Folios
----------------------------------------------

- **Per-inode freeze synchronization**: Instead of holding a global SRCU lock
  across ``fallocate()`` (which would allow one tenant to block live update
  across the host), ``guest_memfd`` uses per-inode freeze state synchronized
  with ``inode->i_mapping->invalidate_lock`` (``filemap_invalidate_lock``).
  While frozen, ``fallocate()``, ``FALLOC_FL_PUNCH_HOLE``, page faults on
  unallocated holes, and ``KVM_SET_MEMORY_ATTRIBUTES2`` return ``-EPERM``.
- **Zero-touch private folio preservation**: ``guest_memfd_luo.c`` zeroes only
  non-uptodate folios under ``folio_lock()`` during ``.preserve`` (which can
  only be newly ``fallocate()``d folios that have not yet passed through
  ``__kvm_gmem_get_pfn()``) and records ``folio_test_uptodate(folio)`` as
  ``KVM_GMEM_LUO_FOLIO_UPTODATE``. Uptodate folios are never touched in either
  the pre-kexec or post-kexec kernel, avoiding guest memory corruption or fatal
  hardware exceptions (machine check on Intel TDX due to ``X86_BUG_TDX_PW_MCE``,
  ``#PF(RMP)`` on AMD SEV-SNP, or a Granule Protection Fault on Arm CCA).
- **Maple-tree attribute range preservation**: Under
  ``KVM_GMEM_LUO_FEAT_PRIVATE``, non-default ``KVM_SET_MEMORY_ATTRIBUTES2``
  ranges in ``GMEM_I(inode)->attributes`` (including unallocated/unfaulted GFN
  ranges) are serialized into ``struct kvm_gmem_luo_attr_range`` entries in
  ``state->attr_ranges``.
- **Why Arm CCA live update requires guest_memfd**: There is no Arm CCA live
  update without ``guest_memfd``. In ``cca-host/v16``, Realm private memory
  (``RIPAS_RAM`` in Protected IPA space) is exclusively backed by
  ``guest_memfd`` (``KVM_MEM_GUEST_MEMFD`` memslots). Arm CCA Realm live update
  therefore consists of ``guest_memfd`` preservation (shared and private
  ``GRANULE_STATE_DATA`` folios kept in place without touching contents) plus
  Realm metadata preservation (``RD``, ``RECs``, Stage-2 ``RTTs``, and RMM
  SRO-donated granules) re-attached in the new kernel.

uAPI and KHO ABI Structure Reference
====================================

========================================  ======================================
Structure                                 Purpose and Key Fields
========================================  ======================================
``liveupdate_session_preserve_fd``        uAPI preserve ioctl argument (72B):
                                          ``size``, ``fd``, ``token``,
                                          ``handler[48]``, ``arg``.
``liveupdate_session_retrieve_fd``        uAPI retrieve ioctl argument (24B):
                                          ``size``, ``fd``, ``token``, ``arg``.
``kvm_guest_memfd_luo_retrieve``          uAPI retrieve argument for
                                          ``guest_memfd`` (8B): ``size``,
                                          ``vm_fd``.
``kvm_vcpu_luo_retrieve``                 uAPI retrieve argument for
                                          ``kvm-vcpu`` (8B): ``size``,
                                          ``vm_fd``.
``kvm_vm_luo_state``                      Top-level ``kvm-vm`` KHO state (144B):
                                          ``features`` (128B), ``type``,
                                          ``arch_state_pa``.
``kvm_vcpu_luo_state``                    Top-level ``kvm-vcpu`` KHO state
                                          (144B): ``features`` (128B),
                                          ``vcpu_id``, ``reserved``,
                                          ``arch_state_pa``.
``kvm_gmem_luo_state``                    Top-level ``guest_memfd`` KHO state
                                          (200B): ``features`` (128B), ``size``,
                                          ``flags``, ``nr_folios``, ``folios``,
                                          ``nr_attr_ranges``, ``attr_ranges``,
                                          ``vm_id``.
``kvm_gmem_luo_folio``                    Per-folio descriptor (16B): ``pfn:52``,
                                          ``flags:12``
                                          (``KVM_GMEM_LUO_FOLIO_UPTODATE``),
                                          ``index``.
``kvm_gmem_luo_attr_range``               Per-range memory attribute descriptor
                                          (32B): ``pgoff``, ``nr_pages``,
                                          ``attributes``, ``reserved``.
``kvm_luo_vm_x86_state``                  x86 VM arch state (51136B): clocks,
                                          PIC/IOAPIC/PIT, GSI routes, ``tdx``,
                                          ``snp``.
``kvm_luo_vcpu_x86_state``                x86 vCPU arch state (25080B): GPRs,
                                          sregs2, XSAVE, LAPIC, CPUID, MSRs,
                                          ``tdx``, ``snp``.
``kvm_luo_vm_arm64_state``                arm64 VM arch state (24680B): ID regs,
                                          timers, vGICv3 dist/redist/SPIs,
                                          SMCCC filter bitmaps, ``cca``.
``kvm_luo_vcpu_arm64_state``              arm64 vCPU arch state (20000B): GPRs,
                                          FP/SVE (``8768B``), ``nr_sys_regs`` and
                                          ``sys_regs`` (``struct
                                          kvm_luo_arm64_sys_reg``, 16B: ``id``,
                                          ``val``), vGICv3
                                          CPU-if/PPIs/``vgic_rd_base``, ``cca``.
``tdx_luo_flb_state``                     Global ``tdx-host`` FLB state (5416B):
                                          ``magic``, ``flags``, ``global_keyid``,
                                          ``nr_tdmrs``, ``tdmr_list_pa``,
                                          ``tdmr_list_order``, ``tdmr_sz``,
                                          ``max_tdmrs``, ``pamts[64]``,
                                          ``lp_init_bitmap``, ``active_hkids``.
``kvm_tdx_vm_luo_state``                  Per-TD VM state (208B): ``tdr_pfn``,
                                          ``tdcs_pfns[16]``, ``nr_tdcs_pages``,
                                          ``hkid``, ``tdx_state``,
                                          ``root_level``, ``attributes``,
                                          ``xfam``, ``tsc_offset``,
                                          ``tsc_multiplier``, ``nr_sept_pages``,
                                          ``sept_pages``
                                          (``struct kvm_tdx_luo_sept_page``).
``kvm_tdx_vcpu_luo_state``                Per-TD vCPU state (256B):
                                          ``tdr_pfn``, ``tdvpr_pfn``,
                                          ``tdcx_pfns[8]``,
                                          ``nr_tdcx_pages``, ``state``,
                                          ``exit_reason``,
                                          ``vp_enter_ret``, ``rcx``, ``rdx``,
                                          ``r8``..``r15``, ``rbx``, ``rdi``,
                                          ``rsi``, ``pi_pir[4]``,
                                          ``pi_control``, ``map_gpa_next``,
                                          ``map_gpa_end``.
``sev_snp_luo_flb_state``                 Global ``sev-snp`` FLB state (2104B):
                                          ``magic``, ``flags``, ``rmp_base``,
                                          ``rmp_end``, ``sev_es_tmr_pa``,
                                          ``sev_init_ex_pa``,
                                          ``hv_fixed_pa[64]``, ``iommus[16]``,
                                          ``active_asids``.
``amd_iommu_luo_state``                   Per-IOMMU preserved buffers (72B):
                                          ``pci_seg``, ``devid``,
                                          ``dev_table_size``, ``evt_buf_size``,
                                          ``ppr_log_size``, ``dev_table_pa``,
                                          ``cmd_buf_pa``, ``evt_buf_pa``,
                                          ``ppr_log_pa``, ``cmd_sem_pa``,
                                          ``ga_log_pa``, ``ga_log_tail_pa``.
``kvm_snp_vm_luo_state``                  Per-SNP VM state (32B): ``gctx_pfn``,
                                          ``asid``, ``flags``,
                                          ``ap_jump_table``, ``policy``.
``kvm_snp_vcpu_luo_state``                Per-SNP vCPU state (120B):
                                          ``vmsa_pfn``, ``vmsa_pa``,
                                          ``ghcb_gpa``, ``ghcb_registered_gpa``,
                                          ``snp_guest_vmsa_gpa``,
                                          ``snp_pending_vmsa_gpa``,
                                          ``sw_scratch``, ``apic_base``,
                                          ``cr0``, ``cr4``, ``efer``, ``flags``,
                                          ``ap_reset_hold_type``, ``int_state``,
                                          ``asid``, ``valid_bitmap[16]``.
``arm_rmm_luo_flb_state``                 Global ``arm-rmm`` FLB state (24B):
                                          ``count``, ``nr_pages``,
                                          ``entries_pa``
                                          (``rmi_sro_donated_entry``).
``kvm_arm64_cca_vm_luo_state``            Per-Realm VM state (48B): ``rd_phys``,
                                          ``pgd_phys``, ``pgd_pages``,
                                          ``ia_bits``, ``realm_state``,
                                          ``nr_rtt_pages``, ``rtt_pfns``
                                          (``kho_vmalloc``).
``kvm_arm64_cca_rec_luo_state``           Per-REC vCPU state (64B): ``mpidr``,
                                          ``rec_phys``, ``run_phys``,
                                          ``fault_esr_el2``, ``fault_far_el2``,
                                          ``fault_hpfar_el2``, ``flags``,
                                          ``rd_phys``.
========================================  ======================================

Confidential Computing Architecture Analysis (A--F)
===================================================

(A) Firmware and Module Lifecycle Across Kexec
----------------------------------------------

- **Intel TDX**: Calling ``TDH.SYS.INIT`` again after kexec is impossible
  without destroying active TDs because ``TDH.SYS.INIT`` is valid only in
  ``SYSINIT_PENDING`` (returning ``TDX_SYS_INIT_NOT_PENDING`` in ``SYS_READY``)
  and ``TDH.SYS.DISABLE`` zeroes all TD private and control pages. However,
  re-initialization is unnecessary: the TDX module in SEAMRR and MKTME key
  tables survive kexec when ``tdx_shutdown()`` skips ``tdx_sys_disable()``
  (gated by ``liveupdate_coco_is_preserving()``). In the new kernel, after
  ``VMXON``, ``tdx_cpu_enable()`` treats ``TDX_SYS_LP_INIT_NOT_PENDING``
  (``0xC000050B00000000ULL``) and ``TDX_SYS_LP_INIT_DONE``
  (``0xC000050300000000ULL``) from ``TDH.SYS.LP.INIT`` as success, and
  ``init_tdx_module()`` adopts the running module from the ``tdx-host`` FLB
  (``struct tdx_luo_flb_state``) using read-only ``TDH.SYS.RD*`` calls while
  skipping ``TDH.SYS.CONFIG``, ``TDH.SYS.KEY.CONFIG``, and ``TDH.SYS.TDMR.INIT``.
- **AMD SEV-SNP**: Calling ``SEV_CMD_SNP_INIT_EX`` after kexec is impossible
  without destroying active guests because ``SNP_INIT_EX`` requires the PSP to
  be in ``UNINIT`` (returning ``INVALID_PLATFORM_STATE`` in ``INIT``), while
  ``SEV_CMD_SNP_SHUTDOWN_EX`` clears memory-controller encryption keys. When
  ``liveupdate_coco_is_preserving()`` is true, ``sev_firmware_shutdown()`` skips
  ``SNP_SHUTDOWN_EX`` and ``disable_iommus()`` leaves AMD IOMMU SNP enforcement
  enabled. In the new kernel, ``sev_pci_init()`` and ``__sev_snp_init_locked()``
  adopt the live PSP ``INIT`` state from the ``sev-snp`` FLB (``struct
  sev_snp_luo_flb_state``) without issuing ``SNP_INIT_EX``.
- **Arm CCA Realms**: The Arm RMM (in Realm PAS at R-EL2) and TF-A GPT (in Root
  PAS at EL3) persist across non-secure EL2 kexec; PSCI ``CPU_OFF``/``CPU_ON``
  runs only per-CPU ``rmm_warmboot_main()``. Because ``SMC_RMI_RMM_CONFIG_SET``
  and ``SMC_RMI_RMM_ACTIVATE`` return ``RMI_ERROR_GLOBAL`` when the RMM is
  already in ``RMM_STATE_ACTIVE``, ``rmi_configure()`` in
  ``drivers/firmware/arm_rmm/rmi.c`` handles ``RMI_ERROR_GLOBAL`` by
  querying ``rmi_rmm_config_get(virt_to_phys(config))``
  (``SMC_RMI_RMM_CONFIG_GET``), verifying
  ``config->rmi_granule_size == granule_size`` (``RMI_GRANULE_SIZE_4KB``) and
  ``config->tracking_region_size == 0``, and skipping ``rmi_rmm_activate()`` on
  an already-active RMM after ``arm64_init_rmi()`` KHO-restores incoming
  SRO-donated pages via ``arm_rmm_kho_restore_incoming()``.
  The SRO Donation Ledger in ``drivers/firmware/arm_rmm/rmi.c`` tracks all
  pages donated via ``SMC_RMI_OP_MEM_DONATE`` (``RMM_ACTIVATE``,
  ``GPT_L1_CREATE``, ``RD_AUX``, ``REC_AUX``) and preserves/restores them via
  the ``arm-rmm`` KHO subtree registered by ``arm_rmm_kho_init()``
  (``struct arm_rmm_luo_flb_state`` and ``struct rmi_sro_donated_entry``).

(B) Memory Metadata and Encryption Key Persistence
--------------------------------------------------

- **Intel TDX**: The ``tdx-host`` FLB preserves ``tdx_tdmr_list``, all
  ``1G``/``2M``/``4K`` PAMT physical page ranges (via ``kho_preserve_pages``),
  ``tdx_global_keyid``, and ``active_hkids`` in ``struct tdx_luo_flb_state``.
  Per-TD guest HKIDs remain programmed in MKTME hardware and are reserved in
  ``tdx_guest_keyid_pool`` during module adoption via ``active_hkids``.
- **AMD SEV-SNP**: The BIOS-reserved RMP table persists in place and
  ``snp_prepare()`` skips ``clear_rmp()``. To prevent host ``#PF(RMP)``
  page-size mismatch faults when the new kernel's direct map maps a 2MB region
  containing a preserved 4KB ``Assigned=1`` RMP entry,
  ``snp_rmptable_luo_early_init()`` and ``snp_quarantine_rmp_2m_regions()``
  scan ``rmptable`` on adopted boot and split any affected 2MB direct-map PMD
  into 4KB PTEs via ``set_memory_4k()``. Because SNP enforcement locks AMD
  IOMMU MMIO base registers (AMD IOMMU Spec sec 2.12.2.1), ``amd_iommu_luo_state``
  preserves and adopts ``dev_table``, ``cmd_buf``, ``evt_buf``, ``ppr_log``,
  ``cmd_sem``, ``ga_log``, and ``ga_log_tail`` (along with ``dev_table_size``,
  ``evt_buf_size``, and ``ppr_log_size``) at their existing physical addresses.
- **Arm CCA Realms**: Root-PAS GPT entries and RMM granule tracking metadata
  persist untouched. Every Realm-PAS granule (``RD``, ``REC``, ``RTT``, ``DATA``,
  and SRO-donated ``RD_AUX``/``REC_AUX``/``L1_GPT``) is KHO-preserved so the
  new kernel's page allocator never hands out a Realm-PAS page to NS software
  (which would trigger a fatal Granule Protection Fault).

(C) Per-VM Control Structure Preservation
-----------------------------------------

- **Intel TDX**: ``struct kvm_tdx_vm_luo_state`` preserves the 4KB ``TDR`` page
  (``tdr_pfn``) and ``TDCS`` pages (``tdcs_pfns[]``) via ``kho_preserve_folio``,
  along with ``hkid``, ``tdx_state`` (``TD_STATE_RUNNABLE``), ``root_level``,
  ``attributes``, ``xfam``, ``tsc_offset``, and ``tsc_multiplier``.
- **AMD SEV-SNP**: ``struct kvm_snp_vm_luo_state`` preserves the 4KB PSP guest
  context page (``gctx_pfn``, ``sev->snp_context``), ``asid`` (reserved in
  ``sev_asid_bitmap``), ``flags``, ``ap_jump_table``, and ``policy``,
  and allocates fresh ``guest_req_buf``/``guest_resp_buf`` bounce pages on
  retrieve.
- **Arm CCA Realms**: ``struct kvm_arm64_cca_vm_luo_state`` preserves the 4KB
  Realm Descriptor (``rd_phys``, ``GRANULE_STATE_RD``), the Stage-2 root PGD
  pages (``pgd_phys``, ``pgd_pages``), ``ia_bits``, ``realm_state``
  (``REALM_STATE_ACTIVE``), and the non-root RTT page array (``rtt_pfns``).

(D) Per-vCPU Control Structure Preservation
-------------------------------------------

- **Intel TDX**: ``struct kvm_tdx_vcpu_luo_state`` preserves ``tdvpr_pfn`` and
  ``tdcx_pfns[]`` along with in-flight hypercall/exit state (``vp_enter_ret``,
  ``rcx``, ``rdx``, ``r8``, ``r9``, ``map_gpa_next``, ``map_gpa_end``). At
  ``.freeze``, ``tdx_flush_vp_on_cpu()`` executes ``TDH.VP.FLUSH`` to
  disassociate ``TDVPR`` from its physical LP (``vcpu->cpu = -1``). On the first
  ``tdx_vcpu_load()`` after retrieve, ``vcpu->cpu != cpu`` re-associates the VP
  and rewrites ``POSTED_INTR_DESC_ADDR`` and ``HOST_RSP`` in ``TDVPR`` via
  ``td_vmcs_write64()`` (``TDH.VP.WR``).
- **AMD SEV-SNP**: ``struct kvm_snp_vcpu_luo_state`` preserves both the
  KVM-allocated ``vmsa_pfn`` (``svm->sev_es.vmsa``) and the active ``vmsa_pa``
  (supporting both BSP VMSA and ``guest_memfd``-backed AP VMSAs created via
  ``SVM_VMGEXIT_AP_CREATION`` where ``snp_has_guest_vmsa`` is true), plus GHCB
  and host-tracked control register (``apic_base``, ``cr0``, ``cr4``, ``efer``,
  ``int_state``) state. At ``.freeze``,
  ``wbinvd_on_all_cpus()`` flushes dirty encrypted VMSA cachelines.
- **Arm CCA Realms**: ``struct kvm_arm64_cca_rec_luo_state`` preserves
  ``rec_phys`` (in Realm PAS, never touched by NS CPU) and ``run_phys`` (in NS
  PAS, preserving ``struct rec_run`` entry/exit state verbatim), plus ``mpidr``,
  ``fault_esr_el2``, ``fault_far_el2``, ``fault_hpfar_el2``, and
  ``KVM_ARM64_CCA_REC_F_REQ_RMI`` (restoring ``KVM_REQ_RMI`` so
  ``kvm_rec_pre_enter()`` completes pending RMI exits on the first ``KVM_RUN``).

(E) Stage-2 / Nested / Secure-EPT Reconstruction
------------------------------------------------

- **Intel TDX**: SEAM S-EPT pages store physical addresses (HPAs); virtual
  pointers exist only in KVM's software mirror TDP MMU (``sp->spt`` and
  ``sp->external_spt``). ``kvm_tdp_mmu_luo_preserve_mirror()`` KHO-preserves
  both ``sp->spt`` and ``sp->external_spt`` (with ``external_spt == 0`` for the
  root because the S-EPT root resides inside ``TDCS``) into ``struct
  kvm_tdx_luo_sept_page`` descriptors. On retrieve,
  ``kvm_tdp_mmu_luo_retrieve_mirror()`` reconstructs the mirror tree into
  ``kvm->arch.tdp_mmu_roots`` without issuing ``TDH.MEM.SEPT.ADD`` or
  ``TDH.MEM.PAGE.AUG``, and verifies each entry via ``tdh_mem_sept_rd()``
  (``TDH.MEM.SEPT.RD``). Shared EPT is rebuilt lazily on EPT violations.
- **AMD SEV-SNP**: Nested Page Tables (NPT) are ordinary hypervisor pages not
  owned by PSP firmware, while RMP entries retain ``(ASID, GPA, Assigned=1,
  Validated=1)``. Zero NPT pages are preserved across kexec; instead, NPT is
  reconstructed lazily on ``#NPF``. ``sev_gmem_make_private()`` checks
  ``snp_lookup_rmpentry()`` and returns ``0`` idempotently when ``assigned`` is
  already true (and ``rmp_level >= level``), installing the NPT PTE without
  re-running ``RMPUPDATE`` or causing guest ``#VC`` exceptions.
- **Arm CCA Realms**: Stage-2 Realm Translation Tables (``GRANULE_STATE_RTT``)
  are owned by the RMM in Realm PAS. Non-root RTTs are tracked in
  ``realm->rtt_list`` and ``realm->nr_rtt_pages`` (updated in
  ``realm_rtt_create()``, ``realm_rtt_fold()``, and ``realm_rtt_destroy()``).
  At ``.freeze``, ``realm_unmap_shared_range()`` walks the unprotected IPA half
  and unmaps NS shared IPA mappings via ``rmi_rtt_unprot_unmap()`` so they
  refault cleanly after kexec, while protected IPA mappings and ``DATA``
  granules remain intact in the RMM. On retrieve, ``pgd_phys`` and
  ``rtt_list`` pages (via ``rtt_pfns``) are KHO-restored into
  ``kvm->arch.mmu`` and ``realm->rtt_list``, and ``realm_map_protected()``
  returns ``0`` early when ``rmi_delegate_range()`` observes an already-delegated
  preserved ``DATA`` granule (``delegated_phys == phys``).

(F) Quiescence, Abort/Cancel, and Unretrieved Teardown
------------------------------------------------------

- **Quiescence and Pre-Kexec Cancel**: ``.preserve`` and ``.freeze`` require all
  vCPUs to be outside ``KVM_RUN`` (``mutex_trylock(&vcpu->mutex)``). If the LUO
  session is closed before kexec, ``.unpreserve`` unfreezes ``guest_memfd`` and
  unpreserves KHO allocations without modifying SEAM, PSP, or RMM state.
- **Unretrieved Post-Kexec Teardown (``.finish`` when not retrieved)**:
  - **TDX**: vCPU ``.finish`` reclaims ``TDVPR``/``TDCX`` via
    ``tdx_luo_reclaim_or_defer_ctrl_page()``; VM ``.finish`` runs
    ``TDH.MNG.VPFLUSHDONE`` -> ``TDH.PHYMEM.CACHE.WB`` ->
    ``TDH.MNG.KEY.FREEID``, reclaims all ``external_spt``, ``TDCS``, and
    ``TDR`` pages, frees ``spt`` pages, and frees ``hkid``; ``guest_memfd``
    ``.finish`` reclaims private folios via ``kvm_arch_gmem_reclaim()``.
  - **SEV-SNP**: vCPU ``.finish`` transitions ``vmsa_pfn`` to shared via
    ``rmp_make_shared()`` and frees the folio; VM ``.finish`` runs
    ``SEV_CMD_SNP_DECOMMISSION`` + ``SEV_CMD_SNP_DF_FLUSH``, frees the
    ``gctx`` firmware page, and keeps ``asid`` reserved in ``sev_asid_bitmap``
    (because decoupled ``guest_memfd`` or ``kvm-vcpu`` files may still hold
    RMP entries assigned to that ASID); ``guest_memfd`` ``.finish``
    transitions private folios to shared via ``kvm_arch_gmem_reclaim()``.
  - **Arm CCA**: vCPU ``.finish`` (``kvm_realm_rec_luo_finish()``) runs
    ``rmi_rec_destroy(rec_phys, sro)`` (reclaiming and freeing ``REC_AUX`` SRO
    pages), undelegates ``rec_phys``, and frees ``rec_page`` and ``run_page``;
    VM ``.finish`` (``kvm_realm_luo_finish()``) runs
    ``realm_unmap_private_abandoned()`` (unmapping and undelegating assigned
    private data granules via ``rmi_rtt_data_unmap()``), calls
    ``rmi_realm_terminate(rd_phys, sro)``, runs ``realm_tear_down_rtt_range()``
    to destroy and free non-root RTTs, calls ``rmi_realm_destroy(rd_phys, sro)``
    (reclaiming and freeing ``RD_AUX`` SRO pages), and undelegates/frees
    ``rd_phys`` and ``pgd_phys``; ``guest_memfd`` ``.finish`` undelegates
    private ``DATA`` folios via ``kvm_arch_gmem_reclaim()``.

Architectural and Firmware Assumptions
======================================

- **Intel TDX (AT1--AT19)**: (AT1) kexec does not reset SEAMRR, the TDX module,
  P-SEAMLDR, or MKTME key tables; (AT2) TDX module stays in ``SYS_READY`` across
  kexec when ``TDH.SYS.DISABLE``/``SHUTDOWN`` are skipped; (AT3) SEAMCALLs work
  after the new kernel executes ``VMXON`` on each LP; (AT4) per-LP module state
  survives AP ``INIT``/``SIPI`` when all vCPUs were ``TDH.VP.FLUSH``ed before
  ``VMXOFF``; (AT5) ``TDH.SYS.LP.INIT`` on an already-initialized LP returns
  ``TDX_SYS_LP_INIT_NOT_PENDING`` / ``TDX_SYS_LP_INIT_DONE`` without side
  effects; (AT6) all LPs were initialized by the old kernel and the new kernel
  boots with the same online CPU set; (AT7) the same TDX module binary remains
  active across kexec; (AT8) PAMT, ``TDR``/``TDCS``/``TDVPR``/``TDCX``, S-EPT,
  and private pages are not modified between preserve and adopt; (AT9) the new
  kernel never writes TD private memory with KeyID 0 (avoiding
  ``X86_BUG_TDX_PW_MCE``); (AT10) ``WBINVD`` during kexec writes back dirty
  private cachelines with their HKIDs intact; (AT11) the new kernel's memory
  map is covered by the preserved TDMRs; (AT12) ``tdx_global_keyid`` and HKID
  partitioning MSRs are unchanged across kexec; (AT13)
  ``POSTED_INTR_DESC_ADDR`` is writable via ``TDH.VP.WR`` on ``vcpu_load``;
  (AT14) host TSC is not reset across kexec; (AT15) private S-EPT leaf mappings
  are 4KB (with ``level`` carried in ``kvm_tdx_luo_sept_page``); (AT16) only
  finalized (``TD_STATE_RUNNABLE``) TDs are preserved; (AT17) global SEAMCALLs
  are idle at freeze; (AT18) TDX Connect and L2 TD partitioning are not active;
  (AT19) the S-EPT root page resides inside ``TDCS``.
- **AMD SEV-SNP (AS1--AS14)**: (AS1) kexec does not reset the PSP and SNP stays
  in ``INIT`` with memory-controller keys intact; (AS2) ``SYSCFG.SNPEn``,
  ``VMPLEn``, ``MFDM``, and ``RMP_BASE``/``RMP_END`` persist on all cores;
  (AS3) the BIOS-reserved RMP table is not cleared by the new kernel; (AS4) the
  new kernel never writes to SNP-assigned/firmware pages and splits mixed 2MB
  direct-map PMDs via ``set_memory_4k()`` before use; (AS5) AMD IOMMU buffers
  and device tables are adopted in place with no DMA in flight to preserved
  pages; (AS6) SNP firmware >= 1.53 remains at the same version across kexec;
  (AS7) legacy SEV state does not conflict with adopted SNP state; (AS8)
  ``WBINVD`` and ``SNP_DF_FLUSH`` are safe with active SNP guests; (AS9) ASID
  partitioning is identical across kexec; (AS10) ``guest_memfd`` GFN-to-PFN
  bindings are recreated at identical GPA offsets so RMP ``GPA`` entries match
  the new NPT; (AS11) no ``SNP_GUEST_REQUEST`` is in flight at freeze and GHCB
  state is quiescent; (AS12) host TSC remains continuous across kexec; (AS13)
  SEV-TIO is not enabled; (AS14) ``HV_Fixed`` pages remain reserved across
  kexec.
- **Common KHO/LUO (AB1--AB5)**: (AB1) ``liveupdate_reboot()`` runs before
  ``device_shutdown()`` and ``syscore_shutdown()``; (AB2) incoming LUO/FLB data
  is available before subsystem/driver init; (AB3) ``kexec_file_load`` with KHO
  places kexec segments only in KHO scratch memory; (AB4) the VMM quiesces
  vCPUs before freeze; (AB5) panic/kdump paths continue to perform full
  destructive teardown.
- **Arm CCA Realms (AA1--AA13)**: (AA1) the new kernel uses the same
  ``PAGE_SIZE`` matching the RMM's configured ``rmi_granule_size``; (AA2) the
  new kernel runs in VHE mode with a compatible ``arm_rmm``/KVM RMI ABI
  (v2.0); (AA3) TF-A EL3 does not reset the GPT or RMM across PSCI
  ``CPU_OFF``/``CPU_ON``; (AA4) no Stateful RMI Operation (SRO) or
  ``RMI_REC_ENTER`` is in flight at freeze; (AA5) ``guest_memfd``, ``RD``,
  ``REC``, ``RTT``, and SRO-donated pages are unmovable and outside KHO scratch
  regions; (AA6) no NS code in the new kernel accesses Realm-PAS pages; (AA7)
  the RMM preserves the RTT tree addressed by ``rd_phys``; (AA8) Realm
  measurements and attestation state are unaffected by host kexec; (AA9) the
  guest Realm kernel requires no live-update modifications; (AA10) Realm device
  assignment (``PDEV``/``VDEV``) and auxiliary planes are not enabled; (AA11)
  the architected counter ``CNTVCT_EL0`` is monotonic across kexec; (AA12)
  in-kernel vGICv3 and timer state are preserved via
  ``kvm_luo_vm_arm64_state``/``kvm_luo_vcpu_arm64_state``; (AA13) physical
  memory layout is unchanged across kexec.

Interfaces
==========

.. kernel-doc:: virt/kvm/kvm_luo.c
   :doc: KVM VM live update

.. kernel-doc:: virt/kvm/guest_memfd_luo.c
   :doc: guest_memfd live update

.. kernel-doc:: include/linux/kho/abi/kvm.h
   :doc: KVM VM live update ABI

.. kernel-doc:: include/linux/kho/abi/kvm.h
   :doc: guest_memfd live update ABI

.. kernel-doc:: include/linux/kho/abi/kvm.h
   :doc: KVM vCPU live update ABI

.. kernel-doc:: include/linux/kho/abi/kvm.h
   :internal:

See also
========

- Documentation/userspace-api/liveupdate.rst
- Documentation/core-api/liveupdate.rst
