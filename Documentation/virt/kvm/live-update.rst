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
                                  KVM_CREATE_GUEST_MEMFD, and all memory that is
                                  allocated in it.
================================  ==============================================

Memory slots and their binding to guest_memfd, user mappings of guest_memfd
and ``kvm_run``, NUMA memory policies, and memory attributes are set up again
by the VMM in the new kernel before resuming vCPU execution. Guest memory that
is not in a guest_memfd is preserved by preserving the file that backs it,
e.g. a memfd.

Which objects can be preserved depends on the architecture and on the kind of
VM. For now, VMs with private or encrypted memory or with protected guest
state cannot be preserved, nor can vCPUs or guest_memfd of VMs with private
memory. They are refused with -EOPNOTSUPP.

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
be allocated in it nor freed from it. fallocate() and PUNCH_HOLE fail with
-EPERM when they would allocate or free memory, touching a hole through a user
mapping raises SIGBUS, and a guest access to a hole fails like any other
failure to allocate guest memory. Memory that is present stays accessible to
the guest and to userspace, and if the guest_memfd and VM are preserved before
stopping the guest, the VM keeps running until the VMM stops its vCPUs to
preserve their vCPU fds. Closing the session before the reboot cancels the
preservation of all files in it, which unfreezes the guest_memfd. The VMs,
vCPUs, and guest_memfd themselves are not affected by cancelling.

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

The state preserved by all three handlers starts with the LUO feature header.
What an object needs from the new kernel is expressed as required features, and
the new kernel refuses to retrieve objects that require features it does not
implement, without affecting other objects.

Support is planned to grow in the following steps, each one adding features:

1. The VM and guest_memfd of VMs without private memory.
2. vCPUs and the VM state a guest needs to continue running, preserved by the
   kernel across kexec so guest execution can resume directly with KVM_RUN.
3. Private guest_memfd memory and confidential VMs, with a separate feature per
   architecture (Intel TDX, AMD SEV-SNP, Arm CCA), so that each can be
   supported independently of the others.

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
