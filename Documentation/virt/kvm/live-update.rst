.. SPDX-License-Identifier: GPL-2.0

=================================
Live update of KVM guests (LUO)
=================================

A live update replaces the running kernel with a new one through kexec, while
selected resources are handed over to the new kernel intact. The Live Update
Orchestrator (LUO, see Documentation/userspace-api/liveupdate.rst) lets
userspace preserve file descriptors in sessions before the reboot and retrieve
them afterwards. KVM provides two LUO file handlers, so that a VMM can keep a
guest and its memory across a live update instead of restarting it:

``kvm-vm``
  Preserves a VM file descriptor. The new kernel creates an equivalent VM.

``guest_memfd``
  Preserves a guest_memfd file descriptor and the guest memory in it. The new
  kernel creates a guest_memfd with the same memory.

The two are independent. A VMM can preserve the VM only, a guest_memfd only,
or both. A guest_memfd is bound to a VM in the new kernel through an explicit
argument when it is retrieved, so the VM can be the preserved one or a new
one.

Preserved state
===============

================================  ==============================================
Object                            Carried over
================================  ==============================================
VM (``kvm-vm``)                   The machine type passed to KVM_CREATE_VM.
guest_memfd (``guest_memfd``)     The size, the flags passed to
                                  KVM_CREATE_GUEST_MEMFD, and all memory that is
                                  allocated in it.
================================  ==============================================

Everything else is set up again by the VMM in the new kernel, as it is for a
new VM: vCPUs and their registers, memory slots and their binding to
guest_memfd, user mappings of guest_memfd, NUMA memory policies, memory
attributes, interrupt controllers, devices and capabilities. Guest memory that
is not in a guest_memfd is preserved by preserving the file that backs it,
e.g. a memfd.

Which objects can be preserved depends on the architecture and on the kind of
VM. For now, VMs with private or encrypted memory or with protected guest
state cannot be preserved, nor can guest_memfd of VMs with private memory.
They are refused with -EOPNOTSUPP.

VMM flow
========

Before the reboot:

1. Allocate all memory the guest is going to use in each guest_memfd, e.g.
   with fallocate().
2. Create a session on ``/dev/liveupdate`` and preserve the guest_memfd and,
   if wanted, the VM with LIVEUPDATE_SESSION_PRESERVE_FD. The handler name may
   be given in ``handler``, the ``arg`` field must be zero. The order does not
   matter.
3. Stop running vCPUs.
4. Keep the session open and reboot into the new kernel with kexec.

From the moment a guest_memfd is preserved, it is frozen: memory can neither
be allocated in it nor freed from it. fallocate() and PUNCH_HOLE fail with
-EPERM when they would allocate or free memory, touching a hole through a user
mapping raises SIGBUS, and a guest access to a hole fails like any other
failure to allocate guest memory. Memory that is present stays accessible to
the guest and to userspace, and the VM keeps running until the VMM stops it.
Closing the session before the reboot cancels the preservation of all files
in it, which unfreezes the guest_memfd. The VMs and guest_memfd themselves are
not affected by cancelling.

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
4. Create memory slots with KVM_SET_USER_MEMORY_REGION2 at the same guest
   physical addresses and guest_memfd offsets as before, map the guest_memfd
   into userspace where needed, and recreate vCPUs and the rest of the VM.
5. Finish the session with LIVEUPDATE_SESSION_FINISH. Preserved files that
   were not retrieved are freed.

A retrieve that fails for any other reason, e.g. because the new kernel does
not support a feature that the preserved state requires, fails permanently:
the preserved object is gone and later attempts return the same error.

Compatibility and plan
======================

The state preserved by both handlers starts with the LUO feature header. What
an object needs from the new kernel is expressed as required features, and the
new kernel refuses to retrieve objects that require features it does not
implement, without affecting other objects.

Support is planned to grow in the following steps, each one adding features:

1. The VM and guest_memfd of VMs without private memory, described here.
2. vCPUs and the VM state a guest needs to continue running, preserved by the
   kernel because confidential VMs cannot hand it to userspace.
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
   :internal:

See also
========

- Documentation/userspace-api/liveupdate.rst
- Documentation/core-api/liveupdate.rst
