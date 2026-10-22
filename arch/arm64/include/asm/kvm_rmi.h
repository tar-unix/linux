/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#ifndef __ASM_KVM_RMI_H
#define __ASM_KVM_RMI_H

#include <asm/kvm_pgtable.h>
#include <linux/arm-smccc-rmi.h>

/**
 * enum realm_state - State of a Realm
 *
 * Mirrors the RMM's Realm lifecycle states where they are meaningful to KVM,
 * with REALM_STATE_DYING being a KVM-internal state used to prevent further
 * requests while teardown is in progress. KVM does not track REALM_SYSTEM_OFF
 * or REALM_ZOMBIE separately as they naturally lead to teardown.
 */
enum realm_state {
	/**
	 * @REALM_STATE_NONE:
	 *      Realm has not yet been created. rmi_realm_create() has not
	 *      yet been called.
	 */
	REALM_STATE_NONE,
	/**
	 * @REALM_STATE_NEW:
	 *      Realm is under construction, rmi_realm_create() has been
	 *      called, but it is not yet activated. Pages may be populated.
	 */
	REALM_STATE_NEW,
	/**
	 * @REALM_STATE_ACTIVE:
	 *      Realm has been created and is eligible for execution with
	 *      rmi_rec_enter(). Pages may no longer be populated with
	 *      rmi_data_create().
	 */
	REALM_STATE_ACTIVE,
	/**
	 * @REALM_STATE_DYING:
	 *      Realm is in the process of being destroyed or has already been
	 *      destroyed.
	 */
	REALM_STATE_DYING,
	/**
	 * @REALM_STATE_DEAD:
	 *      Realm has been destroyed.
	 */
	REALM_STATE_DEAD
};

/**
 * struct realm - Additional per VM data for a Realm
 *
 * @rd: Kernel mapping of the RMM-managed Realm Descriptor (RD) granule
 * @sro: Preallocated SRO state context for Realm MMU operations
 * @state: The lifetime state machine for the realm
 * @ia_bits: Number of valid Input Address bits in the IPA
 * @stage2_unmapped: The Realm stage-2 mappings have been removed
 * @rtts_destroyed: The non-root RTTs have been torn down
 * @luo_preserved: Realm is preserved in an active live update session
 * @luo_frozen: Stage-2 RTTs are frozen for live update handover
 * @luo_retrieved: Realm was retrieved from a live update session
 * @luo_pfns: Preserved vmalloc array of RTT/DATA PFNs during live update freeze
 * @luo_data_pages: Delegated DATA granules of this Realm (by pfn), recorded
 *		    at freeze so the next kernel keeps them out of the allocator
 * @rtt_list: List of non-root RTT struct pages (linked via page->lru)
 * @rtt_lock: Spinlock protecting @rtt_list and @nr_rtt_pages
 * @nr_rtt_pages: Number of active non-root RTT pages in @rtt_list
 */
struct realm {
	void *rd;
	/*
	 * Reused by RTT map/unmap SRO commands. Those commands are only
	 * issued from Realm stage-2 map/unmap paths while kvm->mmu_lock is
	 * held for write, including Realm fault handling where
	 * kvm_fault_lock() takes the write side, so concurrent use is
	 * serialized.
	 */
	struct rmi_sro_state *sro;
	enum realm_state state;
	unsigned int ia_bits;
	bool stage2_unmapped;
	bool rtts_destroyed;
	bool luo_preserved;
	bool luo_frozen;
	bool luo_retrieved;
	u64 *luo_pfns;
	struct xarray luo_data_pages;
	struct list_head rtt_list;
	/* Protects rtt_list and nr_rtt_pages */
	spinlock_t rtt_lock;
	unsigned long nr_rtt_pages;
};

/**
 * struct realm_rec - Additional per VCPU data for a Realm
 *
 * @mpidr: MPIDR (Multiprocessor Affinity Register) value to identify this VCPU
 * @rec_page: Kernel VA of the RMM's private page for this REC
 * @rec_phys: Physical address of @rec_page
 * @run: Kernel VA of the RmiRecRun structure shared with the RMM
 * @run_phys: Physical address of @run
 * @sro: A preallocated SRO state context
 * @luo_preserved: REC is preserved in an active live update session
 */
struct realm_rec {
	unsigned long mpidr;
	void *rec_page;
	phys_addr_t rec_phys;
	struct rec_run *run;
	phys_addr_t run_phys;
	struct rmi_sro_state *sro;
	bool luo_preserved;
};

void kvm_init_rmi(void);
u32 kvm_rmm_ipa_limit(void);
unsigned int kvm_realm_sve_max_vl(void);

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val);

bool kvm_rmi_supports_sve(void);

int kvm_init_realm(struct kvm *kvm);
int kvm_realm_luo_reserve_data(struct kvm *kvm, kvm_pfn_t pfn);
void kvm_realm_luo_release_data(struct kvm *kvm, kvm_pfn_t pfn);
int kvm_activate_realm(struct kvm *kvm);
void kvm_destroy_realm(struct kvm *kvm);
int kvm_realm_teardown_stage2(struct kvm *kvm);
void kvm_destroy_rec(struct kvm_vcpu *vcpu);

struct kvm_arm64_cca_vm_luo_state;
struct kvm_arm64_cca_rec_luo_state;

int kvm_realm_luo_preserve(struct kvm *kvm,
			   struct kvm_arm64_cca_vm_luo_state *cca);
int kvm_realm_luo_freeze(struct kvm *kvm,
			 struct kvm_arm64_cca_vm_luo_state *cca);
void kvm_realm_luo_unfreeze(struct kvm *kvm,
			    struct kvm_arm64_cca_vm_luo_state *cca);
void kvm_realm_luo_unpreserve(struct kvm *kvm,
			      struct kvm_arm64_cca_vm_luo_state *cca);
int kvm_realm_luo_retrieve(struct kvm *kvm,
			   struct kvm_arm64_cca_vm_luo_state *cca);
void kvm_realm_luo_finish(struct kvm *kvm,
			  struct kvm_arm64_cca_vm_luo_state *cca);

int kvm_realm_rec_luo_preserve(struct kvm_vcpu *vcpu,
			       struct kvm_arm64_cca_rec_luo_state *cca);
int kvm_realm_rec_luo_freeze(struct kvm_vcpu *vcpu,
			     struct kvm_arm64_cca_rec_luo_state *cca);
void kvm_realm_rec_luo_unpreserve(struct kvm_vcpu *vcpu,
				  struct kvm_arm64_cca_rec_luo_state *cca);
int kvm_realm_rec_luo_retrieve(struct kvm_vcpu *vcpu,
			       struct kvm_arm64_cca_rec_luo_state *cca);
void kvm_realm_rec_luo_finish(struct kvm_vcpu *vcpu,
			      struct kvm_arm64_cca_rec_luo_state *cca);

int kvm_rec_enter(struct kvm_vcpu *vcpu);
int kvm_rec_exit(struct kvm_vcpu *vcpu, int rec_run_status);
int kvm_rec_handle_request(struct kvm_vcpu *vcpu);
bool kvm_rec_handle_hvc(struct kvm_vcpu *vcpu, int *ret);

struct kvm_arm_rmi_populate;

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *arg);
void kvm_realm_unmap_range(struct kvm *kvm,
			   unsigned long ipa,
			   unsigned long size,
			   bool unmap_private,
			   bool may_block);
int realm_map_ipa(struct kvm *kvm, phys_addr_t ipa,
		  kvm_pfn_t pfn, unsigned long map_size,
		  enum kvm_pgtable_prot prot,
		  struct kvm_mmu_memory_cache *memcache);

int realm_psci_complete(struct kvm_vcpu *source, unsigned long status);

static inline bool kvm_realm_is_private_address(struct realm *realm,
						unsigned long addr)
{
	return !(addr & BIT(realm->ia_bits - 1));
}

#endif /* __ASM_KVM_RMI_H */
