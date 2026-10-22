// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2023-2026 ARM Ltd.
 */

#include <uapi/linux/psci.h>
#include <linux/cleanup.h>
#include <linux/kexec_handover.h>
#include <linux/kho/abi/kvm.h>
#include <linux/kvm_host.h>
#include <linux/vmalloc.h>
#include <linux/xarray.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/rmi_cmds.h>
#include <asm/virt.h>

static inline unsigned long rmi_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return PAGE_SIZE;

	return (1UL << ARM64_HW_PGTABLE_LEVEL_SHIFT(level));
}

static bool rmi_has_feature(int reg, unsigned long feature)
{
	return !!u64_get_bits(rmi_feat_reg(reg), feature);
}

bool kvm_rmi_supports_sve(void)
{
	return rmi_has_feature(0, RMI_FEATURE_REGISTER_0_SVE);
}

u32 kvm_rmm_ipa_limit(void)
{
	return u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_S2SZ);
}

unsigned int kvm_realm_sve_max_vl(void)
{
	return sve_vl_from_vq(u64_get_bits(rmi_feat_reg(0),
					   RMI_FEATURE_REGISTER_0_SVE_VL) + 1);
}

u64 kvm_realm_reset_id_aa64dfr0_el1(const struct kvm_vcpu *vcpu, u64 val)
{
	u32 bps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_BPS);
	u32 wps = u64_get_bits(rmi_feat_reg(0), RMI_FEATURE_REGISTER_0_NUM_WPS);
	u32 ctx_cmps;

	/* Ensure CTX_CMPs is still valid */
	ctx_cmps = FIELD_GET(ID_AA64DFR0_EL1_CTX_CMPs, val);
	ctx_cmps = min(bps, ctx_cmps);

	val &= ~(ID_AA64DFR0_EL1_BRPs_MASK | ID_AA64DFR0_EL1_WRPs_MASK |
		 ID_AA64DFR0_EL1_CTX_CMPs);
	val |= FIELD_PREP(ID_AA64DFR0_EL1_BRPs_MASK, bps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_WRPs_MASK, wps) |
	       FIELD_PREP(ID_AA64DFR0_EL1_CTX_CMPs, ctx_cmps);

	return val;
}

static int get_start_level(struct realm *realm)
{
	return 4 - stage2_pgtable_levels(realm->ia_bits);
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = KVM_PGTABLE_LAST_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rmi_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

static unsigned long rmi_range_entry_size(int rmi_size)
{
	if (WARN_ON(rmi_size > KVM_PGTABLE_LAST_LEVEL))
		return 0;

	return kvm_granule_size(KVM_PGTABLE_LAST_LEVEL - rmi_size);
}

#ifdef CONFIG_LIVEUPDATE
static DEFINE_MUTEX(realm_luo_deferred_lock);
/*
 * Linear-map SRO used under realm_luo_deferred_lock when tearing down state
 * left by the previous kernel and kzalloc() fails. Allocated at boot.
 */
static struct rmi_sro_state *realm_luo_fallback_sro;
static DEFINE_XARRAY(realm_luo_reclaim_pages);

#define REALM_LUO_DATA_DELEGATED	BIT(0)
#define REALM_LUO_DATA_RES_INC		BIT(1)

static void realm_luo_update_data(struct xarray *xa, unsigned long pfn,
				  long delta, unsigned long set,
				  unsigned long clr)
{
	void *old = xa_load(xa, pfn);
	unsigned long val = xa_is_value(old) ? xa_to_value(old) : 0;

	val = ((val + delta) | set) & ~clr;
	if (old || val)
		__xa_store(xa, pfn, val ? xa_mk_value(val) : NULL, 0);
}

static void realm_luo_track_delegated_range(struct realm *realm,
					    unsigned long addr,
					    unsigned long size)
{
	struct xarray *xa = &realm->luo_data_pages;
	unsigned long pfn = PHYS_PFN(addr);
	unsigned long end_pfn = PHYS_PFN(addr + size);

	xa_lock(xa);
	for (; pfn < end_pfn; pfn++)
		realm_luo_update_data(xa, pfn, 0, REALM_LUO_DATA_DELEGATED, 0);
	xa_unlock(xa);
}

static void realm_luo_forget_delegated_range(struct realm *realm,
					     unsigned long addr,
					     unsigned long size)
{
	struct xarray *xa = &realm->luo_data_pages;
	unsigned long pfn = PHYS_PFN(addr);
	unsigned long end_pfn = pfn + PHYS_PFN(size);

	xa_lock(xa);
	for (; pfn < end_pfn; pfn++)
		realm_luo_update_data(xa, pfn, 0, 0, REALM_LUO_DATA_DELEGATED);
	xa_unlock(xa);
}

int kvm_realm_luo_reserve_data(struct kvm *kvm, kvm_pfn_t pfn)
{
	XA_STATE(xas, &kvm->arch.realm.luo_data_pages, pfn);
	unsigned long val;
	void *old;

	do {
		xas_lock(&xas);
		old = xas_load(&xas);
		val = xa_is_value(old) ? xa_to_value(old) : 0;
		xas_store(&xas, xa_mk_value(val + REALM_LUO_DATA_RES_INC));
		xas_unlock(&xas);
	} while (xas_nomem(&xas, GFP_KERNEL_ACCOUNT));

	return xas_error(&xas);
}

void kvm_realm_luo_release_data(struct kvm *kvm, kvm_pfn_t pfn)
{
	struct xarray *xa = &kvm->arch.realm.luo_data_pages;

	xa_lock(xa);
	realm_luo_update_data(xa, pfn, -REALM_LUO_DATA_RES_INC, 0, 0);
	xa_unlock(xa);
}

static void realm_luo_release_reclaimed_range(unsigned long addr,
					      unsigned long size)
{
	unsigned long pfn, end_pfn;

	if (likely(xa_empty(&realm_luo_reclaim_pages)))
		return;

	pfn = PHYS_PFN(addr);
	end_pfn = PHYS_PFN(addr + size);

	for (; pfn < end_pfn; pfn++) {
		void *entry = xa_erase_irq(&realm_luo_reclaim_pages, pfn);

		if (entry && !xa_is_value(entry))
			put_page(entry);
	}
}
#else
static inline void realm_luo_track_delegated_range(struct realm *realm,
						   unsigned long addr,
						   unsigned long size)
{
}

static inline void realm_luo_forget_delegated_range(struct realm *realm,
						    unsigned long addr,
						    unsigned long size)
{
}

int kvm_realm_luo_reserve_data(struct kvm *kvm, kvm_pfn_t pfn)
{
	return 0;
}

void kvm_realm_luo_release_data(struct kvm *kvm, kvm_pfn_t pfn)
{
}

static inline void realm_luo_release_reclaimed_range(unsigned long addr,
						     unsigned long size)
{
}
#endif

static int undelegate_range_desc(struct realm *realm, unsigned long desc)
{
	unsigned long size = rmi_range_entry_size(RMI_ADDR_RANGE_SIZE(desc));
	unsigned long count = RMI_ADDR_RANGE_COUNT(desc);
	unsigned long addr = RMI_ADDR_RANGE_ADDR(desc);
	unsigned long state = RMI_ADDR_RANGE_STATE(desc);
	int ret;

	if (state == RMI_OP_MEM_UNDELEGATED)
		return 0;

	if (size * count == 0)
		return 0;

	ret = rmi_undelegate_range(addr, size * count);
	if (!ret) {
		realm_luo_forget_delegated_range(realm, addr, size * count);
		realm_luo_release_reclaimed_range(addr, size * count);
	}

	return ret;
}

static long realm_rtt_data_unmap_and_undelegate(struct realm *realm,
						unsigned long addr,
						unsigned long end,
						unsigned long flags,
						unsigned long *next_addr)
{
	unsigned long out_range;
	long ret;

	ret = rmi_rtt_data_unmap(virt_to_phys(realm->rd), addr, end, flags, 0,
				 next_addr, &out_range, NULL);
	if (!ret && undelegate_range_desc(realm, out_range))
		ret = -ENXIO;

	return ret;
}

static phys_addr_t alloc_delegated_granule(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys;
	void *virt;

	if (mc) {
		virt = kvm_mmu_memory_cache_alloc(mc);
	} else {
		virt = (void *)__get_free_page(GFP_ATOMIC | __GFP_ZERO |
					       __GFP_ACCOUNT);
	}

	if (!virt)
		return PHYS_ADDR_MAX;

	phys = virt_to_phys(virt);
	if (rmi_delegate_page(phys)) {
		free_page((unsigned long)virt);
		return PHYS_ADDR_MAX;
	}
	INIT_LIST_HEAD(&virt_to_page(virt)->lru);

	return phys;
}

static phys_addr_t alloc_rtt(struct kvm_mmu_memory_cache *mc)
{
	phys_addr_t phys = alloc_delegated_granule(mc);

	if (phys != PHYS_ADDR_MAX)
		kvm_account_pgtable_pages(phys_to_virt(phys), 1);

	return phys;
}

static void free_rtt(phys_addr_t phys)
{
#ifdef CONFIG_LIVEUPDATE
	if (!page_ref_count(phys_to_page(phys))) {
		if (kho_restore_pages(phys, 1))
			free_delegated_page(phys);
		else
			WARN_ON(rmi_undelegate_page(phys));
		return;
	}
#endif
	if (free_delegated_page(phys))
		return;

	kvm_account_pgtable_pages(phys_to_virt(phys), -1);
}

int realm_psci_complete(struct kvm_vcpu *source, unsigned long status)
{
	long ret;

	ret = rmi_psci_complete(source->arch.rec.rec_phys, status);
	if (ret)
		return -ENXIO;

	return 0;
}

static long realm_rtt_create(struct realm *realm,
			     unsigned long addr,
			     int level,
			     phys_addr_t phys)
{
	struct page *rtt_page = phys_to_page(phys);
	unsigned long flags;
	long ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	spin_lock_irqsave(&realm->rtt_lock, flags);
	list_add_tail(&rtt_page->lru, &realm->rtt_list);
	realm->nr_rtt_pages++;
	spin_unlock_irqrestore(&realm->rtt_lock, flags);

	ret = rmi_rtt_create(virt_to_phys(realm->rd), phys, addr, level);
	if (ret) {
		spin_lock_irqsave(&realm->rtt_lock, flags);
		if (!list_empty(&rtt_page->lru)) {
			list_del_init(&rtt_page->lru);
			realm->nr_rtt_pages--;
		}
		spin_unlock_irqrestore(&realm->rtt_lock, flags);
	}

	return ret;
}

static long realm_rtt_fold(struct realm *realm,
			   unsigned long addr,
			   int level,
			   phys_addr_t *rtt_granule)
{
	unsigned long out_rtt;
	long ret;

	addr = ALIGN_DOWN(addr, rmi_rtt_level_mapsize(level - 1));
	ret = rmi_rtt_fold(virt_to_phys(realm->rd), addr, level, &out_rtt);
	if (!ret) {
		struct page *rtt_page = phys_to_page(out_rtt);
		unsigned long flags;

		spin_lock_irqsave(&realm->rtt_lock, flags);
		if (!list_empty(&rtt_page->lru)) {
			list_del_init(&rtt_page->lru);
			realm->nr_rtt_pages--;
		}
		spin_unlock_irqrestore(&realm->rtt_lock, flags);
	}

	if (rtt_granule)
		*rtt_granule = out_rtt;

	return ret;
}

/*
 * realm_rtt_destroy - Destroy an RTT at @level for @addr.
 *
 * Returns - Result of the RMI_RTT_DESTROY call, and:
 * @rtt_granule:	RTT granule, if the RTT was destroyed.
 * @next_addr:		IPA corresponding to the next possible valid entry we
 *			can target
 */
static long realm_rtt_destroy(struct realm *realm, unsigned long addr,
			      int level, phys_addr_t *rtt_granule,
			      unsigned long *next_addr)
{
	unsigned long out_rtt;
	long ret;

	ret = rmi_rtt_destroy(virt_to_phys(realm->rd), addr, level,
			      &out_rtt, next_addr);
	if (!ret) {
		struct page *rtt_page = phys_to_page(out_rtt);
		unsigned long flags;

		spin_lock_irqsave(&realm->rtt_lock, flags);
		if (!list_empty(&rtt_page->lru)) {
			list_del_init(&rtt_page->lru);
			realm->nr_rtt_pages--;
		}
		spin_unlock_irqrestore(&realm->rtt_lock, flags);
	}

	*rtt_granule = out_rtt;

	return ret;
}

static int realm_create_rtt_levels(struct realm *realm,
				   unsigned long ipa,
				   int level,
				   int max_level,
				   struct kvm_mmu_memory_cache *mc)
{
	while (level++ < max_level) {
		phys_addr_t rtt = alloc_rtt(mc);
		long ret;

		if (rtt == PHYS_ADDR_MAX)
			return -ENOMEM;

		ret = realm_rtt_create(realm, ipa, level, rtt);
		if (ret < 0) {
			free_rtt(rtt);
			return ret;
		}

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT &&
		    RMI_RETURN_INDEX(ret) == level - 1) {
			/* The RTT already exists, continue */
			free_rtt(rtt);
			continue;
		}

		if (ret) {
			WARN(1, "Failed to create RTT at level %d: %ld\n",
			     level, ret);
			free_rtt(rtt);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_level(struct realm *realm, int level,
				     unsigned long start, unsigned long end)
{
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		long ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		if (next_addr > end || align_addr != addr) {
			/*
			 * The target range is smaller than what this level
			 * covers, recurse deeper.
			 */
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							min(next_addr, end));
			if (ret)
				return ret;
			continue;
		}

		ret = realm_rtt_destroy(realm, addr, level,
					&rtt_granule, &next_addr);
		if (ret < 0)
			return ret;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (next_addr > addr) {
				/* Missing RTT, skip */
				break;
			}
			/*
			 * We tear down the RTT range for the full IPA
			 * space, after everything is unmapped. Also we
			 * descend down only if we cannot tear down a
			 * top level RTT. Thus RMM must be able to walk
			 * to the requested level. e.g., a block mapping
			 * exists at L1 or L2.
			 */
			if (WARN_ON(RMI_RETURN_INDEX(ret) != level))
				return -EBUSY;
			if (WARN_ON(level == KVM_PGTABLE_LAST_LEVEL))
				return -EBUSY;

			/*
			 * The table has active entries in it, recurse deeper
			 * and tear down the RTTs.
			 */
			next_addr = ALIGN(addr + 1, map_size);
			ret = realm_tear_down_rtt_level(realm,
							level + 1,
							addr,
							next_addr);
			if (ret)
				return ret;
			/*
			 * Now that the child RTTs are destroyed,
			 * retry at this level.
			 */
			next_addr = addr;
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return 0;
}

static int realm_tear_down_rtt_range(struct realm *realm,
				     unsigned long start, unsigned long end)
{
	/*
	 * Root level RTTs can only be destroyed after the RD is destroyed. So
	 * tear down everything below the root level
	 */
	return realm_tear_down_rtt_level(realm, get_start_level(realm) + 1,
					 start, end);
}

/*
 * Returns 0 on successful fold, a negative value on error, a positive value if
 * we were not able to fold all tables at this level.
 */
static int realm_fold_rtt_level(struct realm *realm, int level,
				unsigned long start, unsigned long end)
{
	int not_folded = 0;
	ssize_t map_size;
	unsigned long addr, next_addr;

	if (WARN_ON(level > KVM_PGTABLE_LAST_LEVEL))
		return -EINVAL;

	map_size = rmi_rtt_level_mapsize(level - 1);

	for (addr = start; addr < end; addr = next_addr) {
		phys_addr_t rtt_granule;
		long ret;
		unsigned long align_addr = ALIGN(addr, map_size);

		next_addr = ALIGN(addr + 1, map_size);

		ret = realm_rtt_fold(realm, align_addr, level, &rtt_granule);
		if (ret < 0)
			return ret;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			free_rtt(rtt_granule);
			break;
		case RMI_ERROR_RTT:
			if (level == KVM_PGTABLE_LAST_LEVEL ||
			    RMI_RETURN_INDEX(ret) < level) {
				not_folded++;
				break;
			}
			/* Recurse a level deeper */
			ret = realm_fold_rtt_level(realm,
						   level + 1,
						   addr,
						   next_addr);
			if (ret < 0) {
				return ret;
			} else if (ret == 0) {
				/* Try again at this level */
				next_addr = addr;
			}
			break;
		default:
			WARN_ON(1);
			return -ENXIO;
		}
	}

	return not_folded;
}

static int realm_destroy_rtts(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned int ia_bits = realm->ia_bits;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->rtts_destroyed)
		return 0;

	ret = realm_tear_down_rtt_range(realm, 0, (1UL << ia_bits));
	if (ret)
		return ret;

	realm->rtts_destroyed = true;
	return 0;
}

static void realm_unmap_stage2(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (realm->stage2_unmapped)
		return;

	write_lock(&kvm->mmu_lock);
	kvm_stage2_unmap_range(&kvm->arch.mmu, 0,
			       BIT(realm->ia_bits - 1), true);
	write_unlock(&kvm->mmu_lock);

	realm->stage2_unmapped = true;
}

int kvm_realm_teardown_stage2(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->arch.config_lock);

	realm_unmap_stage2(kvm);
	return realm_destroy_rtts(kvm);
}

static void realm_unmap_shared_range(struct kvm *kvm,
				     unsigned long start,
				     unsigned long end,
				     bool may_block)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long rd = virt_to_phys(realm->rd);
	unsigned long next_addr, addr;
	unsigned long shared_bit = BIT(realm->ia_bits - 1);

	if (start >= end)
		return;

	start += shared_bit;
	end += shared_bit;

	for (addr = start; addr < end; addr = next_addr) {
		long ret;

		next_addr = addr;
		ret = rmi_rtt_unprot_unmap(rd, addr, end, RMI_ADDR_TYPE_NONE,
					   0, &next_addr, NULL, NULL);
		if (WARN_ON(ret < 0))
			return;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, addr, end);

			if (next_addr > addr)
				break;

			if (err_level >= level) {
				/* Nothing present, so skip */
				next_addr = addr + rmi_rtt_level_mapsize(err_level);
				break;
			}

			ret = realm_create_rtt_levels(realm, addr, err_level,
						      level, NULL);
			if (WARN_ON(ret))
				return;
			/* Retry with the RTT levels in place */
			next_addr = addr;
			break;
		}
		default:
			WARN_ON(1);
			return;
		}

		if (may_block) {
			cond_resched_rwlock_write(&kvm->mmu_lock);
			if (READ_ONCE(realm->luo_frozen))
				return;
		}
	}

	if (READ_ONCE(realm->luo_frozen))
		return;

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
}

static int realm_init_sve_param(struct kvm *kvm, struct realm_params *params)
{
	unsigned long i;
	struct kvm_vcpu *vcpu;
	int vl, last_vl = -1;

	if (!kvm_has_sve(kvm))
		return 0;

	/*
	 * Get the preferred SVE configuration, set by userspace with the
	 * KVM_ARM_VCPU_SVE feature and KVM_REG_ARM64_SVE_VLS pseudo-register.
	 */
	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_arm_vcpu_sve_finalized(vcpu))
			return -EINVAL;

		vl = vcpu->arch.sve_max_vl;

		/* We need all vCPUs to have the same SVE config */
		if (last_vl >= 0 && last_vl != vl)
			return -EINVAL;

		last_vl = vl;
	}

	if (last_vl > 0) {
		params->sve_vl = sve_vq_from_vl(last_vl) - 1;
		params->flags0 |= RMI_REALM_PARAM_FLAG_SVE;
	}
	return 0;
}

static int realm_create_rd(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct realm_params *params __free(free_page) = NULL;
	void *rd = NULL;
	phys_addr_t rd_phys, params_phys, top_delegated;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	u64 dfr0 = kvm_read_vm_id_reg(kvm, SYS_ID_AA64DFR0_EL1);
	long rmi_ret;
	int r;

	realm->ia_bits = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);

	if (WARN_ON(realm->rd))
		return -EEXIST;

	params = (void *)get_zeroed_page(GFP_KERNEL_ACCOUNT);
	if (!params)
		return -ENOMEM;

	rd = (void *)__get_free_page(GFP_KERNEL_ACCOUNT);
	if (!rd)
		return -ENOMEM;

	rd_phys = virt_to_phys(rd);
	if (rmi_delegate_page(rd_phys)) {
		r = -ENXIO;
		goto free_rd;
	}

	if (rmi_delegate_range(kvm->arch.mmu.pgd_phys, pgd_size,
			       &top_delegated)) {
		r = -ENXIO;
		goto out_undelegate_tables;
	}

	params->s2sz = VTCR_EL2_IPA(kvm->arch.mmu.vtcr);
	params->rtt_level_start = get_start_level(realm);
	params->rtt_num_start = pgd_size / PAGE_SIZE;
	params->rtt_base = kvm->arch.mmu.pgd_phys;
	params->num_bps = SYS_FIELD_GET(ID_AA64DFR0_EL1, BRPs, dfr0);
	params->num_wps = SYS_FIELD_GET(ID_AA64DFR0_EL1, WRPs, dfr0);
	params->hash_algo = RMI_HASH_SHA_256;

	if (kvm->arch.arm_pmu) {
		params->pmu_num_ctrs = kvm->arch.nr_pmu_counters;
		params->flags0 |= RMI_REALM_PARAM_FLAG_PMU;
	}

	if (kvm_lpa2_is_enabled())
		params->flags0 |= RMI_REALM_PARAM_FLAG_LPA2;

	r = realm_init_sve_param(kvm, params);
	if (r)
		goto out_undelegate_tables;

	params_phys = virt_to_phys(params);

	rmi_ret = rmi_realm_create(rd_phys, params_phys, realm->sro);
	if (rmi_ret) {
		r = rmi_ret < 0 ? rmi_ret : -ENXIO;
		goto out_undelegate_tables;
	}

	realm->rd = rd;
	kvm_set_realm_state(kvm, REALM_STATE_NEW);

	return 0;

out_undelegate_tables:
	if (WARN_ON(rmi_undelegate_range(kvm->arch.mmu.pgd_phys,
					 top_delegated - kvm->arch.mmu.pgd_phys))) {
		/* Leak the pages if they cannot be returned */
		kvm->arch.mmu.pgt = NULL;
	}
	if (WARN_ON(rmi_undelegate_page(rd_phys))) {
		/* Leak the page if it isn't returned */
		return r;
	}
free_rd:
	free_page((unsigned long)rd);
	return r;
}

static void realm_unmap_private_range(struct kvm *kvm,
				      struct realm *realm,
				      unsigned long start,
				      unsigned long end,
				      bool may_block)
{
	unsigned long next_addr, addr;
	long ret;

	for (addr = start; addr < end; addr = next_addr) {
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;
		/* TODO: Optimise using RMI_ADDR_TYPE_LIST */

retry:
		ret = realm_rtt_data_unmap_and_undelegate(realm, addr, end, flags,
							  &next_addr);
		if (WARN_ON(ret < 0))
			return;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			phys_addr_t rtt;

			if (next_addr > addr)
				continue; /* UNASSIGNED */

			rtt = alloc_rtt(NULL);
			if (WARN_ON(rtt == PHYS_ADDR_MAX))
				return;
			ret = realm_rtt_create(realm, addr,
					       RMI_RETURN_INDEX(ret) + 1, rtt);
			if (WARN_ON(ret)) {
				free_rtt(rtt);
				return;
			}
			goto retry;
		} else if (WARN_ON(ret)) {
			continue;
		}

		if (may_block) {
			cond_resched_rwlock_write(&kvm->mmu_lock);
			if (READ_ONCE(realm->luo_frozen))
				return;
		}
	}

	if (READ_ONCE(realm->luo_frozen))
		return;

	realm_fold_rtt_level(realm, get_start_level(realm) + 1,
			     start, end);
}

void kvm_realm_unmap_range(struct kvm *kvm, unsigned long start,
			   unsigned long size, bool unmap_private,
			   bool may_block)
{
	unsigned long end = start + size;
	struct realm *realm = &kvm->arch.realm;

	if (!kvm_realm_is_created(kvm) || READ_ONCE(realm->luo_frozen))
		return;

	end = min(BIT(realm->ia_bits - 1), end);

	realm_unmap_shared_range(kvm, start, end, may_block);
	if (READ_ONCE(realm->luo_frozen))
		return;
	if (unmap_private)
		realm_unmap_private_range(kvm, realm, start, end, may_block);
}

static int realm_data_map_init(struct kvm *kvm, unsigned long ipa,
			       kvm_pfn_t dst_pfn, kvm_pfn_t src_pfn,
			       unsigned long flags)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t dst_phys, src_phys;
	long ret;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	dst_phys = __pfn_to_phys(dst_pfn);
	src_phys = __pfn_to_phys(src_pfn);

	ret = kvm_realm_luo_reserve_data(kvm, dst_pfn);
	if (ret)
		return ret;

	if (rmi_delegate_page(dst_phys)) {
		kvm_realm_luo_release_data(kvm, dst_pfn);
		return -ENXIO;
	}

retry:
	ret = rmi_rtt_data_map_init(rd, dst_phys, ipa, src_phys, flags);
	if (ret >= 0 && RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry */
		int level = RMI_RETURN_INDEX(ret);

		KVM_BUG_ON(level >= KVM_PGTABLE_LAST_LEVEL, kvm);

		ret = realm_create_rtt_levels(realm, ipa, level,
					      level + 1, NULL);
		if (!ret)
			goto retry;
	}

	if (!ret)
		realm_luo_track_delegated_range(realm, dst_phys, PAGE_SIZE);
	else if (WARN_ON(rmi_undelegate_page(dst_phys)))
		/* Leak the page if the undelegate fails */
		get_page(pfn_to_page(dst_pfn));
	kvm_realm_luo_release_data(kvm, dst_pfn);

	return ret <= 0 ? ret : -ENXIO;
}

static unsigned long addr_range_desc(unsigned long phys, unsigned long size,
				     unsigned long state)
{
	unsigned long count = 1;
	unsigned long out;
	int rmi_size;

	for (rmi_size = KVM_PGTABLE_LAST_LEVEL; rmi_size >= 0; rmi_size--) {
		unsigned long entry_size = rmi_range_entry_size(rmi_size);

		if (size == entry_size)
			break;
		if (size > entry_size) {
			rmi_size = -1;
			break;
		}
	}

	if (rmi_size < 0) {
		/*
		 * Only support mapping at the page level granularity when
		 * it's an unusual length. This should get us back onto a larger
		 * block size for the subsequent mappings.
		 */
		rmi_size = 0;
		count = MIN(size >> PAGE_SHIFT, PTRS_PER_PTE - 1);
	}

	WARN_ON(phys & ~PAGE_MASK);

	out = FIELD_PREP(RMI_ADDR_RANGE_SIZE_MASK, rmi_size) |
	      FIELD_PREP(RMI_ADDR_RANGE_COUNT_MASK, count) |
	      FIELD_PREP(RMI_ADDR_RANGE_STATE_MASK, state);
	out |= phys & PAGE_MASK;

	return out;
}

static int realm_map_protected(struct kvm *kvm,
			       unsigned long ipa,
			       kvm_pfn_t pfn,
			       unsigned long map_size,
			       struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t phys = __pfn_to_phys(pfn);
	phys_addr_t base_phys = phys;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t delegated_phys;
	unsigned long base_ipa = ipa;
	unsigned long ipa_top;
	long ret = 0;

	if (WARN_ON(!IS_ALIGNED(map_size, PAGE_SIZE) ||
		    !IS_ALIGNED(ipa, map_size)))
		return -EINVAL;

	if (rmi_delegate_range(phys, map_size, &delegated_phys)) {
		if (delegated_phys == phys) {
			/*
			 * It's likely we raced with another VCPU on the same
			 * fault. Assume the other VCPU has handled the fault
			 * and return to the guest.
			 */
			return 0;
		}
		/* Partial delegation - map as much as we can */
		map_size = delegated_phys - phys;
	}

	ipa_top = ipa + map_size;

	while (ipa < ipa_top) {
		unsigned long flags = RMI_ADDR_TYPE_SINGLE;
		unsigned long range_desc = addr_range_desc(phys, ipa_top - ipa,
							   RMI_OP_MEM_DELEGATED);
		unsigned long out_top;

		ret = rmi_rtt_data_map(rd, ipa, ipa_top, flags, range_desc,
				       &out_top);
		if (ret < 0)
			goto err_undelegate;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			if (WARN_ON(level >= KVM_PGTABLE_LAST_LEVEL))
				goto err_undelegate;
			ret = realm_create_rtt_levels(realm, ipa, level,
						      level + 1,
						      memcache);
			if (ret)
				goto err_undelegate;

			continue;
		}

		if (WARN_ON(ret))
			goto err_undelegate;

		/* Slots were reserved by kvm_realm_luo_reserve_data() */
		realm_luo_track_delegated_range(realm, phys, out_top - ipa);
		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;

err_undelegate:
	realm_unmap_private_range(kvm, realm, base_ipa, ipa, true);
	if (WARN_ON(rmi_undelegate_range(base_phys, map_size))) {
		/* Page can't be returned to NS world so is lost */
		get_page(phys_to_page(base_phys));
	}
	return ret < 0 ? ret : -ENXIO;
}

static int realm_map_non_secure(struct kvm *kvm,
				unsigned long ipa,
				kvm_pfn_t pfn,
				unsigned long size,
				enum kvm_pgtable_prot prot,
				struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long attr, flags = 0;
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = __pfn_to_phys(pfn);
	unsigned long ipa_top = ipa + size;
	long ret;

	if (WARN_ON(!IS_ALIGNED(size, PAGE_SIZE)))
		return -EINVAL;

	switch (prot & (KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC)) {
	case KVM_PGTABLE_PROT_DEVICE | KVM_PGTABLE_PROT_NORMAL_NC:
		return -EINVAL;
	case KVM_PGTABLE_PROT_DEVICE:
		attr = MT_S2_FWB_DEVICE_nGnRE;
		break;
	case KVM_PGTABLE_PROT_NORMAL_NC:
		attr = MT_S2_FWB_NORMAL_NC;
		break;
	default:
		attr = MT_S2_FWB_NORMAL;
	}

	flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_MEMATTR, attr);

	if (prot & KVM_PGTABLE_PROT_R)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP, RMI_S2AP_DIRECT_READ);
	if (prot & KVM_PGTABLE_PROT_W)
		flags |= FIELD_PREP(RMI_RTT_UNPROT_MAP_FLAGS_S2AP, RMI_S2AP_DIRECT_WRITE);

	flags |= RMI_ADDR_TYPE_SINGLE;

	while (ipa < ipa_top) {
		unsigned long range_desc = addr_range_desc(phys, ipa_top - ipa,
							   RMI_OP_MEM_UNDELEGATED);
		unsigned long out_top;

		ret = rmi_rtt_unprot_map(rd, ipa, ipa_top, flags, range_desc,
					 &out_top);
		if (ret < 0)
			return ret;

		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);
			int req_level = find_map_level(realm, ipa, ipa_top);

			/*
			 * There already exists a mapping at the level. May be
			 * we are relaxing a permission for the given range ?
			 */
			if (level >= req_level) {
				realm_unmap_shared_range(kvm, ipa, ipa_top, true);
				if (READ_ONCE(realm->luo_frozen))
					return -EBUSY;
				continue;
			}

			ret = realm_create_rtt_levels(realm, ipa, level,
						      req_level,
						      memcache);
			if (ret)
				return ret;

			ret = rmi_rtt_unprot_map(rd, ipa, ipa_top, flags,
						 range_desc, &out_top);
			if (ret < 0)
				return ret;
		}

		if (ret && RMI_RETURN_STATUS(ret) != RMI_ERROR_RTT)
			return ret;

		phys += out_top - ipa;
		ipa = out_top;
	}

	return 0;
}

int realm_map_ipa(struct kvm *kvm, phys_addr_t ipa,
		  kvm_pfn_t pfn, unsigned long map_size,
		  enum kvm_pgtable_prot prot,
		  struct kvm_mmu_memory_cache *memcache)
{
	struct realm *realm = &kvm->arch.realm;

	if (READ_ONCE(realm->luo_frozen))
		return -EBUSY;

	ipa = ALIGN_DOWN(ipa, map_size);
	if (!kvm_realm_is_private_address(realm, ipa)) {
		return realm_map_non_secure(kvm, ipa, pfn, map_size, prot,
					    memcache);
	}

	/* It's impossible to map protected pages read-only. */
	if (WARN_ON(!(prot & KVM_PGTABLE_PROT_W)))
		return -EFAULT;
	return realm_map_protected(kvm, ipa, pfn, map_size, memcache);
}

static int populate_region_cb(struct kvm *kvm, gfn_t gfn, kvm_pfn_t pfn,
			      struct page *src_page, void *opaque)
{
	unsigned long data_flags = *(unsigned long *)opaque;
	phys_addr_t ipa = gfn_to_gpa(gfn);

	return realm_data_map_init(kvm, ipa, pfn, page_to_pfn(src_page),
				   data_flags);
}

static long populate_region(struct kvm *kvm,
			    gfn_t base_gfn,
			    unsigned long pages,
			    u64 uaddr,
			    unsigned long data_flags)
{
	long ret = 0;

	lockdep_assert_held(&kvm->slots_lock);
	lockdep_assert_held(&kvm->arch.config_lock);

	if (!uaddr)
		return -EINVAL;

	ret = kvm_gmem_populate(kvm, base_gfn, u64_to_user_ptr(uaddr), pages,
				false, populate_region_cb, &data_flags);

	return ret;
}

enum ripas_action {
	RIPAS_INIT,
	RIPAS_SET,
};

static int ripas_change(struct kvm *kvm,
			struct kvm_vcpu *vcpu,
			unsigned long ipa,
			unsigned long end,
			enum ripas_action action,
			unsigned long *top_ipa)
{
	struct realm *realm = &kvm->arch.realm;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys;
	struct kvm_mmu_memory_cache *memcache = NULL;
	long ret = 0;

	if (vcpu) {
		rec_phys = vcpu->arch.rec.rec_phys;
		memcache = &vcpu->arch.mmu_page_cache;

		WARN_ON(action != RIPAS_SET);
	} else {
		WARN_ON(action != RIPAS_INIT);
	}

	while (ipa < end) {
		unsigned long next = ~0;

		switch (action) {
		case RIPAS_INIT:
			ret = rmi_rtt_init_ripas(rd_phys, ipa, end, &next);
			break;
		case RIPAS_SET:
			ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end,
						&next);
			break;
		}

		if (ret < 0)
			goto out;

		switch (RMI_RETURN_STATUS(ret)) {
		case RMI_SUCCESS:
			ipa = next;
			break;
		case RMI_ERROR_RTT: {
			int err_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			/*
			 * If the operation failed at deeper level than
			 * what is required for the address range, this
			 * implies encountering an unexpected entry,
			 * (e.g., RIPAS_DESTROYED), which the RMM prevents
			 * us from modifying. This is only applicable for
			 * RMI_RTT_INIT_RIPAS. All the other requests
			 * are generated by the Realm and thus RMM should
			 * be able to allow the transition.
			 */
			if (action == RIPAS_INIT && WARN_ON_ONCE(err_level >= level))
				return -ENXIO;

			ret = realm_create_rtt_levels(realm, ipa, err_level,
						      level, memcache);
			if (ret)
				goto out;
			/* Retry with the RTT levels in place */
			break;
		}
		default:
			WARN_ON(1);
			ret = -ENXIO;
			goto out;
		}
	}

out:
	if (top_ipa)
		*top_ipa = ipa;

	return ret;
}

static int realm_set_ipa_state(struct kvm_vcpu *vcpu,
			       unsigned long start,
			       unsigned long end,
			       unsigned long ripas,
			       unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	int ret;

	if (READ_ONCE(kvm->arch.realm.luo_frozen))
		return -EBUSY;

	ret = ripas_change(kvm, vcpu, start, end, RIPAS_SET, top_ipa);

	if (!ret && ripas == RMI_EMPTY && *top_ipa != start)
		realm_unmap_private_range(kvm, &kvm->arch.realm, start,
					  *top_ipa, false);

	return ret;
}

static int realm_init_ipa_state(struct kvm *kvm,
				unsigned long gfn,
				unsigned long pages)
{
	return ripas_change(kvm, NULL, gfn_to_gpa(gfn), gfn_to_gpa(gfn + pages),
			    RIPAS_INIT, NULL);
}

static int realm_ensure_created(struct kvm *kvm)
{
	lockdep_assert_held(&kvm->arch.config_lock);

	switch (kvm_realm_state(kvm)) {
	case REALM_STATE_NONE:
		break;
	case REALM_STATE_NEW:
		return 0;
	case REALM_STATE_DEAD:
		return -ENXIO;
	default:
		return -EBUSY;
	}

	return realm_create_rd(kvm);
}

static int set_ripas_of_protected_regions(struct kvm *kvm)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	int idx, bkt;
	int ret = 0;

	lockdep_assert_held(&kvm->arch.config_lock);

	idx = srcu_read_lock(&kvm->srcu);

	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!kvm_slot_has_gmem(memslot))
			continue;

		ret = realm_init_ipa_state(kvm, memslot->base_gfn,
					   memslot->npages);
		if (ret)
			break;
	}
	srcu_read_unlock(&kvm->srcu, idx);

	return ret;
}

int kvm_arm_rmi_populate(struct kvm *kvm,
			 struct kvm_arm_rmi_populate *args)
{
	unsigned long data_flags = 0;
	unsigned long ipa_start = args->base;
	unsigned long ipa_end = ipa_start + args->size;
	long pages_populated;
	int ret;

	if (args->reserved ||
	    (args->flags & ~KVM_ARM_RMI_POPULATE_FLAGS_MEASURE) ||
	    args->base + args->size < args->base ||
	    !IS_ALIGNED(ipa_start, PAGE_SIZE) ||
	    !IS_ALIGNED(ipa_end, PAGE_SIZE) ||
	    !IS_ALIGNED(args->source_uaddr, PAGE_SIZE))
		return -EINVAL;

	if (args->flags & KVM_ARM_RMI_POPULATE_FLAGS_MEASURE)
		data_flags |= RMI_MEASURE_CONTENT;

	mutex_lock(&kvm->slots_lock);
	mutex_lock(&kvm->arch.config_lock);

	ret = realm_ensure_created(kvm);
	if (ret)
		goto out_unlock;

	if (args->size == 0)
		goto out_unlock;

	pages_populated = populate_region(kvm, gpa_to_gfn(ipa_start),
					  args->size >> PAGE_SHIFT,
					  args->source_uaddr, data_flags);

	if (pages_populated < 0) {
		ret = pages_populated;
		goto out_unlock;
	}

	args->size -= pages_populated << PAGE_SHIFT;
	args->source_uaddr += pages_populated << PAGE_SHIFT;
	args->base += pages_populated << PAGE_SHIFT;

out_unlock:
	mutex_unlock(&kvm->arch.config_lock);
	mutex_unlock(&kvm->slots_lock);
	return ret;
}

static int kvm_complete_ripas_change(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm_rec *rec = &vcpu->arch.rec;
	unsigned long base = rec->run->exit.ripas_base;
	unsigned long top = rec->run->exit.ripas_top;
	unsigned long ripas = rec->run->exit.ripas_value;
	unsigned long top_ipa = base;
	int ret;

	do {
		kvm_mmu_topup_memory_cache(&vcpu->arch.mmu_page_cache,
					   kvm_mmu_cache_min_pages(vcpu->arch.hw_mmu));
		write_lock(&kvm->mmu_lock);
		ret = realm_set_ipa_state(vcpu, base, top, ripas, &top_ipa);
		write_unlock(&kvm->mmu_lock);

		if (ret == -ENOMEM) {
			/* If no progress, then stop */
			if (top_ipa == base)
				break;
			base = top_ipa;
			continue;
		}

		if (ret == -EBUSY) {
			rec->run->exit.ripas_base = base;
			kvm_make_request(KVM_REQ_RMI, vcpu);
			return -EBUSY;
		}

		if (WARN_RATELIMIT(ret,
				   "Unable to satisfy RIPAS_CHANGE for %#lx - %#lx, ripas: %#lx\n",
				   base, top, ripas))
			break;

		base = top_ipa;
	} while (base < top);

	/*
	 * If this function is called again before the REC_ENTER call then
	 * avoid calling realm_set_ipa_state() again by changing to the value
	 * of ripas_base for the part that has already been covered. The RMM
	 * ignores the contains of the rec_exit structure so this doesn't
	 * affect the RMM.
	 */
	rec->run->exit.ripas_base = base;

	return 1;
}

static int kvm_rec_complete_psci(struct kvm_vcpu *vcpu)
{
	struct rec_run *run = vcpu->arch.rec.run;
	unsigned long status = PSCI_RET_DENIED;
	unsigned long ret = vcpu_get_reg(vcpu, 0);
	int r;

	switch (run->exit.gprs[0]) {
	case PSCI_0_2_FN64_CPU_ON: {
		if (ret != PSCI_RET_SUCCESS &&
		    ret != PSCI_RET_ALREADY_ON)
			status = PSCI_RET_DENIED;
		else
			status = PSCI_RET_SUCCESS;
		break;
	}
	default:
		return 1;
	}

	r = realm_psci_complete(vcpu, status);
	return r ?: 1;
}

int kvm_rec_handle_request(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	u64 esr;

	switch (rec->run->exit.exit_reason) {
	case RMI_EXIT_SYNC:
		esr = rec->run->exit.esr;
		if (ESR_ELx_EC(esr) == ESR_ELx_EC_SYS64 &&
		    (esr & ESR_ELx_SYS64_ISS_DIR_MASK) ==
				ESR_ELx_SYS64_ISS_DIR_READ) {
			int rt = ESR_ELx_SYS64_ISS_RT(esr);

			if (rt < REC_RUN_GPRS)
				rec->run->enter.gprs[rt] =
					vcpu_get_reg(vcpu, rt);
		}
		break;
	case RMI_EXIT_PSCI:
		return kvm_rec_complete_psci(vcpu);
	case RMI_EXIT_RIPAS_CHANGE:
		return kvm_complete_ripas_change(vcpu);
	case RMI_EXIT_HOST_CALL:
		for (int i = 0; i < REC_RUN_GPRS; i++)
			rec->run->enter.gprs[i] = vcpu_get_reg(vcpu, i);
		break;
	default:
		KVM_BUG(1, vcpu->kvm, "Unhandled realm exit_reason");
		return -ENXIO;
	}

	return 1;
}

static void noinstr load_realm_timer_state(struct kvm_vcpu *vcpu)
{
	struct rec_exit *rec_exit = &vcpu->arch.rec.run->exit;

	/*
	 * The RMM reports the EL1 timer state on every REC exit. Install that
	 * state before returning to the generic KVM run loop, which expects
	 * the loaded vCPU's timers to be live.
	 */
	write_sysreg_el0(rec_exit->cntv_cval, SYS_CNTV_CVAL);
	write_sysreg_el0(rec_exit->cntp_cval, SYS_CNTP_CVAL);
	isb();

	write_sysreg_el0(rec_exit->cntv_ctl, SYS_CNTV_CTL);
	write_sysreg_el0(rec_exit->cntp_ctl, SYS_CNTP_CTL);
}

int noinstr kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	int ret;

	ret = rmi_rec_enter(rec->rec_phys, rec->run_phys);
	if (!ret)
		load_realm_timer_state(vcpu);

	return ret;
}

static int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct user_pt_regs *vcpu_regs = vcpu_gp_regs(vcpu);
	unsigned long mpidr = kvm_vcpu_get_mpidr_aff(vcpu);
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	struct rmi_sro_state *sro;
	struct rec_params *params;
	phys_addr_t rec_phys;
	struct rec_run *run;
	void *rec_page;
	long rmi_ret;
	int r, i;

	if (READ_ONCE(rec->run))
		return -EBUSY;

	/*
	 * The RMM will report PSCI v1.0 to Realms and the KVM_ARM_VCPU_PSCI_0_2
	 * flag covers v0.2 and onwards.
	 */
	if (!vcpu_has_feature(vcpu, KVM_ARM_VCPU_PSCI_0_2))
		return -EINVAL;

	BUILD_BUG_ON(sizeof(*params) > PAGE_SIZE);
	BUILD_BUG_ON(sizeof(*rec->run) > PAGE_SIZE);

	params = (struct rec_params *)get_zeroed_page(GFP_KERNEL);
	rec_page = (void *)__get_free_page(GFP_KERNEL);
	run = (struct rec_run *)get_zeroed_page(GFP_KERNEL);
	sro = kzalloc_obj(*sro);
	if (!params || !rec_page || !run || !sro) {
		r = -ENOMEM;
		goto out_free_pages;
	}

	for (i = 0; i < ARRAY_SIZE(params->gprs); i++)
		params->gprs[i] = vcpu_regs->regs[i];

	params->pc = vcpu_regs->pc;

	if (vcpu->vcpu_id == 0)
		params->flags |= REC_PARAMS_FLAG_RUNNABLE;

	rec_phys = virt_to_phys(rec_page);

	if (rmi_delegate_page(rec_phys)) {
		r = -ENXIO;
		goto out_free_pages;
	}

	params->mpidr = mpidr;

	rmi_ret = rmi_rec_create(virt_to_phys(realm->rd), rec_phys,
				 virt_to_phys(params), sro);
	if (rmi_ret) {
		r = rmi_ret < 0 ? rmi_ret : -ENXIO;
		goto out_undelegate_rmm_rec;
	}

	rec->rec_page = rec_page;
	rec->rec_phys = rec_phys;
	rec->run_phys = virt_to_phys(run);
	rec->sro = sro;
	rec->mpidr = mpidr;
	WRITE_ONCE(rec->run, run);

	free_page((unsigned long)params);
	return 0;

out_undelegate_rmm_rec:
	if (WARN_ON(rmi_undelegate_page(rec_phys)))
		rec_page = NULL;
out_free_pages:
	free_page((unsigned long)run);
	free_page((unsigned long)rec_page);
	free_page((unsigned long)params);
	kfree(sro);
	return r;
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	struct rec_run *run = READ_ONCE(rec->run);

	if (!vcpu_is_rec(vcpu))
		return;

	if (!run) {
		/* Nothing to do if the VCPU hasn't been finalized */
		return;
	}

	if (WARN_ON(rmi_rec_destroy(rec->rec_phys, rec->sro)))
		return;

	WRITE_ONCE(rec->run, NULL);
	free_page((unsigned long)run);
	kfree(rec->sro);
	free_delegated_page(rec->rec_phys);
	rec->sro = NULL;
	rec->rec_page = NULL;
	rec->rec_phys = 0;
	rec->run_phys = 0;
}

int kvm_activate_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_vcpu *vcpu;
	unsigned long i;
	int ret;

	if (!irqchip_in_kernel(kvm)) {
		/* Userspace irqchip not yet supported with realms */
		return -EOPNOTSUPP;
	}

	guard(mutex)(&kvm->arch.config_lock);
	if (kvm_realm_state(kvm) == REALM_STATE_DEAD)
		return -ENXIO;
	if (kvm_realm_state(kvm) == REALM_STATE_ACTIVE) {
		kvm_for_each_vcpu(i, vcpu, kvm) {
			if (!READ_ONCE(vcpu->arch.rec.run))
				return -EINVAL;
		}
		return 0;
	}

	ret = realm_ensure_created(kvm);
	if (ret)
		return ret;

	/* Mark state as dead in case we fail */
	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	kvm_for_each_vcpu(i, vcpu, kvm) {
		ret = kvm_create_rec(vcpu);
		if (ret)
			return ret;
	}

	ret = set_ripas_of_protected_regions(kvm);
	if (ret)
		return ret;

	ret = rmi_realm_activate(virt_to_phys(realm->rd));
	if (ret)
		return -ENXIO;

	kvm_set_realm_state(kvm, REALM_STATE_ACTIVE);
	return 0;
}

#ifdef CONFIG_LIVEUPDATE
struct realm_luo_deferred {
	struct list_head node;
	phys_addr_t rd_phys;
	phys_addr_t pgd_phys;
	size_t pgd_size;
	bool accounted;
};

static LIST_HEAD(realm_luo_deferred_list);

static bool realm_luo_defer_teardown(phys_addr_t rd_phys, phys_addr_t pgd_phys,
				     size_t pgd_size, bool accounted)
{
	struct realm_luo_deferred *def;

	def = kzalloc_obj(*def);
	if (!def)
		return false;

	def->rd_phys = rd_phys;
	def->pgd_phys = pgd_phys;
	def->pgd_size = pgd_size;
	def->accounted = accounted;

	guard(mutex)(&realm_luo_deferred_lock);
	list_add_tail(&def->node, &realm_luo_deferred_list);
	return true;
}

static void realm_luo_drain_deferred(void)
{
	struct rmi_sro_state *dyn_sro __free(kfree) = kzalloc_obj(*dyn_sro);
	struct realm_luo_deferred *def, *tmp;
	struct rmi_sro_state *sro;

	guard(mutex)(&realm_luo_deferred_lock);
	if (list_empty(&realm_luo_deferred_list))
		return;

	sro = dyn_sro ?: realm_luo_fallback_sro;
	if (!sro)
		return;
	if (!dyn_sro)
		memset(sro, 0, sizeof(*sro));

	list_for_each_entry_safe(def, tmp, &realm_luo_deferred_list, node) {
		if (rmi_realm_destroy(def->rd_phys, sro))
			continue;

		free_delegated_page(def->rd_phys);
		if (def->pgd_phys &&
		    !WARN_ON(rmi_undelegate_range(def->pgd_phys, def->pgd_size))) {
			void *pgd_va = phys_to_virt(def->pgd_phys);

			if (def->accounted)
				kvm_account_pgtable_pages(pgd_va,
							  -(def->pgd_size >> PAGE_SHIFT));
			free_pages_exact(pgd_va, def->pgd_size);
		}
		list_del(&def->node);
		kfree(def);
	}
}

#define REALM_LUO_SUBTREE_NAME	"kvm-arm-cca"
#define REALM_LUO_PFN_DATA	BIT_ULL(63)
#define REALM_LUO_PFN_MASK	(~REALM_LUO_PFN_DATA)

struct realm_luo_cca_dir {
	struct kho_vmalloc entries[255];
	u64 reserved[2];
};

static struct realm_luo_cca_dir *realm_luo_dir;

static int realm_luo_dir_register(const struct kho_vmalloc *vm)
{
	unsigned int i;
	int ret;

	if (!vm || !vm->first.phys || !vm->total_pages)
		return 0;

	guard(mutex)(&realm_luo_deferred_lock);
	if (!realm_luo_dir) {
		struct realm_luo_cca_dir *dir;

		BUILD_BUG_ON(sizeof(*dir) > PAGE_SIZE);
		dir = kho_alloc_preserve(PAGE_SIZE);
		if (IS_ERR(dir))
			return PTR_ERR(dir);
		ret = kho_add_subtree(REALM_LUO_SUBTREE_NAME, dir, PAGE_SIZE);
		if (ret) {
			kho_unpreserve_free(dir);
			return ret;
		}
		realm_luo_dir = dir;
	}

	for (i = 0; i < ARRAY_SIZE(realm_luo_dir->entries); i++) {
		if (!realm_luo_dir->entries[i].first.phys ||
		    realm_luo_dir->entries[i].first.phys == vm->first.phys) {
			realm_luo_dir->entries[i] = *vm;
			return 0;
		}
	}

	return -ENOSPC;
}

static void realm_luo_dir_unregister(const struct kho_vmalloc *vm)
{
	bool any = false;
	unsigned int i;

	if (!vm || !vm->first.phys)
		return;

	guard(mutex)(&realm_luo_deferred_lock);
	if (!realm_luo_dir)
		return;

	for (i = 0; i < ARRAY_SIZE(realm_luo_dir->entries); i++) {
		if (realm_luo_dir->entries[i].first.phys == vm->first.phys)
			memset(&realm_luo_dir->entries[i], 0,
			       sizeof(realm_luo_dir->entries[i]));
		else if (realm_luo_dir->entries[i].first.phys)
			any = true;
	}

	if (!any) {
		kho_remove_subtree(realm_luo_dir);
		kho_unpreserve_free(realm_luo_dir);
		realm_luo_dir = NULL;
	}
}

static int __init realm_luo_init_reclaim_pages(void)
{
	struct realm_luo_cca_dir *dir;
	phys_addr_t dir_phys = 0;
	size_t dir_size = 0;
	unsigned int i;

	if (!is_kho_boot())
		return 0;

	realm_luo_fallback_sro = kzalloc_obj(*realm_luo_fallback_sro);

	if (kho_retrieve_subtree(REALM_LUO_SUBTREE_NAME, &dir_phys, &dir_size) ||
	    !dir_phys || dir_size < sizeof(*dir))
		return 0;

	dir = phys_to_virt(dir_phys);
	for (i = 0; i < ARRAY_SIZE(dir->entries); i++) {
		const struct kho_vmalloc *vm = &dir->entries[i];
		u32 entries_per_blk = (PAGE_SIZE / sizeof(u64)) << vm->order;
		struct kho_vmalloc_chunk *chunk;

		for (chunk = KHOSER_LOAD_PTR(vm->first); chunk;
		     chunk = KHOSER_LOAD_PTR(chunk->hdr.next)) {
			for (u32 k = 0; k < KHO_VMALLOC_SIZE && chunk->phys[k]; k++) {
				const u64 *pfns = phys_to_virt(chunk->phys[k]);

				for (u32 j = 0; j < entries_per_blk; j++) {
					unsigned long pfn;

					if (!(pfns[j] & REALM_LUO_PFN_DATA))
						continue;
					pfn = pfns[j] & REALM_LUO_PFN_MASK;
					WARN_ON_ONCE(xa_is_err(xa_store(&realm_luo_reclaim_pages,
									pfn, xa_mk_value(1),
									GFP_KERNEL)));
				}
			}
		}
	}

	kho_restore_free(dir);
	return 0;
}
late_initcall(realm_luo_init_reclaim_pages);

void kvm_arch_gmem_reclaim(kvm_pfn_t pfn, kvm_pfn_t nr_pages)
{
	unsigned long flags;
	kvm_pfn_t i;

	if (!is_kho_boot() || !static_branch_unlikely(&kvm_rmi_is_available) ||
	    likely(xa_empty(&realm_luo_reclaim_pages)))
		return;

	xa_lock_irqsave(&realm_luo_reclaim_pages, flags);
	for (i = 0; i < nr_pages; i++) {
		kvm_pfn_t cur_pfn = pfn + i;
		struct page *page;

		if (xa_load(&realm_luo_reclaim_pages, cur_pfn) != xa_mk_value(1))
			continue;

		page = pfn_to_page(cur_pfn);
		get_page(page);
		if (__xa_cmpxchg(&realm_luo_reclaim_pages, cur_pfn,
				 xa_mk_value(1), page, GFP_NOWAIT) !=
		    xa_mk_value(1))
			put_page(page);
	}
	xa_unlock_irqrestore(&realm_luo_reclaim_pages, flags);
}
#else
static inline bool realm_luo_defer_teardown(phys_addr_t rd_phys,
					    phys_addr_t pgd_phys,
					    size_t pgd_size, bool accounted)
{
	return false;
}

void kvm_arch_gmem_reclaim(kvm_pfn_t pfn, kvm_pfn_t nr_pages)
{
}
#endif

void kvm_destroy_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);

	guard(mutex)(&kvm->arch.config_lock);

	if (!kvm_realm_is_created(kvm)) {
		kvm_free_stage2_pgd(&kvm->arch.mmu);
		kfree(realm->sro);
		realm->sro = NULL;
		xa_destroy(&realm->luo_data_pages);
		return;
	}

	WRITE_ONCE(realm->luo_frozen, false);
	kvm_set_realm_state(kvm, REALM_STATE_DYING);

	/*
	 * REALM_DESTROY requires the realm to be non-live: all RECs must have
	 * been destroyed and the root RTTs must be empty. Unmap the IPA space
	 * and destroy any non-root RTTs before tearing down the RD. The root
	 * RTT pages are still owned by the RMM at this point, so keep the KVM
	 * pgtable alive until after REALM_DESTROY and undelegation.
	 */
	realm_unmap_stage2(kvm);

	if (realm->rd) {
		phys_addr_t rd_phys = virt_to_phys(realm->rd);

		if (WARN_ON(rmi_realm_terminate(rd_phys, realm->sro)))
			return;

		if (WARN_ON(realm_destroy_rtts(kvm)))
			return;

		if (rmi_realm_destroy(rd_phys, realm->sro)) {
			if (realm->luo_retrieved &&
			    realm_luo_defer_teardown(rd_phys,
						     kvm->arch.mmu.pgd_phys,
						     pgd_size, true)) {
				write_lock(&kvm->mmu_lock);
				free_percpu(kvm->arch.mmu.last_vcpu_ran);
				kvm->arch.mmu.last_vcpu_ran = NULL;
				kfree(kvm->arch.mmu.pgt);
				kvm->arch.mmu.pgt = NULL;
				kvm->arch.mmu.pgd_phys = 0;
				write_unlock(&kvm->mmu_lock);
				realm->rd = NULL;
				kvm_set_realm_state(kvm, REALM_STATE_DEAD);
				kfree(realm->sro);
				realm->sro = NULL;
				xa_destroy(&realm->luo_data_pages);
				return;
			}
			WARN_ON(1);
			return;
		}
		free_delegated_page(rd_phys);
		realm->rd = NULL;
	}

	if (WARN_ON(rmi_undelegate_range(kvm->arch.mmu.pgd_phys,
					 pgd_size)))
		return;

	kvm_set_realm_state(kvm, REALM_STATE_DEAD);

	/* Now that the realm is destroyed, free the entry-level RTTs. */
	kvm_free_stage2_pgd(&kvm->arch.mmu);

	kfree(realm->sro);
	realm->sro = NULL;
	xa_destroy(&realm->luo_data_pages);
}

int kvm_init_realm(struct kvm *kvm)
{
	struct realm *realm = &kvm->arch.realm;

	INIT_LIST_HEAD(&realm->rtt_list);
	spin_lock_init(&realm->rtt_lock);
	xa_init(&realm->luo_data_pages);

	realm->sro = kzalloc_obj(*realm->sro);
	if (!realm->sro)
		return -ENOMEM;

	return 0;
}

#ifdef CONFIG_LIVEUPDATE
int kvm_realm_luo_preserve(struct kvm *kvm,
			   struct kvm_arm64_cca_vm_luo_state *cca)
{
	guard(mutex)(&kvm->arch.config_lock);

	if (kvm_realm_state(kvm) != REALM_STATE_ACTIVE)
		return -EINVAL;

	memset(cca, 0, sizeof(*cca));
	WRITE_ONCE(kvm->arch.realm.luo_preserved, true);
	return 0;
}

static void kvm_realm_luo_unpreserve_cca(struct kvm *kvm,
					 struct kvm_arm64_cca_vm_luo_state *cca)
{
	u64 *pfns = kvm ? kvm->arch.realm.luo_pfns : NULL;
	u32 i;

	if (!cca)
		return;

	realm_luo_dir_unregister(&cca->rtt_pfns);

	if (cca->rd_phys)
		kho_unpreserve_pages(phys_to_page(cca->rd_phys), 1);
	if (cca->pgd_phys && cca->pgd_pages)
		kho_unpreserve_pages(phys_to_page(cca->pgd_phys), cca->pgd_pages);

	if (pfns) {
		for (i = 0; i < cca->nr_rtt_pages; i++)
			kho_unpreserve_pages(pfn_to_page(pfns[i]), 1);
	}
	if (cca->rtt_pfns.total_pages)
		kho_unpreserve_vmalloc(&cca->rtt_pfns);
	if (pfns) {
		vfree(pfns);
		kvm->arch.realm.luo_pfns = NULL;
	}

	memset(cca, 0, sizeof(*cca));
}

int kvm_realm_luo_freeze(struct kvm *kvm,
			 struct kvm_arm64_cca_vm_luo_state *cca)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	u32 pgd_pages = pgd_size >> PAGE_SHIFT;
	struct kvm_memory_slot *memslot;
	struct kvm_memslots *slots;
	struct kvm_vcpu *vcpu;
	unsigned long vcpu_idx, data_idx;
	u64 *pfns = NULL;
	u32 nr_rtt, nr_data = 0, total_pfns, i = 0;
	struct page *page;
	unsigned long flags;
	void *xa_entry;
	int ret, srcu_idx, bkt;

	guard(mutex)(&kvm->slots_lock);
	guard(mutex)(&kvm->arch.config_lock);

	if (kvm_realm_state(kvm) != REALM_STATE_ACTIVE || !realm->rd ||
	    !READ_ONCE(realm->luo_preserved))
		return -EINVAL;

	kvm_for_each_vcpu(vcpu_idx, vcpu, kvm) {
		if (!vcpu_is_rec(vcpu) || !vcpu->arch.rec.run ||
		    !READ_ONCE(vcpu->arch.rec.luo_preserved))
			return -EINVAL;
	}

	srcu_idx = srcu_read_lock(&kvm->srcu);
	slots = kvm_memslots(kvm);
	kvm_for_each_memslot(memslot, bkt, slots) {
		if (!kvm_slot_has_gmem(memslot))
			continue;
		if (!kvm_gmem_file_is_frozen(READ_ONCE(memslot->gmem.file))) {
			srcu_read_unlock(&kvm->srcu, srcu_idx);
			return -EINVAL;
		}
	}
	srcu_read_unlock(&kvm->srcu, srcu_idx);

	if (cca->rd_phys) {
		kvm_realm_luo_unpreserve_cca(kvm, cca);
		WRITE_ONCE(realm->luo_frozen, false);
	}

	/*
	 * Freeze under mmu_lock so no stage-2 fault, RIPAS change or MMU
	 * notifier can create, fold or free RTTs after this point; then sync
	 * the RMM donations, which the shared unmap may have changed.
	 */
	write_lock(&kvm->mmu_lock);
	WRITE_ONCE(realm->luo_frozen, true);
	realm_unmap_shared_range(kvm, 0, BIT(realm->ia_bits - 1), false);
	write_unlock(&kvm->mmu_lock);

	ret = arm_rmm_luo_sync_donations();
	if (ret)
		goto err_unfreeze;

	spin_lock_irqsave(&realm->rtt_lock, flags);
	nr_rtt = realm->nr_rtt_pages;
	spin_unlock_irqrestore(&realm->rtt_lock, flags);

	xa_for_each(&realm->luo_data_pages, data_idx, xa_entry) {
		if (!xa_is_value(xa_entry) ||
		    !(xa_to_value(xa_entry) & REALM_LUO_DATA_DELEGATED))
			continue;
		if (!kvm_gmem_pfn_is_frozen(kvm, data_idx)) {
			ret = -EINVAL;
			goto err_unfreeze;
		}
		nr_data++;
	}

	total_pfns = nr_rtt + nr_data;
	if (total_pfns) {
		u32 d_idx;

		pfns = vcalloc(total_pfns, sizeof(u64));
		if (!pfns) {
			ret = -ENOMEM;
			goto err_unfreeze;
		}

		spin_lock_irqsave(&realm->rtt_lock, flags);
		list_for_each_entry(page, &realm->rtt_list, lru) {
			if (i >= nr_rtt)
				break;
			pfns[i++] = page_to_pfn(page);
		}
		spin_unlock_irqrestore(&realm->rtt_lock, flags);
		nr_rtt = i;

		for (i = 0; i < nr_rtt; i++) {
			ret = kho_preserve_pages(pfn_to_page(pfns[i]), 1);
			if (ret)
				goto err_unpreserve_rtts;
		}

		d_idx = nr_rtt;
		xa_for_each(&realm->luo_data_pages, data_idx, xa_entry) {
			if (d_idx >= total_pfns)
				break;
			if (xa_is_value(xa_entry) &&
			    (xa_to_value(xa_entry) & REALM_LUO_DATA_DELEGATED))
				pfns[d_idx++] = REALM_LUO_PFN_DATA | data_idx;
		}

		ret = kho_preserve_vmalloc(pfns, &cca->rtt_pfns);
		if (ret)
			goto err_unpreserve_rtts;
	}

	ret = kho_preserve_pages(phys_to_page(kvm->arch.mmu.pgd_phys),
				 pgd_pages);
	if (ret)
		goto err_unpreserve_vmalloc;

	ret = kho_preserve_pages(virt_to_page(realm->rd), 1);
	if (ret)
		goto err_unpreserve_pgd;

	if (pfns && nr_data) {
		ret = realm_luo_dir_register(&cca->rtt_pfns);
		if (ret)
			goto err_unpreserve_rd;
	}

	realm->luo_pfns = pfns;
	cca->rd_phys = virt_to_phys(realm->rd);
	cca->pgd_phys = kvm->arch.mmu.pgd_phys;
	cca->pgd_pages = pgd_pages;
	cca->ia_bits = realm->ia_bits;
	cca->realm_state = REALM_STATE_ACTIVE;
	cca->nr_rtt_pages = nr_rtt;
	return 0;

err_unpreserve_rd:
	kho_unpreserve_pages(virt_to_page(realm->rd), 1);
err_unpreserve_pgd:
	kho_unpreserve_pages(phys_to_page(kvm->arch.mmu.pgd_phys), pgd_pages);
err_unpreserve_vmalloc:
	if (cca->rtt_pfns.total_pages)
		kho_unpreserve_vmalloc(&cca->rtt_pfns);
err_unpreserve_rtts:
	memset(&cca->rtt_pfns, 0, sizeof(cca->rtt_pfns));
	if (pfns) {
		while (i--)
			kho_unpreserve_pages(pfn_to_page(pfns[i]), 1);
		vfree(pfns);
	}
err_unfreeze:
	WRITE_ONCE(realm->luo_frozen, false);
	return ret;
}

void kvm_realm_luo_unfreeze(struct kvm *kvm,
			    struct kvm_arm64_cca_vm_luo_state *cca)
{
	/*
	 * Unpreserve the RTT pages while still frozen, so that no MMU notifier
	 * or fault can fold and free them underneath kvm_realm_luo_unpreserve_cca().
	 */
	guard(mutex)(&kvm->slots_lock);
	guard(mutex)(&kvm->arch.config_lock);
	kvm_realm_luo_unpreserve_cca(kvm, cca);
	WRITE_ONCE(kvm->arch.realm.luo_frozen, false);
}

void kvm_realm_luo_unpreserve(struct kvm *kvm,
			      struct kvm_arm64_cca_vm_luo_state *cca)
{
	guard(mutex)(&kvm->slots_lock);
	guard(mutex)(&kvm->arch.config_lock);
	kvm_realm_luo_unpreserve_cca(kvm, cca);
	WRITE_ONCE(kvm->arch.realm.luo_preserved, false);
	WRITE_ONCE(kvm->arch.realm.luo_frozen, false);
}

static void realm_luo_teardown_abandoned(struct page *rd_page,
					 struct page *pgd_page,
					 struct list_head *restored_rtts,
					 u32 nr_restored_rtts,
					 struct kvm_arm64_cca_vm_luo_state *cca)
{
	struct rmi_sro_state *dyn_sro __free(kfree) = kzalloc_obj(*dyn_sro);
	struct rmi_sro_state *sro = dyn_sro;
	phys_addr_t rd_phys = page_to_phys(rd_page);
	phys_addr_t pgd_phys = pgd_page ? page_to_phys(pgd_page) : 0;
	size_t pgd_size = (size_t)cca->pgd_pages * PAGE_SIZE;
	struct realm tmp_realm = {};
	u64 *pfns;
	u32 i;

	mutex_lock(&realm_luo_deferred_lock);
	if (!sro)
		sro = realm_luo_fallback_sro;
	if (WARN_ON_ONCE(!sro)) {
		/* Leak the Realm rather than issue RMI calls without an SRO. */
		mutex_unlock(&realm_luo_deferred_lock);
		return;
	}

	INIT_LIST_HEAD(&tmp_realm.rtt_list);
	spin_lock_init(&tmp_realm.rtt_lock);
	xa_init(&tmp_realm.luo_data_pages);
	tmp_realm.rd = page_to_virt(rd_page);
	tmp_realm.ia_bits = cca->ia_bits;
	tmp_realm.sro = sro;

	if (restored_rtts && !list_empty(restored_rtts)) {
		list_splice_tail_init(restored_rtts, &tmp_realm.rtt_list);
		tmp_realm.nr_rtt_pages = nr_restored_rtts;
	}

	if (cca->rtt_pfns.total_pages) {
		pfns = kho_restore_vmalloc(&cca->rtt_pfns);
		memset(&cca->rtt_pfns, 0, sizeof(cca->rtt_pfns));
		if (pfns) {
			for (i = 0; i < cca->nr_rtt_pages; i++) {
				struct page *rtt_page;
				void *rtt_va;

				rtt_page = kho_restore_pages(PFN_PHYS(pfns[i]),
							     1);
				if (!rtt_page)
					continue;
				rtt_va = page_to_virt(rtt_page);
				kvm_account_pgtable_pages(rtt_va, 1);
				list_add_tail(&rtt_page->lru,
					      &tmp_realm.rtt_list);
				tmp_realm.nr_rtt_pages++;
			}
			vfree(pfns);
			cca->nr_rtt_pages = 0;
		}
	}

	realm_unmap_private_range(NULL, &tmp_realm, 0, BIT(cca->ia_bits - 1),
				  false);
	WARN_ON(rmi_realm_terminate(rd_phys, sro));
	WARN_ON(realm_tear_down_rtt_range(&tmp_realm, 0, BIT(cca->ia_bits)));
	if (rmi_realm_destroy(rd_phys, sro)) {
		mutex_unlock(&realm_luo_deferred_lock);
		if (!realm_luo_defer_teardown(rd_phys, pgd_phys, pgd_size,
					      false))
			WARN_ON(1);
	} else {
		mutex_unlock(&realm_luo_deferred_lock);
		free_delegated_page(rd_phys);
		if (pgd_page &&
		    !WARN_ON(rmi_undelegate_range(pgd_phys, pgd_size)))
			free_pages_exact(page_to_virt(pgd_page), pgd_size);
	}

	realm_luo_drain_deferred();
}

int kvm_realm_luo_retrieve(struct kvm *kvm,
			   struct kvm_arm64_cca_vm_luo_state *cca)
{
	struct realm *realm = &kvm->arch.realm;
	size_t pgd_size = kvm_pgtable_stage2_pgd_size(kvm->arch.mmu.vtcr);
	u32 pfns_nr_pages = cca->rtt_pfns.total_pages;
	struct page *rd_page, *pgd_page;
	phys_addr_t pgd_phys = cca->pgd_phys;
	LIST_HEAD(restored_rtts);
	u32 nr_restored_rtts = 0;
	u64 *pfns = NULL;
	u32 i;

	if (!cca->rd_phys || !cca->pgd_phys ||
	    cca->realm_state != REALM_STATE_ACTIVE ||
	    cca->ia_bits != VTCR_EL2_IPA(kvm->arch.mmu.vtcr) ||
	    cca->pgd_pages != (pgd_size >> PAGE_SHIFT))
		return -EINVAL;

	if (cca->nr_rtt_pages &&
	    (!cca->rtt_pfns.first.phys ||
	     pfns_nr_pages <
	     (PAGE_ALIGN(cca->nr_rtt_pages * sizeof(u64)) >> PAGE_SHIFT)))
		return -EINVAL;

	rd_page = kho_restore_pages(cca->rd_phys, 1);
	if (!rd_page)
		return -ENOMEM;
	cca->rd_phys = 0;

	pgd_page = kho_restore_pages(cca->pgd_phys, cca->pgd_pages);
	if (!pgd_page) {
		realm_luo_teardown_abandoned(rd_page, NULL, NULL, 0, cca);
		return -ENOMEM;
	}
	cca->pgd_phys = 0;

	if (pfns_nr_pages) {
		pfns = kho_restore_vmalloc(&cca->rtt_pfns);
		memset(&cca->rtt_pfns, 0, sizeof(cca->rtt_pfns));
		if (!pfns) {
			realm_luo_teardown_abandoned(rd_page, pgd_page, NULL,
						     0, cca);
			return -ENOMEM;
		}

		for (i = 0; i < cca->nr_rtt_pages; i++) {
			struct page *rtt_page;

			rtt_page = kho_restore_pages(PFN_PHYS(pfns[i]), 1);
			if (!rtt_page) {
				u32 j;

				for (j = i + 1; j < cca->nr_rtt_pages; j++) {
					rtt_page = kho_restore_pages(PFN_PHYS(pfns[j]), 1);
					if (!rtt_page)
						continue;
					kvm_account_pgtable_pages(page_to_virt(rtt_page), 1);
					list_add_tail(&rtt_page->lru, &restored_rtts);
					nr_restored_rtts++;
				}
				vfree(pfns);
				cca->nr_rtt_pages = 0;
				realm_luo_teardown_abandoned(rd_page, pgd_page,
							     &restored_rtts,
							     nr_restored_rtts,
							     cca);
				return -ENOMEM;
			}
			kvm_account_pgtable_pages(page_to_virt(rtt_page), 1);
			list_add_tail(&rtt_page->lru, &restored_rtts);
			nr_restored_rtts++;
		}

		/*
		 * Carry this Realm's DATA granules over, so that freezing it
		 * again records them for the next kernel.
		 */
		for (i = cca->nr_rtt_pages;
		     i < pfns_nr_pages * PAGE_SIZE / sizeof(u64); i++) {
			if (!(pfns[i] & REALM_LUO_PFN_DATA))
				continue;
			if (xa_is_err(xa_store(&realm->luo_data_pages,
					       pfns[i] & REALM_LUO_PFN_MASK,
					       xa_mk_value(1),
					       GFP_KERNEL_ACCOUNT))) {
				xa_destroy(&realm->luo_data_pages);
				vfree(pfns);
				cca->nr_rtt_pages = 0;
				realm_luo_teardown_abandoned(rd_page, pgd_page,
							     &restored_rtts,
							     nr_restored_rtts,
							     cca);
				return -ENOMEM;
			}
		}
		vfree(pfns);
		cca->nr_rtt_pages = 0;
	}

	/*
	 * Replace the freshly allocated Stage-2 root PGD from
	 * kvm_init_stage2_mmu() with the preserved RMM-delegated root RTT
	 * and mark the Realm active only after all KHO pages are restored.
	 */
	kvm->arch.mmu.pgt->mm_ops->free_pages_exact(__va(kvm->arch.mmu.pgd_phys),
						    pgd_size);
	kvm_account_pgtable_pages(page_to_virt(pgd_page), cca->pgd_pages);
	kvm->arch.mmu.pgd_phys = pgd_phys;
	kvm->arch.mmu.pgt->pgd = (kvm_pteref_t)page_to_virt(pgd_page);

	list_splice_tail(&restored_rtts, &realm->rtt_list);
	realm->nr_rtt_pages = nr_restored_rtts;
	realm->rd = page_to_virt(rd_page);
	realm->ia_bits = cca->ia_bits;
	realm->luo_retrieved = true;
	kvm_set_realm_state(kvm, REALM_STATE_ACTIVE);

	return 0;
}

void kvm_realm_luo_finish(struct kvm *kvm,
			  struct kvm_arm64_cca_vm_luo_state *cca)
{
	struct page *rd_page = NULL, *pgd_page = NULL;

	if (kvm || !cca) {
		realm_luo_drain_deferred();
		return;
	}

	if (cca->rd_phys) {
		rd_page = kho_restore_pages(cca->rd_phys, 1);
		cca->rd_phys = 0;
	}
	if (cca->pgd_phys) {
		pgd_page = kho_restore_pages(cca->pgd_phys, cca->pgd_pages);
		cca->pgd_phys = 0;
	}

	if (rd_page) {
		realm_luo_teardown_abandoned(rd_page, pgd_page, NULL, 0, cca);
	} else {
		if (cca->rtt_pfns.total_pages) {
			u64 *pfns = kho_restore_vmalloc(&cca->rtt_pfns);

			memset(&cca->rtt_pfns, 0, sizeof(cca->rtt_pfns));
			if (pfns) {
				for (u32 i = 0; i < cca->nr_rtt_pages; i++) {
					if (kho_restore_pages(PFN_PHYS(pfns[i]), 1))
						free_delegated_page(PFN_PHYS(pfns[i]));
				}
				vfree(pfns);
				cca->nr_rtt_pages = 0;
			}
		}
		if (pgd_page) {
			size_t pgd_size = (size_t)cca->pgd_pages * PAGE_SIZE;
			phys_addr_t pgd_phys = page_to_phys(pgd_page);

			if (!WARN_ON(rmi_undelegate_range(pgd_phys, pgd_size)))
				free_pages_exact(page_to_virt(pgd_page), pgd_size);
		}
		realm_luo_drain_deferred();
	}
}

static void kvm_realm_rec_save_state(struct kvm_vcpu *vcpu,
				     struct kvm_arm64_cca_rec_luo_state *cca,
				     bool is_freeze)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	u32 flags = KVM_ARM64_CCA_REC_F_FINALIZED;

	if (kvm_test_request(KVM_REQ_RMI, vcpu))
		flags |= KVM_ARM64_CCA_REC_F_REQ_RMI;
	if (is_freeze && vcpu->mmio_needed)
		flags |= KVM_ARM64_CCA_REC_F_EMULATED_MMIO;

	cca->mpidr = rec->mpidr;
	cca->rec_phys = rec->rec_phys;
	cca->run_phys = rec->run_phys;
	cca->fault_esr_el2 = vcpu->arch.fault.esr_el2;
	cca->fault_far_el2 = vcpu->arch.fault.far_el2;
	cca->fault_hpfar_el2 = vcpu->arch.fault.hpfar_el2;
	cca->flags = flags;
	cca->reserved = 0;
	cca->rd_phys = virt_to_phys(vcpu->kvm->arch.realm.rd);
}

int kvm_realm_rec_luo_preserve(struct kvm_vcpu *vcpu,
			       struct kvm_arm64_cca_rec_luo_state *cca)
{
	struct realm_rec *rec = &vcpu->arch.rec;
	int ret;

	if (!vcpu_is_rec(vcpu) ||
	    kvm_realm_state(vcpu->kvm) != REALM_STATE_ACTIVE ||
	    !READ_ONCE(vcpu->kvm->arch.realm.luo_preserved) ||
	    !vcpu->kvm->arch.realm.rd ||
	    !rec->rec_page || !rec->run)
		return -EINVAL;

	ret = kho_preserve_pages(virt_to_page(rec->rec_page), 1);
	if (ret)
		return ret;

	ret = kho_preserve_pages(virt_to_page(rec->run), 1);
	if (ret) {
		kho_unpreserve_pages(virt_to_page(rec->rec_page), 1);
		return ret;
	}

	kvm_realm_rec_save_state(vcpu, cca, false);
	WRITE_ONCE(rec->luo_preserved, true);
	return 0;
}

int kvm_realm_rec_luo_freeze(struct kvm_vcpu *vcpu,
			     struct kvm_arm64_cca_rec_luo_state *cca)
{
	struct realm_rec *rec = &vcpu->arch.rec;

	if (!vcpu_is_rec(vcpu) ||
	    kvm_realm_state(vcpu->kvm) != REALM_STATE_ACTIVE ||
	    !READ_ONCE(vcpu->kvm->arch.realm.luo_preserved) ||
	    !vcpu->kvm->arch.realm.rd ||
	    !rec->rec_page || !rec->run)
		return -EINVAL;

	if (vcpu->mmio_needed && !kvm_vcpu_dabt_iswrite(vcpu))
		return -EBUSY;

	kvm_realm_rec_save_state(vcpu, cca, true);
	return 0;
}

void kvm_realm_rec_luo_unpreserve(struct kvm_vcpu *vcpu,
				  struct kvm_arm64_cca_rec_luo_state *cca)
{
	if (vcpu)
		WRITE_ONCE(vcpu->arch.rec.luo_preserved, false);

	if (!cca)
		return;

	if (cca->run_phys)
		kho_unpreserve_pages(phys_to_page(cca->run_phys), 1);
	if (cca->rec_phys)
		kho_unpreserve_pages(phys_to_page(cca->rec_phys), 1);

	memset(cca, 0, sizeof(*cca));
}

int kvm_realm_rec_luo_retrieve(struct kvm_vcpu *vcpu,
			       struct kvm_arm64_cca_rec_luo_state *cca)
{
	u32 valid_flags = KVM_ARM64_CCA_REC_F_REQ_RMI |
			  KVM_ARM64_CCA_REC_F_FINALIZED |
			  KVM_ARM64_CCA_REC_F_EMULATED_MMIO;
	struct realm *realm = &vcpu->kvm->arch.realm;
	struct realm_rec *rec = &vcpu->arch.rec;
	struct page *rec_page, *run_page;

	if (!vcpu_is_rec(vcpu) || !cca ||
	    kvm_realm_state(vcpu->kvm) != REALM_STATE_ACTIVE ||
	    !realm->luo_retrieved || !realm->rd)
		return -EINVAL;

	if (!(cca->flags & KVM_ARM64_CCA_REC_F_FINALIZED) ||
	    (cca->flags & ~valid_flags) || cca->reserved ||
	    !cca->rec_phys || !cca->run_phys ||
	    !PAGE_ALIGNED(cca->rec_phys) || !PAGE_ALIGNED(cca->run_phys) ||
	    cca->rd_phys != virt_to_phys(realm->rd) ||
	    cca->mpidr != kvm_vcpu_get_mpidr_aff(vcpu))
		return -EINVAL;

	rec->sro = kzalloc_obj(*rec->sro);
	if (!rec->sro)
		return -ENOMEM;

	rec_page = kho_restore_pages(cca->rec_phys, 1);
	if (!rec_page) {
		kfree(rec->sro);
		rec->sro = NULL;
		return -ENOMEM;
	}

	run_page = kho_restore_pages(cca->run_phys, 1);
	if (!run_page) {
		if (!WARN_ON(rmi_rec_destroy(cca->rec_phys, rec->sro)))
			free_delegated_page(cca->rec_phys);
		cca->rec_phys = 0;
		kfree(rec->sro);
		rec->sro = NULL;
		return -ENOMEM;
	}

	rec->mpidr = cca->mpidr;
	rec->rec_page = page_to_virt(rec_page);
	rec->rec_phys = cca->rec_phys;
	rec->run_phys = cca->run_phys;

	vcpu->arch.fault.esr_el2 = cca->fault_esr_el2;
	vcpu->arch.fault.far_el2 = cca->fault_far_el2;
	vcpu->arch.fault.hpfar_el2 = cca->fault_hpfar_el2;

	if (cca->flags & KVM_ARM64_CCA_REC_F_REQ_RMI)
		kvm_make_request(KVM_REQ_RMI, vcpu);
	if (cca->flags & KVM_ARM64_CCA_REC_F_EMULATED_MMIO)
		((struct rec_run *)page_to_virt(run_page))->enter.flags |=
			REC_ENTER_FLAG_EMULATED_MMIO;
	WRITE_ONCE(rec->run, page_to_virt(run_page));

	cca->rec_phys = 0;
	cca->run_phys = 0;
	return 0;
}

void kvm_realm_rec_luo_finish(struct kvm_vcpu *vcpu,
			      struct kvm_arm64_cca_rec_luo_state *cca)
{
	struct page *rec_page, *run_page;

	if (vcpu || !cca || (!cca->rec_phys && !cca->run_phys)) {
		realm_luo_drain_deferred();
		return;
	}

	if (cca->run_phys) {
		run_page = kho_restore_pages(cca->run_phys, 1);
		if (run_page)
			__free_page(run_page);
		cca->run_phys = 0;
	}

	if (cca->rec_phys) {
		rec_page = kho_restore_pages(cca->rec_phys, 1);
		if (rec_page) {
			struct rmi_sro_state *dyn_sro __free(kfree) = kzalloc_obj(*dyn_sro);
			struct rmi_sro_state *sro = dyn_sro;

			mutex_lock(&realm_luo_deferred_lock);
			if (!sro)
				sro = realm_luo_fallback_sro;
			if (!WARN_ON_ONCE(!sro) &&
			    !WARN_ON(rmi_rec_destroy(cca->rec_phys, sro)))
				free_delegated_page(cca->rec_phys);
			mutex_unlock(&realm_luo_deferred_lock);
		}
		cca->rec_phys = 0;
	}

	realm_luo_drain_deferred();
}
#endif /* CONFIG_LIVEUPDATE */

static int rmm_check_features(void)
{
	if (kvm_lpa2_is_enabled() &&
	    !rmi_has_feature(0, RMI_FEATURE_REGISTER_0_LPA2)) {
		kvm_err("RMM doesn't support LPA2\n");
		return -ENXIO;
	}

	if (!rmi_has_feature(1, RMI_FEATURE_REGISTER_1_HASH_SHA_256)) {
		kvm_err("RMM doesn't support SHA-256 measurements\n");
		return -ENXIO;
	}

	return 0;
}

void kvm_init_rmi(void)
{
	/*
	 * TODO: Support Realm guests in nVHE mode, this will require adding
	 * EL2 stub(s) for REC entry and possibly other things.
	 */
	if (!is_kernel_in_hyp_mode())
		return;

	if (!is_rmi_available())
		return;

	if (rmm_check_features())
		return;

	kvm_info("Realm guests supported\n");
	static_branch_enable(&kvm_rmi_is_available);
}
