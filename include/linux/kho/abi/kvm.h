/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2026, Google LLC.
 * Tarun Sahu <tarunsahu@google.com>
 */

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

#ifndef _LINUX_KHO_ABI_KVM_H
#define _LINUX_KHO_ABI_KVM_H

#include <linux/kho/abi/kexec_handover.h>
#include <linux/kho/abi/luo.h>
#include <linux/types.h>

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

#endif /* _LINUX_KHO_ABI_KVM_H */
