/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 */

/**
 * DOC: Live Update Orchestrator ABI
 *
 * Live Update Orchestrator uses the stable Application Binary Interface
 * defined below to pass state from a source kernel to a target kernel.
 * The ABI is built upon the Kexec HandOver framework and registers the
 * central `struct luo_ser` via the KHO raw subtree API.
 *
 * This interface is a contract. Serialized structures start with a fixed
 * 128-byte feature header (`struct luo_feature_hdr`) holding the source
 * kernel's structure `size` and 15 chained 64-bit feature flags entries
 * (`flags[LUO_FEAT_NR_FLAGS]`). Each entry encodes up to 31 features as
 * 2-bit `0b<req><active>` pairs (`enum luo_feat_state`), with
 * `LUO_FEAT_EXT_MASK` in bits `[63:62]` chaining to the next entry (up to
 * 465 features total). Because the header size is fixed at 128 bytes,
 * payload field offsets do not depend on how many flags entries a source
 * kernel uses.
 *
 * Truth table (`(req,active)` pairs per feature)::
 *
 *   Source Target Action
 *   (1,0)  (x,x)  Reject -EINVAL: invalid source kernel (req without active)
 *   (x,x)  (1,0)  Reject -EINVAL: invalid target kernel (req without active)
 *   (0,0)  (0,0)  Accept: feature absent
 *   (0,0)  (0,1)  Accept: feature absent
 *   (0,0)  (1,1)  Reject -EOPNOTSUPP: target kernel requires the feature
 *   (0,1)  (0,0)  Accept: ignore payload data
 *   (1,1)  (0,0)  Reject -EOPNOTSUPP: source kernel requires the feature
 *   (x,1)  (x,1)  Accept: use payload data
 *
 * The relative order and offsets of fields in serialized structures must
 * remain unchanged as features are added or retired. New fields are always
 * appended at the end of the structure under a new feature flag, and
 * retired fields are kept in place so that the offsets of subsequent
 * fields never shift. If a field's type or format needs to change, the
 * existing field and feature are kept intact (and retired when no longer
 * needed) and a new feature flag with a new appended field of the new type
 * is added.
 *
 * In the target kernel, fields of a `LUO_FEAT_REQUIRED` feature are
 * guaranteed to be present once `luo_feature_hdr_validate()` succeeds,
 * whereas fields of a `LUO_FEAT_OPTIONAL` feature should be accessed only
 * after verifying that the feature is active in the source kernel's header::
 *
 *   if (luo_feature_is_active(&ser->features, FEAT_X))
 *           val = ser->x_field;
 *
 * All current `struct luo_ser` fields (`liveupdate_num`, `sessions_pa`,
 * `flbs_pa`) belong to `LUO_CORE_FEAT_CORE` (`LUO_FEAT_REQUIRED` in
 * `luo_core_features`). Future changes add new entries to
 * `enum luo_core_feature` before `LUO_CORE_FEAT_MAX`.
 *
 * KHO Structure Overview:
 *   The entire LUO state is encapsulated within a single KHO entry named "LUO".
 *   This entry contains the `struct luo_ser` structure.
 *
 * Serialization Structures:
 *   - struct luo_ser:
 *     The central ABI structure that contains the overall state of the LUO.
 *     It includes the feature header (with struct size and 2-bit feature flag
 *     pairs), and the core feature (`LUO_CORE_FEAT_CORE`) fields: the
 *     liveupdate-number and pointers to sessions and FLBs.
 *
 *   - struct luo_session_ser:
 *     Metadata for a single session, including its name and a physical pointer
 *     to the first `struct kho_block_header_ser` for all files in that session.
 *     Multiple blocks are linked via the `next` field in the header.
 *
 *   - struct luo_file_ser:
 *     Metadata for a single preserved file. Contains the handler `name` string
 *     to find the correct handler in the target kernel, a user-provided
 *     `token` for identification, and an opaque `data` handle for the handler
 *     to use.
 *
 *   - struct luo_flb_header_ser:
 *     Header for the FLB array. Contains the total page count of the
 *     preserved memory block and the number of `struct luo_flb_ser` entries
 *     that follow.
 *
 *   - struct luo_flb_ser:
 *     Metadata for a single preserved global object. Contains its FLB `name`
 *     string, an opaque `data` handle, and the `count` number of files
 *     depending on it.
 */

#ifndef _LINUX_KHO_ABI_LUO_H
#define _LINUX_KHO_ABI_LUO_H

#include <linux/array_size.h>
#include <linux/bits.h>
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/errno.h>
#include <linux/kho/abi/block.h>
#include <linux/types.h>
#include <uapi/linux/liveupdate.h>

/*
 * The LUO state is registered under this KHO entry name.
 */
#define LUO_KHO_ENTRY_NAME	"LUO"

#define LUO_FEAT_PER_FLAGS	31
#define LUO_FEAT_NR_FLAGS	15
#define LUO_FEAT_MAX		(LUO_FEAT_NR_FLAGS * LUO_FEAT_PER_FLAGS)
#define LUO_FEAT_EXT_MASK	GENMASK_ULL(63, 62)
#define LUO_FEAT_ACTIVE_MASK	(0x5555555555555555ULL & ~LUO_FEAT_EXT_MASK)
#define LUO_FEAT_REQ_MASK	(0xaaaaaaaaaaaaaaaaULL & ~LUO_FEAT_EXT_MASK)

#define LUO_FEAT_FLAGS_IDX(f)	((unsigned int)(f) / LUO_FEAT_PER_FLAGS)
#define LUO_FEAT_SLOT(f)	((unsigned int)(f) % LUO_FEAT_PER_FLAGS)

#define LUO_FEAT_ACTIVE(f)	BIT_ULL(2 * LUO_FEAT_SLOT(f))
#define LUO_FEAT_REQ(f)		BIT_ULL(2 * LUO_FEAT_SLOT(f) + 1)

/**
 * enum luo_feat_state - 2-bit state of a LUO feature (`0b<req><active>`).
 * @LUO_FEAT_DISABLED: Feature is inactive (`req=0, active=0`).
 * @LUO_FEAT_OPTIONAL: Feature is active and optional (`req=0, active=1`).
 * @LUO_FEAT_REQUIRED: Feature is active and required (`req=1, active=1`).
 */
enum luo_feat_state {
	LUO_FEAT_DISABLED = 0b00,
	LUO_FEAT_OPTIONAL = 0b01,
	LUO_FEAT_REQUIRED = 0b11,
};

/**
 * struct luo_feature_hdr - Fixed 128-byte header for serialized LUO ABI structures.
 * @size:  Size in bytes of the source kernel's enclosing serialized structure.
 * @flags: Chained 64-bit feature flags entries (`0 .. LUO_FEAT_NR_FLAGS - 1`).
 *         Each entry holds 31 2-bit feature pairs (`[2*slot + 1 : 2*slot]`)
 *         plus %LUO_FEAT_EXT_MASK in bits `[63:62]` when the next entry is
 *         active.
 */
struct luo_feature_hdr {
	u64 size;
	u64 flags[LUO_FEAT_NR_FLAGS];
} __packed;

static_assert(sizeof(struct luo_feature_hdr) == 128);

/**
 * luo_feature_hdr_for_each_flags - Iterate over chained flags entries in @hdr.
 * @hdr: Pointer to the &struct luo_feature_hdr to iterate.
 * @idx: Loop cursor of type `unsigned int` (`0 .. LUO_FEAT_NR_FLAGS - 1`).
 */
#define luo_feature_hdr_for_each_flags(hdr, idx)			\
	for ((idx) = 0; (idx) < LUO_FEAT_NR_FLAGS;			\
	     (idx) = (((hdr)->flags[idx] & LUO_FEAT_EXT_MASK) ==	\
		      LUO_FEAT_EXT_MASK) ? (idx) + 1 : LUO_FEAT_NR_FLAGS)

/**
 * luo_feature_hdr_get_flags - Get the flags entry containing feature @feat.
 * @hdr:  Pointer to the source kernel's feature header.
 * @feat: Feature index (`0 .. LUO_FEAT_MAX - 1`).
 *
 * Return: The u64 flags entry containing @feat if the extension chain reaches
 *         it, or 0 otherwise.
 */
static inline u64
luo_feature_hdr_get_flags(const struct luo_feature_hdr *hdr,
			  unsigned int feat)
{
	unsigned int target_idx = LUO_FEAT_FLAGS_IDX(feat);
	unsigned int idx;

	if (target_idx >= LUO_FEAT_NR_FLAGS)
		return 0;

	luo_feature_hdr_for_each_flags(hdr, idx) {
		if (idx == target_idx)
			return hdr->flags[idx];
	}

	return 0;
}

/**
 * luo_feature_is_active - Test whether feature @feat is active in @hdr.
 * @hdr:  Pointer to the source kernel's feature header.
 * @feat: Feature index (`0 .. LUO_FEAT_MAX - 1`).
 *
 * Return: true if the source kernel marked @feat active, false otherwise.
 */
static inline bool luo_feature_is_active(const struct luo_feature_hdr *hdr,
					 unsigned int feat)
{
	return luo_feature_hdr_get_flags(hdr, feat) & LUO_FEAT_ACTIVE(feat);
}

/**
 * luo_feature_is_req - Test whether feature @feat is required in @hdr.
 * @hdr:  Pointer to the source kernel's feature header.
 * @feat: Feature index (`0 .. LUO_FEAT_MAX - 1`).
 *
 * Return: true if the source kernel marked @feat required, false otherwise.
 */
static inline bool luo_feature_is_req(const struct luo_feature_hdr *hdr,
				      unsigned int feat)
{
	return luo_feature_hdr_get_flags(hdr, feat) & LUO_FEAT_REQ(feat);
}

/**
 * luo_feature_pack_entry - Pack up to 31 feature states into a flags entry.
 * @features:    Array of &enum luo_feat_state values indexed by feature ID.
 * @nr_features: Number of elements in @features.
 * @idx:         Flags entry index (`0 .. LUO_FEAT_NR_FLAGS - 1`).
 *
 * Return: The packed 64-bit flags entry for @idx (without %LUO_FEAT_EXT_MASK).
 */
static inline u64
luo_feature_pack_entry(const u8 *features, size_t nr_features,
		       unsigned int idx)
{
	unsigned int base = idx * LUO_FEAT_PER_FLAGS;
	unsigned int slot;
	u64 flags = 0;

	for (slot = 0; slot < LUO_FEAT_PER_FLAGS && base + slot < nr_features;
	     slot++)
		flags |= (u64)(features[base + slot] & 0b11) << (2 * slot);

	return flags;
}

/**
 * __luo_feature_hdr_init - Initialize a serialized LUO feature header.
 * @hdr:         Pointer to the feature header to initialize.
 * @size:        Byte size of the enclosing serialized structure.
 * @features:    Array of &enum luo_feat_state values for the source kernel.
 * @nr_features: Number of elements in @features (`<= LUO_FEAT_MAX`).
 */
static inline void
__luo_feature_hdr_init(struct luo_feature_hdr *hdr, u64 size,
		       const u8 *features, size_t nr_features)
{
	bool ext = false;
	int idx;

	hdr->size = size;
	for (idx = LUO_FEAT_NR_FLAGS - 1; idx >= 0; idx--) {
		u64 flags = luo_feature_pack_entry(features, nr_features, idx);

		WARN_ON_ONCE(((flags & LUO_FEAT_REQ_MASK) >> 1) &
			     ~(flags & LUO_FEAT_ACTIVE_MASK));
		if (ext)
			flags |= LUO_FEAT_EXT_MASK;
		else if (flags)
			ext = true;
		hdr->flags[idx] = flags;
	}
}

/**
 * luo_feature_hdr_init - Initialize a serialized LUO feature header.
 * @hdr:      Pointer to the feature header to initialize.
 * @size:     Byte size of the enclosing serialized structure.
 * @features: Fixed-size `u8` array of &enum luo_feat_state entries.
 */
#define luo_feature_hdr_init(hdr, size, features)			\
({									\
	BUILD_BUG_ON(ARRAY_SIZE(features) > LUO_FEAT_MAX);		\
	__luo_feature_hdr_init(hdr, size, features,			\
			       ARRAY_SIZE(features));			\
})

/**
 * __luo_feature_hdr_validate - Validate a source kernel's LUO feature header
 *                              against the target kernel's feature array.
 * @hdr:         Pointer to the feature header from the source kernel.
 * @features:    Array of &enum luo_feat_state values for the target kernel.
 * @nr_features: Number of elements in @features (`<= LUO_FEAT_MAX`).
 *
 * Return: 0 if compatible, -EINVAL on malformed header or `(req=1, active=0)`
 *         feature state, or -EOPNOTSUPP on required feature mismatch.
 */
static inline int
__luo_feature_hdr_validate(const struct luo_feature_hdr *hdr,
			   const u8 *features, size_t nr_features)
{
	bool src_ext = true, target_ext = (nr_features > 0);
	unsigned int idx;

	if (hdr->size < sizeof(*hdr))
		return -EINVAL;

	for (idx = 0; idx < LUO_FEAT_NR_FLAGS && (src_ext || target_ext); idx++) {
		u64 src = src_ext ? hdr->flags[idx] : 0;
		u64 target = target_ext ?
			luo_feature_pack_entry(features, nr_features, idx) : 0;
		u64 ext = src & LUO_FEAT_EXT_MASK;
		u64 src_act = src & LUO_FEAT_ACTIVE_MASK;
		u64 src_req = (src & LUO_FEAT_REQ_MASK) >> 1;
		u64 target_act = target & LUO_FEAT_ACTIVE_MASK;
		u64 target_req = (target & LUO_FEAT_REQ_MASK) >> 1;

		if (ext && (ext != LUO_FEAT_EXT_MASK ||
			    idx == LUO_FEAT_NR_FLAGS - 1))
			return -EINVAL;
		if (src_req & ~src_act)
			return -EINVAL;
		if (WARN_ON_ONCE(target_req & ~target_act))
			return -EINVAL;
		if ((src_req & ~target_act) || (target_req & ~src_act))
			return -EOPNOTSUPP;

		src_ext = (ext == LUO_FEAT_EXT_MASK);
		target_ext = ((idx + 1) * LUO_FEAT_PER_FLAGS < nr_features);
	}

	return 0;
}

/**
 * luo_feature_hdr_validate - Validate a source kernel's LUO feature header
 *                            against the target kernel's feature array.
 * @hdr:      Pointer to the feature header from the source kernel.
 * @features: Fixed-size `u8` array of &enum luo_feat_state entries.
 *
 * Return: 0 if compatible, -EINVAL on malformed header or feature state, or
 *         -EOPNOTSUPP on required feature mismatch.
 */
#define luo_feature_hdr_validate(hdr, features)				\
({									\
	BUILD_BUG_ON(ARRAY_SIZE(features) > LUO_FEAT_MAX);		\
	__luo_feature_hdr_validate(hdr, features,			\
				   ARRAY_SIZE(features));		\
})

/**
 * enum luo_core_feature - Feature indices for &struct luo_ser.
 * @LUO_CORE_FEAT_CORE: Core feature covering `liveupdate_num`, `sessions_pa`,
 *                      and `flbs_pa`.
 * @LUO_CORE_FEAT_MAX:  Number of defined &enum luo_core_feature features.
 */
enum luo_core_feature {
	LUO_CORE_FEAT_CORE = 0,
	LUO_CORE_FEAT_MAX,
};

static_assert((int)LUO_CORE_FEAT_MAX <= LUO_FEAT_MAX);

/**
 * struct luo_ser - Centralized LUO ABI header.
 * @features:       ABI feature and size header for luo_ser.
 * @liveupdate_num: A counter tracking the number of successful live updates.
 * @sessions_pa:    Physical address of the first session block header.
 * @flbs_pa:        Physical address of the FLB header.
 *
 * This structure is the root of all preserved LUO state.
 */
struct luo_ser {
	struct luo_feature_hdr features;
	u64 liveupdate_num;
	u64 sessions_pa;
	u64 flbs_pa;
} __packed;

/**
 * struct luo_file_ser - Represents the serialized preserves files.
 * @name:        File handler name string.
 * @data:        Private data
 * @token:       User provided token for this file
 *
 * Layout changes must be gated by a required feature in &enum luo_core_feature.
 */
struct luo_file_ser {
	char name[LIVEUPDATE_HNDL_NAME_LENGTH];
	u64 data;
	u64 token;
} __packed;

/**
 * struct luo_file_set_ser - Represents the serialized metadata for file set
 * @files:   The physical address of the first `struct kho_block_header_ser`.
 *           This structure is the header for a block of memory containing
 *           an array of `struct luo_file_ser` entries. Multiple blocks are
 *           linked via the `next` field in the header.
 * @count:   The total number of files that were part of this session during
 *           serialization. Used for iteration and validation during
 *           restoration.
 */
struct luo_file_set_ser {
	u64 files;
	u64 count;
} __packed;

/**
 * struct luo_session_ser - Represents the serialized metadata for a LUO session.
 * @name:         The unique name of the session, provided by the userspace at
 *                the time of session creation.
 * @file_set_ser: Serialized files belonging to this session,
 *
 * This structure is used to package session-specific metadata for transfer
 * between kernels via Kexec Handover. An array of these structures (one per
 * session) is created and passed to the target kernel, allowing it to
 * reconstruct the session context.
 *
 * Layout changes must be gated by a required feature in &enum luo_core_feature.
 */
struct luo_session_ser {
	char name[LIVEUPDATE_SESSION_NAME_LENGTH];
	struct luo_file_set_ser file_set_ser;
} __packed;

/* The max size is set so it can be reliably used during in serialization */
#define LIVEUPDATE_FLB_NAME_LENGTH	48

/**
 * struct luo_flb_header_ser - Header for the serialized FLB data block.
 * @pgcnt: The total number of pages occupied by the entire preserved memory
 *         region, including this header and the subsequent array of
 *         &struct luo_flb_ser entries.
 * @count: The number of &struct luo_flb_ser entries that follow this header
 *         in the memory block.
 *
 * This structure is located at the physical address specified by the
 * flbs_pa in luo_ser.
 *
 * Layout changes must be gated by a required feature in &enum luo_core_feature.
 */
struct luo_flb_header_ser {
	u64 pgcnt;
	u64 count;
} __packed;

/**
 * struct luo_flb_ser - Represents the serialized state of a single FLB object.
 * @name:    The unique name string of the FLB object, used to find the
 *           corresponding &struct liveupdate_flb in the target kernel.
 * @data:    The opaque u64 handle returned by the FLB's .preserve() operation
 *           in the source kernel. This handle encapsulates the entire state
 *           needed for restoration.
 * @count:   The reference count at the time of serialization; i.e., the number
 *           of preserved files that depended on this FLB. This is used by the
 *           target kernel to correctly manage the FLB's lifecycle.
 *
 * An array of these structures is created in a preserved memory region and
 * passed to the target kernel. Each entry allows the LUO core to restore
 * one global, shared object.
 *
 * Layout changes must be gated by a required feature in &enum luo_core_feature.
 */
struct luo_flb_ser {
	char name[LIVEUPDATE_FLB_NAME_LENGTH];
	u64 data;
	u64 count;
} __packed;

/* Kernel Live Update Test ABI */
#ifdef CONFIG_LIVEUPDATE_TEST
#define LIVEUPDATE_TEST_FLB_NAME(i)	"liveupdate-test-flb-v" #i
#endif

#endif /* _LINUX_KHO_ABI_LUO_H */
