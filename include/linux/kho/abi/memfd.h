/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Copyright (c) 2025, Google LLC.
 * Pasha Tatashin <pasha.tatashin@soleen.com>
 *
 * Copyright (C) 2025 Amazon.com Inc. or its affiliates.
 * Pratyush Yadav <ptyadav@amazon.de>
 */

#ifndef _LINUX_KHO_ABI_MEMFD_H
#define _LINUX_KHO_ABI_MEMFD_H

#include <linux/types.h>
#include <linux/kho/abi/kexec_handover.h>
#include <linux/kho/abi/luo.h>

/**
 * DOC: memfd Live Update ABI
 *
 * memfd uses the ABI defined below for preserving its state across a kexec
 * reboot using the LUO.
 *
 * The state is serialized into a packed structure `struct memfd_luo_ser`
 * which is handed over to the target kernel via the KHO mechanism.
 *
 * This interface is a contract. `struct memfd_luo_ser` starts with a fixed
 * 128-byte `struct luo_feature_hdr`. The relative order and offsets of
 * fields must remain unchanged as features are added or retired: new fields
 * are appended at the end of `struct memfd_luo_ser` under a new feature
 * flag in `enum memfd_luo_feature` (before `MEMFD_LUO_FEAT_MAX`), and
 * retired fields are kept in place so subsequent offsets never shift. In
 * the target kernel, fields of a `LUO_FEAT_REQUIRED` feature are guaranteed
 * present once `luo_feature_hdr_validate()` succeeds, whereas fields of a
 * `LUO_FEAT_OPTIONAL` feature should be accessed only after checking
 * `luo_feature_is_active()`. All current fields (`pos`, `size`, `seals`,
 * `flags`, `nr_folios`, `folios`) and `MEMFD_LUO_ALL_SEALS` belong to
 * `MEMFD_LUO_FEAT_CORE` (`LUO_FEAT_REQUIRED` in `memfd_luo_features`).
 */

/**
 * MEMFD_LUO_FOLIO_DIRTY - The folio is dirty.
 *
 * This flag indicates the folio contains data from user. A non-dirty folio is
 * one that was allocated (say using fallocate(2)) but not written to.
 */
#define MEMFD_LUO_FOLIO_DIRTY		BIT(0)

/**
 * MEMFD_LUO_FOLIO_UPTODATE - The folio is up-to-date.
 *
 * An up-to-date folio has been zeroed out. shmem zeroes out folios on first
 * use. This flag tracks which folios need zeroing.
 */
#define MEMFD_LUO_FOLIO_UPTODATE	BIT(1)

/**
 * struct memfd_luo_folio_ser - Serialized state of a single folio.
 * @pfn:       The page frame number of the folio.
 * @flags:     Flags to describe the state of the folio.
 * @index:     The page offset (pgoff_t) of the folio within the original file.
 */
struct memfd_luo_folio_ser {
	u64 pfn:52;
	u64 flags:12;
	u64 index;
} __packed;

/*
 * The set of seals this version supports preserving. If support for any new
 * seals is needed, gate them behind a new feature flag.
 */
#define MEMFD_LUO_ALL_SEALS (F_SEAL_SEAL | \
			     F_SEAL_SHRINK | \
			     F_SEAL_GROW | \
			     F_SEAL_WRITE | \
			     F_SEAL_FUTURE_WRITE | \
			     F_SEAL_EXEC)

/**
 * enum memfd_luo_feature - Feature indices for &struct memfd_luo_ser.
 * @MEMFD_LUO_FEAT_CORE: Core feature covering `pos`, `size`, `seals`, `flags`,
 *                       `nr_folios`, `folios`, and %MEMFD_LUO_ALL_SEALS.
 * @MEMFD_LUO_FEAT_MAX:  Number of defined &enum memfd_luo_feature features.
 */
enum memfd_luo_feature {
	MEMFD_LUO_FEAT_CORE = 0,
	MEMFD_LUO_FEAT_MAX,
};

static_assert((int)MEMFD_LUO_FEAT_MAX <= LUO_FEAT_MAX);

/**
 * struct memfd_luo_ser - Main serialization structure for a memfd.
 * @features:  ABI feature and size header for memfd_luo_ser.
 * @pos:       The file's current position (f_pos).
 * @size:      The total size of the file in bytes (i_size).
 * @seals:     The seals present on the memfd. The seals are uABI so it is safe
 *             to directly use them in the ABI.
 * @flags:     Flags for the file. Unused flag bits must be set to 0.
 * @nr_folios: Number of folios in the folios array.
 * @folios:    KHO vmalloc descriptor pointing to the array of
 *             struct memfd_luo_folio_ser.
 */
struct memfd_luo_ser {
	struct luo_feature_hdr features;
	u64 pos;
	u64 size;
	u32 seals;
	u32 flags;
	u64 nr_folios;
	struct kho_vmalloc folios;
} __packed;

/* The name string for memfd file handler */
#define MEMFD_LUO_FH_NAME	"memfd-v2"

#endif /* _LINUX_KHO_ABI_MEMFD_H */
