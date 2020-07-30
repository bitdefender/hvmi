/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _PGTABLE_H_
#define _PGTABLE_H_

#include "intro_types.h"

#define PAGE_SIZE_4K            4096u
#define PAGE_OFFSET_MASK_4K     (PAGE_SIZE_4K - 1)
#define PAGE_MAX_OFFSET_4K      PAGE_OFFSET_MASK_4K
#define PAGE_BASE_MASK_4K       (0xFFFFFFFFFFFFFFFFULL - PAGE_MAX_OFFSET_4K)

#define PAGE_SIZE_2M            (2 * ONE_MEGABYTE)
#define PAGE_OFFSET_MASK_2M     (PAGE_SIZE_2M - 1)
#define PAGE_MAX_OFFSET_2M      PAGE_OFFSET_MASK_2M
#define PAGE_BASE_MASK_2M       (0xFFFFFFFFFFFFFFFFULL - PAGE_MAX_OFFSET_2M)

#define PAGE_SIZE_4M            (4 * ONE_MEGABYTE)
#define PAGE_OFFSET_MASK_4M     (PAGE_SIZE_4M - 1)
#define PAGE_MAX_OFFSET_4M      PAGE_OFFSET_MASK_4M
#define PAGE_BASE_MASK_4M       (0xFFFFFFFFFFFFFFFFULL - PAGE_MAX_OFFSET_4M)

#define PAGE_SIZE_1G            (ONE_GIGABYTE)
#define PAGE_OFFSET_MASK_1G     (PAGE_SIZE_1G - 1)
#define PAGE_MAX_OFFSET_1G      PAGE_OFFSET_MASK_1G
#define PAGE_BASE_MASK_1G       (0xFFFFFFFFFFFFFFFFULL - PAGE_MAX_OFFSET_1G)

#define PAGE_SIZE               PAGE_SIZE_4K
#define PAGE_OFFSET_MASK        PAGE_OFFSET_MASK_4K
#define PAGE_OFFSET             PAGE_OFFSET_MASK
#define PAGE_MAX_OFFSET         PAGE_MAX_OFFSET_4K
#define PAGE_BASE_MASK          PAGE_BASE_MASK_4K
#define PAGE_MASK               PAGE_BASE_MASK

// Intel tells us that MAXPHYADDR is 52 bit wide; it will never be larger (in this Universe at least...)
#define PHYS_PAGE_MASK          0x000FFFFFFFFFF000ULL

// These are the page access bits defined by Intel
#define PML5_P                  BIT(0)
#define PML5_RW                 BIT(1)
#define PML5_US                 BIT(2)
#define PML5_PWT                BIT(3)
#define PML5_PCD                BIT(4)
#define PML5_A                  BIT(5)
#define PML5_PS                 BIT(7)
#define PML5_LNK                BIT(9)
#define PML5_USED               BIT(10)

#define PML4_P                  BIT(0)
#define PML4_RW                 BIT(1)
#define PML4_US                 BIT(2)
#define PML4_PWT                BIT(3)
#define PML4_PCD                BIT(4)
#define PML4_A                  BIT(5)
#define PML4_PS                 BIT(7)
#define PML4_LNK                BIT(9)
#define PML4_USED               BIT(10)

#define PDP_P                   BIT(0)
#define PDP_RW                  BIT(1)
#define PDP_US                  BIT(2)
#define PDP_PWT                 BIT(3)
#define PDP_PCD                 BIT(4)
#define PDP_A                   BIT(5)
#define PDP_PS                  BIT(7)
#define PDP_LNK                 BIT(9)
#define PDP_USED                BIT(10)

#define PD_P                    BIT(0)
#define PD_RW                   BIT(1)
#define PD_US                   BIT(2)
#define PD_PWT                  BIT(3)
#define PD_PCD                  BIT(4)
#define PD_A                    BIT(5)
#define PD_D                    BIT(6)
#define PD_PS                   BIT(7)
#define PD_G                    BIT(8)
#define PD_LNK                  BIT(9)
#define PD_USED                 BIT(10)

#define PT_P                    BIT(0)
#define PT_RW                   BIT(1)
#define PT_US                   BIT(2)
#define PT_PWT                  BIT(3)
#define PT_PCD                  BIT(4)
#define PT_A                    BIT(5)
#define PT_D                    BIT(6)
#define PT_PAT                  BIT(7)
#define PT_G                    BIT(8)
#define PT_XD                   BIT(63)

#define PML5_INDEX(a)           (DWORD)(((a) & 0x01ff000000000000) >> 48)
#define PML4_INDEX(a)           (DWORD)(((a) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(a)            (DWORD)(((a) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(a)             (DWORD)(((a) & 0x000000003fe00000) >> 21)
#define PT_INDEX(a)             (DWORD)(((a) & 0x00000000001ff000) >> 12)

// Paging structure indexes definitions - for 32 bit mode
// legacy PAE
#define PDPPAE_INDEX(a)         (DWORD)(((a) & 0x00000000c0000000) >> 30)
#define PDPAE_INDEX(a)          (DWORD)(((a) & 0x000000003fe00000) >> 21)
#define PTPAE_INDEX(a)          (DWORD)(((a) & 0x00000000001ff000) >> 12)

// legacy NON-PAE
#define PD32_INDEX(a)           (DWORD)(((a) & 0x00000000ffc00000) >> 22)
#define PT32_INDEX(a)           (DWORD)(((a) & 0x00000000003ff000) >> 12)

#define CR3_LEGACY_PAE_MASK             0x00000000FFFFFFE0
#define CR3_LEGACY_NON_PAE_MASK         0x00000000FFFFF000
#define CR3_LONG_MODE_MASK              PHYS_PAGE_MASK

/// Clears any reserved bits from a long-mode physical address.
///
/// @param[in]  x   Physical address to clean.
///
/// @returns    x, but with all the reserved bits set to 0.
#define CLEAN_PHYS_ADDRESS64(x)         ((x) & CR3_LONG_MODE_MASK)

/// Clears any reserved bits from a 32-bit physical address.
///
/// @param[in]  x   Physical address to clean.
///
/// @returns    x, but with all the reserved bits set to 0.
#define CLEAN_PHYS_ADDRESS32(x)         ((x) & CR3_LEGACY_NON_PAE_MASK)

/// Clears any reserved bits from a 32-bit PAE physical address.
///
/// @param[in]  x   Physical address to clean.
///
/// @returns    x, but with all the reserved bits set to 0.
#define CLEAN_PHYS_ADDRESS32PAE(x)      ((x) & CR3_LONG_MODE_MASK)

/// Clears any reserved bits from PAE root-table entry.
///
/// @param[in]  x   Physical address to clean.
///
/// @returns    x, but with all the reserved bits set to 0.
#define CLEAN_PHYS_ADDRESS32PAE_ROOT(x) ((x) & CR3_LEGACY_PAE_MASK)

/// Checks if a memory address is sign-extended.
///
/// @param[in]  addr    Memory address to check.
///
/// @returns    True if the address has the sign bits set; False if it does not.
#define PAGE_SX(addr)                   (((addr) & 0x800000000000) ? ((addr) | 0xFFFF000000000000) : (addr))

/// Checks if a memory range is split across multiple 4KB pages.
///
/// @param[in]  p       The base of the memory range.
/// @param[in]  s       The size of the memory range.
///
/// @returns    True if the memory range [p, p + s) is split across multiple 4KB pages; False if it is not split.
#define PAGE_SPLIT(p, s)                (((p) & PAGE_OFFSET) > (((p) + (s) - 1) & PAGE_OFFSET))

/// Computes the size of the memory range between a given address and the end of the 4KB memory page that maps that
/// address.
///
/// @param[in]  addr    Memory address for which to do the computation.
///
/// @returns    The size of the portion between addr and the end of the page.
#define PAGE_REMAINING(addr)            (PAGE_SIZE_4K - ((addr) & PAGE_OFFSET_MASK_4K))

#define PAGE_OFFSET_4K(addr)            ((addr) & PAGE_OFFSET_MASK_4K)
#define PAGE_FRAME_NUMBER_4K(addr)      ((addr) >> 12ULL)

/// Obtains the number of 4KB in which a memory range is split.
///
/// @param[in]  addr    Base virtual address.
/// @param[in]  bytes   The length of the memory range.
///
/// @returns    The number of 4KB pages used to map the given memory range.
#define PAGE_COUNT_4K(addr, bytes)      (PAGE_FRAME_NUMBER_4K(PAGE_OFFSET_4K(addr) + (bytes) + PAGE_MAX_OFFSET_4K))

/// Obtains the 4KB page frame number for virtual address.
///
/// @param[in]  addr    Address for which to get the page frame number.
///
/// @returns    The page frame number for the given address.
#define PAGE_FRAME_NUMBER(addr)         PAGE_FRAME_NUMBER_4K(addr)

/// Obtains the number of 4KB in which a memory range is split.
///
/// @param[in]  addr    Base virtual address.
/// @param[in]  bytes   The length of the memory range.
///
/// @returns    The number of 4KB pages used to map the given memory range.
#define PAGE_COUNT(addr, bytes)         PAGE_COUNT_4K(addr, bytes)

#endif // _PGTABLE_H_
