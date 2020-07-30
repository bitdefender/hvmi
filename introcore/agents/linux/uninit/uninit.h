/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _UNINIT_H_
#define _UNINIT_H_

typedef void * (vfree_fn)(void *addr);
typedef int (change_page_attr_set_clr)(unsigned long *addr, int numpages, unsigned long mask_set, unsigned long mask_clr,
                                         int force_split, int in_flag, void **pages);

#pragma pack(push, 1)
struct  data {
    /// @brief The tokens used to communicate with Intocore.
    struct {
        unsigned long hypercall;
        unsigned long completion;
        unsigned long error;
    } token;

    /// @brief The functions used by this agent.
    struct {
        vfree_fn *vfree;
        change_page_attr_set_clr *change_page_attr_set_clr;
    } func;

    /// @brief The functions used by this agent.
    struct {
        void *module_alloc_ptr;         ///< The pointer returned by 'module_alloc'.
        void *vmalloc_ptr;              ///< The pointer returned by 'vmalloc'.

        unsigned long mask_clr;         ///< The clear mask for the allocated memory region.
        unsigned long mask_set;         ///< The set mask for the allocated memory region.
    } args;
};
#pragma pack(pop)

#endif // !_UNINIT_H_
