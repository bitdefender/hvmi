/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INIT_H_
#define _INIT_H_

typedef int (change_page_attr_set_clr_fn)(unsigned long *addr, int numpages, unsigned long mask_set, unsigned long mask_clr,
                                         int force_split, int in_flag, void **pages);
typedef void * (module_alloc_fn)(int size);
typedef void * (vmalloc_fn)(int size);

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
        module_alloc_fn *module_alloc;
        change_page_attr_set_clr_fn *change_page_attr_set_clr;
        vmalloc_fn *vmalloc;
    } func;

    struct {
        unsigned long module_alloc_size;        ///< The size of the 'module' region to allocate.
        unsigned long vmalloc_size;             ///< The size of the 'vm' region to allocate.
    } args;
};

#pragma pack(pop)
#endif // _INIT_H_
