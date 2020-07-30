/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "init.h"
#include "../common.h"

/// @brief The section used for this agent is .adata'.
struct data _data __section(".adata") __aligned(1) = { 0 };

#define PAGE_RW         0x02ULL
#define PAGE_NX         0x8000000000000000ULL

__default_fn_attr
void init (void)
///
/// @brief Allocates memory for detours and agents.
///
/// If an error occurs, the Intocore is notified.
///
{
    void *mod_ptr = _data.func.module_alloc(_data.args.module_alloc_size);
    void *vm_ptr = _data.func.vmalloc(_data.args.vmalloc_size);
    unsigned long ptr = 0;
    int ret = 0;

    breakpoint_2(_data.token.hypercall, mod_ptr, vm_ptr);

    ptr = (unsigned long)(mod_ptr);
    ret = _data.func.change_page_attr_set_clr(&ptr, 0x1, PAGE_NX, PAGE_RW, 0, 0, 0);
    if (ret)
    {
        breakpoint_1(_data.token.error, ret);
        return;
    }

    ptr = (unsigned long)((unsigned long)(mod_ptr) + PAGE_SIZE);
    ret = _data.func.change_page_attr_set_clr(&ptr, 0x2, 0, PAGE_NX | PAGE_RW, 0, 0, 0);
    if (ret)
    {
        breakpoint_1(_data.token.error, ret);
        return;
    }

    breakpoint(_data.token.completion);
}


__fn_naked __section(".start")
void trampoline(void)
///
/// @brief The trampoline of the agent.
///
/// Calls the init function and generate 'exit' asm-code.
///
/// The section used for this function is '.start'.
///
{
    init();

    __exit;
}
