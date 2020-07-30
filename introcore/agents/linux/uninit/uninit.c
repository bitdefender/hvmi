/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "uninit.h"
#include "../common.h"

/// @brief The section used for this agent is .adata'.
struct data _data __section(".adata") __aligned(1) = { 0 };

__default_fn_attr
void uninit (void)
///
/// @brief Deallocate the memory regions previously allocated.
///
/// If an error occurs, the Intocore is notified.
///
{
    unsigned long ptr = (unsigned long)(_data.args.module_alloc_ptr);

    int ret = _data.func.change_page_attr_set_clr(&ptr, 0x3, _data.args.mask_set, _data.args.mask_clr, 0, 0, 0);
    if (ret)
    {
        breakpoint_1(_data.token.error, ret);
        return;
    }

    _data.func.vfree(_data.args.module_alloc_ptr);
    _data.func.vfree(_data.args.vmalloc_ptr);


    breakpoint_1(_data.token.completion, ret);
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
    uninit();

    __exit;
}


