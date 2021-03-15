/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../common.h"

typedef void * (kthread_create_on_node_fn)(int (*threadfn)(void *data), void *data, int node, const char namefmt[], ...);
typedef void * (vmalloc_exec_fn)(unsigned long size);
typedef int (wake_up_process_fn)(void *p);
typedef void *(__vmalloc_node_range_fn)(unsigned long size, unsigned long align, unsigned long start, unsigned long end,
                                     unsigned int gfp_mask, unsigned long prot, unsigned long vm_flags, int node,
                                     const void *caller);

struct data {
    /// @brief The tokens used to communicate with Intocore.
    struct {
        unsigned long hypercall;
        unsigned long completion;
        unsigned long error;
    } token;

    /// @brief The functions used by this agent.
    struct {
        kthread_create_on_node_fn *kthread_create_on_node;
        wake_up_process_fn *wake_up_process;
        vmalloc_exec_fn *vmalloc_exec;
        __vmalloc_node_range_fn *__vmalloc_node_range;
    } func;

    /// @brief The arguments of the agent.
    struct {
        unsigned long vmalloc_size; ///< The size of allocation.
    } args;
};

/// @brief The section used for this agent is .kthread_data'.
struct data _data __agent_data("kthread") = { 0 };

__agent_text("kthread")
void kthread(void)
///
/// @brief Allocates a memory region with size of _data.args.vmalloc_size, deploy the main agent in that memory region
/// and creates kthread that execute the main agent.
///
/// If an error occurs, the Intocore is notified.
///
/// The section used for this function is .kthread_text'.
///
{
    void *ptr = NULL;

    if (_data.func.vmalloc_exec)
    {
        ptr = _data.func.vmalloc_exec(_data.args.vmalloc_size);
    }
    else
    {
        ptr = _data.func.__vmalloc_node_range(_data.args.vmalloc_size, 1, VMALLOC_START, VMALLOC_END, GFP_KERNEL,
                                              PAGE_KERNEL_EXEC, 0, -1, __func__);
    }

    if (!ptr)
    {
        breakpoint_2(_data.token.error, _data.func.vmalloc_exec, 0);
        return;
    }

    void *entry_ptr = (void *)breakpoint_1(_data.token.hypercall, ptr);
    void *task = _data.func.kthread_create_on_node(entry_ptr, NULL, -1, "bdagent");
    if (IS_ERR_VALUE(task))
    {
        breakpoint_2(_data.token.error, _data.func.kthread_create_on_node, task);
        return;
    }

    int ret = _data.func.wake_up_process(task);
    if (!ret)
    {
        breakpoint_2(_data.token.error, _data.func.wake_up_process, ret);
    }

    breakpoint(_data.token.completion);
}


__agent_trampoline("kthread")
void trampoline(void)
///
/// @brief The trampoline of the agent.
///
/// Calls the kthread function and generates the 'exit' asm-code.
///
/// The section used for this function is .kthread_trampoline'.
///
{
    kthread();

    __agent_exit("kthread");
}
