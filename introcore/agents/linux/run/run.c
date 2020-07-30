/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../common.h"

typedef void * (vmalloc_fn)(unsigned long size);
typedef void (vfree_fn)(void *ptr);
typedef char ** (argv_split_fn)(unsigned int gfp, const char *str, int *argcp);
typedef void (argv_free_fn)(char **argv);
typedef void (do_exit_fn)(long code);
typedef void *(call_usermodehelper_setup_fn)(const char *path, char **argv, char **envp, unsigned long gfp_mask,
        int (*init)(void *info, void *new), void (*cleanup)(void *info), void *data);
typedef int (call_usermodehelper_exec_fn)(void *sub_info, int wait);
typedef int (printk_fn)(const char *fmt, ...);

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
        call_usermodehelper_setup_fn *call_usermodehelper_setup;
        call_usermodehelper_exec_fn *call_usermodehelper_exec;
        argv_split_fn *argv_split;
        argv_free_fn *argv_free;
        do_exit_fn *do_exit;
        vfree_fn *vfree;
        printk_fn *printk;
    } func;

    /// @brief The arguments of the agent.
    struct {
        char commnad[1024];             ///< The command line to be executed.

        struct {
            unsigned long wait_proc;    ///< The value of UMH_WAIT_PROC.
            unsigned long wait_exec;    ///< The value of UMH_WAIT_EXEC.
        } umh;
    } args;
};

#pragma pack(pop)

/// @brief The section used for this agent is .adata'.
struct data _data __section(".adata") __aligned(1) = { 0 };

extern void *__address;


__default_fn_attr
int call_usermodehelper(const char *path, char **argv, char **envp, unsigned int wait)
{
    unsigned long gfp_mask = GFP_KERNEL;
    void *info = _data.func.call_usermodehelper_setup(path, argv, envp, gfp_mask, NULL, NULL, NULL);
    if (!info)
    {
        breakpoint_2(_data.token.error, _data.func.call_usermodehelper_setup, info);
        return -1;
    }

    return _data.func.call_usermodehelper_exec(info, wait);
}

__default_fn_attr
void run(void)
///
/// @brief Creates a new process that execute the provided command line.
///
/// If an error occurs, the Intocore is notified.
///
{
    int ret = 0;
    char **argv = NULL;

    char *envp[4];

    envp[0] = "HOME=/";
    envp[1] = "TERM=linux";
    envp[2] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
    envp[3] = NULL;

    argv = _data.func.argv_split(GFP_KERNEL, _data.args.commnad, NULL);
    if (!argv)
    {
        breakpoint_2(_data.token.error, _data.func.argv_split, argv);
        goto _exit;
    }

    call_usermodehelper(argv[0], argv, envp, _data.args.umh.wait_exec);
    if (ret)
    {
        breakpoint_2(_data.token.error, _data.func.call_usermodehelper_exec, ret);
        goto _exit;
    }

    breakpoint(_data.token.completion);

_exit:
    if (argv)
    {
        _data.func.argv_free(argv);
    }
}


__fn_naked __section(".start")
void trampoline(void)
///
/// @brief The trampoline of the agent.
///
/// Calls the run function and calls 'do_exit'.
///
/// The section used for this function is '.start'.
///
{
    run();

    __exit;
    __do_exit(__address, _data.func.do_exit, _data.func.vfree);
}
