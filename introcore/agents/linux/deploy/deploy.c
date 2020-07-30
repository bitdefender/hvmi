/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "../common.h"

typedef void * (filp_open_fn)(const char *filename, int flags, unsigned short mode);
typedef int (filp_close_fn)(void *filp, void *id);
typedef void * (vmalloc_fn)(unsigned long size);
typedef unsigned int (__kernel_write_fn)(void *file, const void *buf, unsigned int count, long long *pos);
typedef int (kernel_write_fn)(void *file, const char *buf, size_t count, unsigned long pos);
typedef void (vfree_fn)(void *ptr);
typedef char ** (argv_split_fn)(unsigned int gfp, const char *str, int *argcp);
typedef void (argv_free_fn)(char **argv);
typedef void *(call_usermodehelper_setup_fn)(const char *path, char **argv, char **envp, unsigned long gfp_mask,
        int (*init)(void *info, void *new), void (*cleanup)(void *info), void *data);
typedef int (call_usermodehelper_exec_fn)(void *sub_info, int wait);
typedef void (do_exit_fn)(long code);
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
        filp_open_fn *filp_open;
        filp_close_fn *filp_close;
        kernel_write_fn *kernel_write;
        __kernel_write_fn *__kernel_write;
        vmalloc_fn *vmalloc;
        vfree_fn *vfree;
        argv_split_fn *argv_split;
        argv_free_fn *argv_free;
        call_usermodehelper_setup_fn *call_usermodehelper_setup;
        call_usermodehelper_exec_fn *call_usermodehelper_exec;
        do_exit_fn *do_exit;
        printk_fn *printk;
    } func;

    /// @brief The arguments of the agent.
    struct {
        unsigned long kernel_version;   ///< The version of the kernel.

        unsigned long vmalloc_size;     ///< The size of the deployed chunks.
        char root[1];                   ///< The root path; allways '/'.
        char name[128];                 ///< The name of the deployed file.

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
void deploy(void)
///
/// @brief Creates a file using the provided name and writes the content given by Introcore in the file.
///
/// If an error occurs, the Intocore is notified.
///
{
    int ret = 0;
    void *file = _data.func.filp_open(_data.args.root, O_CREAT | O_RDWR | O_TRUNC, 0400);
    if (IS_ERR_VALUE(file))
    {
        breakpoint_1(_data.token.error, _data.func.filp_open);
        return;
    }

    void *ptr = _data.func.vmalloc(_data.args.vmalloc_size);
    if (!ptr)
    {
        breakpoint_1(_data.token.error, _data.func.vmalloc);
        goto _exit;
    }

    unsigned int count = 0;
    long long pos = 0;
    do
    {
        count = breakpoint_1(_data.token.hypercall, ptr);
        if (count == 0)
        {
            break;
        }

        if (_data.args.kernel_version <= KERNEL_VERSION(2, 6, 72))
        {
            ret = _data.func.kernel_write(file, ptr, count, pos);
            if (ret < 0)
            {
                breakpoint_1(_data.token.error, _data.func.__kernel_write);
                goto _exit;
            }

            pos += ret;
        }
        else
        {
            ret = _data.func.__kernel_write(file, ptr, count, &pos);
            if (ret < 0)
            {
                breakpoint_1(_data.token.error, _data.func.__kernel_write);
                goto _exit;
            }
        }
    } while (count);

    breakpoint(_data.token.completion);

_exit:
    if (file)
    {
        _data.func.filp_close(file, 0);
    }

    if (ptr)
    {
        _data.func.vfree(ptr);
    }

    if (ret < 0)
    {
        char *argv_remove[4];
        argv_remove[0] = "/bin/rm";
        argv_remove[1] = "-f";
        argv_remove[2] = _data.args.root;
        argv_remove[3] = NULL;

        char *envp[4];
        envp[0] = "HOME=/";
        envp[1] = "TERM=linux";
        envp[2] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
        envp[3] = NULL;

        call_usermodehelper(argv_remove[0], argv_remove, envp, _data.args.umh.wait_exec);
    }
}


__fn_naked __section(".start")
void trampoline(void)
///
/// @brief The trampoline of the agent.
///
/// Calls the deploy function and calls 'do_exit'.
///
/// The section used for this function is '.start'.
///
{
    deploy();

    __exit;
    __do_exit(__address, _data.func.do_exit, _data.func.vfree);
}
