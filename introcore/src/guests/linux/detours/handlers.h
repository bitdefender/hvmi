/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _HANDLERS_H_
#define _HANDLERS_H_

#pragma pack(push, 8)

typedef enum {
    det_commit_creds = 0,
    det_arch_jump_label_transform,
    det_module_param_sysfs_setup,
    det_module_param_sysfs_remove,
    det_wake_up_new_task,
    det_flush_old_exec,
    det_do_exit,
    det_arch_ptrace,
    det_compat_arch_ptrace,
    det_process_vm_rw_core,
    det___vma_link_rb,
    det_change_protection,
    det_vma_adjust,
    det___vma_adjust,
    det_vma_rb_erase,
    det___vma_rb_erase,
    det_expand_downwards,
    det_complete_signal,
    det_text_poke,
    det___text_poke,
    det_ftrace_write,
    det_panic,
    det_crash_kexec,
    det___access_remote_vm,
    det_mprotect_fixup_vma_wants_writenotify,
    det_do_munmap_rb_erase,
    det_vma_adjust_rb_erase,

    det_max_id
} DETOUR_ID;

typedef char * (d_path_fn)(void *path, char *buf, int buflen);

typedef struct _LIX_GUEST_OS_SPECIFIC {
    struct {
        unsigned int MmOffset;
        unsigned int FlagsOffset;
        unsigned int FileOffset;
        unsigned int VmNextOffset;
        unsigned int VmPrevOffset;
        unsigned int Rb;

        unsigned int ProtectionBit;
    } Vma;

    struct {
        unsigned int FlagsOffset;
        unsigned int Rb;

        unsigned int ProtectionBit;
    } Mm;

    struct {
        unsigned int InExecve;
        unsigned int InExecveBit;
    } Task;

    struct {
        unsigned int FileOffset;
    } Binprm;

    struct {
        unsigned int DentryOffset;
        unsigned int PathOffset;
    } File;

    struct {
        unsigned int InodeOffset;
    } Dentry;

    struct {
        unsigned int Mode;
        unsigned int Uid;
        unsigned int Gid;
    } Inode;

    unsigned int CurrentTaskOffset;
    unsigned int CurrentCpuOffset;

    void *PercpuMemPtr;
    d_path_fn *DPathFnPtr;
} LIX_GUEST_OS_SPECIFIC;


typedef struct _LIX_GUEST_DETOUR {
    char Name[32];
    char HijackName[32];
    unsigned long long Address;
    unsigned long long RelocatedCode;
    unsigned long long JumpBack;
    unsigned long long EnableOptions;
} LIX_GUEST_DETOUR;


typedef struct _LIX_HYPERCALL_PAGE
{
    unsigned long long ProtectionOptions;
    unsigned long long DetoursCount;

    LIX_GUEST_DETOUR Detours[det_max_id];

    LIX_GUEST_OS_SPECIFIC OsSpecificFields;
} LIX_HYPERCALL_PAGE;

#pragma pack(pop)

#endif // _HANDLERS_H_
