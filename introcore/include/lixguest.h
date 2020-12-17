/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _LIXGUEST_H_
#define _LIXGUEST_H_

#include "detours.h"

// According to Documentation/x86/x86_64/mm.txt
#define IS_KERNEL_POINTER_LIX(p) (((p) >= 0xFFFF800000000000) && ((p) < 0xffffffffffe00000))


///
/// @brief Encapsulates a protected Linux process.
///
typedef struct _LIX_PROTECTED_PROCESS
{
    LIST_ENTRY  Link;                   ///< Entry inside the #gLixProtectedTasks list.

    /// @brief  Process name pattern (supports glob patterns). Will be used if there is no path.
    CHAR        CommPattern[16];
    QWORD       Flags;                  ///< Flags that describe the protection mode.
    PCHAR       NamePattern;            ///< Full application file name.
    PCHAR       CommFullPattern;        ///< Full application name pattern.
    QWORD       Context;                ///< The context supplied in the protection policy.

    /// @brief  What protection policies should be applied.
    struct
    {
        QWORD   Original;               ///< The original protection flags as received from integrator.
        QWORD   Current;                ///< The currently used protection flags.

        QWORD   Beta;                   ///< Flags that were forced to beta mode.
        QWORD   Feedback;               ///< Flags that will be forced to feedback only mode.
    } Protection;
} LIX_PROTECTED_PROCESS, *PLIX_PROTECTED_PROCESS;


#define LIX_MAX_HOOKED_FN_COUNT         512
#define LIX_MAX_VERSION_STRINGS         3

#define MAX_VERSION_LENGTH              256


///
/// @brief Describes a Linux function used by the detour mechanism.
///
typedef struct _LIX_FUNCTION
{
    DWORD       NameHash;       ///< Crc32 of the function name.
    DWORD       HookHandler;    ///< Used to identify the index of the #LIX_FN_DETOUR the in the gLixHookHandlersx64.
    BOOLEAN     SkipOnBoot;     ///< Unused.
} LIX_FUNCTION;


///
/// @brief  Structure tags used for the Linux structures.
/// @ingroup    group_guest_support
///
typedef enum LIX_STRUCTURE
{
    lixStructureInfo = 0,           ///< The tag for #LIX_FIELD_INFO.
    lixStructureModule,             ///< The tag for #LIX_FIELD_MODULE.
    lixStructureBinprm,             ///< The tag for #LIX_FIELD_BINPRM.
    lixStructureVma,                ///< The tag for #LIX_FIELD_VMA.
    lixStructureDentry,             ///< The tag for #LIX_FIELD_DENTRY.
    lixStructureMmStruct,           ///< The tag for #LIX_FIELD_MMSTRUCT.
    lixStructureTaskStruct,         ///< The tag for #LIX_FIELD_TASKSTRUCT.
    lixStructureFs,                 ///< The tag for #LIX_FIELD_FS.
    lixStructureFdTable,            ///< The tag for #LIX_FIELD_FDTABLE.
    lixStructureFiles,              ///< The tag for #LIX_FIELD_FILES.
    lixStructureInode,              ///< The tag for #LIX_FIELD_INODE.
    lixStructureSocket,             ///< The tag for #LIX_FIELD_SOCKET.
    lixStructureSock,               ///< The tag for #LIX_FIELD_SOCK.
    lixStructureCred,               ///< The tag for #LIX_FIELD_CRED.
    lixStructureNsProxy,            ///< The tag for #LIX_FIELD_NSPROXY.
    lixStructureUngrouped,          ///< The tag for #LIX_FIELD_UNGROUPED.
    lixStructureEnd                 ///< The end of tags.
} LIX_STRUCTURE;


///
/// @brief Describes information about a Linux guest.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_INFO
{
    lixFieldInfoThreadSize = 0,         ///< The size of a thread.
    lixFieldInfoHasModuleLayout,        ///< The guest has module layout.
    lixFieldInfoHasVdsoImageStruct,     ///< The guest has the vdso image struct.
    lixFieldInfoHasSmallSlack,          ///< Unused.
    /// @brief  The guest emit the symbol references in the kallsyms table as 32-bit entries, each containing a
    /// relative value in the range [base, base + U32_MAX]
    lixFieldInfoHasKsymRelative,
    /// @brief  The guest emit an absolute value in the range [0, S32_MAX] or a relative value in the range
    /// [base, base + S32_MAX], where base is the lowest relative symbol address encountered in the image.
    lixFieldInfoHasKsymAbsolutePercpu,
    /// @brief The guest has an additional table that contains the sizes of the functions/variables.
    lixFieldInfoHasKsymSize,
    lixFieldInfoHasAlternateSyscall,    ///< The guest has an alternative syscall handler.
    lixFieldInfoHasVmaAdjustExpand,     ///< Unused.
    lixFieldInfoHasVdsoFixed,           ///< The guest has is build with VSYSCALL support.
    lixFieldInfoHasKsymReducedSize,     ///< The size of a 'kallsym_markers' entry is 4.
    lixFieldInfoEnd                     ///< The end of tags.
} LIX_FIELD_INFO;


///
/// @brief The index for offsets of 'struct module'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_MODULE
{
    lixFieldModuleSizeof = 0,           ///< The value of sizeof(struct module).
    lixFieldModuleList,                 ///< The offset of module.list.
    lixFieldModuleName,                 ///< The offset of module.name.
    lixFieldModuleSymbols,              ///< The offset of module.symbols.
    lixFieldModuleNumberOfSymbols,      ///< The offset of module.sum_syms.
    lixFieldModuleGplSymbols,           ///< The offset of module.gpl_syms.
    lixFieldModuleNumberOfGplSymbols,   ///< The offset of module.num_gpl_syms.
    lixFieldModuleInit,                 ///< The offset of module.init.
    lixFieldModuleModuleInit,           ///< The offset of module.init_layout.
    lixFieldModuleModuleCore,           ///< The offset of module.core_layout.
    lixFieldModuleInitSize,             ///< The offset of module.init_layout.size.
    lixFieldModuleCoreSize,             ///< The offset of module.core_layout.size.
    lixFieldModuleInitTextSize,         ///< The offset of module.init_layout.text_size.
    lixFieldModuleCoreTextSize,         ///< The offset of module.core_layout.text_size.
    lixFieldModuleInitRoSize,           ///< The offset of module.init_layout.ro_size.
    lixFieldModuleCoreRoSize,           ///< The offset of module.core_layout.ro_size.
    lixFieldModuleCoreLayout,           ///< The offset of module.core_layout.
    lixFieldModuleInitLayout,           ///< The offset of module.init_layout.
    lixFieldModuleState,                ///< The offset of module.state.
    lixFieldModuleEnd                   ///< The end of tags.
} LIX_FIELD_MODULE;


///
/// @brief The index for offsets of 'struct linux_binprm'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_BINPRM
{
    lixFieldBinprmSizeof = 0,           ///< The value of sizeof(struct linux_binprm).
    lixFieldBinprmMm,                   ///< The offset of linux_binprm.mm.
    lixFieldBinprmFile,                 ///< The offset of linux_binprm.file.
    lixFieldBinprmCred,                 ///< The offset of linux_binprm.cred.
    lixFieldBinprmFilename,             ///< The offset of linux_binprm.filename.
    lixFieldBinprmInterp,               ///< The offset of linux_binprm.interp.
    lixFieldBinprmVma,                  ///< The offset of linux_binprm.vma.
    lixFieldBinprmArgc,                 ///< The offset of linux_binprm.argc.
    lixFieldBinprmEnd                   ///< The end of tags.
} LIX_FIELD_BINPRM;


///
/// @brief The index for offsets of 'struct vm_area_struct'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_VMA
{
    lixFieldVmaVmaStart = 0,            ///< The offset of vm_area_struct.vm_start.
    lixFieldVmaVmaEnd,                  ///< The offset of vm_area_struct.vm_end.
    lixFieldVmaVmNext,                  ///< The offset of vm_area_struct.vm_next.
    lixFieldVmaVmPrev,                  ///< The offset of vm_area_struct.vm_prev.
    lixFieldVmaMm,                      ///< The offset of vm_area_struct.vm_mm.
    lixFieldVmaFlags,                   ///< The offset of vm_area_struct.flags.
    lixFieldVmaFile,                    ///< The offset of vm_area_struct.file.
    lixFieldVmaRbNode,                  ///< The offset of vm_area_struct.vm_rb.
    lixFieldVmaEnd                      ///< The end of tags.
} LIX_FIELD_VMA;


///
/// @brief The index for offsets of 'struct dentry'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_DENTRY
{
    lixFieldDentryParent = 0,           ///< The offset of dentry.d_parent.
    lixFieldDentryName,                 ///< The offset of dentry.d_name.
    lixFieldDentryDiname,               ///< The offset of dentry.d_iname.
    lixFieldDentryInode,                ///< The offset of dentry.d_inode.
    lixFieldDentryHashList,             ///< The offset of dentry.d_hash.
    lixFieldDentryEnd                   ///< The end of tags.
} LIX_FIELD_DENTRY;


///
/// @brief The index for offsets of 'struct mm_struct'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_MMSTRUCT
{
    lixFieldMmStructPgd = 0,            ///< The offset of mm_struct.pgd.
    lixFieldMmStructMmUsers,            ///< The offset of mm_struct.mm_users.
    lixFieldMmStructMmCount,            ///< The offset of mm_struct.mm_count.
    lixFieldMmStructMmList,             ///< The offset of mm_struct.mmlist.
    lixFieldMmStructStartCode,          ///< The offset of mm_struct.start_code.
    lixFieldMmStructEndCode,            ///< The offset of mm_struct.end_code.
    lixFieldMmStructStartData,          ///< The offset of mm_struct.start_data.
    lixFieldMmStructEndData,            ///< The offset of mm_struct.end_data.
    lixFieldMmStructFlags,              ///< The offset of mm_struct.flags.
    lixFieldMmStructExeFile,            ///< The offset of mm_struct.end_data.exe_file.
    lixFieldMmStructVma,                ///< The offset of mm_struct.mmap.
    lixFieldMmStructStartStack,         ///< The offset of mm_struct.start_stack.
    lixFieldMmStructRbNode,             ///< The offset of mm_struct.mm_rb.
    lixFieldMmStructVdsoAddress,        ///< The offset of mm_struct.context.vdso.
    lixFieldMmStructEnd                 ///< The end of tags.
} LIX_FIELD_MMSTRUCT;


///
/// @brief The index for offsets of 'struct task-struct'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_TASKSTRUCT
{
    lixFieldTaskStructStack = 0,        ///< The offset of task_struct.stack.
    lixFieldTaskStructUsage,            ///< The offset of task_struct.usage.
    lixFieldTaskStructFlags,            ///< The offset of task_struct.flags.
    lixFieldTaskStructTasks,            ///< The offset of task_struct.tasks.
    lixFieldTaskStructPid,              ///< The offset of task_struct.pid.
    lixFieldTaskStructTgid,             ///< The offset of task_struct.tgid.
    lixFieldTaskStructRealParent,       ///< The offset of task_struct.real_parent.
    lixFieldTaskStructParent,           ///< The offset of task_struct.parent.
    lixFieldTaskStructMm,               ///< The offset of task_struct.mm.
    lixFieldTaskStructStartTime,        ///< The offset of task_struct.start_time.
    lixFieldTaskStructComm,             ///< The offset of task_struct.comm.
    lixFieldTaskStructSignal,           ///< The offset of task_struct.signal.
    lixFieldTaskStructExitCode,         ///< The offset of task_struct.exit_code.
    lixFieldTaskStructThreadNode,       ///< The offset of task_struct.thread_node.
    lixFieldTaskStructThreadGroup,      ///< The offset of task_struct.thread_group.
    lixFieldTaskStructCred,             ///< The offset of task_struct.cred.
    lixFieldTaskStructFs,               ///< The offset of task_struct.fs.
    lixFieldTaskStructFiles,            ///< The offset of task_struct.files.
    lixFieldTaskStructNsProxy,          ///< The offset of task_struct.nsproxy.
    lixFieldTaskStructGroupLeader,      ///< The offset of task_struct.group_leader.
    lixFieldTaskStructExitSignal,       ///< The offset of task_struct.exit_signal.
    lixFieldTaskStructInExecve,         ///< The offset of task_struct.in_execve.
    lixFieldTaskStructInExecveBit,      ///< The offset of task_struct.execve.
    lixFieldTaskStructThreadStructSp,   ///< The offset of task_struct.thread_struct.sp.
    lixFieldTaskStructAltStackSp,       ///< The offset of alternate stack.
    lixFieldTaskStructEnd               ///< The end of tags.
} LIX_FIELD_TASKSTRUCT;


///
/// @brief The index for offsets of 'struct fs_struct'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_FS
{
    lixFieldFsSizeof = 0,               ///< The value of sizeof(struct fs_struct).
    lixFieldFsRoot,                     ///< The offset of fs_struct.root.
    lixFieldFsPwd,                      ///< The offset of fs_struct.pwd.
    lixFieldFsEnd                       ///< The end of tags.
} LIX_FIELD_FS;


///
/// @brief The index for offsets of 'struct fdtable'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_FDTABLE
{
    lixFieldFdTableMaxFds = 0,          ///< The offset of fdtable.max_fds.
    lixFieldFdTableFd,                  ///< The offset of fs_struct.fd.
    lixFieldFdTableEnd                  ///< The end of tags.
} LIX_FIELD_FDTABLE;


///
/// @brief The index for offsets of 'struct files_struct'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_FILES
{
    lixFieldFilesSizeof = 0,            ///< The value of sizeof(struct files_struct).
    lixFieldFilesFdt,                   ///< The offset of fs_struct.fdt.
    lixFieldFilesEnd                    ///< The end of tags.
} LIX_FIELD_FILES;


///
/// @brief The index for offsets of 'struct inode'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_INODE
{
    lixFieldInodeSizeof = 0,            ///< The value of sizeof(struct inode).
    lixFieldInodeImode,                 ///< The offset of inode.i_mode.
    lixFieldInodeUid,                   ///< The offset of inode.i_uid.
    lixFieldInodeGid,                   ///< The offset of inode.i_gid.
    lixFieldInodeEnd                    ///< The end of tags.
} LIX_FIELD_INODE;


///
/// @brief The index for offsets of 'struct socket'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_SOCKET
{
    lixFieldSocketState = 0,            ///< The offset of socket.state.
    lixFieldSocketType,                 ///< The offset of socket.type.
    lixFieldSocketFlags,                ///< The offset of socket.flags.
    lixFieldSocketSk,                   ///< The offset of socket.sk.
    lixFieldSocketEnd                   ///< The end of tags.
} LIX_FIELD_SOCKET;


///
/// @brief The index for offsets of 'struct sock'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_SOCK
{
    lixFieldSockSizeof = 0,             ///< The value of sizeof(struct sock).
    lixFieldSockNum,                    ///< The offset of sock.sk_num.
    lixFieldSockDport,                  ///< The offset of sock.sk_dport.
    lixFieldSockDaddr,                  ///< The offset of sock.sk_daddr.
    lixFieldSockRcvSaddr,               ///< The offset of sock.sk_receive_addr.
    lixFieldSockFamily,                 ///< The offset of sock.sk_family.
    lixFieldSockState,                  ///< The offset of sock.sk_state.
    lixFieldSockProto,                  ///< The offset of sock.sk_prot.
    lixFieldSockV6Daddr,                ///< The offset of sock.sk_v6_daddr.
    lixFieldSockV6RcvSaddr,             ///< The offset of sock.sk_v6_daddr.
    lixFieldSockEnd                     ///< The end of tags.
} LIX_FIELD_SOCK;


///
/// @brief The index for offsets of 'struct cred'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_CRED
{
    lixFieldCredSizeof = 0,             ///< The value of sizeof(struct cred).
    lixFieldCredUsage,                  ///< The offset of cred.usage.
    lixFieldCredRcu,                    ///< The offset of cred.rcu.
    lixFieldCredEnd                     ///< The end of tags.
} LIX_FIELD_CRED;


///
/// @brief The index for offsets of 'struct nsproxy'.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_NSPROXY
{
    lixFieldNsProxyCount = 0,           ///< The offset of nsproxy.count.
    lixFieldNsProxyUts,                 ///< The offset of nsproxy.uts_ns.
    lixFieldNsProxyIpc,                 ///< The offset of nsproxy.ipc_ns.
    lixFieldNsProxyMnt,                 ///< The offset of nsproxy.mnt_ns.
    lixFieldNsProxyPid,                 ///< The offset of nsproxy.pid_ns_for_children.
    lixFieldNsProxyNet,                 ///< The offset of nsproxy.net_ns.
    lixFieldNsProxyEnd                  ///< The end of tags.
} LIX_FIELD_NSPROXY;


///
/// @brief The index for offsets of structures that are not grouped.
/// @ingroup    group_guest_support
///
typedef enum _LIX_FIELD_UNGROUPED
{
    lixFieldUngroupedFileDentry = 0,        ///< The offset of file.f_path.dentry.
    lixFieldUngroupedProtoName,             ///< The offset of proto.name.
    lixFieldUngroupedSignalListHead,        ///< The offset of signal_struct.thread_head.
    /// @brief  The guest virtual address of the 'struct socket *sock_alloc(void);' function.
    lixFieldUngroupedSocketAllocVfsInode,
    lixFieldUngroupedRunning,               ///< The value of the system_state.RUNNING.
    lixFieldUngroupedFilePath,              ///< The offset of file.f_path.
    lixFieldUngroupedSignalNrThreads,       ///< The offset of signal_struct.nr_threads.
    lixFieldUngroupedEnd                    ///< The end of tags.
} LIX_FIELD_UNGROUPED;


///
/// @brief  Contains information about various Linux structures.
/// @ingroup    group_guest_support
///
typedef struct _LIX_OPAQUE_FIELDS
{
    DWORD               HooksId;                    ///< What versions of OS are supported by this fields

    DWORD               FunctionsCount;             ///< The number of function to be hooked.
    LIX_FUNCTION        *Functions;                 ///< An array of #LIX_FUNCTION to be hooked.

    struct
    {
        DWORD Info[lixFieldInfoEnd];                ///< Information about the current linux guest.
        DWORD Module[lixFieldModuleEnd];            ///< Information about the 'struct module'.
        DWORD Binprm[lixFieldBinprmEnd];            ///< Information about the 'struct linux_binprm'.
        DWORD Vma[lixFieldVmaEnd];                  ///< Information about the 'struct vm_area_struct'.
        DWORD Dentry[lixFieldDentryEnd];            ///< Information about the 'struct dentry'.
        DWORD MmStruct[lixFieldMmStructEnd];        ///< Information about the 'struct mm_struct'.
        DWORD TaskStruct[lixFieldTaskStructEnd];    ///< Information about the 'struct task_struct'.
        DWORD Fs[lixFieldFsEnd];                    ///< Information about the 'struct fs_struct'.
        DWORD FdTable[lixFieldFdTableEnd];          ///< Information about the 'struct fdtable'.
        DWORD Files[lixFieldFilesEnd];              ///< Information about the 'struct files_struct'.
        DWORD Inode[lixFieldInodeEnd];              ///< Information about the 'struct inode'.
        DWORD Socket[lixFieldSocketEnd];            ///< Information about the 'struct socket'.
        DWORD Sock[lixFieldSockEnd];                ///< Information about the 'struct sock'.
        DWORD Cred[lixFieldCredEnd];                ///< Information about the 'struct cred'.
        DWORD NsProxy[lixFieldNsProxyEnd];          ///< Information about the 'struct nsproxy'.
        DWORD Ungrouped[lixFieldUngroupedEnd];      ///< Information about the ungrouped structures.
    } OpaqueFields;

    DWORD               CurrentTaskOffset;          ///< The offset of the current task from GS.
    DWORD               CurrentCpuOffset;           ///< The offset of the CPU from GS.
    DWORD               ThreadStructOffset;         ///< The offset of the thread_struct from task_struct.

} LIX_OPAQUE_FIELDS, *PLIX_OPAQUE_FIELDS;


///
/// @brief  Macro used to access fields inside the #LIX_OPAQUE_FIELDS structure.
/// @ingroup    group_guest_support
///
/// @param[in]  Structure   The structure name. This is identical to the name of the array in the #LIX_OPAQUE_FIELDS.
/// @param[in]  Field       The name of the field.
///
/// @returns    The value of the requested field
///
#define LIX_FIELD(Structure, Field)      gLixGuest->OsSpecificFields.OpaqueFields.Structure[lixField##Structure##Field]


///
/// @brief Describes a Linux ksym.
/// @ingroup    group_guest_support
///
typedef struct _LIX_SYMBOL
{
    QWORD       Start;      ///< The start guest virtual address of ksym.
    QWORD       End;        ///< The end guest virtual address of ksym (exclusive).
} LIX_SYMBOL, *PLIX_SYMBOL;


///
/// @brief Describes the type of an Linux active-patch.
/// @ingroup    group_guest_support
///
typedef enum _LIX_ACTIVE_PATCH_TYPE
{
    lixActivePatchTextPoke = 0,     ///< Used for 'text_poke'.
    lixActivePatchFtrace,           ///< Used for 'ftrace'.
    lixActivePatchJmpLabel,         ///< Used for 'arch_jump_label_transform'.

    lixActivePatchCount             ///< The number of entries.
} LIX_ACTIVE_PATCH_TYPE;


///
/// @brief Describes the information about a Linux active-patch.
/// @ingroup    group_guest_support
///
typedef struct _LIX_ACTIVE_PATCH
{
    QWORD       Gva;                ///< The start of the region which follows to be patched.
    WORD        Length;             ///< The patch length.
    BYTE        Data[32];           ///< The replacement data which follows to be written.

    BOOLEAN     IsDetour;           ///< If the guest attempts to patch the jump label for our detour.
    /// @brief  If the guest attempts to patch the jump label for our detour, contains the tag of the detour.
    DETOUR_TAG  DetourTag;
} LIX_ACTIVE_PATCH;


///
/// @brief Describes a Linux guest.
///
typedef struct _LINUX_GUEST
{
    /// @brief The version of the Linux kernel.
    union
    {
        DWORD Value;            ///< The Linux full version number.

        struct
        {
            WORD Sublevel;      ///< The sublevel field of the version string.
            BYTE Patch;         ///< The patch field of the version string.
            BYTE Version;       ///< The version field of the version string.
            WORD Backport;      ///< The backport field of the version string.
        };
    } Version;

    CHAR    VersionString[MAX_VERSION_LENGTH];              ///< The version string.

    // WARNING: These may not be page aligned!
    struct
    {
        QWORD           CodeStart;              ///< The guest virtual address where the code starts.
        QWORD           CodeEnd;                ///< The guest virtual address  where the code ends.

        QWORD           DataStart;              ///< The guest virtual address where the data starts.
        QWORD           DataEnd;                ///< The guest virtual address where the data ends.

        QWORD           RoDataStart;            ///< The guest virtual address where the read-only data starts.
        QWORD           RoDataEnd;              ///< The guest virtual address where the read-only data ends.

        QWORD           ExTableStart;           ///< The guest virtual address where the ex-table starts.
        QWORD           ExTableEnd;             ///< The guest virtual address where the ex-table ends.
    } Layout;

    BOOLEAN             Initialized;                    ///< True if the guest is initialized.

    /// The guest virtual address of memcpy, __memcpy, memset, __memset, memmove.
    LIX_SYMBOL          MemoryFunctions[5];

    struct
    {
        QWORD           Vsyscall;               ///< The guest virtual address of the vsyscall.

        QWORD           VdsoStart;              ///< The guest virtual address where the vDSO starts.
        QWORD           VdsoEnd;                ///< The guest virtual address where the vDSO ends.

        QWORD           Vdso32Start;            ///< The guest virtual address where the vDSO x32 starts.
        QWORD           Vdso32End;              ///< The guest virtual address where the vDSO x32 end.
    } Vdso;

    /// @brief  An array that contains information about the active-patches.
    LIX_ACTIVE_PATCH    ActivePatch[lixActivePatchCount];

    QWORD               SyscallAddress;         ///< The guest virtual address of the syscall.
    QWORD               PropperSyscallGva;      ///< The guest virtual address of the 'real' syscall.

    void                *InitProcessObj;        ///< The #LIX_TASK_OBJECT of the 'init' process.

    struct
    {
        struct
        {
            BOOLEAN Initialized;                ///< True if the detours-code/data region is initialized.
            BOOLEAN Cleared;                    ///< True if the detours-code/data region is cleared.

            struct
            {
                QWORD Address;                  ///< The guest virtual address of the detours-code.
                DWORD Length;                   ///< The length (bytes) of the detours-code.

                void  *HookObject;              ///< The hook-object for detours-code region.
            } Code;

            struct
            {
                QWORD Address;                  ///< The guest virtual address of the detours-data.
                DWORD Length;                   ///< The length (bytes) of the detours-data.

                void  *HookObject;              ///< The hook-object for detours-data region.
            } Data;
        } Detour;

        struct
        {
            BOOLEAN Initialized;                ///< True if the agents region is initialized.
            BOOLEAN Cleared;                    ///< True if the agents region is initialized.

            QWORD   Address;                    ///< The guest virtual address of the agents.
            DWORD   Length;                     ///< The length (bytes) of the agents.


            void    *HookObject;                ///< The hook-object for agents region.
        } Agent;

        struct
        {
            QWORD PerCpuAddress;                ///< The guest virtual address of the 'per-cpu' allocated region.
            DWORD PerCpuLength;                 ///< The length (bytes) of the 'per-cpu' region.
        } PerCpuData;

        QWORD OriginalPagesAttr;                ///< The original page protection-attributes for the allocated region.
    } MmAlloc;

    LIX_OPAQUE_FIELDS   OsSpecificFields;       ///< OS-dependent and specific information.
} LINUX_GUEST, *PLINUX_GUEST;

///
/// @brief The max length of the ksym as defined by Linux kernel.
///
#define LIX_SYMBOL_NAME_LEN       128


///
/// @brief Version.Patch.Sublevel (ie. 3.10.0 or 2.6.394).
/// Don't change the order, since it will fail when comparing versions.
///
#define LIX_GET_VERSION(Version)                  ((Version) >> 24)
#define LIX_GET_PATCH(Version)                    (((Version) & 0x00ff0000) >> 16)
#define LIX_GET_SUBLEVEL(Version)                 (((Version) & 0x0000ffff))

#define LIX_CREATE_VERSION(K, Patch, Sublevel)    ((Sublevel) | ((Patch) << 16) | ((K) << 24))

///
/// @brief An array that contains the descriptors about the function that
/// will be hooked (see lixapi.c for more information).
///
extern const LIX_FN_DETOUR gLixHookHandlersx64[];

INTSTATUS
IntLixTextPokeHandler(
    _In_ void *Detour
    );

INTSTATUS
IntLixFtraceHandler(
    _In_ void *Detour
    );

INTSTATUS
IntLixJumpLabelHandler(
    _In_ void *Detour
    );

INTSTATUS
IntLixGuestIsKptiActive(
    _In_ QWORD SyscallGva
    );

INTSTATUS
IntLixGuestNew(
    void
    );

void
IntLixGuestUninit(
    void
    );

int
IntLixGuestGetSystemState(
    void
    );

void
IntLixGuestUninitGuestCode(
    void
    );

BOOLEAN
IntLixGuestDeployUninitAgent(
    void
    );

INTSTATUS
IntGetVersionStringLinux(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    );

#endif
