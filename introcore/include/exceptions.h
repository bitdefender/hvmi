/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _EXCEPTIONS_H_
#define _EXCEPTIONS_H_

///
/// @defgroup   group_exceptions Exceptions mechanism
/// @ingroup    group_internal
/// @brief      Except guest behavior that will normally be blocked
///

///
/// @file       exceptions.h
/// @ingroup    group_exceptions
///

#include "guest_stack.h"
#include "drivers.h"
#include "integrity.h"
#include "introcpu.h"
#include "lixprocess.h"
#include "winummodule.h"

// Special value, so we don't log this
#define EXCEPTION_INTROUNIT_NAME_HASH   0x1036c1b7
#define EXCEPTION_NO_NAME               "<no name>"
#define EXCEPTION_NO_WNAME              u"<no name>"
#define EXCEPTION_NO_INSTRUCTION        "<generic>"
#define EXCEPTION_NO_SYMBOL             "<no sym>"

#define EXPORT_BEGIN_WRITE_ERR_RANGE    0x10
#define EXPORT_NAME_UNKNOWN             "<unknown>"

#define EXCEPTION_UM_GLOB_LENGTH        64

//
// We group exceptions into 16 categories, by the originator hash:
// 0 - GeneralExceptions (special ones)
// 0x00000001 - 0x0fffffff
// 0x10000000 - 0x1fffffff
// 0x20000000 - 0x2fffffff
// .......................
// 0xf0000000 - 0xfffffffe
//
// NOTE: 0xffffffff as a hash is invalid!
//
#define EXCEPTION_TABLE_SIZE            0x10
#define EXCEPTION_TABLE_ID(H)           (((H) & 0xF0000000) >> 0x1c)

/// @brief The maximum offset for codeblocks extraction.
#define EXCEPTION_CODEBLOCKS_OFFSET     0x250

///
/// @brief The type of an exception.
///
typedef enum _EXCEPTION_TYPE
{
    exceptionTypeUm,                        ///< User-mode exception.
    exceptionTypeKm,                        ///< Kernel-mode exception.
    exceptionTypeUmGlob,                    ///< User-mode exception that accepts glob content.
    exceptionTypeKmUm,                      ///< Kernel-User mode exception.
} EXCEPTION_TYPE;


///
/// @brief The identifier that describes a range of signatures.
///
typedef enum _EXCEPTION_SIGNATURE_TYPE
{
    signatureTypeVersionOs          = 50,   ///< The range-identifier used for version operating system signature.
    signatureTypeVersionIntro       = 51,   ///< The range-identifier used for version introspection signature.
    signatureTypeProcessCreation    = 70,   ///< The range-identifier used for process creation signature.
    signatureTypeExport             = 100,  ///< The range-identifier used for export signature.
    signatureTypeValue              = 200,  ///< The range-identifier used for value signature.
    signatureTypeIdt                = 300,  ///< The range-identifier used for idt signature.
    signatureTypeValueCode          = 500,  ///< The range-identifier used for value-code signature.
    signatureTypeCodeBlocks         = 600,  ///< The range-identifier used for codeblocks signature.
} EXCEPTION_SIGNATURE_TYPE;


///
/// @brief Describes the internal exceptions data.
///
typedef struct _EXCEPTIONS
{
    /// @brief  Linked list used for kernel-mode exceptions that have a generic originator (*).
    LIST_HEAD   GenericKernelExceptions;
    /// @brief  Linked list used for user-mode exceptions that have a generic originator(*).
    LIST_HEAD   GenericUserExceptions;

    /// @brief  Linked list used for kernel-user mode exceptions that have a generic originator(*).
    LIST_HEAD   GenericKernelUserExceptions;

    /// @brief  Linked list used for kernel-mode exceptions that don't have a valid originator (-).
    LIST_HEAD   NoNameKernelExceptions;
    /// @brief  Linked list used for user-mode exceptions that don't have a valid originator (-).
    LIST_HEAD   NoNameUserExceptions;

    /// @brief  Linked list used for kernel-user mode exceptions that don't have a valid originator (-).
    LIST_HEAD   NoNameKernelUserExceptions;

    /// @brief  Linked list used for user-mode exceptions that contains glob content.
    LIST_HEAD   GlobUserExceptions;

    LIST_HEAD   KernelExceptions[EXCEPTION_TABLE_SIZE];     ///< Array of linked lists used for kernel-mode exceptions.
    LIST_HEAD   KernelUserExceptions[EXCEPTION_TABLE_SIZE]; ///< Array of linked lists used for kernel-user mode exceptions.
    LIST_HEAD   UserExceptions[EXCEPTION_TABLE_SIZE];       ///< Array of linked lists used for user-mode exceptions.
    LIST_HEAD   ProcessCreationExceptions;                  ///< Linked list used for process creations exceptions.

    /// @brief  Linked list used for user-mode exceptions that have the feedback flag.
    LIST_HEAD   UserFeedbackExceptions;
    /// @brief  Linked list used for kernel-mode exceptions that have the feedback flag.
    LIST_HEAD   KernelFeedbackExceptions;
    /// @brief  Linked list used for kernel-user mode exceptions that have the feedback flag.
    LIST_HEAD   KernelUserFeedbackExceptions;
    /// @brief  Linked list used for process-creation exceptions that have the feedback flag.
    LIST_HEAD   ProcessCreationFeedbackExceptions;

    /// @brief  Linked list used for process-creation exceptions that are added from alert.
    LIST_HEAD   ProcessCreationAlertExceptions;
    /// @brief  Linked list used for user-mode exceptions that are added from alert.
    LIST_HEAD   UserAlertExceptions;
    /// @brief  Linked list used for kernel-mode exceptions that are added from alert.
    LIST_HEAD   KernelAlertExceptions;
    /// @brief  Linked list used for kernel-user mode exceptions that are added from alert.
    LIST_HEAD   KernelUserAlertExceptions;

    LIST_HEAD   CbSignatures;                           ///< Linked list used for codeblocks signatures.
    LIST_HEAD   ExportSignatures;                       ///< Linked list used for export signatures.
    LIST_HEAD   ValueSignatures;                        ///< Linked list used for value signatures.
    LIST_HEAD   ValueCodeSignatures;                    ///< Linked list used for value-code signatures.
    LIST_HEAD   IdtSignatures;                          ///< Linked list used for IDT signatures.
    LIST_HEAD   VersionOsSignatures;                    ///< Linked list used for operating system version signatures.
    LIST_HEAD   VersionIntroSignatures;                 ///< Linked list used for introspection version signatures.
    LIST_HEAD   ProcessCreationSignatures;              ///< Linked list used for process-creation signatures.

    struct
    {
        DWORD       Build;
        WORD        Major;
        WORD        Minor;
    } Version;                                          ///< Loaded exceptions binary version.

    BOOLEAN     Loaded;                                 ///< True if the exceptions are loaded.
} EXCEPTIONS, *PEXCEPTIONS;


///
/// @brief Object type of the kernel-mode exception.
///
typedef enum _KM_EXCEPTION_OBJECT
{
    kmObjNone = 0,              ///< Blocking exception.
    kmObjAny,                   ///< The modified object is any with the modified name.
    kmObjDriver,                ///< The modified object is anything inside the driver.
    kmObjDriverImports,         ///< The modified object is only the driver's EAT.
    kmObjDriverCode,            ///< The modified object is only the driver's code sections.
    kmObjDriverData,            ///< The modified object is only the driver's data sections.
    kmObjDriverResources,       ///< The modified object is only the driver's resources sections.
    kmObjSsdt,                  ///< The modified object is SSDT (valid only on windows x86).
    kmObjDrvObj,                ///< The modified object is anything inside the driver object.
    kmObjFastIo,                ///< The modified object is anything inside the driver's fast IO dispatch table.
    kmObjMsr,                   ///< The modified object is a MSR.
    kmObjCr4,                   ///< The modified object is SMEP and/or SMAP bits of  CR4.
    kmObjHalHeap,               ///< The modified object is anything inside the HAL heap zone.
    kmObjSelfMapEntry,          ///< The modified object is the self map entry inside PDBR.
    kmObjIdt,                   ///< The modified object is any IDT entry.
    kmObjIdtr,                  ///< The modified object is IDTR.
    kmObjGdtr,                  ///< The modified object is GDTR.
    ///< The modified object is WMI_LOGGER_CONTEXT.GetCpuClock used by InfinityHook (valid only on windows).
    kmObjLoggerCtx,
    kmObjDriverExports,         ///< The modified object is only the driver's IAT.
    kmObjTokenPrivs,            ///< The modified object is the privileges field inside the nt!_TOKEN structure.
    kmObjSudExec,               ///< The modified object represents an execution inside SharedUserData.
    kmObjHalPerfCnt,            ///< The modified object is HalPerformanceCounter.
    kmObjSecDesc,               ///< The modified object is the security descriptor pointer of a process.
    kmObjAcl,                   ///< The modified object is an ACL (SACL/DACL) of a process.
    kmObjSudModification,       ///< The modified object is a SharedUserData field.
    kmObjInterruptObject,       ///< The modified object is an interrupt object from KPRCB.

    // Add more as needed
} KM_EXCEPTION_OBJECT;


///
/// @brief Object type of the kernel-user mode exception.
///
typedef enum _KUM_EXCEPTION_OBJECT
{
    kumObjNone = 0,         ///< Blocking exception.
    kumObjAny,              ///< The modified object is any with the modified name.
    kumObjModule,           ///< The modified object is inside the process modules.
    kumObjModuleImports,    ///< The modified object is inside the process module's IAT.
    kumObjModuleExports     ///< The modified object is inside the process module's EAT.

    // Add more as needed
} KUM_EXCEPTION_OBJECT;


///
/// @brief Object type of the user-mode exception
///
typedef enum _UM_EXCEPTION_OBJECT
{
    umObjNone = 0,                  ///< Blocking exception.
    umObjAny,                       ///< The modified object is any with the modified name.
    umObjProcess,                   ///< The modified object is only another process (injection basically).
    umObjModule,                    ///< The modified object is inside the process modules.
    umObjModuleImports,             ///< The modified object is inside the process module's IAT.
    umObjNxZone,                    ///< The object that has a NX zone is executed.
    umObjModuleExports,             ///< The modified object is inside the process module's EAT.
    /// @brief   The modified object is anything inside the structure CONTEXT (valid only for windows).
    umObjProcessThreadContext,
    umObjProcessPeb32,              ///< The modified object is anything inside of the PEB32 structure.
    umObjProcessPeb64,              ///< The modified object is anything inside of the PEB64 structure.
    /// @brief The modified object is the thread which was performed an asynchronous procedure call on.
    umObjProcessApcThread,
    umObjProcessCreation,           ///< The process object creates another process.
    /// @brief The object allows only dlls which are detected as suspicous (e.g. module loads before kernel32.dll
    ///        through double agent technique).
    umObjModuleLoad,
    umObjProcessCreationDpi,        ///< The process object creates another process using DPI flags.
    umObjSharedUserData,            ///< Signals an execution inside SharedUserData.
    umObjProcessInstrumentation,    ///< Signals an attempt to set an insturmentation callback.

    // Add more as needed
} UM_EXCEPTION_OBJECT;



///
/// @brief The exception ID. The layout consists of the exception type and the unique identifier of the exception.
///
#pragma pack(push)
#pragma pack(4)
typedef union _EXCEPTION_SIGNATURE_ID
{
    struct
    {
        DWORD Value : 22;               ///< Contains an unique value.
        DWORD Type : 10;                ///< Contains a type of signature (#EXCEPTION_SIGNATURE_TYPE).
    } Field;

    DWORD Value;                        ///< The union between the type and the value.
} EXCEPTION_SIGNATURE_ID, *PEXCEPTION_SIGNATURE_ID;


///
/// @brief Describe a kernel-mode exception.
///
typedef struct _KM_EXCEPTION
{
    LIST_ENTRY  Link;

    DWORD       OriginatorNameHash;             ///< Contains the originator name-hash.

    DWORD       VictimNameHash;                 ///< Contains the victim name-hash.

    DWORD       Flags;                          ///< Contains any flags from #EXCEPTION_FLG.

    KM_EXCEPTION_OBJECT Type;                   ///< Contains the type of the exception (#KM_EXCEPTION_OBJECT).

    QWORD       Context;                        ///< Contains the context given by the integrator.

    WORD                        SigCount;       ///< Contains the number of signatures.
    EXCEPTION_SIGNATURE_ID      Signatures[];   ///< Contains a array of signatures ID.
} KM_EXCEPTION, *PKM_EXCEPTION;


///
/// @brief Describe a kernel-user mode exception.
///
typedef struct _KUM_EXCEPTION
{
    LIST_ENTRY  Link;

    union
    {
        DWORD       NameHash;                   ///< Contains the originator name-hash.
        DWORD       DriverHash;                 ///< Contains the originator driver name-hash.
        DWORD       ProcessHash;                ///< Contains the originator process name-hash.
    } Originator;

    struct
    {
        DWORD   NameHash;                       ///< Contains the name-hash of the modified module.
        /// @brief  Contains the name-hash of the process in which the modification takes place.
        DWORD   ProcessHash;
    } Victim;

    DWORD       Flags;                          ///< Contains any flags from #EXCEPTION_FLG.

    KUM_EXCEPTION_OBJECT Type;                  ///< Contains the type of the exception (#KM_EXCEPTION_OBJECT).

    QWORD       Context;                        ///< Contains the context given by the integrator.

    WORD                        SigCount;       ///< Contains the number of signatures.
    EXCEPTION_SIGNATURE_ID      Signatures[];   ///< Contains a array of signatures ID.
} KUM_EXCEPTION, *PKUM_EXCEPTION;



///
/// @brief Describe a user-mode exception.
///
typedef struct _UM_EXCEPTION
{
    LIST_ENTRY  Link;

    DWORD       OriginatorNameHash;         ///< Contains the originator name-hash.

    struct
    {
        DWORD   NameHash;                   ///< Contains the name-hash of the modified process.
        /// @brief  Contains the name-hash of the process in which the modification
        /// takes place (missing for injections).
        DWORD   ProcessHash;
    } Victim;

    DWORD       Flags;                      ///< Contains any flags from #_EXCEPTION_FLG.

    UM_EXCEPTION_OBJECT Type;               ///< Contains the type of the exception (#UM_EXCEPTION_OBJECT).

    QWORD       Context;                    ///< Contains the context given by the integrator.

    WORD                    SigCount;       ///< Contains the number of signatures.
    EXCEPTION_SIGNATURE_ID  Signatures[];   ///< Contains an array of signatures ID.
} UM_EXCEPTION, *PUM_EXCEPTION;


///
/// @brief Describe a user-mode glob exception.
///
typedef struct _UM_EXCEPTION_GLOB
{
    LIST_ENTRY  Link;

    /// @brief  Contains the name (a string that can contain glob items) of the originator.
    char        OriginatorNameGlob[EXCEPTION_UM_GLOB_LENGTH];

    struct
    {
        /// @brief  Contains the name (a string that can contain glob items) of the modified process.
        CHAR    NameGlob[EXCEPTION_UM_GLOB_LENGTH];
        /// @brief Contains the name of the process(a string that can contain glob items) in which the modification
        /// takes place (missing for injections).
        CHAR    ProcessGlob[EXCEPTION_UM_GLOB_LENGTH];
    } Victim;

    DWORD       Flags;                                  ///< Contains any flags from #EXCEPTION_FLG.

    UM_EXCEPTION_OBJECT Type;                           ///< Contains the type of the exception (#UM_EXCEPTION_OBJECT).

    QWORD       Context;                                ///< Contains the context given by the integrator.

    WORD                        SigCount;               ///< Contains the number of signatures.
    EXCEPTION_SIGNATURE_ID      Signatures[];           ///< Contains an array of signatures ID.
} UM_EXCEPTION_GLOB, *PUM_EXCEPTION_GLOB;


///
/// @brief Describe a codeblocks signature hash.
///
typedef struct _SIG_CODEBLOCK_HASH
{
    BYTE    Count;                      ///< The number of hashes from the list.
    DWORD   Hashes[];                   ///< The list of hashes.
} SIG_CODEBLOCK_HASH, *PSIG_CODEBLOCK_HASH;


///
/// @brief Describe a value signature hash.
///
typedef struct _SIG_VALUE_HASH
{
    WORD    Offset;                 ///< The displacement from the beginning of the modified zone.
    WORD    Size;                   ///< The size of of the modified zone.
    DWORD   Hash;                   ///< The hash of the modified zone.
} SIG_VALUE_HASH, *PSIG_VALUE_HASH;


///
/// @brief Describe a export signature hash.
///
typedef struct _SIG_EXPORT_HASH
{
    WORD    Delta;                  ///< The number of bytes that are modified.
    DWORD   Hash;                   ///< The hash of the modified function name.
} SIG_EXPORT_HASH, *PSIG_EXPORT_HASH;


///
/// @brief Describes a codeblocks signature.
///
typedef struct _EXCEPTION_CB_SIGNATURE
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#_EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #_SIGNATURE_FLG.

    BYTE        Score;                  ///< The number of (minimum) hashes from a list that need to match.
    BYTE        ListsCount;             ///< The number of the list of hashes.
    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    CHAR        Object[];               ///< Contains list of (#SIG_CODEBLOCK_HASH).
} SIG_CODEBLOCKS, *PSIG_CODEBLOCKS;


///
/// @brief Describes a value signature.
///
typedef struct _SIG_VALUE_CODE
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    INT16       Offset;                 ///< The displacement from the beginning of the modified zone.
    WORD        Length;                 ///< The length of the opcode pattern.
    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    WORD        Object[];               ///< Contains list of opcodes.
} SIG_VALUE_CODE, *PSIG_VALUE_CODE;


///
/// @brief Describes a export signature.
///
typedef struct _SIG_EXPORT
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    DWORD       LibraryNameHash;        ///< The name-hash of the modified library.

    BYTE        ListsCount;             ///< The number of the list of hashes.
    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    CHAR        Object[];               ///< Contains lists of (#SIG_EXPORT_HASH).
} SIG_EXPORT, *PSIG_EXPORT;


///
/// @brief Describes a value signature.
///
typedef struct _SIG_VALUE
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    BYTE        Score;                  ///< The number of (minimum) hashes from a list that need to match.
    BYTE        ListsCount;             ///< The number of the list of hashes.
    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    CHAR        Object[];               ///< Contains lists of (#SIG_VALUE_HASH).
} SIG_VALUE, *PSIG_VALUE;


///
/// @brief Describes a idt signature.
///
typedef struct _SIG_IDT
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    BYTE        Entry;                  ///< The number of the IDT entry.

    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.
} SIG_IDT, *PSIG_IDT;


///
/// @brief Describes a operating system version signature.
///
typedef struct _SIG_VERSION_OS
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    union
    {
        ///< Contains the minimum  version.patch.sublevel-backport of the operating system (used for Linux).
        struct
        {
            BYTE Version;
            BYTE Patch;
            WORD Sublevel;
            WORD Backport;
            BYTE _Reserved[2];
        };

        QWORD Value;            ///< Contains the minimum build number of the operating system (used for windows).
    } Minimum;

    union
    {
        ///< Contains the maximum version.patch.sublevel-backport of the operating system (used for Linux).
        struct
        {
            BYTE Version;
            BYTE Patch;
            WORD Sublevel;
            WORD Backport;
            BYTE _Reserved[2];
        };

        QWORD Value;                ///< Contains the maximum build number of the operating system (used for Windows).
    } Maximum;

} SIG_VERSION_OS, *PSIG_VERSION_OS;


///
/// @brief Describes a introspection version signature.
///
typedef struct _SIG_VERSION_INTRO
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;         ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;                  ///< Contains any flags from #SIGNATURE_FLG.

    BOOLEAN     AlertSignature;         ///< True if the signature is added from alert.

    union
    {
        ///< Contains the minimum version of the introspection.
        struct
        {
            WORD    Major;
            WORD    Minor;
            WORD    Revision;
            WORD    Build;
        };

        QWORD Raw;
    } Minimum;

    union
    {
        ///< Contains the maximum version of the introspection.
        struct
        {
            WORD    Major;
            WORD    Minor;
            WORD    Revision;
            WORD    Build;
        };

        QWORD Raw;
    } Maximum;

} SIG_VERSION_INTRO, *PSIG_VERSION_INTRO;


///
/// @brief Describes a process-creation signature.
///
typedef struct _SIG_PROCESS_CREATION
{
    LIST_ENTRY  Link;

    EXCEPTION_SIGNATURE_ID  Id;     ///< An unique id (#EXCEPTION_SIGNATURE_ID).
    DWORD       Flags;              ///< Contains any flags from #SIGNATURE_FLG.

    BOOLEAN     AlertSignature;     ///< True if the signature is added from alert.

    DWORD       CreateMask;         ///< Contains the DPI mask.

} SIG_PROCESS_CREATION, *PSIG_PROCESS_CREATION;

#pragma pack(pop)


///
/// @brief Describes the flags that can be used by an exception
///
typedef enum _EXCEPTION_FLG
{
    EXCEPTION_FLG_FEEDBACK          = 0x00000001,       ///< The exception sends a feedback alert.
    EXCEPTION_FLG_32                = 0x00000002,       ///< The exception is valid only on 32 bit systems/process.
    EXCEPTION_FLG_64                = 0x00000004,       ///< The exception is valid only on 64 bit systems/process.
    /// @brief  The exception will match only for the init phase of a driver/process.
    EXCEPTION_FLG_INIT              = 0x00000008,
    /// @brief  The exception will take into consideration the return driver/dll.
    EXCEPTION_FLG_RETURN            = 0x00000010,

    EXCEPTION_FLG_LINUX             = 0x00000080,       ///< The exception is valid only for Linux.

    EXCEPTION_FLG_READ              = 0x10000000,       ///< The exception is valid only for read violation.
    EXCEPTION_FLG_WRITE             = 0x20000000,       ///< The exception is valid only for write violation.
    EXCEPTION_FLG_EXECUTE           = 0x40000000,       ///< The exception is valid only for execute violation.

    EXCEPTION_FLG_IGNORE            = 0x80000000,       ///< This exception will be ignored.

    /// @brief  The original RIP is outside a driver and it returns into a driver (which is the originator name).
    EXCEPTION_KM_FLG_NON_DRIVER     = 0x00000100,
    /// @brief  The exception will take into consideration the return driver.
    EXCEPTION_KM_FLG_RETURN_DRV     = 0x00000200,
    EXCEPTION_KM_FLG_SMAP           = 0x00000400,       ///< The exception is valid only for CR4.SMAP write.
    EXCEPTION_KM_FLG_SMEP           = 0x00000800,       ///< The exception is valid only for CR4.SMEP write.

    EXCEPTION_KM_FLG_INTEGRITY      = 0x00001000,       ///< The exception is valid only for integrity zone.

    /// @brief  The exception is valid only if the originator process is a system process.
    EXCEPTION_UM_FLG_SYS_PROC       = 0x00000100,
    /// @brief  The exception is valid only if the modified process is a child of the originator process.
    EXCEPTION_UM_FLG_CHILD_PROC     = 0x00000200,

    EXCEPTION_UM_FLG_ONETIME        = 0x00000800,       ///< The exception is valid only once.
    EXCEPTION_UM_FLG_LIKE_APPHELP   = 0x00001000,       ///< The exception is valid only for apphelp process.

    /// @brief The exception is valid only if the write comes due to an injection from user-mode.
    EXCEPTION_KUM_FLG_USER          = 0x00008000,
    /// @brief The exception is valid only if the write comes due to an injection from kernel-mode.
    EXCEPTION_KUM_FLG_KERNEL        = 0x00010000,
} EXCEPTION_FLG;


///
/// @brief The predefined names for kernel-user-mode exception.
///
typedef enum _KM_EXCEPTION_NAME
{
    kmExcNameAny = 0,       ///< The name can be any string.
    kmExcNameOwn,           ///< Allow modification of it's own driver object.
    kmExcNameKernel,        ///< The name is the operating system kernel name.
    kmExcNameHal,           ///< The name is the operating system HAL name (valid only for windows).
    kmExcNameNone,          ///< The name is missing.

    kmExcNameVdso,          ///< The name is the operating system vdso (valid only for Linux).
    kmExcNameVsyscall,      ///< The name is the operating system vsyscall (valid only for Linux).

    kmExcNameVeAgent,       ///< The name is the \#VE Agent.

    // Note: Add new names only from this line on, because the exception generation
    // script depends on the ordering of these values.

    // Add more as needed

    kmExcNameInvalid        ///< Used to indicate an invalid kernel-mode exception name.

} KM_EXCEPTION_NAME;


///
/// @brief The predefined names for kernel-mode exception.
///
typedef enum _KUM_EXCEPTION_NAME
{
    kumExcNameAny = 0,       ///< The name can be any string.
    kumExcNameOwn,           ///< Allow modification of it's own driver object.
    kumExcNameKernel,        ///< The name is the operating system kernel name.
    kumExcNameHal,           ///< The name is the operating system HAL name (valid only for windows).
    kumExcNameNone,          ///< The name is missing.

    // Note: Add new names only from this line on, because the exception generation
    // script depends on the ordering of these values.

    // Add more as needed

    kumExcNameInvalid        ///< Used to indicate an invalid kernel-mode exception name.

} KUM_EXCEPTION_NAME;


///
/// @brief The predefined names for user-mode exception.
///
typedef enum _UM_EXCEPTION_NAME
{
    umExcNameAny = 0,       ///< The name can be any string.
    umExcNameOwn,           ///< The name is any object belonging to this process (child not included).
    umExcNameVdso,          ///< The name is the operating system vdso (valid only for Linux).
    umExcNameVsyscall,      ///< The name is the operating system vsyscall (valid only for Linux).

    umExcNameNone,          ///< The name is missing.

    // Add more as needed

    umExcNameInvalid        ///< Used to indicate an invalid user-mode exception name.
} UM_EXCEPTION_NAME;


///
/// @brief Describes the flags that can be used by an signature.
///
typedef enum _SIGNATURE_FLG
{
    SIGNATURE_FLG_32                    = 0x00000001,   ///< The signature is valid only on 32 bit systems/processes.
    SIGNATURE_FLG_64                    = 0x00000002,   ///< The signature is valid only on 64 bit systems/processes.

    SIGNATURE_FLG_CB_MEDIUM             = 0x00000004,   ///< Codeblocks were extracted at a medium level.

    /// @brief  The value hash is for the process command line (valid only for value signature).
    SIGNATURE_FLG_VALUE_CLI             = 0x00010000,

    SIGNATURE_FLG_LINUX                 = 0x00000080,   ///< The signature is valid only on Linux.

} SIGNATURE_FLG;


//
// Zone flags
//
#define ZONE_LIB_IMPORTS        0x000000001ULL  ///< Used for the imports of a dll, driver, etc.
#define ZONE_LIB_EXPORTS        0x000000002ULL  ///< Used for the exports of a dll, driver, etc.
#define ZONE_LIB_CODE           0x000000004ULL  ///< Used for a generic code zone.
#define ZONE_LIB_DATA           0x000000008ULL  ///< Used for a generic data zone.
/// @brief  Used for the resources section (usually .rsrc inside a driver or dll).
#define ZONE_LIB_RESOURCES      0x000000010ULL

#define ZONE_PROC_THREAD_CTX    0x000000020ULL  ///< Used for the CONTEXT structure of a thread.
#define ZONE_PROC_THREAD_APC    0x000000040ULL  ///< Used for the APC thread hijacking technique.
#define ZONE_DEP_EXECUTION      0x000000080ULL  ///< Used for executions inside DEP zones.
#define ZONE_MODULE_LOAD        0x000000100ULL  ///< Used for exceptions for double agent.
#define ZONE_PROC_INSTRUMENT    0x000000200ULL  ///< Used for exceptions for instrumentation callback.

#define ZONE_WRITE              0x010000000ULL  ///< Used for write violation.
#define ZONE_READ               0x020000000ULL  ///< Used for read violation.
#define ZONE_EXECUTE            0x040000000ULL  ///< Used for execute violation.

#define ZONE_INTEGRITY          0x100000000ULL  ///< Used for integrity zone.


///
/// @brief Describes the zone types that can be excepted.
///
typedef enum _ZONE_TYPE
{
    exceptionZoneEpt = 1,           ///< The modified object is inside an EPT hook.
    exceptionZoneMsr,               ///< The modified object is a MSR.
    exceptionZoneCr,                ///< The modified object is a CR.
    exceptionZoneIntegrity,         ///< The modified object is inside an integrity hook.
    exceptionZoneProcess,           ///< The modified object is inside a process.
    exceptionZoneDtr,               ///< The modified object is IDTR/GDTR.
    exceptionZonePc,                ///< Used for process-creation violations.
} ZONE_TYPE;


///
/// @brief Describes an EPT victim.
///
typedef struct _EXCEPTION_VICTIM_EPT
{
    QWORD   Gva;                ///< The modified guest virtual address.
    QWORD   Gpa;                ///< The modified guest physical address.
} EXCEPTION_VICTIM_EPT, *PEXCEPTION_VICTIM_EPT;


///
/// @brief Describes a MSR victim.
///
typedef struct _EXCEPTION_VICTIM_MSR
{
    QWORD   NewDriverBase;      ///< The module base where the new value is.
    DWORD   Msr;                ///< The MSR written.
} EXCEPTION_VICTIM_MSR, *PEXCEPTION_VICTIM_MSR;


///
/// @brief Describes a CR victim.
///
typedef struct _EXCEPTION_VICTIM_CR
{
    DWORD   Cr;                 ///< The CR written.

    BOOLEAN Smap;               ///< True if SMAP is modified.
    BOOLEAN Smep;               ///< True if SMEP is modified.
} EXCEPTION_VICTIM_CR, *PEXCEPTION_VICTIM_CR;


///
/// @brief Describes a DTR victim.
///
typedef struct _EXCEPTION_VICTIM_DTR
{
    INTRO_OBJECT_TYPE   Type;   ///< The type of the modified object.
} EXCEPTION_VICTIM_DTR, *PEXCEPTION_VICTIM_DTR;


///
/// @brief Describes a integrity victim.
///
typedef struct _EXCEPTION_VICTIM_INTEGRITY
{
    QWORD   StartVirtualAddress;    ///< The start address of the integrity zone.
    DWORD   Offset;                 ///< The offset of the modification.
    DWORD   TotalLength;            ///< The length of the integrity zone.
    /// @brief The index of the modified interrupt object. Valid only for
    /// #introObjectTypeInterruptObject.
    BYTE    InterruptObjIndex;
    /// @brief  The new security descriptor buffer (valid only if
    /// #INTRO_OBJECT_TYPE is #introObjectTypeSecDesc or #introObjectTypeAcl)
    BYTE    *Buffer;
    /// @brief  The size of the new security descriptor buffer (valid only if
    /// #INTRO_OBJECT_TYPE is #introObjectTypeSecDesc or #introObjectTypeAcl)
    DWORD   BufferSize;
} EXCEPTION_VICTIM_INTEGRITY, *PEXCEPTION_VICTIM_INTEGRITY;


///
/// @brief Describes an injection.
///
typedef struct _EXCEPTION_VICTIM_INJECTION
{
    QWORD   Gva;                    ///< The guest virtual address to be written.
    DWORD   Length;                 ///< The length of the write.

    BYTE    *Buffer;                ///< The buffer to be written.
    DWORD   BufferSize;             ///< The buffer size to be written.
} EXCEPTION_VICTIM_INJECTION, *PEXCEPTION_VICTIM_INJECTION;

///
/// @brief Describes a victim module.
///
typedef struct _EXCEPTION_VICTIM_MODULE
{
    union
    {
        void                *Module;    ///< The internal structure of a module.
        WIN_PROCESS_MODULE  *WinMod;    ///< The internal structure of a windows module.

    };

    char    SectionName[9];             ///< The section name in witch it was modified.

    WINUM_CACHE_EXPORT  *Export;        ///< The export cache for the modified module.
} EXCEPTION_VICTIM_MODULE, *PEXCEPTION_VICTIM_MODULE;


///
/// @brief Describes a victim object.
///
typedef struct _EXCEPTION_VICTIM_OBJECT
{
    INTRO_OBJECT_TYPE   Type;           ///< The type of the modified object.

    DWORD               NameHash;       ///< The hash of the modified object.

    union
    {
        char    *Name;                  ///< The modified process name.
        WCHAR   *NameWide;              ///< The modified module name.
    };

    /// @brief  Depending on INTRO_OBJECT_TYPE we have: CR3 for processes / ModuleBase for km drivers and um dll.
    QWORD               BaseAddress;

    union
    {
        union
        {
            EXCEPTION_VICTIM_MODULE Module;         ///< Used when a module is modified.
            WIN_DRIVER_OBJECT       *DriverObject;  ///< Used when a driver object / fastio dispatch table is modified.
        };

        // All of the fields can be valid (injection into a library which has a VAD for eg.).
        struct
        {
            VAD                     *Vad;           ///< The internal structure of the modified VAD.
            EXCEPTION_VICTIM_MODULE Library;        ///< The victim module of the modified library.

            union
            {
                void               *Process;        ///< The internal structure of the modified process.
                WIN_PROCESS_OBJECT *WinProc;        ///< The internal structure of the modified Windows process.
                LIX_TASK_OBJECT    *LixProc;        ///< The internal structure of the modified Linux process.
            };
        };
    };
} EXCEPTION_VICTIM_OBJECT, *PEXCEPTION_VICTIM_OBJECT;


///
/// @brief Describes the modified zone.
///
typedef struct _EXCEPTION_VICTIM_ZONE
{
    EXCEPTION_VICTIM_OBJECT Object;             ///< The modified object.

    ZONE_TYPE               ZoneType;           ///< The type of the modified zone.
    QWORD                   ZoneFlags;          ///< The flags of the modified zone.

    QWORD                   ProtectionFlag;     ///< The protection flags of the modified zone.

    union
    {
        EXCEPTION_VICTIM_EPT        Ept;        ///< Valid if the modified zone is EPT.
        EXCEPTION_VICTIM_MSR        Msr;        ///< Valid if the modified zone is MSR.
        EXCEPTION_VICTIM_CR         Cr;         ///< Valid if the modified zone is CR.
        EXCEPTION_VICTIM_DTR        Dtr;        ///< Valid if the modified zone is DTR.
        EXCEPTION_VICTIM_INTEGRITY  Integrity;  ///< Valid if the modified zone is Integrity.
        EXCEPTION_VICTIM_INJECTION  Injection;  ///< Valid if the modified zone is Injection.
    };

    union
    {
        struct
        {
            QWORD   OldValue[8];    ///< The original value (maximum 512 bits in case of AVX2).
            QWORD   NewValue[8];    ///< The new value written (maximum 512 bits in case of AVX2).

            DWORD   AccessSize;     ///< The actual size of the write.
        } WriteInfo;

        struct
        {
            QWORD   Value[8];       ///< The original value (maximum 512 bits in case of AVX2).

            DWORD   AccessSize;     ///< The actual size of the write.
        } ReadInfo;

        struct
        {
            QWORD       Rsp;        ///< The value of the guest RSP register at the moment of execution.
            QWORD       StackBase;  ///< The stack base for the thread that attempted the execution.
            QWORD       StackLimit; ///< The stack limit for the thread that attempted the execution.
            DWORD       Length;     ///< The length of the instruction.
        } ExecInfo;
    };
} EXCEPTION_VICTIM_ZONE, *PEXCEPTION_VICTIM_ZONE;


///
/// @brief Describes a kernel-mode originator
///
typedef struct _EXCEPTION_KM_ORIGINATOR
{
    struct
    {
        DWORD           NameHash;               ///< The namehash of the originator return driver.
        DWORD           PathHash;               ///< The pathhash of the originator return driver.
        KERNEL_DRIVER   *Driver;                ///< The driver that's modifying the memory.
        QWORD           Rip;                    ///< The RIP from where the call to the exported function came.
        CHAR            Section[9];             ///< The section where the Rip (not Original Rip) comes from.
    } Return;

    STACK_ELEMENT StackElements[8];             ///< The stacktrace starting from current rip.
    STACK_TRACE StackTrace;

    // Only valid in kernel exceptions
    struct
    {
        DWORD           NameHash;               ///< The namehash of the originator return driver.
        DWORD           PathHash;               ///< The pathhash of the originator return driver.
        KERNEL_DRIVER   *Driver;                ///< The driver that's modifying the memory.
        QWORD           Rip;                    ///< The RIP from where the call to the exported function came.
        CHAR            Section[9];             ///< The section where the Rip (not Original Rip) comes from.
    } Original;

    union
    {
        /// @brief The process object from which the write originates. Valid only for KM-UM writes due to an injection
        ///        originating from user-mode.
        void                *Process;
        WIN_PROCESS_OBJECT  *WinProc;           ///< The Windows process object from which the write originates.
        LIX_TASK_OBJECT     *LixProc;           ///< The Linux process object from which the write originates.
    } Process;

    /// @brief  The modifying instruction (at the OriginalRip). There's no point in getting the instruction at Rip,
    /// since it will be a CALL/JMP.
    INSTRUX                 *Instruction;

    BOOLEAN                 IsEntryPoint;       ///< The the Return-Rip is insied the 'INIT' section.
    BOOLEAN                 IsIntegrity;        ///< True if the originator is found by an integrity check.

    struct
    {
        BOOLEAN User : 1;                       ///< This field is set to TRUE for a write due to an injection from user-mode.
        BOOLEAN Kernel : 1;                     ///< This field is set to TRUE for a write due to an injection from kernel-mode.
    } Injection;
} EXCEPTION_KM_ORIGINATOR, *PEXCEPTION_KM_ORIGINATOR;


///
/// @brief Describes a user-mode originator
///
typedef struct _EXCEPTION_UM_ORIGINATOR
{
    DWORD       NameHash;       ///< The namehash of the process.

    union
    {
        PCHAR   Name;           ///< The process name of the originator (saved as CHAR).
        PWCHAR  NameWide;       ///< The module name of the originator (saved as WCHAR).
    };

    union
    {
        void                *Process;   ///< The process that's modifying the memory (always present).
        WIN_PROCESS_OBJECT  *WinProc;   ///< The windows process that's modifying the memory (always present).
        LIX_TASK_OBJECT     *LixProc;   ///< The Linux process that's modifying the memory (always present).
    };

    union
    {
        void                *Library;   ///< The library that's modifying the memory (if that's the case).
        WIN_PROCESS_MODULE  *WinLib;    ///< The windows library that's modifying the memory (if that's the case).
    };

    union
    {
        QWORD   Rip;            ///< Where the write/exec came.
        QWORD   SourceVA;       ///< The GVA from where the injection is.
    };

    struct
    {
        DWORD   NameHash;       ///< The namehash of the return originator.
        union
        {
            PCHAR   Name;       ///< The process name of the return originator (saved as CHAR).
            PWCHAR  NameWide;   ///< The module name of the return originator (saved as WCHAR).

        };
        QWORD   Rip;            ///< The RIP from where the violation came.

        union
        {
            void                *Library;   ///< The library that's modifying the memory (if that's the case).
            WIN_PROCESS_MODULE  *WinLib;    ///< The windows library that's modifying the memory (if that's the case).
        };
    } Return;

    INTRO_PC_VIOLATION_TYPE     PcType;       ///< Valid if the current violation is DPI Process Creation Violation.

    INSTRUX     *Instruction;   ///< The modifying/executing instruction (valid when Rip != 0).

    BOOLEAN     Execute;        /// True if the current violation is an execution.
} EXCEPTION_UM_ORIGINATOR, *PEXCEPTION_UM_ORIGINATOR;


/// @brief  Flag that can be passed to #IntExceptKernelGetOriginator if the action should not be blocked.
///
/// Useful when we want to obtain a #EXCEPTION_KM_ORIGINATOR structure, but we do not want to block the action if
/// the structure could not be properly filled.
#define EXCEPTION_KM_ORIGINATOR_OPT_DO_NOT_BLOCK    0x00000001u

/// @brief  Flag that can be passed to #IntExceptKernelGetOriginator when the full stack is needed.
///
/// In the usual cases, we fetch only the first return address if the originator RIP is contained inside a valid
/// module. This flag should be used when there is need for at most three extracted stack traces, disregarding
/// whether the originator module is valid or not.
#define EXCEPTION_KM_ORIGINATOR_OPT_FULL_STACK      0x00000002u


//
// Helpers
//
#define for_each_km_exception(_ex_head, _var_name) \
    list_for_each(_ex_head, KM_EXCEPTION, _var_name)
#define for_each_kum_exception(_ex_head, _var_name) \
    list_for_each(_ex_head, KUM_EXCEPTION, _var_name)
#define for_each_um_exception(_ex_head, _var_name) \
    list_for_each(_ex_head, UM_EXCEPTION, _var_name)
#define for_each_um_glob_exception(_ex_head, _var_name) \
    list_for_each(_ex_head, UM_EXCEPTION_GLOB, _var_name)
#define for_each_cb_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_CODEBLOCKS, _var_name)
#define for_each_export_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_EXPORT, _var_name)
#define for_each_value_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_VALUE, _var_name)
#define for_each_value_code_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_VALUE_CODE, _var_name)
#define for_each_idt_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_IDT, _var_name)
#define for_each_version_os_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_VERSION_OS, _var_name)
#define for_each_version_intro_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_VERSION_INTRO, _var_name)
#define for_each_process_creation_signature(_ex_head, _var_name) \
    list_for_each(_ex_head, SIG_PROCESS_CREATION, _var_name)


//
// Functions
//

INTSTATUS
IntExceptInit(
    void
    );

INTSTATUS
IntExceptUninit(
    void
    );

INTSTATUS
IntExceptAlertRemove(
    void
    );

INTSTATUS
IntExceptRemove(
    void
    );

int
IntExceptPrintLixTaskInfo(
    _In_opt_ const LIX_TASK_OBJECT *Task,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    );

int
IntExceptPrintWinModInfo(
    _In_ WIN_PROCESS_MODULE *Module,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    );

int
IntExceptPrintWinProcInfo(
    _In_ WIN_PROCESS_OBJECT *Process,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    );

int
IntExceptPrintWinKmModInfo(
    _In_ KERNEL_DRIVER *Module,
    _In_ char *Header,
    _Out_ char *Line,
    _In_ int MaxLength,
    _In_opt_ DWORD NameAlignment
    );

void
IntExceptUserLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    );

void
IntExceptKernelLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    );

void
IntExceptKernelUserLogInformation(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    );

void
IntExceptDumpSignatures(
    _In_ void *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ BOOLEAN KernelMode,
    _In_ BOOLEAN ReturnDrv
    );

INTSTATUS
IntExceptKernelGetOriginator(
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ DWORD Options
    );

INTSTATUS
IntExceptUserGetExecOriginator(
    _In_ void *Process,
    _Out_ EXCEPTION_UM_ORIGINATOR *Originator
    );

INTSTATUS
IntExceptUserGetOriginator(
    _In_ void *Process,
    _In_ BOOLEAN ModuleWrite,
    _In_ QWORD Address,
    _In_opt_ INSTRUX *Instrux,
    _Out_ EXCEPTION_UM_ORIGINATOR *Originator
    );

INTSTATUS
IntExceptGetOriginatorFromModification(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _Out_ EXCEPTION_KM_ORIGINATOR *Originator
    );

INTSTATUS
IntExceptGetVictimCr(
    _In_ QWORD NewValue,
    _In_ QWORD OldValue,
    _In_ DWORD Cr,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimEpt(
    _In_opt_ void *Context,
    _In_ QWORD Gpa,
    _In_ QWORD Gva,
    _In_ INTRO_OBJECT_TYPE Type,
    _In_ DWORD ZoneFlags,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimProcess(
    _In_ void *Process,
    _In_ QWORD DestinationGva,
    _In_ DWORD Length,
    _In_ QWORD ZoneFlags,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimIntegrity(
    _In_ INTEGRITY_REGION *IntegrityRegion,
    _Inout_ DWORD *Offset,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimMsr(
    _In_ QWORD NewValue,
    _In_ QWORD OldValue,
    _In_ DWORD Msr,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimDtr(
    _In_ DTR *NewValue,
    _In_ DTR *OldValue,
    _In_ INTRO_OBJECT_TYPE Type,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptGetVictimProcessCreation(
    _In_ void *Process,
    _In_ INTRO_OBJECT_TYPE ObjectType,
    _Out_ EXCEPTION_VICTIM_ZONE *Victim
    );

INTSTATUS
IntExceptKernelVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    );

INTSTATUS
IntExceptUserVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    );

INTSTATUS
IntExceptKernelUserVerifyExtra(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION *Exception
    );

INTSTATUS
IntExceptUserVerifyExtraGlobMatch(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ UM_EXCEPTION_GLOB *Exception
    );

INTSTATUS
IntExceptMatchException(
    _In_ void *Victim,
    _In_ void *Originator,
    _In_ void *Exception,
    _In_ EXCEPTION_TYPE ExceptionType,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    );

INTSTATUS
IntExceptKernelMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ KM_EXCEPTION *Exception
    );

INTSTATUS
IntExceptUserMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _In_ void *Exception,
    _In_ EXCEPTION_TYPE ExceptionType
    );

INTSTATUS
IntExceptKernelUserMatchVictim(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ KUM_EXCEPTION *Exception
    );

INTSTATUS
IntExceptKernel(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    );

INTSTATUS
IntExceptUser(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_UM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    );

INTSTATUS
IntExceptKernelUser(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason
    );

void
IntExcept(
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ void *Originator,
    _In_ EXCEPTION_TYPE Type,
    _Out_ INTRO_ACTION *Action,
    _Out_ INTRO_ACTION_REASON *Reason,
    _In_ INTRO_EVENT_TYPE EventClass
    );

void
IntExceptInvCbCacheByGva(
    _In_ QWORD Gva
    );

void
IntExceptInvCbCacheByCr3(
    _In_ QWORD Cr3
    );

BOOLEAN
IntUpdateAreExceptionsLoaded(
    void
    );

/// @brief  Frees an exception or a signature buffer and removes it from the list it is currently in.
///
/// @param[in, out] Ptr     Pointer to the exception to be freed. Will be set to NULL.
/// @param[in]      Tag     The tag used when allocating Ptr.
///
/// @pre            The exception or the signature must be inserted in a list.
/// @post           The exception or the signature is removed from the list and the buffer is freed.
#define IntExceptErase(Ptr, Tag)                \
    do {                                        \
        RemoveEntryList(&((Ptr)->Link));        \
        HpFreeAndNullWithTag(&(Ptr), (Tag));    \
    } while(0)

#endif // _EXCEPTIONS_H_
