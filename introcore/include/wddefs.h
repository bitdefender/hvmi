/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   wddefs.h
///
/// @brief  Contains definitions for structures and constants used by the Windows kernel
///
/// A definition should be placed here if it is unchanged on most (if not all) Windows versions or if placing it
/// inside CAMI is not doable due to some reason. In general, try to avoid defining that types that need a switch
/// on the OS version in order to be used.
/// The definitions are either lifted from public Windows headers (this is the best guarantee that it will not change
/// over time), public debugging symbols, or through reverse engineering.
/// Try to not define all the fields in a structure, as that can quickly lead to the need of defining other structures.
/// Instead, definitions should be kept to the minimum necessary for introcore.
/// Since a 64-bit introcore is used for both 32- and 64-bit guests, structures that are needed for both OS versions
/// will usually be defined twice, once for 32-bit and once for 64-bit.
///

#ifndef _WDDEFS_H_
#define _WDDEFS_H_

#include "introdefs.h"

/// @brief  The offset of the IDT base inside the _KPCR
///
/// Valid for 32- and 64-bit guests
#define IDT_OFFSET                      0x38

#define IDT_DESC_SIZE32                 8   ///< The size of a 32-bit interrupt descriptor
#define IDT_DESC_SIZE64                 16  ///< The size of a 64-bit interrupt descriptor

/// @brief  The type of a _DRIVER_OBJECT structure
///
/// This is the value of the Type field inside the _DRIVER_OBJECT structure
#define DRIVER_OBJECT_TYPE              4

/// @brief  The size of the KeServiceDescriptorTable
///
/// ServiceTableBase, ServiceCounterTableBase, NumberOfServices and ParamTableBase
#define KESDT_SIZE                      (4 * 4)

//
//Windows OS Build number definitions
//
#define WIN_BUILD_7_0                   7600
#define WIN_BUILD_7_1                   7601
#define WIN_BUILD_7_2                   7602
#define WIN_BUILD_8                     9200
#define WIN_BUILD_8_1                   9600
#define WIN_BUILD_10_TH1                10240
#define WIN_BUILD_10_TH2                10586
#define WIN_BUILD_10_RS1                14393
#define WIN_BUILD_10_RS2                15063
#define WIN_BUILD_10_RS3                16299
#define WIN_BUILD_10_RS4                17134
#define WIN_BUILD_10_RS5                17763
#define WIN_BUILD_10_19H1               18362
#define WIN_BUILD_10_19H2               18362
#define WIN_BUILD_10_20H1               19041

//
// HAL related definitions hard coded by Windows versions prior to RS2
//

#define WIN_HAL_HEAP_BASE_32            0xFFD00000          ///< The base address of the HAL heap on 32-bit kernels
#define WIN_HAL_HEAP_BASE_64            0xFFFFFFFFFFD00000  ///< The base address of the HAL heap on 64-bit kernels

/// @brief      Checks if a guest virtual address resides inside the Windows kernel address space
///
/// @param[in]  is64    True for 64-bit guests, False for 32-bit guests
/// @param[in]  p       Guest virtual address to check
///
/// @returns    True if p points inside the kernel, False if it does not
#define IS_KERNEL_POINTER_WIN(is64, p)  ((is64) ? (((p) & 0xFFFF800000000000) == 0xFFFF800000000000) \
                                        : (((p) & 0x80000000) == 0x80000000))

/// @brief      Masks the unused part of a Windows guest virtual address
///
/// For 32-bit guests, masks the upper 32-bits of the address. Does nothing for 64-bit guests.
///
/// @param[in]  is64    True for 64-bit guests, False for 32-bit guests
/// @param[in]  x       The guest virtual address to be masked
///
/// @returns    The value of x after it has been masked
#define FIX_GUEST_POINTER(is64, x)      ((is64) ? (x) : ((x) & 0xFFFFFFFF))

/// @brief      Converts a _EX_FAST_REF value to a pointer
///
/// _EX_FAST_REF encapsulates both a pointer and a counter. It takes advantage of the fact most kernel data structures
/// are aligned to a 8-byte boundary on 32-bit kernels and on a 16-byte boundary on 64-bit kernels. Thus, the lower
/// 3 or 4 bits of their base address are always 0. Windows uses those as a reference counter. This macro cleans
/// them.
///
/// @param[in]  is64    True for 64-bit guests, False for 32-bit guests
/// @param[in]  p       A _EX_FAST_REF
///
/// @returns    The pointer value contained in the _EX_FAST_REF
#define EX_FAST_REF_TO_PTR(is64, p)     ((is64) ? (p) & ~(0x0FULL) : (p) & ~(0x07ULL))

///
/// @brief      A _UNICODE_STRING structure as defined by Windows
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct _UNICODE_STRING
{
    UINT16 Length;
    UINT16 MaximumLength;
    WORD*Buffer;
} UNICODE_STRING;

#pragma pack(push)
#pragma pack(1)

///
/// @brief      The Windows UNICODE_STRING structure used for 32-bit guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct _UNICODE_STRING32
{
    /// @brief      The length, in bytes, of the string in Buffer, not including the NULL terminator, if any
    UINT16 Length;
    /// @brief      The size, in bytes, allocated for Buffer
    UINT16 MaximumLength;
    /// @brief      The guest virtual address at which the wide-character string is located
    ///
    /// Note that the string may not be NULL-terminated inside the guest
    DWORD  Buffer;
} UNICODE_STRING32;

///
/// @brief      The Windows UNICODE_STRING structure used for 64-bit guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct _UNICODE_STRING64
{
    /// @brief      The length, in bytes, of the string in Buffer, not including the NULL terminator, if any
    WORD   Length;
    /// @brief      The size, in bytes, allocated for Buffer
    WORD   MaximumLength;
    DWORD  _Rserved1;   ///< Reserved
    /// @brief      The guest virtual address at which the wide-character string is located
    ///
    /// Note that the string may not be NULL-terminated inside the guest
    QWORD  Buffer;
} UNICODE_STRING64;

///
/// @brief      Models a LIST_ENTRY structure used by 32-bit Windows guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
typedef struct _LIST_ENTRY32
{
    DWORD Flink, Blink;
} LIST_ENTRY32, *PLIST_ENTRY32;

///
/// @brief      Models a LIST_ENTRY structure used by 64-bit Windows guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-list_entry
typedef struct _LIST_ENTRY64
{
    QWORD Flink, Blink;
} LIST_ENTRY64, *PLIST_ENTRY64;

#pragma pack(pop)

///
/// @brief      The _LDR_DATA_TABLE_ENTRY structure used by 32-bit guests
///
typedef struct _LDR_DATA_TABLE_ENTRY32
{
    LIST_ENTRY32            InLoadOrderLinks;
    LIST_ENTRY32            InMemoryOrderLinks;
    LIST_ENTRY32            InInitializationOrderLinks;
    DWORD                   DllBase;
    DWORD                   EntryPoint;
    DWORD                   SizeOfImage;
    UNICODE_STRING32        DriverPath;
    UNICODE_STRING32        DriverName;
    DWORD                   Flags;
    WORD                    LoadCount;
    WORD                    TlsIndex;
    LIST_ENTRY32            HashLinks;
    DWORD                   SectionPointer;
    DWORD                   CheckSum;
    DWORD                   TimeDateStamp;
    DWORD                   LoadedImports;
    DWORD                   EntryPointActivationContext;
    DWORD                   PatchInformation;

    //
    // Add other fields, if needed
    //
} LDR_DATA_TABLE_ENTRY32, *PLDR_DATA_TABLE_ENTRY32;

///
/// @brief      The _LDR_DATA_TABLE_ENTRY structure used by 64-bit guests
///
typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64            InLoadOrderLinks;
    LIST_ENTRY64            InMemoryOrderLinks;
    LIST_ENTRY64            InInitializationOrderLinks;
    QWORD                   DllBase;
    QWORD                   EntryPoint;
    QWORD                   SizeOfImage;
    UNICODE_STRING64        DriverPath;
    UNICODE_STRING64        DriverName;
    DWORD                   Flags;
    WORD                    LoadCount;
    WORD                    TlsIndex;
    LIST_ENTRY64            HashLinks;
    QWORD                   SectionPointer;
    DWORD                   CheckSum;
    DWORD                   TimeDateStamp;
    QWORD                   LoadedImports;
    QWORD                   EntryPointActivationContext;
    QWORD                   PatchInformation;

    //
    // Add other fields, if needed
    //
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

#pragma pack(push)
#pragma pack(1)

///
/// @brief      The _DRIVER_OBJECT structure used by 32-bit guests
///
typedef struct _DRIVER_OBJECT32
{
    WORD                    Type;
    WORD                    Size;
    DWORD                   DeviceObject;
    DWORD                   Flags;
    DWORD                   DriverStart;
    DWORD                   DriverSize;
    DWORD                   DriverSection;
    DWORD                   DriverExtension;
    UNICODE_STRING32        DriverName;
    DWORD                   HardwareDatabase;
    DWORD                   FastIoDispatch;
    DWORD                   DriverInit;
    DWORD                   DriverStartIo;
    DWORD                   DriverUnload;
    DWORD                   MajorFunctions[28];
} DRIVER_OBJECT32, *PDRIVER_OBJECT32;

///
/// @brief      The _DRIVER_OBJECT structure used by 64-bit guests
///
typedef struct _DRIVER_OBJECT64
{
    WORD                    Type;
    WORD                    Size;
    DWORD                   _Reserved1;
    QWORD                   DeviceObject;
    QWORD                   Flags;
    QWORD                   DriverStart;
    QWORD                   DriverSize;
    QWORD                   DriverSection;
    QWORD                   DriverExtension;
    UNICODE_STRING64        DriverName;
    QWORD                   HardwareDatabase;
    QWORD                   FastIoDispatch;
    QWORD                   DriverInit;
    QWORD                   DriverStartIo;
    QWORD                   DriverUnload;
    QWORD                   MajorFunctions[28];
} DRIVER_OBJECT64, *PDRIVER_OBJECT64;

#pragma pack(pop)

///
/// @brief      The _FAST_IO_DISPATCH structure used by 32-bit guests
///
typedef struct _FAST_IO_DISPATCH32
{
    DWORD                   SizeOfFastIoDispatch;
    DWORD                   FastIoCheckIfPossible;
    DWORD                   FastIoRead;
    DWORD                   FastIoWrite;
    DWORD                   FastIoQueryBasicInfo;
    DWORD                   FastIoQueryStandardInfo;
    DWORD                   FastIoLock;
    DWORD                   FastIoUnlockSingle;
    DWORD                   FastIoUnlockAll;
    DWORD                   FastIoUnlockAllByKey;
    DWORD                   FastIoDeviceControl;
    DWORD                   AcquireFileForNtCreateSection;
    DWORD                   ReleaseFileForNtCreateSection;
    DWORD                   FastIoDetachDevice;
    DWORD                   FastIoQueryNetworkOpenInfo;
    DWORD                   AcquireForModWrite;
    DWORD                   MdlRead;
    DWORD                   MdlReadComplete;
    DWORD                   PrepareMdlWrite;
    DWORD                   MdlWriteComplete;
    DWORD                   FastIoReadCompressed;
    DWORD                   FastIoWriteCompressed;
    DWORD                   MdlReadCompleteCompressed;
    DWORD                   MdlWriteCompleteCompressed;
    DWORD                   FastIoQueryOpen;
    DWORD                   ReleaseForModWrite;
    DWORD                   AcquireForCcFlush;
    DWORD                   ReleaseForCcFlush;
} FAST_IO_DISPATCH32, *PFAST_IO_DISPATCH32;

///
/// @brief      The _FAST_IO_DISPATCH structure used by 64-bit guests
///
typedef struct _FAST_IO_DISPATCH64
{
    QWORD                   SizeOfFastIoDispatch;
    QWORD                   FastIoCheckIfPossible;
    QWORD                   FastIoRead;
    QWORD                   FastIoWrite;
    QWORD                   FastIoQueryBasicInfo;
    QWORD                   FastIoQueryStandardInfo;
    QWORD                   FastIoLock;
    QWORD                   FastIoUnlockSingle;
    QWORD                   FastIoUnlockAll;
    QWORD                   FastIoUnlockAllByKey;
    QWORD                   FastIoDeviceControl;
    QWORD                   AcquireFileForNtCreateSection;
    QWORD                   ReleaseFileForNtCreateSection;
    QWORD                   FastIoDetachDevice;
    QWORD                   FastIoQueryNetworkOpenInfo;
    QWORD                   AcquireForModWrite;
    QWORD                   MdlRead;
    QWORD                   MdlReadComplete;
    QWORD                   PrepareMdlWrite;
    QWORD                   MdlWriteComplete;
    QWORD                   FastIoReadCompressed;
    QWORD                   FastIoWriteCompressed;
    QWORD                   MdlReadCompleteCompressed;
    QWORD                   MdlWriteCompleteCompressed;
    QWORD                   FastIoQueryOpen;
    QWORD                   ReleaseForModWrite;
    QWORD                   AcquireForCcFlush;
    QWORD                   ReleaseForCcFlush;
} FAST_IO_DISPATCH64, *PFAST_IO_DISPATCH64;

///
/// @brief      The _OBJECT_HEADER32 structure used by 32-bit guests
///
typedef struct _OBJECT_HEADER32
{
    DWORD           PointerCount;

    union
    {
        DWORD       HandleCount;
        DWORD       NextToFree;
    };

    DWORD           Lock;
    UCHAR           TypeIndex;
    UCHAR           TraceFlags;
    UCHAR           InfoMask;
    UCHAR           Flags;
    DWORD           ObjectCreateInfo;
    DWORD           SecurityDescriptor;
    QWORD           Body;
} OBJECT_HEADER32, *POBJECT_HEADER32;

///
/// @brief      The _OBJECT_HEADER32 structure used by 64-bit guests
///
typedef struct _OBJECT_HEADER64
{
    QWORD           PointerCount;

    union
    {
        QWORD       HandleCount;
        QWORD       NextToFree;
    };

    QWORD           Lock;
    UCHAR           TypeIndex;
    UCHAR           TraceFlags;
    UCHAR           InfoMask;
    UCHAR           Flags;
    DWORD           Spare;

    union
    {
        QWORD       ObjectCreateInfo;
        QWORD       QuotaBlockCharged;
    };

    QWORD           SecurityDescriptor;
    QWORD           Body;
} OBJECT_HEADER64, *POBJECT_HEADER64;

///
/// @brief      The _POOL_HEADER structure used by 32-bit guests
///
typedef struct _POOL_HEADER32
{
    union
    {
        struct
        {
            DWORD   PreviousSize : 9;
            DWORD   PoolIndex : 7;
            DWORD   BlockSize : 9;
            DWORD   PoolType : 7;
        };

        DWORD       Ulong1;
    };

    union
    {
        DWORD       PoolTag;
        struct
        {
            WORD    AllocatorBackTraceIndex;
            WORD    PoolTagHash;
        };
    };
} POOL_HEADER32;

///
/// @brief      The _POOL_HEADER structure used by 64-bit guests
///
typedef struct _POOL_HEADER64
{
    union
    {
        struct
        {
            DWORD   PreviousSize : 8;
            DWORD   PoolIndex : 8;
            DWORD   BlockSize : 8;
            DWORD   PoolType : 8;
        };

        DWORD       Ulong1;
    };

    DWORD           PoolTag;
    union
    {
        QWORD       ProcessBilled;

        struct
        {
            WORD    AllocatorBackTraceIndex;
            WORD    PoolTagHash;
        };
    };
} POOL_HEADER64;

typedef union _POOL_HEADER
{
    POOL_HEADER32   Header32;
    POOL_HEADER64   Header64;
} POOL_HEADER, *PPOOL_HEADER;

#define WIN_POOL_HEADER_SIZE32              0x8     ///< The size of a pool header on 32-bit Windows
#define WIN_POOL_HEADER_SIZE64              0x10    ///< The size of a pool header on 64-bit Windows

#define WIN_POOL_HEADER_SIZE                ((gGuest.Guest64) ? WIN_POOL_HEADER_SIZE64 : WIN_POOL_HEADER_SIZE32)

#define WIN_POOL_BLOCK_SIZE32               0x08    ///< The block size of a pool allocation on 32-bit Windows
#define WIN_POOL_BLOCK_SIZE64               0x10    ///< The block size of a pool allocation on 64-bit Windows

#define WIN_POOL_BLOCK_SIZE                 ((gGuest.Guest64) ? WIN_POOL_BLOCK_SIZE64 : WIN_POOL_BLOCK_SIZE32)


STATIC_ASSERT(sizeof(POOL_HEADER32) == WIN_POOL_HEADER_SIZE32, "Wrong size for POOL_HEADER32!");
STATIC_ASSERT(sizeof(POOL_HEADER64) == WIN_POOL_HEADER_SIZE64, "Wrong size for POOL_HEADER64!");

#if !defined(INT_COMPILER_CLANG)
STATIC_ASSERT(OFFSET_OF(POOL_HEADER32, PoolTag) == OFFSET_OF(POOL_HEADER64, PoolTag), "Wrong PoolTag offset!");
#endif

///
/// @brief      The type of a pool allocation
///
/// See either wdm.h or https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_pool_type
typedef enum _POOL_TYPE
{
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,

    //
    // Define base types for NonPaged (versus Paged) pool, for use in cracking
    // the underlying pool type.
    //

    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,

    //
    // Note these per session types are carefully chosen so that the appropriate
    // masking still applies as well as MaxPoolType above.
    //

    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,

    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

typedef struct _POOL_TRACKER_BIG_PAGES32
{
    DWORD Va;
    DWORD Key;
    DWORD Pattern : 8;
    DWORD PoolType : 12;
    DWORD SlushSize : 12;
    DWORD NumberOfBytes;
} POOL_TRACKER_BIG_PAGES32;

typedef struct _POOL_TRACKER_BIG_PAGES64
{
    QWORD Va;
    DWORD Key;
    DWORD Pattern : 8;
    DWORD PoolType : 12;
    DWORD SlushSize : 12;
    QWORD NumberOfBytes;
} POOL_TRACKER_BIG_PAGES64;

typedef union _POOL_TRACKER_BIG_PAGES
{
    POOL_TRACKER_BIG_PAGES32 Tracker32;
    POOL_TRACKER_BIG_PAGES64 Tracker64;
} POOL_TRACKER_BIG_PAGES, *PPOOL_TRACKER_BIG_PAGES;

#define WIN_POOL_TRACKER_SIZE               (DWORD)((gGuest.Guest64) ? sizeof(POOL_TRACKER_BIG_PAGES64) : \
                                                                       sizeof(POOL_TRACKER_BIG_PAGES32))

//
// SID Attribute flags
// See winnt.h or https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_groups_and_privileges
//
#define SE_GROUP_MANDATORY                 (0x00000001L)
#define SE_GROUP_ENABLED_BY_DEFAULT        (0x00000002L)
#define SE_GROUP_ENABLED                   (0x00000004L)
#define SE_GROUP_OWNER                     (0x00000008L)
#define SE_GROUP_USE_FOR_DENY_ONLY         (0x00000010L)
#define SE_GROUP_INTEGRITY                 (0x00000020L)
#define SE_GROUP_INTEGRITY_ENABLED         (0x00000040L)
#define SE_GROUP_LOGON_ID                  (0xC0000000L)
#define SE_GROUP_RESOURCE                  (0x20000000L)

#define SE_GROUP_VALID_ATTRIBUTES          (SE_GROUP_MANDATORY          | \
                                            SE_GROUP_ENABLED_BY_DEFAULT | \
                                            SE_GROUP_ENABLED            | \
                                            SE_GROUP_OWNER              | \
                                            SE_GROUP_USE_FOR_DENY_ONLY  | \
                                            SE_GROUP_LOGON_ID           | \
                                            SE_GROUP_RESOURCE           | \
                                            SE_GROUP_INTEGRITY          | \
                                            SE_GROUP_INTEGRITY_ENABLED)

typedef enum _SECURITY_IMPERSONATION_LEVEL
{
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
} SECURITY_IMPERSONATION_LEVEL, *PSECURITY_IMPERSONATION_LEVEL;

typedef struct _SID_AND_ATTRIBUTES64
{
    QWORD   Sid;        ///< Pointer to a _SID structure
    DWORD   Attributes; ///< A combination of SE_GROUP_* values
} SID_AND_ATTRIBUTES64, *PSID_AND_ATTRIBUTES64;

//
// dt nt!_SID_AND_ATTRIBUTES, 0x8 bytes
//
typedef struct _SID_AND_ATTRIBUTES32
{
    DWORD   Sid;        ///< Pointer to a _SID structure
    DWORD   Attributes; ///< A combination of SE_GROUP_* values
} SID_AND_ATTRIBUTES32, *PSID_AND_ATTRIBUTES32;

typedef WORD SECURITY_DESCRIPTOR_CONTROL;

typedef struct _SID_IDENTIFIER_AUTHORITY
{
    UCHAR Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID
{
    UCHAR                       Revision;
    UCHAR                       SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY    IdentifierAuthority;
    QWORD                       *SubAuthority;
} SID, *PSID;

#pragma pack(push)
#pragma pack(1)
typedef struct _SECURITY_DESCRIPTOR
{
    BYTE                        Revision;
    BYTE                        Sbz1;
    SECURITY_DESCRIPTOR_CONTROL Control;
    QWORD                       Owner;
    QWORD                       Group;
} SECURITY_DESCRIPTOR, *PSECURITY_DESCRIPTOR;
#pragma pack(pop)

///
/// @brief  An access control list.
///
/// See https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
///
typedef struct _ACL
{
    BYTE AclRevision;
    BYTE Sbz1;
    WORD AclSize;
    WORD AceCount;
    WORD Sbz2;
} ACL, *PACL;

///
/// @brief An access control entry header.
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header
/// 
typedef struct _ACE_HEADER
{
    BYTE AceType;
    BYTE AceFlags;
    WORD AceSize;
} ACE_HEADER;

///
/// @brief  Access Control Entry type - ntifs.h
///
typedef enum _ACE_TYPE
{
    ACCESS_ALLOWED_ACE_TYPE = 0,
    ACCESS_DENIED_ACE_TYPE,
    SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_ALARM_ACE_TYPE,
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_DENIED_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_ACE_TYPE,
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE,
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE,
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE,
    SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE,
    SYSTEM_ACCESS_FILTER_ACE_TYPE
} ACE_TYPE;

/// @brief  Printable version of #ACCESS_ALLOWED_ACE_TYPE.
#define ACCESS_ALLOWED_ACE_TYPE_STRING                     "ACCESS_ALLOWED_ACE_TYPE"
/// @brief  Printable version of #ACCESS_DENIED_ACE_TYPE.
#define ACCESS_DENIED_ACE_TYPE_STRING                      "ACCESS_DENIED_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_AUDIT_ACE_TYPE.
#define SYSTEM_AUDIT_ACE_TYPE_STRING                       "SYSTEM_AUDIT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_ALARM_ACE_TYPE.
#define SYSTEM_ALARM_ACE_TYPES_STRING                      "SYSTEM_ALARM_ACE_TYPE"
/// @brief  Printable version of #ACCESS_ALLOWED_COMPOUND_ACE_TYPE.
#define ACCESS_ALLOWED_COMPOUND_ACE_TYPE_STRING            "ACCESS_ALLOWED_COMPOUND_ACE_TYPE"
/// @brief  Printable version of #ACCESS_ALLOWED_OBJECT_ACE_TYPE.
#define ACCESS_ALLOWED_OBJECT_ACE_TYPE_STRING              "ACCESS_ALLOWED_OBJECT_ACE_TYPE"
/// @brief  Printable version of #ACCESS_DENIED_OBJECT_ACE_TYPE.
#define ACCESS_DENIED_OBJECT_ACE_TYPE_STRING               "ACCESS_DENIED_OBJECT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_AUDIT_OBJECT_ACE_TYPE.
#define SYSTEM_AUDIT_OBJECT_ACE_TYPE_STRING                "SYSTEM_AUDIT_OBJECT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_ALARM_OBJECT_ACE_TYPE.
#define SYSTEM_ALARM_OBJECT_ACE_TYPE_STRING                "SYSTEM_ALARM_OBJECT_ACE_TYPE"
/// @brief  Printable version of #ACCESS_ALLOWED_CALLBACK_ACE_TYPE.
#define ACCESS_ALLOWED_CALLBACK_ACE_TYPE_STRING            "ACCESS_ALLOWED_CALLBACK_ACE_TYPE"
/// @brief  Printable version of #ACCESS_DENIED_CALLBACK_ACE_TYPE.
#define ACCESS_DENIED_CALLBACK_ACE_TYPE_STRING             "ACCESS_DENIED_CALLBACK_ACE_TYPE"
/// @brief  Printable version of #ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE.
#define ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE_STRING     "ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE"
/// @brief  Printable version of #ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE.
#define ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE_STRING      "ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_AUDIT_CALLBACK_ACE_TYPE.
#define SYSTEM_AUDIT_CALLBACK_ACE_TYPE_STRING              "SYSTEM_AUDIT_CALLBACK_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_ALARM_CALLBACK_ACE_TYPE.
#define SYSTEM_ALARM_CALLBACK_ACE_TYPE_STRING              "SYSTEM_ALARM_CALLBACK_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE.
#define SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE_STRING       "SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE.
#define SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE_STRING       "SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_MANDATORY_LABEL_ACE_TYPE.
#define SYSTEM_MANDATORY_LABEL_ACE_TYPE_STRING             "SYSTEM_MANDATORY_LABEL_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE.
#define SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE_STRING          "SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_SCOPED_POLICY_ID_ACE_TYPE.
#define SYSTEM_SCOPED_POLICY_ID_ACE_TYPE_STRING            "SYSTEM_SCOPED_POLICY_ID_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE.
#define SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE_STRING         "SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE"
/// @brief  Printable version of #SYSTEM_ACCESS_FILTER_ACE_TYPE.
#define SYSTEM_ACCESS_FILTER_ACE_TYPE_STRING               "SYSTEM_ACCESS_FILTER_ACE_TYPE"


//
// ACL revision versions - wdm.h
//

// This is the *current* ACL revision
#define ACL_REVISION     (2)
#define ACL_REVISION_DS  (4)

// This is the history of ACL revisions.  Add a new one whenever
// ACL_REVISION is updated
#define ACL_REVISION1   (1)
#define MIN_ACL_REVISION ACL_REVISION2
#define ACL_REVISION2   (2)
#define ACL_REVISION3   (3)
#define ACL_REVISION4   (4)
#define MAX_ACL_REVISION ACL_REVISION4

///
/// @brief  This is the structure as documented in winternl.h
///
typedef struct _RTL_USER_PROCESS_PARAMETERS32
{
    BYTE                Reserved1[16];
    DWORD               Reserved2[10];
    UNICODE_STRING32    ImagePathName;
    UNICODE_STRING32    CommandLine;
} RTL_USER_PROCESS_PARAMETERS32, *PRTL_USER_PROCESS_PARAMETERS32;

///
/// @brief  This is the structure as documented in winternl.h
///
typedef struct _RTL_USER_PROCESS_PARAMETERS64
{
    BYTE                Reserved1[16];
    QWORD               Reserved2[10];
    UNICODE_STRING64    ImagePathName;
    UNICODE_STRING64    CommandLine;
} RTL_USER_PROCESS_PARAMETERS64, *PRTL_USER_PROCESS_PARAMETERS64;

///
/// @brief  This is the structure as documented in ntddk.h
///
typedef struct _RTL_DYNAMIC_HASH_TABLE32
{

    // Entries initialized at creation
    DWORD Flags;
    DWORD Shift;

    // Entries used in bucket computation.
    DWORD TableSize;
    DWORD Pivot;
    DWORD DivisorMask;

    // Counters
    DWORD NumEntries;
    DWORD NonEmptyBuckets;
    DWORD NumEnumerators;

    // The directory. This field is for internal use only.
    DWORD Directory;

} RTL_DYNAMIC_HASH_TABLE32, *PRTL_DYNAMIC_HASH_TABLE32;

///
/// @brief  This is the structure as documented in ntddk.h
///
typedef struct _RTL_DYNAMIC_HASH_TABLE64
{

    // Entries initialized at creation
    DWORD Flags;
    DWORD Shift;

    // Entries used in bucket computation.
    DWORD TableSize;
    DWORD Pivot;
    DWORD DivisorMask;

    // Counters
    DWORD NumEntries;
    DWORD NonEmptyBuckets;
    DWORD NumEnumerators;

    // The directory. This field is for internal use only.
    QWORD Directory;

} RTL_DYNAMIC_HASH_TABLE64, *PRTL_DYNAMIC_HASH_TABLE64;

///
/// @brief  This is the structure as documented in winternl.h
///
typedef struct _PEB32
{
    BYTE        Reserved1[2];
    BYTE        BeingDebugged;
    BYTE        Reserved2[1];
    DWORD       Reserved3[2];
    DWORD       Ldr;                    ///< 32-bit pointer to a _PEB_LDR_DATA structure
    DWORD       ProcessParameters;      ///< 32-bit pointer to a _RTL_USER_PROCESS_PARAMETERS structure
    DWORD       Reserved4[3];
    DWORD       AtlThunkSListPtr;
    DWORD       Reserved5;
    DWORD       Reserved6;
    DWORD       Reserved7;
    DWORD       Reserved8;
    DWORD       AtlThunkSListPtr32;
    DWORD       Reserved9[45];
    BYTE        Reserved10[96];
    DWORD       PostProcessInitRoutine; ///< 32-bit pointer to a PS_POST_PROCESS_INIT_ROUTINE
    BYTE        Reserved11[128];
    DWORD       Reserved12[1];
    DWORD       SessionId;
} PEB32, *PPEB32;

///
/// @brief  This is the structure as documented in winternl.h
///
typedef struct _PEB64
{
    BYTE        Reserved1[2];
    BYTE        BeingDebugged;
    BYTE        Reserved2[1];
    QWORD       Reserved3[2];
    QWORD       Ldr;                    ///< 64-bit pointer to a _PEB_LDR_DATA structure
    QWORD       ProcessParameters;      ///< 64-bit pointer to a _RTL_USER_PROCESS_PARAMETERS structure
    QWORD       Reserved4[3];
    QWORD       AtlThunkSListPtr;
    QWORD       Reserved5;
    DWORD       Reserved6;
    QWORD       Reserved7;
    DWORD       Reserved8;
    DWORD       AtlThunkSListPtr32;
    QWORD       Reserved9[45];
    BYTE        Reserved10[96];
    QWORD       PostProcessInitRoutine; ///< 32-bit pointer to a PS_POST_PROCESS_INIT_ROUTINE
    BYTE        Reserved11[128];
    QWORD       Reserved12[1];
    DWORD       SessionId;
} PEB64, *PPEB64;

// from wdm.h
//
// Define 128-bit 16-byte aligned xmm register type.
//

typedef struct _M128A
{
    UINT64      Low;
    INT64       High;
} M128A, *PM128A;

// Windows 10 RS2 x86 - structure taken from WINDBG
typedef struct _KI_IO_ACCESS_MAP
{
    BYTE DirectionMap[32];
    BYTE IoMap[8196];
} KI_IO_ACCESS_MAP, *PKI_IO_ACCESS_MAP;

#pragma pack(push)
#pragma pack(1)
// Windows 10 RS2 x86 - structure taken from WINDBG
typedef struct _KTSS
{
    WORD            Backlink;
    WORD            Reserved0;
    DWORD           Esp0;
    WORD            Ss0;
    WORD            Reserved1;
    DWORD           NotUsed1[4];
    DWORD           CR3;
    DWORD           Eip;
    DWORD           EFlags;
    DWORD           Eax;
    DWORD           Ecx;
    DWORD           Edx;
    DWORD           Ebx;
    DWORD           Esp;
    DWORD           Ebp;
    DWORD           Esi;
    DWORD           Edi;
    WORD            Es;
    WORD            Reserved2;
    WORD            Cs;
    WORD            Reserved3;
    WORD            Ss;
    WORD            Reserved4;
    WORD            Ds;
    WORD            Reserved5;
    WORD            Fs;
    WORD            Reserved6;
    WORD            Gs;
    WORD            Reserved7;
    WORD            LDT;
    WORD            Reserved8;
    WORD            Flags;
    WORD            IoMapBase;

    //
    // Snippet of the structure
    //

    //KI_IO_ACCESS_MAP   IoMap;
    //BYTE            IntDirectionMap[32];
} KTSS, *PKTSS;
#pragma pack(pop)

// Windows 10 RS2 x86 - structure taken from WINDBG
typedef struct _KTRAP_FRAME32
{
    DWORD   DbgEbp;
    DWORD   DbgEip;
    DWORD   DbgArgMark;
    WORD    TempSegCs;
    BYTE    Logging;
    BYTE    FrameType;
    DWORD   TempEsp;

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    DWORD   SegGs;
    DWORD   SegEs;
    DWORD   SegDs;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;
    BYTE    PreviousPreviousMode;
    BYTE    EntropyQueueDpc;
    BYTE    Reserved[2];
    DWORD   MxCsr;
    DWORD   ExceptionList;  //PEXCEPTION_REGISTRATION_RECORD32
    DWORD   SegFs;

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Ebp;

    DWORD   ErrCode;
    DWORD   Eip;
    DWORD   SegCs;
    DWORD   EFlags;
    DWORD   HardwareEsp;
    DWORD   HardwareSegSs;

    DWORD   V86Es;
    DWORD   V86Ds;
    DWORD   V86Fs;
    DWORD   V86Gs;
} KTRAP_FRAME32, *PKTRAP_FRAME32;


typedef struct _KTRAP_FRAME64
{

    //
    // Home address for the parameter registers.
    //

    QWORD       P1Home;
    QWORD       P2Home;
    QWORD       P3Home;
    QWORD       P4Home;
    QWORD       P5;

    //
    // Previous processor mode (system services only) and previous IRQL
    // (interrupts only).
    //

    BYTE        PreviousMode;
    BYTE        PreviousIrql;

    //
    // Page fault load/store indicator.
    //

    UCHAR       FaultIndicator;

    //
    // Exception active indicator.
    //
    //    0 - interrupt frame.
    //    1 - exception frame.
    //    2 - service frame.
    //

    UCHAR       ExceptionActive;

    //
    // Floating point state.
    //

    DWORD       MxCsr;

    //
    //  Volatile registers.
    //
    // N.B. These registers are only saved on exceptions and interrupts. They
    //      are not saved for system calls.
    //

    QWORD       Rax;
    QWORD       Rcx;
    QWORD       Rdx;
    QWORD       R8;
    QWORD       R9;
    QWORD       R10;
    QWORD       R11;

    //
    // Gsbase is only used if the previous mode was kernel.
    //
    // GsSwap is only used if the previous mode was user.
    //

    union
    {
        QWORD   GsBase;
        QWORD   GsSwap;
    };

    //
    // Volatile floating registers.
    //
    // N.B. These registers are only saved on exceptions and interrupts. They
    //      are not saved for system calls.
    //

    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;

    //
    // First parameter, page fault address, context record address if user APC
    // bypass, or time stamp value.
    //

    union
    {
        QWORD   FaultAddress;
        QWORD   ContextRecord;
        QWORD   TimeStampCKCL;
    };

    //
    //  Debug registers.
    //

    QWORD       Dr0;
    QWORD       Dr1;
    QWORD       Dr2;
    QWORD       Dr3;
    QWORD       Dr6;
    QWORD       Dr7;

    //
    // Special debug registers.
    //

    struct
    {
        QWORD   DebugControl;
        QWORD   LastBranchToRip;
        QWORD   LastBranchFromRip;
        QWORD   LastExceptionToRip;
        QWORD   LastExceptionFromRip;
    };

    //
    //  Segment registers
    //

    UINT16 SegDs;
    UINT16 SegEs;
    UINT16 SegFs;
    UINT16 SegGs;

    //
    // Previous trap frame address.
    //

    QWORD       TrapFrame;

    //
    // Saved nonvolatile registers RBX, RDI and RSI. These registers are only
    // saved in system service trap frames.
    //

    QWORD       Rbx;
    QWORD       Rdi;
    QWORD       Rsi;

    //
    // Saved nonvolatile register RBP. This register is used as a frame
    // pointer during trap processing and is saved in all trap frames.
    //

    QWORD       Rbp;

    //
    // Information pushed by hardware.
    //
    // N.B. The error code is not always pushed by hardware. For those cases
    //      where it is not pushed by hardware a dummy error code is allocated
    //      on the stack.
    //

    union
    {
        QWORD   ErrorCode;
        QWORD   ExceptionFrame;
        QWORD   TimeStampKlog;
    };

    QWORD       Rip;
    UINT16      SegCs;
    UCHAR       Fill0;
    UCHAR       Logging;
    UINT16      Fill1[2];
    DWORD       EFlags;
    DWORD       Fill2;
    QWORD       Rsp;
    UINT16      SegSs;
    UINT16      Fill3;
    DWORD       Fill4;
} KTRAP_FRAME64, *PKTRAP_FRAME64;

// Note that certain fields may be renamed/aliased, depending on the OS version/installed patches, but the size and
// field offsets defined above should always be the same (at least they are for everything from Windows 7 to 10 RS5)
// These static asserts should help in keeping the structure in a good state
STATIC_ASSERT(sizeof(KTRAP_FRAME64) == 0x190, "Wrong size for KTRAP_FRAME64!");
STATIC_ASSERT(OFFSET_OF(KTRAP_FRAME64, Rax) == 0x30, "Wrong offset for Rax in KTRAP_FRAME64!");
STATIC_ASSERT(OFFSET_OF(KTRAP_FRAME64, Rbx) == 0x140, "Wrong offset for Rbx in KTRAP_FRAME64!");
STATIC_ASSERT(OFFSET_OF(KTRAP_FRAME64, Rip) == 0x168, "Wrong offset for Rip in KTRAP_FRAME64!");
STATIC_ASSERT(OFFSET_OF(KTRAP_FRAME64, Rsp) == 0x180, "Wrong offset for Rsp in KTRAP_FRAME64!");


#ifndef EXCEPTION_MAXIMUM_PARAMETERS
#define EXCEPTION_MAXIMUM_PARAMETERS        15ul
#endif // !EXCEPTION_MAXIMUM_PARAMETERS

///
/// @brief      An _EXCEPTION_RECORD structure used by 64-bit guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
///
typedef struct _EXCEPTION_RECORD64
{
    /// @brief  The code generated by hardware, or the one used with RaiseException(), or DBG_CONTROL_C
    DWORD       ExceptionCode;
    DWORD       ExceptionFlags;
    /// @brief  For nested exceptions, will point to the next exception record
    QWORD       ExceptionRecord;
    QWORD       ExceptionAddress;   ///< The address at which the exception was generated
    DWORD       NumberParameters;   ///< The number of valid entries inside the ExceptionInformation array
    DWORD       __unusedAlignment;
    /// @brief  Exception-dependent parameters
    QWORD       ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;

///
/// @brief      An _EXCEPTION_RECORD structure used by 64-bit guests
///
/// See https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record
/// The fields have the same meaning as for #EXCEPTION_RECORD64
///
typedef struct _EXCEPTION_RECORD32
{
    DWORD       ExceptionCode;
    DWORD       ExceptionFlags;
    DWORD       ExceptionRecord;
    DWORD       ExceptionAddress;
    DWORD       NumberParameters;
    DWORD       ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;

///
/// @brief      An _KEXCEPTION_FRAME structure used by 64-bit guests
///
/// This is established when the exception is handled. It will contain the values of all the nonvolatile registers.
///
typedef struct _KEXCEPTION_FRAME64
{

    //
    // Home address for the parameter registers.
    //

    QWORD       P1Home;
    QWORD       P2Home;
    QWORD       P3Home;
    QWORD       P4Home;
    QWORD       P5;
    QWORD       Spare1;

    //
    // Saved nonvolatile floating registers.
    //

    M128A       Xmm6;
    M128A       Xmm7;
    M128A       Xmm8;
    M128A       Xmm9;
    M128A       Xmm10;
    M128A       Xmm11;
    M128A       Xmm12;
    M128A       Xmm13;
    M128A       Xmm14;
    M128A       Xmm15;

    //
    // Kernel callout frame variables.
    //

    QWORD       TrapFrame;
    QWORD       OutputBuffer;
    QWORD       OutputLength;
    QWORD       Spare2;

    //
    // Saved MXCSR when a thread is interrupted in kernel mode via a dispatch
    // interrupt.
    //

    QWORD       MxCsr;

    //
    // Saved nonvolatile register - not always saved.
    //

    QWORD       Rbp;

    //
    // Saved nonvolatile registers.
    //

    QWORD       Rbx;
    QWORD       Rdi;
    QWORD       Rsi;
    QWORD       R12;
    QWORD       R13;
    QWORD       R14;
    QWORD       R15;

    //
    // EFLAGS and return address.
    //

    QWORD       Return;
} KEXCEPTION_FRAME64, *PKEXCEPTION_FRAME64;

// Note that certain fields may be renamed/aliased, depending on the OS version/installed patches, but the size and
// field offsets defined above should always be the same (at least they are for everything from Windows 7 to 10 RS5)
// These static asserts should help in keeping the structure in a good state
STATIC_ASSERT(sizeof(KEXCEPTION_FRAME64) == 0x140, "Wrong size for KEXCEPTION_FRAME64!");
STATIC_ASSERT(OFFSET_OF(KEXCEPTION_FRAME64, Rbp) == 0xF8, "Wrong offset for Rbp in KEXCEPTION_FRAME64!");

//
// PTE specific definitions of Windows
//
#define WIN_PTE_READWRITE           0x080
#define WIN_PTE_TRANSITION          0x800
#define WIN_PTE_PROTOTYPE           0x400
#define WIN_PTE_GUARD               0x200

/// @brief  The number of entries inside the hal dispatch table
///
/// See the HAL_DISPATCH definition in ntddk.h
#define HAL_DISPATCH_TABLE_PTR_COUNT    23

/// @brief      Gets the pointer to the parent of a _RTL_BALANCED_NODE
///
/// @param[in]  Parent  The value of the Parent field as taken from the guest
///
/// @returns    The pointer to the parent node
#define RTL_BALANCED_NODE_PARENT_TO_PTR(Parent)     ((Parent) & ~3)

///
/// @brief      The types of a _MMVAD structure
///
/// This is the value of the VadType part of the VadFlags field of a Windows kernel _MMVAD structure
typedef enum _VAD_TYPE
{
    VadNone,                    ///< None. Normal allocations have this type
    VadDevicePhysicalMemory,    ///< Ignored by introcore
    VadImageMap,                ///< The type used for mapped image files (including executable files)
    /// @brief  The type of an allocation used by Address Windowing Extension. Ignored by introcore
    ///
    /// See https://docs.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions
    VadAwe,
    /// @brief  The type of an allocation that specified the MEM_WRITE_WATCH VirtualAlloc flag
    ///
    /// See https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
    VadWriteWatch,
    /// @brief  The type of an allocation that uses large pages
    ///
    /// See https://docs.microsoft.com/en-us/windows/win32/memory/large-page-support
    VadLargePages,
    /// @brief  Memory used by video drivers to transfer data between the GPU and a process
    VadRotatePhysical,
    VadLargePageSection
} VAD_TYPE;


//
// Virtual Page protection constants (see winnt.h, PAGE_*)
//
#define WIN_MM_PAGE_NOACCESS          0x001 ///< Defined by Windows as PAGE_NOACCESS in winnt.h
#define WIN_MM_PAGE_READONLY          0x002 ///< Defined by Windows as PAGE_READONLY in winnt.h
#define WIN_MM_PAGE_READWRITE         0x004 ///< Defined by Windows as PAGE_READWRITE in winnt.h
#define WIN_MM_PAGE_WRITECOPY         0x008 ///< Defined by Windows as PAGE_WRITECOPY in winnt.h
#define WIN_MM_PAGE_EXECUTE           0x010 ///< Defined by Windows as PAGE_EXECUTE  in winnt.h
#define WIN_MM_PAGE_EXECUTE_READ      0x020 ///< Defined by Windows as PAGE_EXECUTE_READ in winnt.h
#define WIN_MM_PAGE_EXECUTE_READWRITE 0x040 ///< Defined by Windows as PAGE_EXECUTE_READWRITE in winnt.h
#define WIN_MM_PAGE_EXECUTE_WRITECOPY 0x080 ///< Defined by Windows as PAGE_EXECUTE_WRITECOPY in winnt.h
#define WIN_MM_PAGE_GUARD             0x100 ///< Defined by Windows as PAGE_GUARD in winnt.h
#define WIN_MM_PAGE_NOCACHE           0x200 ///< Defined by Windows as PAGE_NOCACHE in winnt.h
#define WIN_MM_PAGE_WRITECOMBINE      0x400 ///< Defined by Windows as PAGE_WRITECOMBINE in winnt.h


///
/// @brief  The waiting status of the threads
///
typedef enum _KWAIT_REASON
{
    Executive = 0,
    FreePage,
    PageIn,
    PoolAllocation,
    DelayExecution,
    Suspended,
    UserRequest,
    WrExecutive,
    WrFreePage,
    WrPageIn,
    WrPoolAllocation,
    WrDelayExecution,
    WrSuspended,
    WrUserRequest,
    WrSpare0,
    WrQueue,
    WrLpcReceive,
    WrLpcReply,
    WrVirtualMemory,
    WrPageOut,
    WrRendezvous,
    WrKeyedEvent,
    WrTerminated,
    WrProcessInSwap,
    WrCpuRateControl,
    WrCalloutStack,
    WrKernel,
    WrResource,
    WrPushLock,
    WrMutex,
    WrQuantumEnd,
    WrDispatchInt,
    WrPreempted,
    WrYieldExecution,
    WrFastMutex,
    WrGuardedMutex,
    WrRundown,
    WrAlertByThreadId,
    WrDeferredPreempt,
    WrPhysicalFault,
    MaximumWaitReason
} KWAIT_REASON;


///
/// @brief  Thread scheduling states.
///
typedef enum _KTHREAD_STATE
{
    Initialized = 0,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWait,                       // GateWaitObsolete in Windows 10
    WaitingForProcessInSwap,
} KTHREAD_STATE;

/// @brief  Disables execution rights for memory that contains data. Enables DEP
///
/// This is the _KEXECUTE_OPTIONS.ExecuteDisable Windows flag found in the _EPROCESS.Flags field
#define KEXEC_OPT_EXEC_DISABLE      1
/// @brief  Enables execution rights for memory that contains data. Disables DEP
///
/// This is the _KEXECUTE_OPTIONS.ExecuteEnable Windows flag found in the _EPROCESS.Flags field
#define KEXEC_OPT_EXEC_ENABLE       2
/// @brief  Freezes the DEP settings for a process
///
/// This is the _KEXECUTE_OPTIONS.Permanent Windows flag found in the _EPROCESS.Flags field
/// If it is set, the user mode SetProcessDEPPolicy() API will not be able to disable DEP for a process.
/// See https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy
#define KEXEC_OPT_PERMANENT         8

///
/// @brief      An _OBJECT_TYPE structure used by 64-bit guests
///
typedef struct _OBJECT_TYPE64
{
    LIST_ENTRY64        TypeList;
    UNICODE_STRING64    Name;
    QWORD               DefaultObject;
    BYTE                Index;
    DWORD               TotalNumberOfObjects;
    DWORD               TotalNumberOfHandles;
    DWORD               HighWaterNumberOfObjects;
    DWORD               HighWaterNumberOfHandles;

    //
    // The following fields were changed from Windows 7 to Windows 8; we don't really need them at the moment
    // Add them if needed
    //

} OBJECT_TYPE64, *POBJECT_TYPE64;

STATIC_ASSERT(sizeof(OBJECT_TYPE64) == 0x40, "Invalid OBJECT_TYPE64 size!");

///
/// @brief      An _OBJECT_TYPE structure used by 32-bit guests
///
typedef struct _OBJECT_TYPE32
{
    LIST_ENTRY32        TypeList;
    UNICODE_STRING32    Name;
    DWORD               DefaultObject;
    BYTE                Index;
    DWORD               TotalNumberOfObjects;
    DWORD               TotalNumberOfHandles;
    DWORD               HighWaterNumberOfObjects;
    DWORD               HighWaterNumberOfHandles;

    //
    // The following fields were changed from Windows 7 to Windows 8; we don't really need them at the moment
    // Add them if needed
    //

} OBJECT_TYPE32, *POBJECT_TYPE32;

STATIC_ASSERT(sizeof(OBJECT_TYPE32) == 0x28, "Invalid OBJECT_TYPE32 size!");

///
/// @brief      An OBJECT_DIRECTORY_ENTRY64 structure used by 64-bit guests
///
typedef struct _OBJECT_DIRECTORY_ENTRY64
{
    QWORD Chain;  ///< Gva to the next _OBJECT_DIRECTORY_ENTRY, may be NULL
    QWORD Object; ///< Pointer to the object, may be NULL

    //
    // Other fields may follow, but we don't use them
    //
} OBJECT_DIRECTORY_ENTRY64, *POBJECT_DIRECTORY_ENTRY64;

///
/// @brief      An OBJECT_DIRECTORY_ENTRY64 structure used by 32-bit guests
///
typedef struct _OBJECT_DIRECTORY_ENTRY32
{
    DWORD Chain;  ///< Gva to the next _OBJECT_DIRECTORY_ENTRY, may be NULL
    DWORD Object; ///< Pointer to the object, may be NULL

    //
    // Other fields may follow, but we don't use them
    //
} OBJECT_DIRECTORY_ENTRY32, *POBJECT_DIRECTORY_ENTRY32;

///
/// @brief      An _OBJECT_HEADER_NAME_INFO structure used by 64-bit guests
///
typedef struct _OBJECT_NAME64
{
    QWORD               Directory;      ///< Pointer to the _OBJECT_DIRECTORY that owns this
    UNICODE_STRING64    Name;           ///< The object name
    DWORD               ReferenceCount; ///< Reference count
} OBJECT_NAME64, *POBJECT_NAME64;

///
/// @brief      An _OBJECT_HEADER_NAME_INFO structure used by 32-bit guests
///
typedef struct _OBJECT_NAME32
{
    DWORD               Directory;      ///< Pointer to the _OBJECT_DIRECTORY that owns this
    UNICODE_STRING32    Name;           ///< The object name
    DWORD               ReferenceCount; ///< Reference count
} OBJECT_NAME32, *POBJECT_NAME32;

//
//  Define the size of the 80387 save area, which is in the context frame.
//

#define SIZE_OF_80387_REGISTERS         80
#define MAXIMUM_SUPPORTED_EXTENSION     512

///
/// @brief  Format of data for (F)XSAVE/(F)XRSTOR instruction for 32-bit guests
///
typedef struct _XSAVE_FORMAT
{
    WORD   ControlWord;
    WORD   StatusWord;
    BYTE  TagWord;
    BYTE  Reserved1;
    WORD   ErrorOpcode;
    DWORD ErrorOffset;
    WORD   ErrorSelector;
    WORD   Reserved2;
    DWORD DataOffset;
    WORD   DataSelector;
    WORD   Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];

    M128A XmmRegisters[16];
    BYTE  Reserved4[96];


} XSAVE_FORMAT, *PXSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

///
/// @brief  Format of data for (F)XSAVE/(F)XRSTOR instruction
///
typedef struct _FLOATING_SAVE_AREA
{
    DWORD   ControlWord;
    DWORD   StatusWord;
    DWORD   TagWord;
    DWORD   ErrorOffset;
    DWORD   ErrorSelector;
    DWORD   DataOffset;
    DWORD   DataSelector;
    BYTE    RegisterArea[SIZE_OF_80387_REGISTERS];
    DWORD   Spare0;
} FLOATING_SAVE_AREA;
typedef FLOATING_SAVE_AREA *PFLOATING_SAVE_AREA;

///
/// @brief  Context Frame for 64-bit guests
///
typedef struct _CONTEXT64
{
    QWORD P1Home;
    QWORD P2Home;
    QWORD P3Home;
    QWORD P4Home;
    QWORD P5Home;
    QWORD P6Home;

    DWORD ContextFlags;
    DWORD MxCsr;

    WORD   SegCs;
    WORD   SegDs;
    WORD   SegEs;
    WORD   SegFs;
    WORD   SegGs;
    WORD   SegSs;
    DWORD EFlags;

    QWORD Dr0;
    QWORD Dr1;
    QWORD Dr2;
    QWORD Dr3;
    QWORD Dr6;
    QWORD Dr7;

    QWORD Rax;
    QWORD Rcx;
    QWORD Rdx;
    QWORD Rbx;
    QWORD Rsp;
    QWORD Rbp;
    QWORD Rsi;
    QWORD Rdi;
    QWORD R8;
    QWORD R9;
    QWORD R10;
    QWORD R11;
    QWORD R12;
    QWORD R13;
    QWORD R14;
    QWORD R15;

    QWORD Rip;

    union
    {
        XMM_SAVE_AREA32 FltSave;
        struct
        {
            M128A Header[2];
            M128A Legacy[8];
            M128A Xmm0;
            M128A Xmm1;
            M128A Xmm2;
            M128A Xmm3;
            M128A Xmm4;
            M128A Xmm5;
            M128A Xmm6;
            M128A Xmm7;
            M128A Xmm8;
            M128A Xmm9;
            M128A Xmm10;
            M128A Xmm11;
            M128A Xmm12;
            M128A Xmm13;
            M128A Xmm14;
            M128A Xmm15;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

    M128A VectorRegister[26];
    QWORD VectorControl;

    QWORD DebugControl;
    QWORD LastBranchToRip;
    QWORD LastBranchFromRip;
    QWORD LastExceptionToRip;
    QWORD LastExceptionFromRip;
} CONTEXT64, *PCONTEXT64;

///
/// @brief  Context Frame for 32-bit guests
///
typedef struct _CONTEXT32
{
    DWORD ContextFlags;

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    FLOATING_SAVE_AREA FloatSave;

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;
    DWORD   EFlags;
    DWORD   Esp;
    DWORD   SegSs;

    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT32, *PCONTEXT32;

///
/// @brief  Mitigation flags
///
/// Available on Windows >= RS3 (16299). These are the possible values for the MitigationFlagsValues field from
/// _EPROCESS
typedef union _WIN_MITIGATION_FLAGS
{
    struct
    {
        DWORD   ControlFlowGuardEnabled : 1;
        DWORD   ControlFlowGuardExportSuppressionEnabled : 1;
        DWORD   ControlFlowGuardStrict : 1;
        DWORD   DisallowStrippedImages : 1;
        DWORD   ForceRelocateImages : 1;
        DWORD   HighEntropyASLREnabled : 1;
        DWORD   StackRandomizationDisabled : 1;
        DWORD   ExtensionPointDisable : 1;
        DWORD   DisableDynamicCode : 1;
        DWORD   DisableDynamicCodeAllowOptOut : 1;
        DWORD   DisableDynamicCodeAllowRemoteDowngrade : 1;
        DWORD   AuditDisableDynamicCode : 1;
        DWORD   DisallowWin32kSystemCalls : 1;
        DWORD   AuditDisallowWin32kSystemCalls : 1;
        DWORD   EnableFilteredWin32kAPIs : 1;
        DWORD   AuditFilteredWin32kAPIs : 1;
        DWORD   DisableNonSystemFonts : 1;
        DWORD   AuditNonSystemFontLoading : 1;
        DWORD   PreferSystem32Images : 1;
        DWORD   ProhibitRemoteImageMap : 1;
        DWORD   AuditProhibitRemoteImageMap : 1;
        DWORD   ProhibitLowILImageMap : 1;
        DWORD   AuditProhibitLowILImageMap : 1;
        DWORD   SignatureMitigationOptIn : 1;
        DWORD   AuditBlockNonMicrosoftBinaries : 1;
        DWORD   AuditBlockNonMicrosoftBinariesAllowStore : 1;
        DWORD   LoaderIntegrityContinuityEnabled : 1;
        DWORD   AuditLoaderIntegrityContinuity : 1;
        DWORD   EnableModuleTamperingProtection : 1;
        DWORD   EnableModuleTamperingProtectionNoInherit : 1;
    } Values;

    DWORD       Flags;
} WIN_MITIGATION_FLAGS, *PWIN_MITIGATION_FLAGS;

///
/// @brief  Mitigation flags
///
/// Available on Windows >= RS3 (16299). These are the possible values for the MitigationFlags2Values field from
/// _EPROCESS
typedef union _WIN_MITIGATION_FLAGS2
{
    struct
    {
        DWORD   EnableExportAddressFilter : 1;
        DWORD   AuditExportAddressFilter : 1;
        DWORD   EnableExportAddressFilterPlus : 1;
        DWORD   AuditExportAddressFilterPlus : 1;
        DWORD   EnableRopStackPivot : 1;
        DWORD   AuditRopStackPivot : 1;
        DWORD   EnableRopCallerCheck : 1;
        DWORD   AuditRopCallerCheck : 1;
        DWORD   EnableRopSimExec : 1;
        DWORD   AuditRopSimExec : 1;
        DWORD   EnableImportAddressFilter : 1;
        DWORD   AuditImportAddressFilter : 1;
    } Values;

    DWORD       Flags;
} WIN_MITIGATION_FLAGS2, *PWIN_MITIGATION_FLAGS2;

///
/// @brief  The _SYSTEM_POWER_STATE enum values used by the Windows kernel
///
/// These are used by the #IntWinPowHandlePowerStateChange detour handler.
///
typedef enum
{
    PowerSystemUnspecified = 0,
    PowerSystemWorking,
    PowerSystemSleeping1,
    PowerSystemSleeping2,
    PowerSystemSleeping3,
    PowerSystemHibernate,
    PowerSystemShutdown,
    PowerSystemMaximum
} SYSTEM_POWER_STATE;

///
/// @brief  The _POWER_ACTION enum values used by the Windows kernel
///
/// These are used by the #IntWinPowHandlePowerStateChange detour handler.
///
typedef enum
{
    PowerActionNone = 0,
    PowerActionReserved,
    PowerActionSleep,
    PowerActionHibernate,
    PowerActionShutdown,
    PowerActionShutdownReset,
    PowerActionShutdownOff,
    PowerActionWarmEject
} POWER_ACTION;

#define POOL_TAG_INCO   'oCnI'  ///< Inet Compartment
#define POOL_TAG_INPA   'APnI'  ///< Inet Port Array
#define POOL_TAG_INCS   'SCnI'  ///< Inet Compartment Set
#define POOL_TAG_INNL   'lNnI'  ///< Used to search for address family

#define POOL_TAG_TCCO   'oCcT'  ///< Tcp Compartment
#define POOL_TAG_TCHT   'THcT'  ///< Tcp Hash Table
#define POOL_TAG_TCPT   'tPcT'  ///< Tcp Partition

#define POOL_TAG_TCPE   'EpcT'  ///< Tcp Endpoint
#define POOL_TAG_TCPL   'LpcT'  ///< Tcp Listener
#define POOL_TAG_TCTW   'WTcT'  ///< Tcp Time Wait Endpoint

/// @brief  Verifier provider initialization structures for 32-bit processes
///
/// See Alex Ionescu's presentation "Esoteric Hooks" http://www.alex-ionescu.com/Estoteric%20Hooks.pdf
typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR_32
{
    DWORD   pwszDllName;
    DWORD   dwDllFlags;
    DWORD   pvDllAddress;
    DWORD   pvDllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR_32, *PRTL_VERIFIER_DLL_DESCRIPTOR_32;

/// @brief  Verifier provider initialization structures for 64-bit processes
///
/// See Alex Ionescu's presentation "Esoteric Hooks" http://www.alex-ionescu.com/Estoteric%20Hooks.pdf
typedef struct _RTL_VERIFIER_DLL_DESCRIPTOR_64
{
    QWORD   pwszDllName;
    DWORD   dwDllFlags;
    QWORD   pvDllAddress;
    QWORD   pvDllThunks;
} RTL_VERIFIER_DLL_DESCRIPTOR_64, *PRTL_VERIFIER_DLL_DESCRIPTOR_64;

/// @brief  Verifier provider initialization structures for 32-bit processes
///
/// See Alex Ionescu's presentation "Esoteric Hooks" http://www.alex-ionescu.com/Estoteric%20Hooks.pdf
typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR_32
{
    DWORD   dwLength;
    DWORD   pvProviderDlls;
    DWORD   pvProviderDllLoadCallback;
    DWORD   pvProviderDllUnloadCallback;
    DWORD   pwszVerifierImage;
    DWORD   dwVerifierFlags;
    DWORD   dwVerifierDebug;
    DWORD   pvRtlpGetStackTraceAddress;
    DWORD   pvRtlpDebugPageHeapCreate;
    DWORD   pvRtlpDebugPageHeapDestroy;
    DWORD   pvProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR_32, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR_32;

/// @brief  Verifier provider initialization structures for 64-bit processes
///
/// See Alex Ionescu's presentation "Esoteric Hooks" http://www.alex-ionescu.com/Estoteric%20Hooks.pdf
typedef struct _RTL_VERIFIER_PROVIDER_DESCRIPTOR_64
{
    DWORD   dwLength;
    QWORD   pvProviderDlls;
    QWORD   pvProviderDllLoadCallback;
    QWORD   pvProviderDllUnloadCallback;
    QWORD   pwszVerifierImage;
    DWORD   dwVerifierFlags;
    DWORD   dwVerifierDebug;
    QWORD   pvRtlpGetStackTraceAddress;
    QWORD   pvRtlpDebugPageHeapCreate;
    QWORD   pvRtlpDebugPageHeapDestroy;
    QWORD   pvProviderNtdllHeapFreeCallback;
} RTL_VERIFIER_PROVIDER_DESCRIPTOR_64, *PRTL_VERIFIER_PROVIDER_DESCRIPTOR_64;

// DllMain possible calling reasons
#define DLL_PROCESS_DETACH      0
#define DLL_PROCESS_ATTACH      1
#define DLL_THREAD_ATTACH       2
#define DLL_THREAD_DETACH       3
#define DLL_VERIFIER_PROVIDER   4

///
/// @brief  The states in which a Windows socket can be in
///
typedef enum _WIN_SOCK_STATE
{
    WIN_TCP_CLOSED = 0,
    WIN_TCP_LISTENING,
    WIN_TCP_SYN_SENT,
    WIN_TCP_SYN_RECV,
    WIN_TCP_ESTABLISHED,
    WIN_TCP_FIN_WAIT,
    WIN_TCP_FIN_WAIT2,
    WIN_TCP_CLOSE_WAIT,
    WIN_TCP_CLOSING,
    WIN_TCP_LAST_ACK,
    WIN_TCP_TIME_WAIT = 12,
    WIN_TCP_DELETE_TCB,

    WIN_TCP_MAX_STATE
} WIN_SOCK_STATE;

#define AF_INET  0x02 ///< IPv4
#define AF_INET6 0x17 ///< IPv6

typedef union _ADDRINFO
{
    struct
    {
        QWORD Local;
        QWORD _pad0;
        QWORD Remote;
    } Addr64;

    union
    {
        struct
        {
            DWORD Local;
            DWORD _pad1;
            DWORD Remote;
        } Win7;

        struct
        {
            DWORD Local;
            DWORD _pad2[2];
            DWORD Remote;
        } Win8AndAbove;
    } Addr32;
} ADDRINFO, *PADDRINFO;

typedef union _LOCAL_ADDRESS
{
    struct
    {
        BYTE _pad0[0x0c];
        DWORD InAddr;
    } Addr32;

    struct
    {
        BYTE _pad1[0x10];
        QWORD InAddr;
    } Addr64;
} LOCAL_ADDRESS, *PLOCAL_ADDRESS;

///
/// @brief The common part of nt!_KINTERRUPT on all x86 Windows versions.
///
typedef struct _KINTERRUPT_COMMON32
{
    WORD Type;
    WORD Size;
    DWORD InterruptListEntryFlink;
    DWORD InterruptListEntryBlink;
    DWORD ServiceRoutine;
    DWORD MessageServiceRoutine;
    DWORD MessageIndex;
    DWORD ServiceContext;
    DWORD SpinLock;
    DWORD TickCount;
    DWORD ActualLock;
    DWORD DispatchAddress;
    // We don't care about the others, even if they are fixed.
} KINTERRUPT_COMMON32, *PKINTERRUPT_COMMON32;

STATIC_ASSERT(OFFSET_OF(KINTERRUPT_COMMON32, ServiceRoutine) == 0xc, "Wrong ServiceRoutine offset in KINTERRUPT32!");
STATIC_ASSERT(OFFSET_OF(KINTERRUPT_COMMON32, DispatchAddress) == 0x28, "Wrong DispatchAddress offset in KINTERRUPT32!");

///
/// @brief The common part of nt!_KINTERRUPT on all x64 Windows versions.
///
typedef struct _KINTERRUPT_COMMON64
{
    WORD Type;
    WORD Size;
    QWORD InterruptListEntryFlink;
    QWORD InterruptListEntryBlink;
    QWORD ServiceRoutine;
    QWORD MessageServiceRoutine;
    DWORD MessageIndex;
    QWORD ServiceContext;
    QWORD SpinLock;
    DWORD TickCount;
    QWORD ActualLock;
    QWORD DispatchAddress;
    // We don't care about the others, even if they are fixed.
} KINTERRUPT_COMMON64, *PKINTERRUPT_COMMON64;

STATIC_ASSERT(OFFSET_OF(KINTERRUPT_COMMON64, ServiceRoutine) == 0x18, "Wrong ServiceRoutine offset in KINTERRUPT64!");
STATIC_ASSERT(OFFSET_OF(KINTERRUPT_COMMON64, DispatchAddress) == 0x50, "Wrong DispatchAddress offset in KINTERRUPT64!");


#endif // _WDDEFS_H_
