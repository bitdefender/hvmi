/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file   upperiface.h
///
/// @brief  Defines an interface that exposes various services to the introspection engine.
///
/// This must be fully implemented by an integrator. Unlike glueiface.h, this can be implemented
/// without any support from the hypervisor.
///
/// @ingroup group_public_headers
///

#ifndef _UPPERIFACE_H_
#define _UPPERIFACE_H_

#include "intro_types.h"

#if !defined(INT_COMPILER_MSVC)
#    define PRINTF_ATTRIBUTE __attribute__((format(printf, 3, 4)))
#else
#    define PRINTF_ATTRIBUTE
#endif // !defined(INT_COMPILER_MSVC)

//
// Core Functions exposed by the integrator.
//

///
/// @brief  Provides print-like trace functionality for introcore.
///
/// @param[in]  File    NULL terminated string of the name of the file from which the message originates, can be NULL.
/// @param[in]  Line    The line at which the log originates. If File is NULL it should be ignored.
/// @param[in]  Format  printf-like format string.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value
///
typedef INTSTATUS
PRINTF_ATTRIBUTE
(*PFUNC_IntTracePrint)(
    _In_opt_ const CHAR *File,
    _In_opt_ DWORD Line,
    _In_z_ const CHAR *Format,
    ...
    );

///
/// @brief  Initializes a spin lock
///
/// @param[out] SpinLock    Pointer to an opaque void* value that will represent the spin lock.
/// @param[in]  Name        NULL-terminated string that contains the name of the spin lock.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSpinLockInit)(
    _Outptr_ void **SpinLock,
    _In_z_ PCHAR Name
    );

///
/// @brief  Uninits a spin lock
///
/// @param[in, out] SpinLock    Pointer to an opaque void* value that will represent the spin lock.
///                             This was previously initialized by a #UPPER_IFACE.SpinLockInit call.
///                             On success, SpinLock will be set to NULL.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSpinLockUnInit)(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    );

///
/// @brief  Exclusively acquires a spin lock.
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         #UPPER_IFACE.SpinLockInit call.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSpinLockAcquire)(
    _In_ void *SpinLock
    );

///
/// @brief  Release a spin lock previously acquired with #UPPER_IFACE.SpinLockAcquire.
///
/// @param[in]  SpinLock    The lock that must be released.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntSpinLockRelease)(
    _In_ void *SpinLock
    );

///
/// @brief  Initializes a rw-spin lock.
///
/// @param[out] SpinLock    Pointer to an opaque void* value that will represent the spin lock.
/// @param[in]  Name        NULL-terminated string that contains the name of the spin lock.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockInit)(
    _Outptr_ void **SpinLock,
    _In_z_ PCHAR Name
    );

///
/// @brief  Uninits a rw-spin lock.
///
/// @param[in, out] SpinLock    Pointer to an opaque void* value that will represent the spin lock.
///                             This was previously initialized by a #UPPER_IFACE.RwSpinLockInit call.
///                             On success, SpinLock will be set to NULL.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockUnInit)(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    );

///
/// @brief  Acquires a spin rw-lock in shared mode.
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         #UPPER_IFACE.RwSpinLockInit call.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockAcquireShared)(
    _In_ void *SpinLock
    );

///
/// @brief  Acquires a spin rw-lock in exclusive mode.
///
/// @param[in]  SpinLock    The lock that must be acquired. This was previously initialized by a
///                         #UPPER_IFACE.RwSpinLockInit call.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockAcquireExclusive)(
    _In_ void *SpinLock
    );

///
/// @brief  Release a spin rw-lock previously acquired in shared mode with #UPPER_IFACE.RwSpinLockAcquireShared.
///
/// @param[in]  SpinLock    The lock that must be released.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockReleaseShared)(
    _In_ void *SpinLock
    );

///
/// @brief  Release a spin rw-lock previously acquired in exclusive mode with #UPPER_IFACE.RwSpinLockAcquireExclusive.
///
/// @param[in]  SpinLock    The lock that must be released.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntRwSpinLockReleaseExclusive)(
    _In_ void *SpinLock
    );

///
/// @brief  Get the available free memory available to introcore.
///
/// This function is used by introcore to determine if certain operations can be attempted. In low memory conditions,
/// certain operations will not be attempted.
///
/// @param[out] TotalHeapSize   The total size of the heap, in bytes.
/// @param[out] FreeHeapSize    The size of the remaining free heap, in bytes.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_IntQueryHeapSize)(
    _Out_ size_t *TotalHeapSize,
    _Out_ size_t *FreeHeapSize
    );

///
/// @brief  Crashes the introspection engine.
///
/// This API is used by introcore when an unrecoverable error is encountered. Integrators are free to handle this in
/// the best possible way they can. It is recommended to uninit the introspection engine and to create a memory dump,
/// if possible.
///
typedef void
(*PFUNC_IntBugCheck)(
    void
    );

///
/// @brief  Breaks into the debugger.
///
/// This API is used by introcore to enter a debugger, if one is available.
///
typedef void
(*PFUNC_IntEnterDebugger)(
    void
    );

///
/// @brief  Allocates a block of memory.
///
/// @param[in]  Address     on success, will contain a pointer to the allocated memory region.
/// @param[in]  Size        The size of the block.
/// @param[in]  Tag         The tag of the allocation.
///
/// @returns   #INT_SUCCESS if the allocation succeeded.
/// @returns   #INT_STATUS_INSUFFICIENT_RESOURCES if there is not enough memory available.
///
typedef INTSTATUS
(*PFUNC_HpAllocWithTagAndInfo)(
    _Outptr_result_bytebuffer_(Size) void **Address,
    _In_ size_t Size,
    _In_ DWORD Tag
    );

///
/// @brief  Frees a memory block previously allocated with #UPPER_IFACE.MemAllocWithTagAndInfo.
///
/// @param[in]  Address     Pointer to the memory address of the allocated block. After the function returns it will be
///                         set to NULL.
/// @param[in]  Tag         The tag of the allocation. Must match the one provided by the
///                         #UPPER_IFACE.MemFreeWithTagAndInfo call.
///
/// @returns    #INT_STATUS_SUCCESS on success, or an appropriate INTSTATUS error value.
///
typedef INTSTATUS
(*PFUNC_HpFreeWithTagAndInfo)(
    _Inout_ _At_(*Address, _Post_null_) void **Address,
    _In_ DWORD Tag
    );

#pragma pack(push)
#pragma pack(8)

///
/// @brief  Interface that exposes basic services to the introspection engines.
///
/// Before using any of the function pointers in the structure, it must be validated using the #UPPER_IFACE.Version
/// and #UPPER_IFACE.Size fields in order to ensure that the introcore version used matches the one for which this
/// header file was published.
///
typedef struct _UPPER_IFACE
{
    /// The version of the interface. Must match #UPPER_IFACE_VERSION_1
    DWORD                                   Version;
    /// The size of the interface.Must match #UPPER_IFACE_VERSION_1_SIZE
    DWORD                                   Size;
    QWORD                                   Reserved;

    PFUNC_IntTracePrint                     TracePrint;
    PFUNC_HpAllocWithTagAndInfo             MemAllocWithTagAndInfo;
    PFUNC_HpFreeWithTagAndInfo              MemFreeWithTagAndInfo;
    PFUNC_IntSpinLockInit                   SpinLockInit;
    PFUNC_IntSpinLockUnInit                 SpinLockUnInit;
    PFUNC_IntSpinLockAcquire                SpinLockAcquire;
    PFUNC_IntSpinLockRelease                SpinLockRelease;
    PFUNC_IntRwSpinLockInit                 RwSpinLockInit;
    PFUNC_IntRwSpinLockUnInit               RwSpinLockUnInit;
    PFUNC_IntRwSpinLockAcquireShared        RwSpinLockAcquireShared;
    PFUNC_IntRwSpinLockAcquireExclusive     RwSpinLockAcquireExclusive;
    PFUNC_IntRwSpinLockReleaseShared        RwSpinLockReleaseShared;
    PFUNC_IntRwSpinLockReleaseExclusive     RwSpinLockReleaseExclusive;
    PFUNC_IntQueryHeapSize                  QueryHeapSize;
    PFUNC_IntBugCheck                       BugCheck;
    PFUNC_IntEnterDebugger                  EnterDebugger;
} UPPER_IFACE, *PUPPER_IFACE;

#define UPPER_IFACE_VERSION_1           0x00010074
#define UPPER_IFACE_VERSION_1_SIZE      sizeof(UPPER_IFACE)

#define UPPER_IFACE_VERSION_LATEST      UPPER_IFACE_VERSION_1
#define UPPER_IFACE_VERSION_LATEST_SIZE UPPER_IFACE_VERSION_1_SIZE

#pragma pack(pop)

#endif // _UPPERIFACE_H_
