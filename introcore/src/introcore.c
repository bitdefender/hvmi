/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "introcore.h"
#include "debugger.h"
#include "guests.h"
#include "introapi.h"
#include "introcpu.h"
#include "gpacache.h"
#include "winprocess.h"
#include "lixprocess.h"

#ifdef INT_COMPILER_MSVC
#    include "../../autogen/ver.h"
#endif // INT_COMPILER_MSVC

/// @brief  A lock that ensures that all the events are serialized inside introcore
///
/// This essentially makes introcore act as a single threaded library, since only one callback will be executing at
/// a time. Since events on Xen are already synchronized this is already true for VMX events even without this lock.
/// It just ensures that this behavior is consistent across all APIs, not just event handlers. Not acquiring this lock
/// is a fatal error as all the code in introcore assumes that this lock is held.
void *gLock = NULL;

/// @brief  The version of the introcore library
const INT_VERSION_INFO IntHviVersion =
{
    .VersionInfo =
    {
        .Build = INTRO_VERSION_BUILDNUMBER & 0xFFFF,
        .Revision = INTRO_VERSION_REVISION,
        .Minor = INTRO_VERSION_MINOR,
        .Major = INTRO_VERSION_MAJOR
    }
};

/// @brief  Global storage for the error context used by #GLUE_IFACE.NotifyIntrospectionErrorState
///
/// Since API calls are serialized, all the error notifications use this as the context in order to avoid allocating
/// extra memory when reporting an error, as some errors may be triggered by low memory conditions and we would like
/// to avoid memory allocations in those situations.
INTRO_ERROR_CONTEXT gErrorContext = { 0 };

/// @brief  Holds information about page mappings that contain multiple pages
typedef struct _MULTI_PAGE_MAP
{
    LIST_ENTRY  Link;       ///< Entry inside the #gMultiPageMaps list
    void        *HostPtr;   ///< The virtual address to which #Gva was mapped. Page aligned.
    void        *OrigAlloc; ///< The original allocation, which may bot be page aligned.
    QWORD       Gva;        ///< Guest virtual address to map
    DWORD       Length;     ///< The size to map
} MULTI_PAGE_MAP, *PMULTI_PAGE_MAP;

/// @brief  List of all the currently valid multi page maps
LIST_HEAD gMultiPageMaps = LIST_HEAD_INIT(gMultiPageMaps);

/// @brief  Set to True if introcore should abort the initialization process
BOOLEAN gAbortLoad = FALSE;

/// @brief  Set to True if support for SSE 4.2 was detected
extern BOOLEAN gSse42Supported;

/// @brief  Set to True when introcore is inside a debugger
///
/// This is used to avoid pausing VCPUs while trapped inside a debugger, as that can lead
/// to deadlocks
extern BOOLEAN gInsideDebugger;

/// @brief  Converts a byte number to a mask having the bits in those bytes set
///
/// For example, for 5, will return 0x0000000000ff00ff which has bytes 0 and 1 filled.
const QWORD gByteMaskToBitMask[256] =
{
    0x0000000000000000, 0x00000000000000ff, 0x000000000000ff00, 0x000000000000ffff,
    0x0000000000ff0000, 0x0000000000ff00ff, 0x0000000000ffff00, 0x0000000000ffffff,
    0x00000000ff000000, 0x00000000ff0000ff, 0x00000000ff00ff00, 0x00000000ff00ffff,
    0x00000000ffff0000, 0x00000000ffff00ff, 0x00000000ffffff00, 0x00000000ffffffff,
    0x000000ff00000000, 0x000000ff000000ff, 0x000000ff0000ff00, 0x000000ff0000ffff,
    0x000000ff00ff0000, 0x000000ff00ff00ff, 0x000000ff00ffff00, 0x000000ff00ffffff,
    0x000000ffff000000, 0x000000ffff0000ff, 0x000000ffff00ff00, 0x000000ffff00ffff,
    0x000000ffffff0000, 0x000000ffffff00ff, 0x000000ffffffff00, 0x000000ffffffffff,
    0x0000ff0000000000, 0x0000ff00000000ff, 0x0000ff000000ff00, 0x0000ff000000ffff,
    0x0000ff0000ff0000, 0x0000ff0000ff00ff, 0x0000ff0000ffff00, 0x0000ff0000ffffff,
    0x0000ff00ff000000, 0x0000ff00ff0000ff, 0x0000ff00ff00ff00, 0x0000ff00ff00ffff,
    0x0000ff00ffff0000, 0x0000ff00ffff00ff, 0x0000ff00ffffff00, 0x0000ff00ffffffff,
    0x0000ffff00000000, 0x0000ffff000000ff, 0x0000ffff0000ff00, 0x0000ffff0000ffff,
    0x0000ffff00ff0000, 0x0000ffff00ff00ff, 0x0000ffff00ffff00, 0x0000ffff00ffffff,
    0x0000ffffff000000, 0x0000ffffff0000ff, 0x0000ffffff00ff00, 0x0000ffffff00ffff,
    0x0000ffffffff0000, 0x0000ffffffff00ff, 0x0000ffffffffff00, 0x0000ffffffffffff,
    0x00ff000000000000, 0x00ff0000000000ff, 0x00ff00000000ff00, 0x00ff00000000ffff,
    0x00ff000000ff0000, 0x00ff000000ff00ff, 0x00ff000000ffff00, 0x00ff000000ffffff,
    0x00ff0000ff000000, 0x00ff0000ff0000ff, 0x00ff0000ff00ff00, 0x00ff0000ff00ffff,
    0x00ff0000ffff0000, 0x00ff0000ffff00ff, 0x00ff0000ffffff00, 0x00ff0000ffffffff,
    0x00ff00ff00000000, 0x00ff00ff000000ff, 0x00ff00ff0000ff00, 0x00ff00ff0000ffff,
    0x00ff00ff00ff0000, 0x00ff00ff00ff00ff, 0x00ff00ff00ffff00, 0x00ff00ff00ffffff,
    0x00ff00ffff000000, 0x00ff00ffff0000ff, 0x00ff00ffff00ff00, 0x00ff00ffff00ffff,
    0x00ff00ffffff0000, 0x00ff00ffffff00ff, 0x00ff00ffffffff00, 0x00ff00ffffffffff,
    0x00ffff0000000000, 0x00ffff00000000ff, 0x00ffff000000ff00, 0x00ffff000000ffff,
    0x00ffff0000ff0000, 0x00ffff0000ff00ff, 0x00ffff0000ffff00, 0x00ffff0000ffffff,
    0x00ffff00ff000000, 0x00ffff00ff0000ff, 0x00ffff00ff00ff00, 0x00ffff00ff00ffff,
    0x00ffff00ffff0000, 0x00ffff00ffff00ff, 0x00ffff00ffffff00, 0x00ffff00ffffffff,
    0x00ffffff00000000, 0x00ffffff000000ff, 0x00ffffff0000ff00, 0x00ffffff0000ffff,
    0x00ffffff00ff0000, 0x00ffffff00ff00ff, 0x00ffffff00ffff00, 0x00ffffff00ffffff,
    0x00ffffffff000000, 0x00ffffffff0000ff, 0x00ffffffff00ff00, 0x00ffffffff00ffff,
    0x00ffffffffff0000, 0x00ffffffffff00ff, 0x00ffffffffffff00, 0x00ffffffffffffff,
    0xff00000000000000, 0xff000000000000ff, 0xff0000000000ff00, 0xff0000000000ffff,
    0xff00000000ff0000, 0xff00000000ff00ff, 0xff00000000ffff00, 0xff00000000ffffff,
    0xff000000ff000000, 0xff000000ff0000ff, 0xff000000ff00ff00, 0xff000000ff00ffff,
    0xff000000ffff0000, 0xff000000ffff00ff, 0xff000000ffffff00, 0xff000000ffffffff,
    0xff0000ff00000000, 0xff0000ff000000ff, 0xff0000ff0000ff00, 0xff0000ff0000ffff,
    0xff0000ff00ff0000, 0xff0000ff00ff00ff, 0xff0000ff00ffff00, 0xff0000ff00ffffff,
    0xff0000ffff000000, 0xff0000ffff0000ff, 0xff0000ffff00ff00, 0xff0000ffff00ffff,
    0xff0000ffffff0000, 0xff0000ffffff00ff, 0xff0000ffffffff00, 0xff0000ffffffffff,
    0xff00ff0000000000, 0xff00ff00000000ff, 0xff00ff000000ff00, 0xff00ff000000ffff,
    0xff00ff0000ff0000, 0xff00ff0000ff00ff, 0xff00ff0000ffff00, 0xff00ff0000ffffff,
    0xff00ff00ff000000, 0xff00ff00ff0000ff, 0xff00ff00ff00ff00, 0xff00ff00ff00ffff,
    0xff00ff00ffff0000, 0xff00ff00ffff00ff, 0xff00ff00ffffff00, 0xff00ff00ffffffff,
    0xff00ffff00000000, 0xff00ffff000000ff, 0xff00ffff0000ff00, 0xff00ffff0000ffff,
    0xff00ffff00ff0000, 0xff00ffff00ff00ff, 0xff00ffff00ffff00, 0xff00ffff00ffffff,
    0xff00ffffff000000, 0xff00ffffff0000ff, 0xff00ffffff00ff00, 0xff00ffffff00ffff,
    0xff00ffffffff0000, 0xff00ffffffff00ff, 0xff00ffffffffff00, 0xff00ffffffffffff,
    0xffff000000000000, 0xffff0000000000ff, 0xffff00000000ff00, 0xffff00000000ffff,
    0xffff000000ff0000, 0xffff000000ff00ff, 0xffff000000ffff00, 0xffff000000ffffff,
    0xffff0000ff000000, 0xffff0000ff0000ff, 0xffff0000ff00ff00, 0xffff0000ff00ffff,
    0xffff0000ffff0000, 0xffff0000ffff00ff, 0xffff0000ffffff00, 0xffff0000ffffffff,
    0xffff00ff00000000, 0xffff00ff000000ff, 0xffff00ff0000ff00, 0xffff00ff0000ffff,
    0xffff00ff00ff0000, 0xffff00ff00ff00ff, 0xffff00ff00ffff00, 0xffff00ff00ffffff,
    0xffff00ffff000000, 0xffff00ffff0000ff, 0xffff00ffff00ff00, 0xffff00ffff00ffff,
    0xffff00ffffff0000, 0xffff00ffffff00ff, 0xffff00ffffffff00, 0xffff00ffffffffff,
    0xffffff0000000000, 0xffffff00000000ff, 0xffffff000000ff00, 0xffffff000000ffff,
    0xffffff0000ff0000, 0xffffff0000ff00ff, 0xffffff0000ffff00, 0xffffff0000ffffff,
    0xffffff00ff000000, 0xffffff00ff0000ff, 0xffffff00ff00ff00, 0xffffff00ff00ffff,
    0xffffff00ffff0000, 0xffffff00ffff00ff, 0xffffff00ffffff00, 0xffffff00ffffffff,
    0xffffffff00000000, 0xffffffff000000ff, 0xffffffff0000ff00, 0xffffffff0000ffff,
    0xffffffff00ff0000, 0xffffffff00ff00ff, 0xffffffff00ffff00, 0xffffffff00ffffff,
    0xffffffffff000000, 0xffffffffff0000ff, 0xffffffffff00ff00, 0xffffffffff00ffff,
    0xffffffffffff0000, 0xffffffffffff00ff, 0xffffffffffffff00, 0xffffffffffffffff,
};


static __forceinline BOOLEAN
IsSse42Supported(
    void
    )
///
/// @brief      Checks if support for SSE 4.2 is present
///
/// @returns    True if support was detected, False if it was not
///
{
    int regs[4] = {0};

    __cpuid(regs, 1);

    if (regs[2] & (1 << 20))
    {
        return TRUE;
    }

    return FALSE;
}


void
IntPreinit(
    void
    )
///
/// @brief  Initializes the global variables used throughout the project.
///
/// This should be called before #IntInit in order to ensure that the global state
/// is properly zeroed before introcore starts.
///
/// @post   The global introcore state is reset and zeroed.
///
{
    IntGlueReset();
}


//
// IntInit
//
INTSTATUS
IntInit(
    _Inout_ GLUE_IFACE *GlueInterface,
    _In_ UPPER_IFACE const *UpperInterface
    )
///
/// @brief          Initializes introcore
///
/// This will validate and initialize the #GLUE_IFACE and #UPPER_IFACE instances, as well as the #gLock lock.
///
/// @param[in, out] GlueInterface   The instance of #GLUE_IFACE to be used. The part that must be implemented
///                                 by the integrator must be implemented. Introcore will fill initialize the
///                                 APIs it exposes.
/// @param[in]      UpperInterface  The instance of #UPPER_IFACE to be used. All the mandatory APIs must be implemented
///
/// @returns        INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
/// @pre    #IntPreinit was called
///
/// @post   #gIface, #gUpIface, and #gLock are fully initialized and can be used
///
{
    INTSTATUS status;

    status = IntGlueInit(GlueInterface, UpperInterface);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    //
    // Populate our part of the interface
    //
    GlueInterface->NewGuestNotification             = IntNewGuestNotification;
    GlueInterface->DisableIntro                     = IntDisableIntro;
    GlueInterface->NotifyGuestPowerStateChange      = IntNotifyGuestPowerStateChange;
    GlueInterface->DebugProcessCommand              = IntProcessDebugCommand;
    GlueInterface->UpdateExceptions                 = IntUpdateExceptions;
    GlueInterface->GetExceptionsVersion             = IntGetExceptionsVersion;
    GlueInterface->GetGuestInfo                     = IntGetGuestInfo;
    GlueInterface->InjectProcessAgent               = IntInjectProcessAgentInGuest;
    GlueInterface->InjectFileAgent                  = IntInjectFileAgentInGuest;
    GlueInterface->SetIntroAbortStatus              = IntAbortEnableIntro;
    GlueInterface->AddExceptionFromAlert            = IntAddExceptionFromAlert;
    GlueInterface->RemoveException                  = IntRemoveException;
    GlueInterface->FlushAlertExceptions             = IntFlushAlertExceptions;
    GlueInterface->AddRemoveProtectedProcessUtf16   = IntAddRemoveProtectedProcessUtf16;
    GlueInterface->AddRemoveProtectedProcessUtf8    = IntAddRemoveProtectedProcessUtf8;
    GlueInterface->RemoveAllProtectedProcesses      = IntRemoveAllProtectedProcesses;
    GlueInterface->GetCurrentInstructionLength      = IntGetCurrentInstructionLength;
    GlueInterface->GetCurrentInstructionMnemonic    = IntGetCurrentInstructionMnemonic;
    GlueInterface->IterateVirtualAddressSpace       = IntIterateVaSpace;
    GlueInterface->ModifyDynamicOptions             = IntModifyDynamicOptions;
    GlueInterface->FlushGpaCache                    = IntFlushGpaCache;
    GlueInterface->GetCurrentIntroOptions           = IntGetCurrentIntroOptions;
    GlueInterface->UpdateSupport                    = IntUpdateSupport;
    GlueInterface->GetSupportVersion                = IntGetSupportVersion;
    GlueInterface->SetLogLevel                      = IntSetLogLevel;
    GlueInterface->GetVersionString                 = IntGetVersionString;

    gSse42Supported = IsSse42Supported();

    LOG("IntroCore initialised: version %d.%d.%d, build %05d, changeset %s, built on %s %s from branch %s\n",
        INTRO_VERSION_MAJOR, INTRO_VERSION_MINOR, INTRO_VERSION_REVISION, INTRO_VERSION_BUILDNUMBER,
        INTRO_VERSION_CHANGESET, __DATE__, __TIME__, INTRO_VERSION_BRANCH);

    status = IntSpinLockInit(&gLock, "INTRO GLOCK");
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSpinLockInit failed: %08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


//
// IntUninit
//
INTSTATUS
IntUninit(
    void
    )
///
/// @brief  Disables and uninitializes Introcore
///
/// This will disable introspection engine, remove the guest protection and uninitialize the global state.
/// Note that if a guest is initialized, disabling the protection for it will be done using the
/// #IG_DISABLE_IGNORE_SAFENESS option.
/// This will also unmap everything in the #gMultiPageMaps list of mappings, reset the #GLUE_IFACE and #UPPER_IFACE
/// instances and uninitialize the #gLock lock.
///
{
    LIST_ENTRY *list;

    TRACE("[INFO] Unloading introspection library...\n");

    if (gGuest.Initialized)
    {
        INTSTATUS status = IntDisableIntro(gIntHandle, IG_DISABLE_IGNORE_SAFENESS);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDisableIntro failed: 0x%08x\n", status);
        }
    }

    if (gLock)
    {
        IntSpinLockUnInit(&gLock);
    }

    list = gMultiPageMaps.Flink;
    while (list != &gMultiPageMaps)
    {
        MULTI_PAGE_MAP *pPage = CONTAINING_RECORD(list, MULTI_PAGE_MAP, Link);
        list = list->Flink;

        HpFreeAndNullWithTag(&pPage->OrigAlloc, IC_TAG_MLMP);
        RemoveEntryList(&pPage->Link);
        HpFreeAndNullWithTag(&pPage, IC_TAG_MLMP);
    }

    IntGlueReset();

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntVirtMemReadWrite(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _When_(Write == TRUE, _In_reads_bytes_(Length))
    _When_(Write == FALSE, _Out_writes_bytes_(Length))
    void *Buffer,
    _Out_opt_ DWORD *RetLength,
    _In_ BOOLEAN Write
    )
///
/// @brief          Transfers memory between a guest virtual memory range and Introcore
///
/// This function will copy a virtual-address range to a designated buffer, or a designated buffer inside a
/// virtual-address range. If the range spans across multiple pages, it will map each page individually, but no more
/// than one page at a time.
/// If it returns INT_STATUS_SUCCESS, for write operations, the memory range will contain Length bytes from Buffer;
/// for read operations, Buffer will contain Length bytes from the physical address range. If RetLength is not NULL,
/// it will contain the value Length. If it doesn't return INT_STATUS_SUCCESS, RetLength will contain the number of
/// bytes successfully transferred (which will most likely be less than Length).
/// Note that write operations will be done even if Address is not writable inside the guest's page tables.
///
/// @param[in]      VirtualAddress  The start of the virtual address range
/// @param[in]      Length          The size to be read or written
/// @param[in]      Cr3             The Cr3 used to translate VirtualAddress to a physical address. If 0, the current
///                                 Cr3 used by the guest will be used. If KPTI is enabled and the current process
///                                 has different user mode and kernel mode page directory base registers, the one
///                                 for the kernel will be used, even if the user mode Cr3 is loaded.
/// @param[in, out] Buffer          If Write is True, the buffer from which contents will be copied inside the guest's
///                                 memory. If Write is False, the buffer in which the contents of the guest memory
///                                 will be copied to. Must be at least Length bytes in size.
/// @param[out]     RetLength       The actual size that we managed to transfer from the guest to introcore. If
///                                 INT_STATUS_SUCCES is returned, this will be equal to Length. May be NULL.
/// @param[in]      Write           True for write operations, False for read operations.
///
/// @retval         INT_STATUS_SUCCESS in case of success
/// @retval         #INT_STATUS_INVALID_PARAMETER_2 is Length is 0
/// @retval         #INT_STATUS_PAGE_NOT_PRESENT if VirtualAddress is not present inside the guest page tables
///
{
    INTSTATUS status;
    DWORD left = Length;
    QWORD gva = VirtualAddress;
    BYTE *buffer = Buffer;

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &Cr3);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    do
    {
        DWORD size = MIN(left, PAGE_REMAINING(gva));
        void *p;

        status = IntVirtMemMap(gva, size, Cr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        if (__unlikely(Write))
        {
            memcpy(p, buffer, size);
        }
        else
        {
            memcpy(buffer, p, size);
        }

        IntVirtMemUnmap(&p);

        gva += size;
        left -= size;
        buffer += size;
    } while (gva < VirtualAddress + Length);

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (RetLength != NULL)
    {
        *RetLength = Length - left;
    }

    return status;
}


INTSTATUS
IntVirtMemSet(
    _In_ QWORD VirtualAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_ BYTE Value
    )
{
    INTSTATUS status;
    DWORD left = Length;
    QWORD gva = VirtualAddress;

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &Cr3);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    do
    {
        DWORD size = MIN(left, PAGE_REMAINING(gva));
        void *p;

        status = IntVirtMemMap(gva, size, Cr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        memset(p, Value, size);
        IntVirtMemUnmap(&p);

        gva += size;
        left -= size;
    } while (gva < VirtualAddress + Length);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntPhysMemReadWriteAnySize(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _When_(Write == TRUE, _In_reads_bytes_(Length))
    _When_(Write == FALSE, _Out_writes_bytes_(Length))
    void *Buffer,
    _Out_opt_ DWORD *RetLength,
    _In_ BOOLEAN Write
    )
///
/// @brief          Transfers memory between a guest physical memory range and Introcore
///
/// This function will copy a physical-address range to a designated buffer, or a designated buffer inside a
/// physical-address range. If the range spans across multiple pages, it will map each page individually, but no more
/// than one page at a time.
/// If it returns INT_STATUS_SUCCESS, for write operations, the memory range will contain Length bytes from Buffer;
/// for read operations, Buffer will contain Length bytes from the physical address range. If RetLength is not NULL,
/// it will contain the value Length. If it doesn't return INT_STATUS_SUCCESS, RetLength will contain the number of
/// bytes successfully transferred (which will most likely be less than Length).
/// Note that the guest physical address space is not guaranteed to be contiguous, so calling this function for a
/// range that spans across multiple pages must be done only in very specific cases when the caller can guarantee
/// that those pages are contiguous.
///
/// @param[in]      PhysicalAddress The start of the physical memory range
/// @param[in]      Length          The size of the physical memory range
/// @param[in, out] Buffer          If Write is True, the buffer from which contents will be copied inside the guest's
///                                 memory. If Write is False, the buffer in which the contents of the guest memory
///                                 will be copied to. Must be at least Length bytes in size.
/// @param[out]     RetLength       The actual size that we managed to transfer from the guest to introcore. If
///                                 INT_STATUS_SUCCES is returned, this will be equal to Length. May be NULL.
/// @param[in]      Write           True for write operations, False for read operations.
///
/// @retval         INT_STATUS_SUCCESS in case of success
/// @retval         #INT_STATUS_INVALID_PARAMETER_2 is Length is 0
///
{
    INTSTATUS status;
    DWORD left = Length;
    QWORD gpa = PhysicalAddress;
    BYTE *buffer = Buffer;

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    while (gpa < PhysicalAddress + Length)
    {
        DWORD size = MIN(left, PAGE_REMAINING(gpa));
        void *p;

        status = IntPhysMemMap(gpa, size, 0, &p);
        if (!INT_SUCCESS(status))
        {
            goto cleanup_and_exit;
        }

        if (__unlikely(Write))
        {
            memcpy(p, buffer, size);
        }
        else
        {
            memcpy(buffer, p, size);
        }

        IntVirtMemUnmap(&p);

        gpa += size;
        left -= size;
        buffer += size;
    }

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (RetLength != NULL)
    {
        *RetLength = Length - left;
    }

    return status;
}


static INTSTATUS
IntPhysMemReadWrite(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Inout_updates_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength,
    _In_ BOOLEAN Write
    )
///
/// @brief          Transfers memory between a guest physical memory range and Introcore, but only for a single
///                 memory page
///
/// This function will copy the contents of a physical memory page to a designated buffer, or a designated buffer
/// inside a physical memory page. It will not work if the memory range spans across multiple pages.
/// If it returns INT_STATUS_SUCCESS, for write operations, the memory range will contain Length bytes from Buffer;
/// for read operations, Buffer will contain Length bytes from the physical address range. If RetLength is not NULL,
/// it will contain the value Length. If it doesn't return INT_STATUS_SUCCESS, RetLength will contain the number of
/// bytes successfully transferred (which will most likely be less than Length).
///
/// @param[in]      PhysicalAddress The start of the physical memory range
/// @param[in]      Length          The size of the physical memory range
/// @param[in, out] Buffer          If Write is True, the buffer from which contents will be copied inside the guest's
///                                 memory. If Write is False, the buffer in which the contents of the guest memory
///                                 will be copied to. Must be at least Length bytes in size.
/// @param[out]     RetLength       The actual size that we managed to transfer from the guest to Introcore. If
///                                 INT_STATUS_SUCCES is returned, this will be equal to Length. May be NULL.
/// @param[in]      Write           True for write operations, False for read operations.
///
/// @retval         INT_STATUS_SUCCESS in case of success
/// @retval         #INT_STATUS_INVALID_PARAMETER_1 if the physical memory range spans across multiple pages
/// @retval         #INT_STATUS_INVALID_PARAMETER_2 is Length is 0
///
{
    INTSTATUS status;
    void *p;
    DWORD copiedSize = 0;

    if (PAGE_COUNT(PhysicalAddress, Length) > 1)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    status = IntPhysMemMap(PhysicalAddress, PAGE_REMAINING(PhysicalAddress), 0, &p);
    if (!INT_SUCCESS(status))
    {
        TRACE("[ERROR] IntPhysMemMap failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (Write)
    {
        memcpy(p, Buffer, Length);
    }
    else
    {
        memcpy(Buffer, p, Length);
    }

    copiedSize = Length;

    IntPhysMemUnmap(&p);

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (RetLength != NULL)
    {
        *RetLength = copiedSize;
    }

    return status;
}


INTSTATUS
IntVirtMemRead(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    )
///
/// @brief      Reads data from a guest virtual memory range
///
/// @param[in]  Gva         The start of the guest virtual memory range
/// @param[in]  Length      The size of the memory range
/// @param[in]  Cr3         The Cr3 used to translate Gva. If 0, the current kernel Cr3 will be used.
/// @param[out] Buffer      Buffer in which data will be read. Must be at least Length bytes in size.
/// @param[out] RetLength   The size we managed to read. In case of success, it will always be equal to Length. May
///                         be NULL.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemReadWrite(Gva, Length, Cr3, Buffer, RetLength, FALSE);
}


INTSTATUS
IntVirtMemWrite(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_reads_bytes_(Length) void *Buffer
    )
///
/// @brief      Writes data to a guest virtual memory range
///
/// @param[in]  Gva         The start of the guest virtual memory range
/// @param[in]  Length      The size of the memory range
/// @param[in]  Cr3         The Cr3 used to translate Gva. If 0, the current kernel Cr3 will be used.
/// @param[out] Buffer      Buffer with the data to be written. Must be at least Length bytes in size.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemReadWrite(Gva, Length, Cr3, Buffer, NULL, TRUE);
}


INTSTATUS
IntKernVirtMemRead(
    _In_ QWORD KernelGva,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    )
///
/// @brief      Reads data from a guest kernel virtual memory range
///
/// Similar to #IntVirtMemRead, but will always use the system Cr3 saved in #gGuest.
///
/// @param[in]  KernelGva   The start of the guest virtual memory range
/// @param[in]  Length      The size of the memory range
/// @param[out] Buffer      Buffer in which data will be read. Must be at least Length bytes in size.
/// @param[out] RetLength   The size we managed to read. In case of success, it will always be equal to Length. May
///                         be NULL.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemReadWrite(KernelGva, Length, gGuest.Mm.SystemCr3, Buffer, RetLength, FALSE);
}


INTSTATUS
IntKernVirtMemWrite(
    _In_ QWORD KernelGva,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    )
///
/// @brief      Writes data to a guest kernel virtual memory range
///
/// Similar to #IntVirtMemWrite, but will always use the system Cr3 saved in #gGuest.
///
/// @param[in]  KernelGva   The start of the guest virtual memory range
/// @param[in]  Length      The size of the memory range
/// @param[out] Buffer      Buffer with the data to be written. Must be at least Length bytes in size.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemReadWrite(KernelGva, Length, gGuest.Mm.SystemCr3, Buffer, NULL, TRUE);
}


INTSTATUS
IntPhysicalMemRead(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    )
///
/// @brief      Reads data from a guest physical memory range, but only for a single page
///
/// @param[in]  PhysicalAddress     The start of the guest physical memory range
/// @param[in]  Length              The size of the memory range
/// @param[out] Buffer              Buffer in which data will be read. Must be at least Length bytes in size.
/// @param[out] RetLength           The size we managed to read. In case of success, it will always be equal to Length.
///                                 May be NULL.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntPhysMemReadWrite(PhysicalAddress, Length, Buffer, RetLength, FALSE);
}


INTSTATUS
IntPhysicalMemWrite(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    )
///
/// @brief      Writes data to a guest physical memory range, but only for a single page
///
/// @param[in]  PhysicalAddress     The start of the guest physical memory range
/// @param[in]  Length              The size of the memory range
/// @param[out] Buffer              Buffer that contains the data to be written. Must be at least Length bytes in size.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntPhysMemReadWrite(PhysicalAddress, Length, Buffer, NULL, TRUE);
}


INTSTATUS
IntPhysicalMemReadAnySize(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _Out_writes_bytes_(Length) void *Buffer,
    _Out_opt_ DWORD *RetLength
    )
///
/// @brief      Reads data from a guest physical memory range, regardless of how many pages it spans across
///
/// This is useful when reading contents from large pages, for example.
///
/// @param[in]  PhysicalAddress     The start of the guest physical memory range
/// @param[in]  Length              The size of the memory range
/// @param[out] Buffer              Buffer in which data will be read. Must be at least Length bytes in size.
/// @param[out] RetLength           The size we managed to read. In case of success, it will always be equal to Length.
///                                 May be NULL.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntPhysMemReadWriteAnySize(PhysicalAddress, Length, Buffer, RetLength, FALSE);
}


INTSTATUS
IntPhysicalMemWriteAnySize(
    _In_ QWORD PhysicalAddress,
    _In_ DWORD Length,
    _In_reads_bytes_(Length) void *Buffer
    )
///
/// @brief      Writes data to a guest physical memory range, regardless of how many pages it spans across
///
/// This is useful when writing to large pages, for example.
///
/// @param[in]  PhysicalAddress     The start of the guest physical memory range
/// @param[in]  Length              The size of the memory range
/// @param[out] Buffer              Buffer that contains the data to be written. Must be at least Length bytes in size.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntPhysMemReadWriteAnySize(PhysicalAddress, Length, Buffer, NULL, TRUE);
}


INTSTATUS
IntKernVirtMemFetchQword(
    _In_ QWORD GuestVirtualAddress,
    _Out_ QWORD *Data
    )
///
/// @brief      Reads 8 bytes from the guest kernel memory
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[out] Data                    Data read from the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemRead(GuestVirtualAddress, 8,  Data, NULL);
}


INTSTATUS
IntKernVirtMemFetchDword(
    _In_ QWORD GuestVirtualAddress,
    _Out_ DWORD *Data
    )
///
/// @brief      Reads 4 bytes from the guest kernel memory
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[out] Data                    Data read from the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemRead(GuestVirtualAddress, 4, Data, NULL);
}


INTSTATUS
IntKernVirtMemFetchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _Out_ void *Data
    )
///
/// @brief      Reads a guest pointer from the guest kernel memory
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[out] Data                    Data read from the guest. Must be at least 8 bytes long for 64-bit guests, and
///                                     at least 4 bytes long for 32-bit guests.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemRead(GuestVirtualAddress, gGuest.WordSize, Data, NULL);
}


INTSTATUS
IntVirtMemFetchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ QWORD *Data
    )
///
/// @brief      Reads 8 bytes from the guest memory
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data read from the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemRead(GuestVirtualAddress, 8, Cr3, Data, NULL);
}


INTSTATUS
IntVirtMemFetchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ DWORD *Data
    )
///
/// @brief      Reads 4 bytes from the guest memory
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data read from the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemRead(GuestVirtualAddress, 4, Cr3, Data, NULL);
}


INTSTATUS
IntVirtMemFetchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _Out_ void *Data
    )
///
/// @brief      Reads a guest pointer from the guest memory
///
/// For 64-bit guests, this will read 8 bytes. For 32-bit guests, this will read 4 bytes.
///
/// @param[in]  GuestVirtualAddress     Virtual address from which to read
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data read from the guest. The buffer must be at least 8 bytes in size for
///                                     64-bit guests, and 4 bytes in size for 32-bit guests.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemRead(GuestVirtualAddress, gGuest.WordSize, Cr3, Data, NULL);
}


INTSTATUS
IntKernVirtMemPatchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_ QWORD Data
    )
///
/// @brief      Writes 8 bytes in the guest kernel memory
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[out] Data                    Data to write inside the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemWrite(GuestVirtualAddress, 8, &Data);
}


INTSTATUS
IntKernVirtMemPatchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD Data
    )
///
/// @brief      Writes 4 bytes in the guest kernel memory
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[out] Data                    Data to write inside the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemWrite(GuestVirtualAddress, 4, &Data);
}


INTSTATUS
IntKernVirtMemPatchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_ QWORD Data
    )
///
/// @brief      Writes a guest pointer inside the guest kernel memory
///
/// For 64-bit guests, this will write 8 bytes. For 32-bit guests, this will write 4 bytes.
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[out] Data                    Data to write inside the guest. For 32-bit guests, only the low 32-bits
///                                     will be written.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntKernVirtMemWrite(GuestVirtualAddress, gGuest.WordSize, &Data);
}


INTSTATUS
IntVirtMemPatchQword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ QWORD Data
    )
///
/// @brief      Writes 8 bytes in the guest memory
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data to write inside the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemWrite(GuestVirtualAddress, 8, Cr3, &Data);
}


INTSTATUS
IntVirtMemPatchDword(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ DWORD Data
    )
///
/// @brief      Writes 4 bytes in the guest memory
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data to write inside the guest
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemWrite(GuestVirtualAddress, 4, Cr3, &Data);
}


INTSTATUS
IntVirtMemPatchWordSize(
    _In_ QWORD GuestVirtualAddress,
    _In_opt_ QWORD Cr3,
    _In_ QWORD Data
    )
///
/// @brief      Writes a guest pointer inside the guest memory
///
/// @param[in]  GuestVirtualAddress     Virtual address at which the write is done
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used.
/// @param[out] Data                    Data to write inside the guest. For 32-bit guests, only the low 32-bits
///                                     will be written.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    return IntVirtMemWrite(GuestVirtualAddress, gGuest.WordSize, Cr3, &Data);
}


INTSTATUS
IntVirtMemFetchString(
    _In_ QWORD Gva,
    _In_ DWORD MaxLength,
    _In_opt_ QWORD Cr3,
    _Out_writes_z_(MaxLength) void *Buffer
    )
///
/// @brief      Reads a NULL-terminated string from the guest
///
/// @param[in]  Gva         Guest virtual address from which the read starts
/// @param[in]  MaxLength   Maximum length to be read. If a NULL terminator is not found before MaxLength bytes are
///                         read, the read stops.
/// @param[in]  Cr3         The Cr3 used to translate Gva. If 0, the current kernel Cr3 will be used.
/// @param[out] Buffer      Buffer containing the data read from the guest
///
/// @retval     INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 is Buffer is NULL
/// @retval     #INT_STATUS_NOT_FOUND if a NULL terminator is not found before MaxLength bytes are read
///
{
    INTSTATUS status;
    PCHAR pBuf;
    QWORD chunk;
    DWORD i, j;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    i = 0;
    chunk = 0;

    pBuf = (PCHAR)Buffer;

    // We will basically read 8 bytes at a time
    while (i < MaxLength)
    {
        // Read current chunk
        status = IntVirtMemRead(Gva + i, 8, Cr3, &chunk, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        // Check if we exceed maximum length, and if we have a NULL terminator
        for (j = 0; j < MIN(8u, MaxLength - i); j++)
        {
            pBuf[i++] = (CHAR)chunk;
            chunk >>= 8;

            if (pBuf[i - 1] == 0)
            {
                // Done! We found the NULL terminator
                return INT_STATUS_SUCCESS;
            }
        }
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntMapGpaForTranslation(
    _In_ QWORD Gpa,
    _Outptr_ void **HostPtr
    )
///
/// @brief      Maps a guest physical address used for memory translation in Introcore address space
///
/// #IntMapGpaForTranslation should be used to free any resources allocated for this mapping.
///
/// @param[in]  Gpa     Guest physical address to map
/// @param[out] HostPtr On success, will contain a pointer to the mapped address
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    //
    // The reason for the #ifdef is that on Napoca, the fastmap is more than enough.
    // The speed-up of using the cache is less than 5%, so don't bother.
    //
#ifdef USER_MODE
    if (__likely(gGuest.GpaCache))
    {
        return IntGpaCacheFindAndAdd(gGuest.GpaCache, Gpa, HostPtr);
    }
#endif // USER_MODE

    return IntPhysMemMap(Gpa, PAGE_SIZE, 0, HostPtr);
}


static INTSTATUS
IntUnmapGpaForTranslation(
    _In_ QWORD Gpa,
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    )
///
/// @brief          Unmaps an address that was previously mapped with #IntMapGpaForTranslation
///
/// @param[in]      Gpa     Guest physical address that was mapped
/// @param[in, out] HostPtr Pointer to the allocated memory
///
/// @returns        INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
#ifdef USER_MODE
    if (__likely(gGuest.GpaCache))
    {
        return IntGpaCacheRelease(gGuest.GpaCache, Gpa);
    }
#else
    UNREFERENCED_PARAMETER(Gpa);
#endif // USER_MODE

    return IntPhysMemUnmap(HostPtr);
}


static INTSTATUS
IntTranslateVa32(
    _In_ UINT32 Gva,
    _In_ UINT32 Cr3,
    _Out_ VA_TRANSLATION *Translation
    )
///
/// @brief      Translates a guest virtual address when 32-bit paging is used
///
/// @param[in]  Gva         Guest virtual address to translate
/// @param[in]  Cr3         Cr3 used for the translation
/// @param[out] Translation Translation information
///
/// @retval     INT_STATUS_SUCCESS in case of success. This does not guarantee that Gva is present inside the
///             leaf page table
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed.
///
{
    INTSTATUS status;

    UINT32 pdi = PD32_INDEX(Gva);
    UINT32 pti = PT32_INDEX(Gva);

    UINT32 pde, pte, pf;
    UINT32 *pd, *pt;

    pd = pt = NULL;
    pde = pte = 0;

    Translation->Pointer64 = FALSE;

    //
    // Fetch and handle PD entry.
    //
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS32(Cr3), &pd);
    if (!INT_SUCCESS(status))
    {
        /// ERROR("[ERROR] Failed mapping cr3 0x%016llx (cached: %d): 0x%08x\n", Cr3, pCache != NULL, status);
        goto cleanup_and_exit;
    }

    pde = pd[pdi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS32(Cr3) + 4ull * pdi;
    Translation->MappingsEntries[Translation->MappingsCount] = pde;
    Translation->MappingsCount++;

    if ((pde & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit;
    }

    Translation->IsUser = Translation->IsUser && !!(pde & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pde & PT_RW);

    // Check if this is a 4 MB page.
    if (0 != (pde & PD_PS))
    {
        // This is a 4 MB page, next table is in fact the physical address of the page
        Translation->Flags = pde;
        Translation->PageSize = PAGE_SIZE_4M;

        pf = (pde & 0xFFC00000) | ((pde & 0x003FE000) << 19);
        pf += (Gva & 0x3FFFFF);

        goto using_4m_page;
    }


    // Fetch & handle PT entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS32(pde), &pt);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    pte = pt[pti];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS32(pde) + 4ull * pti;
    Translation->MappingsEntries[Translation->MappingsCount] = pte;
    Translation->MappingsCount++;

    Translation->Flags = pte;
    Translation->PageSize = PAGE_SIZE_4K;

    if ((pte & PD_P) == 0)
    {
        pf = 0;
    }
    else
    {
        Translation->IsUser = Translation->IsUser && !!(pte & PT_US);
        Translation->IsWritable = Translation->IsWritable && !!(pte & PT_RW);

        pf = CLEAN_PHYS_ADDRESS32(pte);
        pf += (Gva & 0xFFF);
    }

using_4m_page:
    Translation->PhysicalAddress = pf;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != pd)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS32(Cr3), &pd);
    }

    if (NULL != pt)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS32(pde), &pt);
    }

    return status;
}


static INTSTATUS
IntTranslateVa32Pae(
    _In_ UINT64 Gva,
    _In_ UINT64 Cr3,
    _Out_ VA_TRANSLATION *Translation
    )
///
/// @brief      Translates a guest virtual address when 32-bit PAE paging is used
///
/// @param[in]  Gva         Guest virtual address to translate
/// @param[in]  Cr3         Cr3 used for the translation
/// @param[out] Translation Translation information
///
/// @retval     INT_STATUS_SUCCESS in case of success. This does not guarantee that Gva is present inside the
///             leaf page table
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed.
///
{
    INTSTATUS status;

    UINT32 pdpi = PDPPAE_INDEX(Gva);
    UINT32 pdi  = PDPAE_INDEX(Gva);
    UINT32 pti  = PTPAE_INDEX(Gva);

    UINT64 pdpe, pde, pte, pf;
    UINT64 *pdp, *pd, *pt;

    pdp = pd = pt = NULL;
    pdpe = pde = pte = 0;

    Translation->Pointer64 = TRUE;

    //
    // Fetch and handle the PDP entry.
    //
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(Cr3), &pdp);
    if (!INT_SUCCESS(status))
    {
        /// ERROR("[ERROR] Failed mapping cr3 0x%016llx (cached: %d): 0x%08x\n", Cr3, pCache != NULL, status);
        goto cleanup_and_exit_pae;
    }

    // CR3 is aligned only to 32 bytes, not 4096 bytes.
    pdp = (PQWORD)(((PBYTE)pdp) + (Cr3 & 0xFE0));

    // We get the PDPE from the PDP, which points to a PD
    pdpe = pdp[pdpi];

    Translation->MappingsTrace[Translation->MappingsCount] = (CLEAN_PHYS_ADDRESS32PAE_ROOT(Cr3)) + 8ull * pdpi;
    Translation->MappingsEntries[Translation->MappingsCount] = pdpe;
    Translation->MappingsCount++;

    pdp = (PQWORD)(((PBYTE)pdp) - (Cr3 & 0xFE0));

    if ((pdpe & PDP_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_pae;
    }

    //
    // Fetch and handle PD entry.
    //
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(pdpe), &pd);
    if (!INT_SUCCESS(status))
    {
        /// ERROR("[ERROR] Failed mapping pd 0x%016llx (cached: %d): 0x%08x\n", pdpe, pCache != NULL, status);
        goto cleanup_and_exit_pae;
    }

    pde = pd[pdi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS32PAE(pdpe) + 8ull * pdi;
    Translation->MappingsEntries[Translation->MappingsCount] = pde;
    Translation->MappingsCount++;

    if ((pde & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_pae;
    }

    Translation->IsUser = Translation->IsUser && !!(pde & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pde & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pde & PT_XD);

    // Check if this is a 2 MB page.
    if (pde & PD_PS)
    {
        // This is a 2 MB page, next table is in fact the physical address of the page
        Translation->Flags = pde;
        Translation->PageSize = PAGE_SIZE_2M;

        pf = CLEAN_PHYS_ADDRESS32PAE(pde) & (~0x1FFFFFULL);
        pf += (Gva & 0x1FFFFF);

        goto using_2m_page_pae;
    }

    //
    // Fetch and handle PT entry.
    //
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(pde), &pt);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_pae;
    }

    pte = pt[pti];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS32PAE(pde) + 8ull * pti;
    Translation->MappingsEntries[Translation->MappingsCount] = pte;
    Translation->MappingsCount++;

    Translation->Flags = pte;
    Translation->PageSize = PAGE_SIZE_4K;

    if ((pte & PT_P) == 0)
    {
        pf = 0;
    }
    else
    {
        Translation->IsUser = Translation->IsUser && !!(pte & PT_US);
        Translation->IsWritable = Translation->IsWritable && !!(pte & PT_RW);
        Translation->IsExecutable = Translation->IsExecutable && !(pte & PT_XD);

        pf = CLEAN_PHYS_ADDRESS32PAE(pte);
        pf += (Gva & 0xFFF);
    }

using_2m_page_pae:
    Translation->PhysicalAddress = pf;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit_pae:
    if (NULL != pdp)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(Cr3), &pdp);
    }

    if (NULL != pd)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(pdpe), &pd);
    }

    if (NULL != pt)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS32PAE(pde), &pt);
    }

    return status;
}


static INTSTATUS
IntTranslateVa64(
    _In_ UINT64 Gva,
    _In_ UINT64 Cr3,
    _Out_ VA_TRANSLATION *Translation
    )
///
/// @brief      Translates a guest virtual address when 4-level paging is used
///
/// @param[in]  Gva         Guest virtual address to translate
/// @param[in]  Cr3         Cr3 used for the translation
/// @param[out] Translation Translation information
///
/// @retval     INT_STATUS_SUCCESS in case of success. This does not guarantee that Gva is present inside the
///             leaf page table
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed.
///
{
    INTSTATUS status;

    UINT32 pml4i = PML4_INDEX(Gva);
    UINT32 pdpi  = PDP_INDEX (Gva);
    UINT32 pdi   = PD_INDEX  (Gva);
    UINT32 pti   = PT_INDEX  (Gva);

    UINT64 pml4e, pdpe, pde, pte, pf;   // entries values
    UINT64 *pml4, *pdp, *pd, *pt;       // mapped pages

    pml4 = pdp = pd = pt = NULL;
    pml4e = pdpe = pde = pte = 0;

    Translation->Pointer64 = TRUE;

    // Fetch and handle the PML4 entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(Cr3), &pml4);
    if (!INT_SUCCESS(status))
    {
        /// ERROR("[ERROR] Failed mapping cr3 0x%016llx (cached: %d): 0x%08x\n", Cr3, pCache != NULL, status);
        goto cleanup_and_exit_4_level;
    }

    pml4e = pml4[pml4i];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(Cr3) + 8ull * pml4i;
    Translation->MappingsEntries[Translation->MappingsCount] = pml4e;
    Translation->MappingsCount++;

    if ((pml4e & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_4_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pml4e & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pml4e & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pml4e & PT_XD);

    // Fetch and handle the PDP entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml4e), &pdp);
    if (!INT_SUCCESS(status))
    {
        /// ERROR("[ERROR] Failed mapping pdp 0x%016llx (cached: %d): 0x%08x\n", pml4e, pCache != NULL, status);
        goto cleanup_and_exit_4_level;
    }

    pdpe = pdp[pdpi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pml4e) + 8ull * pdpi;
    Translation->MappingsEntries[Translation->MappingsCount] = pdpe;
    Translation->MappingsCount++;

    if ((pdpe & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_4_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pdpe & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pdpe & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pdpe & PT_XD);

    // Check if this is a 1 GB page.
    if (pdpe & PDP_PS)
    {
        // This is a 1 GB page, next table is in fact the physical address of the page
        Translation->Flags = pdpe;
        Translation->PageSize = PAGE_SIZE_1G;

        pf = CLEAN_PHYS_ADDRESS64(pdpe) & (~0x3FFFFFFFULL);
        pf += (Gva & 0x3FFFFFFF);

        goto using_1g_page_4_level;
    }

    // Fetch and handle the PD entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pdpe), &pd);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_4_level;
    }

    pde = pd[pdi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pdpe) + 8ull * pdi;
    Translation->MappingsEntries[Translation->MappingsCount] = pde;
    Translation->MappingsCount++;

    if ((pde & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_4_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pde & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pde & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pde & PT_XD);

    // Check if this is a 2 MB page.
    if (pde & PD_PS)
    {
        // This is a 2 MB page, next table is in fact the physical address of the page
        Translation->Flags = pde;
        Translation->PageSize = PAGE_SIZE_2M;

        pf = CLEAN_PHYS_ADDRESS64(pde) & (~0x1FFFFFULL);
        pf += (Gva & 0x1FFFFF);

        goto using_2m_page_4_level;
    }

    // Fetch and handle the PT entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pde), &pt);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_4_level;
    }

    pte = pt[pti];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pde) + 8ull * pti;
    Translation->MappingsEntries[Translation->MappingsCount] = pte;
    Translation->MappingsCount++;

    Translation->Flags = pte;
    Translation->PageSize = PAGE_SIZE_4K;

    if ((pte & PD_P) == 0)
    {
        // If the last page is not present, we will return success; The caller must check if the page is
        // present or not.
        pf = 0;
    }
    else
    {
        Translation->IsUser = Translation->IsUser && !!(pte & PT_US);
        Translation->IsWritable = Translation->IsWritable && !!(pte & PT_RW);
        Translation->IsExecutable = Translation->IsExecutable && !(pte & PT_XD);

        pf = CLEAN_PHYS_ADDRESS64(pte);
        pf += (Gva & 0xFFF);
    }

using_1g_page_4_level:
using_2m_page_4_level:
    Translation->PhysicalAddress = pf;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit_4_level:
    if (NULL != pml4)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(Cr3), &pml4);
    }

    if (NULL != pdp)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml4e), &pdp);
    }

    if (NULL != pd)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pdpe), &pd);
    }

    if (NULL != pt)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pde), &pt);
    }

    return status;
}


static INTSTATUS
IntTranslateVa64La57(
    _In_ UINT64 Gva,
    _In_ UINT64 Cr3,
    _Out_ VA_TRANSLATION *Translation
    )
///
/// @brief      Translates a guest virtual address when 5-level paging is used
///
/// @param[in]  Gva         Guest virtual address to translate
/// @param[in]  Cr3         Cr3 used for the translation
/// @param[out] Translation Translation information
///
/// @retval     INT_STATUS_SUCCESS in case of success. This does not guarantee that Gva is present inside the
///             leaf page table
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed.
///
{
    INTSTATUS status;

    UINT32 pml5i = PML5_INDEX(Gva);
    UINT32 pml4i = PML4_INDEX(Gva);
    UINT32 pdpi = PDP_INDEX(Gva);
    UINT32 pdi = PD_INDEX(Gva);
    UINT32 pti = PT_INDEX(Gva);

    UINT64 pml5e, pml4e, pdpe, pde, pte, pf;    // entries values
    UINT64 *pml5, *pml4, *pdp, *pd, *pt;        // mapped pages

    pml5 = pml4 = pdp = pd = pt = NULL;
    pml5e = pml4e = pdpe = pde = pte = 0;

    Translation->Pointer64 = TRUE;

    // Fetch and handle PML5 entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(Cr3), &pml5);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_5_level;
    }

    pml5e = pml5[pml5i];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(Cr3) + 8ull * pml5i;
    Translation->MappingsEntries[Translation->MappingsCount] = pml5e;
    Translation->MappingsCount++;

    if ((pml5e & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_5_level;
    }

    // Fetch and handle PML4 entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml5e), &pml4);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_5_level;
    }

    pml4e = pml4[pml4i];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(Cr3) + 8ull * pml4i;
    Translation->MappingsEntries[Translation->MappingsCount] = pml4e;
    Translation->MappingsCount++;

    if ((pml4e & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_5_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pml4e & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pml4e & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pml4e & PT_XD);

    // Fetch and handle the PDP entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml4e), &pdp);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_5_level;
    }

    pdpe = pdp[pdpi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pml4e) + 8ull * pdpi;
    Translation->MappingsEntries[Translation->MappingsCount] = pdpe;
    Translation->MappingsCount++;

    if ((pdpe & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_5_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pdpe & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pdpe & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pdpe & PT_XD);

    // Check if this is a 1 GB page.
    if (pdpe & PDP_PS)
    {
        // This is a 1 GB page, next table is in fact the physical address of the page
        Translation->Flags = pdpe;
        Translation->PageSize = PAGE_SIZE_1G;

        pf = CLEAN_PHYS_ADDRESS64(pdpe) & (~0x3FFFFFFFULL);
        pf += (Gva & 0x3FFFFFFF);

        goto using_1g_page_5_level;
    }

    // Fetch and handle the PD entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pdpe), &pd);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_5_level;
    }

    pde = pd[pdi];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pdpe) + 8ull * pdi;
    Translation->MappingsEntries[Translation->MappingsCount] = pde;
    Translation->MappingsCount++;

    if ((pde & PD_P) == 0)
    {
        status = INT_STATUS_NO_MAPPING_STRUCTURES;
        goto cleanup_and_exit_5_level;
    }

    Translation->IsUser = Translation->IsUser && !!(pde & PT_US);
    Translation->IsWritable = Translation->IsWritable && !!(pde & PT_RW);
    Translation->IsExecutable = Translation->IsExecutable && !(pde & PT_XD);

    // Check if this is a 2 MB page.
    if (pde & PD_PS)
    {
        // This is a 2 MB page, next table is in fact the physical address of the page
        Translation->Flags = pde;
        Translation->PageSize = PAGE_SIZE_2M;

        pf = CLEAN_PHYS_ADDRESS64(pde) & (~0x1FFFFFULL);
        pf += (Gva & 0x1FFFFF);

        goto using_2m_page_5_level;
    }

    // Fetch and handle the PT entry.
    status = IntMapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pde), &pt);
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit_5_level;
    }

    pte = pt[pti];

    Translation->MappingsTrace[Translation->MappingsCount] = CLEAN_PHYS_ADDRESS64(pde) + 8ull * pti;
    Translation->MappingsEntries[Translation->MappingsCount] = pte;
    Translation->MappingsCount++;

    Translation->Flags = pte;
    Translation->PageSize = PAGE_SIZE_4K;

    if ((pte & PD_P) == 0)
    {
        // If the last page is not present, we will return success; The caller must check if the page is
        // present or not.
        pf = 0;
    }
    else
    {
        Translation->IsUser = Translation->IsUser && !!(pte & PT_US);
        Translation->IsWritable = Translation->IsWritable && !!(pte & PT_RW);
        Translation->IsExecutable = Translation->IsExecutable && !(pte & PT_XD);

        pf = CLEAN_PHYS_ADDRESS64(pte);
        pf += (Gva & 0xFFF);
    }

using_1g_page_5_level:
using_2m_page_5_level:
    Translation->PhysicalAddress = pf;

    status = INT_STATUS_SUCCESS;

cleanup_and_exit_5_level:
    if (NULL != pml5)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(Cr3), &pml5);
    }

    if (NULL != pml4)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml5e), &pml4);
    }

    if (NULL != pdp)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pml4e), &pdp);
    }

    if (NULL != pd)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pdpe), &pd);
    }

    if (NULL != pt)
    {
        IntUnmapGpaForTranslation(CLEAN_PHYS_ADDRESS64(pde), &pt);
    }

    return status;
}


INTSTATUS
IntTranslateVirtualAddressEx(
    _In_ QWORD Gva,
    _In_ QWORD Cr3,
    _In_ DWORD Flags,
    _Out_ VA_TRANSLATION *Translation
    )
///
/// @brief      Translates a guest virtual address to a guest physical address
///
/// If error is returned, an incomplete trace is stored in the translation, and the translated physical address
/// is not valid. If success is returned, a complete trace is stored inside the translation, however, it may still
/// be possible that the page frame is not present. The caller must check the translation flags upon successful exit.
///
/// @param[in]  Gva         Guest virtual address to be translated
/// @param[in]  Cr3         The Cr3 used for the translation
/// @param[in]  Flags       Flags controlling the translation. May be 0 or a combination of @ref group_translation_flags
///                         values. If it does not specify a paging mode, the function will deduce it by using the
///                         memory information inside #gGuest. If #TRFLG_CACHING_ATTR is set, will also obtain the
///                         caching attributes using the guest's IA32_PAT MSR.
/// @param[out] Translation Translation information
///
/// @retval     INT_STATUS_SUCCESS in case of success. This does not guarantee that Gva is present inside the
///             leaf page table
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed.
///
{
    INTSTATUS status;
    BYTE pagingMode;

    if (Translation == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    memzero(Translation, sizeof(*Translation));

    if (__unlikely(0 != (Flags & TRFLG_MODE_MASK)))
    {
        switch (Flags & TRFLG_MODE_MASK)
        {
        case TRFLG_NORMAL_MODE:
            pagingMode = PAGING_NORMAL_MODE;
            break;
        case TRFLG_PAE_MODE:
            pagingMode = PAGING_PAE_MODE;
            break;
        case TRFLG_4_LEVEL_MODE:
            pagingMode = PAGING_4_LEVEL_MODE;
            break;
        case TRFLG_5_LEVEL_MODE:
            pagingMode = PAGING_5_LEVEL_MODE;
            break;
        default:
            return INT_STATUS_INVALID_PARAMETER_2;
        }
    }
    else
    {
        if (__unlikely(gVcpu && !(gVcpu->Regs.Cr0 & CR0_PG)))
        {
            pagingMode = PAGING_NONE;
        }
        else
        {
            pagingMode = gGuest.Mm.Mode;
        }
    }

    Translation->VirtualAddress = Gva;
    Translation->Cr3 = Cr3;
    Translation->IsUser = Translation->IsWritable = Translation->IsExecutable = TRUE;
    Translation->PagingMode = pagingMode;

    if (pagingMode == PAGING_5_LEVEL_MODE)
    {
        status = IntTranslateVa64La57(Gva, Cr3, Translation);
    }
    else if (pagingMode == PAGING_4_LEVEL_MODE)
    {
        status = IntTranslateVa64(Gva, Cr3, Translation);
    }
    else if (pagingMode == PAGING_PAE_MODE)
    {
        status = IntTranslateVa32Pae(Gva, Cr3, Translation);
    }
    else if (pagingMode == PAGING_NORMAL_MODE)
    {
        status = IntTranslateVa32((UINT32)Gva, (UINT32)Cr3, Translation);
    }
    else
    {
        // The CPU is probably in real mode/without paging for the moment.
        Translation->PhysicalAddress = Gva;

        status = INT_STATUS_SUCCESS;
    }

    // Validate the caching attributes, if required.
    if (__unlikely((INT_STATUS_SUCCESS == status) && (0 != (Flags & TRFLG_CACHING_ATTR))))
    {
        // For now, we assume PAT is ALWAYS present & used.

        // Get the per-page caching attributes of this VA page.
        BYTE patIndex;
        IG_QUERY_MSR msr = {0};

        patIndex = 0;

        // Compute the PAT index.
        patIndex |= (Translation->Flags & PT_PAT) >> 5;
        patIndex |= (Translation->Flags & PT_PCD) >> 3;
        patIndex |= (Translation->Flags & PT_PWT) >> 3;

        // Read the PAT MSR.
        msr.MsrId = IG_IA32_PAT;

        status = IntQueryGuestInfo(IG_QUERY_INFO_CLASS_READ_MSR,
                                   (void *)(size_t)IG_CURRENT_VCPU,
                                   &msr,
                                   sizeof(IG_QUERY_MSR));
        if (!INT_SUCCESS(status))
        {
            Translation->CachingAttribute = IG_MEM_UNKNOWN;
        }
        else
        {
            Translation->CachingAttribute = (msr.Value >> (patIndex * 8)) & 0x7;
        }
    }

    return status;
}


INTSTATUS
IntTranslateVirtualAddress(
    _In_ QWORD Gva,
    _In_opt_ QWORD Cr3,
    _Out_ QWORD *PhysicalAddress
    )
///
/// @brief      Translates a guest virtual address to a guest physical address
///
/// This is a wrapper over #IntTranslateVirtualAddressEx, but instead of returning the entire translation information,
/// it will return only the physical address to which Gva maps. This function will fail if Gva is not present.
///
/// @param[in]  Gva             Guest virtual address to be translated
/// @param[in]  Cr3             The Cr3 to be used for the translation. If 0, the currently loaded kernel Cr3 will be
///                             used. If the current process has different page directory table base registers for user
///                             mode and kernel mode due to KPTI, the kernel Cr3 will be used even if the user mode
///                             Cr3 is currently loaded
/// @param[out] PhysicalAddress On success, the physical address to which Gva maps.
///
/// @retval     INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_3 if PhysicalAddress is NULL
/// @retval     #INT_STATUS_PAGE_NOT_PRESENT if Gva is not present or if the paging mode is #PAGING_NONE
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed
///
{
    INTSTATUS status;
    VA_TRANSLATION translation = { 0 };

    if (NULL == PhysicalAddress)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (0 == Cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &Cr3);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
            return status;
        }
    }

    status = IntTranslateVirtualAddressEx(Gva, Cr3, TRFLG_NONE, &translation);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 == (translation.Flags & PT_P) && PAGING_NONE != translation.PagingMode)
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    *PhysicalAddress = translation.PhysicalAddress;

    return INT_STATUS_SUCCESS;
}


__forceinline static INTSTATUS
IntVirtMemMapMultiPage(
    _In_ QWORD GuestVirtualAddress,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    )
///
/// @brief      Maps a guest kernel virtual memory range inside Introcore virtual address space regardless of the
///             number of pages it spans across
///
/// @param[in]  GuestVirtualAddress     The start of the guest virtual address range
/// @param[in]  Length                  The size of the memory range
/// @param[in]  Cr3                     The Cr3 used to translate GuestVirtualAddress. If 0, the current kernel Cr3
///                                     will be used
/// @param[out] HostPtr                 On success, will contain a pointer to the mapped memory
///
/// @retval     INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory is available
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE is an inconsistency was detected
///
{
    INTSTATUS status;
    void *pAlloc, *pAlignedAlloc;
    DWORD readSize = 0;
    MULTI_PAGE_MAP *pPage;

    pAlloc = HpAllocWithTag((size_t)Length + PAGE_SIZE, IC_TAG_MLMP);
    if (NULL == pAlloc)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pAlignedAlloc = (void *)ALIGN_UP((SIZE_T)pAlloc, PAGE_SIZE_4K);

    // This will trigger a recursive call, but it's safe since form IntVirtMemRead it will
    // only map one page per call, and will not re-enter this function.
    status = IntVirtMemRead(GuestVirtualAddress, Length, Cr3, pAlignedAlloc, &readSize);
    if (!INT_SUCCESS(status))
    {
        HpFreeAndNullWithTag(&pAlloc, IC_TAG_MLMP);

        return status;
    }
    else if (readSize != Length)
    {
        // Something went wrong without an error. IntKernVirtMemRead always returns an error when
        // a map fails, so this isn't the case.
        HpFreeAndNullWithTag(&pAlloc, IC_TAG_MLMP);

        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    pPage = HpAllocWithTag(sizeof(*pPage), IC_TAG_MLMP);
    if (NULL == pPage)
    {
        HpFreeAndNullWithTag(&pAlloc, IC_TAG_MLMP);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pPage->Gva = GuestVirtualAddress;
    pPage->Length = Length;
    pPage->HostPtr = pAlignedAlloc;
    pPage->OrigAlloc = pAlloc;

    InsertTailList(&gMultiPageMaps, &pPage->Link);

    *HostPtr = pAlignedAlloc;

    return INT_STATUS_SUCCESS;
}


__must_check
INTSTATUS
IntVirtMemMap(
    _In_ QWORD Gva,
    _In_ DWORD Length,
    _In_opt_ QWORD Cr3,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    )
///
/// @brief      Maps a guest virtual memory range inside Introcore virtual address space
///
/// If the virtual range spans across multiple pages, #IntVirtMemMapMultiPage will be used
///
/// @param[in]  Gva     Guest virtual address to be mapped
/// @param[in]  Length  The length of the virtual range
/// @param[in]  Cr3     Cr3 used to translate Gva. If 0, the current kernel Cr3 will be used
/// @param[in]  Flags   Ignored. TODO: remove
/// @param[out] HostPtr On success, will contain a pointer to the mapped memory
///
/// @retval     INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if Length is 0
/// @retval     #INT_STATUS_PAGE_NOT_PRESENT if Gva is not present or if the paging mode is #PAGING_NONE
/// @retval     #INT_STATUS_NO_MAPPING_STRUCTURES if at any given point, the translation fails because a mapping
///             structure can't be accessed
///
{
    INTSTATUS status;
    VA_TRANSLATION translation;
    DWORD flags;

    UNREFERENCED_PARAMETER(Flags);

    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (0 == Cr3)
    {
        status = IntCr3Read(IG_CURRENT_VCPU, &Cr3);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
    }

    if (__unlikely(PAGE_COUNT_4K(Gva, Length) > 1))
    {
        return IntVirtMemMapMultiPage(Gva, Length, Cr3, HostPtr);
    }

    status = IntTranslateVirtualAddressEx(Gva, Cr3, TRFLG_NONE, &translation);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (0 == (translation.Flags & PT_P) && PAGING_NONE != translation.PagingMode)
    {
        return INT_STATUS_PAGE_NOT_PRESENT;
    }

    flags = (translation.PageSize != PAGE_SIZE_4K) ? IG_PHYSMAP_NO_CACHE : 0;

    return IntPhysMemMap(translation.PhysicalAddress, Length, flags, HostPtr);
}


static BOOLEAN
IntVirtMemUnmapMultiPage(
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    )
///
/// @brief          Unamps a memory range previously mapped with #IntVirtMemMapMultiPage
///
/// @param[in, out] HostPtr     Pointer to the mapped region. On success, it will point to NULL
///
/// @returns        True if HostPtr matched any known multi map ranges; False if it did not
///
{
    list_for_each(gMultiPageMaps, MULTI_PAGE_MAP, pPage)
    {
        if (__unlikely(pPage->HostPtr == *HostPtr))
        {
            HpFreeAndNullWithTag(&pPage->OrigAlloc, IC_TAG_MLMP);

            RemoveEntryList(&pPage->Link);

            HpFreeAndNullWithTag(&pPage, IC_TAG_MLMP);

            *HostPtr = NULL;

            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntVirtMemUnmap(
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    )
///
/// @brief      Unmaps a memory range previously mapped with #IntVirtMemMap
///
/// @param[in]  HostPtr     Points to the memory area allocated when the map was done. After this function returns,
///                         it will point to NULL.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;

    if (__unlikely(IntVirtMemUnmapMultiPage(HostPtr)))
    {
        return INT_STATUS_SUCCESS;
    }

    status = IntPhysMemUnmap(HostPtr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPhysMemUnmap failed for (%p %p): 0x%08x\n", HostPtr, *HostPtr, status);
    }

    return status;
}


INTSTATUS
IntInjectExceptionInGuest(
    _In_ BYTE Vector,
    _In_ QWORD Cr2,
    _In_ DWORD ErrorCode,
    _In_ DWORD CpuNumber
    )
///
/// @brief      Injects an exception inside the guest
///
/// Note that even if this function exits with success, there is still no guarantee that the exception was injected
/// inside the guest, as the hypervisor may have other exceptions to inject. In order to be sure that the exception
/// we scheduled was injected, the #IntHandleEventInjection callback registered with
/// #GLUE_IFACE.RegisterEventInjectionHandler is used.
///
/// @param[in]  Vector      Vector to be injected
/// @param[in]  Cr2         Cr2 value. Ignored if Vector is not 14 (page fault)
/// @param[in]  ErrorCode   The error code of the exception. Ignored for exceptions that do not have an error code
/// @param[in]  CpuNumber   The CPU on which the exception should be injected. #IG_CURRENT_VCPU is not a valid value
///
/// @retval     INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_INVALID_PARAMETER_4 is the CPU number is not valid
/// @retval     #INT_STATUS_ALREADY_INITIALIZED if an exception is already scheduled on the specified CPU
///
{
    INTSTATUS status;

    if (CpuNumber >= gGuest.CpuCount)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (gGuest.VcpuArray[CpuNumber].Exception.Valid)
    {
        ERROR("[ERROR] An exception injection is already pending on CPU %d: vector %d, CR2 0x%016llx, "
              "error code 0x%08x",
              CpuNumber, gGuest.VcpuArray[CpuNumber].Exception.Vector, gGuest.VcpuArray[CpuNumber].Exception.Cr2,
              gGuest.VcpuArray[CpuNumber].Exception.ErrorCode);
        return INT_STATUS_ALREADY_INITIALIZED;
    }

    status = IntInjectTrap(CpuNumber, Vector, ErrorCode, Cr2);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    gGuest.VcpuArray[CpuNumber].Exception.Valid = TRUE;
    gGuest.VcpuArray[CpuNumber].Exception.Vector = Vector;
    gGuest.VcpuArray[CpuNumber].Exception.Cr2 = Cr2;
    gGuest.VcpuArray[CpuNumber].Exception.ErrorCode = ErrorCode;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntPauseVcpus(
    void
    )
///
/// @brief      Pauses all the guest VCPUs
///
/// If #gInsideDebugger is True, the function does nothing. VCPUs should be resumed using the #IntResumeVcpus function.
/// It is safe to call this multiple times in a row, but each call must match a #IntResumeVcpus call.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
/// @remarks    A failure to pause the VCPUs is considered a fatal error and introcore will try to trap to a debugger
///
/// @post       All the virtual processors used by the guest are no longer scheduled and the guest is paused.
///
{
    INTSTATUS status;

    if (gInsideDebugger)
    {
        return INT_STATUS_SUCCESS;
    }

    status = GluePauseVcpus();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] GluePauseVcpus failed: 0x%08x\n", status);
        IntDbgEnterDebugger();
    }

    return status;
}


INTSTATUS
IntResumeVcpus(
    void
    )
///
/// @brief      Resumes the VCPUs previously paused with #IntPauseVcpus
///
/// If #gInsideDebugger is True, the function does nothing.
/// It is an error to call this more times than #IntPauseVcpus was called.
///
/// @returns    INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
/// @remarks    A failure to resume the VCPUs is considered a fatal error and introcore will try to trap to a debugger
///
{
    INTSTATUS status;

    if (gInsideDebugger)
    {
        return INT_STATUS_SUCCESS;
    }

    status = GlueResumeVcpus();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] GlueResumeVcpus failed: 0x%08x\n", status);
        IntDbgEnterDebugger();
    }

    return status;
}


void
IntEnterDebugger2(
    _In_ PCHAR File,
    _In_ DWORD Line
    )
///
/// @brief  Traps to a debugger
///
/// This function should not be used directly, the #IntEnterDebugger macro should be used instead.
///
/// @param[in]  File    NULL-terminated string containing the name of the file from which this function was called
/// @param[in]  Line    The line number from which this function was called
///
{
    if (NULL != File)
    {
        LOG("[DEBUGGER] IntEnterDebugger called from %s:%d\n", File, Line);
    }

    GlueEnterDebugger();
}


void
IntDbgEnterDebugger2(
    _In_ PCHAR File,
    _In_ DWORD Line
    )
///
/// @brief  Traps to a debugger and dumps the Introcore state
///
/// This function should not be used directly, the #IntDbgEnterDebugger macro should be used instead.
///
/// @param[in]  File    NULL-terminated string containing the name of the file from which this function was called
/// @param[in]  Line    The line number from which this function was called
///
{
    const char *commands[] =
    {
        "!processes",                               // Dump the processes
        "!stvad",
        "!modules_intro",                           // Dump the introspection drivers
        "!modules_guest",                           // Dump the guest modules
        "!hooks_gpa",                               // Dump the GPA hooks
        "!hooks_gva",                               // Dump the GVA hooks
        "!pts_dump",                                // Dump the PTS tree
        "!pfnlocks",                                // Dump the PFN locks
        "!transactions",                            // Dump the swap-in transactions
        "!stats",                                   // Dump the performance stats.
        "!icache",                                  // Dump the instruction cache content.
    };

    LOG("[CRITICAL] IntDbgEnterDebugger called from %s:%d\n", File, Line);
    LOG("Bug check generated! Dumps follow:\n");

    for (DWORD i = 0; i < ARRAYSIZE(commands); i++)
    {
        IntDbgProcessCommand(1, &commands[i]);
    }

    LOG("Bug check dump complete!\n");

    GlueEnterDebugger();
}


BOOLEAN
IntMatchPatternUtf8(
    _In_z_ const CHAR *Pattern,
    _In_z_ const CHAR *String,
    _In_ DWORD Flags
    )
///
/// @brief      Matches a pattern using glob match
///
/// @param[in]  Pattern     A NULL-terminated string containing the pattern
/// @param[in]  String      A NULL-terminated string against which the pattern is matched
/// @param[in]  Flags       Flags containing the match. Can be 0, in which case a standard glob match is done, or
///                         #INTRO_MATCH_TRUNCATED, in which case the match will be done up to the first "*" found
///                         inside Pattern
///
/// @retval     True if a match is found
/// @retval     False if a match is not found
///
{
    CHAR pat[255] = {0};

    if (Flags & INTRO_MATCH_TRUNCATED)
    {
        char *wild = strchr(Pattern, '*');

        if (wild && ((size_t)(wild - Pattern + 1) < sizeof(pat) - 1))
        {
            memcpy(pat, Pattern, (size_t)(wild - Pattern + 1));

            Pattern = pat;
        }
    }

    return glob_match_utf8(Pattern, String, TRUE, FALSE);
}


BOOLEAN
IntMatchPatternUtf16(
    _In_z_ const WCHAR *Pattern,
    _In_z_ const WCHAR *String,
    _In_ DWORD Flags
    )
///
/// @brief      Matches a pattern using glob match
///
/// This function simply converts the input parameters to UTF-8 and uses #IntMatchPatternUtf8.
///
/// @param[in]  Pattern     A NULL-terminated string containing the pattern
/// @param[in]  String      A NULL-terminated string against which the pattern is matched
/// @param[in]  Flags       Flags containing the match. Can be 0, in which case a standard glob match is done, or
///                         #INTRO_MATCH_TRUNCATED, in which case the match will be done up to the first "*" found
///                         inside Pattern
///
/// @retval     True if a match is found
/// @retval     False if a match is not found
///
{
    CHAR pat[255];
    CHAR str[255];

    utf16toutf8(pat, Pattern, sizeof(pat));
    utf16toutf8(str, String, sizeof(str));

    return IntMatchPatternUtf8(pat, str, Flags);
}


INTSTATUS
IntGuestUninitOnBugcheck(
    _In_ void const  *Detour
    )
///
/// @brief      Prepares Introcore unload in case of a guest crash in order to clean up the code and data injected
///             inside the guest
/// @ingroup    group_detours
///
/// If the #INTRO_OPT_BUGCHECK_CLEANUP activation flag is not set, this function does nothing.
/// Will set BugCheckInProgress inside #gGuest to True.
///
/// @param[in]  Detour  Ignored
///
/// @retval     #INT_STATUS_NOT_NEEDED_HINT if the #INTRO_OPT_BUGCHECK_CLEANUP option is not active
/// @retval     #INT_STATUS_REMOVE_DETOUR_AND_SET_RIP if cleanup should be done. This will make the detour mechanism
///             remove the hook that invoked this handler in order to clean up the hook itself.
///
{
    const char *func;

    UNREFERENCED_PARAMETER(Detour);

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_BUGCHECK_CLEANUP))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    func = gGuest.OSType == introGuestWindows ? "KiDisplayBlueScreen" : "panic";

    LOG("[INFO] Guest reached %s handler. Will attempt to uninit!\n", func);

    TRACE("[INFO] Will dump RIPs for all VCPUs\n");
    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        TRACE("[INFO][CPU %d] RIP @ 0x%016llx\n", i, gGuest.VcpuArray[i].Regs.Rip);
    }

    gGuest.BugCheckInProgress = TRUE;

    // Need this because, if we uninit on the same exit as this one, we'll end up calling
    // IntDetUninit -> we'll remove the jump back for the function and end up making the
    // current vcpu execute garbage code.
    return INT_STATUS_REMOVE_DETOUR_AND_SET_RIP;
}


BOOLEAN
IntPolicyProcIsBeta(
    _In_opt_ const void *Process,
    _In_ QWORD Flag
    )
///
/// @brief      Checks if a process protection policy is in log-only mode
///
/// @param[in]  Process     The process for which the check is done. For Windows guests this is a pointer to a
///                         #WIN_PROCESS_OBJECT structure; for Linux guests this is a pointer to a #LIX_TASK_OBJECT
///                         structure
/// @param[in]  Flag        Protection option to be checked. This must be one of the @ref group_process_options values
///
/// @returns    True if the option is in log-only mode; False if it is not
///
{
    if (Process == NULL)
    {
        return FALSE;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinProcPolicyIsBeta(Process, Flag);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixProcPolicyIsBeta(Process, Flag);
    }

    return FALSE;
}


BOOLEAN
IntPolicyCoreIsOptionBeta(
    _In_ QWORD Flag
    )
///
/// @brief      Checks if one of the kernel protection options is in log-only mode
///
/// If the option is one of the #POLICY_KM_BETA_FLAGS options and the #INTRO_OPT_KM_BETA_DETECTIONS option was also
/// used, the function will always return True. Otherwise the beta options from CAMI are checked.
///
/// @param[in]  Flag    The option to check. Must be one of the @ref group_options values.
///
/// @returns    True if the option is in log-only mode; False if it is not
///
{
    if ((Flag & POLICY_KM_BETA_FLAGS) && gGuest.KernelBetaDetections)
    {
        return TRUE;
    }

    return (gGuest.CoreOptions.Beta & Flag) != 0;
}


BOOLEAN
IntPolicyProcIsFeedback(
    _In_opt_ const void *Process,
    _In_ QWORD Flag
    )
///
/// @brief      Checks if a process protection policy is in feedback-only mode
///
/// @param[in]  Process     The process for which the check is done. For Windows guests this is a pointer to a
///                         #WIN_PROCESS_OBJECT structure; for Linux guests this is a pointer to a #LIX_TASK_OBJECT
///                         structure
/// @param[in]  Flag        Protection option to be checked. This must be one of the @ref group_process_options values
///
/// @returns    True if the option is in feedback-only mode; False if it is not
///
{
    if (Process == NULL)
    {
        return FALSE;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinProcPolicyIsFeedback(Process, Flag);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixProcPolicyIsFeedback(Process, Flag);
    }

    return FALSE;
}


QWORD
IntPolicyGetProcProt(
    _In_opt_ const void *Process
    )
///
/// @brief      Gets the protection policy for a process
///
/// @param[in]  Process     Process for which the protection policy is returned. For Windows guests this is a pointer
///                         to a #WIN_PROCESS_OBJECT structure; for Linux guests this is a pointer to a
///                         #LIX_TASK_OBJECT structure
///
/// @returns    The process protection policy. This is a combination of @ref group_process_options values
///
{
    if (NULL == Process)
    {
        return 0;
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return IntWinProcGetProtOption(Process);
    }
    else if (gGuest.OSType == introGuestLinux)
    {
        return IntLixProcGetProtOption(Process);
    }

    return 0;
}


BOOLEAN
IntPolicyCoreTakeAction(
    _In_ QWORD Flag,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief          Returns the action that should be taken for a core introspection option
///
/// @param[in]      Flag    Protection option for which the policy is returned. Must be one of the @ref group_options
///                         values.
/// @param[in, out] Action  Action to be taken
/// @param[in, out] Reason  The reason for which Action is taken
///
/// @returns        True if an alert should be generated
///
{
    if (gGuest.CoreOptions.Feedback & Flag)
    {
        *Action = introGuestAllowed;
        *Reason = introReasonAllowedFeedback;

        return TRUE;
    }

    if (*Action == introGuestNotAllowed && (IntPolicyCoreIsOptionBeta(Flag)))
    {
        //
        // Don't change the action here, since in the alert we must know the original action & reason. The
        // only thing we do, is return a TRUE so the alert gets sent and the ALERT_FLAG_BETA will be set
        // inside it.
        //
        return TRUE;
    }

    return *Action == introGuestNotAllowed || *Reason == introReasonAllowedFeedback;
}


BOOLEAN
IntPolicyProcTakeAction(
    _In_ QWORD Flag,
    _In_ void const *Process,
    _Inout_ INTRO_ACTION *Action,
    _Inout_ INTRO_ACTION_REASON *Reason
    )
///
/// @brief          Returns the action that should be taken for a process protection option
///
/// @param[in]      Flag    Protection option for which the policy is returned. Must be one of the
///                         @ref group_process_options values.
/// @param[in]      Process Process for which the protection policy is checked. For Windows guests this is a pointer
///                         to a #WIN_PROCESS_OBJECT structure; for Linux guests this is a pointer to a
///                         #LIX_TASK_OBJECT structure
/// @param[in, out] Action  Action to be taken
/// @param[in, out] Reason  The reason for which Action is taken
///
/// @returns        True if an alert should be generated
///
{
    if ((gGuest.CoreOptions.Feedback & IntPolicyGetProcProt(Process)) || IntPolicyProcIsFeedback(Process, Flag))
    {
        *Action = introGuestAllowed;
        *Reason = introReasonAllowedFeedback;

        return TRUE;
    }

    if (*Action == introGuestNotAllowed && (IntPolicyProcIsBeta(Process, Flag)))
    {
        // Don't change the action here, since in the alert we must know the original action & reason. The
        // only thing we do, is return a TRUE so the alert gets sent and the ALERT_FLAG_BETA will be set
        // inside it.
        return TRUE;
    }

    return *Action == introGuestNotAllowed || *Reason == introReasonAllowedFeedback;
}


BOOLEAN
IntPolicyProcForceBetaIfNeeded(
    _In_ QWORD Flag,
    _In_ void *Process,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief          Checks if a forced action should be taken even if the process log-only mode is active
///
/// @param[in]      Flag    Protection option for which the check is done. Must be one of the
///                         @ref group_process_options values.
/// @param[in]      Process Process for which the check is done. For Windows guests this is a pointer to a
///                         #WIN_PROCESS_OBJECT structure; for Linux guests this is a pointer to a #LIX_TASK_OBJECT
///                         structure
/// @param[in, out] Action  Action to be taken
///
/// @returns        True if the action should be taken even if the log-only option is active
///
{
    if (*Action == introGuestNotAllowed && IntPolicyProcIsBeta(Process, Flag))
    {
        *Action = introGuestAllowed;

        return TRUE;
    }

    return FALSE;
}


BOOLEAN
IntPolicyCoreForceBetaIfNeeded(
    _In_ QWORD Flag,
    _Inout_ INTRO_ACTION *Action
    )
///
/// @brief          Checks if a forced action should be taken even if the log-only mode is active
///
/// @param[in]      Flag    Protection option for which the check is done. Must be one of the
///                         @ref group_options values.
/// @param[in, out] Action  Action to be taken
///
/// @returns        True if the action should be taken even if the log-only option is active
///
{
    if (*Action == introGuestNotAllowed && (IntPolicyCoreIsOptionBeta(Flag)))
    {
        *Action = introGuestAllowed;

        return TRUE;
    }

    return FALSE;
}


BOOLEAN
IntPolicyIsCoreOptionFeedback(
    _In_ QWORD Flag
    )
///
/// @brief      Checks if a core protection option is in feedback-only mode
///
/// @param[in]  Flag    Protection option for which the check is done. Must be one of the @ref group_options values.
///
/// @returns    True if the option is in feedback-only mode
///
{
    return (gGuest.CoreOptions.Feedback & Flag) != 0;
}


char *
utf16_for_log(
    _In_z_ const WCHAR *WString
    )
///
/// @brief      Converts a UTF-16 to a UTF-8 string to be used inside logging macros
///
/// This function should be called only from one of the log macros (#TRACE, #INFO. #WARNING, #LOG, #ERROR, #CRITICAL).
/// Note that each string is limited to a size of 1KB and calling this function more than 8 times in a row (in the
/// same logging macro) is an error. The log macros will reset the global state used for conversion.
/// This is needed because not all logging implementations can handle wide char strings.
///
/// @param[in]   WString     NULL-terminated string to be converted
///
/// @returns    A pointer to a NULL-terminated string containing the converted WString. This is returned from a static
///             array.
///
{
    static char gLogBuffer[8][ONE_KILOBYTE];
    char *c;

    if (__unlikely(gCurLogBuffer >= ARRAYSIZE(gLogBuffer)))
    {
        ERROR("[ERROR] gCurLogBuffer = %d/%ld\n", gCurLogBuffer, ARRAYSIZE(gLogBuffer));
        return "";
    }

    c = utf16toutf8(gLogBuffer[gCurLogBuffer], WString, sizeof(gLogBuffer[0]));

    gCurLogBuffer++;

    return c;
}


INTSTATUS
IntReadString(
    _In_ QWORD StrGva,
    _In_ DWORD MinimumLength,
    _In_ BOOLEAN AnsiOnly,
    _Inout_ char **String,
    _Out_opt_ DWORD *StringLength
    )
///
/// @brief      Reads a string from the guest kernel memory
///
/// @param[in]      StrGva          Guest virtual address from which to read the string
/// @param[in]      MinimumLength   The minimum length the string should have
/// @param[in]      AnsiOnly        If the string should be an ANSI string
/// @param[in, out] String          On success, will point to the string. This will be allocated with
///                                 #HpAllocWithTag. The caller is responsible of freeing this memory with
///                                 #HpFreeAndNullWithTag.
/// @param[out]     StringLength    The length of the string. May be NULL.
///
/// @retval         INT_STATUS_SUCCESS in case of success
/// @retval         #INT_STATUS_INVALID_PARAMETER_1 if StrGva does not point inside the kernel
/// @retval         #INT_STATUS_INVALID_PARAMETER_2 is MinimumLength is 0 or more than #PAGE_SIZE. Note that the
///                 string can still span across two pages
/// @retval         #INT_STATUS_NOT_FOUND if no valid string is found
/// @retval         #INT_STATUS_INSUFFICIENT_RESOURCES if not enough memory could be allocated for the string
///
{
    INTSTATUS status;
    DWORD strLen;
    QWORD gva;
    BOOLEAN found;
    char *str;

    if (introGuestLinux == gGuest.OSType && !IS_KERNEL_POINTER_LIX(StrGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }
    else if (introGuestWindows == gGuest.OSType && !IS_KERNEL_POINTER_WIN(gGuest.Guest64, StrGva))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == MinimumLength || PAGE_SIZE < MinimumLength)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    str = NULL;

    if (NULL != StringLength)
    {
        *StringLength = 0;
    }

    // In case the string splits in two pages
    strLen = 0;
    gva = StrGva;
    found = FALSE;
    do
    {
        int i = 0;
        DWORD remaining = PAGE_REMAINING(gva);
        char *p, *pStr;

        status = IntVirtMemMap(gva, remaining, gGuest.Mm.SystemCr3, 0, &pStr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx with size %x: 0x%08x\n",
                  gva, remaining, status);
            return status;
        }

        p = pStr;

        if (AnsiOnly)
        {
            i = is_str_ansi(p, remaining, MinimumLength);
        }
        else
        {
            while ((DWORD)i < remaining && *p)
            {
                i++;
                p++;
            }

            if ((DWORD)i < MinimumLength)
            {
                i = -1;
            }
        }

        IntVirtMemUnmap(&pStr);

        // this is no string
        if (-1 == i)
        {
            break;
        }

        strLen += i;

        // found in this page
        if (i < (int)remaining && i > 0)
        {
            found = TRUE;
            break;
        }

        // go to the next page (will be aligned from now on)
        gva += remaining;
    } while ((gva & PAGE_MASK) - (StrGva & PAGE_MASK) == PAGE_SIZE);

    if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    // From now on we include the NULL terminator.
    strLen++;

    if (NULL == *String)
    {
        str = HpAllocWithTag(strLen, IC_TAG_NAME);
        if (NULL == str)
        {
            return INT_STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    else
    {
        str = *String;
    }

    // This is fine, because we check in the beginning that the StrGva is a kernel pointer.
    status = IntKernVirtMemRead(StrGva, strLen, str, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for gva 0x%016llx, length %x: 0x%08x\n", StrGva, strLen, status);
        goto _clean_leave;
    }

    // We just allocated strLen + 1, so we are guaranteed to have space for the NULL terminator.
    str[strLen - 1] = 0;

    *String = str;

    if (NULL != StringLength)
    {
        *StringLength = strLen;
    }

_clean_leave:
    if (!INT_SUCCESS(status))
    {
        if (NULL != StringLength)
        {
            *StringLength = 0;
        }

        if (NULL != str)
        {
            HpFreeAndNullWithTag(&str, IC_TAG_NAME);
        }
    }

    return status;
}
