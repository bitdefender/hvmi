/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "glue.h"
#include "alert_exceptions.h"

///
/// @brief  If defined, the MTRRs will be checked for every mapping
///
/// This ensures that only Write-Back memory will be mapped by introcore, and thus avoid special types of memory usually
/// used by devices.
///
#define CFG_CHECK_MTRR_ON_MAPS


#ifndef USER_MODE
/// @brief  Indicates which pages inside the fast map region are free
///
/// Every bit describes a page. If the bit is set, the corresponding page is allocated. Valid only for Napoca.
QWORD gPageBitmap[8] = { 0 };
/// @brief  The base of the fast map memory region
///
/// Allocated pointers are in the region [gFastPaPageBase, gFastPaPageBase + #gFastPaPagesCount * #PAGE_SIZE]. Valid
/// only on Napoca
void *gFastPaPageBase = NULL;
/// @brief  The base of the page table that maps the fast map zone
///
/// gFastPaPtBase[0] will be the PT entry that maps #gFastPaPageBase. Valid only on Napoca.
void *gFastPaPtBase = NULL;
/// @brief  The number of pages reserved for the fast map zone
///
/// Valid only for Napoca.
DWORD gFastPaPagesCount = 0;
#endif // !USER_MODE

/// @brief  The instance of the #GLUE_IFACE that is being used
///
/// This is initialized in #IntGlueInit and reset in #IntGlueReset.
static GLUE_IFACE gIface = {0};
/// @brief  The instance of #UPPER_IFACE that is being used
///
/// This is initialized in #IntGlueInit and reset in #IntGlueReset.
static UPPER_IFACE gUpIface = {0};
/// @brief  The guest handle provided by the integrator at initialization
///
/// This is used when communicating between the introspection engine and the integrator and is treated as an opaque
/// pointer by introcore.
void *gIntHandle = NULL;

/// @brief  The ID of the current event
///
/// Each event handler increments this when a new event is triggered. It is reset back to zero by #IntGlueReset. This
/// can be used to tag events and caches.
QWORD gEventId = 0;

/// @brief  Used for #utf16_for_log to support calling that function 8 times in a single macro
DWORD gCurLogBuffer = 0;

/// @brief  The currently used log level
///
/// For debug builds, this defaults to #intLogLevelDebug; for Release builds the default value is #intLogLevelWarning.
/// Can be changed at runtime by the integrator using the #GLUE_IFACE.SetLogLevel API. #INT_LOG will check this before
/// deciding if a message will be logged or not.
#ifdef DEBUG
IG_LOG_LEVEL gLogLevel = intLogLevelDebug;
#else
IG_LOG_LEVEL gLogLevel = intLogLevelWarning;
#endif

/// @brief  The trace API used
PFUNC_IntTracePrint GlueTracePrint = NULL;
/// @brief  The API used to break into the debugger
PFUNC_IntEnterDebugger GlueEnterDebugger = NULL;

void
IntGlueReset(
    void
    )
///
/// @brief  Resets the global glue state (#gIface. #gUpIface, #gIntHandle, #gEventId, etc)
///
{
    memzero(&gIface, sizeof(gIface));
    memzero(&gUpIface, sizeof(gUpIface));

    gIntHandle = NULL;

    gEventId = 0;

#ifndef USER_MODE
    memset(gPageBitmap, 0, sizeof(gPageBitmap));
    gFastPaPageBase = NULL;
    gFastPaPtBase = NULL;
    gFastPaPagesCount = 0;
#endif // !USER_MODE
}


INTSTATUS
IntGlueInit(
    _In_ GLUE_IFACE const *GlueInterface,
    _In_ UPPER_IFACE const *UpperInterface
    )
///
/// @brief  Initializes the instances of #GLUE_IFACE and #UPPER_IFACE that will be used
///
/// This is one of the first functions called when introcore starts, it needs to set up the interfaces used for
/// communication with the integrator.
/// On Napoca, it will also initialize the fast page map mechanism. Failure to initialize this is not treated as
/// an error, and initialization can continue.
/// Once this function returns, #gIface and #gUpIface can safely be used to call functions exposed by the integrator.
/// It is important to note, that a failure reported by this function can't even be logged, as there is no logging
/// API available before #gUpIface is initialized.
///
/// @param[in]  GlueInterface   Instance of the #GLUE_IFACE interface which has the APIs exposed by the integrator
///                             initialized
/// @param[in]  UpperInterface  Instance of the #UPPER_IFACE interface which has the APIs exposed by the integrator
///                             initialized
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_ALREADY_INITIALIZED_HINT if #gIface or #gUpIface is already initialized
/// @retval     #INT_STATUS_NOT_SUPPORTED if the sizes reported inside the interfaces do not match
///             #GLUE_IFACE_VERSION_LATEST or #GLUE_IFACE_VERSION_LATEST_SIZE, or the versions reported inside the
///             interfaces do not match #UPPER_IFACE_VERSION_LATEST or #UPPER_IFACE_VERSION_LATEST_SIZE
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if one of the mandatory APIs inside #GLUE_IFACE are not found in
///             GlueInterface
/// @retval     #INT_STATUS_INVALID_PARAMETER_2 if one of the mandatory APIs inside #UPPER_IFACE are not found in
///             UpperInterface
///
{
    if ((gIface.Size) || (gUpIface.Size))
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    if ((GLUE_IFACE_VERSION_LATEST != GlueInterface->Version) ||
        (GLUE_IFACE_VERSION_LATEST_SIZE != GlueInterface->Size))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if ((NULL == GlueInterface->QueryGuestInfo) ||
        (NULL == GlueInterface->PhysMemMapToHost) ||
        (NULL == GlueInterface->PhysMemUnmap) ||
        (NULL == GlueInterface->RegisterMSRHandler) ||
        (NULL == GlueInterface->UnregisterMSRHandler) ||
        (NULL == GlueInterface->RegisterEPTHandler) ||
        (NULL == GlueInterface->UnregisterEPTHandler) ||
        (NULL == GlueInterface->GetEPTPageProtection) ||
        (NULL == GlueInterface->SetEPTPageProtection) ||
        (NULL == GlueInterface->PhysMemGetTypeFromMtrrs) ||
        (NULL == GlueInterface->EnableMSRExit) ||
        (NULL == GlueInterface->DisableMSRExit) ||
        (NULL == GlueInterface->PauseVcpus) ||
        (NULL == GlueInterface->ResumeVcpus) ||
        (NULL == GlueInterface->GpaToHpa) ||
        (NULL == GlueInterface->RegisterIntroTimerHandler) ||
        (NULL == GlueInterface->UnregisterIntroTimerHandler) ||
        (NULL == GlueInterface->RegisterIntroCallHandler) ||
        (NULL == GlueInterface->UnregisterIntroCallHandler) ||
        (NULL == GlueInterface->RegisterDtrHandler) ||
        (NULL == GlueInterface->UnregisterDtrHandler) ||
        (NULL == GlueInterface->InjectTrap) ||
        (NULL == GlueInterface->SetIntroEmulatorContext) ||
        (NULL == GlueInterface->RegisterXcrWriteHandler) ||
        (NULL == GlueInterface->UnregisterXcrWriteHandler) ||
        (NULL == GlueInterface->RegisterCrWriteHandler) ||
        (NULL == GlueInterface->UnregisterCrWriteHandler) ||
        (NULL == GlueInterface->EnableCrWriteExit) ||
        (NULL == GlueInterface->DisableCrWriteExit) ||
        (NULL == GlueInterface->NotifyIntrospectionAlert) ||
        (NULL == GlueInterface->RegisterBreakpointHandler) ||
        (NULL == GlueInterface->UnregisterBreakpointHandler) ||
        (NULL == GlueInterface->ReleaseBuffer))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if ((UPPER_IFACE_VERSION_LATEST != UpperInterface->Version) ||
        (UPPER_IFACE_VERSION_LATEST_SIZE != UpperInterface->Size))
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    if ((NULL == UpperInterface->TracePrint) ||
        (NULL == UpperInterface->MemAllocWithTagAndInfo) ||
        (NULL == UpperInterface->MemFreeWithTagAndInfo) ||
        (NULL == UpperInterface->SpinLockInit) ||
        (NULL == UpperInterface->SpinLockUnInit) ||
        (NULL == UpperInterface->SpinLockAcquire) ||
        (NULL == UpperInterface->SpinLockRelease) ||
        (NULL == UpperInterface->RwSpinLockInit) ||
        (NULL == UpperInterface->RwSpinLockUnInit) ||
        (NULL == UpperInterface->RwSpinLockAcquireExclusive) ||
        (NULL == UpperInterface->RwSpinLockAcquireShared) ||
        (NULL == UpperInterface->RwSpinLockReleaseExclusive) ||
        (NULL == UpperInterface->RwSpinLockReleaseShared) ||
        (NULL == UpperInterface->BugCheck) ||
        (NULL == UpperInterface->EnterDebugger))
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    memcpy(&gIface, GlueInterface, sizeof(gIface));
    memcpy(&gUpIface, UpperInterface, sizeof(gUpIface));

    GlueTracePrint = gUpIface.TracePrint;
    GlueEnterDebugger = gUpIface.EnterDebugger;

#ifndef USER_MODE
    // Only for Napoca, request a PT for fast mappings
    // Keep at max 512 pages if more are given
    IntReserveVaSpaceWithPt(&gFastPaPageBase, &gFastPaPagesCount, &gFastPaPtBase);
    gFastPaPagesCount = MIN(gFastPaPagesCount, ARRAYSIZE(gPageBitmap) * 64);

    gUpIface.TracePrint(__FILE__, __LINE__, "[FASTMAP] Reserved %d pages @ %p/%p\n", gFastPaPagesCount, gFastPaPageBase,
                        gFastPaPtBase);
#endif // !USER_MODE

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntQueryGuestInfo(
    _In_ DWORD InfoClass,
    _In_opt_ void *InfoParam,
    _When_(InfoClass == IG_QUERY_INFO_CLASS_SET_REGISTERS, _In_reads_bytes_(BufferLength))
    _When_(InfoClass != IG_QUERY_INFO_CLASS_SET_REGISTERS, _Out_writes_bytes_(BufferLength))
    void *Buffer,
    _In_ DWORD BufferLength
    )
{
    return gIface.QueryGuestInfo(gIntHandle, InfoClass, InfoParam, Buffer, BufferLength);
}


INTSTATUS
IntGpaToHpa(
    _In_ QWORD Gpa,
    _Out_ QWORD *Hpa
    )
{
    return gIface.GpaToHpa(gIntHandle, Gpa, Hpa);
}


#ifndef USER_MODE
static INTSTATUS
IntPhysMemFastMap(
    _In_ QWORD PhysAddress,
    _Outptr_ void **HostPtr
    )
///
/// @brief      Maps a guest physical address using the fast map mechanism
///
/// Available only on Napoca. This is faster than issuing a #GLUE_IFACE.PhysMemMapToHost call.
/// Since on Napoca we run directly in the VMX root, we can easily access the hypervisor
/// page tables. Note that we need to also be able to invalidate page table entries.
/// Implementing this for scenarios in which introcore does not run inside the hypervisor
/// is not really feasible.
///
/// @param[in]  PhysAddress     The guest physical address to be mapped
/// @param[out] HostPtr         On success, contains a pointer to the mapped memory
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_OUT_OF_RESOURCES if no more free pages exist
/// @retval     #INT_STATUS_INVALID_DATA_TYPE is #CFG_CHECK_MTRR_ON_MAPS is defined and the memory type
///             is not #IG_MEM_WB
///
{
    BYTE *pPage = gFastPaPageBase;
    QWORD *pPageTable = gFastPaPtBase;
    DWORD firstFreeIndex = ARRAYSIZE(gPageBitmap);
    DWORD pos = 0;
    QWORD freeSlot;
    QWORD hpa;
    INTSTATUS status;

    for (DWORD i = 0; i < ARRAYSIZE(gPageBitmap); i++)
    {
        if (gPageBitmap[i] != UINT64_MAX)
        {
            firstFreeIndex = i;
            break;
        }
    }

    if ((firstFreeIndex * 64 >= gFastPaPagesCount) || (firstFreeIndex >= ARRAYSIZE(gPageBitmap)))
    {
        return INT_STATUS_OUT_OF_RESOURCES;
    }

    status = IntGpaToHpa(PhysAddress, &hpa);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

#ifdef CFG_CHECK_MTRR_ON_MAPS
    {
        IG_MEMTYPE memType = IG_MEM_UNKNOWN;

        status = IntPhysMemGetTypeFromMtrrs(PhysAddress, &memType);
        if (!INT_SUCCESS(status))
        {
            return status;
        }
        else if (memType != IG_MEM_WB)
        {
            return INT_STATUS_INVALID_DATA_TYPE;
        }
    }
#endif // CFG_CHECK_MTRR_ON_MAPS

    // Check for the first free position
    if (!_BitScanForward64(&pos, ~gPageBitmap[firstFreeIndex]))
    {
        return INT_STATUS_OUT_OF_RESOURCES;
    }

    freeSlot = (firstFreeIndex * 64ull) + pos;

    pPageTable[freeSlot] = ((hpa & PHYS_PAGE_MASK) | (pPageTable[freeSlot] & 0xFFCULL) | 0x003);    // R/W = 1, P = 1
    *HostPtr = pPage + (freeSlot * PAGE_SIZE) + (PhysAddress & PAGE_OFFSET);

    __invlpg(*HostPtr);

    gPageBitmap[firstFreeIndex] |= (1ULL << pos);

    return INT_STATUS_SUCCESS;
}
#endif // !USER_MODE


INTSTATUS
IntPhysMemMap(
    _In_ QWORD PhysAddress,
    _In_ DWORD Length,
    _In_ DWORD Flags,
    _Outptr_result_bytebuffer_(Length) void **HostPtr
    )
///
/// @brief      Maps a guest physical address inside Introcore VA space
///
/// #IntPhysMemUnmap must be used to unmap memory obtained from this function.
/// For scenarios in which Introcore runs directly inside the VMX root, and if the fast map
/// mechanism is implemented (by providing a #GLUE_IFACE.ReserveVaSpaceWithPt implementation),
/// it will map the page directly inside a predefined range reserved at startup. In this way,
/// we avoid making long, slow calls to mapping APIs, which has a significant performance impact.
/// If the fast mapping is not available, or no more free pages are found, we use the standard
/// mapping API: #GLUE_IFACE.PhysMemMapToHost. For most use-cases this is true, and this function
/// can be considered a thin wrapper over #GLUE_IFACE.PhysMemMapToHost.
///
/// @param[in]  PhysAddress     The guest physical address to be mapped
/// @param[in]  Length          The size to be mapped, in bytes
/// @param[in]  Flags           Flags that control the mapping. Either 0 or #PHYS_MAP_FLG_NO_FASTMAP.
///                             #PHYS_MAP_FLG_NO_FASTMAP is ignored if the hypervisor is not Napoca, since
///                             that is true by default in those cases.
/// @param[out] HostPtr         On success, will hold a pointer to the memory at which PhysicalAddress is
///                             mapped
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    if (0 == Length)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

#ifndef USER_MODE
    if (PAGE_COUNT(PhysAddress, Length) == 1 &&
        !(Flags & PHYS_MAP_FLG_NO_FASTMAP))
    {
        INTSTATUS status = IntPhysMemFastMap(PhysAddress, HostPtr);
        if (INT_SUCCESS(status))
        {
            return status;
        }

        // This means that MTRR memory type is not WB
        if (status == INT_STATUS_INVALID_DATA_TYPE)
        {
            return status;
        }
    }
#endif // !USER_MODE

    Flags &= ~PHYS_MAP_FLG_NO_FASTMAP; // clear the introspection's internal flags
    return gIface.PhysMemMapToHost(gIntHandle, PhysAddress, Length, Flags, HostPtr);
}


INTSTATUS
IntPhysMemUnmap(
    _Inout_ _At_(*HostPtr, _Post_null_) void **HostPtr
    )
///
/// @brief          Unmaps an address previously mapped with #IntPhysMemMap
///
/// This function handles the cases in which memory came from the fast mapping mechanism by checking if the provided
/// address is in the range [#gFastPaPageBase, #gFastPaPageBase + #gFastPaPagesCount * #PAGE_SIZE]. For most use-cases
/// this is a thin wrapper over #GLUE_IFACE.PhysMemUnmap.
///
/// @param[in, out] HostPtr     Points to the address at the start of the area that must be unmapped. Must be the same
///                             address as obtained from #IntPhysMemMap, partial unmaps are not possible. After this
///                             function returns it will point to NULL and the old address is no longer valid.
///
/// @returns        #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    INTSTATUS status;
#ifndef USER_MODE
    // Check if this page is mapped in the fast map zone.
    if ((*HostPtr >= gFastPaPageBase) &&
        (*HostPtr < (void *)((BYTE *)gFastPaPageBase + (QWORD)gFastPaPagesCount * PAGE_SIZE)))
    {
        QWORD currentSlot, *pPageTable;

        pPageTable = (QWORD *)gFastPaPtBase;

        // Get the slot used by this allocation
        currentSlot = (((size_t) * HostPtr & PAGE_MASK) - (size_t)gFastPaPageBase) / PAGE_SIZE;

        // Mark the slot as being available
        gPageBitmap[currentSlot / 64] &= ~(1ULL << (currentSlot % 64));

        pPageTable[currentSlot] = (pPageTable[currentSlot] & 0xFFCULL);

        __invlpg(*HostPtr);
        *HostPtr = NULL;

        return INT_STATUS_SUCCESS;
    }
#endif // !USER_MODE

    status = gIface.PhysMemUnmap(gIntHandle, HostPtr);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] gIface.PhysMemUnmap failed for (%p %p): 0x%08x\n", HostPtr, *HostPtr, status);
    }

    *HostPtr = NULL;

    return status;
}


INTSTATUS
IntReserveVaSpaceWithPt(
    _Outptr_ void **FirstPageBase,
    _Out_ DWORD *PagesCount,
    _Outptr_ void **PtBase
    )
///
/// @brief      Reserves a contiguous region of virtual memory which will then be used to map physical pages

/// Will return the base address of the region, the number of pages reserved , and the Page Table base, which maps the
/// given virtual address range. Calling this function more than once should be avoided.
///
/// @param[in]  FirstPageBase       On success, will contain the start of the virtual address range
/// @param[in]  PagesCount          On success, will contain the number of pages reserved
/// @param[in]  PtBase              On success, will contain a pointer to the page table that was reserved
///
/// @retval     #INT_STATUS_SUCCESS in case of success
/// @retval     #INT_STATUS_OPERATION_NOT_IMPLEMENTED if #GLUE_IFACE.ReserveVaSpaceWithPt is not implemented. Since
///             this API is optional, this should not be treated as a fatal error
///
{
    if (NULL == gIface.ReserveVaSpaceWithPt)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    return gIface.ReserveVaSpaceWithPt(gIntHandle, FirstPageBase, PagesCount, PtBase);
}


INTSTATUS
GluePauseVcpus(
    void
    )
{
    return gIface.PauseVcpus(gIntHandle);
}


INTSTATUS
GlueResumeVcpus(
    void
    )
{
    return gIface.ResumeVcpus(gIntHandle);
}


INTSTATUS
IntEnableMsrExit(
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    )
{
    return gIface.EnableMSRExit(gIntHandle, Msr, OldValue);
}


INTSTATUS
IntDisableMsrExit(
    _In_ DWORD Msr,
    _Out_ BOOLEAN *OldValue
    )
{
    return gIface.DisableMSRExit(gIntHandle, Msr, OldValue);
}


INTSTATUS
IntRegisterMSRHandler(
    _In_ PFUNC_IntMSRViolationCallback Callback
    )
{
    return gIface.RegisterMSRHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterMSRHandler(
    void
    )
{
    return gIface.UnregisterMSRHandler(gIntHandle);
}


INTSTATUS
IntPhysMemGetTypeFromMtrrs(
    _In_ QWORD Gpa,
    _Out_ IG_MEMTYPE *MemType
    )
{
    return gIface.PhysMemGetTypeFromMtrrs(gIntHandle, Gpa, MemType);
}


INTSTATUS
IntEnableCrWriteExit(
    _In_ DWORD Cr
    )
{
    return gIface.EnableCrWriteExit(gIntHandle, Cr);
}


INTSTATUS
IntDisableCrWriteExit(
    _In_ DWORD Cr
    )
{
    return gIface.DisableCrWriteExit(gIntHandle, Cr);
}


INTSTATUS
IntRegisterCrWriteHandler(
    _In_ PFUNC_IntCrWriteCallback Callback
    )
{
    return gIface.RegisterCrWriteHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterCrWriteHandler(
    void
    )
{
    return gIface.UnregisterCrWriteHandler(gIntHandle);
}


INTSTATUS
IntRegisterBreakpointHandler(
    _In_ PFUNC_IntBreakpointCallback Callback
    )
{
    return gIface.RegisterBreakpointHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterBreakpointHandler(
    void
    )
{
    return gIface.UnregisterBreakpointHandler(gIntHandle);
}


INTSTATUS
IntRegisterEventInjectionHandler(
    _In_ PFUNC_IntEventInjectionCallback Callback
    )
{
    return gIface.RegisterEventInjectionHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterEventInjectionHandler(
    void
    )
{
    return gIface.UnregisterEventInjectionHandler(gIntHandle);
}


INTSTATUS
IntRegisterEnginesResultCallback(
    _In_ PFUNC_IntEventEnginesResultCallback Callback
    )
///
/// @brief      Thin wrapper over the optional #GLUE_IFACE.RegisterEnginesResultCallback API
///
/// @param[in]  Callback    The callback to be registered
///
/// @returns    Since the API is optional, it either returns the same values as the API, or #INT_STATUS_NOT_NEEDED_HINT
///             if it is not implemented
///
{
    if (NULL == gIface.RegisterEnginesResultCallback)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return gIface.RegisterEnginesResultCallback(gIntHandle, Callback);
}

INTSTATUS
IntUnregisterEnginesResultCalback(
    void
    )
///
/// @brief      Thin wrapper over the optional #GLUE_IFACE.UnregisterEnginesResultCalback API
///
/// @returns    Since the API is optional, it either returns the same values as the API, or #INT_STATUS_NOT_NEEDED_HINT
///             if it is not implemented
///
{
    if (NULL == gIface.UnregisterEnginesResultCalback)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    return gIface.UnregisterEnginesResultCalback(gIntHandle);
}

INTSTATUS
IntGetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Gpa,
    _Out_ BYTE *Read,
    _Out_ BYTE *Write,
    _Out_ BYTE *Execute
    )
{
    return gIface.GetEPTPageProtection(gIntHandle, EptIndex, Gpa, Read, Write, Execute);
}


INTSTATUS
IntSetEPTPageProtection(
    _In_ DWORD EptIndex,
    _In_ QWORD Gpa,
    _In_ BYTE Read,
    _In_ BYTE Write,
    _In_ BYTE Execute
    )
{
    return gIface.SetEPTPageProtection(gIntHandle, EptIndex, Gpa, Read, Write, Execute);
}


INTSTATUS
IntGetSPPPageProtection(
    _In_ QWORD Gpa,
    _Out_ QWORD *Spp
    )
{
    return gIface.GetSPPPageProtection(gIntHandle, Gpa, Spp);
}


INTSTATUS
IntSetSPPPageProtection(
    _In_ QWORD Gpa,
    _In_ QWORD Spp
    )
{
    return gIface.SetSPPPageProtection(gIntHandle, Gpa, Spp);
}


BOOLEAN
GlueIsSppApiAvailable(
    void
    )
///
/// @brief      Checks if the SPP APIs in #GLUE_IFACE are implemented
///
/// Checks if #GLUE_IFACE.GetSPPPageProtection and #GLUE_IFACE.SetSPPPageProtection are implemented.
/// These APIs are optional and their absence is treated as if the hypervisor does not have support for Intel SPP.
///
/// @retval     True if the APIs are available
/// @retval     False if the APIs are not available
///
{
    return (gIface.GetSPPPageProtection && gIface.SetSPPPageProtection);
}


INTSTATUS
IntRegisterEPTHandler(
    _In_ PFUNC_IntEPTViolationCallback Callback
    )
{
    return gIface.RegisterEPTHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterEPTHandler(
    void
    )
{
    return gIface.UnregisterEPTHandler(gIntHandle);
}


INTSTATUS
IntRegisterIntroCallHandler(
    _In_ PFUNC_IntIntroCallCallback Callback
    )
{
    return gIface.RegisterIntroCallHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterIntroCallHandler(
    void
    )
{
    return gIface.UnregisterIntroCallHandler(gIntHandle);
}


INTSTATUS
IntRegisterVmxTimerHandler(
    _In_ PFUNC_IntIntroTimerCallback Callback
    )
{
    return gIface.RegisterIntroTimerHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterVmxTimerHandler(
    void
    )
{
    return gIface.UnregisterIntroTimerHandler(gIntHandle);
}


INTSTATUS
IntRegisterDtrHandler(
    _In_ PFUNC_IntIntroDescriptorTableCallback Callback
    )
{
    return gIface.RegisterDtrHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterDtrHandler(
    void
    )
{
    return gIface.UnregisterDtrHandler(gIntHandle);
}


INTSTATUS
IntRegisterXcrWriteHandler(
    _In_ PFUNC_IntXcrWriteCallback Callback
    )
{
    return gIface.RegisterXcrWriteHandler(gIntHandle, Callback);
}


INTSTATUS
IntUnregisterXcrWriteHandler(
    void
    )
{
    return gIface.UnregisterXcrWriteHandler(gIntHandle);
}


INTSTATUS
IntSpinLockInit(
    _Outptr_ void **SpinLock,
    _In_z_ char *Name
    )
{
    return gUpIface.SpinLockInit(SpinLock, Name);
}


INTSTATUS
IntSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    )
{
    return gUpIface.SpinLockUnInit(SpinLock);
}


_Acquires_lock_(SpinLock)
void
IntSpinLockAcquire(
    _In_ void *SpinLock
    )
{
    INTSTATUS status = gUpIface.SpinLockAcquire(SpinLock);
    if (!INT_SUCCESS(status))
    {
        CRITICAL("[ERROR] SpinLockAcquire failed: 0x%08x\n", status);
        IntBugCheck();
    }
}


_Releases_lock_(SpinLock)
void
IntSpinLockRelease(
    _In_ void *SpinLock
    )
{
    INTSTATUS status = gUpIface.SpinLockRelease(SpinLock);
    if (!INT_SUCCESS(status))
    {
        CRITICAL("[ERROR] SpinLockRelease failed: 0x%08x\n", status);
        IntBugCheck();
    }
}


INTSTATUS
IntRwSpinLockInit(
    _Outptr_ void **SpinLock,
    _In_z_ char *Name
    )
{
    return gUpIface.RwSpinLockInit(SpinLock, Name);
}


INTSTATUS
IntRwSpinLockUnInit(
    _Inout_ _At_(*SpinLock, _Post_null_) void **SpinLock
    )
{
    return gUpIface.RwSpinLockUnInit(SpinLock);
}


INTSTATUS
IntRwSpinLockAcquireShared(
    _In_ void *SpinLock
    )
{
    return gUpIface.RwSpinLockAcquireShared(SpinLock);
}


INTSTATUS
IntRwSpinLockAcquireExclusive(
    _In_ void *SpinLock
    )
{
    return gUpIface.RwSpinLockAcquireExclusive(SpinLock);
}


INTSTATUS
IntRwSpinLockReleaseShared(
    _In_ void *SpinLock
    )
{
    return gUpIface.RwSpinLockReleaseShared(SpinLock);
}


INTSTATUS
IntRwSpinLockReleaseExclusive(
    _In_ void *SpinLock
    )
{
    return gUpIface.RwSpinLockReleaseExclusive(SpinLock);
}


__noreturn void
IntBugCheck(
    void
    )
{
    gUpIface.BugCheck();
    __unreachable;
}


INTSTATUS
IntNotifyIntroActive(
    void
    )
{
    if (NULL == gIface.NotifyIntrospectionActivated)
    {
        return INT_STATUS_SUCCESS;
    }

    return gIface.NotifyIntrospectionActivated(gIntHandle);
}


INTSTATUS
IntNotifyIntroInactive(
    void
    )
{
    if (NULL == gIface.NotifyIntrospectionDeactivated)
    {
        return INT_STATUS_SUCCESS;
    }

    return gIface.NotifyIntrospectionDeactivated(gIntHandle);
}


INTSTATUS
IntNotifyIntroDetectedOs(
    _In_ INTRO_GUEST_TYPE OsType,
    _In_ DWORD OsVersion,
    _In_ BOOLEAN Is64
    )
///
/// @brief      Wrapper over #GLUE_IFACE.NotifyIntrospectionDetectedOs
///
/// Simply encapsulates the guest information into a #GUEST_INFO structure and sends it to the integrator.
///
/// @param[in]  OsType      The type of the OS
/// @param[in]  OsVersion   The version of the OS kernel
/// @param[in]  Is64        True for 64-bit kernels, False for 32-bit kernels
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    GUEST_INFO info = {0};

    if (NULL == gIface.NotifyIntrospectionDetectedOs)
    {
        return INT_STATUS_SUCCESS;
    }

    info.Type = OsType;
    info.BuildNumber = info.OsVersion = OsVersion;
    info.Guest64 = Is64;
    info.StartupTime = IG_INVALID_TIME;

    return gIface.NotifyIntrospectionDetectedOs(gIntHandle, &info);
}


INTSTATUS
IntNotifyIntroErrorState(
    _In_ INTRO_ERROR_STATE State,
    _In_opt_ INTRO_ERROR_CONTEXT *Context
    )
{
    if (NULL == gIface.NotifyIntrospectionErrorState)
    {
        return INT_STATUS_SUCCESS;
    }

    return gIface.NotifyIntrospectionErrorState(gIntHandle, State, Context);
}


INTSTATUS
IntNotifyEngines(
    _Inout_ void *Parameters
    )
{
    if (NULL == gIface.NotifyScanEngines)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.NotifyScanEngines(gIntHandle, Parameters);
}


INTSTATUS
IntSetIntroEmulatorContext(
    _In_ DWORD CpuNumber,
    _In_ QWORD VirtualAddress,
    _In_ DWORD BufferSize,
    _In_reads_bytes_(BufferSize) BYTE *Buffer
    )
{
    return gIface.SetIntroEmulatorContext(gIntHandle, CpuNumber, VirtualAddress, BufferSize, Buffer);
}


INTSTATUS
IntInjectTrap(
    _In_ DWORD CpuNumber,
    _In_ BYTE TrapNumber,
    _In_ DWORD ErrorCode,
    _In_opt_ QWORD Cr2
    )
{
    return gIface.InjectTrap(gIntHandle, CpuNumber, TrapNumber, ErrorCode, Cr2);
}


INTSTATUS
IntNotifyIntroEvent(
    _In_ INTRO_EVENT_TYPE EventClass,
    _In_ void *Param,
    _In_ size_t EventSize
    )
///
/// @brief      Notifies the integrator about an introspection alert
///
/// It also sets the exception information inside the event before sending it
///
/// @param[in]  EventClass  The type of the event
/// @param[in]  Param       The event buffer
/// @param[in]  EventSize   The size of the Param buffer, in bytes
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    IntAlertCreateExceptionInEvent(Param, EventClass);

    return gIface.NotifyIntrospectionAlert(gIntHandle, EventClass, Param, EventSize);
}


INTSTATUS
IntGetAgentContent(
    _In_ DWORD AgentTag,
    _In_ BOOLEAN Is64,
    _Out_ DWORD *Size,
    _Outptr_ BYTE **Content
    )
{
    if (NULL == gIface.GetAgentContent)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    return gIface.GetAgentContent(gIntHandle, AgentTag, Is64, Size, Content);
}


INTSTATUS
IntReleaseBuffer(
    _In_ void *Buffer,
    _In_ DWORD Size
    )
{
    if (NULL == gIface.ReleaseBuffer)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    return gIface.ReleaseBuffer(gIntHandle, Buffer, Size);
}


INTSTATUS
IntToggleRepOptimization(
    _In_ BOOLEAN Enable
    )
{
    if (NULL == gIface.ToggleRepOptimization)
    {
        return INT_STATUS_SUCCESS;
    }

    return gIface.ToggleRepOptimization(gIntHandle, Enable);
}


INTSTATUS
IntQueryHeapSize(
    _Out_ size_t *TotalHeapSize,
    _Out_ size_t *FreeHeapSize
    )
{
    if (NULL == gUpIface.QueryHeapSize)
    {
        *TotalHeapSize = 0xFFFFFFFF;
        *FreeHeapSize  = 0xFFFFFFFF;

        return INT_STATUS_SUCCESS;
    }

    return gUpIface.QueryHeapSize(TotalHeapSize, FreeHeapSize);
}


INTSTATUS
IntSendMessage(
    _In_ char const *Message
    )
///
/// @brief      Sends an Introcore message
///
/// This will encapsulate Message inside a #EVENT_INTROSPECTION_MESSAGE structure and will send an event of type
/// #introEventMessage
///
/// @param[in]  Message     NULL terminated string with the message
///
/// @returns    #INT_STATUS_SUCCESS if successful, or an appropriate INTSTATUS error value
///
{
    EVENT_INTROSPECTION_MESSAGE msg;

    strlcpy(msg.Message, Message, sizeof(msg.Message));

    return IntNotifyIntroEvent(introEventMessage, &msg, sizeof(msg));
}


INTSTATUS
IntSetVEInfoPage(
    _In_ DWORD CpuNumber,
    _In_ QWORD VeInfoGpa
    )
{
    if (NULL == gIface.SetVeInfoPage)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.SetVeInfoPage(gIntHandle, CpuNumber, VeInfoGpa);
}


INTSTATUS
IntCreateEPT(
    _Out_ DWORD *EptIndex
    )
{
    if (NULL == gIface.CreateEPT)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.CreateEPT(gIntHandle, EptIndex);
}


INTSTATUS
IntDestroyEPT(
    _In_ DWORD EptIndex
    )
{
    if (NULL == gIface.DestroyEPT)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.DestroyEPT(gIntHandle, EptIndex);
}


INTSTATUS
IntSwitchEPT(
    _In_ DWORD NewEptIndex
    )
{
    if (NULL == gIface.SwitchEPT)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.SwitchEPT(gIntHandle, NewEptIndex);
}


INTSTATUS
IntGetEPTPageConvertible(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _Out_ BOOLEAN *Convertible
    )
{
    if (NULL == gIface.GetEPTPageConvertible)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.GetEPTPageConvertible(gIntHandle, EptIndex, Address, Convertible);
}


INTSTATUS
IntSetEPTPageConvertible(
    _In_ DWORD EptIndex,
    _In_ QWORD Address,
    _In_ BOOLEAN Convertible
    )
{
    if (NULL == gIface.SetEPTPageConvertible)
    {
        return INT_STATUS_NOT_SUPPORTED;
    }

    return gIface.SetEPTPageConvertible(gIntHandle, EptIndex, Address, Convertible);
}


INTSTATUS
IntFlushEPTPermissions(
    void
    )
{
    if (NULL == gIface.FlushEPTPermissions)
    {
        // Simulate a flush by pausing and resuming the VCPUs.
        IntPauseVcpus();

        IntResumeVcpus();

        return INT_STATUS_SUCCESS;
    }

    return gIface.FlushEPTPermissions(gIntHandle);
}


BOOLEAN
GlueIsVeApiAvailable(
    void
    )
///
/// @brief      Checks if the virtualization exception API is implemented
///
/// If at least one of the APIs is not implemented, we will not use the \#VE filtering mechanism even if the
/// #INTRO_OPT_VE option is used.
///
/// @retval     True if the API is implemented
/// @retval     False if it is not
///
{
    return (gIface.SetVeInfoPage &&
            gIface.CreateEPT &&
            gIface.DestroyEPT &&
            gIface.SwitchEPT &&
            gIface.GetEPTPageConvertible &&
            gIface.SetEPTPageConvertible);
}


BOOLEAN
GlueIsScanEnginesApiAvailable(
    void
    )
///
/// @brief      Checks if the third party memory scanning engines are present
///
/// If the API needed for the scanning engines is not present, the support will be considered to be off and the feature
/// will not be available.
///
/// @retval     True if the API is implemented
/// @retval     False if it is not
///
{
    return (gIface.NotifyScanEngines && gIface.RegisterEnginesResultCallback);
}


#ifdef INT_COMPILER_MSVC

__attribute__((malloc))
__attribute__ ((alloc_size (1)))
__must_check
void *
IntAllocWithTag(
    _In_ size_t Length,
    _In_ DWORD Tag,
    _In_ const char *FileName,
    _In_ DWORD FileLine
    )
{
    INTSTATUS status;
    void *addr = NULL;

    if (Length >= 4 * ONE_GIGABYTE)
    {
        return addr;
    }

    if (Length < 8)
    {
        Length = 8;
    }

    status = gUpIface.MemAllocWithTagAndInfo(&addr, Length, Tag);
    if (INT_SUCCESS(status))
    {
        memzero(addr, Length);
    }
    else
    {
        addr = NULL;

        gUpIface.TracePrint(__FILE__, __LINE__,
                            "[ERROR] MemAllocWithTagAndInfo failed in file '%s:%d' for size 0x%llx: 0x%08x\n",
                            FileName, FileLine, Length, status);
    }

    return addr;
}


INTSTATUS
IntFreeWithTag(
    _In_ void *Address,
    _In_ DWORD Tag
    )
{
    void **addr = &Address;

    return gUpIface.MemFreeWithTagAndInfo(addr, Tag);
}

#endif
