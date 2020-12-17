/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "windriver.h"
#include "alerts.h"
#include "crc32.h"
#include "hook.h"
#include "swapmem.h"
#include "winpe.h"
#include "winagent.h"
#include "windrv_protected.h"

extern LIST_HEAD gKernelDrivers;

///
/// @file windriver.c
///
/// @brief This file handles Windows Drivers related events (loading, unloading, writes, etc.)
///
/// Introcore provides a very good protection against kernel exploits by identifying already loaded
/// drivers and intercepting driver load/unload events. Once a driver is identified, read/write hooks
/// are placed in order to protect critical structures (such as the EAT, IAT, etc.). This file contains
/// all the functions used to identify the kernel drivers, hook critical driver structures, handle driver
/// related EPT violations and notify the integrator upon driver related events.
///


static void
IntWinDrvSendEvent(
    _In_ KERNEL_DRIVER *Driver,
    _In_ BOOLEAN Loaded
    )
///
/// @brief Send a driver loaded/unloaded event.
///
/// If #INTRO_OPT_EVENT_MODULES is set, the integrator will be notified
/// when a driver has been loaded or unloaded.
///
/// @param[in]  Driver The driver that was loaded/unloaded.
/// @param[in]  Loaded True if the driver has been loaded, FALSE otherwise.
///
{
    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_MODULES))
    {
        return;
    }

    EVENT_MODULE_EVENT *pModEvent = &gAlert.Module;
    memzero(pModEvent, sizeof(*pModEvent));

    pModEvent->Loaded = Loaded;
    pModEvent->Protected = Driver->Protected;

    IntAlertFillWinKmModule(Driver, &pModEvent->Module);
    IntAlertFillWinProcessCurrent(&pModEvent->CurrentProcess);

    INTSTATUS status = IntNotifyIntroEvent(introEventModuleEvent, pModEvent, sizeof(*pModEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


INTSTATUS
IntWinDrvIsListHead(
    _In_ QWORD PsLoadedModuleListGva,
    _In_ void *PsLoadedModuleList,
    _In_ QWORD KernelLdr
    )
///
/// @brief Used to identify #WINDOWS_GUEST::PsLoadedModuleList.
///
/// @param[in]  PsLoadedModuleListGva   The PsLoadedModuleList GVA.
/// @param[in]  PsLoadedModuleList      The PsLoadedModuleList (mapped).
/// @param[in]  KernelLdr               GVA pointer to a #LDR_DATA_TABLE_ENTRY32 or #LDR_DATA_TABLE_ENTRY64 structure.
///
/// @retval #INT_STATUS_SUCCESS If the PsLoadedModuleListGva is the actual list head.
///
{
    INTSTATUS status;
    BOOLEAN matched;
    QWORD name = 0;

    if (gGuest.Guest64)
    {
        LDR_DATA_TABLE_ENTRY64 mod64;
        LIST_ENTRY64 *pListHead;

        // PsModuleList is LIST_HEAD, it must not spill into the next page
        if ((PsLoadedModuleListGva & PAGE_OFFSET) + sizeof(LIST_ENTRY64) > PAGE_SIZE)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // The driver pointed by the head must not spill in another page.
        if ((KernelLdr & PAGE_OFFSET) + sizeof(LDR_DATA_TABLE_ENTRY64) > PAGE_SIZE)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        pListHead = (LIST_ENTRY64 *)PsLoadedModuleList;
        if (!IS_KERNEL_POINTER_WIN(TRUE, pListHead->Flink) ||
            !IS_KERNEL_POINTER_WIN(TRUE, pListHead->Blink))
        {
            TRACE("Failed kernel pointer checks on PsLoadedModuleList Flink/Blink = 0x%016llx/0x%016llx\n",
                  pListHead->Flink, pListHead->Blink);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = IntKernVirtMemRead(KernelLdr, sizeof(mod64), &mod64, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        // The invariant rules
        matched = IS_KERNEL_POINTER_WIN(TRUE, mod64.InLoadOrderLinks.Flink);
        matched = matched && IS_KERNEL_POINTER_WIN(TRUE, mod64.InLoadOrderLinks.Blink);
        matched = matched && IS_KERNEL_POINTER_WIN(TRUE, mod64.DllBase);
        matched = matched && IS_KERNEL_POINTER_WIN(TRUE, mod64.DriverName.Buffer);
        matched = matched && (mod64.DllBase % PAGE_SIZE == 0);
        matched = matched && (mod64.EntryPoint > mod64.DllBase && mod64.EntryPoint < mod64.DllBase + mod64.SizeOfImage);

        if (!matched)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (mod64.InLoadOrderLinks.Blink != PsLoadedModuleListGva)
        {
            TRACE("[INFO] Found & skipped shadow module list at 0x%016llx (head->flink->blink should be same as head)\n",
                  PsLoadedModuleListGva);

            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Fetch the name of the driver, to make sure it's the kernel (ntos*)
        status = IntKernVirtMemFetchQword(mod64.DriverName.Buffer, &name);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        if (name != 0x0073006f0074006e) // "ntos", UNICODE
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = INT_STATUS_SUCCESS;
    }
    else
    {
        LDR_DATA_TABLE_ENTRY32 mod32;
        LIST_ENTRY32 *pListHead;

        // PsModuleList is LIST_HEAD, it must not spill into the next page
        if ((PsLoadedModuleListGva & PAGE_OFFSET) + sizeof(LIST_ENTRY32) > PAGE_SIZE)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // The driver pointed by the head must not spill in another page.
        if ((KernelLdr & PAGE_OFFSET) + sizeof(LDR_DATA_TABLE_ENTRY32) > PAGE_SIZE)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        pListHead = (LIST_ENTRY32 *)PsLoadedModuleList;
        if (!IS_KERNEL_POINTER_WIN(FALSE, pListHead->Flink) ||
            !IS_KERNEL_POINTER_WIN(FALSE, pListHead->Blink))
        {
            TRACE("Failed kernel pointer checks on PsLoadedModuleList Flink/Blink = 0x%08x/0x%08x\n",
                  pListHead->Flink, pListHead->Blink);
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = IntKernVirtMemRead(KernelLdr, sizeof(mod32), &mod32, NULL);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        // The invariant rules
        matched = IS_KERNEL_POINTER_WIN(FALSE, mod32.InLoadOrderLinks.Flink);
        matched = matched && IS_KERNEL_POINTER_WIN(FALSE, mod32.InLoadOrderLinks.Blink);
        matched = matched && IS_KERNEL_POINTER_WIN(FALSE, mod32.DllBase);
        matched = matched && IS_KERNEL_POINTER_WIN(FALSE, mod32.DriverName.Buffer);
        matched = matched && (mod32.DllBase % PAGE_SIZE == 0);
        matched = matched &&
                  (mod32.EntryPoint > mod32.DllBase && mod32.EntryPoint < (QWORD)mod32.DllBase + mod32.SizeOfImage);

        if (!matched)
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        if (mod32.InLoadOrderLinks.Blink != PsLoadedModuleListGva)
        {
            TRACE("[INFO] Found & skipped shadow module list at 0x%08x (head->flink->blink should be same as head)\n",
                  (DWORD)PsLoadedModuleListGva);

            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        // Fetch the name of the driver, to make sure it's the kernel (ntos*)
        status = IntKernVirtMemFetchQword(mod32.DriverName.Buffer, &name);
        if (!INT_SUCCESS(status))
        {
            return status;
        }

        if (name != 0x0073006f0074006e) // "ntos", UNICODE
        {
            return INT_STATUS_INVALID_OBJECT_TYPE;
        }

        status = INT_STATUS_SUCCESS;
    }

    return status;
}


INTSTATUS
IntWinDrvIterateLoadedModules(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Used to iterate trough the #WINDOWS_GUEST::PsLoadedModuleList.
///
/// @param[in]  Callback    The #PFUNC_IterateListCallback callback invoked for every module.
/// @param[in]  Aux         The auxiliary value passed to the callback.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD count = 0;
    QWORD currentModule = gWinGuest->PsLoadedModuleList;

    if (Callback == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    // Read the Flink value
    if (gGuest.Guest64)
    {
        status = IntKernVirtMemFetchQword(currentModule, &currentModule);
    }
    else
    {
        status = IntKernVirtMemFetchDword(currentModule, (DWORD *)&currentModule);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the Flink value of MODULE @ 0x%016llx: 0x%08x\n", currentModule, status);
        return status;
    }

    status = INT_STATUS_SUCCESS;

    // We'll iterate for maximum DRIVER_MAX_ITERATIONS. We assume that there won't be more than this many drivers.
    // This is a guard to avoid denial of service with crafted drivers nodes.
    while ((currentModule != gWinGuest->PsLoadedModuleList) && (count++ < DRIVER_MAX_ITERATIONS))
    {
        status = Callback(currentModule, Aux);
        if (INT_STATUS_BREAK_ITERATION == status)
        {
            return INT_STATUS_SUCCESS;
        }

        // Go to the next entry
        if (gGuest.Guest64)
        {
            status = IntKernVirtMemFetchQword(currentModule, &currentModule);
        }
        else
        {
            status = IntKernVirtMemFetchDword(currentModule, (DWORD *)&currentModule);
            currentModule &= 0xFFFFFFFF;
        }
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the Flink value of LDR_DATA_TABLE_ENTRY @ 0x%016llx: 0x%08x\n",
                  currentModule, status);
            break;
        }
    }

    if (count == DRIVER_MAX_ITERATIONS)
    {
        // This means that the guest list os crafted somehow...
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntWinDrvCreateFromAddress(
    _In_ QWORD ModuleInfo,
    _In_ QWORD Flags
    )
///
/// @brief Adds a driver to introspection's LoadedModuleList (#gKernelDrivers).
/// This way we avoid lots of mapping when searching a driver.
///
/// @param[in]  ModuleInfo  The #LDR_DATA_TABLE_ENTRY32 or #LDR_DATA_TABLE_ENTRY64 corresponding to the module.
/// @param[in]  Flags       If #FLAG_DYNAMIC_DETECTION flag is set, we will execute-protect the first page of
///                         the module. This way, when the first instruction will get executed, we will be
///                         notified, and we'll have a chance to protect the driver's driver object.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    LDR_DATA_TABLE_ENTRY32 pModuleInfo32 = {0};
    LDR_DATA_TABLE_ENTRY64 pModuleInfo64 = {0};
    const PROTECTED_MODULE_INFO *pProt = NULL;
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;
    DWORD nameSize, pathSize;
    QWORD entryPoint;

    pDriver = NULL;

    if (gGuest.Guest64)
    {
        status = IntKernVirtMemRead(ModuleInfo, sizeof(LDR_DATA_TABLE_ENTRY64), &pModuleInfo64, NULL);
    }
    else
    {
        status = IntKernVirtMemRead(ModuleInfo, sizeof(LDR_DATA_TABLE_ENTRY32), &pModuleInfo32, NULL);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed reading from GVA 0x%016llx to host: 0x%08x\n", ModuleInfo, status);
        return status;
    }

    pDriver = HpAllocWithTag(sizeof(*pDriver), IC_TAG_MODU);
    if (NULL == pDriver)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    if (gGuest.Guest64)
    {
        pDriver->BaseVa = pModuleInfo64.DllBase;
        pDriver->Size = 0xFFFFFFFF & pModuleInfo64.SizeOfImage;
        pDriver->EntryPoint = pModuleInfo64.EntryPoint;

        entryPoint = pModuleInfo64.EntryPoint;

        pathSize = 0xFFFF & pModuleInfo64.DriverPath.Length;

        // pathLength + 2: OK - pathLength is DWORD and is AND with 0xFFFF.
        pDriver->Win.Path = HpAllocWithTag(pathSize + 2ull, IC_TAG_DRNU);
        if (NULL == pDriver->Win.Path)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _cleanup_and_leave;
        }

        status = IntKernVirtMemRead(pModuleInfo64.DriverPath.Buffer, pathSize, pDriver->Win.Path, NULL);
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pDriver->Win.Path, IC_TAG_DRNU);
            pDriver->Win.PathHash = INITIAL_CRC_VALUE;
            pDriver->Win.PathLength = 0;
        }
        else
        {
            strlower_utf16(pDriver->Win.Path, pathSize / 2);
            pDriver->Win.PathLength = pathSize / 2;
            pDriver->Win.PathHash = Crc32Wstring(pDriver->Win.Path, INITIAL_CRC_VALUE);
        }

        nameSize = 0xFFFF & pModuleInfo64.DriverName.Length;

        // nameLength + 2: OK - pathLength is DWORD and is AND with 0xFFFF.
        pDriver->Name = HpAllocWithTag(nameSize + 2ull, IC_TAG_DRNU);
        if (NULL == pDriver->Name)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _cleanup_and_leave;
        }

        status = IntKernVirtMemRead(pModuleInfo64.DriverName.Buffer, nameSize, pDriver->Name, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading driver name: 0x%08x\n", status);
            goto _cleanup_and_leave;
        }

        strlower_utf16(pDriver->Name, nameSize / 2);
        pDriver->NameLength = nameSize / 2;
        pDriver->NameHash = Crc32Wstring(pDriver->Name, INITIAL_CRC_VALUE);
    }
    else
    {
        pDriver->BaseVa = pModuleInfo32.DllBase;
        pDriver->Size = pModuleInfo32.SizeOfImage;
        pDriver->EntryPoint = pModuleInfo32.EntryPoint;

        entryPoint = pModuleInfo32.EntryPoint;

        pathSize = 0xFFFF & pModuleInfo32.DriverPath.Length;

        // pathLength + 2 OK - pathLength is DWORD and is AND with 0xFFFF.
        pDriver->Win.Path = HpAllocWithTag(pathSize + 2ull, IC_TAG_DRNU);
        if (NULL == pDriver->Win.Path)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _cleanup_and_leave;
        }

        status = IntKernVirtMemRead(pModuleInfo32.DriverPath.Buffer, pathSize, pDriver->Win.Path, NULL);
        if (!INT_SUCCESS(status))
        {
            HpFreeAndNullWithTag(&pDriver->Win.Path, IC_TAG_DRNU);
            pDriver->Win.PathHash = INITIAL_CRC_VALUE;
            pDriver->Win.PathLength = 0;
        }
        else
        {
            strlower_utf16(pDriver->Win.Path, pathSize / 2);
            pDriver->Win.PathLength = pathSize / 2;
            pDriver->Win.PathHash = Crc32Wstring(pDriver->Win.Path, INITIAL_CRC_VALUE);
        }

        nameSize = 0xFFFF & pModuleInfo32.DriverName.Length;

        // nameLength + 2 OK - pathLength is DWORD and is AND with 0xFFFF.
        pDriver->Name = HpAllocWithTag(nameSize + 2ull, IC_TAG_DRNU);
        if (NULL == pDriver->Name)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _cleanup_and_leave;
        }

        status = IntKernVirtMemRead(pModuleInfo32.DriverName.Buffer, nameSize, pDriver->Name, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed reading driver name from 0x%08x [%d]: 0x%08x\n",
                  pModuleInfo32.DriverName.Buffer, pModuleInfo32.DriverName.Length, status);
            goto _cleanup_and_leave;
        }

        strlower_utf16(pDriver->Name, nameSize / 2);
        pDriver->NameHash = Crc32Wstring(pDriver->Name, INITIAL_CRC_VALUE);
        pDriver->NameLength = nameSize / 2;
    }

    TRACE("[DRIVER] Driver '%s' @ 0x%016llx (base: 0x%016llx, hash: 0x%08x) just loaded\n",
          utf16_for_log(pDriver->Name), ModuleInfo, pDriver->BaseVa, pDriver->NameHash);

    if ((0 != (Flags & FLAG_DYNAMIC_DETECTION)) &&
        IS_KERNEL_POINTER_WIN(gGuest.Guest64, entryPoint) &&
        IntWinDrvHasDriverObject(pDriver))
    {
        // We will execute-protect the page with EP from the newly loaded driver. This way,
        // when the first instruction will get executed, we will be notified, and we'll have
        // a chance to protect the driver's driver object. As a cool stuff, the section with
        // the EP of any newly-loaded driver is always mapped in memory (will not be swapped
        // out). If it isn't, then we're dealing with a regular dll, and not a driver.

        status = IntHookObjectCreate(introObjectTypeKmModule, 0, &pDriver->Win.EpHookObject);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
            goto _cleanup_and_leave;
        }

        status = IntHookObjectHookRegion(pDriver->Win.EpHookObject,
                                         0,
                                         entryPoint & PAGE_MASK,
                                         PAGE_SIZE,
                                         IG_EPT_HOOK_EXECUTE,
                                         IntWinDrvHandleDriverEntry,
                                         pDriver,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectHookRegion failed: 0x%08x\n", status);
            goto _cleanup_and_leave;
        }
    }

    pProt = IntWinDrvIsProtected(pDriver);
    if (pProt)
    {
        status = IntWinDrvProtect(pDriver, pProt->RequiredFlags);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvProtect failed: 0x%08x\n", status);
        }
    }

    IntWinDrvSendEvent(pDriver, TRUE);

    InsertTailList(&gKernelDrivers, &pDriver->Link);

    return INT_STATUS_SUCCESS;

_cleanup_and_leave:
    if (!INT_SUCCESS(status) && (NULL != pDriver))
    {
        IntWinDrvRemoveEntry(pDriver);
    }

    return status;
}


INTSTATUS
IntWinDrvRemoveFromAddress(
    _In_ QWORD ModuleInfo
    )
///
/// @brief Removes a driver from the introspection's loaded modules list (#gKernelDrivers).
///
/// @param[in]  ModuleInfo  The #LDR_DATA_TABLE_ENTRY32 or #LDR_DATA_TABLE_ENTRY64 corresponding to the module.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD sizeOfImage;
    QWORD moduleBase;
    LDR_DATA_TABLE_ENTRY32 *pModuleInfo32 = NULL;
    LDR_DATA_TABLE_ENTRY64 *pModuleInfo64 = NULL;
    DWORD loadCount;

    if (gGuest.Guest64)
    {
        status = IntVirtMemMap(ModuleInfo, sizeof(*pModuleInfo64), gGuest.Mm.SystemCr3, 0, &pModuleInfo64);
    }
    else
    {
        status = IntVirtMemMap(ModuleInfo, sizeof(*pModuleInfo32), gGuest.Mm.SystemCr3, 0, &pModuleInfo32);
    }
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for GVA 0x%016llx: 0x%08x\n", ModuleInfo, status);
        return status;
    }

    if (pModuleInfo64)
    {
        sizeOfImage = 0xffffffff & pModuleInfo64->SizeOfImage;
        moduleBase = pModuleInfo64->DllBase;
        loadCount = pModuleInfo64->LoadCount;
    }
    else if (pModuleInfo32)
    {
        sizeOfImage = pModuleInfo32->SizeOfImage;
        moduleBase = (QWORD)pModuleInfo32->DllBase;
        loadCount = pModuleInfo32->LoadCount;
    }
    else
    {
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    if (loadCount > 1)
    {
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto _cleanup_and_leave;
    }

    status = INT_STATUS_NOT_FOUND;

    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        if (pDriver->BaseVa == moduleBase && pDriver->Size == sizeOfImage)
        {
            IntDriverCacheInv(pDriver->BaseVa, pDriver->Size);

            TRACE("[DRIVER] Driver 0x%016llx unloaded\n", pDriver->BaseVa);

            IntWinDrvSendEvent(pDriver, FALSE);

            RemoveEntryList(&pDriver->Link);

            status = IntWinDrvRemoveEntry(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvRemoveEntry failed: 0x%08x\n", status);
            }

            status = INT_STATUS_SUCCESS;

            goto _cleanup_and_leave;
        }
    }

    WARNING("[WARNING] Requested unload of the driver 0x%016llx with"
            "size 0x%08x, LDR 0x%016llx, but it wasn't found...\n",
            moduleBase, sizeOfImage, ModuleInfo);

_cleanup_and_leave:
    if (pModuleInfo64)
    {
        IntVirtMemUnmap(&pModuleInfo64);
    }
    else if (pModuleInfo32)
    {
        IntVirtMemUnmap(&pModuleInfo32);
    }

    return status;
}


INTSTATUS
IntWinProtectReadNtEat(
    void
    )
///
/// @brief Used to place a read hook on the ntoskrnl.exe EAT.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_NOT_READY;
    IMAGE_DATA_DIRECTORY dataDir = { 0 };
    DWORD eatRva;
    DWORD eatSize;

    if (!gGuest.KernelDriver)
    {
        goto exit;
    }

    if (gGuest.KernelDriver->Win.EatReadHook)
    {
        goto exit;
    }

    status = IntPeGetDirectory(0, gGuest.KernelDriver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT, &dataDir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
        goto exit;
    }

    eatRva = dataDir.VirtualAddress;
    eatSize = dataDir.Size;

    if (eatRva > gGuest.KernelDriver->Size ||
        eatSize > gGuest.KernelDriver->Size ||
        (QWORD)eatRva + eatSize > gGuest.KernelDriver->Size)
    {
        ERROR("[ERROR] eatRva/eatSize are not valid eatRva:0x%08x, eatSize:0x%08x, "
              "KernelBaseVa:0x%llx, KernelSize:0x%llx\n",
              eatRva, eatSize, gGuest.KernelDriver->BaseVa,
              gGuest.KernelDriver->Size);

        status = INT_STATUS_OUT_OF_RANGE;

        goto exit;
    }

    status = IntHookObjectHookRegion(gGuest.KernelDriver->HookObject,
                                     0,
                                     gGuest.KernelDriver->BaseVa + eatRva,
                                     eatSize,
                                     IG_EPT_HOOK_READ,
                                     IntWinDrvHandleRead,
                                     gGuest.KernelDriver,
                                     0,
                                     (HOOK_REGION_DESCRIPTOR **)&gGuest.KernelDriver->Win.EatReadHook);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed hooking EAT for ntoskrnl.exe 0x%08x\n", status);
    }

exit:
    return status;
}


INTSTATUS
IntWinUnprotectReadNtEat(
    void
    )
///
/// @brief Used to remove the EAT read hook from ntoskrnl.exe.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status = INT_STATUS_NOT_READY;

    if (!gGuest.KernelDriver)
    {
        goto exit;
    }

    if (!gGuest.KernelDriver->Win.EatReadHook)
    {
        goto exit;
    }

    status = IntHookObjectRemoveRegion((HOOK_REGION_DESCRIPTOR **)&gGuest.KernelDriver->Win.EatReadHook, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectRemoveRegion failed, status: 0x%08x\n", status);
    }
    gGuest.KernelDriver->Win.EatReadHook = NULL;

exit:
    return status;
}


static INTSTATUS
IntWinDrvHeadersInMemory(
    _In_ void *Context,
    _In_ QWORD Cr3,
    _In_ QWORD VirtualAddress,
    _In_ QWORD PhysicalAddress,
    _In_reads_bytes_(DataSize) void *Data,
    _In_ DWORD DataSize,
    _In_ DWORD Flags
    )
///
/// @brief This callback is called as soon as all the driver headers have been read using #IntSwapMemReadData.
///
/// @param[in]  Context             The #KERNEL_DRIVER structure.
/// @param[in]  Cr3                 The virtual address space.
/// @param[in]  VirtualAddress      The base virtual address read.
/// @param[in]  PhysicalAddress     The physical address of the first page (VirtualAddress) read.
/// @param[in]  Data                Buffer containing the read data. This will be freed once the callback returns!
/// @param[in]  DataSize            Size of the Data buffer. Will normally be equal to the Length
///                                 passed to read function.
/// @param[in]  Flags               Swap flags. Check out SWAPMEM_FLG* for more info.
///
/// @retval #INT_STATUS_SUCCESS  On success.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;
    IMAGE_SECTION_HEADER sec;
    DWORD i, iatSize, eatSize, iatRva, eatRva;
    QWORD sectionBase;
    BOOLEAN iatHooked, eatHooked;
    IMAGE_DATA_DIRECTORY dataDir = { 0 };
    INTRO_PE_INFO peInfo = { 0 };

    UNREFERENCED_PARAMETER(Cr3);
    UNREFERENCED_PARAMETER(VirtualAddress);
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(DataSize);

    pDriver = Context;

    pDriver->Win.HeadersSwapHandle = NULL;

    iatHooked = FALSE;
    eatHooked = FALSE;

    TRACE("[DRIVER] Adding protection on driver '%s' at %llx...\n",
          utf16_for_log(pDriver->Name), pDriver->BaseVa);

    pDriver->Win.MzPeHeaders = HpAllocWithTag(PAGE_SIZE, IC_TAG_HDRS);
    if (NULL == pDriver->Win.MzPeHeaders)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read the kernel headers and cache them internally for every protected driver.
    status = IntKernVirtMemRead(pDriver->BaseVa, PAGE_SIZE, pDriver->Win.MzPeHeaders, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    status = IntPeValidateHeader(pDriver->BaseVa, pDriver->Win.MzPeHeaders, PAGE_SIZE, &peInfo, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeValidateHeader failed: 0x%08x\n", status);
        return INT_STATUS_INVALID_OBJECT_TYPE;
    }

    // Get the base address of the section headers and set an EPT hook on every section that it's not writable.
    // The idea is that this way, we will protect the code, IAT, EAT with one shot, since both the IAT & EAT are
    // placed by the compiler inside a read-only section.

    pDriver->Win.TimeDateStamp = peInfo.TimeDateStamp;
    pDriver->EntryPoint = pDriver->BaseVa + peInfo.EntryPoint;

    sectionBase = pDriver->BaseVa + peInfo.SectionOffset;

    status = IntPeGetDirectory(0, pDriver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_IAT, &dataDir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
        return status;
    }

    iatRva = dataDir.VirtualAddress;
    iatSize = dataDir.Size;

    status = IntPeGetDirectory(0, pDriver->Win.MzPeHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT, &dataDir);
    if (!INT_SUCCESS(status) && status != INT_STATUS_NOT_FOUND)
    {
        ERROR("[ERROR] IntPeGetDirectory failed: 0x%08x\n", status);
        return status;
    }

    eatRva = dataDir.VirtualAddress;
    eatSize = dataDir.Size;

    TRACE("[DRIVER] %s @ 0x%016llx has timedate stamp 0x%08x and size 0x%08x\n",
          utf16_for_log(pDriver->Name), pDriver->BaseVa, pDriver->Win.TimeDateStamp, (DWORD)pDriver->Size);

    status = IntHookObjectCreate(introObjectTypeKmModule, 0, &pDriver->HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        return status;
    }

    for (i = 0; i < peInfo.NumberOfSections; i++)
    {
        BOOLEAN hookSection = FALSE, ignoreAlign = FALSE;
        QWORD secStart;
        QWORD secEnd;

        // section offset + current section + sizeof section < PAGE_SIZE
        if (pDriver->Win.MzPeHeaders && (peInfo.SectionOffset + i * sizeof(sec) + sizeof(sec) < PAGE_SIZE))
        {
            memcpy(&sec, pDriver->Win.MzPeHeaders + peInfo.SectionOffset + i * sizeof(sec), sizeof(sec));
        }
        else
        {
            status = IntKernVirtMemRead(sectionBase + i * sizeof(sec), sizeof(sec), &sec, NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed reading IMAGE_SECTION_HEADER %d for driver 0x%016llx\n", i, pDriver->BaseVa);
                continue;
            }
        }

        // Skip NULL sections.
        if (0 == sec.Misc.VirtualSize)
        {
            continue;
        }

        secStart = pDriver->BaseVa + sec.VirtualAddress;
        secEnd = secStart + ROUND_UP((QWORD)sec.Misc.VirtualSize, peInfo.SectionAlignment);

        hookSection = (!(sec.Characteristics & IMAGE_SCN_MEM_WRITE)) &&     // section must not be writable
                      (!(sec.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)); // section must not be discardable

        // Special ntoskrnl.exe treatment for some sections.
        if (pDriver->BaseVa == gGuest.KernelVa)
        {
            // Special treatment for INITKDBG section, which is overwritten by kdcom anyway...
            if (memcmp(sec.Name, "INITKDBG", 8) == 0)
            {
                TRACE("[DRIVER] Skipping section INITKDBG...\n");
                continue;
            }

            // Special treatment for ERRATA section (windows 10 BETA [the after the official release])
            if (memcmp(sec.Name, "ERRATA", 6) == 0)
            {
                TRACE("[DRIVER] Skipping section ERRATA on build %d...\n", gGuest.OSVersion);
                continue;
            }

            if (memcmp(sec.Name, "ALMOSTRO", 8) == 0)
            {
                // Override the hookSection flag, as even if the ALMOSTRO section contains the KeServiceDescriptorTable
                // which we want to hook.
                if (gWinGuest->KeServiceDescriptorTable >= secStart &&
                    gWinGuest->KeServiceDescriptorTable < secEnd)
                {
                    TRACE("[DRIVER] Overriding the hook flag, will hook ALMOSTRO section...\n");
                    hookSection = ignoreAlign = TRUE;
                    secStart = gWinGuest->KeServiceDescriptorTable;
                    secEnd = secStart + KESDT_SIZE;
                }
            }
        }

        if ((0 == iatRva) ||
            ((hookSection) && IN_RANGE_LEN(iatRva, sec.VirtualAddress, sec.Misc.VirtualSize) &&
             IN_RANGE_LEN(iatRva + iatSize, sec.VirtualAddress, sec.Misc.VirtualSize + 1)))
        {
            iatHooked = TRUE;
        }

        if ((0 == eatRva) ||
            ((hookSection) && IN_RANGE_LEN(eatRva, sec.VirtualAddress, sec.Misc.VirtualSize) &&
             IN_RANGE_LEN(eatRva + eatSize, sec.VirtualAddress, sec.Misc.VirtualSize + 1)))
        {
            eatHooked = TRUE;
        }

        // Now hook the section, if we can
        if (hookSection)
        {
            // Handle overlapping section (Xen drivers workaround).
            if (!ignoreAlign && ((secStart % PAGE_SIZE != 0) || (secEnd % PAGE_SIZE != 0)))
            {
                IMAGE_SECTION_HEADER sec2 = { 0 };
                QWORD lastPage = (secEnd - 1) & PAGE_MASK;
                QWORD firstPage = secStart & PAGE_MASK;
                DWORD k;
                BOOLEAN lowOverlap = FALSE, highOverlap = FALSE;

                WARNING("[WARNING] Section %d of driver '%s' is not aligned (%llx:%llx): alignment %x\n",
                        i, utf16_for_log(pDriver->Name), secStart, secEnd, peInfo.SectionAlignment);

                // Section is not aligned, make sure there is no other writable section that starts in the last page of
                // this section or ends in the first page of it.
                for (k = 0; k < peInfo.NumberOfSections; k++)
                {
                    QWORD curSecStart = 0, curSecEnd = 0, curLastPage = 0, curFirstPage = 0;

                    if (pDriver->Win.MzPeHeaders && (peInfo.SectionOffset + k * sizeof(sec) + sizeof(sec) < PAGE_SIZE))
                    {
                        memcpy(&sec2, pDriver->Win.MzPeHeaders + peInfo.SectionOffset + k * sizeof(sec2), sizeof(sec2));
                    }
                    else
                    {
                        status = IntKernVirtMemRead(sectionBase + k * sizeof(sec2),
                                                    sizeof(sec2),
                                                    &sec2,
                                                    NULL);
                        if (!INT_SUCCESS(status))
                        {
                            ERROR("[ERROR] Failed reading IMAGE_SECTION_HEADER %d for driver %llx\n",
                                  k, pDriver->BaseVa);
                            continue;
                        }
                    }

                    curSecStart = pDriver->BaseVa + sec2.VirtualAddress;
                    curSecEnd = curSecStart + ROUND_UP((QWORD)sec2.Misc.VirtualSize, peInfo.SectionAlignment);

                    curLastPage = (curSecEnd - 1) & PAGE_MASK;
                    curFirstPage = curSecStart & PAGE_MASK;

                    // Check if the ends of this section is inside a page where a writable section starts.
                    if ((lastPage == curFirstPage) && (0 != (sec2.Characteristics & IMAGE_SCN_MEM_WRITE)))
                    {
                        WARNING("[WARNING] Section %d overlaps writable section %d (%llx:%llx - %llx:%llx)!\n",
                                i, k, secStart, secEnd, curSecStart, curSecEnd);

                        highOverlap = TRUE;
                    }

                    // Check if the beginning of this section is inside a page where a writable section ends.
                    if ((firstPage == curLastPage) && (0 != (sec2.Characteristics & IMAGE_SCN_MEM_WRITE)))
                    {
                        WARNING("[WARNING] Section %d overlaps writable section %d (%llx:%llx - %llx:%llx)!\n",
                                i, k, secStart, secEnd, curSecStart, curSecEnd);

                        lowOverlap = TRUE;
                    }
                }

                if (highOverlap)
                {
                    // Re-align the page end down to a page-size multiple.
                    secEnd &= PAGE_MASK;
                }

                if (lowOverlap)
                {
                    // Re-align the page start up to a page-size multiple.
                    secStart = (secStart & PAGE_MASK) + 0x1000;
                }
            }

            if (secStart >= secEnd)
            {
                WARNING("[WARNING] Section %d overlaps entirely writable sections; will not hook it.\n", i);
                continue;
            }

            status = IntHookObjectHookRegion(pDriver->HookObject,
                                             0,
                                             secStart,
                                             secEnd - secStart,
                                             IG_EPT_HOOK_WRITE,
                                             IntWinDrvHandleWrite,
                                             pDriver,
                                             0,
                                             NULL);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed hooking section %d for driver 0x%016llx: 0x%08x\n", i, pDriver->BaseVa, status);
                continue;
            }
        }
    }

    // Hook the IAT, if it wasn't hooked already.
    if (!iatHooked)
    {
        status = IntHookObjectHookRegion(pDriver->HookObject,
                                         0,
                                         pDriver->BaseVa + iatRva,
                                         iatSize,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinDrvHandleWrite,
                                         pDriver,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking IAT for driver 0x%016llx: 0x%08x\n", pDriver->BaseVa, status);
        }
    }

    // Hook the EAT, if it wasn't hooked already.
    if (!eatHooked)
    {
        status = IntHookObjectHookRegion(pDriver->HookObject,
                                         0,
                                         pDriver->BaseVa + eatRva,
                                         eatSize,
                                         IG_EPT_HOOK_WRITE,
                                         IntWinDrvHandleWrite,
                                         pDriver,
                                         0,
                                         NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed hooking IAT for driver 0x%016llx: 0x%08x\n", pDriver->BaseVa, status);
        }


    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_NT_EAT_READS)
    {
        if (pDriver->BaseVa == gGuest.KernelVa && gWinGuest)
        {
            gGuest.KernelDriver = pDriver;
            status = IntWinProtectReadNtEat();
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] Failed hooking EAT for ntoskrnl.exe, failed: 0x%08x\n", status);
            }
        }
    }

    pDriver->Protected = TRUE;

    return status;
}


INTSTATUS
IntWinDrvProtect(
    _In_ KERNEL_DRIVER *Driver,
    _In_ QWORD ProtectionFlag
    )
///
/// @brief  Used to enable protection for the given driver.
///
/// @param[in] Driver            The driver to be protected.
/// @param[in] ProtectionFlag    The protection flag.
///
/// @retval #INT_STATUS_SUCCESS                      On success.
/// @retval #INT_STATUS_ALREADY_INITIALIZED_HINT     If the driver is already protected.
/// @retval #INT_STATUS_INVALID_PARAMETER_1          If the driver is NULL.
///
{
    if (NULL == Driver)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (Driver->Protected)
    {
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    Driver->Protected = TRUE;
    Driver->ProtectionFlag = ProtectionFlag;

    return IntSwapMemReadData(0, Driver->BaseVa, PAGE_SIZE, SWAPMEM_OPT_NO_FAULT, Driver, 0,
                              IntWinDrvHeadersInMemory, NULL, &Driver->Win.HeadersSwapHandle);
}


INTSTATUS
IntWinDrvUnprotect(
    _In_ KERNEL_DRIVER *Driver
    )
///
/// @brief  Used to disable protection for the given driver.
///
/// @param[in] Driver    The driver to be removed from protection.
///
/// @retval #INT_STATUS_SUCCESS                  On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1      If the driver is NULL.
///
{
    if (NULL == Driver)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!Driver->Protected)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    TRACE("[DRIVER] Removing protection on module '%s' at %llx...\n",
          utf16_for_log(Driver->Name), Driver->BaseVa);

    if (NULL != Driver->Win.MzPeHeaders)
    {
        HpFreeAndNullWithTag(&Driver->Win.MzPeHeaders, IC_TAG_HDRS);
    }

    if (NULL != Driver->HookObject)
    {
        IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Driver->HookObject, 0);
    }

    if (NULL != Driver->Win.HeadersSwapHandle)
    {
        IntSwapMemRemoveTransaction(Driver->Win.HeadersSwapHandle);

        Driver->Win.HeadersSwapHandle = NULL;
    }

    Driver->Protected = FALSE;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvHandleDriverEntry(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Used to notify the introspection engine when the DriverEntry of a module starts executing.
///
/// This hook will be established on the page containing the EP of freshly loaded drivers. On the execution of
/// the first EP instruction, we will be notified, and we will be able to retrieve the driver-object associated
/// to that driver, and hook it, if needed.
///
/// @param[in]      Context     User-supplied context (may contain anything, including NULL).
/// @param[in]      Hook        The GPA hook associated to this callback.
/// @param[in]      Address     GPA address that was accessed.
/// @param[out]     Action      Desired action (allow, block).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;
    PWIN_DRIVER_OBJECT pDrvObj;
    IG_ARCH_REGS *pRegs;
    QWORD guestAddress;

    UNREFERENCED_PARAMETER(Address);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    guestAddress = 0;
    pDrvObj = NULL;
    pDriver = Context;

    pRegs = &gVcpu->Regs;

    if (pRegs->Rip != pDriver->EntryPoint)
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    if (gGuest.Guest64)
    {
        guestAddress = pRegs->Rcx;
    }
    else
    {
        status = IntKernVirtMemFetchDword(pRegs->Rsp + 4, (DWORD *)&guestAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemPatchDword failed: 0x%08x\n", status);
        }
    }

    if (IntWinDrvObjIsValidDriverObject(guestAddress))
    {
        status = IntWinDrvObjCreateFromAddress(guestAddress, FALSE, &pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjCreateDriverObject failed: 0x%08x\n", status);
            pDrvObj = NULL;
        }

        pDriver->Win.DriverObject = pDrvObj;
    }

    if (NULL != pDriver->Win.EpHookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&pDriver->Win.EpHookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed: 0x%08x\n", status);
        }
    }

    // we will allow the action, and we don't want notifications to be sent to LINUX/Winguest.
    *Action = introGuestRetry;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinDrvSendAlert(
    _In_ KERNEL_DRIVER *Driver,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends a driver related EPT violation alert.
///
/// @param[in]      Driver      The driver for which the violation took place.
/// @param[in]      Victim      The victim.
/// @param[in]      Originator  The originator.
/// @param[in]      Action      Taken action.
/// @param[in]      Reason      Reason for the taken reason.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;
    PEVENT_EPT_VIOLATION pEptViol;
    PIG_ARCH_REGS regs;

    regs = &gVcpu->Regs;

    pEptViol = &gAlert.Ept;
    memzero(pEptViol, sizeof(*pEptViol));

    pEptViol->Header.Action = Action;
    pEptViol->Header.Reason = Reason;

    if (!!(Victim->ZoneFlags & ZONE_READ))
    {
        pEptViol->Header.MitreID = idExploitRemote;
    }
    else
    {
        pEptViol->Header.MitreID = idRootkit;
    }

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertEptFillFromKmOriginator(Originator, pEptViol);
    IntAlertEptFillFromVictimZone(Victim, pEptViol);

    pEptViol->Header.Flags = IntAlertCoreGetFlags(Driver->ProtectionFlag, Reason);

    IntAlertFillWinProcessByCr3(regs->Cr3, &pEptViol->Header.CurrentProcess);

    IntAlertFillCodeBlocks(Originator->Original.Rip, regs->Cr3, FALSE, &pEptViol->CodeBlocks);
    IntAlertFillExecContext(0, &pEptViol->ExecContext);

    IntAlertFillVersionInfo(&pEptViol->Header);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvHandleWrite(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Used to notify the introspection engine when a write took place on a protected driver.
///
/// @param[in]      Context     The driver for which the violation took place (#KERNEL_DRIVER structure).
/// @param[in]      Hook        The GPA hook associated to this callback.
/// @param[in]      Address     GPA address that was accessed.
/// @param[out]     Action      Desired action (allow, block).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTSTATUS status;
    INTRO_ACTION_REASON reason;
    BOOLEAN exitAfterInformation;
    KERNEL_DRIVER *pDriver;

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    UNREFERENCED_PARAMETER(Hook);

    STATS_ENTER(statsExceptionsKern);

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    // By default we do not allow this
    *Action = introGuestNotAllowed;
    reason = introReasonUnknown;
    exitAfterInformation = FALSE;
    pDriver = Context;

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(pDriver,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeKmModule,
                                   ZONE_WRITE,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        reason = introReasonInternalError;
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(pDriver->ProtectionFlag, Action, &reason))
    {
        IntWinDrvSendAlert(pDriver, &victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(pDriver->ProtectionFlag, Action);

    return status;
}


static KERNEL_DRIVER *
IntWinGetDriverByGva(
    _In_ QWORD Rip
    )
///
/// @brief  Iterates all the loaded drivers to see if the Rip points inside any of them.
///
/// @param[in]  Rip The RIP to be checked.
///
/// @retval     The #KERNEL_DRIVER structure of the originating driver.
/// @retval     NULL if the Rip does NOT points inside a known driver.
///
{
    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        if (Rip >= pDriver->BaseVa && Rip < pDriver->BaseVa + pDriver->Size)
        {
            return pDriver;
        }
    }

    return NULL;
}


static INTSTATUS
IntWinDrvForceDisableReadNtEat(
    _In_ KERNEL_DRIVER *CurrentOriginator
    )
///
/// @brief  This function is used to disable the #INTRO_OPT_PROT_KM_NT_EAT_READS by removing the
/// hook #IntWinDrvHandleRead.
///
/// In some cases, a known driver could read the NT EAT so many times that a significant performance impact will be
/// noticed (even if all the reads are allowed). After reaching a predetermined threshold, the
/// #INTRO_OPT_PROT_KM_NT_EAT_READS option will be disabled so that the system will not "hang" and the integrator will
/// be notified.
///
/// @param[in]      CurrentOriginator       The last driver that read the EAT (in is not necessarily the driver that
///                                         performed all the reads, although is highly likely).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;

    if (!CurrentOriginator)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (!gGuest.KernelDriver)
    {
        return INT_STATUS_NOT_INITIALIZED;
    }

    ERROR("[ERROR] We have reached %llu reads from ntoskrnl.exe EAT, last driver %s, disabling protection\n",
          gGuest.KernelDriver->Win.EatReadCount, utf16_for_log(CurrentOriginator->Name));

    status = IntWinUnprotectReadNtEat();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinUnprotectReadNtEat failed: 0x%08x\n", status);
    }

    IntGuestUpdateCoreOptions(gGuest.CoreOptions.Current & ~INTRO_OPT_PROT_KM_NT_EAT_READS);
    gGuest.KernelDriver->Win.EatReadCount = 0;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvHandleRead(
    _In_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief  Used to notify the introspection engine when a read took place on a protected driver
/// (used only for ntoskrnl.exe).
///
/// @param[in]      Context     The driver for which the violation took place (#KERNEL_DRIVER structure).
/// @param[in]      Hook        The GPA hook associated to this callback.
/// @param[in]      Address     GPA address that was accessed.
/// @param[out]     Action      Desired action (allow, block).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    EXCEPTION_VICTIM_ZONE victim;
    EXCEPTION_KM_ORIGINATOR originator;
    INTSTATUS status;
    INTRO_ACTION_REASON reason;
    KERNEL_DRIVER *pDriver;
    KERNEL_DRIVER *pOriginatingDriver;
    BOOLEAN exitAfterInformation;
    QWORD ripPage;

#define NTOSKRNL_RIP_PAGES_COUNT    20
#define PATCHGUARD_RIP_COUNT        4
#define MAX_KNOWN_DRIVER_READS      100000

    static QWORD ntoskrnlRipPages[NTOSKRNL_RIP_PAGES_COUNT] = { 0 };
    static DWORD ntoskrnlRipPagesCount = 0;

    static QWORD patchguardRip[PATCHGUARD_RIP_COUNT] = { 0 };
    static DWORD patchguardRipCount = 0;

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    // By default we allow this
    *Action = introGuestAllowed;
    reason = introReasonAllowed;
    pDriver = Context;
    status = INT_STATUS_SUCCESS;
    exitAfterInformation = FALSE;

    STATS_ENTER(statsNtEatRead);

    // The ntoskrnl.exe also reads its own EAT - multiple RIPs that are contained within a few pages.
    // In order to increase the performance, we are going to save the pages (one by one when the
    // originator.Return.Driver is ntoskrnl.exe) and compare the current RIP page value with stored values.
    ripPage = gVcpu->Regs.Rip & PAGE_MASK;
    for (DWORD i = 0; i < ntoskrnlRipPagesCount; i++)
    {
        if (ntoskrnlRipPages[i] == ripPage)
        {
            goto exit;
        }
    }

    // The PatchGuard usually reads the EAT multiple times from a few RIPs (none of which are inside any known module).
    // In order to increase the performance, we are going to save the RIPs (one by one when the
    // originator.Original.Driver  is NULL and we match the exceptions) and compare the current RIP value with
    // stored values.
    for (DWORD i = 0; i < patchguardRipCount; i++)
    {
        if (patchguardRip[i] == gVcpu->Regs.Rip)
        {
            goto exit;
        }
    }

    // If the read originates from within one of our own agents - allow.
    if (IntWinAgentIsRipInsideCurrentAgent(gVcpu->Regs.Rip))
    {
        goto exit;
    }

    // If the read originates from within a known driver - allow.
    pOriginatingDriver = IntWinGetDriverByGva(gVcpu->Regs.Rip);
    if (pOriginatingDriver)
    {
        if (pOriginatingDriver->BaseVa == gGuest.KernelVa)
        {
            TRACE("[DRIVER] Saving ntoskrnl.exe page:0x%llx\n", gVcpu->Regs.Rip & PAGE_MASK);
            ntoskrnlRipPages[(ntoskrnlRipPagesCount++) % NTOSKRNL_RIP_PAGES_COUNT] = gVcpu->Regs.Rip & PAGE_MASK;
        }
        else
        {
            gGuest.KernelDriver->Win.EatReadCount++;

            if (MAX_KNOWN_DRIVER_READS == gGuest.KernelDriver->Win.EatReadCount)
            {
                status = IntWinDrvForceDisableReadNtEat(pOriginatingDriver);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntWinDrvDisableReadNtEat failed: 0x%08x\n", status);
                }
            }
        }

        goto exit;
    }

    memzero(&victim, sizeof(victim));
    memzero(&originator, sizeof(originator));

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        exitAfterInformation = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting originator: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    status = IntExceptGetVictimEpt(pDriver,
                                   Address,
                                   IntHookGetGlaFromGpaHook(Hook, Address),
                                   introObjectTypeKmModule,
                                   ZONE_READ,
                                   &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting zone details: 0x%08x\n", status);
        reason = introReasonInternalError;
        exitAfterInformation = TRUE;
    }

    if (exitAfterInformation)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    // This is the probably PatchGuard. We are going to store its RIP.
    if (introGuestAllowed == *Action)
    {
        TRACE("[DRIVER] Saving PatchGuard RIP:0x%llx\n", gVcpu->Regs.Rip);
        patchguardRip[(patchguardRipCount++) % PATCHGUARD_RIP_COUNT] = gVcpu->Regs.Rip;
    }

    if (IntPolicyCoreTakeAction(pDriver->ProtectionFlag, Action, &reason))
    {
        IntWinDrvSendAlert(pDriver, &victim, &originator, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(pDriver->ProtectionFlag, Action);

exit:
    STATS_EXIT(statsNtEatRead);

#undef NTOSKRNL_RIP_PAGES_COUNT
#undef PATCHGUARD_RIP_COUNT
#undef MAX_KNOWN_DRIVER_READS

    return status;
}


static INTSTATUS
IntWinDrvFreeEntry(
    _In_ KERNEL_DRIVER *Driver,
    _In_ QWORD Reserved
    )
///
/// @brief Frees the memory allocate for the #KERNEL_DRIVER structure.
///
/// @param[in]  Driver      The driver to be freed.
/// @param[in]  Reserved    Reserved for further use.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    UNREFERENCED_PARAMETER(Reserved);

    if (NULL != Driver->Win.Path)
    {
        HpFreeAndNullWithTag(&Driver->Win.Path, IC_TAG_DRNU);
    }

    if (NULL != Driver->Name)
    {
        HpFreeAndNullWithTag(&Driver->Name, IC_TAG_DRNU);
    }

    if (NULL != Driver->Win.MzPeHeaders)
    {
        HpFreeAndNullWithTag(&Driver->Win.MzPeHeaders, IC_TAG_HDRS);
    }

    HpFreeAndNullWithTag(&Driver, IC_TAG_MODU);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinDrvRemoveEntry(
    _In_ KERNEL_DRIVER *Driver
    )
///
/// @brief Removes the #KERNEL_DRIVER from the internal structures.
///
/// @param[in]  Driver The driver to be removed.
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    INTSTATUS status;

    if (NULL == Driver)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntWinDrvUnprotect(Driver);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinModuleUnHook failed: 0x%08x\n", status);
    }

    if (NULL != Driver->Win.EpHookObject)
    {
        IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Driver->Win.EpHookObject, 0);
    }

    if (NULL != Driver->Win.DriverObject)
    {
        PWIN_DRIVER_OBJECT pDrvObj = Driver->Win.DriverObject;

        RemoveEntryList(&pDrvObj->Link);

        status = IntWinDrvObjRemove(pDrvObj);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvObjRemoveDriverObject failed: 0x%08x\n", status);
        }

        Driver->Win.DriverObject = NULL;
    }

    status = IntWinDrvFreeEntry(Driver, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinDrvFreeEntry failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinDrvUpdateProtection(
    void
    )
///
/// @brief Used to update the protection for all the loaded modules (#gKernelDrivers).
///
/// @retval #INT_STATUS_SUCCESS      On success.
///
{
    TRACE("[DRIVER] Updating kernel drivers protections...\n");

    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        INTSTATUS status;

        const PROTECTED_MODULE_INFO *pProtInfo = IntWinDrvIsProtected(pDriver);

        if (!pDriver->Protected && (NULL != pProtInfo))
        {
            status = IntWinDrvProtect(pDriver, pProtInfo->RequiredFlags);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvProtect failed for '%s': 0x%08x\n",
                      utf16_for_log(pDriver->Name), status);
            }
        }
        else if (pDriver->Protected && (NULL == pProtInfo))
        {
            status = IntWinDrvUnprotect(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvUnprotect failed for '%s': 0x%08x\n",
                      utf16_for_log(pDriver->Name), status);
            }
        }
    }

    return INT_STATUS_SUCCESS;
}
