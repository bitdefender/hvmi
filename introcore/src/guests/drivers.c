/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "drivers.h"
#include "guests.h"

/// @brief  List of all the drivers currently loaded inside the guest.
///
/// Can always be safely used.
LIST_HEAD gKernelDrivers = LIST_HEAD_INIT(gKernelDrivers);

/// @brief  Iterates the #gKernelDrivers linked list.
///
/// Can be used to safely iterate the drivers list. The current driver pointed to by _var_name can safely be removed
/// from the list, but note that removing other drivers while iterating the list using this macro is not a valid
/// operation and can corrupt the list.
///
/// @param[in]  _var_name   The name of the variable in which the #KERNEL_DRIVER pointer will be placed. This variable
///                         will be declared by the macro an available only in the context created by the macro.
#define for_each_driver(_var_name) list_for_each (gKernelDrivers, KERNEL_DRIVER, _var_name)

/// @brief  Maximum entries inside the #DRIVER_EXPORT_CACHE.
#define MAX_DRIVER_EXPORT_CACHE_ENTRIES 10

///
/// @brief  Driver export cache.
///
typedef struct _DRIVER_EXPORT_CACHE
{
    /// @brief  The number of valid entries inside the Entry array.
    WORD                        CurrentEntry;
    /// @brief  The cache entries.
    DRIVER_EXPORT_CACHE_ENTRY   Entry[MAX_DRIVER_EXPORT_CACHE_ENTRIES];
} DRIVER_EXPORT_CACHE, *PDRIVER_EXPORT_CACHE;

/// @brief  The driver exports cache.
///
/// This is used in order to validate that a guest RIP points inside a driver, without the need of actually
/// parsing the driver exports.
static DRIVER_EXPORT_CACHE gDriverExportCache = {0};


INTSTATUS
IntDriverLoadHandler(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a guest loads a new driver.
/// @ingroup    group_detours
///
/// This handles driver loading in both Windows and Linux OSs. It simply gathers the arguments from the guest and
/// delegates the driver loading event to #IntLixDrvCreateFromAddress or #IntWinDrvCreateFromAddress. If one of
/// this function fails Introcore will try to trap to a debugger.
///
/// @param[in]  Detour  The detour handle. Ignored.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    INTSTATUS status;
    IG_ARCH_REGS const *pRegs = &gVcpu->Regs;

    UNREFERENCED_PARAMETER(Detour);

    if (gGuest.OSType == introGuestLinux)
    {
        status = IntLixDrvCreateFromAddress(pRegs->R8, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixDrvCreateFromAddress failed for module 0x%016llx: 0x%08x\n", pRegs->Rdi, status);
            IntDbgEnterDebugger();
        }
    }
    else
    {
        QWORD args[2];
        QWORD ldrAddress;
        DWORD load;

        status = IntDetGetArguments(Detour, 2, args);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetGetArguments failed: 0x%08x\n", status);
            return status;
        }

        ldrAddress = args[0];
        load = (args[1] & 0xFFFFFFFF) > 0;

        // The module is unloading, we are not interested in this, we already caught that...
        if (!load)
        {
            return INT_STATUS_SUCCESS;
        }

        status = IntWinDrvCreateFromAddress(ldrAddress, FLAG_DYNAMIC_DETECTION);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinDrvCreateFromAddress failed for GVA 0x%016llx: 0x%08x\n", ldrAddress, status);
            IntDbgEnterDebugger();
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntDriverUnloadHandler(
    _In_ void const *Detour
    )
///
/// @brief      The detour handler that will be invoked when a guest driver is unloaded.
/// @ingroup    group_detours
///
/// This handles driver unloading for both Windows and Linux OSs. It simply gathers the arguments from the guest and
/// delegates the driver unloading event to #IntLixDrvRemoveFromAddress or #IntWinDrvRemoveFromAddress. If one of
/// this function fails introcore will try to trap to a debugger.
///
/// @param[in]  Detour  The detour handle. Ignored.
///
/// @returns    #INT_STATUS_SUCCESS is always returned.
///
{
    INTSTATUS status;
    IG_ARCH_REGS const *pRegs = &gVcpu->Regs;

    UNREFERENCED_PARAMETER(Detour);

    if (gGuest.OSType == introGuestLinux)
    {
        status = IntLixDrvRemoveFromAddress(pRegs->R8);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixDrvRemoveFromAddress failed for GVA 0x%016llx: 0x%08x\n", pRegs->Rdi, status);
            IntDbgEnterDebugger();
        }
    }
    else
    {
        QWORD ldrAddress = 0;

        status = IntDetGetArgument(Detour, 0, NULL, 0, &ldrAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetGetArgument failed: 0x%08x\n", status);
            return status;
        }

        status = IntWinDrvRemoveFromAddress(ldrAddress);
        if (!INT_SUCCESS(status) && (INT_STATUS_NOT_FOUND != status))
        {
            ERROR("[ERROR] IntWinDrvRemoveFromAddress failed for GVA 0x%016llx: 0x%08x\n", ldrAddress, status);
            IntDbgEnterDebugger();
        }
    }

    return INT_STATUS_SUCCESS;
}


KERNEL_DRIVER *
IntDriverFindByAddress(
    _In_ QWORD Gva
    )
///
/// @brief      Returns the driver in which Gva resides.
///
/// For Windows guests, this will check that Gva is inside a kernel module and will return the appropriate driver.
/// For Linux guests, if the module is initialized, this will check that the Gva is inside a kernel module and
/// will return the appropriate driver; if the module is not initialized, this will check that Gva is inside the
/// 'init_layout' memory region.
///
/// @param[in]  Gva     The searched guest virtual address.
///
/// @returns    A pointer to a #KERNEL_DRIVER structure, or NULL if Gva is not inside a driver.
///
{
    for_each_driver(pDriver)
    {
        if (pDriver->BaseVa <= Gva && pDriver->BaseVa + pDriver->Size > Gva)
        {
            return pDriver;
        }
    }

    if (gGuest.OSType == introGuestWindows)
    {
        return NULL;
    }

    for_each_driver(pDriver)
    {
        if (pDriver->Lix.Initialized)
        {
            continue;
        }

        if (IN_RANGE_LEN(Gva, pDriver->Lix.InitLayout.Base, pDriver->Lix.InitLayout.Size))
        {
            return pDriver;
        }
    }

    return NULL;
}


KERNEL_DRIVER *
IntDriverFindByBase(
    _In_ QWORD Gva
    )
///
/// @brief      Searches a driver object by its module base.
///
/// @param[in]  Gva     Guest virtual address to search for.
///
/// @returns    A pointer to a #KERNEL_DRIVER structure, or NULL if Gva is not inside a driver.
///
{
    for_each_driver(pDriver)
    {
        if (pDriver->BaseVa == Gva)
        {
            return pDriver;
        }
    }

    return NULL;
}


KERNEL_DRIVER *
IntDriverFindByLoadOrder(
    _In_ DWORD LoadOrder
    )
///
/// @brief      Searches a driver by its module load order.
///
/// The load order is the order in which the drivers were added to the #gKernelDrivers list. For Windows drivers,
/// the driver at position 0 is always ntoskrnl.exe, while the driver at position 1 is always hal.dll.
///
/// @param[in]  LoadOrder   The index inside the list.
///
/// @returns    A pointer to a #KERNEL_DRIVER structure, or NULL if no driver is found.
///
{
    DWORD currentPosition = 0;

    for_each_driver(pDriver)
    {
        if (LoadOrder == currentPosition)
        {
            return pDriver;
        }

        currentPosition++;
    }

    return NULL;
}


KERNEL_DRIVER *
IntDriverFindByName(
    _In_ const void *Name
    )
///
/// @brief      Searches for a driver by its name.
///
/// @param[in]  Name    NULL-terminated string with the driver name. For Windows guests this must be a wide char
///                     string; for Linux guests it must be a char string.
///
/// @returns    A pointer to a #KERNEL_DRIVER structure, or NULL if no driver is found.
///
{
    if (NULL == Name)
    {
        return NULL;
    }

    for_each_driver(pDriver)
    {
        int cmp = 1;

        if (NULL == pDriver->Name)
        {
            continue;
        }

        if (gGuest.OSType == introGuestWindows)
        {
            cmp = wstrcasecmp(Name, pDriver->Name);
        }
        else
        {
            cmp = strcmp(pDriver->Name, Name);
        }

        if (0 == cmp)
        {
            return pDriver;
        }
    }

    return NULL;
}


KERNEL_DRIVER *
IntDriverFindByPath(
    _In_ const WCHAR *Path
    )
///
/// @brief      Searches for a driver by its module path.
///
/// This function always returns NULL for Linux guests.
///
/// @param[in]  Path    NULL-terminated string with the kernel module path.
///
/// @returns    A pointer to a #KERNEL_DRIVER structure, or NULL if no driver is found.
///
{
    // We have no path on Linux, so no need for it
    if (introGuestLinux == gGuest.OSType)
    {
        return NULL;
    }

    if (NULL == Path)
    {
        return NULL;
    }

    for_each_driver(pDriver)
    {
        if (NULL == pDriver->Win.Path)
        {
            continue;
        }

        if (0 == wstrcasecmp(Path, pDriver->Win.Path))
        {
            return pDriver;
        }
    }

    return NULL;
}


void
IntDriverUninit(
    void
    )
///
/// @brief  Uninitializes the drivers submodule.
///
/// This will free every driver inside the #gKernelDrivers list. The actual remove operation is delegated to
/// #IntLixDrvRemoveEntry or #IntWinDrvRemoveEntry.
///
{
    for_each_driver(pDriver)
    {
        INTSTATUS status;

        RemoveEntryList(&pDriver->Link);

        if (gGuest.OSType == introGuestLinux)
        {
            status = IntLixDrvRemoveEntry(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixDrvRemoveEntry failed: 0x%08x\n", status);
            }
        }
        else
        {
            status = IntWinDrvRemoveEntry(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinDrvRemoveEntry failed: 0x%08x\n", status);
            }
        }
    }
}


void
IntDriverDump(
    void
    )
///
/// @brief  Prints all the currently loaded drivers.
///
{
    DWORD i = 0;

    for_each_driver(pDriver)
    {
        if (gGuest.OSType == introGuestLinux)
        {
            LOG("  #%03d I: %d, Core: 0x%016llx, CoreSize: 0x%08llx, CoreTextSize: 0x%08x, "
                "CoreRoSize: 0x%08x, Name: '%s'\n",
                i++,
                pDriver->Lix.Initialized,
                pDriver->BaseVa,
                pDriver->Size,
                pDriver->Lix.CoreLayout.TextSize,
                pDriver->Lix.CoreLayout.RoSize,
                (char *)pDriver->Name);
        }
        else
        {
            LOG("  #%03d Base: 0x%016llx, Size: 0x%08llx, PathHash: 0x%08x, NameHash: 0x%08x, Name: '%s'\n",
                i++, pDriver->BaseVa, pDriver->Size, pDriver->Win.PathHash,
                pDriver->NameHash, utf16_for_log(pDriver->Name));

            if (pDriver->Win.DriverObject)
            {
                LOG("------> 0x%016llx : %s\n",
                    pDriver->Win.DriverObject->DriverObjectGva,
                    utf16_for_log(((PWIN_DRIVER_OBJECT)pDriver->Win.DriverObject)->Name));
            }
        }
    }
}


void
IntDriverCacheCreateExport(
    _In_ const QWORD Rip
    )
///
/// @brief      Adds a new export entry to the #gDriverExportCache.
///
/// If the cache is full, it is reset.
///
/// @param[in]  Rip     The guest RIP for which this entry is created.
///
{
    if (gDriverExportCache.CurrentEntry == MAX_DRIVER_EXPORT_CACHE_ENTRIES)
    {
        gDriverExportCache.CurrentEntry = 0;
    }

    memzero(&gDriverExportCache.Entry[gDriverExportCache.CurrentEntry], sizeof(DRIVER_EXPORT_CACHE_ENTRY));

    gDriverExportCache.Entry[gDriverExportCache.CurrentEntry].Rip = Rip;
    gDriverExportCache.Entry[gDriverExportCache.CurrentEntry].Type.Export = 1;

    gDriverExportCache.CurrentEntry++;
}


void
IntDriverCacheCreateUnknown(
    _In_ const QWORD Rip
    )
///
/// @brief      Adds a new entry to the #gDriverExportCache.
///
/// If the cache is full, it is reset.
///
/// @param[in]  Rip     The guest RIP for which this entry is created.
///
{
    if (gDriverExportCache.CurrentEntry == MAX_DRIVER_EXPORT_CACHE_ENTRIES)
    {
        gDriverExportCache.CurrentEntry = 0;
    }

    memzero(&gDriverExportCache.Entry[gDriverExportCache.CurrentEntry], sizeof(DRIVER_EXPORT_CACHE_ENTRY));

    gDriverExportCache.Entry[gDriverExportCache.CurrentEntry].Rip = Rip;
    gDriverExportCache.Entry[gDriverExportCache.CurrentEntry].Type.Unknown = 1;

    gDriverExportCache.CurrentEntry++;
}


DRIVER_EXPORT_CACHE_ENTRY *
IntDriverCacheExportFind(
    _In_ const QWORD Rip
    )
///
/// @brief      Finds an entry inside the #gDriverExportCache.
///
/// @param[in]  Rip     The guest RIP to search for.
///
/// @returns    The cache entry for the given RIP, if one exists; NULL if no cache entry exists.
///
{
    for (DWORD index = 0; index < ARRAYSIZE(gDriverExportCache.Entry); index++)
    {
        if (Rip == gDriverExportCache.Entry[index].Rip)
        {
            return &gDriverExportCache.Entry[index];
        }
    }

    return NULL;
}


void
IntDriverCacheInv(
    _In_ const QWORD BaseAddress,
    _In_ const QWORD Length
    )
///
/// @brief      Invalidates all cache entries for a given guest memory range.
///
/// @param[in]  BaseAddress The start of the range.
/// @param[in]  Length      The size of the range.
///
{
    for (DWORD index = 0; index < ARRAYSIZE(gDriverExportCache.Entry); index++)
    {
        if (IN_RANGE_LEN(gDriverExportCache.Entry[index].Rip, BaseAddress, Length))
        {
            memzero(&gDriverExportCache.Entry[index], sizeof(DRIVER_EXPORT_CACHE_ENTRY));
        }
    }
}
