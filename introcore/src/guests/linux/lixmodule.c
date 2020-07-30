/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixmodule.h"
#include "alerts.h"
#include "crc32.h"
#include "decoder.h"
#include "hook.h"
#include "lixksym.h"


///
/// @brief  List of all the drivers currently loaded inside the guest.
///
extern LIST_HEAD gKernelDrivers;

///
/// @brief  Used to count the modules that are unloading.
///
DWORD gModuleIgnore = 0;


///
/// @brief The state of a kernel module.
///
typedef enum _MODULE_STATE
{
    moduleStateLive = 0,        ///< The module is running.
    moduleStateComing,          ///< The module is full formed, running module_init.
    moduleStateGoing,           ///< The module is going away.
    moduleStateUnformed,        ///< The module is still setting it up.
} MODULE_STATE;


///
/// @brief Module mapping space, as defined by linux kernel (mm.txt)
///
#define LIX_MODULE_MAP_START    0xffffffffa0000000
#define LIX_MODULE_MAP_END      0xfffffffffeffffff

#define LIX_MODULE_MAX_ITERATIONS   4096


static INTSTATUS
IntLixDrvValidate(
    _In_ QWORD Driver
    )
///
/// @brief Validates if the provided driver with the provided address is valid.
///
/// This function performs the following checks:
///     - the state is one of the four values in 'enum module_state';
///     - the name is a string; at least one character and at maxim length of LIX_MODULE_NAME_LENGTH;
///     - the layout values are in range [LIX_MODULE_MAP_START, LIX_MODULE_MAP_END];
///     - the size don't exceed the end of modules mapping;
///
/// @param[in]  Driver  The guest virtual address of the 'struct module'.
///
/// @retval     INT_STATUS_SUCCESS              If the driver is valid.
/// @retval     INT_STATUS_INVALID_OBJECT_TYPE  If the driver is invalid.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BYTE *pLixModule = NULL;
    CHAR *pName = NULL;
    QWORD moduleBase = 0;
    DWORD coreSize = 0;
    DWORD textSize = 0;
    DWORD index = 0;

    status = IntVirtMemMap(Driver, LIX_FIELD(Module, Sizeof), gGuest.Mm.SystemCr3, 0, &pLixModule);
    if (!INT_SUCCESS(status))
    {
        return status;
    }

    if (*(DWORD *)(pLixModule + LIX_FIELD(Module, State)) > moduleStateUnformed)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    pName = (CHAR *)(pLixModule + LIX_FIELD(Module, Name));
    while (index < LIX_MODULE_NAME_LEN && pName[index])
    {
        if (pName[index] < ' ' || pName[index] > 'z')
        {
            status = INT_STATUS_INVALID_OBJECT_TYPE;
            goto _exit;
        }

        index++;
    }

    if (index == LIX_MODULE_NAME_LEN)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    if (!LIX_FIELD(Info, HasModuleLayout))
    {
        moduleBase = *(QWORD *)(pLixModule + LIX_FIELD(Module, ModuleCore));
        coreSize = *(DWORD *)(pLixModule + LIX_FIELD(Module, CoreSize));
        textSize = *(DWORD *)(pLixModule + LIX_FIELD(Module, CoreTextSize));
    }
    else
    {
        moduleBase = *(QWORD *)(pLixModule + LIX_FIELD(Module, CoreLayout));
        coreSize = *(DWORD *)(pLixModule + LIX_FIELD(Module, CoreLayout) + 0x08);
        textSize = *(DWORD *)(pLixModule + LIX_FIELD(Module, CoreLayout) + 0x0c);
    }

    if (!IN_RANGE(moduleBase, LIX_MODULE_MAP_START, LIX_MODULE_MAP_END) || moduleBase > Driver)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    if (coreSize == 0 ||
        coreSize >= (LIX_MODULE_MAP_END - moduleBase) ||
        textSize == 0 ||
        textSize >= (LIX_MODULE_MAP_END - moduleBase) ||
        textSize >= coreSize)
    {
        status = INT_STATUS_INVALID_OBJECT_TYPE;
        goto _exit;
    }

    TRACE("[LIXMODULE] Found module '%s' with base 0x%016llx and size %x and text size %x\n",
          pName, moduleBase, coreSize, textSize);

    status = INT_STATUS_SUCCESS;

_exit:
    IntVirtMemUnmap(&pLixModule);

    return status;
}


static INTSTATUS
IntLixDrvActivateProtection(
    _In_ KERNEL_DRIVER *Driver
    )
///
/// @brief Activates protection for the provided driver.
///
/// This function activates protection only if the guest options has the #INTRO_OPT_PROT_KM_LX_MODULES flag.
/// The driver's '.rodata' section is protected against write using an EPT hook.
///
/// @param[in]  Driver  The internal structure of the driver.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_NOT_INITIALIZED_HINT     If the driver is not initialized yet.
/// @retval     INT_STATUS_ALREADY_INITIALIZED_HINT If the driver is already protected.
///
{
    INTSTATUS status;

    if (!(gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LX_MODULES))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    if (!Driver->Lix.Initialized)
    {
        WARNING("[WARNING]_IntLixDrvActivateProtection called but driver %s is not initialized yet!\n",
                (char *)Driver->Name);
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    if (Driver->Protected)
    {
        TRACE("[INFO] Driver %s is already protected.", (char *)Driver->Name);
        return INT_STATUS_ALREADY_INITIALIZED_HINT;
    }

    status = IntHookObjectCreate(introObjectTypeKmModule, 0, &Driver->HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed for driver %s. Protection will be disabled! \n",
              (char *)Driver->Name);
        return status;
    }

    status = IntHookObjectHookRegion(Driver->HookObject, 0, Driver->Lix.CoreLayout.Base, Driver->Lix.CoreLayout.RoSize,
                                     IG_EPT_HOOK_WRITE, IntLixDrvHandleWrite, Driver, 0, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed for Driver->Name ->  %s Layout.Base -> 0x%llx "
              "Layout.RoSize -> 0x%x\n",
              (char *)Driver->Name, Driver->Lix.CoreLayout.Base, Driver->Lix.CoreLayout.RoSize);

        IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Driver->HookObject, 0);

        Driver->Protected = FALSE;

        return status;
    }

    Driver->Protected = TRUE;
    Driver->ProtectionFlag = INTRO_OPT_PROT_KM_LX_MODULES;

    TRACE("[INFO] Driver %s successfully hooked. GVA: 0x%llx Size: 0x%x\n",
          (char *)Driver->Name, Driver->Lix.CoreLayout.Base, Driver->Lix.CoreLayout.RoSize);

    return INT_STATUS_SUCCESS;
}


static void
IntLixDrvDeactivateProtection(
    _In_ KERNEL_DRIVER *Driver
    )
///
/// @brief Disable protection for the provided driver.
///
/// This function removes the EPT write-hooks from '.rodata' section of the driver.
///
/// @param[in]  Driver  The internal structure of the driver.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (!Driver->Protected || (!Driver->HookObject))
    {
        return;
    }

    status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&Driver->HookObject, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectDestroy failed for driver %s", (char *)Driver->Name);
    }

    Driver->Protected = FALSE;
    Driver->ProtectionFlag = 0;
}


INTSTATUS
IntLixDrvFindList(
    _Out_ QWORD *Drivers
    )
///
/// @brief Searches the Linux kernel for the 'modules' variable.
///
/// This variable it's declared as static inside 'module.c', so we can't find it in kallsyms.
/// Note: Only call this on the static initialization.
///
/// @param[out]  Drivers    Contains the guest virtual address of 'struct module *modules'.
///
/// @retval     INT_STATUS_SUCCESS      On success.
/// @retval     INT_STATUS_NOT_FOUND    If the 'modules' variable is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD *ptr = NULL;
    BOOLEAN found = FALSE;

    for (QWORD startGva = gLixGuest->Layout.DataStart & PAGE_MASK;
         startGva < gLixGuest->Layout.DataEnd;
         startGva += PAGE_SIZE)
    {
        DWORD parsed = 0;
        DWORD toParse = PAGE_SIZE / sizeof(QWORD);

        status = IntVirtMemMap(startGva, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &ptr);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for 0x%016llx: 0x%08x\n", startGva, status);
            return status;
        }

        // On the last page, ignore the last one (it can't start there)
        if (startGva == gLixGuest->Layout.DataEnd - PAGE_SIZE)
        {
            --toParse;
        }

        while (parsed < toParse)
        {
            QWORD next, prev;
            QWORD current = startGva + parsed * sizeof(QWORD);

            next = ptr[parsed];

            // The pointers may point inside Linux module mapping space or to itself
            if ((next < LIX_MODULE_MAP_START || next > LIX_MODULE_MAP_END) && next != current)
            {
                goto _next_ptr;
            }

            // Make sure we don't overflow
            if (parsed == PAGE_SIZE / sizeof(QWORD) - 1)
            {
                // It's safe, since on the last page it won't get to this case.
                status = IntVirtMemFetchQword(startGva + PAGE_SIZE, gGuest.Mm.SystemCr3, &prev);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed getting the prev pointer from 0x%016llx: 0x%08x\n",
                          startGva + PAGE_SIZE, status);
                    break;
                }
            }
            else
            {
                prev = ptr[parsed + 1];
            }

            if ((prev < LIX_MODULE_MAP_START || prev > LIX_MODULE_MAP_END) && prev != current)
            {
                goto _next_ptr;
            }

            // It's an empty list we shall ignore it. If we have no modules loaded, then we don't care.
            if (next == prev && next == current)
            {
                goto _next_ptr;
            }

            // We found one candidate (a doubly linked list). Make sure the addresses are good and that they point
            // to a 'struct module'.
            if (next != current)
            {
                status = IntLixDrvValidate(next - LIX_FIELD(Module, List));
                if (!INT_SUCCESS(status))
                {
                    goto _next_ptr;
                }
            }

            if (prev != current)
            {
                status = IntLixDrvValidate(prev - LIX_FIELD(Module, List));
                if (!INT_SUCCESS(status))
                {
                    goto _next_ptr;
                }
            }

            // We can say that this is our list.
            found = TRUE;
            break;

_next_ptr:
            parsed++;
        }

        IntVirtMemUnmap(&ptr);

        if (found)
        {
            *Drivers = startGva + parsed * sizeof(QWORD);
            LOG("[MODULE] Found the 'modules' list at 0x%016llx\n", *Drivers);
            break;
        }
    }

    if (!found)
    {
        return INT_STATUS_NOT_FOUND;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDrvInitVfreeHandler(
    _In_ void  *Context,
    _In_ QWORD VirtualAddress,
    _In_ QWORD OldEntry,
    _In_ QWORD NewEntry,
    _In_ QWORD OldPageSize,
    _In_ QWORD NewPageSize
    )
///
/// @brief This function is called when the init section of the driver is freed.
///
/// The page-table of the 'init' section of the driver is hooked to know when it's freed. After the 'init' section is
/// freed the driver is fully initialized and we can hook the '.rodata' against write.
///
/// @param[in]  Context         The internal structure of the driver.
/// @param[in]  VirtualAddress  Unused.
/// @param[in]  OldEntry        The old page-table entry.
/// @param[in]  NewEntry        The new page-table entry.
/// @param[in]  OldPageSize     Unused.
/// @param[in]  NewPageSize     Unused.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_REMOVE_HOOK_ON_RET       If fails to remove the init section's hook
///
{
    UNREFERENCED_PARAMETER(OldPageSize);
    UNREFERENCED_PARAMETER(NewPageSize);
    UNREFERENCED_PARAMETER(VirtualAddress);

    // If the previous was present/W and the new is not present/W
    if (((OldEntry & PD_P) && !(NewEntry & PD_P)) || (!(OldEntry & PD_RW) && (NewEntry & PD_RW)))
    {
        KERNEL_DRIVER *pDriver = Context;
        INTSTATUS status;

        pDriver->Lix.Initialized = TRUE;

        status = IntLixDrvActivateProtection(pDriver);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixDrvActivateProtection failed for `%s` (0x%llx 0x%08x)\n",
                  (char *)pDriver->Name,
                  pDriver->Lix.CoreLayout.Base,
                  pDriver->Lix.CoreLayout.RoSize);
        }

        if (NULL != pDriver->Lix.InitSwapHook)
        {
            status = IntHookGvaRemoveHook((HOOK_GVA **)&pDriver->Lix.InitSwapHook, 0);

            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntHookGvaRemoveHook: 0x%08x\n", status);
                return INT_STATUS_REMOVE_HOOK_ON_RET;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixDrvSendEvent(
    _In_ KERNEL_DRIVER *Driver,
    _In_ BOOLEAN Loaded,
    _In_ BOOLEAN StaticDetected
    )
///
/// @brief Send an event to the integrator that contains the information about the provided driver.
///
/// @param[in]  Driver          The internal structure of the driver.
/// @param[in]  Loaded          True if the driver object is created, otherwise false.
/// @param[in]  StaticDetected  True if the driver is static detected, otherwise false.
///
/// @retval     INT_STATUS_SUCCESS              On success.
/// @retval     INT_STATUS_NOT_NEEDED_HINT      If the core options INTRO_OPT_EVENT_MODULES is not set.
///
{
    INTSTATUS status;
    EVENT_MODULE_EVENT *pEvent;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_MODULES))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pEvent = &gAlert.Module;
    memzero(pEvent, sizeof(*pEvent));

    pEvent->Loaded = Loaded;
    pEvent->Protected = TRUE;

    IntAlertFillLixKmModule(Driver, &pEvent->Module);

    if (!StaticDetected)
    {
        IntAlertFillLixCurrentProcess(&pEvent->CurrentProcess);
    }
    else
    {
        pEvent->CurrentProcess.Valid = FALSE;
    }

    status = IntNotifyIntroEvent(introEventModuleEvent, pEvent, sizeof(*pEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return status;
}


void
IntLixDrvUpdateProtection(
    void
    )
///
/// @brief Update Linux drivers protection according to the new core options.
///
{
    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        if (gGuest.KernelDriver == pDriver)
        {
            continue;
        }

        if (INTRO_OPT_PROT_KM_LX_MODULES & gGuest.CoreOptions.Current)
        {
            IntLixDrvActivateProtection(pDriver);
        }
        else
        {
            IntLixDrvDeactivateProtection(pDriver);
        }
    }
}


static void
IntLixDrvRemoveDuplicate(
    _In_ QWORD DriverGva
    )
///
/// @brief Removes the driver with the provided guest virtual address if exists in our list.
///
/// This function is used only for dynamic detection because we can race with the guest. A race condition with the
/// guest is possible because we scan the 'modules' list from the guest and hook the 'module_param_sysfs_setup' that is
/// called after the drivers is added to the 'modules' list. If we scan the 'modules' list when a driver is loading
/// there's chance to add the same driver to out list.
///
/// @param[in]  DriverGva  The address of the 'struct module'.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        if (pDriver->ObjectGva == DriverGva)
        {
            WARNING("[WARNING] Driver %s (%llx) already exists in our list...\n",
                    (char *)pDriver->Name, pDriver->ObjectGva);

            if (!pDriver->Lix.Initialized)
            {
                ERROR("[ERROR] Driver '%s' %llx is not initialized but already in our list...\n",
                      (char *)pDriver->Name, pDriver->ObjectGva);
            }

            RemoveEntryList(&pDriver->Link);

            IntLixDrvSendEvent(pDriver, FALSE, FALSE);

            status = IntLixDrvRemoveEntry(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixDrvRemoveEntry failed: 0x%08x\n", status);
            }
        }
    }
}


static INTSTATUS
IntLixDrvCreateDriverObject(
    _In_ QWORD DriverGva,
    _Out_ KERNEL_DRIVER **Object
    )
///
/// @brief Create a #KERNEL_DRIVER object that contains the information found at the address of the 'struct module'.
///
/// @param[in]  DriverGva   The address of the 'struct module'.
/// @param[out] Object      The #KERNEL_DRIVER object to be created.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INSUFFICIENT_RESOURCES   If the HpAllocWithTag fails.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    KERNEL_DRIVER *pDriver = NULL;
    CHAR *pLixMod = NULL;

    pDriver = HpAllocWithTag(sizeof(*pDriver), IC_TAG_MODU);
    if (NULL == pDriver)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pDriver->ObjectGva = DriverGva;

    status = IntVirtMemMap(pDriver->ObjectGva, LIX_FIELD(Module, Sizeof), gGuest.Mm.SystemCr3, 0, &pLixMod);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed mapping GVA 0x%016llx: 0x%08x\n", pDriver->ObjectGva, status);
        goto _exit;
    }

    // Don't assume the guest structure isn't corrupted!
    pDriver->NameLength = strlen_s(pLixMod + LIX_FIELD(Module, Name), LIX_MODULE_NAME_LEN);
    if (pDriver->NameLength >= LIX_MODULE_NAME_LEN)
    {
        pDriver->NameLength = LIX_MODULE_NAME_LEN - 1;
    }

    // NameLength + 2 OK: NameLength is not longer than LIX_MODULE_NAME_LEN.
    pDriver->Name = HpAllocWithTag(pDriver->NameLength + 2ull, IC_TAG_DRNU);
    if (NULL == pDriver->Name)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto _exit;
    }

    memcpy(pDriver->Name, pLixMod + LIX_FIELD(Module, Name), pDriver->NameLength);
    *((char *)pDriver->Name + pDriver->NameLength + 1) = 0;

    pDriver->NameHash = Crc32String(pDriver->Name, INITIAL_CRC_VALUE);

    pDriver->Lix.KernelSymbols = *(QWORD *)(pLixMod + LIX_FIELD(Module, Symbols));
    pDriver->Lix.SymbolsCount = *(DWORD *)(pLixMod + LIX_FIELD(Module, NumberOfSymbols));

    pDriver->Lix.GplSymbols = *(QWORD *)(pLixMod + LIX_FIELD(Module, GplSymbols));
    pDriver->Lix.GplSymbolsCount = *(DWORD *)(pLixMod + LIX_FIELD(Module, NumberOfGplSymbols));

    if (!LIX_FIELD(Info, HasModuleLayout))
    {
        // NOTE: module_layout isn't randomized
        pDriver->Lix.InitLayout.Base = *(QWORD *)(pLixMod + LIX_FIELD(Module, ModuleInit));
        pDriver->Lix.InitLayout.Size = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitSize));
        pDriver->Lix.InitLayout.TextSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitTextSize));
        pDriver->Lix.InitLayout.RoSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitRoSize));

        pDriver->Lix.CoreLayout.Base = *(QWORD *)(pLixMod + LIX_FIELD(Module, ModuleCore));
        pDriver->Lix.CoreLayout.Size = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreSize));
        pDriver->Lix.CoreLayout.TextSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreTextSize));
        pDriver->Lix.CoreLayout.RoSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreRoSize));
    }
    else
    {
        pDriver->Lix.InitLayout.Base = *(QWORD *)(pLixMod + LIX_FIELD(Module, InitLayout));
        pDriver->Lix.InitLayout.Size = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitLayout) + 0x08);
        pDriver->Lix.InitLayout.TextSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitLayout) + 0x0c);
        pDriver->Lix.InitLayout.RoSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, InitLayout) + 0x10);

        pDriver->Lix.CoreLayout.Base = *(QWORD *)(pLixMod + LIX_FIELD(Module, CoreLayout));
        pDriver->Lix.CoreLayout.Size = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreLayout) + 0x08);
        pDriver->Lix.CoreLayout.TextSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreLayout) + 0x0c);
        pDriver->Lix.CoreLayout.RoSize = *(DWORD *)(pLixMod + LIX_FIELD(Module, CoreLayout) + 0x10);
    }

    pDriver->EntryPoint = *(QWORD *)(pLixMod + LIX_FIELD(Module, Init));
    pDriver->BaseVa = pDriver->Lix.CoreLayout.Base;
    pDriver->Size = pDriver->Lix.CoreLayout.Size;

    *Object = pDriver;

    return INT_STATUS_SUCCESS;

_exit:
    if (pDriver != NULL)
    {
        if (pDriver->Name != NULL)
        {
            HpFreeAndNullWithTag(&pDriver->Name, IC_TAG_DRNU);
        }

        HpFreeAndNullWithTag(&pDriver, IC_TAG_MODU);
    }

    if (pLixMod != NULL)
    {
        IntVirtMemUnmap(&pLixMod);
    }

    return status;
}


static BOOLEAN
IntLixDrvIsActivePatch(
    _In_ QWORD Gva
    )
///
/// @brief Checks if the provided guest virtual address is inside an active-patch range.
///
/// @param[in]  Gva   The guest virtual address to be checked.
///
/// @retval     True, if the guest virtual address is inside an active-patch range, otherwise false.
///
{
    for (DWORD index = 0; index < ARRAYSIZE(gLixGuest->ActivePatch); index++)
    {
        if (IN_RANGE_LEN(Gva, gLixGuest->ActivePatch[index].Gva, gLixGuest->ActivePatch[index].Length))
        {
            return TRUE;
        }
    }

    return FALSE;
}


INTSTATUS
IntLixDrvCreateFromAddress(
    _In_ QWORD DriverGva,
    _In_ QWORD StaticDetected
    )
///
/// @brief Create the \ref KERNEL_DRIVER object from the provided 'module struct' address and activate the protection
/// for it.
///
/// This function calls '_IntLixDrvRemoveDuplicate' to check if the provided drivers already exists in out list. If the
/// driver is found, it is delete and an event is sent to the integrator.
/// The function reads the vale of the 'enum module_state' in order to check if the driver should be protected and
/// added to out list.
/// The 'module_state' has one of the following value:
///     - LIVE/COMMING: the driver runs and it should be protected
///     - GOING: the driver is dying and it should not be protected
///     - UNFORMED: the driver is setting up and it should not be protected yet because it will be protected when the
///                 'module_sysfs_param_setup' is called.
/// If the driver has a valid 'init' section, the page-table of the init section is hooked to know when the section is
/// freed; when the hook-callback is called the driver is initialized and it can be protected (valid only for dynamic
/// driver initialization).
///
/// @param[in]  DriverGva       The address of the 'struct module'.
/// @param[in]  StaticDetected  True if the driver is static detected, otherwise false
///
/// @retval     INT_STATUS_SUCCESS          On success.
/// @retval     INT_STATUS_NOT_INITIALIZED  If the IDT of the provided CPU is not initialized.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    KERNEL_DRIVER *pDriver = NULL;

    if (!StaticDetected)
    {
        IntLixDrvRemoveDuplicate(DriverGva);
    }

    if (StaticDetected)
    {
        DWORD moduleState = 0;

        status = IntKernVirtMemFetchDword(DriverGva + LIX_FIELD(Module, State), &moduleState);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchDword failed for @ 0x%016llx with status: 0x%08x\n",
                  DriverGva + LIX_FIELD(Module, State), status);
            return status;
        }

        switch (moduleState)
        {
        case moduleStateLive:
        case moduleStateComing:
        {
            break;
        }

        case moduleStateGoing:
        {
            LOG("[MODULE] Module @ %llx is dying...\n", DriverGva);
            gModuleIgnore++;

            return INT_STATUS_SUCCESS;
        }

        case moduleStateUnformed:
        {
            LOG("[MODULE] Module @ %llx still setting up. Will ignore on static init...\n", DriverGva);
            return INT_STATUS_SUCCESS;
        }

        default:
        {
            ERROR("[ERROR] Shouldn't reach here. State type %d...\n", moduleState);
            return INT_STATUS_SUCCESS;
        }
        }
    }

    status = IntLixDrvCreateDriverObject(DriverGva, &pDriver);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixDrvCreateDriverObject failed with status: 0x%08x\n", status);
        return status;
    }

    // Hook the page-table of the init section to know when it's freed (after the module was initialized)
    if (!StaticDetected && pDriver->Lix.InitLayout.Base != 0 && pDriver->Lix.InitLayout.Size != 0)
    {
        status = IntHookGvaSetHook(0, pDriver->Lix.InitLayout.Base, PAGE_SIZE, IG_EPT_HOOK_NONE,
                                   IntLixDrvInitVfreeHandler, pDriver, NULL, 0,
                                   (HOOK_GVA **)&pDriver->Lix.InitSwapHook);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookGvaSetHook failed for VA 0x%llx with size %08x in module %s: 0x%08x",
                  pDriver->Lix.InitLayout.Base, MIN(PAGE_SIZE, pDriver->Lix.InitLayout.Size),
                  (char *)pDriver->Name, status);

            pDriver->Lix.InitSwapHook = NULL;
            pDriver->Lix.Initialized = TRUE;
        }
    }
    else
    {
        // We have no init section or this is a static scan... Then it's initialized!
        pDriver->Lix.Initialized = TRUE;
    }

    TRACE("[MODULE] Loaded 0x%016llx @ 0x%016llx: %s\n", pDriver->ObjectGva, pDriver->BaseVa, (char *)pDriver->Name);
    TRACE("---> EP: 0x%016llx, Size: %llx, TextSize: %x, RoSize: %x\n",
          pDriver->EntryPoint, pDriver->Size, pDriver->Lix.CoreLayout.TextSize, pDriver->Lix.CoreLayout.RoSize);

    if (!StaticDetected && pDriver->Lix.InitLayout.Base != 0 && pDriver->Lix.InitLayout.Size != 0)
    {
        TRACE("---> Init: 0x%016llx, Size: %x, TextSize: %x, RoSize: %x\n",
              pDriver->Lix.InitLayout.Base, pDriver->Lix.InitLayout.Size,
              pDriver->Lix.InitLayout.TextSize, pDriver->Lix.InitLayout.RoSize);
    }

    InsertTailList(&gKernelDrivers, &pDriver->Link);

    if (pDriver->Lix.Initialized)
    {
        IntLixDrvActivateProtection(pDriver);
    }

    IntLixDrvSendEvent(pDriver, TRUE, StaticDetected != 0);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDrvRemoveEntry(
    _In_ KERNEL_DRIVER *Driver
    )
///
/// @brief Disable protection and frees the driver structure from our internal list.
///
/// If the swap-mem hook on the init section is enabled, the function will disable it.
///
/// @param[in]  Driver   The internal driver structure.
///
/// @retval     INT_STATUS_SUCCESS              On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1  If the parameter is invalid.
///
{
    if (NULL == Driver)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    IntLixDrvDeactivateProtection(Driver);

    if (NULL != Driver->Lix.InitSwapHook)
    {
        IntHookGvaRemoveHook((HOOK_GVA **)&Driver->Lix.InitSwapHook, 0);
    }

    if (Driver->Name)
    {
        HpFreeAndNullWithTag(&Driver->Name, IC_TAG_DRNU);
    }

    HpFreeAndNullWithTag(&Driver, IC_TAG_MODU);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDrvRemoveFromAddress(
    _In_ QWORD DriverGva
    )
///
/// @brief Disable protection and remove the driver structure from our internal list
///
/// If the swap-mem hook on the init section is enabled, the function will disable it.
///
/// @param[in]  DriverGva   The internal driver structure
///
/// @retval     INT_STATUS_SUCCESS              On success.
///
{
    list_for_each(gKernelDrivers, KERNEL_DRIVER, pDriver)
    {
        if (pDriver->ObjectGva == DriverGva)
        {
            INTSTATUS status;

            TRACE("[MODULE] Unloaded module %s @ 0x%016llx\n", (char *)pDriver->Name, pDriver->BaseVa);

            RemoveEntryList(&pDriver->Link);

            IntLixDrvSendEvent(pDriver, FALSE, FALSE);

            status = IntLixDrvRemoveEntry(pDriver);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntLixDrvRemoveEntry failed: 0x%08x\n", status);
            }

            return INT_STATUS_SUCCESS;
        }
    }

    gModuleIgnore--;

    if (gModuleIgnore != 0)
    {
        ERROR("[ERROR] Driver @ 0x%016llx is not found in internal list! Count: %d. \n", DriverGva, gModuleIgnore);
    }

    return INT_STATUS_SUCCESS;
}


void
IntLixDrvGetSecName(
    _In_ KERNEL_DRIVER *Driver,
    _In_ QWORD Gva,
    _Out_writes_(8) CHAR *SectionName
    )
///
/// @brief Get the section of the driver that contains the provided guest virtual address.
///
/// If the guest virtual address not belong to any section the 'unknown' string is returned.
///
/// @param[in]  Driver      The internal driver structure.
/// @param[in]  Gva         The guest virtual address that belong to a section.
/// @param[out] SectionName A string that contains the name of the section, if any.
///
{
    if (Driver == NULL)
    {
        return;
    }

    if (SectionName == NULL)
    {
        return;
    }

    if (IN_RANGE_LEN(Gva, Driver->BaseVa, Driver->Size))
    {
        QWORD offset = Gva - Driver->BaseVa;

        if (offset < Driver->Lix.CoreLayout.TextSize)
        {
            memcpy(SectionName, "text", sizeof("text"));
        }
        else if (offset < Driver->Lix.CoreLayout.RoSize)
        {
            memcpy(SectionName, "text_ro", sizeof("text_ro"));
        }
        else
        {
            memcpy(SectionName, "text_rw", sizeof("text_rw"));
        }
    }
    else if (!Driver->Lix.Initialized && IN_RANGE(Gva, Driver->Lix.InitLayout.Base, Driver->Lix.InitLayout.Size))
    {
        QWORD offset = Gva - Driver->Lix.InitLayout.Base;

        if (offset < Driver->Lix.InitLayout.TextSize)
        {
            memcpy(SectionName, "init", sizeof("init"));
        }
        else if (offset < Driver->Lix.InitLayout.RoSize)
        {
            memcpy(SectionName, "init_ro", sizeof("init_ro"));
        }
        else
        {
            memcpy(SectionName, "init_rw", sizeof("init_rw"));
        }
    }
    else
    {
        memcpy(SectionName, "unknown", sizeof("unknown"));
    }
}


INTSTATUS
IntLixDrvIsLegitimateTextPoke(
    _In_ void *Hook,
    _In_ QWORD Address,
    _In_ LIX_ACTIVE_PATCH *ActivePatch,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief This function checks if the modified zone by the current instruction is a 'text_poke'.
///
/// This function get the modified memory from the instruction operand and check if it match with the last active-patch
/// information fetched from the 'text_poke' detour.
///
/// @param[in]  Hook        The hook object.
/// @param[in]  Address     The modified address.
/// @param[in]  ActivePatch The active patch that modified the protected memory zone.
/// @param[out] Action      The action that must be taken.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If the provided Hook is null.
/// @retval     INT_STATUS_INVALID_PARAMETER_3      If the provided Action is null.
/// @retval     INT_STATUS_NOT_SUPPORTED            If the modified guest virtual address is not in our active-patch
///                                                 range.
///
{
    INTSTATUS status;
    OPERAND_VALUE newValue = { 0 };
    BYTE patchData[sizeof(ActivePatch->Data)];
    BYTE *pWriteBuffer;
    QWORD gva;
    DWORD writeSize;

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (ActivePatch == NULL)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_4;
    }

    *Action = introGuestNotAllowed;

    gva = IntHookGetGlaFromGpaHook(Hook, Address);

    if (!IN_RANGE_LEN(gva, ActivePatch->Gva, ActivePatch->Length))
    {
        WARNING("[WARNING] IntLixDrvIsLegitimateTextPoke called for 0x%llx which is not in ActivePatch range!\n", gva);
        LOG("[INFO] Active patch is at 0x%llx and is %d bytes long\n",
            ActivePatch->Gva, ActivePatch->Length);
        return INT_STATUS_NOT_SUPPORTED;
    }

    writeSize = gVcpu->AccessSize;
    if (gVcpu->Instruction.IsRepeated)
    {
        writeSize *= (DWORD)gVcpu->Regs.Rcx;
    }

    if ((gVcpu->Instruction.IsRepeated && (gVcpu->Regs.Rcx > ActivePatch->Length)) ||
        writeSize > ActivePatch->Length ||
        writeSize > sizeof(patchData))
    {
        WARNING("[WARNING] Invalid patch write at GVA %llx with size %d (rcx: 0x%llx)\n",
                ActivePatch->Gva, writeSize, gVcpu->Regs.Rcx);

        return INT_STATUS_SUCCESS;
    }

    if (!gVcpu->Instruction.IsRepeated)
    {
        status = IntDecGetWrittenValueFromInstruction(&gVcpu->Instruction, &gVcpu->Regs, NULL, &newValue);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Can't get newValue from instruction: 0x%08x\n", status);
            return status;
        }

        pWriteBuffer = newValue.Value.ByteValues;
    }
    else if (ND_INS_MOVS == gVcpu->Instruction.Instruction)
    {
        status = IntKernVirtMemRead(gVcpu->Regs.Rsi, writeSize, patchData, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for 0x%llx and size %d with status 0x%08x\n",
                  gVcpu->Regs.Rsi, writeSize, status);
            return status;
        }

        pWriteBuffer = patchData;
    }
    else
    {
        CHAR nd[ND_MIN_BUF_SIZE];

        NdToText(&gVcpu->Instruction, gVcpu->Regs.Rip, sizeof(nd), nd);

        ERROR("[ERROR] Instruction %s at RIP %llx is not supported for detour writes...\n", nd, gVcpu->Regs.Rip);

        return INT_STATUS_NOT_SUPPORTED;
    }

    // Quick check to see if the access is at a page boundary.
    // And this is the callback for the second page.
    if (((gVcpu->Gla & PAGE_OFFSET) + writeSize > PAGE_SIZE) && (0 == (Address & PAGE_OFFSET)))
    {
        DWORD delta = (DWORD)PAGE_REMAINING(gVcpu->Gla);

        if (delta > writeSize)
        {
            ERROR("[ERROR] Found a delta greater than the written size (d:%d w:%d).\n", delta, writeSize);
        }
        else
        {
            pWriteBuffer += delta;
            writeSize -= delta;
        }
    }

    if (0 != memcmp(pWriteBuffer, ActivePatch->Data + (gva - ActivePatch->Gva), writeSize))
    {
        WARNING("[WARNING] Invalid patch write at GVA %llx with size %d\n",
                ActivePatch->Gva, writeSize);
        return INT_STATUS_SUCCESS;
    }

    *Action = introGuestAllowed;

    return INT_STATUS_SUCCESS;
}


static void
IntLixDrvSendViolationEvent(
    _In_ KERNEL_DRIVER *Driver,
    _In_ EXCEPTION_KM_ORIGINATOR *Originator,
    _In_ EXCEPTION_VICTIM_ZONE *Victim,
    _In_ HOOK_GPA *Hook,
    _In_ QWORD Address,
    _In_ INTRO_ACTION Action,
    _In_ INTRO_ACTION_REASON Reason
    )
///
/// @brief Sends an #introEventEptViolation event for a protected kernel module.
///
/// @param[in]  Driver      The #KERNEL_DRIVER object.
/// @param[in]  Victim      The victim information, as obtained from the exception mechanism.
/// @param[in]  Originator  The originator information, as obtained from the exception mechanism.
/// @param[in]  Hook        The GPA hook associated to this callback.
/// @param[in]  Address     The GPA address that was accessed.
/// @param[in]  Action      The action that was taken.
/// @param[in]  Reason      The reason for which Action was taken.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    EVENT_EPT_VIOLATION *pEptViol = &gAlert.Ept;
    HOOK_GVA *pGvaHook = (HOOK_GVA *)(((HOOK_GPA *)Hook)->Header.ParentHook);
    CHAR modSym[LIX_SYMBOL_NAME_LEN] = { 0 };
    QWORD addr = pGvaHook->GvaPage + (Address & PAGE_OFFSET);

    memzero(pEptViol, sizeof(*pEptViol));

    pEptViol->Header.Action = Action;
    pEptViol->Header.Reason = Reason;
    pEptViol->Header.MitreID = idRootkit;

    pEptViol->Header.Flags = IntAlertCoreGetFlags(Driver->ProtectionFlag, Reason);

    IntAlertFillCpuContext(TRUE, &pEptViol->Header.CpuContext);

    IntAlertFillLixKmModule(Originator->Original.Driver, &pEptViol->Originator.Module);
    IntAlertFillLixKmModule(Originator->Return.Driver, &pEptViol->Originator.ReturnModule);

    if (addr >= gLixGuest->Layout.ExTableStart && addr < gLixGuest->Layout.ExTableEnd)
    {
        Victim->Object.Type = introObjectTypeExTable;
    }

    IntAlertFillLixKmModule(Victim->Object.Module.Module, &pEptViol->Victim.Module);

    IntAlertFillLixCurrentProcess(&pEptViol->Header.CurrentProcess);

    pEptViol->Offset = addr & PAGE_OFFSET;
    pEptViol->VirtualPage = pGvaHook->GvaPage;
    pEptViol->HookStartVirtual = Driver->BaseVa;

    IntTranslateVirtualAddress(pEptViol->HookStartVirtual, gGuest.Mm.SystemCr3, &pEptViol->HookStartPhysical);

    pEptViol->Violation = IG_EPT_HOOK_WRITE;
    pEptViol->ZoneTypes = Victim->ZoneFlags;

    pEptViol->ReturnRip = 0;

    status = IntKsymFindByAddress(addr, sizeof(modSym), modSym, NULL, NULL);
    if (INT_SUCCESS(status))
    {
        memcpy(pEptViol->FunctionName, modSym, sizeof(pEptViol->FunctionName) - 1);
    }

    IntLixDrvGetSecName(Driver, addr, pEptViol->ModifiedSectionName);

    IntLixDrvGetSecName(Originator->Original.Driver, Originator->Original.Rip, pEptViol->RipSectionName);

    IntAlertFillVersionInfo(&pEptViol->Header);

    IntAlertFillCodeBlocks(Originator->Original.Rip, gGuest.Mm.SystemCr3, FALSE, &pEptViol->CodeBlocks);

    IntAlertFillExecContext(gGuest.Mm.SystemCr3, &pEptViol->ExecContext);

    IntAlertEptFillFromVictimZone(Victim, pEptViol);

    status = IntNotifyIntroEvent(introEventEptViolation, pEptViol, sizeof(*pEptViol));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }
}


static BOOLEAN
IntLixDrvSystemBooting(
    void
    )
///
/// @brief Checks if the system is booting.
///
/// @retval True, if the system is booting, otherwise false.
///
{
    static int state = -1;

    if (__likely(state >= (int)(LIX_FIELD(Ungrouped, Running))))
    {
        // Last time we checked the system was Running, there is no way it's gonna get back to booting again
        return FALSE;
    }

    // Re-fetch the system state
    state = IntLixGuestGetSystemState();

    if (state != -1 && (state < (int)LIX_FIELD(Ungrouped, Running)))
    {
        return TRUE;
    }

    return FALSE;
}


INTSTATUS
IntLixDrvHandleWrite(
    _In_opt_ void *Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Called if an write occurs on the protected memory zone.
///
/// This function checks if the write comes from a 'text_poke' or the write occurs when the system is booting.
/// If these checks fails, the exception mechanism is used to decide if the write should be allowed.
///
/// @param[in]  Context     The context provided by the caller; in our case is the driver object.
/// @param[in]  Hook        The GPA hook associated to this callback.
/// @param[in]  Address     The GPA address that was accessed.
/// @param[out] Action      The action that must be taken.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If the provided Context is null.
/// @retval     INT_STATUS_INVALID_PARAMETER_2      If the provided Hook is null.
/// @retval     INT_STATUS_INVALID_PARAMETER_4      If the provided Action is null.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    KERNEL_DRIVER *pDriver = NULL;
    HOOK_GVA *pGvaHook = NULL;
    EXCEPTION_VICTIM_ZONE victim = { 0 };
    EXCEPTION_KM_ORIGINATOR originator = { 0 };
    INTRO_ACTION_REASON reason = introReasonUnknown;
    BOOLEAN informationOnly = FALSE;

    UNREFERENCED_LOCAL_VARIABLE(reason);

    if (NULL == Context)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == Hook)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Action)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    *Action = introGuestNotAllowed;
    pDriver = Context;
    pGvaHook = (HOOK_GVA *)(((HOOK_GPA *)Hook)->Header.ParentHook);

    if (IntLixDrvIsActivePatch(pGvaHook->GvaPage + (Address & PAGE_OFFSET)))
    {
        for (DWORD index = 0; index < ARRAYSIZE(gLixGuest->ActivePatch); index++)
        {
            status = IntLixDrvIsLegitimateTextPoke(Hook, Address, &gLixGuest->ActivePatch[index], Action);
            if (INT_SUCCESS(status))
            {
                break;
            }
        }

        if (INT_SUCCESS(status) && (*Action == introGuestAllowed))
        {
            return INT_STATUS_SUCCESS;
        }

        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixDrvHandleTextPoke failed for GPA: 0x%llx, GVA: 0x%llx: 0x%08x\n",
                    Address, pGvaHook->GvaPage + (Address & PAGE_OFFSET), status);
        }
    }

    if (IntLixDrvSystemBooting())
    {
        *Action = introGuestAllowed;
        return INT_STATUS_SUCCESS;
    }

    STATS_ENTER(statsExceptionsKern);

    status = IntExceptKernelGetOriginator(&originator, 0);
    if (status == INT_STATUS_EXCEPTION_BLOCK)
    {
        reason = introReasonNoException;
        informationOnly = TRUE;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptKernelGetOriginator failed with status: 0x%08x\n", status);
        reason = introReasonInternalError;
        informationOnly = TRUE;
    }

    status = IntExceptGetVictimEpt(pDriver, Address, pGvaHook->GvaPage + (Address & PAGE_OFFSET),
                                   introObjectTypeKmModule, ZONE_WRITE, &victim);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntExceptGetVictimEpt failed with status: 0x%08x\n", status);
        reason = introReasonInternalError;
        informationOnly = TRUE;
    }

    if (informationOnly)
    {
        IntExceptKernelLogInformation(&victim, &originator, *Action, reason);
    }
    else
    {
        IntExcept(&victim, &originator, exceptionTypeKm, Action, &reason, introEventEptViolation);
    }

    STATS_EXIT(statsExceptionsKern);

    if (IntPolicyCoreTakeAction(pDriver->ProtectionFlag,  Action, &reason))
    {
        IntLixDrvSendViolationEvent(pDriver, &originator, &victim, Hook, Address, *Action, reason);
    }

    IntPolicyCoreForceBetaIfNeeded(pDriver->ProtectionFlag, Action);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixDrvIterateList(
    _In_ PFUNC_IterateListCallback Callback,
    _In_ QWORD Aux
    )
///
/// @brief Iterates the 'modules' list form the guest and activate protection for each driver that is initialized.
///
/// @param[in] Callback     The callback that will be called for each found driver.
/// @param[in] Aux          The auxiliary parameter (StaticDetection) passed to the callback.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INVALID_PARAMETER_1      If the provided callback is invalid.
/// @retval     INT_STATUS_NOT_FOUND                If the 'modules' list is not found.
/// @retval     INT_STATUS_NOT_INITIALIZED_HINT     If the 'modules' list is empty.
/// @retval     INT_STATUS_NOT_SUPPORTED            If the number of the drivers exceed the #LIX_MODULE_MAX_ITERATIONS
///                                                 limit.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD currentDriver = 0;
    QWORD moduleList = 0;
    DWORD count = 0;

    if (NULL == Callback)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntLixDrvFindList(&moduleList);
    if (INT_STATUS_NOT_FOUND == status)
    {
        if (NULL == gLixGuest->InitProcessObj)
        {
            WARNING("[WARNING] No modules found, and init process didn't started...\n");
        }
        else if (IntLixTaskGetExecCount() <= 2)
        {
            WARNING("[WARNING] No modules found, and there are only 2 processes started...\n");
        }
        else
        {
            return status;
        }

        return INT_STATUS_NOT_INITIALIZED_HINT;
    }
    else if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed finding the module list: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemFetchQword(moduleList, &currentDriver);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed getting the first module from 0x%016llx\n", currentDriver);
        return status;
    }

    while (currentDriver != moduleList && (count++ < LIX_MODULE_MAX_ITERATIONS))
    {
        currentDriver -= LIX_FIELD(Module, List);

        status = Callback(currentDriver, Aux);
        if (!INT_SUCCESS(status))
        {
            break;
        }

        status = IntKernVirtMemFetchQword(currentDriver + LIX_FIELD(Module, List), &currentDriver);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the next module from 0x%016llx\n",
                  currentDriver + LIX_FIELD(Module, List));
            break;
        }
    }

    if (count >= LIX_MODULE_MAX_ITERATIONS)
    {
        status = INT_STATUS_NOT_SUPPORTED;
    }

    return status;
}


INTSTATUS
IntLixDrvCreateKernel(
    void
    )
///
/// @brief Create the #KERNEL_DRIVER object for the operating system kernel and activate the protection for it.
///
/// @retval     INT_STATUS_SUCCESS                  On success.
/// @retval     INT_STATUS_INSUFFICIENT_RESOURCES   If the HpAllocWithTag fails.
///
{
    KERNEL_DRIVER *pDriver = HpAllocWithTag(sizeof(*pDriver), IC_TAG_MODU);
    if (NULL == pDriver)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pDriver->Name = HpAllocWithTag(sizeof("kernel"), IC_TAG_DRNU);
    if (NULL == pDriver->Name)
    {
        HpFreeAndNullWithTag(&pDriver, IC_TAG_MODU);
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    memcpy(pDriver->Name, "kernel", sizeof("kernel"));
    pDriver->NameLength = sizeof("kernel") - 1;

    pDriver->NameHash = Crc32String(pDriver->Name, INITIAL_CRC_VALUE);

    pDriver->BaseVa = gLixGuest->Layout.CodeStart;
    pDriver->Size = (DWORD)(gLixGuest->Layout.RoDataEnd - gLixGuest->Layout.CodeStart);

    pDriver->Lix.CoreLayout.Base = gLixGuest->Layout.CodeStart;
    pDriver->Lix.CoreLayout.TextSize = (DWORD)(gLixGuest->Layout.CodeEnd - gLixGuest->Layout.CodeStart);
    pDriver->Lix.CoreLayout.RoSize = (DWORD)(gLixGuest->Layout.RoDataEnd - gLixGuest->Layout.CodeStart);
    pDriver->Lix.CoreLayout.Size = (DWORD)(gLixGuest->Layout.DataEnd - gLixGuest->Layout.CodeStart);

    pDriver->Lix.Initialized = TRUE;

    gGuest.KernelDriver = pDriver;

    InsertTailList(&gKernelDrivers, &pDriver->Link);

    return INT_STATUS_SUCCESS;
}
