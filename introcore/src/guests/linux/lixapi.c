/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixapi.h"
#include "decoder.h"
#include "drivers.h"
#include "lixcrash.h"
#include "lixcred.h"
#include "lixmm.h"
#include "guests.h"
#include "crc32.h"
#include "lixksym.h"


///
/// @brief Create a new #LIX_FN_DETOUR entry.
///
/// The 'FunctionName', 'Callback' and 'EnableFlags' are provided by the caller and the ID of the detour-entry is
/// generated.
///
#define __init_detour_entry(fn_name, callback, flags)                           \
    {                                                                           \
        .FunctionName = #fn_name,                                               \
        .HijackFunctionName = NULL,                                             \
        .Callback = (callback),                                                 \
        .Id = det_ ## fn_name,                                                  \
        .EnableFlags = (flags),                                                 \
    }


///
/// @brief Create a new #LIX_FN_DETOUR entry that appends the provided 'regex' to the end of the 'FunctioName'.
///
/// The 'FunctionName', 'Callback', 'EnableFlags' and 'Regex' are provided by the caller and the ID of the detour-entry
/// is generated.
///
#define __init_detour_entry_regex(fn_name, regex, callback, flags)              \
    {                                                                           \
        .FunctionName = #fn_name regex,                                         \
        .HijackFunctionName = NULL,                                             \
        .Callback = callback,                                                   \
        .Id = det_ ## fn_name,                                                  \
        .EnableFlags = flags,                                                   \
    }



///
/// @brief Create a new #LIX_FN_DETOUR entry that is used for middle-function detours.
///
/// The 'FunctionName', 'Callback', 'EnableFlags' and 'HijackFunctionName' are provided by the caller and the ID of the
/// detour-entry is generated.
///
#define __init_detour_entry_hijack(fn_name, hijack_fn_name, callback, flags)    \
    {                                                                           \
        .FunctionName = #fn_name,                                               \
        .HijackFunctionName = #hijack_fn_name,                                  \
        .Callback = callback,                                                   \
        .Id = det_ ## fn_name ## _ ## hijack_fn_name,                           \
        .EnableFlags = flags,                                                   \
    }



///
/// @brief An array of the #LIX_FN_DETOUR that contains all detours used by the introspection engine.
///
const LIX_FN_DETOUR gLixHookHandlersx64[] =
{
    __init_detour_entry(commit_creds,                   IntLixCommitCredsHandle,        DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(arch_jump_label_transform,      IntLixJumpLabelHandler,         INTRO_OPT_PROT_KM_LX_TEXT_READS                         ),
    __init_detour_entry(module_param_sysfs_setup,       IntDriverLoadHandler,           DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(module_param_sysfs_remove,      IntDriverUnloadHandler,         DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(wake_up_new_task,               IntLixTaskHandleFork,           DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(flush_old_exec,                 IntLixTaskHandleExec,           DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(do_exit,                        IntLixTaskHandleDoExit,         DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(arch_ptrace,                    IntLixTaskHandlePtrace,         INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(compat_arch_ptrace,             IntLixTaskHandlePtrace,         INTRO_OPT_ENABLE_UM_PROTECTION                          ),

    __init_detour_entry_regex(process_vm_rw_core,  "*", IntLixTaskHandleVmRw,         INTRO_OPT_ENABLE_UM_PROTECTION                          ),

    __init_detour_entry(__vma_link_rb,                  IntLixVmaInsert,                INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(change_protection,              IntLixVmaChangeProtection,      INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(vma_adjust,                     IntLixVmaAdjust,                INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(__vma_adjust,                   IntLixVmaAdjust,                INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(vma_rb_erase,                   IntLixVmaRemove,                INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(__vma_rb_erase,                 IntLixVmaRemove,                INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(expand_downwards,               IntLixVmaExpandDownwards,       INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(complete_signal,                IntLixCrashHandle,              INTRO_OPT_ENABLE_UM_PROTECTION                          ),
    __init_detour_entry(text_poke,                      IntLixTextPokeHandler,          DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(__text_poke,                    IntLixTextPokeHandler,          DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(ftrace_write,                   IntLixFtraceHandler,            DETOUR_ENABLE_ALWAYS                                    ),
    __init_detour_entry(panic,                          IntLixCrashPanicHandler,        INTRO_OPT_PANIC_CLEANUP | INTRO_OPT_EVENT_OS_CRASH      ),
    __init_detour_entry(crash_kexec,                    IntLixCrashPanicHandler,        INTRO_OPT_PANIC_CLEANUP | INTRO_OPT_EVENT_OS_CRASH      ),
    __init_detour_entry(__access_remote_vm,             IntLixAccessRemoteVmHandler,    INTRO_OPT_ENABLE_UM_PROTECTION                          ),

    __init_detour_entry_hijack(mprotect_fixup,     vma_wants_writenotify,          IntLixVmaChangeProtection,      INTRO_OPT_ENABLE_UM_PROTECTION),
    __init_detour_entry_hijack(do_munmap,          rb_erase,                       IntLixVmaRemove,                INTRO_OPT_ENABLE_UM_PROTECTION),
    __init_detour_entry_hijack(vma_adjust,         rb_erase,                       IntLixVmaRemove,                INTRO_OPT_ENABLE_UM_PROTECTION),
};



static INTSTATUS
IntLixApiHijackHook(
    _In_ const LIX_FN_DETOUR *FnDetour,
    _Out_ QWORD *Address
    )
///
/// @brief  Fetch the address of the hijack function name provided by the #LIX_FN_DETOUR.
///
/// This function fetch the address of the #LIX_FN_DETOUR.FunctionName and parse the function. For each instruction the
/// function looks for 'CALL rel addr' pattern and if the pattern matches, the relative address is compared with
/// #LIX_FN_DETOUR.HijackFunctionName relative address.
///
/// @param[in]  FnDetour    The internal structure of the detour entry.
/// @param[out] Address     On success, contains the address of the hijack function.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the provided hijack function name is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    INSTRUX instrux;
    QWORD ksymStart = 0;
    QWORD ksymEnd = 0;
    QWORD ksymHijack = 0;

    *Address = 0;

    ksymHijack = IntKsymFindByName(FnDetour->HijackFunctionName, NULL);
    if (!ksymHijack)
    {
        ERROR("[ERROR] IntLixGuestFindKsymByName failed with status: 0x%08x. (%s)\n",
              status, FnDetour->HijackFunctionName);
        return status;
    }

    ksymStart = IntKsymFindByName(FnDetour->FunctionName, &ksymEnd);
    if (!ksymStart)
    {
        ERROR("[ERROR] IntLixGuestFindKsymByName failed with status: 0x%08x. (%s)\n", status, FnDetour->FunctionName);
        return status;
    }

    while (ksymStart < ksymEnd)
    {
        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, ksymStart, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed with status: 0x%08x.\n", status);
            return status;
        }

        if (instrux.Instruction == ND_INS_CALLNR)
        {
            QWORD hijackRelativeAddr = ksymHijack - (ksymStart + 5);

            if (hijackRelativeAddr == instrux.Operands[0].Info.RelativeOffset.Rel)
            {
                *Address = ksymStart;

                return INT_STATUS_SUCCESS;
            }
        }

        ksymStart += instrux.Length;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixApiHook(
    _In_ const LIX_FN_DETOUR *FnDetour,
    _Out_ BOOLEAN *MustValidateThreads
    )
///
/// @brief Will hook one function as described by the FnDetour.
///
/// If the provided #LIX_FN_DETOUR describes a middle-function detour, the #IntLixApiHijackHook is called to fetch the
/// address of the function, otherwise the IntKsymFindByName is called. The found address is passed to the
/// #IntDetSetLixHook to hook it.
///
/// @param[in]  FnDetour            The internal structure of the detour entry.
/// @param[out] MustValidateThreads On success, contains true if the thread safeness must validate the running threads,
///                                 otherwise false
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the provided #LIX_FN_DETOUR is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    QWORD functionAddress = 0;

    if (FnDetour->HijackFunctionName == NULL)
    {
        functionAddress = IntKsymFindByName(FnDetour->FunctionName, NULL);
        if (!functionAddress)
        {
            ERROR("[ERROR] Critical API '%s' not found! Aborting!\n", FnDetour->FunctionName);
            return INT_STATUS_NOT_FOUND;
        }

        TRACE("[DETOUR] Found function '%s' @ 0x%016llx\n", FnDetour->FunctionName, functionAddress);
    }
    else
    {
        status = IntLixApiHijackHook(FnDetour, &functionAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Critical API '%s' not found! Aborting!\n", FnDetour->FunctionName);
            return INT_STATUS_NOT_FOUND;
        }
        TRACE("[DETOUR] Found hijack function '%s' inside function '%s' @ 0x%016llx\n",
              FnDetour->HijackFunctionName, FnDetour->FunctionName, functionAddress);
    }

    *MustValidateThreads = TRUE;

    status = IntDetSetLixHook(functionAddress, FnDetour, MustValidateThreads);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to detour %s: 0x%08x\n", FnDetour->FunctionName, status);

        IntDisasmGva(functionAddress, 0x20);

        return status;
    }

    return INT_STATUS_SUCCESS;
}


static __forceinline BOOLEAN
IntLixApiCmpFunctionNameWithHash(
    _In_ const char *Name,
    _In_ DWORD NameHash
    )
///
/// @brief Check if the crc32 of the Name is equal to the provided NameHash.
///
/// @param[in]  Name        A string that contains the name of the function.
/// @param[in]  NameHash    The crc32 that is compared with the crc32 of the Name.
///
/// @retval     True if the NameHash is equal to the crc32 of the Name.
///
{
    return NameHash == Crc32String(Name, INITIAL_CRC_VALUE);
}


INTSTATUS
IntLixApiHookAll(
    void
    )
///
/// @brief Iterates through all APIs that can be hooked and sets requested hooks.
///
/// The function name of the #LIX_FN_DETOUR may be duplicated, but it has different 'HijackFunctionName'.
/// The 'HookHandler' field of the #LIX_FUNCTION structure describes the index of the #LIX_FN_DETOUR that must be
/// hooked.
///
/// @retval INT_STATUS_SUCCESS      On success.
/// @retval INT_STATUS_NOT_FOUND    If the provided #LIX_FN_DETOUR is not found.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    BOOLEAN validateThreads = FALSE;

    for (DWORD i = 0; i < gLixGuest->OsSpecificFields.FunctionsCount; i++)
    {
        DWORD descriptorCount = 0;
        DWORD descriptorNumber = gLixGuest->OsSpecificFields.Functions[i].HookHandler;

        for (DWORD j = 0; j < ARRAYSIZE(gLixHookHandlersx64); j++)
        {
            if (IntLixApiCmpFunctionNameWithHash(gLixHookHandlersx64[j].FunctionName,
                                                 gLixGuest->OsSpecificFields.Functions[i].NameHash))
            {
                if (descriptorCount != descriptorNumber)
                {
                    descriptorCount++;
                    continue;
                }

                descriptorCount++;

                BOOLEAN mustValidate = FALSE;
                status = IntLixApiHook(&gLixHookHandlersx64[j], &mustValidate);
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] Failed to set hook, status: 0x%x\n", status);
                    return status;
                }

                if (mustValidate)
                {
                    validateThreads = TRUE;
                }

                break;
            }
        }
    }

    status = IntKernVirtMemWrite(gLixGuest->MmAlloc.Detour.Data.Address, sizeof(QWORD), &gGuest.CoreOptions.Current);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed for 0x%llx with status: 0x%08x\n",
              gLixGuest->MmAlloc.Detour.Data.Address, status);
        return status;

    }

    TRACE("[DETOUR] Linux detours activated... \n");

    if (!validateThreads)
    {
        LOG("[LIXAPI] No need for validating threads!\n");
        return INT_STATUS_SUCCESS;
    }

    LOG("[LIXAPI] Ensuring no thread will return into our hooks!\n");

    status = IntThrSafeCheckThreads(THS_CHECK_DETOURS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntThrSafeCheckThreads failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


void
IntLixApiUpdateHooks(
    void
    )
///
/// @brief Update the hookable APIs according to the current Introcore options.
///
/// This function writes the 'ProtectionOptions' field of the #LIX_HYPERCALL_PAGE.
///
{
    IntPauseVcpus();

    INTSTATUS status = INT_STATUS_SUCCESS;

    // The memory zone that contains the #LIX_HYPERCALL_PAGE is protected against write/execute
    status = IntKernVirtMemPatchQword(gLixGuest->MmAlloc.Detour.Data.Address + OFFSET_OF(LIX_HYPERCALL_PAGE,
                                                                                         ProtectionOptions),
                                      gGuest.CoreOptions.Current);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemPatchQword failed with status: 0x%08x\n", status);
    }

    IntResumeVcpus();
}
