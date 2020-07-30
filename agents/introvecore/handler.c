/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "handler.h"
#include "cpu.h"
#include "asmlib.h"
#include "hviface.h"
#include "emu.h"
#include "vestatus.h"
#include "spinlock.h"


//
// VirtualizationExceptionHandler
//
void
VirtualizationExceptionHandler(
    PVECPU Cpu
    )
//
// This function handles any kind of #VE. It will further dispatch the events, depending on the reason and
// qualification. Note that only EPT violations can be delivered as #VE.
//
{
    VESTATUS status = VE_STATUS_SUCCESS;
    QWORD tsc = __rdtsc();

    Cpu->Raised = FALSE;

    _InterlockedIncrement64(&Cpu->VeTotal);

    // Handle the exit.
    switch (Cpu->Reason)
    {
    case EXIT_REASON_EPT_VIOLATION:
        if (0 == (Cpu->Qualification & EPT_QUAL_GLA_ACCESS))
        {
            status = VeHandlePageWalk(Cpu);
            if (!VE_SUCCESS(status))
            {
                HvBreak(VE_BREAK_PAGE_WALK_FAILED, status);
                goto cleanup_and_exit;
            }

            _InterlockedIncrement64(&Cpu->VePageWalk);
        }
        else
        {
            // Make sure the fault was triggered in kernel mode.
            if (Cpu->Registers.CS != 0x10)
            {
                status = VE_STATUS_ACCESS_DENIED;
                HvBreak(VE_BREAK_CS_NOT_KERNEL, status);
                goto cleanup_and_exit;
            }

            // Handle the PT write
            status = VeHandlePtWrite(Cpu);
            if (!VE_SUCCESS(status))
            {
                HvBreak(VE_BREAK_EMULATION_FAILED, status);
                goto cleanup_and_exit;
            }

            // used for #VE Stats
            _InterlockedIncrement64(&Cpu->VeMm);
        }

        break;

    default:
        HvBreak(VE_BREAK_UNKNOWN_EXIT, 0);
        break;
    }

cleanup_and_exit:
    if (!Cpu->Raised)
    {
        _InterlockedIncrement64(&Cpu->VeIgnoredTotal);

        Cpu->TscTotal += __rdtsc() - tsc;
        Cpu->TscCount++;
    }

    // All done!
}
