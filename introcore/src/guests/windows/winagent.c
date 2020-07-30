/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winagent.h"
#include "alerts.h"
#include "guests.h"
#include "hnd_loggather.h"
#include "hnd_remediation.h"
#include "icache.h"
#include "kernvm.h"
#include "loader.h"
#include "memcloak.h"
#include "ptfilter.h"
#include "slack.h"
#include "vecore.h"
#include "winbootdrv_Win32.h"
#include "winbootdrv_x64.h"
#include "winpe.h"
#include "winprocesshp.h"
#include "winstubs.h"


///
/// @file winagent.c
///
/// @brief This file deals with Windows agents injection.
///
/// Introcore supports injecting agents inside the guest VM. An agent is a file, process or driver which is deployed
/// inside the guest, and which is removed when it is not needed anymore. Typical agents usage include:
/// - Inject a file (archive) inside the guest;
/// - Inject a process (an application which is started inside the guest);
/// - Inject a driver (for example, the VE or PT driver).
/// The injection mechanism is composed of three main components:
///
/// 0. Detoured instruction. This is an instruction inside the SYSCALL handler, which gets executed by the operating
/// system, and which we replace with a "CALL" to the trampoline code (see the next section). The instruction must
/// be at least 5 bytes in size (since 5 is the length of the relative "CALL" we use). Once a SYSCALL is generated
/// and the detoured instruction is hit, the trampoline code gets activated.
/// In case we want to inject a breakpoint agent, we replace this instruction with just a breakpoint, so instead
/// of going through the trampoline, the breakpoint would be handled directly, without the intervention of the
/// trampoline.
///
/// 1. The trampoline. The trampoline is a small chunk of code which is injected inside the guest as soon as Introcore
/// is initialized, and remains inside the guest until Introcore unloads. This piece of code has the responsibility
/// of jumping to the bootstrap code; the reason we need this trampoline is because we have no guarantee that we
/// we will be able to allocate the bootstrap code within [-2G, +2G] of the NT image, and because we need a simple
/// mechanism of handling the bootstrap thread termination; therefore, this trampoline
/// code contains an indirect branch which will jump to the bootstrap no matter where it was allocated. The
/// trampoline looks like this (on 64 bit, on 32 bit it is nearly identical):
///     _start:
///         push        rax
///         int3
///         test        rax, rax
///         jz          _skip
///         call        rax
///     _skip:
///         pop         rax
///         retn
///     _stop:
///         int3
///         xor eax, eax
///         retn
/// The anatomy of the trampoline is the following (remember that the trampoline is executed when the detoured
/// instruction, replaced by a "CALL", is executed and branches to it):
/// - On entry, it saves RAX on the stack;
/// - It issues a hyper call using INT3; this will end up executing #IntWinAgentHandleLoader1Hypercall;
/// - Inside Introcore, #IntWinAgentHandleLoader1Hypercall will:
///     - Store in the RAX register the address of the bootstrap code;
///     - Modify the return address saved by the "CALL" to point 5 bytes backwards - exactly to the address
///       of the detoured instruction;
///     - Restore the detoured instruction inside guest memory.
/// - Once back inside the guest, we test the value in RAX; if it is 0, it means that Introcore does not want
///   the trampoline to jump to the bootstrap; this can happen if two VCPUs executed the INT3 at the same time;
///   we only need it one time, so the second time we end up handling the INT3, we can safely ignore it, and
///   this is signaled to the trampoline by returning 0 in RAX.
///   If RAX is not 0, then it contains the address of the bootstrap, and the trampoline will call it right away;
/// - The _stop label is hit once the bootstrap finishes its job; once the bootstrap thread is done, it will
///   jump to this label, which does nothing else but returning 0 and terminating the current thread, as this
///   executes in the context of a new thread created inside the bootstrap code;
/// - the _skip label is reached once the bootstrap initiates the second hyper call, which is immediately
///   after it created a thread inside the bootstrap; the instructions here simply restore RAX and return execution
///   to the instruction that has been interrupted;
/// Please find the trampoline code in the following files:
/// - trampoline32.asm (32 bit, VMCALL hyper call)
/// - trampoline32_bp.asm (32 bit, INT3 hyper call)
/// - trampoline64.asm (64 bit, VMCALL hyper call)
/// - trampoline64_bp.asm (64 bit, INT3 hyper call)
///
/// 2. The bootstrap. The bootstrap code is a larger piece of code that gets injected and removed dynamically with
/// each injection request. The bootstrap contains two sections:
/// - The initial section is called by the trampoline code via the "CALL rax" instruction (due to this indirect call
///   we can allocate the bootstrap code anywhere in memory). This section does the following:
///     - Save all general purpose registers on the stack;
///     - Allocate memory for the boot driver;
///     - Issue a hyper call to notify Introcore about the allocated memory;
///     - The hyper call will be handled by the #IntWinAgentHandleLoader2Hypercall function, which will write the
///       boot driver inside the guest memory;
///     - Create a thread into the second section of the bootstrap;
///     - Issue a hyper call to notify Introcore about the started thread;
///     - The hyper call will be handled by the #IntWinAgentHandleLoader2Hypercall, which will modify the general
///       purpose registers state by restoring all the registers saved on the stack, RIP included, which will now
///       point to the trampoline:_skip label;
///     - Upon guest re-entry, the trampoline!_skip label gets executed, which simply returns to the interrupted
///       instruction, and guest execution resumes normally;
/// - The thread section is executed as a different thread as soon as the initial section creates it:
///     - Call the entry point of the boot driver (previously injected by Introcore during the first hyper call issued
///       by the bootstrap code)
///     - On boor driver return, jmp to the trampoline!_stop label;
///     - As already described, this label will issue a hyper call, handled by the #IntWinAgentHandleLoader1Hypercall,
///       which will free the bootstrap from guest memory, and terminate the thread by returning 0;
/// Please find the bootstrap code in the following files:
/// - agent32.asm (32 bit)
/// - agent64.asm (64 bit)
///
/// 3. The boot driver. The boot driver is a separate project - introbootdrv. It has the main responsibility of
/// handling commands from Introcore; currently defined commands are:
/// - Drop a file inside the guest;
/// - Start process inside the guest;
/// - Load/unload the VE driver;
/// - Load/unload the PT driver;
/// Please find the boot driver in the introbootdrv project.
///
/// NOTE: There can be only one active agent at any time (by active agent we mean an instance of the boot driver).
/// NOTE: When injecting a process, the boot driver will return as soon as the process was started; this means that it
/// does not wait for the process to finish, allowing Introcore to inject other agents in the meantime, so there can
/// be an arbitrary number of active injected processes at any given time.
/// NOTE: When injecting processes, the IntWinAgentInject function accepts a PID argument which represents the process
/// the agent should be started from. If this argument is 0, the injected process agent will be started in the context
/// of the winlogon.exe process, with SYSTEM privileges!!!
/// NOTE: #IntKernVirtMemWrite can be used only for buffers that were allocated/validated by Introcore.
/// For buffers sent from within the guest, use #IntVirtMemSafeWrite instead, which validates both the guest page tables
/// and the EPT and ring rights in order to see if the buffer is safe to be written.
///

// We obviously have different drivers for x86 and x64...
#define REM_DRV(arch64)  ((arch64) ? (gBootDriverx64) : (gBootDriverWin32))
#define REM_SIZE(arch64) ((arch64) ? (sizeof(gBootDriverx64)) : sizeof((gBootDriverWin32)))

#define AGENT_FLAG_STARTED   0x00000001
#define AGENT_FLAG_ALLOCATED 0x00000002
#define AGENT_FLAG_ACTIVE    0x00000004
#define AGENT_FLAG_COMPLETED 0x00000008
#define AGENT_FLAG_ALL_DONE  0x0000000F


///
/// Describes the name of an injected process agent. Whenever a named agent is injected, we allocate such an entry.
/// Whenever a process is created, we check if its name matches the name of an injected agent; if it does, it will
/// be flagged as being an agent. Therefore, it is advisable to use complicated names for the agents, in order
/// to avoid having regular processes marked as agents.
///
typedef struct _AGENT_NAME
{
    LIST_ENTRY  Link;                           ///< List entry element.
    CHAR        ImageName[IMAGE_BASE_NAME_LEN]; ///< Image base name.
    SIZE_T      NameLen;                        ///< Name length.
    DWORD       Tag;                            ///< Agent tag.
    DWORD       Agid;                           ///< Agent ID.
    DWORD       RefCount;                       ///< Number of times this name has been used by agents.
} AGENT_NAME, *PAGENT_NAME;

/// Just a page filled with zeros.
BYTE gTrampolineZero[4096] = {0};


///
/// Global agents state.
///
typedef struct _AGENT_STATE
{
    BOOLEAN Initialized;   ///< True if the agents state has been initialized.
    QWORD Trampoline;      ///< The address of the trampoline code (slacked inside the kernel).
    void *TrampolineCloak; ///< Cloak handle used to hide the trampoline inside the guest.
    DWORD TrampolineSize;  ///< Size of the trampoline code.

    WORD OffsetStop;    ///< Offset to the code chunk that stops the thread (_stop label).
    WORD OffsetVmcall1; ///< Offset to the first hyper call.
    WORD OffsetVmcall2; ///< Offset to the second hyper call.

    DWORD Counter; ///< Incremented on each agent injection, used to generate unique agent IDs.

    LIST_ENTRY PendingAgents;    ///< List of agents waiting to be injected.
    LIST_ENTRY AgentNames;       ///< List of agent names.
    void *ActiveAgent;           ///< There can be only one active agent at any given moment. This is the one.
    DWORD PendingAgentsCount;    ///< Number of agents waiting to be activated.
    DWORD BootstrapAgentsCount;  ///< Number of agents bootstrapping.
    DWORD CompletingAgentsCount; ///< Number of agents that are yet to complete execution.
    BOOLEAN SafeToInjectProcess; ///< Will be true the moment it's safe to inject agents (the OS has booted).
} AGENT_STATE, *PAGENT_STATE;

static AGENT_STATE gAgentState = {0};



BOOLEAN
IntWinAgentIsRipInsideCurrentAgent(
    _In_ QWORD Rip
    )
///
/// @brief Return true if the given RIP points inside the currently active boot driver.
///
/// @param[in]  Rip The RIP to be checked.
///
/// @returns True if the Rip points inside an active boot driver, false otherwise.
///
{
    PWIN_AGENT currentAgent = gAgentState.ActiveAgent;

    if (currentAgent)
    {
        if (Rip >= currentAgent->DriverAddress && Rip < currentAgent->DriverAddress + currentAgent->DriverSize)
        {
            return TRUE;
        }
    }

    return FALSE;
}


//
// Execution callback in the SYSCALL page - used to redirect RIP to our bootstrap code.
//
INTSTATUS
IntWinAgentSelectBootstrapAddress(
    _In_ DWORD Size,
    _Out_ QWORD *Address
    );

INTSTATUS
IntWinAgentReleaseBootstrapAddress(
    _In_ QWORD Address
    );


static INTSTATUS
IntWinAgentFree(
    _In_ PWIN_AGENT Agent,
    _In_ QWORD DataInfo
    )
///
/// @brief Frees an agent.
///
/// This function frees an agent and all the resources allocated to it, for example, its contents.
/// NOTE: The contents of the agent may have been memory-mapped by the integrator; if this is the case, we cannot
/// correctly free it ourselves; instead, we call a dedicated glue API which notifies the integrator that it is
/// safe to free the memory allocated for the agent.
///
/// @param[in]  Agent       The agent to be freed.
/// @param[in]  DataInfo    Unused.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    UNREFERENCED_PARAMETER(DataInfo);

    if ((NULL != Agent->AgentContent) && !Agent->AgentInternal)
    {
        IntReleaseBuffer(Agent->AgentContent, Agent->AgentSize);

        Agent->AgentContent = NULL;
    }

    HpFreeAndNullWithTag(&Agent, IC_TAG_AGNE);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentRemove(
    _In_ PWIN_AGENT Agent
    )
///
/// @brief Removes the given agent.
///
/// This function removes an agent. It will restore the hooked instruction and the boot code, and then it will free it.
///
/// @param[in]  Agent   The agent to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    // Pause the VCPUs while we do the cleanup.
    IntPauseVcpus();

    // If needed, restore the patched instruction.
    if (!Agent->InstructionRestored)
    {
        if (NULL != Agent->InsCloakRegion)
        {
            status = IntMemClkUncloakRegion(Agent->InsCloakRegion, MEMCLOAK_OPT_APPLY_PATCH);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
            }

            Agent->InsCloakRegion = NULL;
        }
        else
        {
            if (!!(Agent->Options & AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE))
            {
                BYTE fiveByteNop[] = {0x66, 0x66, 0x66, 0x66, 0x90};

                status = IntDetModifyPublicData(detTagPowerState, fiveByteNop, sizeof(fiveByteNop), "5bytenop");
                if (!INT_SUCCESS(status))
                {
                    ERROR("[ERROR] IntDetModifyPublicData failed: 0x%08x\n", status);
                }
            }
            else
            {
                ERROR("[ERROR] Instruction was not restored and the cloak region is NULL!\n");
                IntDbgEnterDebugger();
            }
        }

        Agent->InstructionRestored = TRUE;
    }


    // If needed, remove the bootstrap code.
    if (0 != Agent->BootstrapAddress)
    {
        // Remove the cloaked boot region.
        if (NULL != Agent->BootCloakRegion)
        {
            status = IntMemClkUncloakRegion(Agent->BootCloakRegion, MEMCLOAK_OPT_APPLY_PATCH);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
            }

            Agent->BootCloakRegion = NULL;
        }

        status = IntWinAgentReleaseBootstrapAddress(Agent->BootstrapAddress);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentReleaseBootstrapAddress failed: 0x%08x\n", status);
        }

        Agent->BootstrapAddress = 0;
    }

    IntResumeVcpus();

    // Free the agent.
    status = IntWinAgentFree(Agent, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentFree failed: 0x%08x\n", status);
    }

    return status;
}


INTSTATUS
IntWinAgentInjectTrampoline(
    void
    )
///
/// @brief Inject the agent trampoline inside the guest.
///
/// The agent trampoline is a small chunk of code that gets injected inside a region of NT slack space. This
/// trampoline is used to intermediate the code transfers to the bootstrap code, which is dynamically allocated
/// and must be freed once the agent is done.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD slackSize;
    PBYTE trampoline;
    BYTE origTrampoline[TRAMPOLINE_MAX_SIZE] = {0};

    if (gGuest.Guest64)
    {
        slackSize = sizeof(gTrampolineAgentx64);
        trampoline = gTrampolineAgentx64;

        gAgentState.OffsetStop = TRAMP_X64_STOP;
        gAgentState.OffsetVmcall1 = TRAMP_X64_VMCALL1;
        gAgentState.OffsetVmcall2 = TRAMP_X64_VMCALL2;
    }
    else
    {
        slackSize = sizeof(gTrampolineAgentx86);
        trampoline = gTrampolineAgentx86;

        gAgentState.OffsetStop = TRAMP_X86_STOP;
        gAgentState.OffsetVmcall1 = TRAMP_X86_VMCALL1;
        gAgentState.OffsetVmcall2 = TRAMP_X86_VMCALL2;
    }

    status = IntSlackAlloc(gGuest.KernelVa, FALSE, slackSize, &gAgentState.Trampoline, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSlackAlloc failed: 0x%08x\n", status);
        return status;
    }

    status = IntKernVirtMemRead(gAgentState.Trampoline, slackSize, origTrampoline, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for %llx, %d: 0x%08x\n", gAgentState.Trampoline, slackSize, status);

        // Remove the slack allocation.
        IntSlackFree(gAgentState.Trampoline);

        gAgentState.Trampoline = 0;

        return status;
    }

    gAgentState.TrampolineSize = slackSize;

    // Inject the trampoline and cloak it.
    status = IntMemClkCloakRegion(gAgentState.Trampoline,
                                  0,
                                  slackSize,
                                  MEMCLOAK_OPT_APPLY_PATCH,
                                  origTrampoline,
                                  trampoline,
                                  NULL,
                                  &gAgentState.TrampolineCloak);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);

        // Remove the slack allocation.
        IntSlackFree(gAgentState.Trampoline);

        gAgentState.Trampoline = 0;

        return status;
    }

    TRACE("[AGENT] Selected trampoline at 0x%016llx\n", gAgentState.Trampoline);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentDeployWinDriver(
    _In_ PWIN_AGENT Agent
    )
///
/// @brief Inject the Windows boot driver.
///
/// This function injects the Windows boot driver inside the guest. The boot driver will be written at an
/// address that was previously allocated by the boot code. Once the Windows boot driver is written inside
/// the guest memory, the boot code will start a thread pointing inside the boot driver.
///
/// @param[in]  Agent   The agent handle.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_OPERATION_NOT_IMPLEMENTED If the guest OS is not Windows.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
/// @retval #INT_STATUS_NOT_FOUND If the entry point of the boot driver is not found.
///
{
    INTSTATUS status;
    QWORD cr3;
    DWORD imageSize, imageEp, ring;
    PBYTE pImage;
    BOOLEAN is64;

    imageSize = imageEp = ring = 0;
    pImage = NULL;
    cr3 = 0;

    if (gGuest.OSType != introGuestWindows)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    status = IntCr3Read(IG_CURRENT_VCPU, &cr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr3Read failed: 0x%08x\n", status);
        return status;
    }

    status = IntGetCurrentRing(IG_CURRENT_VCPU, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    TRACE("[AGENT] Initiating boot driver deployment...\n");

    is64 = gGuest.Guest64;

    status = IntLdrGetImageSizeAndEntryPoint(REM_DRV(is64), REM_SIZE(is64), &imageSize, &imageEp);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrGetImageSizeAndEntryPoint failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (imageEp == 0)
    {
        ERROR("[ERROR] No entry point found!\n");
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

    pImage = HpAllocWithTag(imageSize, IC_TAG_IMGE);
    if (NULL == pImage)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    TRACE("[AGENT] Loading boot driver image...\n");

    // NOTE: We will fix the imports inside the driver. The thing is, the EAT of certain modules may be swapped out;
    // Injecting page faults in order to access it is very possible & doable, but it would induce a very high
    // performance penalty; it is preferred, therefore, to fix the imports directly inside the driver.
    status = IntLdrLoadPEImage(REM_DRV(is64),
                               REM_SIZE(is64),
                               Agent->DriverAddress,
                               pImage,
                               imageSize,
                               LDR_FLAG_FIX_RELOCATIONS);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrLoadPEImage failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    TRACE("[AGENT] Deploying boot driver image...\n");

    IntPauseVcpus();

    status = IntVirtMemSafeWrite(cr3, Agent->DriverAddress, imageSize, pImage, ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        goto resume_and_exit;
    }

resume_and_exit:
    IntResumeVcpus();

    // Preserved status from IntValidateRangeForWrite/IntKernVirtMemWrite.
    if (!INT_SUCCESS(status))
    {
        goto cleanup_and_exit;
    }

    TRACE("[AGENT] Boot driver deployment successful!\n");

    // over-write the status
    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (NULL != pImage)
    {
        HpFreeAndNullWithTag(&pImage, IC_TAG_IMGE);
    }

    return status;
}


static INTSTATUS
IntWinAgentFindPropperSyscall(
    _Out_ QWORD *PropperSyscall
    )
///
/// @brief Find the main SYSCALL handler.
///
/// This function finds the main SYSCALL handler. Note that on KPTI systems, the SYSCALL MSR points to a shadow
/// SYSCALL handler, which only does the CR3 switch, and then jumps to the main SYSCALL handler, which is
/// interesting to us.
///
/// @param[in]  PropperSyscall  Will contain, upon successful return, the address of the main SYSCALL handler.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD rva;
    WIN_UNEXPORTED_FUNCTION_PATTERN *pPattern;

    // KiSystemServiceUser
    WIN_UNEXPORTED_FUNCTION_PATTERN functionPatternx64 =
    {
        .SectionHint = {0},
        .Signature = {
            .Length = 33,
            .SignatureId = 0,
            .Offset = 0,
            .Pattern = {
                0xc6, 0x45, 0x100, 0x02,                              // mov      byte ptr [rbp-55h],2
                0x65, 0x48, 0x8b, 0x1c, 0x25, 0x88, 0x01, 0x00, 0x00, // mov      rbx,qword ptr gs:[188h]
                0x0f, 0x0d, 0x8b, 0x100, 0x100, 0x00, 0x00,           // prefetchw [rbx+90h]
                0x0f, 0xae, 0x5d, 0x100,                              // stmxcsr dword ptr [rbp-54h]
                0x65, 0x0f, 0xae, 0x14, 0x25, 0x80, 0x01, 0x00, 0x00, // ldmxcsr dword ptr gs:[180h]
            }
        }
    };

    // KiFastCallEntryCommon
    WIN_UNEXPORTED_FUNCTION_PATTERN functionPatternx86 =
    {
        .SectionHint = {0},
        .Signature = {
            .Length = 34,
            .SignatureId = 0,
            .Offset = 0,
            .Pattern = {
                0x6a, 0x02,                               // push    2
                0x83, 0xc2, 0x08,                         // add     edx,8
                0x9d,                                     // popfd
                0x80, 0x4c, 0x24, 0x01, 0x02,             // or      byte ptr [esp+1],2
                0x6a, 0x1b,                               // push    1Bh
                0xff, 0x35, 0x100, 0x100, 0x100, 0x100,   // push    dword ptr [nt!KeI386FastSystemCallReturn
                                                          //                    (81ebdfdc)]
                0x6a, 0x00,                               // push    0
                0x55,                                     // push    ebp
                0x53,                                     // push    ebx
                0x56,                                     // push    esi
                0x57,                                     // push    edi
                0x64, 0x8b, 0x1d, 0x1c, 0x00, 0x00, 0x00, // mov     ebx,dword ptr fs:[1Ch]
                0x6a, 0x3b,                               // push    3Bh
            }
        }
    };

    // Already found the KiSystemServiceUser
    if (0 != gWinGuest->PropperSyscallGva)
    {
        *PropperSyscall = gWinGuest->PropperSyscallGva;
        return INT_STATUS_SUCCESS;
    }

    if (gGuest.Guest64)
    {
        pPattern = &functionPatternx64;
    }
    else
    {
        pPattern = &functionPatternx86;
    }

    // Find KiSystemServiceUser/KiFastCallEntryCommon. Since this is called only once and it is possible that we don't
    // have the KernelBuffer saved yet (there might be BP agents injected at init in order to swap the kernel),
    // we won't use the buffer in this case.
    status = IntPeFindFunctionByPattern(gGuest.KernelVa, pPattern, TRUE, &rva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntPeFindFunctionByPattern failed: 0x%08x\n", status);
        return status;
    }

    gWinGuest->PropperSyscallGva = gGuest.KernelVa + rva;

    *PropperSyscall = gWinGuest->PropperSyscallGva;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentFindSyscallLinkage(
    _In_ DWORD SyscallNumber,
    _Out_ QWORD *LinkageAddress
    )
///
/// @brief Find the address of the kernel linkage of a syscall.
///
/// Will use kernel buffer if available.
///
/// @param[in] SyscallNumber    The number of the syscall to be searched for.
/// @param[out] LinkageAddress  The address of the syscall kernel linkage.
///
/// @returns #INT_STATUS_SUCCESS on success or an appropriate #INTSTATUS error value.
///
{
    static WIN_UNEXPORTED_FUNCTION_PATTERN linkage64 =
    {
        .SectionHint = { 0 },
        .Signature =
        {
            .Length = 30,
            .SignatureId = 0,
            .Offset = 0,
            .Pattern =
            {
                0x48, 0x8b, 0xc4,                               // mov     rax,rsp
                0xfa,                                           // cli
                0x48, 0x83, 0xec, 0x10,                         // sub     rsp,10h
                0x50,                                           // push    rax
                0x9c,                                           // pushfq
                0x6a, 0x10,                                     // push    10h
                0x48, 0x8d, 0x100, 0x100, 0x100, 0x100, 0x100,  // lea     rax,[nt!KiServiceLinkage (fffff800`026fbb50)]
                0x50,                                           // push    rax
                0xb8, 0x81, 0x01, 0x00, 0x00,                   // mov     eax,181h
                0xe9, 0x100, 0x100, 0x100, 0x100,               // jmp     nt!KiServiceInternal (fffff800`02707e00)

            }
        }
    };

    static WIN_UNEXPORTED_FUNCTION_PATTERN linkage32 =
    {
        .SectionHint = { 0 },
        .Signature =
        {
            .Length = 20,
            .SignatureId = 0,
            .Offset = 0,
            .Pattern =
            {
                0xb8, 0x1e, 0x00, 0x00, 0x00,                   // mov     eax,1Eh
                0x8d, 0x54, 0x24, 0x04,                         // lea     edx,[esp+4]
                0x9c,                                           // pushfd
                0x6a, 0x08,                                     // push    8
                0xe8, 0x100, 0x100, 0x100, 0x100,               // call    nt!KiSystemService (8197d85a)
                0xc2, 0x100, 0x00,                              // ret     18h

            }
        }
    };

    WIN_UNEXPORTED_FUNCTION_PATTERN *const linkage = gGuest.Guest64 ? &linkage64 : &linkage32;
    const DWORD sysNoOffset = gGuest.Guest64 ? 21 : 1;
    DWORD rva;
    INTSTATUS status;

    // Place the syscall number inside the pattern
    for (size_t i = 0; i < sizeof(SyscallNumber); i++)
    {
        linkage->Signature.Pattern[i + sysNoOffset] = ((BYTE *)&SyscallNumber)[i];
    }

    if (NULL != gWinGuest->KernelBuffer && 0 == gWinGuest->RemainingSections)
    {
        status = IntPeFindFunctionByPatternInBuffer(gWinGuest->KernelBuffer, gWinGuest->KernelBufferSize,
                                                    linkage, TRUE, &rva);
    }
    else
    {
        status = IntPeFindFunctionByPattern(gGuest.KernelVa, linkage, TRUE, &rva);
    }

    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed to find syscall 0x%x kernel linkage: 0x%08x\n", SyscallNumber, status);
        return status;
    }

    TRACE("[INFO] Found syscall 0x%x linkage @ 0x%016llx\n", SyscallNumber, gGuest.KernelVa + rva);

    *LinkageAddress = gGuest.KernelVa + rva;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentFindInstruction(
    _In_ BYTE MinLen,
    _Out_ QWORD *InstructionVa,
    _Out_ BYTE *InstructionLen,
    _Out_writes_bytes_(ND_MAX_INSTRUCTION_LENGTH) BYTE *InstructionBytes
    )
///
/// @brief Searches for a suitable instruction to replace with a CALL to the trampoline code.
///
/// Will try to find, starting with the SYSCALL/SYSENTER address, the first "STI" instruction and then the first
/// instruction that's at least 5 bytes in length; this instruction will host our CALL towards the agent trampoline.
/// On x64, we will seek the 3rd STI instruction. The first 2 get executed on a very rare path.
/// If we inject a breakpoint agent, we will replace the instruction with an INT3 instead of a CALL.
///
/// @param[in]  MinLen              Unused.
/// @param[in]  InstructionVa       The guest virtual address where a suitable instruction was found.
/// @param[in]  InstructionLen      The length of the identified instruction.
/// @param[in]  InstructionBytes    Actual instruction bytes.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    PBYTE pSyscallCode;
    QWORD syscallGva;
    size_t parsed;
    BYTE cdef, ddef, stiCount, neededStiCount;
    BOOLEAN bFound, bStiFound;
    INSTRUX instrux;

    UNREFERENCED_LOCAL_VARIABLE(MinLen);

    if (NULL == InstructionVa)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    pSyscallCode = NULL;
    parsed = 0;
    bFound = bStiFound = FALSE;
    stiCount = 0;
    syscallGva = 0;

    pSyscallCode = HpAllocWithTag(PAGE_SIZE, IC_TAG_ALLOC);
    if (NULL == pSyscallCode)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    syscallGva = gWinGuest->SyscallAddress;

    if (gGuest.OSVersion <= 9200)
    {
        // Windows 7 and Windows 8 only have two STI instructions in the syscall code.
        neededStiCount = 2;
    }
    else
    {
        // Windows 8.1 and Windows 10 have 3 STI instructions in the syscall code.
        neededStiCount = 3;
    }

    status = IntWinAgentFindPropperSyscall(&syscallGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentFindKiSystemServiceUser failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    TRACE("[AGENT] Discovered the KiSystemServiceUser at 0x%016llx\n", syscallGva);

    // Read the SYSCALL/SYSENTRY code.
    status = IntKernVirtMemRead(syscallGva, PAGE_SIZE, pSyscallCode, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for syscall 0x%016llx: 0x%08x\n", syscallGva, status);
        goto cleanup_and_exit;
    }

    // Parse the read code in order to find the first "STI" and then the first instruction after the "STI" that's
    // at least 5 bytes long.
    if (gGuest.Guest64)
    {
        cdef = ND_CODE_64;
        ddef = ND_DATA_64;
    }
    else
    {
        cdef = ND_CODE_32;
        ddef = ND_DATA_32;
    }

    while (parsed + 16 < PAGE_SIZE)
    {
        NDSTATUS ndstatus;

        ndstatus = NdDecodeEx(&instrux, pSyscallCode + parsed, 0x1000 - parsed, cdef, ddef);
        if (!ND_SUCCESS(ndstatus))
        {
            ERROR("[ERROR] NdDecodeEx failed at 0x%016llx: 0x%08x\n", syscallGva + parsed, ndstatus);
            status = INT_STATUS_DISASM_ERROR;
            break;
        }

        if (!bStiFound)
        {
            if (ND_INS_STI == instrux.Instruction)
            {
                stiCount++;

                if ((stiCount == neededStiCount) || !gGuest.Guest64)
                {
                    bStiFound = TRUE;
                }
            }
        }
        else if ((instrux.Length >= MinLen) && !ND_HAS_PREDICATE(&instrux)) // Avoid conditional instructions.
        {
            bFound = TRUE;
            *InstructionVa = syscallGva + parsed;
            *InstructionLen = instrux.Length;
            memcpy(InstructionBytes, instrux.InstructionBytes, ND_MAX_INSTRUCTION_LENGTH);
            break;
        }

        parsed += instrux.Length;
    }

    if (!bFound)
    {
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    if (NULL != pSyscallCode)
    {
        HpFreeAndNullWithTag(&pSyscallCode, IC_TAG_ALLOC);
    }

    return status;
}


INTSTATUS
IntWinAgentActivatePendingAgent(
    void
    )
///
/// @brief Activates a pending agent that waits to be injected.
///
/// This function will inject a pending agent. The steps required are:
/// 1. Allocate slack space for the bootstrap code (NT slack)
/// 2. Inject & hide the bootstrap code inside the allocated slack space.
/// 3. Find a suitable instruction of length min 5 to detour
/// 4. Replace the instruction with a CALL to the trampoline code
/// Once the trampoline hyper call is hit, we will move execution to the bootstrap code.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;
    PWIN_AGENT pAgent;
    BYTE newCode[ND_MAX_INSTRUCTION_LENGTH] = {0};
    PBYTE originalBootstrap;

    pAgent = NULL;
    originalBootstrap = NULL;

    // If there are no pending agents or there are other agents bootstrapping, leave. We will inject our
    // agent only after the other ones are started.
    if ((0 == gAgentState.PendingAgentsCount) || (0 != gAgentState.BootstrapAgentsCount) ||
        (0 != gAgentState.CompletingAgentsCount))
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    // Search a suitable pending agent.
    list = gAgentState.PendingAgents.Flink;
    while (list != &gAgentState.PendingAgents)
    {
        PWIN_AGENT pAg = CONTAINING_RECORD(list, WIN_AGENT, Link);

        list = list->Flink;

        if ((pAg->AgentType == AGENT_TYPE_FILE) ||
            (pAg->AgentType == AGENT_TYPE_BINARY) ||
            (pAg->AgentType == AGENT_TYPE_DRIVER) ||
            (pAg->AgentType == AGENT_TYPE_BREAKPOINT) ||
            (pAg->AgentType == AGENT_TYPE_VE_LOADER) ||
            (pAg->AgentType == AGENT_TYPE_VE_UNLOADER) ||
            (pAg->AgentType == AGENT_TYPE_PT_LOADER) ||
            (pAg->AgentType == AGENT_TYPE_PT_UNLOADER) ||
            ((pAg->AgentType == AGENT_TYPE_PROCESS) && (gAgentState.SafeToInjectProcess)))
        {
            pAgent = pAg;

            break;
        }
    }

    if (NULL == pAgent)
    {
        status = INT_STATUS_SUCCESS;
        goto cleanup_and_exit;
    }

    TRACE("[AGENT] Activating pending agent, %d, remaining %d\n",
          gAgentState.SafeToInjectProcess, gAgentState.PendingAgentsCount - 1);

    // 1. Remove the agent from the pending-agents list and mark it as being the active agent.
    RemoveEntryList(&pAgent->Link);

    gAgentState.PendingAgentsCount--;

    gAgentState.BootstrapAgentsCount++;

    gAgentState.CompletingAgentsCount++;

    // Mark the current active agent.
    gAgentState.ActiveAgent = pAgent;


    // Pause the VCPUs while we modify the guest memory.
    IntPauseVcpus();

    // Handle special breakpoint agent injection.
    if (pAgent->AgentType == AGENT_TYPE_BREAKPOINT)
    {
        goto skip_bsp_injection;
    }

    // 2. Resolve the jump-back address of this bootstrap code. We will jump inside the trampoline, to the termination
    // code, and that code will inform us that the agent finished execution and can be removed.
    if (gGuest.Guest64)
    {
        *((PQWORD)(pAgent->BootStrap + pAgent->OffsetJumpBack)) = gAgentState.Trampoline + gAgentState.OffsetStop;
    }
    else
    {
        *((PDWORD)(pAgent->BootStrap + pAgent->OffsetJumpBack)) = (DWORD)(gAgentState.Trampoline +
                                                                          gAgentState.OffsetStop);
    }

    TRACE("[AGENT] Agent jumpback address is 0x%016llx\n", gAgentState.Trampoline + gAgentState.OffsetStop);

    // 3. Get us a bootstrap address for the loader. That's where the bootstrap code will be injected.
    status = IntWinAgentSelectBootstrapAddress(pAgent->BootstrapSize, &pAgent->BootstrapAddress);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntAgentSelectBootstrapAddress failed: 0x%08x\n", status);
        goto unpause_and_exit;
    }

    TRACE("[AGENT] Selected bootstrap address at 0x%016llx\n", pAgent->BootstrapAddress);

    // Patch the relocation offset.
    if (!gGuest.Guest64)
    {
        *((DWORD *)&pAgent->BootStrap[OFFSET_WIN_X86_RELOC]) = (DWORD)pAgent->BootstrapAddress;
    }

    // 4. Deploy the loader inside the previously obtained bootstrap zone and cloak the region it will reside in.
    originalBootstrap = HpAllocWithTag(pAgent->BootstrapSize, IC_TAG_ALLOC);
    if (NULL == originalBootstrap)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto unpause_and_exit;
    }

    status = IntKernVirtMemRead(pAgent->BootstrapAddress, pAgent->BootstrapSize, originalBootstrap, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for size %d on address %llx: 0x%08x\n",
              pAgent->BootstrapSize, pAgent->BootstrapAddress, status);
        goto unpause_and_exit;
    }

    status = IntMemClkCloakRegion(pAgent->BootstrapAddress,
                                  0,
                                  pAgent->BootstrapSize,
                                  MEMCLOAK_OPT_ALLOW_INTERNAL | MEMCLOAK_OPT_APPLY_PATCH,
                                  originalBootstrap,
                                  pAgent->BootStrap,
                                  NULL,
                                  &pAgent->BootCloakRegion);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed: 0x%08x\n", status);
        goto unpause_and_exit;
    }

skip_bsp_injection:
    // 5. Find a suitable instruction to overwrite. We parse the SYSCALL/SYSENTER code, and search for a "STI"
    // instruction. Once we find the "STI", we will seek an instruction that's at least 5 bytes in size, which
    // will host the CALL towards the trampoline.

    if (!!(pAgent->Options & AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE))
    {
        // We know for sure if the AG_FLAG_SET_INSTRUCTION_ON_RIP is given we are on the NtSetSystemPowerState
        // hook handler. So, after Rip (which is an int3) we'll have a 5 bytes NOP instruction which we'll replace
        // with a call to our agent trampoline. In the future we can search for an instruction with length >=5 starting
        // from the current rip but for now I can't see a use case regarding this.
        pAgent->InstructionAddress = gVcpu->Regs.Rip + 1;
        pAgent->InstructionLen = 5;

        status = IntKernVirtMemRead(pAgent->InstructionAddress, pAgent->InstructionLen, pAgent->InstructionBytes, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            goto unpause_and_exit;
        }
    }
    else
    {
        status = IntWinAgentFindInstruction(pAgent->AgentType == AGENT_TYPE_BREAKPOINT ? 1 : 5,
                                            &pAgent->InstructionAddress,
                                            &pAgent->InstructionLen,
                                            pAgent->InstructionBytes);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentFindInstruction failed: 0x%08x\n", status);
            goto unpause_and_exit;
        }
    }

    TRACE("[AGENT] Found suitable instruction of len %d at 0x%016llx\n", pAgent->InstructionLen,
          pAgent->InstructionAddress);

    // Initialize the new code. Fill it out with NOPs, and then add a CALL towards our handler or an INT3.
    memset(newCode, 0x90, sizeof(newCode));

    if (pAgent->AgentType == AGENT_TYPE_BREAKPOINT)
    {
        newCode[0] = 0xCC;
    }
    else
    {
        newCode[0] = 0xE8;
        *(DWORD *)(newCode + 1) = (DWORD)(gAgentState.Trampoline - pAgent->InstructionAddress - 5);
    }

    pAgent->InstructionRestored = FALSE;

    // 7. Patch the instruction with a CALL to the VMCALL code and cloak the region for that instruction.
    if (!!(pAgent->Options & AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE))
    {
        status = IntDetModifyPublicData(detTagPowerState, newCode, pAgent->InstructionLen, "5bytenop");
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDetModifyPublicData failed: 0x%08x\n", status);
            goto unpause_and_exit;
        }
    }
    else
    {
        status = IntMemClkCloakRegion(pAgent->InstructionAddress,
                                      0,
                                      pAgent->InstructionLen,
                                      MEMCLOAK_OPT_APPLY_PATCH,
                                      pAgent->InstructionBytes,
                                      newCode,
                                      NULL,
                                      &pAgent->InsCloakRegion);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed cloaking region 0x%016llx: 0x%08x\n", pAgent->InstructionAddress, status);
            goto unpause_and_exit;
        }
    }

    IntIcFlushAddress(gGuest.InstructionCache, pAgent->InstructionAddress, IC_ANY_VAS);

    // Done! Everything went fine!
    TRACE("[AGENT] Region successfully hooked!\n");

    status = INT_STATUS_SUCCESS;

unpause_and_exit:
    IntResumeVcpus();

cleanup_and_exit:
    if (NULL != originalBootstrap)
    {
        HpFreeAndNullWithTag(&originalBootstrap, IC_TAG_ALLOC);
    }

    if (!INT_SUCCESS(status))
    {
        // If we get here, the activation was not successful. Remove the agent.
        INTSTATUS status2 = IntWinAgentRemove(pAgent);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] IntAgentRemove failed: 0x%08x\n", status2);
        }

        gAgentState.BootstrapAgentsCount--;

        gAgentState.CompletingAgentsCount--;

        gAgentState.ActiveAgent = NULL;
    }

    return status;
}


static INTSTATUS
IntWinAgentRestoreState64(
    _In_ PWIN_AGENT Agent,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Restore the general purpose registers state.
///
/// This function restores the general purpose registers state after the bootstrap code has finished execution.
/// The transfer from the first section of the bootstrap to the trampoline must be done this way because in rare
/// cases, the thread that we created in the second section of the bootstrap may finish execution BEFORE the
/// first section of the bootstrap gets to return back to the trampoline, and it may lead to a use-after-free
/// situation, where we free the bootstrap inside guest memory before it returned to the trampoline. By doing
/// the transfer ourselves, and using a small semaphore inside the thread, we are ensured that the thread cannot
/// finish execution before the bootstrap returned to the trampoline.
///
/// @param[in]  Agent       The agent.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    QWORD regs[16] = {0}, sema = 1;

    // Fetch the registers + return address (note that RSP is not saved, hence 15 + 1 QWORDs) from the guest stack.
    status = IntKernVirtMemRead(Registers->Rsp, sizeof(regs), regs, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    // 2. Restore the registers inside the GPRs state
    Registers->R15 = regs[0];
    Registers->R14 = regs[1];
    Registers->R13 = regs[2];
    Registers->R12 = regs[3];
    Registers->R11 = regs[4];
    Registers->R10 = regs[5];
    Registers->R9 = regs[6];
    Registers->R8 = regs[7];
    Registers->Rdi = regs[8];
    Registers->Rsi = regs[9];
    Registers->Rbp = regs[10];
    Registers->Rbx = regs[11];
    Registers->Rdx = regs[12];
    Registers->Rcx = regs[13];
    Registers->Rax = regs[14];

    // 4. Restore the RIP
    Registers->Rip = regs[15];

    // 3. Restore the stack
    Registers->Rsp += 16 * 8;

    // Patch the registers!
    status = IntSetGprs(IG_CURRENT_VCPU, Registers);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        return status;
    }

    // Patch the semaphore field, used to spin. This is fine, we don't have to use IntVirtMemSafeWrite because
    // BootstrapAddress is allocated by Introcore, and is located in a protected memory region.
    status = IntKernVirtMemWrite(Agent->BootstrapAddress + OFFSET_WIN_X64_SEMAPHORE, 4, &sema);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        return status;
    }

    return status;
}


static INTSTATUS
IntWinAgentRestoreState32(
    _In_ PWIN_AGENT Agent,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Restore the general purpose registers state.
///
/// This function restores the general purpose registers state after the bootstrap code has finished execution.
/// The transfer from the first section of the bootstrap to the trampoline must be done this way because in rare
/// cases, the thread that we created in the second section of the bootstrap may finish execution BEFORE the
/// first section of the bootstrap gets to return back to the trampoline, and it may lead to a use-after-free
/// situation, where we free the bootstrap inside guest memory before it returned to the trampoline. By doing
/// the transfer ourselves, and using a small semaphore inside the thread, we are ensured that the thread cannot
/// finish execution before the bootstrap returned to the trampoline.
///
/// @param[in]  Agent       The agent.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    DWORD regs[9] = {0}, sema = 1;

    // Fetch the registers + return address (8 + 1 DWORDs) from the guest stack.
    status = IntKernVirtMemRead(Registers->Rsp, sizeof(regs), regs, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
        return status;
    }

    // 2. Restore the registers inside the GPRs state
    Registers->Rdi = regs[0];
    Registers->Rsi = regs[1];
    Registers->Rbp = regs[2];
    Registers->Rbx = regs[4];
    Registers->Rdx = regs[5];
    Registers->Rcx = regs[6];
    Registers->Rax = regs[7];

    // 4. Restore the RIP
    Registers->Rip = regs[8];

    // 3. Restore the stack
    Registers->Rsp += 9 * 4;

    // Patch the registers!
    status = IntSetGprs(IG_CURRENT_VCPU, Registers);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
        return status;
    }

    // Patch the semaphore field, used to spin. This is fine, we don't have to use IntVirtMemSafeWrite because
    // BootstrapAddress is allocated by Introcore, and is located in a protected memory region.
    status = IntKernVirtMemWrite(Agent->BootstrapAddress + OFFSET_WIN_X86_SEMAPHORE, 4, &sema);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        return status;
    }

    return status;
}


static INTSTATUS
IntWinAgentHandleBreakpointAgent(
    _In_ PWIN_AGENT Agent,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Handle an INT3 that was initiated by a breakpoint agent.
///
/// This function simply calls the injection callback. This function is used by the breakpoint agents, which
/// are simple agents that only trigger a breakpoint on the SYSCALL flow, where it is safe to inject kernel
/// page-faults or call kernel APIs. Once the injection callback is called, the agent will be freed.
/// NOTE: The ring must already be validated.
///
/// @param[in]  Agent       The agent to be injected.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success, if the breakpoint has already been handled.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NO_DETOUR_EMU If the breakpoint was handled by this instance.
///
{
    INTSTATUS status;

    if (NULL == Agent)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Registers->Rip != Agent->InstructionAddress)
    {
        ERROR("[ERROR] RIP mismatch: 0x%016llx vs. 0x%016llx!\n", Registers->Rip, Agent->InstructionAddress);
    }

    // First VMCALL inside the trampoline hit. We have to store in RAX the address of the bootstrap, we have
    // to restore the old, patched instruction, and we have to patch the return address for the call in order to
    // return to the actual "interrupted" instruction.
    TRACE("[AGENT] BREAKPOINT hit, restoring original code and calling callback...\n");

    // Now, if we're started, we can leave. Otherwise, proceed and restore the instruction + remove the cloaking.
    if (Agent->Flags & AGENT_FLAG_STARTED)
    {
        return INT_STATUS_SUCCESS;
    }

    // Remove the cloak region.
    status = IntMemClkUncloakRegion(Agent->InsCloakRegion, MEMCLOAK_OPT_APPLY_PATCH);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
        IntBugCheck();
    }

    Agent->InsCloakRegion = NULL;

    Agent->InstructionRestored = TRUE;

    Agent->Flags |= AGENT_FLAG_STARTED;

    status = Agent->InjectionCallback(0, Agent->AgentTag, Agent->Context);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Agent->InjectCallback failed: 0x%08x\n", status);
        return status;
    }

    Agent->Flags = AGENT_FLAG_ALL_DONE;

    status = IntWinAgentRemove(Agent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentRemove failed: 0x%08x\n", status);
    }

    // Decrement the number of active agents.
    gAgentState.CompletingAgentsCount--;

    gAgentState.BootstrapAgentsCount--;

    // Make the current active agent NULL.
    gAgentState.ActiveAgent = NULL;

    return INT_STATUS_NO_DETOUR_EMU;
}


static INTSTATUS
IntWinAgentHandleLoader1Hypercall(
    _In_opt_ WIN_AGENT *Agent,
    _In_ IG_ARCH_REGS *Registers
    )
///
/// @brief Handle a hyper call initiated by the trampoline code.
///
/// First HYPERCALL inside the trampoline hit. We have to store in RAX the address of the bootstrap, we have
/// to restore the old, patched instruction, and we have to patch the return address for the call in order to
/// return to the actual "interrupted" instruction.
///
/// NOTE: The ring must already be validated.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If the current RIP does not point inside the trampoline code.
///
{
    INTSTATUS status;

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    if (Registers->Rip == gAgentState.Trampoline + gAgentState.OffsetVmcall1)
    {
        DWORD offset = 0;
        QWORD retAddr = 0;

        // First HYPERCALL inside the trampoline hit. We have to store in RAX the address of the bootstrap, we have
        // to restore the old, patched instruction, and we have to patch the return address for the call in order to
        // return to the actual "interrupted" instruction.
        // Note that this may be hit after the agent terminated - a thread may have been de-scheduled right before
        // the INT3, and it may have been re-scheduled after the agent has completed.
        offset = gGuest.WordSize;

        // Fetch the return address.
        status = IntKernVirtMemRead(Registers->Rsp + offset, gGuest.WordSize, &retAddr, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for VA 0x%016llx (offset %x): 0x%08x\n",
                  Registers->Rsp, offset, status);
            IntBugCheck();
        }

        retAddr -= 5;

        status = IntVirtMemSafeWrite(gGuest.Mm.SystemCr3, Registers->Rsp + offset,
                                     gGuest.WordSize, &retAddr, IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemWrite failed for VA 0x%016llx: 0x%08x\n", Registers->Rsp + offset, status);
            IntBugCheck();
        }

        Registers->Rax = (NULL == Agent) ? 0 : ((Agent->Flags & AGENT_FLAG_STARTED) ? 0 : Agent->BootstrapAddress);

        // Patch the registers.
        status = IntSetGprs(IG_CURRENT_VCPU, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
            IntBugCheck();
        }

        // Now, if we're started, we can leave. Otherwise, proceed and restore the instruction + remove the cloaking.
        // Also, if the agent is NULL, leave now - it may have completed by now.
        if ((NULL == Agent) || (Agent->Flags & AGENT_FLAG_STARTED))
        {
            return INT_STATUS_SUCCESS;
        }

        TRACE("[AGENT] HYPERCALL1 hit, storing the agent bootstrap: 0x%016llx\n", Agent->BootstrapAddress);

        // Remove the cloak region.
        if (!!(Agent->Options & AG_OPT_INJECT_ON_RIP_POWSTATE_CHANGE))
        {
            BYTE fiveByteNop[] = {0x66, 0x66, 0x66, 0x66, 0x90};

            status = IntDetModifyPublicData(detTagPowerState, fiveByteNop, sizeof(fiveByteNop), "5bytenop");
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDetModifyPublicData failed: 0x%08x\n", status);
                IntBugCheck();
            }
        }
        else
        {
            status = IntMemClkUncloakRegion(Agent->InsCloakRegion, MEMCLOAK_OPT_APPLY_PATCH);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
                IntBugCheck();
            }
        }

        Agent->InsCloakRegion = NULL;

        Agent->InstructionRestored = TRUE;

        Agent->Flags |= AGENT_FLAG_STARTED;

        return status;
    }
    else if (Registers->Rip == gAgentState.Trampoline + gAgentState.OffsetVmcall2)
    {
        if (NULL == Agent)
        {
            return INT_STATUS_INVALID_PARAMETER_2;
        }

        // Second VMCALL hit, we can free the agent!
        TRACE("[AGENT] HYPERCALL2 hit, freeing the bootstrap at 0x%016llx\n", Agent->BootstrapAddress);

        if (AGENT_FLAG_ALL_DONE != (Agent->Flags & AGENT_FLAG_ALL_DONE))
        {
            ERROR("[ERROR] Agent termination requested, but the agent is not done yet = %x!\n", Agent->Flags);
            status = INT_STATUS_SUCCESS;
        }
        else
        {
            status = IntWinAgentRemove(Agent);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntAgentRemove failed: 0x%08x\n", status);
            }

            // Decrement the number of active agents.
            gAgentState.CompletingAgentsCount--;

            // Make the current active agent NULL.
            gAgentState.ActiveAgent = NULL;
        }

        return status;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntWinAgentReleaseBootstrap(
    _In_ WIN_AGENT *Agent,
    _In_ IG_ARCH_REGS *Registers
    )
///
/// @brief Releases the bootstrap allocated inside the guest.
///
/// @param[in]  Agent       The agent handle.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_NO_DETOUR_EMU As the call happens on a VMCALL, and we move the RIP ourselves, we do not wish to
///         have this emulated.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    if (gGuest.Guest64)
    {
        status = IntWinAgentRestoreState64(Agent, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentRestoreState64 failed: 0x%08x\n", status);
            IntBugCheck();
        }
    }
    else
    {
        status = IntWinAgentRestoreState32(Agent, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentRestoreState32 failed: 0x%08x\n", status);
            IntBugCheck();
        }
    }

    status = INT_STATUS_NO_DETOUR_EMU;

    Agent->Flags |= AGENT_FLAG_ACTIVE;

    // Update the bootstrap agents count. This one bootstrapped, we can decrement the counter.
    gAgentState.BootstrapAgentsCount--;

    return status;
}


static INTSTATUS
IntWinAgentRemoveAgentAndResetState(
    _In_ WIN_AGENT *Agent
    )
///
/// @brief Removes the indicated agent.
///
/// @param[in]  Agent   The agent to be removed.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntWinAgentRemove(Agent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentRemove failed: 0x%08x\n", status);
        return status;
    }

    gAgentState.CompletingAgentsCount--;

    gAgentState.ActiveAgent = NULL;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentReleaseBootstrapAndRemoveAgent(
    _In_ WIN_AGENT *Agent,
    _In_ IG_ARCH_REGS *Registers
    )
///
/// @brief Releases the bootstrap address and removes the agent.
///
/// @param[in]  Agent       The agent to be removed.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntWinAgentReleaseBootstrap(Agent, Registers);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentReleaseBootstrap failed: 0x%08x\n", status);
        return status;
    }

    status = IntWinAgentRemoveAgentAndResetState(Agent);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentRemoveAgentAndResetState failed: 0x%08x\n", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentHandleLoader2Hypercall(
    _In_ PWIN_AGENT Agent,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Handles VMCALLs issued by the bootstrap code.
///
/// This function handles hyper calls issued by the bootstrap code. There are 3 hyper calls defined:
/// 1. Allocate. The first hyper call is called as soon as memory is allocated inside the guest for the boot driver.
///    When handling this hyper call, we will simply deliver the boot driver in the freshly allocated memory space.
/// 2. Start. The second hyper call is called once the boot driver is started (a thread is created which executes
///    the boot driver). Inside this hyper-call we will modify the general purpose registers context in order
///    to divert code execution from the bootstrap to the trampoline, which will resume the execution of the detours
///    instruction.
/// 3. Complete. The final hyper call is issued when the thread has returned and the space allocated for the boot
///    driver has been freed.
/// NOTE: The ring must already be validated.
///
/// @param[in]  Agent       The agent.
/// @param[in]  Registers   The general purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NO_DETOUR_EMU If the VMCALL was handled by this function.
/// @retval #INT_STATUS_NOT_FOUND If the VMCALL was not issued by the bootstrap code.
///
{
    INTSTATUS status;
    QWORD argument;

    if (NULL == Agent)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    status = INT_STATUS_SUCCESS;

    // Second stage loader.

    // HYPERCALL from the bootstrap stub. The argument is in RCX.
    argument = Registers->Rcx;

    // We got our agent!
    if (Registers->Rdx == Agent->Token1)
    {
        // Agent has just been allocated.

        TRACE("[AGENT] Bootstrap reports that the agent has been allocated at 0x%016llx\n", argument);

        if (argument == 0 && !INT_SUCCESS((INTSTATUS)Registers->Rsi))
        {
            ERROR("[ERROR] Bootstrap reports agent allocation failed with status: 0x%08x\n", (DWORD)Registers->Rsi);

            status = IntWinAgentReleaseBootstrapAndRemoveAgent(Agent, Registers);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentReleaseBootstrapAndRemoveAgent failed: 0x%08x\n", status);
            }

            return INT_STATUS_NO_DETOUR_EMU;
        }

        Agent->DriverAddress = argument;

        status = IntWinAgentDeployWinDriver(Agent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentInjectWinDriver failed: 0x%08x\n", status);
            IntBugCheck();
        }

        // Invoke the injection callback.
        status = Agent->InjectionCallback(Agent->DriverAddress, Agent->AgentTag, Agent->Context);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Injection failed: 0x%08x\n", status);
        }

        Agent->Flags |= AGENT_FLAG_ALLOCATED;
    }
    else if (Registers->Rdx == Agent->Token2)
    {
        // Agent has just been started
        TRACE("[AGENT] Bootstrap reports that the agent has been started with result 0x%016llx\n", argument);

        status = IntWinAgentReleaseBootstrap(Agent, Registers);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentReleaseBootstrap failed: 0x%08x\n", status);
            return status;
        }

        if (!INT_SUCCESS(argument))
        {
            ERROR("[ERROR] Thread creation status: 0x%08x, will remove agent\n", (DWORD)argument);

            status = IntWinAgentRemoveAgentAndResetState(Agent);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentRemoveAgentAndResetState failed: 0x%08x\n", status);
            }

            return INT_STATUS_NO_DETOUR_EMU;
        }
    }
    else if (Registers->Rdx == Agent->Token3)
    {
        TRACE("[AGENT] Bootstrap reports completion with status = 0x%08x!\n", (DWORD)argument);

        Agent->Flags |= AGENT_FLAG_COMPLETED;
    }
    else
    {
        return INT_STATUS_NOT_FOUND;
    }

    if (AGENT_FLAG_ALL_DONE == (Agent->Flags & AGENT_FLAG_ALL_DONE))
    {
        INTSTATUS status2;

        TRACE("[AGENT] Agent bootstrap completed execution, will remove it soon.\n");

        status2 = Agent->CompletionCallback(Agent->DriverAddress, Agent->ErrorCode, Agent->AgentTag, Agent->Context);
        if (!INT_SUCCESS(status2))
        {
            ERROR("[ERROR] CompletionCallback failed: 0x%08x\n", status2);
        }

        Agent->DriverAddress = 0;
    }

    return status;
}


static INTSTATUS
IntWinAgentHandleDriverVmcall(
    _In_ PWIN_AGENT Agent,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief This function handles VMCALLs issued by the boot driver.
///
/// The boot driver may issue several VMCALLs which will be handled by Introcore. The defined VMCALLs are:
/// 1. #AGENT_HCALL_FETCH_CMD - fetches the command; this will make Introcore write a AGENT_COMMAND structure
///    inside the guest space, which will describe the operation that the boot driver must do.
/// 2. #AGENT_HCALL_FETCH_CHUNK - fetches a chunk of the actual agent; the size of the chunk is variable, and
///    the driver tells Introcore via the VMCALL parameters what is the max size it accepts.
/// 3. #AGENT_HCALL_MOD_BASE - returns the base address of a loaded module.
/// 4. #AGENT_HCALL_OWN_BASE - returns the base address of the boot driver itself.
/// 5. #AGENT_HCALL_VE - calls the init/uninit callback for the VE driver.
/// 6. #AGENT_HCALL_PT - calls the init/uninit callback for the PT driver.
/// 7. #AGENT_HCALL_VCPUID - returns the current VCPU id.
/// 8. #AGENT_HCALL_SYS_LNK - returns the address of a kernel syscall linkage.
/// 9. #AGENT_HCALL_ERROR - notify an error to the Introspection engine. Errors may capture various failures
///    along the agent injection path. For example, if a process agent is injected, and starting it inside
///    the guest fails, this will be used to send the error that appeared.
/// NOTE: Validations must be already made when calling this function.
///
/// @param[in]  Agent       The currently active agent.
/// @param[in]  Registers   General purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    QWORD arg1, arg2, op, res;

    if (NULL == Agent)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    res = 0;

    // The driver calls us. We'll make two safety checks:
    // 1. The caller is in kernel.
    // 2. The memory pages where we'll deploy the agent must be writable
    if (gGuest.Guest64)
    {
        arg1 = Registers->Rcx;
        arg2 = Registers->Rbx;
    }
    else
    {
        arg1 = Registers->Rsi;
        arg2 = Registers->Rdi;
    }

    op = Registers->Rdx;

    // If we are pending unload, ignore any agent request; we can simply return 0, which means error, and the agent
    // will bail out, and we'll be able to unload safely.
    if (gGuest.UninitPrepared && (AGENT_HCALL_ERROR != op) && (Agent->AgentType != AGENT_TYPE_PT_UNLOADER) &&
        (Agent->AgentType != AGENT_TYPE_VE_UNLOADER))
    {
        LOG("[AGENT] Uninit is prepared, will return error to the in-guest agent.\n");
        IntWinAgentRemoveEntryByAgid(Agent->Agid, NULL);
        res = (QWORD) - 1;
        goto bail_out;
    }

    if (AGENT_HCALL_FETCH_CMD == op)
    {
        AGENT_COMMAND cmd = {0};
        DWORD pidToInject = Agent->Pid;

        // This mirrors the logic from remdrv.sys' HandleProcess which will search for winlogon only when the PID
        // returned from this hypercall is 0
        if (0 == pidToInject)
        {
            PWIN_PROCESS_OBJECT pWinLogon = IntWinProcFindObjectByName("winlogon.exe", TRUE);

            if (NULL != pWinLogon)
            {
                pidToInject = pWinLogon->Pid;
            }
        }

        // The first argument is the buffer with the command.
        // The second argument is the buffer size.
        if (arg2 != sizeof(AGENT_COMMAND))
        {
            ERROR("[ERROR] Agent command structure mismatch: %lld vs %zu!\n", arg2, sizeof(AGENT_COMMAND));
            return INT_STATUS_NOT_SUPPORTED;
        }

        // Fetch the command.
        status = IntKernVirtMemRead(arg1, (DWORD)arg2, &cmd, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", arg1, status);
            return status;
        }

        if (cmd.Version != AGENT_COMMAND_VERSION)
        {
            ERROR("[ERROR] Agent command versions mismatch: %d vs %d\n", cmd.Version, AGENT_COMMAND_VERSION);
            return INT_STATUS_NOT_SUPPORTED;
        }

        cmd.Version = AGENT_COMMAND_VERSION;
        cmd.Pid = pidToInject;
        cmd.Type = Agent->AgentType;
        cmd.Synched = FALSE;
        cmd.Agid = Agent->Agid;
        cmd.Size = Agent->AgentSize;
        cmd.Flags = 0;
        cmd.Pointer = 0;
        memcpy(cmd.Name, Agent->Name, sizeof(cmd.Name));
        memcpy(cmd.Args, Agent->Args, sizeof(cmd.Args));

        if (AGENT_TYPE_VE_UNLOADER == Agent->AgentType)
        {
            cmd.Pointer = IntVeGetDriverAddress();
        }
        else if (AGENT_TYPE_PT_UNLOADER == Agent->AgentType)
        {
            cmd.Pointer = IntPtiGetAgentAddress();
        }

        IntPauseVcpus();

        status = IntVirtMemSafeWrite(Registers->Cr3, arg1, (DWORD)arg2, &cmd, IG_CS_RING_0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemSafeWrite failed: 0x%08x\n", status);
        }

        IntResumeVcpus();

        res = INT_SUCCESS(status) ? 0 : (QWORD) - 1;
    }
    else if (AGENT_HCALL_FETCH_CHUNK == op)
    {
        DWORD actualCopy;

        IntPauseVcpus();

        actualCopy = (DWORD)MIN(arg2, Agent->AgentSize - Agent->AgentPosition);

        if (actualCopy > 0 && Agent->AgentPosition < Agent->AgentSize)
        {
            status = IntVirtMemSafeWrite(Registers->Cr3,
                                         arg1,
                                         actualCopy,
                                         &Agent->AgentContent[Agent->AgentPosition],
                                         IG_CS_RING_0);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntVirtMemSafeWrite failed at GVA 0x%016llx, size %x: 0x%08x\n",
                      arg1, actualCopy, status);

                res = 0;
            }
            else
            {
                res = actualCopy;

                Agent->AgentPosition += (DWORD)res;
            }
        }
        else
        {
            res = 0;
        }

        IntResumeVcpus();
    }
    else if (AGENT_HCALL_MOD_BASE == op)
    {
        char modName[256];
        PWCHAR wModuleName;
        DWORD len, i;
        QWORD modBase;

        wModuleName = NULL;

        memset(modName, 0, sizeof(modName));

        len = (DWORD)MIN(arg2, 255u);

        status = IntKernVirtMemRead(arg1, len, modName, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x\n", status);
            modBase = 0;
            goto _mod_fail_and_exit;
        }

        // len + 2 OK: len is not longer than 255.
        wModuleName = HpAllocWithTag((len + 1ull) * 2, IC_TAG_DRNU);
        if (NULL == wModuleName)
        {
            modBase = 0;
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto _mod_fail_and_exit;
        }

        i = 0;

        while (i < len + 1)
        {
            wModuleName[i] = modName[i];

            i++;
        }

        if (0 == strcmp(modName, "ntoskrnl.exe"))
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByLoadOrder(0);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntDriverFindByLoadOrder failed for %s: 0x%08x\n", modName, status);
                modBase = 0;
                goto _mod_fail_and_exit;
            }

            modBase = pDriver->BaseVa;
        }
        else if (0 == strcmp(modName, "hal.dll"))
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByLoadOrder(1);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntDriverFindByLoadOrder failed for %s: 0x%08x\n", modName, status);
                modBase = 0;
                goto _mod_fail_and_exit;
            }

            modBase = pDriver->BaseVa;
        }
        else
        {
            KERNEL_DRIVER *pDriver = IntDriverFindByName(wModuleName);
            if (NULL == pDriver)
            {
                ERROR("[ERROR] IntDriierverFindByName failed for %s: 0x%08x\n", modName, status);
                modBase = 0;
                goto _mod_fail_and_exit;
            }

            modBase = pDriver->BaseVa;
        }


_mod_fail_and_exit:

        if (NULL != wModuleName)
        {
            HpFreeAndNullWithTag(&wModuleName, IC_TAG_DRNU);
        }

        // Store the module base in Rax.
        res = modBase;
    }
    // op == 4 -> Request agent pool address.
    else if (AGENT_HCALL_OWN_BASE == op)
    {
        res = Agent->DriverAddress;
    }
    // op == 5 -> Request a generic data region to be delivered inside a pre-allocated memory region.
    else if (AGENT_HCALL_VE == op || AGENT_HCALL_PT == op)
    {
        if (NULL != Agent->DeliverCallback)
        {
            res = Agent->DeliverCallback(arg1, (DWORD)arg2, Agent->Context);
        }
    }
    else if (AGENT_HCALL_VCPUID == op)
    {
        res = gVcpu->Index;
    }
    else if (AGENT_HCALL_SYS_LNK == op)
    {
        QWORD linkage = 0;
        DWORD sysNo;

        if (arg1 >= winKmFieldSyscallNumbersEnd)
        {
            ERROR("[ERROR] Requested syscall linkage not supported by introcore: 0x%016llx\n", arg1);
            goto _sys_lnk_fail_and_exit;
        }

        sysNo = gWinGuest->OsSpecificFields.Km.SyscallNumbers[arg1];
        status = IntWinAgentFindSyscallLinkage(sysNo, &linkage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentFindSyscallLinkage failed for 0x%x: 0x%08x\n", sysNo, status);
            linkage = 0;
        }

_sys_lnk_fail_and_exit:

        res = linkage;
    }
    else if (AGENT_HCALL_ERROR == op)
    {
        LOG("[AGENT] Agent reports error code: 0x%08x\n", (DWORD)arg2);
        Agent->ErrorCode = (DWORD)arg2;
        res = 0;

        if (Agent->ErrorCode != 0)
        {
            PEVENT_AGENT_EVENT event = &gAlert.Agent;

            event->Event = agentError;
            event->AgentTag = Agent->AgentTag;
            event->ErrorCode = Agent->ErrorCode;

            status = IntNotifyIntroEvent(introEventAgentEvent, event, sizeof(*event));
            if (!INT_SUCCESS(status))
            {
                WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
            }

            // An error occurred, the process will never be created - remove it from the list of pending processes.
            IntWinAgentRemoveEntryByAgid(Agent->Agid, NULL);
        }
    }

bail_out:
    // NOTE: The result is returned in EDX/RDX due to the fact that Xen hypercall interface always returns 0 in EAX/RAX.
    Registers->Rdx = res;

    status = IntSetGprs(IG_CURRENT_VCPU, Registers);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSetGprs failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntWinAgentHandleAppVmcall(
    _In_opt_ void *Reserved,
    _In_ PIG_ARCH_REGS Registers
    )
///
/// @brief Handles a VMCALL issued by an application that has been injected inside the guest.
///
/// Each injected application should have its own private VMCALL structure, depending on what information
/// it wants to report. Currently, Introcore can digest VMCALLs from two types of applications:
/// 1. #AGENT_HCALL_REM_TOOL - the remediation tool. This is used to send scan statuses (detections, disinfections,
///    etc.) to Introcore and to the integrator.
/// 2. #AGENT_HCALL_GATHER_TOOL - the log gather tool. This tool is used to gather logs from the target virtual
///    machine and this VMCALL is used to send to log chunks to Introcore and the integrator.
/// NOTE: If the current process has not been marked as an agent (if it was not started directly by us or by a process
/// which we injected), all the VMCALLs will be silently discarded.
///
/// @param[in]  Reserved        Reserved for future use.
/// @param[in]  Registers       General purpose registers state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    QWORD arg1, arg2, op;

    UNREFERENCED_PARAMETER(Reserved);

    if (NULL == Registers)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    // The driver calls us. We'll make two safety checks:
    // 1. The caller is in kernel.
    // 2. The memory pages where we'll deploy the agent must be writable
    if (gGuest.Guest64)
    {
        arg1 = Registers->Rcx;
        arg2 = Registers->Rbx;
    }
    else
    {
        arg1 = (DWORD)Registers->Rsi;
        arg2 = (DWORD)Registers->Rdi;
    }

    op = Registers->Rdx;

    // for now, we will keep different HCALLs for different visibility event jobs, but maybe we should have one
    // HCALL and multiple job types?
    if (AGENT_HCALL_INTERNAL == op)
    {
        // This is reserved for reporting error codes from within the winlogon.exe process start stub.
        PEVENT_AGENT_EVENT event = &gAlert.Agent;

        IntWinAgentRemoveEntryByAgid((DWORD)arg1, &event->AgentTag);

        event->Event = agentError;
        event->ErrorCode = (DWORD)arg2;

        LOG("[AGENT] User-mode stub reports error for agent with tag %d: 0x%08x\n", event->AgentTag, event->ErrorCode);

        status = IntNotifyIntroEvent(introEventAgentEvent, event, sizeof(*event));
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%x\n", status);
        }
    }
    else
    {
        PWIN_PROCESS_OBJECT pProc = IntWinProcFindObjectByCr3(Registers->Cr3);

        // bail out if this VMCALL is not from an agent or it is from a previous agent
        if (NULL == pProc)
        {
            WARNING("[WARNING] VMCALL received from unknown process, will ignore. Cr3 = 0x%016llx\n", Registers->Cr3);
            return INT_STATUS_SUCCESS;
        }
        else if (!pProc->IsAgent || pProc->IsPreviousAgent)
        {
            TRACE("[AGENT] VMCALL with op = %lld from `%s` (PID = %d) which is not an agent (previous = %d), "
                  "will ignore\n", op, pProc->Name, pProc->Pid, pProc->IsPreviousAgent);
            return INT_STATUS_SUCCESS;
        }

        if (AGENT_HCALL_REM_TOOL == op)
        {
            status = IntAgentHandleRemediationVmcall(NULL, Registers);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntAgentHandleRemediationVmcall failed: 0x%08x\n", status);
                return status;
            }
        }
        else if (AGENT_HCALL_GATHER_TOOL == op)
        {
            status = IntAgentHandleLogGatherVmcall(NULL, Registers);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntAgentHandleLogGatherVmcall failed: 0x%08x\n", status);
                return status;
            }
        }
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinAgentHandleInt3(
    _In_ QWORD Rip,
    _In_ DWORD CpuNumber
    )
///
/// @brief Handle a breakpoint that was initiated inside the guest.
///
/// This function will search for an appropriate handler for the breakpoint. There are several causes for
/// such breakpoints:
/// 1. Issued by the trampoline code;
/// 2. Issued by the bootstrap code;
/// 3. Issued directly by the instruction that was replaced with a breakpoint (direct breakpoint agents);
/// 4. Spuriously issued by the remnant of an agent (it can happen in multi-CPU systems, where a breakpoint
///    remains pending on a VCPU until another VCPU gets to handle it).
/// NOTE: The notion of VMCALL or hyper call is used generically to any method of communication between the
/// in-guest Introcore components and Introcore. Generally, due to space constraints, we use breakpoint
/// "hyper calls" instead of VMCALL, since a breakpoint is a single byte, instead of three.
///
/// @param[in]  Rip         Unused.
/// @param[in]  CpuNumber   The VCPU number on which the event took place.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_FOUND If a handler is not found.
///
{
    INTSTATUS status, status2;
    PWIN_AGENT pAg;
    PIG_ARCH_REGS regs;
    DWORD ring;

    UNREFERENCED_PARAMETER(Rip);

    ring = 0;

    regs = &gVcpu->Regs;

    status = IntGetCurrentRing(CpuNumber, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    // No point in handling ring 3 breakpoints. We never establish breakpoints in user-mode, so this must be reinjected.
    if (0 != ring)
    {
        return INT_STATUS_NOT_FOUND;
    }

    // Make sure we have an active agent.
    pAg = gAgentState.ActiveAgent;

    if ((NULL == pAg) && (regs->Rip == gAgentState.Trampoline + gAgentState.OffsetVmcall1))
    {
        // This can happen when:
        // 1. there are more than 1 VCPUs
        // 2. the trigger SYSCALL is executed on at least 2 VCPUs
        // 3. one of the VCPUs gets to inject the agent
        // 4. the other VCPU is delayed significantly and executes the INT3 after the agent has been fully injected
        status = IntWinAgentHandleLoader1Hypercall(NULL, regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentHandleLoader1Hypercall failed: 0x%08x\n", status);
        }

        goto cleanup_and_exit;
    }

    if (pAg)
    {
        // Trampoline breakpoint.
        if ((regs->Rip == gAgentState.Trampoline + gAgentState.OffsetVmcall1) ||
            (regs->Rip == gAgentState.Trampoline + gAgentState.OffsetVmcall2))
        {
            status = IntWinAgentHandleLoader1Hypercall(pAg, regs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentHandleLoader1Hypercall failed: 0x%08x\n", status);
            }
        }
        // Bootstrap breakpoint.
        else if ((regs->Rip >= pAg->BootstrapAddress) && (regs->Rip < pAg->BootstrapAddress + pAg->BootstrapSize))
        {
            status = IntWinAgentHandleLoader2Hypercall(pAg, regs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentHandleLoader2Hypercall failed: 0x%08x\n", status);
            }
        }
        // Direct breakpoint agent.
        else if ((regs->Rip == pAg->InstructionAddress) && (pAg->AgentType == AGENT_TYPE_BREAKPOINT))
        {
            status = IntWinAgentHandleBreakpointAgent(pAg, regs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentHandleBreakpointAgent failed: 0x%08x\n", status);
            }
        }
        // Unknown.
        else
        {
            status = INT_STATUS_NOT_FOUND;
            goto cleanup_and_exit;
        }
    }
    else
    {
        status = INT_STATUS_NOT_FOUND;
        goto cleanup_and_exit;
    }

cleanup_and_exit:
    // One agent finished execution, schedule another, if there are any.
    status2 = IntWinAgentActivatePendingAgent();
    if (!INT_SUCCESS(status2))
    {
        ERROR("[ERROR] IntAgentActivatePendingAgent failed: 0x%08x\n", status2);
    }

    return status;
}


INTSTATUS
IntWinAgentHandleVmcall(
    _In_ QWORD Rip
    )
///
/// @brief Handle a VMCALL that was executed inside the guest.
///
/// This function handles VMCALLs that took place inside the guest. Since the small agent components
/// (trampoline, bootstrap) use INT3, the VMCALL issued by the boot driver and the user-mode applications
/// that get injected by Introcore.
///
/// @param[in]  Rip The RIP where the VMCALL was initiated.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;
    PIG_ARCH_REGS regs;
    DWORD ring = 0;

    regs = &gVcpu->Regs;

    status = IntGetCurrentRing(gVcpu->Index, &ring);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGetCurrentRing failed: 0x%08x\n", status);
        return status;
    }

    TRACE("VMCALL -> rip: 0x%016llx, cr3: 0x%016llx, rax: 0x%016llx, rcx: 0x%016llx, rdx: 0x%016llx, rbx: 0x%016llx\n",
          regs->Rip, regs->Cr3, regs->Rax, regs->Rcx, regs->Rdx, regs->Rbx);

    if (0 == ring)
    {
        PWIN_AGENT pAg;

        // ring0 hypercall; this happens in three cases:
        // 1. stage 1 loader
        // 2. stage 2 loader
        // 3. agent driver

        // Make sure we have an active agent.
        if (NULL == gAgentState.ActiveAgent)
        {
            ERROR("[ERROR] VMCALL with no active agent from RIP 0x%016llx!\n", regs->Rip);
            goto cleanup_and_exit;
        }

        pAg = gAgentState.ActiveAgent;

        if ((pAg->DriverAddress <= Rip) && (pAg->DriverAddress + pAg->DriverSize > Rip))
        {
            status = IntWinAgentHandleDriverVmcall(pAg, regs);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntWinAgentHandleDriverVmcall failed: 0x%08x\n", status);
            }
        }
    }
    else
    {
        // ring3 hypercall; these are initiated by the agents. Note that these can be issued at any time, even
        // after an introcore unload/reload. They must not fail.
        status = IntWinAgentHandleAppVmcall(NULL, regs);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentHandleAppVmcall failed: 0x%08x\n", status);
        }
    }

cleanup_and_exit:

    // One agent finished execution, schedule another, if there are any.
    status = IntWinAgentActivatePendingAgent();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinAgentActivatePendingAgent failed: 0x%08x\n", status);
    }

    // We must return success, otherwise the HV might bug-check.
    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinAgentSelectBootstrapAddress(
    _In_ DWORD Size,
    _Out_ QWORD *Address
    )
///
/// @brief Finds an in-guest adders that can be used to host the bootstrap code.
///
/// This function will try to allocate slack space inside NT. If no such space is found, it will attempt to find slack
/// space inside another loaded module. This is safe, since the small trampoline code jumps to the bootstrap code via
/// an indirect call (CALL rax), so the bootstrap code doesn't have to be withing [-2G, +2G] of the trampoline.
///
/// @param[in]  Size    The size required for the bootstrap code.
/// @param[out] Address Guest virtual address where the bootstrap has been allocated.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    INTSTATUS status;
    KERNEL_DRIVER *pDriver;

    if (NULL == Address)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    // If we've been loaded from the OS, we'll use the first page of the kernel - the headers.
    // This is dirty and patchy, but it is just for testing purposes.

    // First, try the kernel.
    TRACE("[AGENT] Trying to find slack inside the kernel...\n");

    status = IntSlackAlloc(gGuest.KernelVa, FALSE, Size, Address, 0);
    if (INT_SUCCESS(status))
    {
        // We've found slack space, we're done here.
        gGuest.BootstrapAgentAllocated = TRUE;
        goto cleanup_and_exit;
    }

    // We couldn't find slack inside the kernel, we'll try inside hal or other core module, that can't unload.
    for (DWORD i = 1; i < 5; i++)
    {
        pDriver = IntDriverFindByLoadOrder(i);
        if (NULL == pDriver)
        {
            continue;
        }

        TRACE("[AGENT] Trying to find slack inside '%s'...\n", utf16_for_log(pDriver->Name));

        status = IntSlackAlloc(pDriver->BaseVa, FALSE, Size, Address, 0);
        if (INT_SUCCESS(status))
        {
            // We've found slack space, we're done here.
            goto cleanup_and_exit;
        }
    }

cleanup_and_exit:
    ;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinAgentReleaseBootstrapAddress(
    _In_ QWORD Address
    )
///
/// @brief Releases the slack space allocated for the bootstrap code.
///
/// @param[in]  Address The previously allocated bootstrap address.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    gGuest.BootstrapAgentAllocated = FALSE;

    return IntSlackFree(Address);
}


static void
IntWinAgentSelectTokens(
    _Out_opt_ QWORD *Token1,
    _Out_opt_ QWORD *Token2,
    _Out_opt_ QWORD *Token3
    )
///
/// @brief Randomly select 3 tokens to be used by the bootstrap code when issuing hyper calls.
///
/// Since we don't want to allow random hyper calls from guest space, we randomly generate 3 tokens which will
/// be passed to Introcore by the bootstrap code. Each token must match when calling Introcore.
///
/// @param[out] Token1  The first token.
/// @param[out] Token2  The second token.
/// @param[out] Token3  The third token.
///
{
    QWORD tk;

    if (NULL != Token1)
    {
        tk = __rdtsc();

        *Token1 = gGuest.Guest64 ? tk : (tk & 0xFFFFFFFF);
    }

    if (NULL != Token2)
    {
        tk = __rdtsc();

        *Token2 = gGuest.Guest64 ? tk : (tk & 0xFFFFFFFF);
    }

    if (NULL != Token3)
    {
        tk = __rdtsc();

        *Token3 = gGuest.Guest64 ? tk : (tk & 0xFFFFFFFF);
    }
}


INTSTATUS
IntWinAgentInject(
    _In_ PFUNC_AgentInjection InjectionCallback,
    _In_ PFUNC_AgentCompletion CompletionCallback,
    _In_opt_ PFUNC_AgentDeliver DeliverCallback,
    _In_opt_ void *Context,
    _In_ PBYTE AgentContent,
    _In_ DWORD AgentSize,
    _In_ BOOLEAN AgentInternal,
    _In_ DWORD AgentTag,
    _In_ AGENT_TYPE AgentType,
    _In_opt_z_ const CHAR *Name,
    _In_ DWORD Options,
    _In_opt_ const CHAR *Args,
    _In_opt_ DWORD Pid,
    _Outptr_opt_ PWIN_AGENT *Agent
    )
///
/// @brief Schedule an agent injection inside the guest.
///
/// This function schedules the injection of an agent inside the guest space. If this function succeeds means that the
/// injection has been successfully scheduled; it does not mean that the agent has been successfully injected.
/// This function can be used to inject files or processes inside the guest. This function is also used to inject
/// the VE and PT agents inside the guest. Due to the 3 callbacks architecture, it is very flexible and it allows
/// the caller to extend this mechanism with his own defined callbacks.
///
/// @param[in]  InjectionCallback   This callback is called after the boot driver has been successfully injected
///                                 inside the guest.
/// @param[in]  CompletionCallback  This callback is called after the boot driver has finished execution, and
///                                 the agent is being removed from memory.
/// @param[in]  DeliverCallback     This callback is called by VE and PT handlers inside the boot driver. This
///                                 callback basically allows us to inject a next stage agent, and to initialize
///                                 it, without having to rely on the guest for that.
/// @param[in]  Context             Optional agent context.
/// @param[in]  AgentContent        Pointer to a memory area containing the actual agent.
/// @param[in]  AgentSize           The size of the agent, in bytes.
/// @param[in]  AgentInternal       True if this is an internal agent (statically allocated inside Introcore).
/// @param[in]  AgentTag            Agent tag. Check out AGENT_TAG* for more info.
/// @param[in]  AgentType           Agent type. Check out AGENT_TYPE* for more info.
/// @param[in]  Name                Agent name.
/// @param[in]  Options             Agent options.
/// @param[in]  Args                Agent arguments. Passed as a command line for process agents.
/// @param[in]  Pid                 PID of the process that will be the parent of the agent process.
///                                 if this is 0, winlogon will be chosen as a parent.
/// @param[in]  Agent               Will contain, in successful return, the handle to the newly scheduled agent.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_OPERATION_NOT_IMPLEMENTED If the current guest is not Windows.
/// @retval #INT_STATUS_ALREADY_INITIALIZED If an agent with the same name has already been injected.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    PWIN_AGENT pAg;
    PAGENT_NAME pAgName;
    INTSTATUS status;
    QWORD token1, token2, token3;
    PBYTE pBs;

    UNREFERENCED_PARAMETER(Agent);

    token1 = 0;
    token2 = 0;
    token3 = 0;
    pAgName = NULL;
    pAg = NULL;

    if (NULL == InjectionCallback)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == CompletionCallback)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (gGuest.OSType != introGuestWindows)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    if (AGENT_TYPE_PROCESS == AgentType)
    {
        if (NULL == Name)
        {
            return INT_STATUS_INVALID_PARAMETER_4;
        }

        if (strlen(Name) >= IG_MAX_AGENT_NAME_LENGTH)
        {
            return INT_STATUS_INVALID_PARAMETER_4;
        }

        if ((NULL != Args) && (strlen(Args) >= IG_MAX_COMMAND_LINE_LENGTH))
        {
            return INT_STATUS_INVALID_PARAMETER_10;
        }
    }

    if (AGENT_TYPE_FILE == AgentType)
    {
        if (NULL == Name)
        {
            return INT_STATUS_INVALID_PARAMETER_4;
        }
    }

    // Make sure that another agent with this name isn't injected
    if (NULL != Name)
    {
        LIST_ENTRY *list = gAgentState.AgentNames.Flink;
        while (list != &gAgentState.AgentNames)
        {
            pAgName = CONTAINING_RECORD(list, AGENT_NAME, Link);
            list = list->Flink;

            if (0 == strcasecmp(pAgName->ImageName, Name))
            {
                ERROR("[ERROR] An agent with the name '%s' is already injected!\n", Name);

                status = INT_STATUS_ALREADY_INITIALIZED;

                goto cleanup_and_exit;
            }
        }

        pAgName = NULL;
    }

    IntWinAgentSelectTokens(&token1, &token2, &token3);

    TRACE("[AGENT] Selected tokens: 0x%016llx 0x%016llx 0x%016llx\n", token1, token2, token3);

    pAg = HpAllocWithTag(sizeof(*pAg), IC_TAG_AGNE);
    if (NULL == pAg)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    pAg->AgentType = AgentType;
    pAg->HcallType = AGENT_HCALL_INT3;
    pAg->InjectionCallback = InjectionCallback;
    pAg->CompletionCallback = CompletionCallback;
    pAg->DeliverCallback = DeliverCallback;
    pAg->Context = Context;
    pAg->AgentTag = AgentTag;
    pAg->DriverAddress = 0;
    pAg->Token1 = token1;
    pAg->Token2 = token2;
    pAg->Token3 = token3;
    pAg->InsCloakRegion = NULL;
    pAg->BootCloakRegion = NULL;
    pAg->InstructionRestored = TRUE;
    pAg->Pid = Pid;
    pAg->ArgsLen = 0;
    pAg->AgentContent = AgentContent;
    pAg->AgentSize = AgentSize;
    pAg->AgentInternal = AgentInternal;
    pAg->AgentPosition = 0;
    pAg->Agid = gAgentState.Counter++;
    pAg->Options = Options;

    if (NULL != Args)
    {
        pAg->ArgsLen = strlen(Args);
        if (pAg->ArgsLen >= sizeof(pAg->Args))
        {
            status = INT_STATUS_INVALID_PARAMETER_12;
            goto cleanup_and_exit;
        }

        if (pAg->ArgsLen > 0)
        {
            strlcpy(pAg->Args, Args, sizeof(pAg->Args));
        }
    }

    if (NULL != Name)
    {
        strlcpy(pAg->Name, Name, sizeof(pAg->Name));
    }

    status = IntLdrGetImageSizeAndEntryPoint(REM_DRV(gGuest.Guest64),
                                             REM_SIZE(gGuest.Guest64),
                                             &pAg->DriverSize,
                                             &pAg->DriverEntryPoint);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLdrGetImageSizeAndEntryPoint failed: 0x%08x\n", status);
        goto cleanup_and_exit;
    }

    if (gGuest.Guest64)
    {
        pAg->BootstrapSize = sizeof(gWindowsBootstrapAgentx64);

        memcpy(pAg->BootStrap, gWindowsBootstrapAgentx64, MIN(MAX_BOOTSTRAP_SIZE, pAg->BootstrapSize));
    }
    else
    {
        pAg->BootstrapSize = sizeof(gWindowsBootstrapAgentx86);

        memcpy(pAg->BootStrap, gWindowsBootstrapAgentx86, MIN(MAX_BOOTSTRAP_SIZE, pAg->BootstrapSize));
    }

    pBs = pAg->BootStrap;

    // Fix bootstrap agent internal variables
    if (gGuest.Guest64)
    {
        *((PQWORD)(pBs + OFFSET_WIN_X64_ALLOC)) = gWinGuest->ExAllocatePoolWithTag;
        *((PQWORD)(pBs + OFFSET_WIN_X64_THREAD)) = gWinGuest->PsCreateSystemThread;
        *((PQWORD)(pBs + OFFSET_WIN_X64_FREE)) = gWinGuest->ExFreePoolWithTag;
        *((PDWORD)(pBs + OFFSET_WIN_X64_AGENT_SIZE)) = pAg->DriverSize;
        *((PDWORD)(pBs + OFFSET_WIN_X64_AGENT_EP)) = pAg->DriverEntryPoint;
        // It seems that on Windows 10 RS6 return NULL if we try to ExAllocatePoolWithTag and the tag is in the
        // range used by our internals tags ([0, 100]).
        // Anyways, the documentation states that each tag character must have a value between [0x20, 0x7E].
        *((PDWORD)(pBs + OFFSET_WIN_X64_AGENT_TAG)) = 'Agnt'; // AgentTag;

        *((PQWORD)(pBs + OFFSET_WIN_X64_TOKEN1)) = token1;
        *((PQWORD)(pBs + OFFSET_WIN_X64_TOKEN2)) = token2;
        *((PQWORD)(pBs + OFFSET_WIN_X64_TOKEN3)) = token3;

        *((PQWORD)(pBs + OFFSET_WIN_X64_JUMPBACK)) = 0;

        pAg->OffsetJumpBack = OFFSET_WIN_X64_JUMPBACK;
    }
    else
    {
        *((PDWORD)(pBs + OFFSET_WIN_X86_ALLOC)) = (DWORD)gWinGuest->ExAllocatePoolWithTag;
        *((PDWORD)(pBs + OFFSET_WIN_X86_THREAD)) = (DWORD)gWinGuest->PsCreateSystemThread;
        *((PDWORD)(pBs + OFFSET_WIN_X86_FREE)) = (DWORD)gWinGuest->ExFreePoolWithTag;
        *((PDWORD)(pBs + OFFSET_WIN_X86_AGENT_SIZE)) = pAg->DriverSize;
        *((PDWORD)(pBs + OFFSET_WIN_X86_AGENT_EP)) = pAg->DriverEntryPoint;
        // It seems that on Windows 10 RS6 return NULL if we try to ExAllocatePoolWithTag and the tag is in the
        // range used by our internals tags ([0, 100]).
        // Anyways, the documentation states that each tag character must have a value between [0x20, 0x7E].
        *((PDWORD)(pBs + OFFSET_WIN_X86_AGENT_TAG)) = 'Agnt'; // AgentTag;

        *((PDWORD)(pBs + OFFSET_WIN_X86_TOKEN1)) = (DWORD)token1;
        *((PDWORD)(pBs + OFFSET_WIN_X86_TOKEN2)) = (DWORD)token2;
        *((PDWORD)(pBs + OFFSET_WIN_X86_TOKEN3)) = (DWORD)token3;

        *((PDWORD)(pBs + OFFSET_WIN_X86_JUMPBACK)) = 0;

        pAg->OffsetJumpBack = OFFSET_WIN_X86_JUMPBACK;
    }

    if (AGENT_TYPE_PROCESS == AgentType)
    {
        // Now allocate and insert the agent-name structure, so we can send agent process creation/termination events.
        pAgName = HpAllocWithTag(sizeof(*pAgName), IC_TAG_AGNN);
        if (NULL == pAgName)
        {
            status = INT_STATUS_INSUFFICIENT_RESOURCES;
            goto cleanup_and_exit;
        }

        strlcpy(pAgName->ImageName, Name, sizeof(pAgName->ImageName));

        pAgName->NameLen = strlen(pAgName->ImageName);

        strlower_utf8(pAgName->ImageName, pAgName->NameLen);

        pAgName->Tag = AgentTag;
        pAgName->Agid = pAg->Agid;

        // Not an typo... We only increment to 1 when the agent starts!
        pAgName->RefCount = 0;

        InsertTailList(&gAgentState.AgentNames, &pAgName->Link);
    }

    InsertTailList(&gAgentState.PendingAgents, &pAg->Link);

    gAgentState.PendingAgentsCount++;

    TRACE("[AGENT] Agent allocated and initialized!\n");

    // For now, we're done. The rest of the dirty work will be done by the execution handler.
    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        TRACE("[INFO] Can't inject agent: 0x%08x\n", status);

        if (NULL != pAg)
        {
            // Note: we don't free/unmap the agent here; if this function returns an error, the caller must unmap the
            // agent content.
            HpFreeAndNullWithTag(&pAg, IC_TAG_AGNE);
        }
    }

    if (INT_STATUS_SUCCESS == status)
    {
        // The agent has been created, but now we need to see if we can schedule it. If there aren't any other agents
        // active, then we will activate this one.
        status = IntWinAgentActivatePendingAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntWinAgentActivatePendingAgent failed: 0x%08x\n", status);
        }
    }

    return status;
}


INTSTATUS
IntWinAgentInjectBreakpoint(
    _In_ PFUNC_AgentInjection InjectionCallback,
    _In_opt_ void *Context,
    _Outptr_opt_ PWIN_AGENT *Agent
    )
///
/// @brief Injects a breakpoint agent inside the guest.
///
/// This function injects a breakpoint agent inside the guest. These breakpoint agents are used simply to
/// generate a breakpoint VM exit on the SYSCALL flow, since that flow is the safest to inject kernel
/// faults or to call kernel APIs.
///
/// @param[in]  InjectionCallback   Callback to be called when the breakpoint is hit.
/// @param[in]  Context             Optional context to be passed to the callback.
/// @param[out] Agent               Optional agent handle.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_OPERATION_NOT_IMPLEMENTED If the guest is not Windows.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
///
{
    PWIN_AGENT pAg;
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Agent);

    if (NULL == InjectionCallback)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (gGuest.OSType != introGuestWindows)
    {
        return INT_STATUS_OPERATION_NOT_IMPLEMENTED;
    }

    pAg = HpAllocWithTag(sizeof(*pAg), IC_TAG_AGNE);
    if (NULL == pAg)
    {
        status = INT_STATUS_INSUFFICIENT_RESOURCES;
        goto cleanup_and_exit;
    }

    pAg->AgentType = AGENT_TYPE_BREAKPOINT;
    pAg->HcallType = AGENT_HCALL_INT3;
    pAg->InjectionCallback = InjectionCallback;
    pAg->Context = Context;
    pAg->InsCloakRegion = NULL;
    pAg->BootCloakRegion = NULL;
    pAg->InstructionRestored = TRUE;
    pAg->ArgsLen = 0;
    pAg->Agid = gAgentState.Counter++;

    InsertTailList(&gAgentState.PendingAgents, &pAg->Link);

    gAgentState.PendingAgentsCount++;

    TRACE("[AGENT] Agent allocated and initialized!\n");

    // For now, we're done. The rest of the dirty work will be done by the execution handler.
    status = INT_STATUS_SUCCESS;

cleanup_and_exit:
    if (!INT_SUCCESS(status))
    {
        TRACE("[INFO] Can't inject agent: 0x%08x\n", status);

        if (NULL != pAg)
        {
            HpFreeAndNullWithTag(&pAg, IC_TAG_AGNE);
        }
    }

    if (INT_STATUS_SUCCESS == status)
    {
        // The agent has been created, but now we need to see if we can schedule it. If there aren't any other agents
        // active, then we will activate this one.
        status = IntWinAgentActivatePendingAgent();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentActivatePendingAgent failed: 0x%08x\n", status);
        }
    }

    return status;
}


INTSTATUS
IntWinAgentEnableInjection(
    void
    )
///
/// @brief enables agent injections.
///
/// @retval #INT_STATUS_SUCCESS On success.
///
{
    // Flag that agent injection is now safe.
    gAgentState.SafeToInjectProcess = TRUE;

    // Wake-up any pending agent.
    return IntWinAgentActivatePendingAgent();
}


void
IntWinAgentCheckIfProcessAgentAndIncrement(
    _In_ CHAR *ImageName,
    _Out_ BOOLEAN *IsAgent,
    _Out_ DWORD *Tag
    )
///
/// @brief Checks if a process is an agent or not, and increments the ref count of that name.
///
/// Each time a process is created, we check if its name matches the name of a previously injected agent. If
/// it does, we flag that process as an agent, and we increment the reference count of the name.
///
/// @param[in]  ImageName   The image name of the process which is checked.
/// @param[out] IsAgent     True if the process is agent, false otherwise.
/// @param[out] Tag         The agent tag, if the process is found to be an agent.
///
{
    LIST_ENTRY *list;

    if (NULL == ImageName)
    {
        return;
    }

    if (NULL == IsAgent)
    {
        return;
    }

    *IsAgent = FALSE;
    *Tag = 0;

    if (IsListEmpty(&gAgentState.AgentNames))
    {
        return;
    }

    list = gAgentState.AgentNames.Flink;
    while (list != &gAgentState.AgentNames)
    {
        PAGENT_NAME pAgName = CONTAINING_RECORD(list, AGENT_NAME, Link);
        list = list->Flink;

        if (0 == strcasecmp(ImageName, pAgName->ImageName))
        {
            pAgName->RefCount++;

            *IsAgent = TRUE;
            *Tag = pAgName->Tag;

            return;
        }
    }
}


void
IntWinAgentCheckIfProcessAgentAndDecrement(
    _In_ CHAR *ImageName,
    _Out_opt_ BOOLEAN *IsAgent,
    _Out_opt_ DWORD *Tag,
    _Out_opt_ BOOLEAN *Removed
    )
///
/// @brief Checks if a process is an agent or not, and decrements the ref count of that name.
///
/// Each time a process terminates, we check if it was an agent, and we decrement the reference count if its name.
/// Once the reference count of an agent name reaches 0, it will be removed.
///
/// @param[in]  ImageName   The image name of the process which is checked.
/// @param[out] IsAgent     True if the process is agent, false otherwise.
/// @param[out] Tag         The agent tag, if the process is found to be an agent.
/// @param[out] Removed     True if the agent was removed.
///
{
    LIST_ENTRY *list;

    if (IsAgent)
    {
        *IsAgent = FALSE;
    }

    if (Tag)
    {
        *Tag = 0;
    }

    if (Removed)
    {
        *Removed = FALSE;
    }

    if (IsListEmpty(&gAgentState.AgentNames))
    {
        return;
    }

    list = gAgentState.AgentNames.Flink;
    while (list != &gAgentState.AgentNames)
    {
        PAGENT_NAME pAgName = CONTAINING_RECORD(list, AGENT_NAME, Link);

        list = list->Flink;

        if (0 == strcasecmp(ImageName, pAgName->ImageName))
        {
            if (IsAgent)
            {
                *IsAgent = TRUE;
            }

            if (Tag)
            {
                *Tag = pAgName->Tag;
            }

            if (pAgName->RefCount > 0)
            {
                --pAgName->RefCount;
            }
            else
            {
                WARNING("[WARNING] Agent %s already done by our logic!\n", pAgName->ImageName);
            }

            if (pAgName->RefCount == 0)
            {
                RemoveEntryList(&pAgName->Link);

                HpFreeAndNullWithTag(&pAgName, IC_TAG_AGNN);

                if (Removed)
                {
                    *Removed = TRUE;
                }
            }

            return;
        }
    }
}


void
IntWinAgentRemoveEntryByAgid(
    _In_ DWORD Counter,
    _Out_opt_ DWORD *Tag
    )
///
/// @brief Removes an agent name from the list of names, using the ID.
///
/// @param[in]  Counter The counter/ID to be removed.
/// @param[out] Tag     Optional tag of the removed name.
///
{
    LIST_ENTRY *list;

    if (Tag)
    {
        *Tag = 0;
    }

    if (IsListEmpty(&gAgentState.AgentNames))
    {
        return;
    }

    list = gAgentState.AgentNames.Flink;
    while (list != &gAgentState.AgentNames)
    {
        PAGENT_NAME pAgName = CONTAINING_RECORD(list, AGENT_NAME, Link);

        list = list->Flink;

        if (Counter == pAgName->Agid)
        {
            if (Tag)
            {
                *Tag = pAgName->Tag;
            }

            RemoveEntryList(&pAgName->Link);

            HpFreeAndNullWithTag(&pAgName, IC_TAG_AGNN);

            return;
        }
    }
}


BOOLEAN
IntWinAgentIsPtrInTrampoline(
    _In_ QWORD Ptr,
    _In_ THS_PTR_TYPE Type
    )
///
/// @brief Check if the provided address points inside the agent trampoline.
///
/// @param[in]  Ptr     The pointer to be checked.
/// @param[in]  Type    The pointer type: live RIP or stack value.
///
/// @returns True if the address points inside the trampoline, false otherwise.
///
{
    if ((Ptr >= gAgentState.Trampoline) && (Ptr < gAgentState.Trampoline + gAgentState.TrampolineSize))
    {
        WARNING("[WARNING] Found %s 0x%016llx in agent trampoline 0x%016llx, 0x%x\n",
                Type == ptrLiveRip ? "live RIP" : "stack value",
                Ptr, gAgentState.Trampoline, gAgentState.TrampolineSize);
        return TRUE;
    }

    return FALSE;
}


AG_WAITSTATE
IntWinAgentGetState(
    _Out_opt_ DWORD *Tag
    )
///
/// @brief Gets the global agents state.
///
/// @param[out] Tag Optional agent tag, if an agent is active or pending.
///
/// @retval #agActive If there's an active agent.
/// @retval #agWaiting If there's a pending agent.
/// @retval #agNone If there are no active or pending agents.
///
{
    // Normally, we wait only for the current agent to finish. However, if #VE is on, we need
    // to wait & inject the #VE unloader first.

    if (gAgentState.ActiveAgent)
    {
        if (NULL != Tag)
        {
            PWIN_AGENT pAg = gAgentState.ActiveAgent;
            *Tag = pAg->AgentTag;
        }
        return agActive;
    }

    if (gAgentState.PendingAgentsCount)
    {
        if (NULL != Tag)
        {
            PWIN_AGENT pAg = CONTAINING_RECORD(gAgentState.PendingAgents.Flink, WIN_AGENT, Link);
            *Tag = pAg->AgentTag;
        }
        return agWaiting;
    }

    if (NULL != Tag)
    {
        *Tag = 0;
    }

    return agNone;
}


void
IntWinAgentDisablePendingAgents(
    void
    )
///
/// @brief Disables all pending agents.
///
/// This function should be called during the uninit phase, as it will disable all the pending agents. These
/// agents will never be injected inside the guest. The only exception is given by the VE or PT unloaders,
/// which must be injected on uninit in order to remove the VE or PT drivers from the guest memory.
///
{
    LIST_ENTRY *list;

    // Remove the pending agents.
    if (0 != gAgentState.PendingAgentsCount)
    {
        list = gAgentState.PendingAgents.Flink;

        while (list != &gAgentState.PendingAgents)
        {
            PWIN_AGENT pAg = CONTAINING_RECORD(list, WIN_AGENT, Link);

            list = list->Flink;

            // NOTE: The #VE unloader needs to be injected anyway, so don't remove that one.
            if ((pAg->AgentTag == IG_AGENT_TAG_VE_DRIVER && pAg->AgentType == AGENT_TYPE_VE_UNLOADER) ||
                (pAg->AgentTag == IG_AGENT_TAG_PT_DRIVER && pAg->AgentType == AGENT_TYPE_PT_UNLOADER))
            {
                continue;
            }

            RemoveEntryList(&pAg->Link);

            IntWinAgentFree(pAg, 0);

            gAgentState.PendingAgentsCount--;
        }
    }
}


void
IntWinAgentInit(
    void
    )
///
/// @brief Initialize the agents state.
///
{
    gAgentState.SafeToInjectProcess = FALSE;
    gAgentState.ActiveAgent = NULL;

    InitializeListHead(&gAgentState.PendingAgents);

    InitializeListHead(&gAgentState.AgentNames);

    gAgentState.Initialized = TRUE;
}


INTSTATUS
IntWinAgentUnInit(
    void
    )
///
/// @brief Uninit the agents state.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_INITIALIZED_HINT If the agents state has not been initialized yet.
///
{
    INTSTATUS status;
    LIST_ENTRY *list;

    if (!gAgentState.Initialized)
    {
        return INT_STATUS_NOT_INITIALIZED_HINT;
    }

    // Uninit the common part.
    list = gAgentState.AgentNames.Flink;
    while (list != &gAgentState.AgentNames)
    {
        PAGENT_NAME pAgName = CONTAINING_RECORD(list, AGENT_NAME, Link);

        list = list->Flink;

        RemoveEntryList(&pAgName->Link);

        HpFreeAndNullWithTag(&pAgName, IC_TAG_AGNN);
    }

    if (gAgentState.ActiveAgent != NULL)
    {
        status = IntWinAgentRemove(gAgentState.ActiveAgent);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntAgentRemove failed: 0x%08x\n", status);
        }

        gAgentState.ActiveAgent = NULL;
    }

    // The trampoline is initialized, remove it.
    if (0 != gAgentState.Trampoline)
    {
        if (NULL != gAgentState.TrampolineCloak)
        {
            status = IntMemClkUncloakRegion(gAgentState.TrampolineCloak, MEMCLOAK_OPT_APPLY_PATCH);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntMemClkUncloakRegion failed: 0x%08x\n", status);
            }

            gAgentState.TrampolineCloak = NULL;
        }
        else
        {
            ERROR("[ERROR] The trampoline is initialized, but no cloak region was found!\n");
            IntDbgEnterDebugger();
        }
    }

    gAgentState.Initialized = FALSE;

    memzero(&gAgentState, sizeof(gAgentState));

    return INT_STATUS_SUCCESS;
}
