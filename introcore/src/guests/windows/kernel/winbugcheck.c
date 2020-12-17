/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "winbugcheck.h"
#include "alerts.h"
#include "decoder.h"
#include "guests.h"
#include "memcloak.h"
#include "winprocesshp.h"

static char const *
IntGetBugCheckName(
    _In_ QWORD Reason
    )
///
/// @brief      Returns a name for a bug check code.
///
/// @param[in]  Reason  The bug check reason, as obtained from the guest. This is one of the reasons documented
///                     by Microsoft:
///                     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
///
/// @returns    The name of the bug check.
///
{
/// Jump over the "BUGCHECK_" part of the define
#define BUGCHECK_NAME(x)    case(x): return &(#x[9])

    switch (Reason)
    {
        BUGCHECK_NAME(BUGCHECK_IRQL_NOT_LESS_OR_EQUAL);
        BUGCHECK_NAME(BUGCHECK_BAD_POOL_HEADER);
        BUGCHECK_NAME(BUGCHECK_MEMORY_MANAGEMENT);
        BUGCHECK_NAME(BUGCHECK_KMODE_EXCEPTION_NOT_HANDLED);
        BUGCHECK_NAME(BUGCHECK_SYSTEM_SERVICE_EXCEPTION);
        BUGCHECK_NAME(BUGCHECK_PFN_LIST_CORRUPT);
        BUGCHECK_NAME(BUGCHECK_PAGE_FAULT_IN_NONPAGED_AREA);
        BUGCHECK_NAME(BUGCHECK_PROCESS_INITIALIZATION_FAILED);
        BUGCHECK_NAME(BUGCHECK_KERNEL_STACK_INPAGE_ERROR);
        BUGCHECK_NAME(BUGCHECK_KERNEL_DATA_INPAGE_ERROR);
        BUGCHECK_NAME(BUGCHECK_INACCESSIBLE_BOOT_DEVICE);
        BUGCHECK_NAME(BUGCHECK_SYSTEM_THREAD_EXCEPTION_NOT_HANDLED);
        BUGCHECK_NAME(BUGCHECK_UNEXPECTED_KERNEL_MODE_TRAP);
        BUGCHECK_NAME(BUGCHECK_KERNEL_MODE_EXCEPTION_NOT_HANDLED);
        BUGCHECK_NAME(BUGCHECK_CRITICAL_PROCESS_DIED);
        BUGCHECK_NAME(BUGCHEDCK_CRITICAL_STRUCTURE_CORRUPTION);
    default:
        return "Unknown";
    }

#undef BUGCHECK_NAME
}

static char const *
IntGetBugCheckLink(
    _In_ QWORD Reason
    )
///
/// @brief      Returns the bug check documentation page link for a bug check reason.
///
/// @param[in]  Reason  The bug check reason, as obtained from the guest. This is one of the reasons documented
///                     by Microsoft:
///                     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
///
/// @returns    The link to the online documentation.
///
{
    switch (Reason)
    {
    case BUGCHECK_IRQL_NOT_LESS_OR_EQUAL:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0xa--irql-not-less-or-equal";
    case BUGCHECK_BAD_POOL_HEADER:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x19--bad-pool-header";
    case BUGCHECK_MEMORY_MANAGEMENT:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1a--memory-management";
    case BUGCHECK_KMODE_EXCEPTION_NOT_HANDLED:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x1e--kmode-exception-not-handled";
    case BUGCHECK_SYSTEM_SERVICE_EXCEPTION:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x3b--system-service-exception";
    case BUGCHECK_PFN_LIST_CORRUPT:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x4e--pfn-list-corrupt";
    case BUGCHECK_PAGE_FAULT_IN_NONPAGED_AREA:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x50--page-fault-in-nonpaged-area";
    case BUGCHECK_PROCESS_INITIALIZATION_FAILED:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x60--process-initialization-failed";
    case BUGCHECK_KERNEL_STACK_INPAGE_ERROR:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x77--kernel-stack-inpage-error";
    case BUGCHECK_KERNEL_DATA_INPAGE_ERROR:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7a--kernel-data-inpage-error";
    case BUGCHECK_INACCESSIBLE_BOOT_DEVICE:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7b--inaccessible-boot-device";
    case BUGCHECK_SYSTEM_THREAD_EXCEPTION_NOT_HANDLED:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7e--system-thread-exception-not-handled";
    case BUGCHECK_UNEXPECTED_KERNEL_MODE_TRAP:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x7f--unexpected-kernel-mode-trap";
    case BUGCHECK_KERNEL_MODE_EXCEPTION_NOT_HANDLED:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x8e--kernel-mode-exception-not-handled";
    case BUGCHECK_CRITICAL_PROCESS_DIED:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0xef--critical-process-died";
    case BUGCHEDCK_CRITICAL_STRUCTURE_CORRUPTION:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption";
    default:
        return "https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2";
    }
}


__forceinline static void
IntLogBSODParams(
    _In_ QWORD Reason,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4
    )
///
/// @brief      Logs the bug check parameters.
///
/// @param[in]  Reason  The bug check reason, as obtained from the guest. This is one of the reasons documented
///                     by Microsoft:
///                     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
/// @param[in]  Param1  First parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param2  Second parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param3  Third parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param4  Fourth parameter, as obtained from the guest. It has different meanings based on the Reason.
///
{
    CHAR const *name = IntGetBugCheckName(Reason);
    CHAR const *link = IntGetBugCheckLink(Reason);

    NLOG("Bugcheck 0x%llx - %s\n"
         "Parameter 1: 0x%016llx\n"
         "Parameter 2: 0x%016llx\n"
         "Parameter 3: 0x%016llx\n"
         "Parameter 4: 0x%016llx\n"
         "See the online documentation at %s for details\n",
         Reason, name, Param1, Param2, Param3, Param4, link);
}


static void
IntLogCurrentIP(
    _In_ QWORD Rip,
    _In_opt_ CHAR const *Message
    )
///
/// @brief      Logs information about the RIP at which the crash was triggered.
///
/// This will log the instruction at RIP, and, if possible, the name of the module in which RIP resided and the
/// offset relative to the module base at which the crash was triggered.
///
/// @param[in]  Rip     The RIP to be logged.
/// @param[in]  Message Optional message to be displayed.
///
{
    INTSTATUS status;
    INSTRUX instrux;
    KERNEL_DRIVER const *pDriver;

    status = IntDecDecodeInstruction(gGuest.Guest64 ? IG_CS_TYPE_64B : IG_CS_TYPE_32B, Rip, &instrux);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntDecDecodeInstruction failed for instruction at 0x%016llx: 0x%08x\n", Rip, status);
        return;
    }

    pDriver = IntDriverFindByAddress(Rip);
    if (NULL == pDriver)
    {
        ERROR("[ERROR] IntDriverFindByAddress failed: 0x%016llx", Rip);
        return;
    }

    if (Message)
    {
        NLOG("\n%s:\n", Message);
    }

    NLOG("%s+0x%llx\n0x%016llx\n", utf16_for_log(pDriver->Name), Rip - pDriver->BaseVa, Rip);

    IntDumpInstruction(&instrux, Rip);
}


static void
IntLogGuestRegisters(
    void
    )
///
/// @brief      Logs the guest register state
///
/// This will dump the general purpose registers, control register, eflags, debug registers, segment registers, ant
/// the base and limit of the IDT and GDT for all the guests CPUs.
///
{
    IG_ARCH_REGS const *pRegs = &gVcpu->Regs;
    IG_SEG_REGS segs = {0};

    NLOG("\nGuest registers on the CPU that caused the bugcheck (%d):\n", gVcpu->Index);

    IntDumpArchRegs(pRegs);

    LOG("CR0 = 0x%016llx CR2 = 0x%016llx CR3 = 0x%016llx CR4 = 0x%016llx CR8 = 0x%016llx\n",
        pRegs->Cr0, pRegs->Cr2, pRegs->Cr3, pRegs->Cr4, pRegs->Cr8);
    LOG("FLG = 0x%016llx DR7 = 0x%016llx\n", pRegs->Flags, pRegs->Dr7);

    LOG("IDT Base = 0x%016llx Limit = 0x%016llx\n", pRegs->IdtBase, pRegs->IdtLimit);
    LOG("GDT Base = 0x%016llx Limit = 0x%016llx\n", pRegs->GdtBase, pRegs->GdtLimit);

    IntGetSegs(gVcpu->Index, &segs);
    LOG("CS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.CsSelector, segs.CsBase, segs.CsLimit, segs.CsAr);
    LOG("SS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.SsSelector, segs.SsBase, segs.SsLimit, segs.SsAr);
    LOG("DS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.DsSelector, segs.DsBase, segs.DsLimit, segs.DsAr);
    LOG("ES = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.EsSelector, segs.EsBase, segs.EsLimit, segs.EsAr);
    LOG("FS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.FsSelector, segs.FsBase, segs.FsLimit, segs.FsAr);
    LOG("GS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
        segs.GsSelector, segs.GsBase, segs.GsLimit, segs.GsAr);

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        VCPU_STATE const *v = &gGuest.VcpuArray[i];
        IG_ARCH_REGS regs = {0};

        if (v->Index == gVcpu->Index)
        {
            continue;
        }

        IntGetGprs(v->Index, &regs);
        pRegs = &regs;

        NLOG("\nGuest registers on the CPU %d:\n", v->Index);

        IntDumpArchRegs(pRegs);

        LOG("CR0 = 0x%016llx CR2 = 0x%016llx CR3 = 0x%016llx CR4 = 0x%016llx CR8 = 0x%016llx\n",
            pRegs->Cr0, pRegs->Cr2, pRegs->Cr3, pRegs->Cr4, pRegs->Cr8);
        LOG("FLG = 0x%016llx DR7 = 0x%016llx\n", pRegs->Flags, pRegs->Dr7);

        LOG("IDT Base = 0x%016llx Limit = 0x%016llx\n", pRegs->IdtBase, pRegs->IdtLimit);
        LOG("GDT Base = 0x%016llx Limit = 0x%016llx\n", pRegs->GdtBase, pRegs->GdtLimit);

        IntGetSegs(v->Index, &segs);
        LOG("CS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.CsSelector, segs.CsBase, segs.CsLimit, segs.CsAr);
        LOG("SS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.SsSelector, segs.SsBase, segs.SsLimit, segs.SsAr);
        LOG("DS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.DsSelector, segs.DsBase, segs.DsLimit, segs.DsAr);
        LOG("ES = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.EsSelector, segs.EsBase, segs.EsLimit, segs.EsAr);
        LOG("FS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.FsSelector, segs.FsBase, segs.FsLimit, segs.FsAr);
        LOG("GS = 0x%02llx Base = 0x%016llx Limit = 0x%016llx Ar = 0x%08llx\n",
            segs.GsSelector, segs.GsBase, segs.GsLimit, segs.GsAr);
    }
}


static void
IntLogProcessInfo(
    void
    )
///
/// @brief      Logs information about the current process
///
{
    IG_ARCH_REGS const *regs = &gVcpu->Regs;
    WIN_PROCESS_OBJECT const *process = IntWinProcFindObjectByCr3(regs->Cr3);

    if (NULL != process)
    {
        NLOG("\nPROCESS INFORMATION\n"
             "Process name:  %s\n"
             "Process path:  %s\n"
             "Eprocess:      0x%016llx\n"
             "Parent:        0x%016llx\n"
             "Real parent:   0x%016llx\n"
             "Creation time: 0x%016llx\n"
             "Cr3/User Cr3:  0x%016llx/0x%016llx\n"
             "Pid:           %d\n"
             "Token:         0x%016llx\n",
             process->Name,
             process->Path ? utf16_for_log(process->Path->Path) : "<invalid>",
             process->EprocessAddress,
             process->ParentEprocess,
             process->RealParentEprocess,
             process->CreationTime,
             process->Cr3, process->UserCr3,
             process->Pid,
             process->OriginalTokenPtr);

        if (gGuest.Guest64)
        {
            NLOG("PEB32 address: 0x%016llx\nPEB64 address: 0x%016llx\n", process->Peb32Address, process->Peb64Address);
        }
        else
        {
            NLOG("PEB32 address: 0x%016llx\n", process->Peb32Address);
        }

        NLOG("Flags: 0x%08x Exit Status: 0x%08x\n", process->Flags, process->ExitStatus);
    }
}


static void
IntWinLogVAInfo(
    _In_ QWORD Va
    )
///
/// @brief      Logs information about a guest virtual address translation
///
/// @param[in]  Va      Guest virtual address to log
///
{
    INTSTATUS status;
    VA_TRANSLATION vaTrans = {0};
    IG_ARCH_REGS const *registers = &gVcpu->Regs;

    status = IntTranslateVirtualAddressEx(Va, registers->Cr3, TRFLG_NONE, &vaTrans);
    if (!INT_SUCCESS(status))
    {
        return;
    }

    NLOG("\nVA TRANSLATION\n");
    NLOG("Virtual Address: 0x%016llx\nPhysical Address: 0x%016llx\nEntries mappings:\n",
         vaTrans.VirtualAddress, vaTrans.PhysicalAddress);

    for (DWORD index = 0; index < vaTrans.MappingsCount; index++)
    {
        NLOG("  EntryMapping[%d]: 0x%016llx\n", index, vaTrans.MappingsEntries[index]);
    }
}


static void
IntWinDumpEflags(
    _In_ DWORD Eflags
    )
///
/// @brief      Logs the EFLAGS contents
///
/// @param[in]  Eflags      Raw guest EFLAGS value
///
{
    EFLAGS efl;

    efl.Raw = Eflags;
    NLOG("%s %s %s %s %s %s %s %s %s\n",
         (efl.IOPL ? "iopl=1   " : "iopl=0    "),
         (efl.OF ? "ov" : "nv"),
         (efl.DF ? "dn" : "up"),
         (efl.IF ? "ei" : "di"),
         (efl.SF ? "ng" : "pl"),
         (efl.ZF ? "zr" : "nr"),
         (efl.AF ? "ac" : "na"),
         (efl.PF ? "pe" : "po"),
         (efl.CF ? "cy" : "nc"));
}


static void
IntLogStackTrace(
    _In_ QWORD Address,
    _In_opt_ CHAR const *Message
    )
///
/// @brief      Attempts to log a guest stack trace
///
/// @param[in]  Address     Guest virtual address from which to obtain a trace. If 0, will use the value of the
///                         guest RSP on the current CPU
/// @param[in]  Message     Optional NULL-terminated string with a message to be displayed.
///
{
#define MODULE_NAMES_TO_PRINT 64
#define TRACE_LIMIT_X64       0x2000
#define TRACE_LIMIT_X86       0x2000
    INTSTATUS status;
    PIG_ARCH_REGS pRegs;
    QWORD rsp;
    QWORD rspValue = 0;
    QWORD limit;
    QWORD writtenModules = 0;

    if (Message)
    {
        NLOG("\n%s\n", Message);
    }

    pRegs = &gVcpu->Regs;

    if (Address)
    {
        rsp = Address;
    }
    else
    {
        rsp = pRegs->Rsp;
    }

    limit = gGuest.Guest64 ? TRACE_LIMIT_X64 : TRACE_LIMIT_X86;

    for (size_t i = 1; i < limit; i++)
    {
        if (gGuest.Guest64)
        {
            status = IntKernVirtMemFetchQword(rsp + 8 * i, &rspValue);
        }
        else
        {
            status = IntKernVirtMemFetchDword(rsp + 4 * i, (DWORD *)&rspValue);
        }

        if (!INT_SUCCESS(status))
        {
            break;
        }

        KERNEL_DRIVER *pDriver = IntDriverFindByAddress(rspValue);
        if (pDriver)
        {
            if (gGuest.Guest64)
            {
                NLOG("0x%016llx %s+0x%llx\n", rsp + 8ull * i, utf16_for_log(pDriver->Name), rspValue - pDriver->BaseVa);
            }
            else
            {
                NLOG("%08llx %s+0x%llx\n", rsp + 4ull * i, utf16_for_log(pDriver->Name), rspValue - pDriver->BaseVa);
            }

            writtenModules++;
        }

        if (writtenModules > MODULE_NAMES_TO_PRINT)
        {
            break;
        }
    }
#undef MODULE_NAMES_TO_PRINT
#undef TRACE_LIMIT_X64
#undef TRACE_LIMIT_X86
}


static void
IntLogTrapFrame(
    _In_ QWORD TrapFrame
    )
///
/// @brief      Logs information about a trap frame
///
/// @param[in]  TrapFrame   Guest virtual address from which the trap frame will be read
///
{
    if (gGuest.Guest64)
    {
        INTSTATUS status;
        KTRAP_FRAME64 trapStructure = {0};

        NLOG("\nTrap Frame at 0x%016llx:\n", TrapFrame);
        status = IntKernVirtMemRead(TrapFrame, sizeof(trapStructure), &trapStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", TrapFrame, status);
            return;
        }

        NLOG("rax = %016llx  rbx = %016llx  rcx = %016llx\n"
             "rdx = %016llx  rsi = %016llx  rdi = %016llx\n"
             "rip = %016llx  rsp = %016llx  rbp = %016llx\n"
             " r8 = %016llx   r9 = %016llx  r10 = %016llx\n"
             "r11 = %016llx  r12 = %016llx  r13 = %016llx\n"
             "r14 = %016llx  r15 = %016llx\n"
             "eflags = %08x\n",
             trapStructure.Rax, trapStructure.Rbx, trapStructure.Rcx,
             trapStructure.Rdx, trapStructure.Rsi, trapStructure.Rdi,
             trapStructure.Rip, trapStructure.Rsp, trapStructure.Rbp,
             trapStructure.R8, trapStructure.R9, trapStructure.R10,
             trapStructure.R11, 0ull, 0ull, 0ull, 0ull,
             trapStructure.EFlags);

        IntWinDumpEflags(trapStructure.EFlags);
        IntLogCurrentIP(trapStructure.Rip, NULL);
        IntLogStackTrace(trapStructure.Rsp, "Stack trace:");
        IntLogStackTrace(0, NULL);
    }
    else
    {
        INTSTATUS status;
        KTSS ktssStructure = {0};

        NLOG("\nKTSS at %08llx:\n", TrapFrame);

        status = IntKernVirtMemRead(TrapFrame, sizeof(ktssStructure), &ktssStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", TrapFrame, status);
            return;
        }

        NLOG("eax = 0x%08x  ebx = 0x%08x  ecx = 0x%08x\n"
             "edx = 0x%08x  esi = 0x%08x  edi = 0x%08x\n"
             "eip = 0x%08x  esp = 0x%08x  ebp = 0x%08x\n"
             "cs = %04x ss = %04x ds = %04x es = %04x fs = %04x gs = %04x      efl=0x%08x\n",
             ktssStructure.Eax, ktssStructure.Ebx, ktssStructure.Ecx, ktssStructure.Edx, ktssStructure.Esi,
             ktssStructure.Edi, ktssStructure.Eip, ktssStructure.Esp, ktssStructure.Ebp, ktssStructure.Cs,
             ktssStructure.Ss, ktssStructure.Ds, ktssStructure.Es, ktssStructure.Fs, ktssStructure.Gs,
             ktssStructure.EFlags);

        IntWinDumpEflags(ktssStructure.EFlags);
        IntLogCurrentIP(ktssStructure.Eip, NULL);
        IntLogStackTrace(ktssStructure.Esp, "Stack trace:");
        IntLogStackTrace(0, NULL);
    }
}


static void
IntLogContextRecord(
    _In_ QWORD ContextRecord
    )
///
/// @brief      Logs information about a context record
///
/// @param[in]  ContextRecord   Guest virtual address from which the context record will be read
///
{
    if (gGuest.Guest64)
    {
        INTSTATUS status;
        CONTEXT64 contextStructure = {0};

        NLOG("\nContext Record at 0x%016llx:\n", ContextRecord);

        status = IntKernVirtMemRead(ContextRecord, sizeof(contextStructure), &contextStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", ContextRecord, status);
            return;
        }

        NLOG("rax = 0x%016llx  rbx = 0x%016llx  rcx = 0x%016llx\n"
             "rdx = 0x%016llx  rsi = 0x%016llx  rdi = 0x%016llx\n"
             "rip = 0x%016llx  rsp = 0x%016llx  rbp = 0x%016llx\n"
             " r8 = 0x%016llx   r9 = 0x%016llx  r10 = 0x%016llx\n"
             "r11 = 0x%016llx  r12 = 0x%016llx  r13 = 0x%016llx\n"
             "r14 = 0x%016llx  r15 = 0x%016llx\n"
             "cs = 0x%04x ss = 0x%04x ds = 0x%04x es = 0x%04x fs = 0x%04x gs = 0x%04x      efl = 0x%08x\n",
             contextStructure.Rax, contextStructure.Rbx, contextStructure.Rcx,
             contextStructure.Rdx, contextStructure.Rsi, contextStructure.Rdi,
             contextStructure.Rip, contextStructure.Rsp, contextStructure.Rbp,
             contextStructure.R8, contextStructure.R9, contextStructure.R10,
             contextStructure.R11, contextStructure.R12, contextStructure.R13,
             contextStructure.R14, contextStructure.R15, contextStructure.SegCs,
             contextStructure.SegSs, contextStructure.SegDs, contextStructure.SegEs,
             contextStructure.SegFs, contextStructure.SegGs, contextStructure.EFlags);

        IntWinDumpEflags(contextStructure.EFlags);
        IntLogCurrentIP(contextStructure.Rip, NULL);
    }
    else
    {
        INTSTATUS status;
        CONTEXT32 contextStructure = {0};

        NLOG("\nContext Record at %08llx:\n", ContextRecord);

        status = IntKernVirtMemRead(ContextRecord, sizeof(contextStructure), &contextStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", ContextRecord, status);
            return;
        }

        NLOG("eax = 0x%08x  ebx = 0x%08x  ecx = 0x%08x edx = 0x%08x  esi = 0x%08x  edi = 0x%08x\n"
             "eip = 0x%08x  esp = 0x%08x  ebp = 0x%08x\n"
             "cs = 0x%04x ss = 0x%04x ds = 0x%04x es = 0x%04x fs = 0x%04x gs = 0x%04x      efl = %08x\n",
             contextStructure.Eax, contextStructure.Ebx, contextStructure.Ecx,
             contextStructure.Edx, contextStructure.Esi, contextStructure.Edi,
             contextStructure.Eip, contextStructure.Esp, contextStructure.Ebp,
             contextStructure.SegCs, contextStructure.SegSs, contextStructure.SegDs,
             contextStructure.SegEs, contextStructure.SegFs,
             contextStructure.SegGs, contextStructure.EFlags);

        IntWinDumpEflags(contextStructure.EFlags);
        IntLogCurrentIP(contextStructure.Eip, NULL);
    }
}


static void
IntLogExceptionRecord(
    _In_ QWORD ExceptionRecord
    )
///
/// @brief      Logs information about an exception record
///
/// @param[in]  ExceptionRecord     Guest virtual address from which the except exception will be read
///
{
    if (gGuest.Guest64)
    {
        INTSTATUS status;
        EXCEPTION_RECORD64 excpStructure = {0};

        NLOG("\nException Record at 0x%016llx:\n", ExceptionRecord);

        status = IntKernVirtMemRead(ExceptionRecord, sizeof(excpStructure), &excpStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", ExceptionRecord, status);
            return;
        }

        NLOG("Exception address: 0x%016llx\n"
             "Exception Code: 0x%08x\n"
             "ExceptionFlags: 0x%08x\n"
             "NumberParameters: 0x%x\n",
             excpStructure.ExceptionAddress, excpStructure.ExceptionCode,
             excpStructure.ExceptionFlags, excpStructure.NumberParameters);

        excpStructure.NumberParameters = MIN(excpStructure.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);

        for (DWORD excpParam = 0; excpParam < excpStructure.NumberParameters; excpParam++)
        {
            NLOG("   Parameter[%d]: 0x%016llx\n", excpParam, excpStructure.ExceptionInformation[excpParam]);
        }
    }
    else
    {
        INTSTATUS status;
        EXCEPTION_RECORD32 excpStructure = {0};

        NLOG("\nException Record at %08llx:\n", ExceptionRecord);

        status = IntKernVirtMemRead(ExceptionRecord, sizeof(excpStructure), &excpStructure, NULL);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemRead failed at 0x%016llx: 0x%08x\n", ExceptionRecord, status);
            return;
        }

        NLOG("Exception address: %08x\n"
             "Exception Code: 0x%08x\n"
             "ExceptionFlags: 0x%08x\n"
             "NumberParameters: 0x%x\n",
             excpStructure.ExceptionAddress, excpStructure.ExceptionCode,
             excpStructure.ExceptionFlags, excpStructure.NumberParameters);

        excpStructure.NumberParameters = MIN(excpStructure.NumberParameters, EXCEPTION_MAXIMUM_PARAMETERS);

        for (DWORD excpParam = 0; excpParam < excpStructure.NumberParameters; excpParam++)
        {
            NLOG("   Parameter[%d]: 0x%08x\n", excpParam, excpStructure.ExceptionInformation[excpParam]);
        }
    }
}


static void
IntLogCriticalProcessHasDied(
    _In_ QWORD Param1,
    _In_ QWORD Param2
    )
///
/// @brief  Handles a #BUGCHECK_CRITICAL_PROCESS_DIED bug check.
///
/// @param[in]  Param1  First parameter, as obtained from the guest. This is the process object.
/// @param[in]  Param2  Second parameter, as obtained from the guest. If 0, a process died; if 1, a thread died.
///
{
    const WIN_PROCESS_OBJECT *proc = IntWinProcFindObjectByEprocess(Param1);
    const CHAR *objectType = "<unknown>";

    if (Param2 == 0)
    {
        objectType = "process";
    }
    else if (Param2 == 1)
    {
        objectType = "thread";
    }

    LOG("A %s object has died!\n", objectType);
    if (proc != NULL)
    {
        NLOG("\tProcess name: \"%s\" PID: %u Eprocess: 0x%016llx Cr3: 0x%016llx User Cr3: 0x%016llx Protected: %u\n",
             proc->Name, proc->Pid, proc->EprocessAddress, proc->Cr3, proc->UserCr3, proc->Protected);
    }
    else
    {
        NLOG("\tNo process found for Eprocess 0x%016llx\n", Param1);
    }
}


static void
IntLogCriticalStructureCoruption(
    _In_ QWORD Param3,
    _In_ QWORD Param4
    )
///
/// @brief      Handles a #BUGCHEDCK_CRITICAL_STRUCTURE_CORRUPTION bug check.
///
/// This is usually generated by patch guard. The different types of corrupted regions are documented here:
/// https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption
///
/// @param[in]  Param3  Third parameter, as obtained from the guest. It has different meanings based on the Reason
/// @param[in]  Param4  Fourth parameter, as obtained from the guest. It has different meanings based on the Reason.
///                     This is the type of the region that was corrupted.
///
{
    QWORD regionType = Param4;
    const PCHAR regions[] =
    {
        /* 0  */ "A generic data region",
        /* 1  */ "Modification of a function or .pdata",
        /* 2  */ "A processor IDT",
        /* 3  */ "A processor GDT",
        /* 4  */ "Type 1 process list corruption",
        /* 5  */ "Type 2 process list corruption",
        /* 6  */ "Debug routine modification",
        /* 7  */ "Critical MSR modification",
        /* 8  */ "Object type",
        /* 9  */ "A processor IVT",
        /* a  */ "Modification of a system service function",
        /* b  */ "A generic session data region",
        /* c  */ "Modification of a session function or .pdata",
        /* d  */ "Modification of an import table",
        /* e  */ "Modification of a session import table",
        /* f  */ "Ps Win32 callout modification",
        /* 10 */ "Debug switch routine modification",
        /* 11 */ "IRP allocator modification",
        /* 12 */ "Driver call dispatcher modification",
        /* 13 */ "IRP completion dispatcher modification",
        /* 14 */ "IRP deallocator modification",
        /* 15 */ "A processor control register",
        /* 16 */ "Critical floating point control register modification",
        /* 17 */ "Local APIC modification",
        /* 18 */ "Kernel notification callout modification",
        /* 19 */ "Loaded module list modification",
        /* 1a */ "Type 3 process list corruption",
        /* 1b */ "Type 4 process list corruption",
        /* 1c */ "Driver object corruption",
        /* 1d */ "Executive callback object modification",
        /* 1e */ "Modification of module padding",
        /* 1f */ "Modification of a protected process",
        /* 20 */ "A generic data region",
        /* 21 */ "A page hash mismatch",
        /* 22 */ "A session page hash mismatch",
        /* 23 */ "Load config directory modification",
        /* 24 */ "Inverted function table modification",
        /* 25 */ "Session configuration modification",
        /* 26 */ "An extended processor control register",
        /* 27 */ "Type 1 pool corruption",
        /* 28 */ "Type 2 pool corruption",
        /* 29 */ "Type 3 pool corruption",
        /* 2a */ "Type 4 pool corruption",
        /* 2b */ "Modification of a function or .pdata",
        /* 2c */ "Image integrity corruption",
        /* 2d */ "Processor misconfiguration",
        /* 2e */ "Type 5 process list corruption",
        /* 2f */ "Process shadow corruption",
    };

    if (regionType < ARRAYSIZE(regions))
    {
        LOG("0x%04llx - %s\n", regionType, regions[regionType]);
    }
    else if (0x101 == regionType)
    {
        LOG("0x%04llx - %s\n", regionType, "General pool corruption");
    }
    else if (0x102 == regionType)
    {
        LOG("0x%04llx - %s\n", regionType, "Modification of win32k.sys");
    }
    else
    {
        LOG("0x%04llx - %s\n", regionType, "Undocumented");
    }

    LOG("Dumping cloak regions\n");
    IntMemClkDump();

    if (0x2b == regionType && IS_KERNEL_POINTER_WIN(gGuest.Guest64, Param3))
    {
        IntDumpGvaEx(gGuest.Mm.SystemCr3, Param3 & PAGE_MASK, PAGE_SIZE, 16, 1, TRUE, TRUE);
    }
}


static void
IntWinBcLogBsodEvent(
    _In_ QWORD Reason,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4
    )
///
/// @brief      Logs a bug check event and related information about the crash and the kernel.
///
/// @param[in]  Reason  The bug check reason, as obtained from the guest. This is one of the reasons documented
///                     by Microsoft:
///                     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
/// @param[in]  Param1  First parameter, as obtained from the guest. It has different meanings based on the Reason
/// @param[in]  Param2  Second parameter, as obtained from the guest. It has different meanings based on the Reason
/// @param[in]  Param3  Third parameter, as obtained from the guest. It has different meanings based on the Reason
/// @param[in]  Param4  Fourth parameter, as obtained from the guest. It has different meanings based on the Reason.
///                     This is the type of the region that was corrupted.
///
{
    KERNEL_DRIVER const *pKernel = gGuest.KernelDriver;

    NLOG("\n**********************************************************************\n"
         "*                                                                    *\n"
         "*                          Bugcheck Analysis                         *\n"
         "*                                                                    *\n"
         "**********************************************************************\n\n");

    IntLogBSODParams(Reason, Param1, Param2, Param3, Param4);

    switch (Reason)
    {
    case BUGCHECK_IRQL_NOT_LESS_OR_EQUAL:
        IntLogCurrentIP(Param4, "Faulting IP");
        IntWinLogVAInfo(Param1);
        break;

    case BUGCHECK_SYSTEM_SERVICE_EXCEPTION:
        IntLogCurrentIP(Param2, "Faulting IP");
        IntLogContextRecord(Param3);
        break;

    case BUGCHECK_SYSTEM_THREAD_EXCEPTION_NOT_HANDLED:
        IntLogExceptionRecord(Param3);
        IntLogContextRecord(Param4);
        break;

    case BUGCHECK_UNEXPECTED_KERNEL_MODE_TRAP:
    case BUGCHECK_KERNEL_MODE_EXCEPTION_NOT_HANDLED:
        IntLogTrapFrame(Param2);
        break;

    case BUGCHECK_CRITICAL_PROCESS_DIED:
        IntLogCriticalProcessHasDied(Param1, Param2);
        break;

    case BUGCHEDCK_CRITICAL_STRUCTURE_CORRUPTION:
        IntLogCriticalStructureCoruption(Param3, Param4);
        break;

    default: // More can be added if it is needed
        NLOG("Bug Check reason not known!\n");
        break;
    }

    if (NULL != pKernel)
    {
        LOG("Kernel loaded at 0x%016llx Version info: 0x%08x:0x%08llx\n",
            pKernel->BaseVa, pKernel->Win.TimeDateStamp, pKernel->Size);
    }

    IntLogGuestRegisters();

    IntLogProcessInfo();

    IntLogStackTrace(0, "Stack Trace:");
}


static INTSTATUS
IntWinBcSendBsodEvent(
    _In_ QWORD Reason,
    _In_ QWORD Param1,
    _In_ QWORD Param2,
    _In_ QWORD Param3,
    _In_ QWORD Param4
    )
///
/// @brief      Sends a #introEventCrashEvent event.
///
/// If the #INTRO_OPT_EVENT_OS_CRASH option is not enabled, this function does nothing.
///
/// @param[in]  Reason  The bug check reason, as obtained from the guest. This is one of the reasons documented
///                     by Microsoft:
///                     https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2
/// @param[in]  Param1  First parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param2  Second parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param3  Third parameter, as obtained from the guest. It has different meanings based on the Reason.
/// @param[in]  Param4  Fourth parameter, as obtained from the guest. It has different meanings based on the Reason.
///                     This is the type of the region that was corrupted.
{
    INTSTATUS status;
    EVENT_CRASH_EVENT *pCrashEvent;

    if (0 == (gGuest.CoreOptions.Current & INTRO_OPT_EVENT_OS_CRASH))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    pCrashEvent = &gAlert.Crash;
    memzero(pCrashEvent, sizeof(*pCrashEvent));

    pCrashEvent->Reason = Reason;
    pCrashEvent->Param1 = Param1;
    pCrashEvent->Param2 = Param2;
    pCrashEvent->Param3 = Param3;
    pCrashEvent->Param4 = Param4;

    IntAlertFillWinProcessCurrent(&pCrashEvent->CurrentProcess);

    status = IntNotifyIntroEvent(introEventCrashEvent, pCrashEvent, sizeof(*pCrashEvent));
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntNotifyIntroEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntWinBcHandleBugCheck(
    _In_ void const *Detour
    )
///
/// @brief      Handles a Windows OS crash.
/// @ingroup    group_detours
///
/// This is the detour handle for the KeBugCheck2 32-bit Windows kernel API and the KeBugCheckEx 64-bit Windows
/// kernel API.
/// This will log as much information as possible and will notify the integrator about the event.
///
/// @param[in]  Detour      The detour handle for this hook.
///
/// @retval     INT_STATUS_SUCCESS in case of success.
/// @retval     #INT_STATUS_INVALID_PARAMETER_1 if Detour is NULL.
///

{
    INTSTATUS status;
    PIG_ARCH_REGS pRegs;
    QWORD code, param1, param2, param3, param4;

    if (NULL == Detour)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    pRegs = &gVcpu->Regs;

    if (gGuest.Guest64)
    {
        code = pRegs->Rcx;
        param1 = pRegs->Rdx;
        param2 = pRegs->R8;
        param3 = pRegs->R9;

        IntKernVirtMemFetchQword(pRegs->Rsp + 8 * 5, &param4);
    }
    else
    {
        // We have RET, Arg1, ... on the stack.
        IntKernVirtMemFetchDword(pRegs->Rsp + 4 * 1, (DWORD *)&code);
        IntKernVirtMemFetchDword(pRegs->Rsp + 4 * 2, (DWORD *)&param1);
        IntKernVirtMemFetchDword(pRegs->Rsp + 4 * 3, (DWORD *)&param2);
        IntKernVirtMemFetchDword(pRegs->Rsp + 4 * 4, (DWORD *)&param3);
        IntKernVirtMemFetchDword(pRegs->Rsp + 4 * 5, (DWORD *)&param4);
    }

    LOG("[INFO] The guest has generated a bugcheck on CPU %d: 0x%08x 0x%016llx 0x%016llx 0x%016llx 0x%016llx\n",
        gVcpu->Index, (DWORD)code, param1, param2, param3, param4);

    // Set the beta alerts, so we don't block the writes that will follow
    gGuest.KernelBetaDetections = TRUE;

    IntWinBcLogBsodEvent(code, param1, param2, param3, param4);

    status = IntWinBcSendBsodEvent(code, param1, param2, param3, param4);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntWinBcSendBsodEvent failed: 0x%08x\n", status);
    }

    return INT_STATUS_SUCCESS;
}
