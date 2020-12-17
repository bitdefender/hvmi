/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "lixguest.h"
#include "cr_protection.h"
#include "decoder.h"
#include "drivers.h"
#include "hook.h"
#include "introcpu.h"
#include "lixapi.h"
#include "lixidt.h"
#include "lixkernel.h"
#include "lixmm.h"
#include "lixvdso.h"
#include "msr_protection.h"
#include "dtr_protection.h"
#include "lixfiles.h"
#include "lixksym.h"
#include "memcloak.h"

#include "linux/agents/agents_content.h"
#include "detours_hypercall.h"

///
/// @brief  Global variable holding the state of a Linux guest
///
/// This is not dynamically allocated. It points to the _LinuxGuest field of the #gGuest variable.
/// Its value is set by #IntLixGuestNew.
LINUX_GUEST *gLixGuest = NULL;

extern LIST_HEAD gKernelDrivers;

/// An array that contains the distro signatures.
PATTERN_SIGNATURE *gLinuxDistSigs;
/// The number of distro signatures from #gLinuxDistSigs.
DWORD gLinuxDistSigsCount = 0;

/// The maximum number of pages of kernel that will be scanned.
#define LIX_KERNEL_MAX_PAGES                16384

#define LIX_BANNER_START                    "Linux version "        ///< The start of the 'linux_proc_banner' string.

#define LIX_MODULE_MAPPING_SPACE_START      0xffffffffa0000000      ///< The start of module mapping region.
#define LIX_MODULE_MAPPING_SPACE_END        0xfffffffffeffffff      ///< The end of module mapping region.

/// The max value of 'kaiser_enabled_pcp' offset (the maximum observed was 0xD040 on CentOS - kernel 3.10)
#define LIX_KAISER_ENABLED_PCP_OFFSET_CAP   0xE000UL


static void
IntLixGuestSetOsVersion(
    void
    )
///
/// @brief Computes the OS version number using the version, patch and sublevel.
///
{
    gGuest.OSVersion = ((gLixGuest->Version.Version & 0xFF) << 24);
    gGuest.OSVersion |= ((gLixGuest->Version.Patch & 0xFF) << 16);
    gGuest.OSVersion |= (gLixGuest->Version.Sublevel & 0xFFFF);
}


static INTSTATUS
IntLixGuestParseVersion(
    _In_reads_z_(BufferLength) const char *Buffer,
    _In_ DWORD BufferLength
    )
///
/// @brief Parses the 'linux_proc_banner' and searches for 'version.patch.sublevel-backport' pattern.
///
/// On success, #LINUX_GUEST.Version contains the found version.
///
/// @param[in]  Buffer          A buffer that contains the 'linux_proc_banner'.
/// @param[in]  BufferLength    The size (bytes) of the banner.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the version is not found.
///
{
    DWORD start, end;
    WORD v[3];
    char c[5];
    BOOLEAN hasBackport;

    start = end = 0;
    hasBackport = FALSE;
    for (DWORD i = 0; i < 3; i++)
    {
        BOOLEAN found = FALSE;
        while (end < BufferLength && Buffer[end])
        {
            // See the 'linux_proc_banner' for more info
            if ('.' == Buffer[end] || ' ' == Buffer[end] || '-' == Buffer[end] || '+' == Buffer[end])
            {
                found = TRUE;
                hasBackport = '-' == Buffer[end];
                break;
            }
            else if (Buffer[end] < '0' || Buffer[end] > '9')
            {
                return INT_STATUS_NOT_FOUND;
            }

            end++;
        }

        if (!found)
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (end - start >= sizeof(c))
        {
            WARNING("[WARNING] Version number too big (%d/%zu)\n", end - start, sizeof(c));
            return INT_STATUS_NOT_FOUND;
        }

        memcpy(c, &Buffer[start], end - start);
        c[end - start] = 0;
        v[i] = (WORD)strtol(c, NULL, 0);

        ++end;
        start = end;
    }

    gLixGuest->Version.Version = (BYTE)v[0];
    gLixGuest->Version.Patch = (BYTE)v[1];
    gLixGuest->Version.Sublevel = v[2];

    if (!hasBackport)
    {
        TRACE("[LIXGUEST] No backport info!");

        gLixGuest->Version.Backport = 0;
        goto _log_and_exit;
    }

    start = end;
    while (end < BufferLength && Buffer[end] >= '0' && Buffer[end] <= '9')
    {
        ++end;
    }

    if (end - start >= sizeof(c))
    {
        WARNING("[WARNING] Backport number too big (%d/%zu)\n", end - start, sizeof(c));

        gLixGuest->Version.Backport = 0;
        goto _log_and_exit;
    }

    memset(c, 0, sizeof(c));
    memcpy(c, &Buffer[start], end - start);
    gLixGuest->Version.Backport = (WORD)strtol(c, NULL, 0);

_log_and_exit:


    TRACE("[LIXGUEST] We run kernel version %d.%d.%d-%d (%08x)\n",
          gLixGuest->Version.Version,
          gLixGuest->Version.Patch,
          gLixGuest->Version.Sublevel,
          gLixGuest->Version.Backport,
          gLixGuest->Version.Value);

    IntLixGuestSetOsVersion();

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixGuestFindKernelVersionAndRo(
    _In_ QWORD StartGva
    )
///
/// @brief Scans pages from guest memory, starting from the provided StartGva and tries to find the .rodata section and
/// the Linux kernel version.
///
/// This function translates a guest virtual address and maps the corresponding guest physical page. In order to find
/// the Linux kernel version the #IntLixGuestParseVersion is called; the 'linux_proc_banner' is the first data from the
/// .rodata section, thus we mark the guest virtual address of the 'linux_proc_banner' as the start of the .rodata
/// section.
/// If the Linux kernel version is found and the current guest physical page is not present, we mark the current guest
/// virtual address as the end of the .rodata section.
///
/// @param[in]  StartGva    The guest virtual address from which we start scanning.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the Linux kernel version/.rodata section is not found.
///
{
    INTSTATUS status;
    QWORD gva = StartGva & PAGE_MASK;
    DWORD pageCount = 0;
    BOOLEAN versionFound = FALSE;

    // Now find the version and the size. Skip pages which are not present until we find the linux banner.
    // We already counted how many pages are to the beginning, now count how many are to the end.
    gva = StartGva & PAGE_MASK;
    while (pageCount < LIX_KERNEL_MAX_PAGES)
    {
        char *pPage;
        DWORD parsed, size;
        VA_TRANSLATION tr;

        // If translation fails we stop. We only continue if the page is not present and we haven't found
        // the Linux banner yet.
        status = IntTranslateVirtualAddressEx(gva, gGuest.Mm.SystemCr3, 0, &tr);
        if (!INT_SUCCESS(status))
        {
            break;
        }

        if (0 == (tr.Flags & PT_P))
        {
            if (versionFound)
            {
                // We have the version, this should be the end of kernel.
                break;
            }

            // Continue searching
            gva += PAGE_SIZE;
            pageCount++;
            continue;
        }

        if (versionFound)
        {
            // No need to skip only one page if we already have the version.
            gva += tr.PageSize;
            pageCount += (DWORD)(tr.PageSize / PAGE_SIZE);
            continue;
        }

        status = IntPhysMemMap(tr.PhysicalAddress, PAGE_SIZE, 0, &pPage);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntPhysMemMap failed for %016llx (%016llx): 0x%08x\n", tr.PhysicalAddress, gva, status);
            break;
        }

        for (parsed = 0; parsed + sizeof(LIX_BANNER_START) < PAGE_SIZE; parsed++)
        {
            DWORD verMax = parsed;
            BOOLEAN verMaxFound = FALSE;

            if (0 != strncmp(&pPage[parsed], LIX_BANNER_START, sizeof(LIX_BANNER_START) - 1))
            {
                continue;
            }

            TRACE("[LIXGUEST] Found a 'Linux version ' at %llx. The start of rodata is at %llx\n", gva + parsed, gva);

            status = IntLixGuestParseVersion(pPage + parsed + CSTRLEN(LIX_BANNER_START),
                                             PAGE_SIZE - parsed - CSTRLEN(LIX_BANNER_START));
            if (!INT_SUCCESS(status))
            {
                continue;
            }

            // Find out if the linux_proc_banner ends in the same page (it should!), and print it.
            // If it doesn't, just skip it for now...
            while (verMax < PAGE_SIZE)
            {
                if (pPage[verMax] == '\0')
                {
                    LOG("[LIXGUEST] Linux version complete: %s\n", &pPage[parsed]);

                    verMaxFound = TRUE;
                    verMax++; // Include the NULL-terminator

                    break;
                }

                verMax++;
            }

            if (!verMaxFound)
            {
                continue;
            }

            size = verMax - parsed + sizeof(LIX_BANNER_START) - 1;

            if (size > sizeof(gLixGuest->VersionString))
            {
                memcpy(gLixGuest->VersionString,
                       &pPage[parsed + sizeof(LIX_BANNER_START) - 1],
                       sizeof(gLixGuest->VersionString) - 1);
            }
            else
            {
                // Already includes the NULL terminator
                memcpy(gLixGuest->VersionString, &pPage[parsed + sizeof(LIX_BANNER_START) - 1], size);
            }

            gLixGuest->Layout.RoDataStart = gva;

            // Temporary set, until we find kallsyms
            gLixGuest->Layout.CodeEnd = gva;

            versionFound = TRUE;
        }

        IntPhysMemUnmap(&pPage);

        gva += PAGE_SIZE;
        pageCount++;
    }

    if (!versionFound)
    {
        WARNING("[WARNING] Could not find kernel version! Retry ...");
        return INT_STATUS_NOT_FOUND;
    }

    gLixGuest->Layout.RoDataEnd = gva;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestFindKernelBase(
    _In_ QWORD StartGva
    )
///
/// @brief Scans pages from guest memory, starting from the provided StartGva, until we find a signature that matches
/// a given kernel.
///
/// For each mapped guest memory address, the function tries to match a distro pattern from #gLinuxDistSigs.
/// We will stop after we parser a maximum number of pages (#LIX_KERNEL_MAX_PAGES), or after we find a page that is not
/// present, or when a distro matches.
/// If we find a distro signature that matches, we mark the current guest virtual address as the start of the .text
/// section.
///
/// @param[in]  StartGva    The guest virtual address from which we start scanning.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the kernel .text section is not found.
///
{
    INTSTATUS status;
    QWORD kernelBase = StartGva & PAGE_MASK;
    DWORD pageCount = 0;
    void *p = NULL;

    status = IntVirtMemMap(kernelBase, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &p);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemMap failed for %016llx: %08x\n", kernelBase, status);
        return status;
    }

    while (SIG_NOT_FOUND == IntPatternMatch(p, gLinuxDistSigsCount, gLinuxDistSigs) &&
           pageCount++ < LIX_KERNEL_MAX_PAGES)
    {
        kernelBase -= PAGE_SIZE;

        IntVirtMemUnmap(&p);

        status = IntVirtMemMap(kernelBase, PAGE_SIZE, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for %016llx: %08x\n", kernelBase, status);
            return status;
        }
    }

    IntVirtMemUnmap(&p);

    if (pageCount >= LIX_KERNEL_MAX_PAGES)
    {
        ERROR("[ERROR] Failed finding the base of the kernel, bailing out...\n");
        return INT_STATUS_NOT_FOUND;
    }

    gGuest.KernelVa = kernelBase;

    gLixGuest->Layout.CodeStart = kernelBase;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestFindKernel(
    _In_ QWORD SyscallHandler
    )
///
/// @brief Finds the most things required by Introcore to be able to initialize completely.
///
/// NOTE: Only the gGuest.KernelVa and gGuest.KernelSize are valid, the layout will be changed after we find and
/// parse the kallsyms.
///
/// @param[in]  SyscallHandler    The guest virtual address of the syscall handler.
///
/// @retval #INT_STATUS_SUCCESS                 On success.
/// @retval #INT_STATUS_INVALID_PARAMETER_1     If the provided SyscallHandler is not a kernel pointer.
/// @retval #INT_STATUS_INVALID_INTERNAL_STATE  If the distro patterns could not be loaded.
/// @retval #INT_STATUS_NOT_FOUND               If the kernel sections or version are not found.
///
{
    INTSTATUS status;

    if (!IS_KERNEL_POINTER_LIX(SyscallHandler))
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    status = IntCamiLoadSection(CAMI_SECTION_HINT_DIST_SIG | CAMI_SECTION_HINT_LINUX);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Could not load dist sigs from update buffer.");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    status = IntLixGuestFindKernelVersionAndRo(SyscallHandler + PAGE_SIZE);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixGuestFindKernelVersionAndRo failed for syscall %llx: %08x\n", SyscallHandler, status);
        return status;
    }

    status = IntLixGuestFindKernelBase(SyscallHandler);
    if (INT_SUCCESS(status))
    {
        gGuest.KernelSize = (DWORD)(gLixGuest->Layout.RoDataEnd - gGuest.KernelVa);
    }

    HpFreeAndNullWithTag(&gLinuxDistSigs, IC_TAG_CAMI);

    return status;
}


static INTSTATUS
IntLixGuestResolveExTableLimits(
    void
    )
///
/// @brief Decodes each instruction of the 'search_exception_tables' function and searches for 'MOV REG/RSI, immediate'
/// pattern.
///
/// The specified pattern must be found twice. The immediate operand of the MOV instruction represents the start and
/// the end of the exception table.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'search_exception_tables' ksym is not found or the start/end of extable is
///                                 not found.
///
{
    QWORD funcStart, funcEnd;
    INTSTATUS status;
    INSTRUX instrux;
    QWORD addrs[2] = { 0 };

    funcStart = IntKsymFindByName("search_exception_tables", &funcEnd);
    if (!funcStart)
    {
        ERROR("[ERROR] IntKsymFindByName could not find search_exception_tables\n");
        return INT_STATUS_NOT_FOUND;
    }

    while (funcStart < funcEnd)
    {
        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, funcStart, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed: %08x\n", status);
            return status;
        }

        funcStart += instrux.Length;

        if (ND_INS_MOV != instrux.Instruction || ND_OP_IMM != instrux.Operands[1].Type)
        {
            continue;
        }

        if (0 == addrs[0])
        {
            addrs[0] = SIGN_EX_32(instrux.Operands[1].Info.Immediate.Imm);
        }
        else
        {
            addrs[1] = SIGN_EX_32(instrux.Operands[1].Info.Immediate.Imm);
            break;
        }
    }

    if (!addrs[1])
    {
        return INT_STATUS_NOT_FOUND;
    }

    gLixGuest->Layout.ExTableStart = ((addrs[0] < addrs[1]) ? addrs[0] : addrs[1]);
    gLixGuest->Layout.ExTableEnd = ((addrs[0] > addrs[1]) ? addrs[0] : addrs[1]);

    // ExTableEnd points to the last entry of the exception table.
    // Since this function will be called only on Debian 8, we can assume that sizeof(struct exception_table_entry) == 8.
    // On newer kernels they added another int field so the sizeof became 12.

    gLixGuest->Layout.ExTableEnd += 8;

    return INT_STATUS_SUCCESS;
}


static void
IntLixGuestResolveSymbols(
    void
    )
///
/// @brief Searches for the 'memcpy', '__memcpy', 'memset', '__memset' and 'memmove' ksyms.
///
{
    const char *memoryFuncs[] =
    {
        "memcpy",
        "__memcpy",
        "memset",
        "__memset",
        "memmove"
    };

    STATIC_ASSERT(ARRAYSIZE(memoryFuncs) == ARRAYSIZE(gLixGuest->MemoryFunctions), "These two should be equal...");

    for (DWORD i = 0; i < ARRAYSIZE(memoryFuncs); i++)
    {
        gLixGuest->MemoryFunctions[i].Start = IntKsymFindByName(memoryFuncs[i], &gLixGuest->MemoryFunctions[i].End);
    }
}


static INTSTATUS
IntLixResolveCurrentProcessOffset(
    void
    )
///
/// @brief Decodes each instruction of the 'do_exit' function and searches for 'MOV REG/MEM, [gs:displacement]' pattern
/// in order to find the 'current' offset.
///
/// The 'displacement' from operand [gs:displacement] represents the offset of the 'current' task.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'do_exit' ksym is not found or the offset of the 'current' is not found.
///
{
    QWORD gva, ksymEnd;

    gva = IntKsymFindByName("do_exit", &ksymEnd);
    if (!gva)
    {
        ERROR("[ERROR] IntKsymFindByName could not find do_exit\n");
        return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
    }

    while (gva < ksymEnd)
    {
        INSTRUX instrux;

        INTSTATUS status = IntDecDecodeInstruction(IG_CS_TYPE_64B, gva, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed decoding instruction at 0x%016llx: %08x\n", gva, status);
            return status;
        }

        gva += instrux.Length;

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.OperandsCount == 2 &&
            instrux.Operands[1].Type == ND_OP_MEM &&
            instrux.Seg == ND_PREFIX_G2_SEG_GS)
        {
            gLixGuest->OsSpecificFields.CurrentTaskOffset = instrux.Displacement;
            LOG("[OFFSETS] 'current' gs offset: 0x%x\n", gLixGuest->OsSpecificFields.CurrentTaskOffset);

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixResolveCurrentCpuOffset(
    void
    )
///
/// @brief Searches for the 'cpu_number' offset.
///
/// The function tries to find the 'cpu_number' ksym; if the ksym is found the value of 'cpu_number' is stored.
///
/// If the 'cpu_number' can't be found using IntKsymFindByName function, the function decode each instruction of the
/// 'xen_halt' function and search for the first instruction that matches the 'MOV REG/MEM, [gs:displacement]'.
/// The 'displacement' from operand [gs:displacement] represents the offset of 'cpu_number'.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'xen_halt' ksym is not found or the offset of the 'cpu_number' is not found.
///
{
    QWORD cpuNumberAddress;

    cpuNumberAddress = IntKsymFindByName("cpu_number", NULL);
    if (!cpuNumberAddress)
    {
        QWORD gva, functionEnd;
        INSTRUX instrux;

        LOG("[WARNING] Failed finding 'cpu_number' will try with xen_halt");

        gva = IntKsymFindByName("xen_halt", &functionEnd);
        if (!gva)
        {
            WARNING("[WARNING] IntKsymFindByName could not find xen_halt\n");
            return INT_STATUS_NOT_FOUND;
        }

        while (gva < functionEnd)
        {
            INTSTATUS status = IntDecDecodeInstruction(IG_CS_TYPE_64B, gva, &instrux);
            if (!INT_SUCCESS(status))
            {
                ERROR("[ERROR] IntDecDecodeInstruction failed at %llx: %08x\n", gva, status);
                return status;
            }

            gva += instrux.Length;

            if (instrux.Instruction == ND_INS_MOV &&
                instrux.OperandsCount == 2 &&
                instrux.Operands[1].Type == ND_OP_MEM &&
                instrux.Seg == ND_PREFIX_G2_SEG_GS)
            {
                DWORD cpuNumberOffset = instrux.Displacement;

                if (instrux.IsRipRelative)
                {
                    cpuNumberOffset += (DWORD)gva;
                }

                gLixGuest->OsSpecificFields.CurrentCpuOffset = cpuNumberOffset;

                LOG("[OFFSETS] 'current cpu' gs offset: 0x%x\n", cpuNumberOffset);

                return INT_STATUS_SUCCESS;
            }
        }
    }
    else
    {
        gLixGuest->OsSpecificFields.CurrentCpuOffset = (DWORD)cpuNumberAddress;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixResolveThreadStructOffset(
    void
    )
///
/// @brief Decodes each instruction of the 'set_tls_desc' function and searches for 'MOV RDI, immediate' pattern in
/// order to find the 'task_struct->thread_struct' offset.
///
/// The 'Immediate' operand represents the offset of the 'thread_struct' in the 'task_struct' structure.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'set_tls_desc' ksym is not found or the offset of the 'thread_struct' is not
///                                 found.
///
{
    INTSTATUS status;
    QWORD gva, ksymEnd;

    gva = IntKsymFindByName("set_tls_desc", &ksymEnd);
    if (!gva)
    {
        ERROR("[ERROR] IntKsymFindByName could not find set_tls_desc\n");
        return INT_STATUS_NOT_FOUND;
    }

    while (gva < ksymEnd)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, gva, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed at %llx: %08x\n", gva, status);
            return status;
        }

        if (instrux.Instruction == ND_INS_ADD &&
            instrux.OperandsCount == 3 &&
            instrux.Operands[1].Type == ND_OP_IMM &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Reg == NDR_RDI)
        {
            if (instrux.Operands[1].Info.Immediate.Imm < PAGE_SIZE * 3)
            {
                gLixGuest->OsSpecificFields.ThreadStructOffset = (DWORD)(instrux.Operands[1].Info.Immediate.Imm);
                LOG("[OFFSETS] 'thread_struct' offset (task_struct): 0x%x\n",
                    gLixGuest->OsSpecificFields.ThreadStructOffset);

                return INT_STATUS_SUCCESS;
            }
            else
            {
                WARNING("[WARNING] Candidate 'thread_struct' offset (0x%lx) is bigger than 0x%x ...\n",
                        instrux.Operands[1].Info.Immediate.Imm, PAGE_SIZE * 3);
            }
        }

        gva += instrux.Length;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixResolveExeFileOffset(
    void
    )
///
/// @brief Decodes each instruction of the 'get_mm_exe_file' function and searches for 'MOV REG, [RDI + Displacement]'
/// pattern in order to find the 'mm_struct->exe_file' offset.
///
/// The 'Displacement' operand represents the offset of the 'exe_file' in the 'mm_struct' structure
/// (mm_struct->exe_file).
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'get_mm_exe_file' ksym is not found or the offset of the 'exe_file' is not
///                                 found.
///
{
    INTSTATUS status;
    QWORD gva, ksymEnd;
    DWORD paramReg = NDR_RDI;

    gva = IntKsymFindByName("get_mm_exe_file", &ksymEnd);
    if (!gva)
    {
        WARNING("[WARNING] IntKsymFindByName could not find get_mm_exe_file\n");
        return INT_STATUS_NOT_FOUND;
    }

    while (gva < ksymEnd)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, gva, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed at %llx: %08x\n", gva, status);
            return status;
        }

        // Maybe it saves RDI into another one
        if (instrux.Instruction == ND_INS_MOV &&
            instrux.OperandsCount == 2 &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[1].Type == ND_OP_REG &&
            (instrux.Operands[1].Info.Register.Reg == NDR_RDI ||
             instrux.Operands[1].Info.Register.Reg == paramReg))
        {
            paramReg = instrux.Operands[0].Info.Register.Reg;
        }

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.OperandsCount == 2 &&
            instrux.Operands[1].Type == ND_OP_MEM &&
            instrux.Operands[1].Info.Memory.HasBase &&
            instrux.Operands[1].Info.Memory.HasDisp &&
            (instrux.Operands[1].Info.Memory.Base == NDR_RDI ||
             instrux.Operands[1].Info.Memory.Base == paramReg) &&
            instrux.Operands[1].Info.Memory.Disp < PAGE_SIZE &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Type == ND_REG_GPR &&
            instrux.Operands[0].Info.Register.Size == gGuest.WordSize)
        {
            LIX_FIELD(MmStruct, ExeFile) = (DWORD)instrux.Operands[1].Info.Memory.Disp;
            LOG("[OFFSETS] mm_struct->exe_file offset: 0x%x\n", LIX_FIELD(MmStruct, ExeFile));

            return INT_STATUS_SUCCESS;
        }

        gva += instrux.Length;
    }

    return INT_STATUS_NOT_FOUND;
}


INTSTATUS
IntLixGuestFindProperSyscall(
    _In_ QWORD SyscallAddress,
    _Out_ QWORD *ProperSyscallAddress
    )
///
/// @brief Decodes each instruction from the provided syscall handler address and searches for a pattern if the
/// provided syscall address is not inside the kernel mapping region.
///
/// The function searches for two patterns in the syscall address: 'MOV RDI, immediate' and
/// 'JMP RDI'/'CALL relative_address'.
/// The immediate operand form 'MOV RDI, immediate' instruction represents the 'real' syscall guest virtual address;
/// the function stores this value and search for the next patterns.
/// Next, the function search for 'JMP RDI' or 'CALL realtive_address'; if this pattern is found we mark the previously
/// saved value as the syscall 'real' guest virtual address.
///
/// @param[in]  SyscallAddress          The guest virtual address of the syscall handler.
/// @param[out] ProperSyscallAddress    The 'real' syscall guest virtual address.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the 'real' syscall address is inside the kernel text mapping region or if the
///                                 'real' syscall address is not found.
///
{
    QWORD currentSyscallAddress;
    QWORD foundSyscallAddress = 0;

    *ProperSyscallAddress = 0;

    if ((SyscallAddress >> 31) & 1)
    {
        return INT_STATUS_NOT_FOUND;
    }

    currentSyscallAddress = SyscallAddress;

    while (currentSyscallAddress - SyscallAddress < PAGE_SIZE)
    {
        INSTRUX instrux;
        NDSTATUS status;

        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, currentSyscallAddress, &instrux);
        if (!ND_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed with status 0x%08X", status);
            return INT_STATUS_NOT_FOUND;
        }

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.OperandsCount == 2 &&
            instrux.Operands[0].Info.Register.Reg == NDR_RDI &&
            instrux.Operands[1].Type == ND_OP_IMM &&
            IS_KERNEL_POINTER_LIX(instrux.Operands[1].Info.Immediate.Imm))
        {
            foundSyscallAddress = instrux.Operands[1].Info.Immediate.Imm;
        }
        else if (0 != foundSyscallAddress &&
                 ((instrux.Instruction == ND_INS_CALLNR &&
                   instrux.Operands[0].Type == ND_OP_OFFS &&
                   instrux.Operands[0].Info.RelativeOffset.Rel < 0x20) ||
                  (instrux.Instruction == ND_INS_JMPNI &&
                   instrux.Operands[0].Type == ND_OP_REG &&
                   instrux.Operands[0].Info.Register.Reg == NDR_RDI)))
        {
            *ProperSyscallAddress = foundSyscallAddress;
            return INT_STATUS_SUCCESS;
        }

        currentSyscallAddress += instrux.Length;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixGuestResolveOffsets(
    void
    )
///
/// @brief Finds the offsets required by Introcore.
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If a required offset is not found.
///
{
    INTSTATUS status;

    status = IntLixResolveCurrentProcessOffset();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixResolveCurrentProcessOffset failed: 0x%08x\n", status);
        return status;
    }

    status = IntLixResolveCurrentCpuOffset();
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixResolveCurrentCpuOffset failed: 0x%08x\n", status);
        // not a critical error
    }

    status = IntLixResolveExeFileOffset();
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntLixResolveExeFileOffset failed: 0x%08x\n", status);
        // for now not a critical error
    }

    status = IntLixResolveThreadStructOffset();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixResolveThreadStructOffset failed: 0x%08x\n", status);
        return status;
    }

    // The following offsets can be found dynamically:
    //      taks->flags                      -> at begining
    //      task->tgid, task->pid            -> '__audit_ptrace'
    //      task->real_parent, task_parent   -> '__ptrace_unlink'
    //      task->mm, task->active_mm        -> 'sys_brk'
    //      task->comm                       -> 'get_task_comm'
    //      task->signal                     -> 'do_signal_stop'
    //      task->exit_code                  ->
    //      module->list                     -> at begining
    //      module->name                     -> fixed
    //      moulde->core_layout              -> 'module_disable_ro'
    //      moulde->init_layout              -> 'module_disable_ro'
    //      module->init                     -> 'do_init_module'
    //
    // NOTE: Add more as needed

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestActivateProtection(
    void
    )
///
/// @brief  Activates the protection for a Linux guest.
///
/// Depending on the used core-options, this will activate various protection mechanisms: IDT, MSR, CR4, IDTR, and GDTR.
///
/// @retval    #INT_STATUS_SUCCESS On success, or an appropriate INTSTATUS error value.
///
{
    INTSTATUS status;
    INTSTATUS returnStatus = INT_STATUS_SUCCESS;

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LX)
    {
        status = IntLixKernelWriteProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixKernelWriteProtect failed: 0x%08x\n", status);
            returnStatus = status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_LX_TEXT_READS)
    {
        status = IntLixKernelReadProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixKernelReadProtect failed: 0x%08x\n", status);
            returnStatus = status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_VDSO)
    {
        status = IntLixVdsoProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixVdsoProtect failed: 0x%08x\n", status);
            returnStatus = status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_GDTR)
    {
        IntGdtrProtect();
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDTR)
    {
        IntIdtrProtect();
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_IDT)
    {
        status = IntLixIdtProtectAll();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixIdtProtectAll failed: 0x%08x\n", status);
            // Not critical, go forward
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_MSR_SYSCALL)
    {
        status = IntMsrSyscallProtect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMsrSyscallProtect failed: 0x%08x\n", status);
            returnStatus = status;
        }
    }

    if (gGuest.CoreOptions.Current & INTRO_OPT_PROT_KM_CR4)
    {
        status = IntCr4Protect();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntCr4Protect failed: 0x%08x\n", status);
            returnStatus = status;
        }
    }

    gGuest.ProtectionActivated = TRUE;

    return returnStatus;
}


INTSTATUS
IntLixGuestIsKptiActive(
    _In_ QWORD SyscallGva
    )
///
/// @brief  Checks if the Linux guest has the KPTI active.
///
/// This function decodes instructions from syscall handler address and searches for the 'MOV CR3, REG' pattern; if this
/// pattern is not found, the KPTI is not active for this guest.
///
/// If the 'TEST [gs:displacement], immediate' pattern is not found and the 'MOV CR3, REG', the KPTI is active for this
/// guest, otherwise the value of 'displacement' operand is saved.
///
/// NOTE: The 'displacement' operand from  instruction 'TEST [gs:displacement], imm' represents the value of
/// 'kaiser_enabled_pcp' kallsym.
///
/// If the 'MOV CR3, REG' pattern is found and if the value of [GS:displacement] (previously saved from 'TEST
/// [GS:displacement], imm') has the KAISER_PCP_ENABLED (1 << 0), thus the KPTI is active on this guest; otherwise KPTI
/// is not active.
///
/// @param[in]  SyscallGva  The address of the syscall handler.
///
/// @retval    #INT_STATUS_SUCCESS On success, or an appropriate #INTSTATUS error value.
///
{
    QWORD gsBase;
    DWORD gsOffset = 0;
    DWORD gsValue = 0;
    INTSTATUS status;
    BOOLEAN foundMovCr3 = FALSE;
    BYTE pSyscall[256];

    gGuest.KptiActive = FALSE;
    gGuest.KptiInstalled = TRUE;

    status = IntKernVirtMemRead(SyscallGva, sizeof(pSyscall), pSyscall, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for %llx: %08x\n", SyscallGva, status);
        return status;
    }

    for (DWORD i = 0; i < sizeof(pSyscall);)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstructionFromBuffer(&pSyscall[i], sizeof(pSyscall) - i, IG_CS_TYPE_64B, &instrux);
        if (!INT_SUCCESS(status))
        {
            if (sizeof(pSyscall) - i < ND_MAX_INSTRUCTION_LENGTH)
            {
                break;
            }

            ERROR("[ERROR] Invalid instruction in syscall @ %llx: %08x\n", SyscallGva, status);
            return status;
        }

        if (i <= 10 &&
            (instrux.Instruction == ND_INS_JMPNR &&
             instrux.Operands[0].Type == ND_OP_OFFS))
        {
            LOG("[INFO] Found a JMP right after SWAPGS, skip until that (+%02x)\n", instrux.RelativeOffset);
            i += instrux.RelativeOffset;
        }

        i += instrux.Length;

        if (instrux.Instruction == ND_INS_TEST &&
            instrux.Operands[0].Type == ND_OP_MEM &&
            instrux.Seg == ND_PREFIX_G2_SEG_GS)
        {
            gsOffset = instrux.Displacement;
        }

        if (instrux.Instruction == ND_INS_MOV_CR &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Type == ND_REG_CR &&
            instrux.Operands[0].Info.Register.Reg == NDR_CR3 &&
            instrux.Operands[1].Type == ND_OP_REG &&
            instrux.Operands[1].Info.Register.Type == ND_REG_GPR)
        {
            foundMovCr3 = TRUE;
            break;
        }
    }

    if (!foundMovCr3)
    {
        goto _do_leave;
    }

    if (0 == gsOffset)
    {
        gGuest.KptiActive = TRUE;
        goto _do_leave;
    }

    if (gsOffset > LIX_KAISER_ENABLED_PCP_OFFSET_CAP)
    {
        ERROR("[ERROR] The value of misplacement operand (0x%08x) from instruction 'TEST [GS:displacement], immediate' "
              "exceed our cap (0x%lx)\n", gsOffset, LIX_KAISER_ENABLED_PCP_OFFSET_CAP);
        gGuest.KptiActive = FALSE;
        goto _do_leave;
    }

    status = IntGsRead(IG_CURRENT_VCPU, &gsBase);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntGsRead failed: %08x\n", status);
        return status;
    }

    if (!IS_KERNEL_POINTER_LIX(gsBase))
    {
        gGuest.KptiInstalled = FALSE;
        goto _do_leave;
    }

    status = IntKernVirtMemFetchDword(gsBase + gsOffset, &gsValue);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] IntKernVirtMemFetchDword failed for %llx: %08x\n", gsBase + gsOffset, status);
        gGuest.KptiInstalled = FALSE;
        goto _do_leave;
    }

    gGuest.KptiActive = (gsValue & 1) != 0;

_do_leave:
    if (gGuest.KptiInstalled)
    {
        LOG("[LIXGUEST] KPTI active: %d\n", gGuest.KptiActive);
    }
    else
    {
        LOG("[LIXGUEST] KPTI cannot be reliable detected... Defer it!\n");
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixFindDataStart(
    void
    )
///
/// @brief Decodes each instruction of the 'mark_rodata_ro' function and searches for end of .rodata section and the
/// start of .data section.
///
/// The function searches for the 'MOV REG, immediate' and creates an array that looks like:
///    arr[0] ->        _stext
///    arr[1] ->        _etext
///    arr[2] ->        __start_rodata (it may be unaligned)
///    ...
///    arr[k] ->        __end_rodata
///    arr[k + 1] ->    __end_rodata_hpage_aligned -> _sdata
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the start/end addresses are not found.
///
{
    INTSTATUS status;
    QWORD gvaStart, gvaEnd;
    INSTRUX instrux;
    QWORD allGvas[10];
    DWORD nrOfGvas = 0, iGva;
    QWORD gva;

    gvaStart = IntKsymFindByName("mark_rodata_ro", &gvaEnd);
    if (!gvaStart)
    {
        ERROR("[ERROR] IntKsymFindByName failed for mark_rodata_ro\n");
        return INT_STATUS_NOT_FOUND;
    }

    while (gvaStart < gvaEnd)
    {
        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, gvaStart, &instrux);
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] IntDecDecodeInstruction failed: %08x\n", status);
            break;
        }

        gvaStart += instrux.Length;
        gva = instrux.Operands[1].Info.Immediate.Imm;

        if (!(instrux.Operands[0].Type == ND_OP_REG && instrux.Operands[1].Type == ND_OP_IMM) ||
            ((0xFFFFFFFF80000000 & gva) != 0xFFFFFFFF80000000))
        {
            continue;
        }

        for (iGva = 0; iGva < nrOfGvas; iGva++)
        {
            if (allGvas[iGva] == gva)
            {
                break;
            }
        }

        if (nrOfGvas != iGva)
        {
            continue; // already exists
        }

        for (iGva = nrOfGvas; (iGva > 0) && (allGvas[iGva - 1]  > gva); iGva--)
        {
            allGvas[iGva] = allGvas[iGva - 1];
        }

        allGvas[iGva] = gva;
        nrOfGvas++;

        if (nrOfGvas >= 10)
        {
            break;
        }
    }

    if (nrOfGvas <= 4)
    {
        return INT_STATUS_NOT_FOUND;
    }

    if ((allGvas[2] & PAGE_MASK) != gLixGuest->Layout.RoDataStart)
    {
        return INT_STATUS_NOT_FOUND;
    }

    for (iGva = 4; iGva < nrOfGvas; iGva++)
    {
        if (allGvas[iGva] >= gLixGuest->Layout.DataEnd)
        {
            return INT_STATUS_NOT_FOUND;
        }

        if (!(allGvas[iGva] & PAGE_OFFSET_MASK_2M) &&
            (((allGvas[iGva] - 1) & PAGE_BASE_MASK_2M) == ((allGvas[iGva - 1] & PAGE_BASE_MASK_2M))))
        {
            gLixGuest->Layout.RoDataEnd = allGvas[iGva - 1] & PAGE_MASK;
            gLixGuest->Layout.DataStart = allGvas[iGva];

            return INT_STATUS_SUCCESS;
        }
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixGuestFindPgd(
    _Out_ QWORD *Pgd
    )
///
/// @brief Searches for the system CR3.
///
/// This function tries to get the system CR3 by searching for 'init_top_pgt' or 'init_level4_pgt' ksyms; if the ksym
/// is found the value of it is returned.
///
/// If the function ksyms are not available, the 'arch_crash_save_vmcoreinfo' is disassembled and parsed. When the
/// second 'CALL vmcoreinfo_append_str' is found, the function marks the value of the RDX as a system CR3.
///
/// arch_crash_save_vmcoreinfo(...)
/// {
///     VMCOREINFO_NUMBER(phys_base);
///     VMCOREINFO_SYMBOL(init_top_pgt);
/// }
///
/// NOTE:  We are dependent on the guest state for the system cr3. When we are initialized static, the CR3 of the
/// current processor can be anywhere, souse the Linux variable 'init_level4_pgt' ('swapper_pg_dir' points to it).
///
/// @param[out] Pgd     On success, the value of the system CR3 (PGD).
///
/// @retval #INT_STATUS_SUCCESS     On success.
/// @retval #INT_STATUS_NOT_FOUND   If the value of the system CR3 is not found.
///
{
    INTSTATUS status;
    QWORD ksymEnd, ksymEndAux;

    QWORD pgdAddr = IntKsymFindByName("init_top_pgt", NULL);
    if (pgdAddr)
    {
        *Pgd = pgdAddr;
        return INT_STATUS_SUCCESS;
    }

    pgdAddr = IntKsymFindByName("init_level4_pgt", NULL);
    if (pgdAddr)
    {
        *Pgd = pgdAddr;
        return INT_STATUS_SUCCESS;
    }

    QWORD ksymStart = IntKsymFindByName("arch_crash_save_vmcoreinfo", &ksymEnd);
    if (!ksymStart)
    {
        ERROR("[ERROR] IntKsymFindByName could not find arch_crash_save_vmcoreinfo\n");
        return INT_STATUS_NOT_FOUND;
    }

    QWORD ksymStartAux = IntKsymFindByName("vmcoreinfo_append_str", &ksymEndAux);
    if (!ksymStartAux)
    {
        ERROR("[ERROR] IntKsymFindByName could not find vmcoreinfo_append_str\n");
        return INT_STATUS_NOT_FOUND;
    }

    WORD funcCallCount = 0;
    while (ksymStart < ksymEnd)
    {
        INSTRUX instrux;

        status = IntDecDecodeInstruction(IG_CS_TYPE_64B, ksymStart, &instrux);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntDecDecodeInstruction failed at GVA %llx: 0x%08x.\n", ksymStart, status);
            ksymStart++;
            continue;
        }

        if (instrux.Instruction == ND_INS_MOV &&
            instrux.Operands[0].Type == ND_OP_REG &&
            instrux.Operands[0].Info.Register.Reg == NDR_RDX &&
            instrux.Operands[1].Type == ND_OP_IMM)
        {
            pgdAddr = instrux.Operands[1].Info.Immediate.Imm;
        }

        if (instrux.Instruction == ND_INS_CALLNR)
        {
            QWORD ksymRelAux = ksymStartAux - (ksymStart + 5);

            if (instrux.Operands[0].Info.RelativeOffset.Rel == ksymRelAux)
            {
                funcCallCount++;
            }

            if (funcCallCount == 2)
            {
                *Pgd = pgdAddr;
                return INT_STATUS_SUCCESS;
            }
        }

        ksymStart += instrux.Length;
    }

    return INT_STATUS_NOT_FOUND;
}


static INTSTATUS
IntLixPatchHandler(
    _In_ void *Detour,
    _In_ LIX_ACTIVE_PATCH *ActivePatch
    )
///
/// @brief Handles the incoming patches (ftrace/text_poke) from the guest.
///
/// If the originator of the patch is a driver a, the function stores the information about the patch, otherwise patch
/// is ignored.
/// The patch is also ignored if the size of the write is grater the sizeof(ActivePatch->Data).
///
/// @param[in] Detour       The detour for which this callback is invoked.
/// @param[in] ActivePatch  The active-patch structure that contains information about the patch.
///
/// @retval #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIST_ENTRY *list = NULL;
    QWORD patchGva, address;
    WORD length;
    BOOLEAN bFound;

    UNREFERENCED_PARAMETER(Detour);

    patchGva = gVcpu->Regs.R8;
    length = (WORD)gVcpu->Regs.R10;
    address = gVcpu->Regs.R9;

    list = gKernelDrivers.Head;
    bFound = FALSE;
    while (list != &gKernelDrivers)
    {
        KERNEL_DRIVER *pDriver = CONTAINING_RECORD(list, KERNEL_DRIVER, Link);
        list = list->Flink;

        if (pDriver->Lix.CoreLayout.Base <= patchGva &&
            patchGva < pDriver->Lix.CoreLayout.Base + pDriver->Lix.CoreLayout.RoSize)
        {
            bFound = TRUE;
            break;
        }
    }

    if (!bFound)
    {
        // If we can not find the address in any driver then most likely that area is not protected.
        // But there is a chance the GVA points to a GPA which is hooked by introcore e.g. __va(__pa(x))
        TRACE("[WARNING] Incoming patch at address 0x%llx with no corresponding driver. Will ignore!\n", patchGva);
        return INT_STATUS_SUCCESS;
    }

    if (length > sizeof(ActivePatch->Data))
    {
        WARNING("[WARNING] Patch with size %d... We ignore it!\n", length);
        return INT_STATUS_SUCCESS;
    }

    status = IntKernVirtMemRead(address, length, ActivePatch->Data, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed: 0x%08x. Patch at GVA 0x%llx will be ignored.\n", status, patchGva);
        return status;
    }

    ActivePatch->Gva = patchGva;
    ActivePatch->Length = length;

    ActivePatch->IsDetour = IntDetIsPtrInRelocatedCode(patchGva, &ActivePatch->DetourTag);

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixTextPokeHandler(
    _In_ void *Detour
    )
///
/// @brief Handles the incoming 'text_poke' patches from the guest.
///
/// @param[in] Detour       The detour for which this callback is invoked.
///
/// @retval #INT_STATUS_SUCCESS     On success.
///
{
    LIX_ACTIVE_PATCH *pActivePatch = &gLixGuest->ActivePatch[lixActivePatchTextPoke];

    return IntLixPatchHandler(Detour, pActivePatch);
}


INTSTATUS
IntLixFtraceHandler(
    _In_ void *Detour
    )
///
/// @brief Handles the incoming 'text_poke' patches from the guest.
///
/// @retval #INT_STATUS_SUCCESS     On success.
///
{
    LIX_ACTIVE_PATCH *pActivePatch = &gLixGuest->ActivePatch[lixActivePatchFtrace];

    return IntLixPatchHandler(Detour, pActivePatch);
}


INTSTATUS
IntLixJumpLabelHandler(
    _In_ void *Detour
    )
///
/// @brief Handles the incoming read (arch_jmp_label_transform) from the guest.
///
/// The function stores the information about the incoming read.
///
/// @param[in] Detour       The detour for which this callback is invoked.
///
/// @retval #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;
    LIX_ACTIVE_PATCH *pActivePatch = &gLixGuest->ActivePatch[lixActivePatchJmpLabel];
    QWORD jumpEntry = gVcpu->Regs.R8;
    QWORD gva = 0;

    UNREFERENCED_PARAMETER(Detour);

    status = IntKernVirtMemFetchQword(jumpEntry,  &gva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: %08x\n", jumpEntry, status);
        return status;
    }

    pActivePatch->Gva = gva;
    pActivePatch->Length = 5;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestInit(
    void
    )
///
/// @brief  Initializes a new Linux guest.
///
/// Initialize the information required to protect the current guest.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT         If the gGuest.Initialized is false.
/// @retval     #INT_STATUS_GUEST_OS_NOT_SUPPORTED  If the Linux kernel used by the guest is not supported.
///
{
    INTSTATUS status;

    if (gGuest.GuestInitialized)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    status = IntKsymInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKsymInit failed: 0x%08x", status);
        return status;
    }

    gLixGuest->Layout.CodeEnd = IntKsymFindByName("_etext", NULL);
    if (!gLixGuest->Layout.CodeEnd)
    {
        ERROR("[ERROR] Failed finding '_etext' symbol\n");
        return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
    }

    // If this is missing, then the kernel exports in kallsyms only the functions.
    // We can still approximate the layout (based on _sinittext and _etext)
    gLixGuest->Layout.DataStart = IntKsymFindByName("_sdata", NULL);
    if (!gLixGuest->Layout.DataStart)
    {
        gLixGuest->Layout.DataStart = ROUND_UP(gLixGuest->Layout.CodeEnd, PAGE_SIZE);

        gLixGuest->Layout.DataEnd = IntKsymFindByName("_sinittext", NULL);
        if (!gLixGuest->Layout.DataEnd)
        {
            ERROR("[ERROR] IntKsymFindByName could not find _sinittext\n");
            return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        }

        status = IntLixFindDataStart();
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntLixFindDataStart failed: %08x\n", status);
            return status;
        }

        status = IntLixGuestResolveExTableLimits();
        if (!INT_SUCCESS(status))
        {
            WARNING("[WARNING] Could not find ex_table limits: 0x%08x\n", status);
        }
    }
    else
    {
        gLixGuest->Layout.DataEnd = IntKsymFindByName("_edata", NULL);
        if (!gLixGuest->Layout.DataEnd)
        {
            ERROR("[ERROR] IntKsymFindByName could not find _edata\n");
            return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        }

        gLixGuest->Layout.ExTableStart = IntKsymFindByName("__start___ex_table", &gLixGuest->Layout.ExTableEnd);
        if (!gLixGuest->Layout.ExTableStart)
        {
            ERROR("[ERROR] IntKsymFindByName could not find __start___ex_table\n");
            return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        }

        gLixGuest->Layout.RoDataStart = IntKsymFindByName("__start_rodata", NULL);
        if (!gLixGuest->Layout.RoDataStart)
        {
            ERROR("[ERROR] IntKsymFindByName could not find __start_rodata\n");
            return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        }

        gLixGuest->Layout.RoDataEnd = IntKsymFindByName("__end_rodata", NULL);
        if (!gLixGuest->Layout.RoDataEnd)
        {
            ERROR("[ERROR] IntKsymFindByName could not find __end_rodata\n");
            return INT_STATUS_GUEST_OS_NOT_SUPPORTED;
        }
    }

    if (LIX_FIELD(Info, HasAlternateSyscall))
    {
        gLixGuest->PropperSyscallGva = IntKsymFindByName("do_syscall_64", NULL);
        if (!gLixGuest->PropperSyscallGva)
        {
            WARNING("[WARNING] Could not find proper syscall gva. Agent injection may fail!\n");
        }
        else
        {
            TRACE("[INFO] Proper syscall address: %llx\n", gLixGuest->PropperSyscallGva);
        }
    }

    TRACE("[LIXGUEST] .kernel : 0x%016llx - 0x%016llx  (%4lld kB)\n",
          gGuest.KernelVa,
          gGuest.KernelVa + gGuest.KernelSize,
          gGuest.KernelSize / ONE_KILOBYTE);
    TRACE("[LIXGUEST] .text   : 0x%016llx - 0x%016llx  (%4lld kB)\n",
          gLixGuest->Layout.CodeStart, gLixGuest->Layout.CodeEnd,
          (gLixGuest->Layout.CodeEnd - gLixGuest->Layout.CodeStart) / ONE_KILOBYTE);
    TRACE("[LIXGUEST] .data   : 0x%016llx - 0x%016llx  (%4lld kB)\n",
          gLixGuest->Layout.DataStart, gLixGuest->Layout.DataEnd,
          (gLixGuest->Layout.DataEnd - gLixGuest->Layout.DataStart) / ONE_KILOBYTE);
    TRACE("[LIXGUEST] .rodata : 0x%016llx - 0x%016llx  (%4lld kB)\n",
          gLixGuest->Layout.RoDataStart, gLixGuest->Layout.RoDataEnd,
          (gLixGuest->Layout.RoDataEnd - gLixGuest->Layout.RoDataStart) / ONE_KILOBYTE);

    status = IntLixDrvCreateKernel();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Failed initializing the linux kernel driver: 0x%08x\n", status);
        return status;
    }

    IntLixGuestResolveSymbols();

    status = IntLixGuestResolveOffsets();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestResolveOffsets failed: 0x%08x\n", status);
        return status;
    }

    gGuest.GuestInitialized = TRUE;

    return INT_STATUS_SUCCESS;
}


void
IntLixGuestUninit(
    void
    )
///
/// @brief  Uninitialize the Linux guest.
///
/// This function deactivate the protection and free any resources held by the #LINUX_GUEST state.
///
{
    INTSTATUS status;

    if (!gGuest.GuestInitialized || NULL == gLixGuest)
    {
        return;
    }

    IntLixVdsoUnprotect();

    status = IntLixIdtUnprotectAll();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixIdtUnprotectAll failed: 0x%08x\n", status);
    }

    status = IntCr4Unprotect();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntCr4Unprotect failed: 0x%08x\n", status);
    }

    IntDriverUninit();

    IntLixTaskUninit();

    if (NULL != gLixGuest->OsSpecificFields.Functions)
    {
        HpFreeAndNullWithTag(&gLixGuest->OsSpecificFields.Functions, IC_TAG_CAMI);
    }

    IntKsymUninit();

    IntLixAgentUninit();

    IntLixFilesCacheUninit();

    TRACE("[INTRO-UNINIT] Uninit allocated guest memory ...\n");
    IntLixGuestUninitGuestCode();

    gGuest.GuestInitialized = FALSE;
}


static BOOLEAN
IntLixGuestIsSupported(
    void
    )
///
/// @brief  Load OS information from CAMI if the guest is supported.
///
/// Loads all OS specific information from CAMI, for the current guest described by #GUEST_STATE.OSVersion then sets
/// #GUEST_STATE.SafeToApplyOptions
///
/// @retval True if the guest is supported, otherwise false.
///
{
    INTSTATUS status = IntCamiLoadSection(CAMI_SECTION_HINT_SUPPORTED_OS | CAMI_SECTION_HINT_LINUX);
    if (!INT_SUCCESS(status))
    {
        return FALSE;
    }

    gGuest.SafeToApplyOptions = TRUE;

    return TRUE;
}


static INTSTATUS
IntLixGuestDetourDataHandler(
    _In_opt_ void **Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Dumps information about the read/write attempt.
///
/// @param[in]  Context         Unused.
/// @param[in]  Hook            The #HOOK_GPA associated to this callback.
/// @param[in]  Address         The guest physical address that was accessed.
/// @param[in]  Action          Desired action (allow, block).
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status;
    QWORD address = IntHookGetGlaFromGpaHook(Hook, Address);
    CHAR ksymbol[126] = { 0 };
    HOOK_GPA *pHook = Hook;

    UNREFERENCED_PARAMETER(Context);

    status = IntKsymFindByAddress(gVcpu->Regs.Rip, sizeof(ksymbol), ksymbol, NULL, NULL);
    TRACE("[LIXGUEST] %s attempt on detour code from @0x%016llx (%s).\n",
          pHook->Header.EptHookType == IG_EPT_HOOK_WRITE ? "Write" : "Execute",
          address, INT_SUCCESS(status) ? ksymbol : "none");

    TRACE("[LIXGUEST] Instruction:");
    IntDisasmGva(gVcpu->Regs.Rip, ND_MAX_INSTRUCTION_LENGTH);
    IntDumpArchRegs(&gVcpu->Regs);

    *Action = introGuestNotAllowed;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestAgentContentHandler(
    _In_opt_ void **Context,
    _In_ void *Hook,
    _In_ QWORD Address,
    _Out_ INTRO_ACTION *Action
    )
///
/// @brief Dumps information about the read/write attempt.
///
/// @param[in]  Context         Unused.
/// @param[in]  Hook            The #HOOK_GPA associated to this callback.
/// @param[in]  Address         The guest physical address that was accessed.
/// @param[in]  Action          Desired action (allow, block).
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    UNREFERENCED_PARAMETER(Context);
    INTSTATUS status;
    QWORD address = IntHookGetGlaFromGpaHook(Hook, Address);
    CHAR ksymbol[126] = { 0 };

    status = IntKsymFindByAddress(gVcpu->Regs.Rip, sizeof(ksymbol), ksymbol, NULL, NULL);
    TRACE("[LIXGUEST] Write/Read attempt on agent content from @0x%016llx (%s).\n",
          address, INT_SUCCESS(status) ? ksymbol : "none");

    TRACE("[LIXGUEST] Instruction:");
    IntDisasmGva(gVcpu->Regs.Rip, ND_MAX_INSTRUCTION_LENGTH);
    IntDumpArchRegs(&gVcpu->Regs);

    *Action = introGuestNotAllowed;

    return INT_STATUS_SUCCESS;
}


INTSTATUS
IntLixGuestAllocateDeploy(
    void
    )
///
/// @brief Deploys the content of Linux detours and the content of the Linux agents.
///
/// The layout of the detours header (#LIX_HYPERCALL_PAGE):
///     - Protection options:   Used to enable/disable a detour handler; contains the gGuest.Operands.Current.
///     - DetoursCount:         The number of the detours handler.
///     - Detours:              An array of #LIX_GUEST_DETOUR structures.
///     - OsSpecificFields:     The offsets used by the detours.
///
/// The layout of the #LIX_GUEST_DETOUR:
///     - Name:         The name of the hooked function.
///     - HijackName:   The name of the hijack-hooked function (see lixapi.c for more information about hijack detours).
///     - Address:      The guest virtual address of the detour's code.
///     - RelocatedCode:The guest virtual address of the detour's relocated code.
///     - JumpBack:     The guest virtual address of the original function where the detours will jump.
///     - EnableOptions:The enable-options for the current detour (e.g. #INTRO_OPT_PROT_KM_LX);
///                     Used to check if the current detour should generate an exit (if the options is set in
///                     #LIX_HYPERCALL_PAGE.ProtectionOptions).
///
/// The detour's code is located after the #LIX_HYPERCALL_PAGE.
///
/// The agents code and data is located after the detours (data and code).
///
/// NOTE: The deployed detours and agents are protected using EPT hooks. The data is protected only against write
/// (because an EPT hook against read will generate a lot of exits); the code is protected against read and write.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_NOT_SUPPORTED           If the size of detours/agents content exceed the allocated memory.
/// @retval     #INT_STATUS_INVALID_INTERNAL_STATE  If the IntKsymFindByName fails.
///
{
    INTSTATUS status;
    LIX_HYPERCALL_PAGE *pHypercallPage = (LIX_HYPERCALL_PAGE *)(gLixDetours);

    if (sizeof(*pHypercallPage) > gLixGuest->MmAlloc.Detour.Data.Length)
    {
        ERROR("[ERROR] Linux hypercall page size exceed %d bytes", gLixGuest->MmAlloc.Detour.Data.Length);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (sizeof(gLixDetours) > ((size_t)gLixGuest->MmAlloc.Detour.Code.Length + gLixGuest->MmAlloc.Detour.Data.Length))
    {
        ERROR("[ERROR] Linux detours content size exceed %d bytes", gLixGuest->MmAlloc.Detour.Data.Length);
        return INT_STATUS_NOT_SUPPORTED;
    }

    if (sizeof(gLixAgents) > gLixGuest->MmAlloc.Agent.Length)
    {
        ERROR("[ERROR] Linux agents content size exceed %d bytes", gLixGuest->MmAlloc.Detour.Data.Length);
        return INT_STATUS_NOT_SUPPORTED;
    }

    pHypercallPage->OsSpecificFields.Mm.FlagsOffset = LIX_FIELD(MmStruct, Flags);
    pHypercallPage->OsSpecificFields.Mm.ProtectionBit = 63;
    pHypercallPage->OsSpecificFields.Mm.Rb = LIX_FIELD(MmStruct, RbNode);

    pHypercallPage->OsSpecificFields.Vma.MmOffset = LIX_FIELD(Vma, Mm);
    pHypercallPage->OsSpecificFields.Vma.FlagsOffset = LIX_FIELD(Vma, Flags);
    pHypercallPage->OsSpecificFields.Vma.FileOffset = LIX_FIELD(Vma, File);
    pHypercallPage->OsSpecificFields.Vma.VmNextOffset = LIX_FIELD(Vma, VmNext);
    pHypercallPage->OsSpecificFields.Vma.VmPrevOffset = LIX_FIELD(Vma, VmPrev);
    pHypercallPage->OsSpecificFields.Vma.Rb = LIX_FIELD(Vma, RbNode);
    pHypercallPage->OsSpecificFields.Vma.ProtectionBit = 63;

    pHypercallPage->OsSpecificFields.Task.InExecve = LIX_FIELD(TaskStruct, InExecve);
    pHypercallPage->OsSpecificFields.Task.InExecveBit = LIX_FIELD(TaskStruct, InExecveBit);

    pHypercallPage->OsSpecificFields.Binprm.FileOffset = LIX_FIELD(Binprm, File);

    pHypercallPage->OsSpecificFields.File.DentryOffset = LIX_FIELD(Ungrouped, FileDentry);
    pHypercallPage->OsSpecificFields.File.PathOffset = LIX_FIELD(Ungrouped, FilePath);

    pHypercallPage->OsSpecificFields.Dentry.InodeOffset = LIX_FIELD(Dentry, Inode);

    pHypercallPage->OsSpecificFields.Inode.Mode = LIX_FIELD(Inode, Imode);
    pHypercallPage->OsSpecificFields.Inode.Uid = LIX_FIELD(Inode, Uid);
    pHypercallPage->OsSpecificFields.Inode.Gid = LIX_FIELD(Inode, Gid);

    pHypercallPage->OsSpecificFields.CurrentTaskOffset = gLixGuest->OsSpecificFields.CurrentTaskOffset;
    pHypercallPage->OsSpecificFields.CurrentCpuOffset = gLixGuest->OsSpecificFields.CurrentCpuOffset;

    pHypercallPage->OsSpecificFields.PercpuMemPtr = (void *)(gLixGuest->MmAlloc.PerCpuData.PerCpuAddress);

    pHypercallPage->OsSpecificFields.DPathFnPtr = (void *)(IntKsymFindByName("d_path", NULL));
    if (!pHypercallPage->OsSpecificFields.DPathFnPtr)
    {
        ERROR("[ERROR] IntKsymFindByName could not find 'd_path'\n");
        return INT_STATUS_INVALID_INTERNAL_STATE;
    }

    status = IntKernVirtMemWrite(gLixGuest->MmAlloc.Agent.Address, sizeof(gLixAgents), gLixAgents);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        return status;
    }

    TRACE("[LIXGUEST] Deployed agents @0x%016llx.", gLixGuest->MmAlloc.Agent.Address);

    status = IntKernVirtMemWrite(gLixGuest->MmAlloc.Detour.Data.Address, gLixGuest->MmAlloc.Detour.Data.Length, gLixDetours);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed: 0x%08x\n", status);
        return status;
    }

    TRACE("[LIXGUEST] Deployed detours data @0x%016llx.", gLixGuest->MmAlloc.Detour.Data.Address);

    status = IntMemClkCloakRegion(gLixGuest->MmAlloc.Detour.Code.Address,
                                  0,
                                  gLixGuest->MmAlloc.Detour.Code.Length,
                                  MEMCLOAK_OPT_APPLY_PATCH,
                                  NULL,
                                  gLixDetours + gLixGuest->MmAlloc.Detour.Data.Length,
                                  NULL,
                                  &gLixGuest->MmAlloc.Detour.Code.HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntMemClkCloakRegion failed for 0x%016llx (%d bytes) with status: 0x%08x\n",
              gLixGuest->MmAlloc.Detour.Code.Address, gLixGuest->MmAlloc.Detour.Code.Length, status);
        return status;
    }

    TRACE("[LIXGUEST] Deployed detours code @0x%016llx.", gLixGuest->MmAlloc.Detour.Code.Address);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestClearGuestMemory(
    _In_ QWORD Gva,
    _In_ DWORD Length
    )
///
/// @brief Clear the provided memory zone.
///
/// This function is called after the allocated guest memory zone (used for agents and detours) is freed and we want to
/// remove our data.
///
/// @param[in]  Gva     The start of the memory zone.
/// @param[in]  Length  The length of the memory zone.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
///
{
    INTSTATUS status;
    void *p;
    DWORD left = Length;
    QWORD gva = Gva;

    do
    {
        DWORD size = MIN(left, PAGE_REMAINING(Gva));

        status = IntVirtMemMap(gva, size, gGuest.Mm.SystemCr3, 0, &p);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntVirtMemMap failed for %llx: %08x\n", gva, status);
            return status;
        }

        memzero(p, size);

        IntVirtMemUnmap(&p);

        gva += size;
        left -= size;
    } while (gva < Gva + Length);

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestAllocateFill(
    void
    )
///
/// @brief Fill the required information about the allocated memory zone from the guest.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_INSUFFICIENT_RESOURCES  If the allocation fails.
///
{
    INTSTATUS status;
    IG_ARCH_REGS *pRegs = &gVcpu->Regs;
    VA_TRANSLATION translation = { 0 };

    if (pRegs->R8 == 0)
    {
        ERROR("[ERROR] Failed to allocate guest virtual space for detours. Abort...\n");
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    // The provided guest virtual address must be inside the module mapping range [ffffffffa0000000 - fffffffffeffffff].
    if (!IN_RANGE(pRegs->R8, LIX_MODULE_MAPPING_SPACE_START, LIX_MODULE_MAPPING_SPACE_END))
    {
        ERROR("[ERROR] The guest virtual address (0x%016llx) return by 'module_alloc' is not inside the module mapping "
              "region. Abort...\n", pRegs->R8);
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    gLixGuest->MmAlloc.Detour.Data.Address = pRegs->R8;
    gLixGuest->MmAlloc.Detour.Data.Length = PAGE_SIZE;
    gLixGuest->MmAlloc.PerCpuData.PerCpuAddress = pRegs->R9;

    TRACE("[LIXGUEST] Allocated guest virtual memory for detours data @ 0x%016llx (0x%x bytes)\n",
          gLixGuest->MmAlloc.Detour.Data.Address, gLixGuest->MmAlloc.Detour.Data.Length);

    gLixGuest->MmAlloc.Detour.Code.Address = pRegs->R8 + PAGE_SIZE;
    gLixGuest->MmAlloc.Detour.Code.Length = PAGE_SIZE;

    TRACE("[LIXGUEST] Allocated guest virtual memory for detours code @ 0x%016llx (0x%x bytes)\n",
          gLixGuest->MmAlloc.Detour.Code.Address, gLixGuest->MmAlloc.Detour.Code.Length);

    gLixGuest->MmAlloc.Detour.Initialized = TRUE;

    gLixGuest->MmAlloc.Agent.Address = pRegs->R8 + PAGE_SIZE * 2;
    gLixGuest->MmAlloc.Agent.Length = PAGE_SIZE;
    TRACE("[LIXGUEST] Allocated guest virtual memory for agent code @ 0x%016llx (0x%x bytes)\n",
          gLixGuest->MmAlloc.Agent.Address, gLixGuest->MmAlloc.Agent.Length);

    gLixGuest->MmAlloc.Agent.Initialized = TRUE;

    status = IntTranslateVirtualAddressEx(pRegs->R8, gGuest.Mm.SystemCr3, TRFLG_NONE, &translation);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntTranslateVirtualAddressEx failed with status: 0x%08x.\n", status);
        return status;
    }

    gLixGuest->MmAlloc.OriginalPagesAttr = translation.MappingsEntries[translation.MappingsCount - 1];

    return INT_STATUS_SUCCESS;
}


void
IntLixGuestUnhookGuestCode(
    void
    )
///
/// @brief  Remove the EPT hooks and memcloack from detours and agents.
///
{
    INTSTATUS status;

    if (gLixGuest->MmAlloc.Detour.Data.HookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLixGuest->MmAlloc.Detour.Data.HookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed with status: 0x%08x\n", status);
        }

        gLixGuest->MmAlloc.Detour.Data.HookObject = NULL;
    }

    if (gLixGuest->MmAlloc.Detour.Code.HookObject)
    {
        status = IntMemClkUncloakRegion(gLixGuest->MmAlloc.Detour.Code.HookObject, MEMCLOAK_OPT_APPLY_PATCH);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntMemClkUncloakRegion failed with status: 0x%08x\n", status);
        }

        gLixGuest->MmAlloc.Detour.Code.HookObject = NULL;
    }

    if (gLixGuest->MmAlloc.Agent.HookObject)
    {
        status = IntHookObjectDestroy((HOOK_OBJECT_DESCRIPTOR **)&gLixGuest->MmAlloc.Agent.HookObject, 0);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntHookObjectDestroy failed with status: 0x%08x\n", status);
        }

        gLixGuest->MmAlloc.Agent.HookObject = NULL;
    }
}


INTSTATUS
IntLixGuestAllocateHook(
    void
    )
///
/// @brief  Add EPT hooks for the detours and agents.
///
/// The data is protected only against write (because an EPT hook against read will generate a lot of exits); the code
/// is protected against read and write.
///
/// @retval     #INT_STATUS_SUCCESS     On success.
///
{
    INTSTATUS status = INT_STATUS_SUCCESS;

    status = IntHookObjectCreate(introObjectTypeRaw, 0, &gLixGuest->MmAlloc.Detour.Data.HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        goto _exit;
    }

    status = IntHookObjectHookRegion(gLixGuest->MmAlloc.Detour.Data.HookObject,
                                     gGuest.Mm.SystemCr3,
                                     gLixGuest->MmAlloc.Detour.Data.Address,
                                     gLixGuest->MmAlloc.Detour.Data.Length,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixGuestDetourDataHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed with status: 0x%x", status);
        goto _exit;
    }

    status = IntHookObjectHookRegion(gLixGuest->MmAlloc.Detour.Data.HookObject,
                                     gGuest.Mm.SystemCr3,
                                     gLixGuest->MmAlloc.Detour.Data.Address,
                                     gLixGuest->MmAlloc.Detour.Data.Length,
                                     IG_EPT_HOOK_EXECUTE,
                                     IntLixGuestDetourDataHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed with status: 0x%x", status);
        goto _exit;
    }

    status = IntHookObjectCreate(introObjectTypeRaw, 0, &gLixGuest->MmAlloc.Agent.HookObject);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectCreate failed: 0x%08x\n", status);
        goto _exit;
    }

    status = IntHookObjectHookRegion(gLixGuest->MmAlloc.Agent.HookObject,
                                     gGuest.Mm.SystemCr3,
                                     gLixGuest->MmAlloc.Agent.Address,
                                     gLixGuest->MmAlloc.Agent.Length,
                                     IG_EPT_HOOK_WRITE,
                                     IntLixGuestAgentContentHandler,
                                     NULL,
                                     0,
                                     NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntHookObjectHookRegion failed with status: 0x%x", status);
        goto _exit;
    }

    return INT_STATUS_SUCCESS;

_exit:
    IntLixGuestUnhookGuestCode();

    return status;
}


int
IntLixGuestGetSystemState(
    void
    )
///
/// @brief  Get the system state of the Linux guest.
///
/// This function fetches the value of the 'system_state' ksym.
///
/// @retval     On success, returns the system state value; otherwise returns -1.
///
{
    INTSTATUS status;
    static QWORD sysStateStart = 0;

    if (__unlikely(0 == sysStateStart))
    {
        sysStateStart = IntKsymFindByName("system_state", NULL);
        if (!sysStateStart)
        {
            return -1;
        }
    }

    DWORD systemState;

    // The value of the 'system_state' must be validated by the caller.
    status = IntKernVirtMemFetchDword(sysStateStart, &systemState);
    if (INT_SUCCESS(status))
    {
        return (int)systemState;
    }

    return -1;
}


BOOLEAN
IntLixGuestDeployUninitAgent(
    void
    )
///
/// @brief Inject the 'uninit' agent to free the previously allocated memory for detours/agents.
///
/// The agents argument structure is completed with the addresses of the previously allocated memory.
/// The page-attrs are also restored.
///
/// @retval     True if the agent is injected, otherwise false.
///
{
    INTSTATUS status;
    LIX_AGENT_HANDLER *pHandler;
    LIX_AGENT_UNINIT_ARGS *pArgs;

    if (!gGuest.GuestInitialized)
    {
        return FALSE;
    }

    if (!gLixGuest->MmAlloc.Agent.Initialized && !gLixGuest->MmAlloc.Detour.Initialized)
    {
        return FALSE;
    }

    // If the guest is terminating there is no reason to perform any cleanup.
    if (gGuest.Terminating || IntLixTaskGuestTerminating())
    {
        return FALSE;
    }

    if (!gLixGuest->MmAlloc.Agent.Cleared || !gLixGuest->MmAlloc.Detour.Cleared)
    {
        WARNING("[WARNING] Trying to deploy init agent without clearing the memory: %d %d\n",
                gLixGuest->MmAlloc.Agent.Cleared, gLixGuest->MmAlloc.Detour.Cleared);
    }

    pHandler = IntLixAgentGetHandlerByTag(lixAgTagUninit);
    if (pHandler == NULL)
    {
        ERROR("[ERROR] Requested to deploy the uninit agent, but none was found!\n");
        return FALSE;
    }

    pArgs = pHandler->Args.Content;
    pArgs->Free.ModuleAddress = gLixGuest->MmAlloc.Detour.Data.Address;
    pArgs->Free.PerCpuAddress = gLixGuest->MmAlloc.PerCpuData.PerCpuAddress;

    // Get the page attrs from original guest mapping entry to create a 'set mask' and a 'clear mask' to restore the
    // original attrs
    pArgs->Attr.MaskSet = gLixGuest->MmAlloc.OriginalPagesAttr & (PT_RW | PT_XD);
    pArgs->Attr.MaskClear = (gLixGuest->MmAlloc.OriginalPagesAttr & (PT_RW | PT_XD)) ^ (PT_RW | PT_XD);

    TRACE("[LIXGUEST] Change page (0x%llx) attributes: Clear -> 0x%llx Set -> 0x%llx\n",
          gLixGuest->MmAlloc.OriginalPagesAttr, pArgs->Attr.MaskClear, pArgs->Attr.MaskSet);

    LOG("[LIXGUEST] Deploy the uninit agent...\n");

    status = IntLixAgentInject(lixAgTagUninit, NULL, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentInject failed with status: 0x%08x.", status);
        return FALSE;
    }

    gLixGuest->MmAlloc.Agent.Initialized = FALSE;
    gLixGuest->MmAlloc.Detour.Initialized = FALSE;

    return TRUE;
}


static INTSTATUS
IntLixGuestAllocateInit(
    void
    )
///
/// @brief Initialize the required information about the allocated memory zone for detours/agents.
///
/// @retval     #INT_STATUS_SUCCESS On success.
///
{
    INTSTATUS status;

    status = IntLixGuestAllocateFill();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestAllocateFill failed with status: %08x\n", status);
        return status;
    }

    status = IntLixGuestAllocateHook();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestAllocateHook failed with status: %08x\n", status);
        return status;
    }

    status = IntLixGuestAllocateDeploy();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestAllocateDeploy failed with status: %08x", status);
        return status;
    }

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestInitAgentHypercall(
    _In_ void *Context
    )
///
/// @brief This callback is called when the 'init' agent has been allocated the memory zone from guest.
///
/// @param[in]  Context     Unused.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT If the guest state is not initialized.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    if (gGuest.UninitPrepared)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntPauseVcpus();

    status = IntLixGuestAllocateInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestAllocateInit failed with status: 0x%08x.", status);
        goto _exit;
    }

    IntResumeVcpus();

    return INT_STATUS_SUCCESS;

_exit:
    IntResumeVcpus();
    gGuest.DisableOnReturn = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestInitAgentCompletion(
    void *Context
    )
///
/// @brief This callback is called when the 'init' agent completed the execution and the protection can be activated.
///
/// Depending on the used core-options, this will activate the appropriate protection.
///
/// NOTE: Clear the stack to remove any addresses that may have been save by the kernel.
///
/// NOTE: The guest protection can be activate ONLY in this point because the memory zone allocated by the 'init' agent
/// doesn't have the required protection attributes (the default attributes is R/NX). The 'init' agent also changes the
/// attributes: the data pages have the NX/WR attributes, the code pages have the WR attributes.
///
/// @param[in]  Context     Unused.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_NEEDED_HINT If the guest state is not initialized.
///
{
    INTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    if (gGuest.UninitPrepared)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    IntPauseVcpus();

    // Clear the stack to remove any addresses that may have been save by the kernel
    QWORD addr = gVcpu->Regs.Rsp - 8; // Do not clear the return address
    QWORD stackBase = addr & (~((QWORD)LIX_FIELD(Info, ThreadSize) - 1));
    DWORD length = MIN(PAGE_SIZE, (DWORD)(addr - stackBase));

    status = IntVirtMemSet(addr - length, length, gGuest.Mm.SystemCr3, 0);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntVirtMemSet failed for gva 0x%016llx with status: 0x%08x\n", addr, status);
    }

    status = IntLixTaskIterateGuestTasks(IntLixTaskAdd, TRUE);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixTaskIterateGuestTasks failed, status = 0x%08x\n", status);
        goto _exit;
    }

    status = IntLixDrvIterateList(IntLixDrvCreateFromAddress, TRUE);
    if (!INT_SUCCESS(status))
    {
        if (status != INT_STATUS_NOT_INITIALIZED)
        {
            ERROR("[ERROR] IntLixDrvIterateList failed, status = 0x%08x\n", status);
        }

        IntGuestSetIntroErrorState(intErrGuestStructureNotFound, NULL);
        goto _exit;
    }

    status = IntLixApiHookAll();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixHookAll failed with status: 0x%08x", status);
        goto _exit;
    }

    status = IntLixGuestActivateProtection();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestActivateProtection failed: 0x%08x\n", status);
        goto _exit;
    }

    status = IntNotifyIntroActive();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntNotifyIntroActive failed: 0x%08x\n", status);
    }

    IntGuestSetIntroErrorState(intErrNone, NULL);

    IntResumeVcpus();

    return INT_STATUS_SUCCESS;

_exit:
    IntResumeVcpus();
    gGuest.DisableOnReturn = TRUE;

    return INT_STATUS_SUCCESS;
}


static INTSTATUS
IntLixGuestAllocate(
    void
    )
///
/// @brief Injects the 'init' agent in order to allocate a memory zone inside the guest.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_FOUND       If the agent-handler is not found.
///
{
    INTSTATUS status;

    LIX_AGENT_HANDLER *pHandler = IntLixAgentGetHandlerByTag(lixAgTagInit);
    if (pHandler == NULL)
    {
        return INT_STATUS_NOT_FOUND;
    }

    LIX_AGENT_INIT_ARGS *pArgs = pHandler->Args.Content;

    pArgs->Allocate.PerCpuLength = (QWORD)gGuest.CpuCount * PAGE_SIZE;

    status = IntLixAgentInject(lixAgTagInit, IntLixGuestInitAgentHypercall, IntLixGuestInitAgentCompletion);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixAgentInject failed with status: 0x%08x.", status);
        return status;
    }

    TRACE("[LIXGUEST] Allocation agent injected...");

    return INT_STATUS_SUCCESS;
}


void
IntLixGuestUninitGuestCode(
    void
    )
///
/// @brief Removes the EPT hooks from detours/agents memory zone and clears these memory zones.
///
{
    INTSTATUS status;

    if (!gLixGuest->MmAlloc.Agent.Initialized || gLixGuest->MmAlloc.Agent.Cleared ||
        !gLixGuest->MmAlloc.Detour.Initialized || gLixGuest->MmAlloc.Detour.Cleared)
    {
        return;
    }

    TRACE("[LIXGUEST] Clear the allocated guest memory...\n");

    status = IntLixGuestClearGuestMemory(gLixGuest->MmAlloc.Detour.Data.Address, gLixGuest->MmAlloc.Detour.Data.Length);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestClearGuestMemory failed with status: 0x%08x. (detour data)", status);
    }

    status = IntLixGuestClearGuestMemory(gLixGuest->MmAlloc.Agent.Address, gLixGuest->MmAlloc.Agent.Length);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestClearGuestMemory failed with status: 0x%08x. (agent content)", status);
    }

    IntLixGuestUnhookGuestCode();

    gLixGuest->MmAlloc.Agent.Cleared = TRUE;
    gLixGuest->MmAlloc.Detour.Cleared = TRUE;
}


INTSTATUS
IntLixGuestNew(
    void
    )
///
/// @brief  Starts the initialization and enable protection for a new Linux guest.
///
/// This function initializes the #LINUX_GUEST structure and searches for required objects: syscall, kernel sections,
/// ksyms, version. This function also calls the #IntLixGuestAllocate in order to inject the 'init' agent.
///
/// @retval     #INT_STATUS_SUCCESS         On success.
/// @retval     #INT_STATUS_NOT_SUPPORTED   If the guest doesn't have a 64 bit architecture.
///
{
    INTSTATUS status;
    QWORD originalSyscall, syscallGva, properSyscallGva, initPgd;

    if (!gGuest.Guest64)
    {
        // Just a sanity check... Theoretically syscall patterns shouldn't match, so there should be no way to
        // get here.
        return INT_STATUS_NOT_SUPPORTED;
    }

    // Uninitialize some things which may have been left here from the previous retry
    if (gLixGuest)
    {
        IntKsymUninit();

        memzero(gLixGuest, sizeof(*gLixGuest));
    }

    gLixGuest = &gGuest._LinuxGuest;

    status = IntSyscallRead(IG_CURRENT_VCPU, NULL, &syscallGva);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntSyscallRead failed: 0x%08x\n", status);
        return status;
    }

    originalSyscall = syscallGva;

    TRACE("[INTRO-INIT] Found SYSCALL handler @ %llx\n", syscallGva);

    status = IntLixGuestFindProperSyscall(syscallGva, &properSyscallGva);
    if (INT_SUCCESS(status))
    {
        syscallGva = properSyscallGva;

        TRACE("[INTRO-INIT] Found SYSCALL handler @ %llx (the proper one)", syscallGva);
    }

    status = IntLixGuestIsKptiActive(originalSyscall);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestIsKptiActive failed: 0x%08x\n", status);
        return status;
    }

    status = IntLixGuestFindKernel(syscallGva);
    if (!INT_SUCCESS(status))
    {
        WARNING("[WARNING] Failed locating the kernel image in memory starting from syscall %llx: %08X\n",
                syscallGva, status);

        IntGuestSetIntroErrorState(intErrGuestKernelNotFound, NULL);

        return status;
    }

    // Fill the guest info
    gGuest.ActiveCpuCount = gGuest.CpuCount;
    gGuest.OSType = introGuestLinux;
    gGuest.IntroActiveEventId = gEventId;

    if (!IntLixGuestIsSupported())
    {
        ERROR("[ERROR] Unsupported guest OS loaded, will NOT activate protection!\n");

        IntGuestSetIntroErrorState(intErrGuestNotSupported, NULL);

        return INT_STATUS_NOT_SUPPORTED;
    }

    gLixGuest->SyscallAddress = originalSyscall;

    status = IntLixGuestInit();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestInit failed, status = 0x%08x\n", status);
        return status;
    }

    status = IntLixGuestFindPgd(&initPgd);
    if (!INT_SUCCESS(status))
    {
        QWORD initMmGva;

        ERROR("[ERROR] IntLixGuestFindPgd failed with status: 0x%08x\n", status);

        status = IntLixMmGetInitMm(&initMmGva);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] Failed getting the init_mm: 0x%08x\n", status);
            goto _exit;
        }

        status = IntKernVirtMemFetchQword(initMmGva + LIX_FIELD(MmStruct, Pgd), &initPgd);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntKernVirtMemFetchQword failed for %llx: 0x%08x\n",
                  initMmGva + LIX_FIELD(MmStruct, Pgd), status);
            goto _exit;
        }
    }

    status = IntTranslateVirtualAddress(initPgd, 0, &gGuest.Mm.SystemCr3);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] Translating init PGD failed, status = 0x%08x\n", status);
        goto _exit;
    }

    TRACE("[INTRO-INIT] Found SystemCr3 @ %llx\n", gGuest.Mm.SystemCr3);

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        QWORD idtBase;
        WORD idtLimit;

        status = IntIdtFindBase(i, &idtBase, &idtLimit);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] CPU %d doesn't appear to be used, skipping IDT...\n", i);
            continue;
        }

        gGuest.VcpuArray[i].IdtBase = idtBase;
        gGuest.VcpuArray[i].IdtLimit = idtLimit;
    }

    IntLixAgentInit();

    IntLixAgentEnableInjection();

    status = IntLixGuestAllocate();
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntLixGuestAllocate failed with status: 0x%08x.", status);
        goto _exit;
    }

    IntNotifyIntroDetectedOs(gGuest.OSType, gGuest.OSVersion, gGuest.Guest64);

    status = INT_STATUS_SUCCESS;

_exit:
    if (!INT_SUCCESS(status))
    {
        IntLixAgentDisablePendingAgents();

        gGuest.GuestInitialized = FALSE;
    }

    return status;
}


INTSTATUS
IntGetVersionStringLinux(
    _In_  DWORD FullStringSize,
    _In_  DWORD VersionStringSize,
    _Out_ CHAR *FullString,
    _Out_ CHAR *VersionString
    )
///
/// @brief  Gets the version string for a Linux guest.
///
/// @param[in]  FullStringSize              The size of the FullString buffer.
/// @param[in]  VersionStringSize           The size of the VersionString buffer.
/// @param[out] FullString                  A NULL-terminated string containing detailed version information.
/// @param[out] VersionString               A NULL-terminated string containing human-readable version information.
///
/// @retval     #INT_STATUS_SUCCESS                 On success.
/// @retval     #INT_STATUS_DATA_BUFFER_TOO_SMALL   If the version string length exceed the provided FullStringSize
///                                                 length.
/// @retval     #INT_STATUS_INVALID_DATA_VALUE      If the version string is invalid.
///
{
    DWORD startOfDistroName = 0;
    int count = 0;
    DWORD endOfDistroName = 0;
    DWORD sizeOfString;

    // OK to type cast to DWORD here, the internal VersionString won't exceed 2G...
    sizeOfString = (DWORD)strlen(gLixGuest->VersionString);

    if (sizeOfString >= FullStringSize)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    while (startOfDistroName < sizeOfString && count != 3)
    {
        if (gLixGuest->VersionString[startOfDistroName] == '(')
        {
            ++count;
        }

        ++startOfDistroName;
    }

    if (count < 3)
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    if (startOfDistroName >= sizeOfString)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    endOfDistroName = startOfDistroName;
    while (endOfDistroName < sizeOfString &&
           (IN_RANGE_INCLUSIVE(gLixGuest->VersionString[endOfDistroName], 'a', 'z') ||
            IN_RANGE_INCLUSIVE(gLixGuest->VersionString[endOfDistroName], 'A', 'Z') ||
            gLixGuest->VersionString[endOfDistroName] == ' '))
    {
        endOfDistroName += 1;
    }

    if (endOfDistroName >= sizeOfString)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    strcpy(FullString, gLixGuest->VersionString);

    count = snprintf(VersionString, VersionStringSize, "Kernel: %d.%d.%d-%d distro: ",
                     gLixGuest->Version.Version,
                     gLixGuest->Version.Patch,
                     gLixGuest->Version.Sublevel,
                     gLixGuest->Version.Backport);
    if (count < 0)
    {
        return INT_STATUS_INVALID_DATA_VALUE;
    }

    if ((DWORD)count >= VersionStringSize)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    if (gLixGuest->VersionString[endOfDistroName] == ')')
    {
        ++endOfDistroName;
    }

    if (endOfDistroName - startOfDistroName >= VersionStringSize - count)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    // Oracle linux has a kernel identically with Red Hat one, so the only special identification is the
    // "el7uek" string in the version
    if (strstr(FullString, "el7uek"))
    {
        snprintf(VersionString + count, sizeof("Oracle"), "%s", "Oracle");
    }
    else
    {
        snprintf(VersionString + count, endOfDistroName - startOfDistroName, "%s", FullString + startOfDistroName);
    }

    return INT_STATUS_SUCCESS;
}

