/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "rtlpvirtualunwind.h"
#include "guests.h"
#include "introcpu.h"


BOOLEAN gRipInsideRtlpVirtualUnwindReloc;


INTSTATUS
IntRtlpVirtualUnwindCheckAccess(
    void
    )
///
/// @brief Check if a memory read operation was issued by RtlpVirtualUnwind or friends and update the cache.
///
/// Sometimes, on Windows 7 especially, the RtlpVirtualUnwind family of functions may read code from a page that
/// has been read hooked via EPT (because we have API hooks inside it). This code usually scans the code
/// page for specific opcodes (for example, 0x48 REX prefix). In order to avoid all of these reads, we will detour
/// all the code regions that we know read the code page, and we will place a handler for them inside the NT
/// slack space. This handler is simply a cache, and it will compare the address of the read, and if a match
/// is found, it will load an immediate, instead of accessing the memory. Whenever a new read fault takes place,
/// we will update the cache.
/// Therefore, multiple reads from these functions, which touch the same addresses, will not cause an EPT
/// violation anymore, since the detour handler would compare that value as an immediate.
/// Example of instrumentation:
/// Consider instruction "mov     al, [rcx]" inside the NT!RtlpVirtualUnwind. This instruction may trigger lots
/// of EPT read violations, so we instrument it as follows:
/// 1. We replace it with a "JMP" to our detour handler
/// 2. Our detour handler looks like this:
///     cli
/// entry0:
///     mov al, value0
///     cmp ecx, address0
///     jz match
/// entry1:
///     mov al, value1
///     cmp ecx, address1
///     jz match
///     ...
/// entryk:
///     mov al, valuek
///     cmp ecx, addressk
///     jmp match
///     ...
///     mov al, [rcx]
/// match:
///     sti
///     jmp original_code
/// 3. When the handler is first hit, there will be no matches, so the original instruction "mov al, [rcx]" will
///    be executed, which will generate an EPT violation.
/// 4. When such a read EPT violation takes place, this function will randomly select an entry inside the handler
///    and store the value at [rcx] inside al (valuek) and the low 32 bits from the kernel address in ecx
///    (addressk - note that this is ok, since we only instrument NT sequences).
/// NOTE: These sequences of instructions are instrumented during init, they are not hooked dynamically; however,
/// the handler code (the cache) is dynamically updated whenever a read takes place that did not match the cache.
/// NOTE: Only several instructions are instrumented using this algorithm. Please take a look at the switch tag
/// statement, as each block is made for a particular instruction.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_NOT_NEEDED_HINT If the instruction needs not be inspected.
///
{
    INTSTATUS status;
    QWORD detourAddr, readAddr, byteAddr, cmpAddr, cmpValue;
    DWORD size;
    DETOUR_TAG tag;
    BYTE byteValue;
    QWORD e;

    if (gGuest.OSType != introGuestWindows || !gGuest.Guest64 || gGuest.OSVersion >= 8000)
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // Ignore anything coming outside the kernel image. This happens when PatchGuard triggers read faults. Also, ignore
    // reads that don't hit inside the kernel image.
    if ((gVcpu->Regs.Rip < gGuest.KernelVa || gVcpu->Regs.Rip >= gGuest.KernelVa + gGuest.KernelSize) ||
        (gVcpu->Gla < gGuest.KernelVa || gVcpu->Gla >= gGuest.KernelVa + gGuest.KernelSize))
    {
        return INT_STATUS_NOT_NEEDED_HINT;
    }

    // If the read didn't came from one of our handlers, bail out.
    status = IntDetGetAddrAndTag(gVcpu->Regs.Rip, &detourAddr, &size, &tag);
    if (!INT_SUCCESS(status))
    {
        return status;
    }


    // NOTE: It's perfectly safe to compare only the low 32 bit of the base register, since we restrict this
    // optimization for the kernel image only.

    switch (tag)
    {
    case detTagRtlVirtualUnwind1:
        // mov     al, [rcx]
        e = __rdtsc() % 12;
        readAddr = gVcpu->Regs.Rcx;
        cmpValue = gVcpu->Regs.Rcx;
        byteAddr = detourAddr + 1 + (e * 10) + 1;
        cmpAddr = detourAddr + 1 + (e * 10) + 4;
        break;

    case detTagRtlVirtualUnwind2:
        // mov     al, [rcx+1]
        e = __rdtsc() % 12;
        readAddr = gVcpu->Regs.Rcx + 1;
        cmpValue = gVcpu->Regs.Rcx;
        byteAddr = detourAddr + 1 + (e * 10ull) + 1;
        cmpAddr = detourAddr + 1 + (e * 10ull) + 4;
        break;

    case detTagRtlVirtualUnwind3:
        // mov     dl, [rcx]
        e = __rdtsc() % 12;
        readAddr = gVcpu->Regs.Rcx;
        cmpValue = gVcpu->Regs.Rcx;
        byteAddr = detourAddr + 1 + (e * 10ull) + 1;
        cmpAddr = detourAddr + 1 + (e * 10ull) + 4;
        break;

    case detTagRtlVirtualUnwind4:
        // mov     al, [rbp+1]
        e = __rdtsc() % 12;
        readAddr = gVcpu->Regs.Rbp + 1;
        cmpValue = gVcpu->Regs.Rbp;
        byteAddr = detourAddr + 1 + (e * 10) + 1;
        cmpAddr = detourAddr + 1 + (e * 10) + 4;
        break;

    case detTagRtlVirtualUnwind5:
        // cmp     byte ptr[rbp + 0], 48h
        e = __rdtsc() % 8;
        readAddr = gVcpu->Regs.Rbp;
        cmpValue = gVcpu->Regs.Rbp;
        byteAddr = detourAddr + 2 + (e * 16) + 9;
        cmpAddr = detourAddr + 2 + (e * 16) + 2;
        break;

    case detTagRtlVirtualUnwind6:
        // mov     al, [rbp + 0]
        e = __rdtsc() % 12;
        readAddr = gVcpu->Regs.Rbp;
        cmpValue = gVcpu->Regs.Rbp;
        byteAddr = detourAddr + 1 + (e * 10) + 1;
        cmpAddr = detourAddr + 1 + (e * 10) + 4;
        break;

    case detTagRtlVirtualUnwind7:
        // cmp     byte ptr[rbp + 1], 8Dh
        e = __rdtsc() % 8;
        readAddr = gVcpu->Regs.Rbp + 1;
        cmpValue = gVcpu->Regs.Rbp;
        byteAddr = detourAddr + 2 + (e * 16) + 9;
        cmpAddr = detourAddr + 2 + (e * 16) + 2;
        break;

    case detTagRtlVirtualUnwind8:
        // cmp     byte ptr[rcx + 1], 0FFh
        e = __rdtsc() % 8;
        readAddr = gVcpu->Regs.Rcx + 1;
        cmpValue = gVcpu->Regs.Rcx;
        byteAddr = detourAddr + 2 + (e * 16) + 9;
        cmpAddr = detourAddr + 2 + (e * 16) + 2;
        break;

    default:
        return INT_STATUS_NOT_FOUND;
    }

    IntPauseVcpus();

    gRipInsideRtlpVirtualUnwindReloc = FALSE;

    for (DWORD i = 0; i < gGuest.CpuCount; i++)
    {
        QWORD rip;

        // Ignore the current VCPU, since it obviously points inside a handler.
        if (gVcpu->Index == i)
        {
            continue;
        }

        status = IntRipRead(i, &rip);
        if (!INT_SUCCESS(status))
        {
            ERROR("[ERROR] IntRipRead failed: 0x%08x\n", status);
            continue;
        }

        if (rip >= detourAddr && rip < detourAddr + size)
        {
            gRipInsideRtlpVirtualUnwindReloc = TRUE;
        }
    }

    if (gRipInsideRtlpVirtualUnwindReloc)
    {
        TRACE("[RTLPVIRTUALUNWIND] A rip seems to be inside our relocs, bailing out for now...\n");
        status = INT_STATUS_NOT_NEEDED_HINT;
        goto resume_and_exit;
    }

    // Read the byte value.
    status = IntKernVirtMemRead(readAddr, 1, &byteValue, NULL);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemRead failed for %llx: 0x%08x\n", readAddr, status);
        goto resume_and_exit;
    }

    // Patch the immediate in the instruction.
    status = IntKernVirtMemWrite(byteAddr, 1, &byteValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed for %llx: 0x%08x\n", byteAddr, status);
        goto resume_and_exit;
    }

    // Patch the accessed target address.
    status = IntKernVirtMemWrite(cmpAddr, 4, &cmpValue);
    if (!INT_SUCCESS(status))
    {
        ERROR("[ERROR] IntKernVirtMemWrite failed for %llx: 0x%08x\n", cmpAddr, status);
        goto resume_and_exit;
    }

    status = INT_STATUS_SUCCESS;

    TRACE("[RTLPVIRTUALUNWIND] Successfully patched detour with tag %d, entry %llu, IF = %d\n",
          tag - detTagRtlVirtualUnwind1, e, (gVcpu->Regs.Flags & NDR_RFLAG_IF) ? 1 : 0);

resume_and_exit:
    IntResumeVcpus();

    return status;
}
