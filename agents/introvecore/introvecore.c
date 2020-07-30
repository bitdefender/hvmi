/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vetypes.h"
#include "hviface.h"
#include "cpu.h"
#include "asmlib.h"

// The #VE info pages and the #VE stacks will be allocated in sepparate sections.
#pragma section("VEINFO", read,write,nopage)
#pragma section("VESTACKS", read,write,nopage)

// The #VE info pages will be a contiguous 64 pages inside the driver.
__declspec(allocate("VEINFO"))
VECPU_PAGE VeCoreVePages[MAX_CPU_COUNT];

// The stacks; 2 pages for each CPU.
__declspec(allocate("VESTACKS"))
VE_STACK VeCoreVeStacks[MAX_CPU_COUNT];


// nd_vsnprintf_s
// This function must be implemented as the disassembler makes use if it. Since Napoca also uses the disassembler,
// it will also define this function; therefore, we only need to implement it in introcore when building for Xen or for
// vecore.
int
nd_vsnprintf_s(char *str, unsigned long long sizeOfBuffer, unsigned long long count, const char *format, ...)
{
    UNREFERENCED_PARAMETER(str);
    UNREFERENCED_PARAMETER(sizeOfBuffer);
    UNREFERENCED_PARAMETER(count);
    UNREFERENCED_PARAMETER(format);

    return -1;
}


void *memset(void *, int, size_t);
#pragma function(memset)
void *
nd_memset(void *s, int c, size_t n)
{
    // The compiler will happily replace any loop that looks like memset with a call to memset,
    // but the linker won't find any
    __stosb(s, c, n);
    return s;
}


//
// DllInitialize
//
VESTATUS
DllInitialize(
    void *RegistryPath
    )
{
    UNREFERENCED_PARAMETER(RegistryPath);

    return VE_STATUS_SUCCESS;
}


//
// DllUnload
//
VESTATUS
DllUnload(
    void
    )
{
    return VE_STATUS_SUCCESS;
}
