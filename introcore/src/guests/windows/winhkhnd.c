/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
///
/// @file       winhkhnd.c
/// @ingroup    group_detours
/// @brief      Windows detour descriptors
///
/// This file contains the descriptors for all the detours introcore will set on Windows kernel functions.
///
/// Each descriptor is a #API_HOOK_DESCRIPTOR structure and contains the information needed in order to properly
/// set the hook.
///
/// If a detour uses the hypercall type #hypercallTypeInt3 it must have a INT3 instruction (0xCC) in its handler
/// and set #API_HOOK_HANDLER.HypercallOffset to the offset at which the INT3 is found.
/// If a detour uses the hypercall type #hypercallTypeVmcall it must have a VMCALL instruction (0x0F 0x01 0xC1) and
/// set #API_HOOK_HANDLER.HypercallOffset to the offset at which the VMCALL is found. In addition to this, the handler
/// must set RAX = 34, RDI = 24, RSI = 0 for 64-bit guests and EAX = 34, EBX = 24, ECX = 0 for 32-bit guests,
/// otherwise the VMCALL may not be recognized by the hypervisor (Xen will inject a general protection fault inside
/// the guest, for example).
/// Usually, there is no reason to use VMCALL as the hypercall for a function detour and INT3 is recommended.
///
/// Check the documentation of individual detour handlers for details about those.
///
/// Convention for documenting the assembly code:
/// 1. Each instruction will be placed on a separate line;
/// 2. Each instruction will be preceded by a line comment using the following template:
///     "// 0x00: MOV      eax, ebx     ; Additional information"
///     * The instruction offset inside the handler, hex format, two digits;
///     * The mneomonic;
///     * Operands;
///     * Comments (optional);
/// 3. Labels will be placed above the referencing instruction, with an underscore and ending in :
///     "// _label:"
/// 4. Detailed descriptions can be placed before the instruction line comment
/// Example:
///     // This is just a NOP.
///     // _label:
///     // 0x20  nop
///     0x90,
/// 5. Relative addressing should reference the destination instruction offset, not a label:
///    "// 0x20: JMP        0x22"
///    0xEB, 0x00,
///    "// 0x22: ..."
///

#include "introcore.h"
#include "winbugcheck.h"
#include "winpool.h"
#include "winpower.h"
#include "winthread.h"
#include "winumcrash.h"
#include "winvad.h"
#include "drivers.h"

///
/// @brief  The functions to be hooked for 32-bit Windows guests.
///
API_HOOK_DESCRIPTOR gHookableApisX86[]
__section(".detours") =
{
    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "ExAllocatePoolWithTag",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinPoolHandleAlloc,
        .Tag           = detTagPoolAlloc,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3c,
                .Code =
                {
                    // 0x00: CMP       dword ptr [esp+0xc], 0xf6697244
                    0x81, 0x7C, 0x24, 0x0c, 0x44, 0x72, 0x69, 0xF6,
                    // 0x08: JZ        0x34
                    0x74, 0x2a,
                    // 0x0A: CMP       dword ptr [esp+0xc], 0x76697244
                    0x81, 0x7C, 0x24, 0x0c, 0x44, 0x72, 0x69, 0x76,
                    // 0x12: JZ        0x34
                    0x74, 0x20,
                    // 0x14: CMP       dword ptr [esp+0xc], 0x69664d46
                    0x81, 0x7C, 0x24, 0x0c, 0x46, 0x4D, 0x66, 0x69,
                    // 0x1C: JZ        0x34
                    0x74, 0x16,
                    // 0x1E: CMP       dword ptr [esp+0xc], 0x656b6f54
                    0x81, 0x7C, 0x24, 0x0c, 0x54, 0x6f, 0x6b, 0x65,
                    // 0x26: JZ        0x34
                    0x74, 0x0C,
                    // 0x28: CMP       dword ptr [esp+0xc], 0xe56b6f54
                    0x81, 0x7C, 0x24, 0x0c, 0x54, 0x6f, 0x6b, 0xe5,
                    // 0x30: JZ        0x34
                    0x74, 0x02,
                    // 0x32: JMP       0x37
                    0xEB, 0x03,
                    // 0x34: INT3
                    0xCC,
                    // 0x35: NOP
                    0x90,
                    // 0x36: NOP
                    0x90,
                    // 0x37: JMP       0x3c
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x34,
                .RelocatedCodeOffset    = 0x37,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "ExFreePoolWithTag",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinPoolHandleFree,
        .Tag           = detTagPoolFree,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x28,
                .Code =
                {
                    // 0x00: CMP       dword ptr [esp+0x8], 0xf6697244
                    0x81, 0x7C, 0x24, 0x08, 0x44, 0x72, 0x69, 0xF6,
                    // 0x08: JZ        0x20
                    0x74, 0x16,
                    // 0x0A: CMP       dword ptr [esp+0x8], 0x76697244
                    0x81, 0x7C, 0x24, 0x08, 0x44, 0x72, 0x69, 0x76,
                    // 0x12: JZ        0x20
                    0x74, 0x0C,
                    // 0x14: CMP       dword ptr [esp+0x8], 0x69664d46
                    0x81, 0x7C, 0x24, 0x08, 0x46, 0x4D, 0x66, 0x69,
                    // 0x1C: JZ        0x20
                    0x74, 0x02,
                    // 0x1E: JMP       0x23
                    0xEB, 0x03,
                    // 0x20: INT3
                    0xCC,
                    // 0x21: NOP
                    0x90,
                    // 0x22: NOP
                    0x90,
                    // 0x23: JMP       0x28
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset         = 0x20,
                .RelocatedCodeOffset     = 0x23,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "KeBugCheck2",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinBcHandleBugCheck,
        .Tag           = detTagBugcheck,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_BUGCHECK_CLEANUP | INTRO_OPT_EVENT_OS_CRASH,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiProcessLoaderEntry",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntDriverLoadHandler,
        .Tag           = detTagModuleLoad,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiUnloadSystemImage",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntDriverUnloadHandler,
        .Tag           = detTagModuleUnload,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "PspInsertProcess",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .PreCallback   = IntWinProcPatchPspInsertProcess86,
        .Callback      = IntWinProcHandleCreate,
        .Tag           = detTagProcCreate,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x10,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: JMP       0xb
                    0xEB, 0x08,
                    // If we want to block a process, we increment the RIP from IntWinProcHandleCreate
                    // so that it points here.
                    // 0x03: MOV       eax, 0xc0000022
                    0xB8, 0x22, 0x00, 0x00, 0xC0,
                    // 0x08: RETN      0x0018
                    0xC2, 0x18, 0x00,
                    // <call PspInsertProcess>
                    // 0x0B: JMP       0x10
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x00,
                .RelocatedCodeOffset    = 0x0B,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MmCleanProcessAddressSpace",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleTerminate,
        .Tag           = detTagProcTerminate,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },


    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MmCopyVirtualMemory",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleCopyMemory,
        .PreCallback   = IntWinProcPatchCopyMemoryDetour,
        .Tag           = detTagProcInject,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x55,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ebx
                    0x53,
                    // 0x02: PUSH      ecx
                    0x51,
                    // 0x03: MOV       eax, dword ptr [esp+0x10]
                    0x8b, 0x44, 0x24, 0x10,
                    // 0x07: MOV       ebx, dword ptr [esp+0x18]
                    0x8b, 0x5c, 0x24, 0x18,
                    // 0x0B: CMP       eax, ebx
                    0x39, 0xd8,
                    // 0x0D: JZ        0x4d
                    0x74, 0x3e,
                    // 0x0F: MOV       ecx, cr3
                    0x0f, 0x20, 0xd9,
                    // 0x12: CMP       ecx, dword ptr [ebx+0x0]
                    0x3b, 0x8b, 0x00, 0x00, 0x00, 0x00,
                    // 0x18: JZ        0x2d
                    0x74, 0x13,
                    // is_write:
                    // 0x1A: MOV       ebx, dword ptr [ebx+0x0]
                    0x8b, 0x9b, 0x00, 0x00, 0x00, 0x00,
                    // 0x20: CMP       bl, 0x2a
                    0x80, 0xfb, 0x2a,
                    // 0x23: JNZ       0x4d
                    0x75, 0x28,
                    // 0x25: BT        ebx, 0x09
                    0x0f, 0xba, 0xe3, 0x09,
                    // 0x29: JNC       0x4d
                    0x73, 0x22,
                    // 0x2B: JMP       0x3d
                    0xeb, 0x10,
                    // _is_read:
                    // 0x2D: MOV       eax, dword ptr [eax+0x0]
                    0x8b, 0x80, 0x00, 0x00, 0x00, 0x00,
                    // 0x33: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x35: JNZ       0x4d
                    0x75, 0x16,
                    // 0x37: BT        eax, 0x0a
                    0x0f, 0xba, 0xe0, 0x0a,
                    // 0x3B: JNC       0x4d
                    0x73, 0x10,
                    // _do_int3:
                    // 0x3D: INT3
                    0xcc,
                    // 0x3E: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x43: JNZ       0x4d
                    0x75, 0x08,
                    // 0x45: POP       ecx
                    0x59,
                    // 0x46: POP       ebx
                    0x5b,
                    // 0x47: ADD       esp, 0x04
                    0x83, 0xc4, 0x04,
                    // 0x4A: RETN      0x001c
                    0xc2, 0x1c, 0x00,
                    // _continue_function:
                    // 0x4D: POP       ecx
                    0x59,
                    // 0x4E: POP       ebx
                    0x5b,
                    // 0x4F: POP       eax
                    0x58,
                    // _leave:
                    // 0x50: JMP       0x55
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x3d,
                .RelocatedCodeOffset    = 0x50,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "NtSetInformationProcess",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleInstrument,
        .PreCallback   = IntWinProcPrepareInstrument,
        .Tag           = detTagSetProcInformation,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x7f,
                .Code =
                {
                    // 0x00: cmp    DWORD PTR [esp+0x8],0x28
                    0x83, 0x7c, 0x24, 0x08, 0x28,
                    // 0x05: jne    0x7a <_irelevant>
                    0x75, 0x73,
                    // 0x07: push   eax
                    0x50,
                    // 0x08: push   ecx
                    0x51,
                    // 0x09: push   edx
                    0x52,
                    // 0x0a: mov    ecx,DWORD PTR [esp+0x10]
                    0x8b, 0x4c, 0x24, 0x10,
                    // 0x0e: sub    esp,0x10
                    0x83, 0xec, 0x10,
                    // Save everything early on the stack in the location where intro expects them
                    // 0x11: mov    eax,DWORD PTR [esp+0x24]
                    0x8b, 0x44, 0x24, 0x24,
                    // 0x15: mov    DWORD PTR [esp+0x8],eax
                    0x89, 0x44, 0x24, 0x08,
                    // 0x19: mov    eax,DWORD PTR [esp+0x28]
                    0x8b, 0x44, 0x24, 0x28,
                    // 0x1d: mov    DWORD PTR [esp+0xc],eax
                    0x89, 0x44, 0x24, 0x0c,
                    // 0x21: lea    eax,[esp+0x4]
                    0x8d, 0x44, 0x24, 0x04,
                    // 0x25: mov    DWORD PTR [esp+0x4],0x0
                    0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
                    // 0x2d: push   0x0
                    0x6a, 0x00,
                    // 0x2f: push   eax
                    0x50,
                    // 0x30: push   0x1
                    0x6a, 0x01,
                    // PsProcessType
                    // 0x32: push   DWORD PTR ds:0xfffff800
                    0xff, 0x35, 0x00, 0xf8, 0xff, 0xff,
                    // 0x38: push   0x10
                    0x6a, 0x10,
                    // 0x3a: push   ecx
                    0x51,
                    // ObReferenceObjectByHandle
                    // 0x3b: mov    eax,0xfffff800
                    0xb8, 0x00, 0xf8, 0xff, 0xff,
                    // 0x40: call   eax
                    0xff, 0xd0,
                    // 0x42: test   eax,eax
                    0x85, 0xc0,
                    // 0x44: jne    0x67 <_exit>
                    0x75, 0x21,
                    // 0x46: mov    ecx,DWORD PTR [esp+0x4]
                    0x8b, 0x4c, 0x24, 0x04,
                    // This offset will be patched by intro with the offset of `_EPROCESS.Spare`
                    // 0x4a: mov    eax,DWORD PTR [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x50: cmp    al,0x2a
                    0x3c, 0x2a,
                    // 0x52: bt     eax,0xd
                    0x0f, 0xba, 0xe0, 0x0d,
                    // 0x56: jne    5d <_dereference_and_exit>
                    0x75, 0x05,
                    // 0x58: jae    5d <_dereference_and_exit>
                    0x73, 0x03,
                                        
                    // 0x5a <_hypercall>:
                    // 0x5a: int3
                    0xcc,
                    // 0x5b: nop
                    0x90,
                    // 0x5c: nop
                    0x90,
                                        
                    // 0x5d <_dereference_and_exit>:
                    // 0x5d: push   eax
                    0x50,
                    // 0x5e: push   ecx
                    0x51,
                    // ObDereferenceObject
                    // 0x5f: mov    eax,0xfffff800
                    0xb8, 0x00, 0xf8, 0xff, 0xff,
                    // 0x64: call   eax
                    0xff, 0xd0,
                    // 0x66: pop    eax
                    0x58,
                                        
                    // 0x67 <_exit>:
                    // 0x67: add    esp,0x10
                    0x83, 0xc4, 0x10,
                    // 0x6a: pop    edx
                    0x5a,
                    // 0x6b: pop    ecx
                    0x59,
                    // 0x6c: cmp    eax,0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x71: jne    0x79 <_allow>
                    0x75, 0x06,
                    // 0x73: add    esp,0x4
                    0x83, 0xc4, 0x04,
                    // 0x76: ret    0x10
                    0xc2, 0x10, 0x00,
                                        
                    // 0x79 <_allow>:
                    // 0x79: pop    eax
                    0x58,
                                        
                    // 0x7a <_irelevant>:
                    // 0x7a: jmp    0x74 <_irelevant+0x1>
                    0xe9, 0xfc, 0xff, 0xff, 0xff,

                },
                .HypercallOffset        = 0x5a,
                .RelocatedCodeOffset    = 0x7a,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "NtQueueApcThreadEx",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinThrHandleQueueApc,
        .PreCallback   = IntWinThrPrepareApcHandler,
        .Tag           = detTagProcQueueApc,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x89,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ecx
                    0x51,
                    // 0x02: PUSH      edx
                    0x52,
                    // 0x03: MOV       ecx, dword ptr [esp+0x10]
                    0x8b, 0x4c, 0x24, 0x10,
                    // 0x07: SUB       esp, 0x10
                    0x83, 0xec, 0x10,
                    // 0x0A: LEA       eax, [esp+0x4]
                    0x8d, 0x44, 0x24, 0x04,
                    // 0x0E: MOV       dword ptr [esp+0x4], 0x00000000
                    0xc7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
                    // 0x16: PUSH      0x00
                    0x6a, 0x00,
                    // 0x18: PUSH      eax
                    0x50,
                    // 0x19: PUSH      0x01
                    0x6a, 0x01,
                    // 0x1B: PUSH      dword ptr [0xfffff800]
                    0xff, 0x35, 0x00, 0xf8, 0xff, 0xff,
                    // PsThreadType
                    // 0x21: PUSH      0x10
                    0x6a, 0x10,
                    // 0x23: PUSH      ecx
                    0x51,
                    // 0x24: MOV       eax, 0xfffff800
                    0xb8, 0x00, 0xf8, 0xff, 0xff,
                    // ObReferenceObjectByHandle
                    // 0x29: CALL      eax
                    0xff, 0xd0,
                    // 0x2B: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x2D: JNZ       0x71
                    0x75, 0x42,
                    // 0x2F: MOV       ecx, dword ptr [esp+0x4]
                    0x8b, 0x4c, 0x24, 0x04,
                    // Victim thread obj
                    // 0x33: MOV       eax, dword ptr [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // AttachedProcess
                    // 0x39: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x3B: JNZ       0x43
                    0x75, 0x06,
                    // 0x3D: MOV       eax, dword ptr [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // _attached:
                    // 0x43: MOV       eax, dword ptr [eax+0x150]
                    0x8b, 0x80, 0x50, 0x01, 0x00, 0x00,
                    // ImageFileName
                    // 0x49: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // Check for '*' in process name
                    // 0x4B: BT        eax, 0x0c
                    0x0f, 0xba, 0xe0, 0x0c,
                    // Check QueueApc protection flag
                    // 0x4F: MOV       eax, 0x00000000
                    0xb8, 0x00, 0x00, 0x00, 0x00,
                    // 0x54: JNZ       0x61
                    0x75, 0x0b,
                    // 0x56: JNC       0x61
                    0x73, 0x09,
                    // 0x58: MOV       eax, dword ptr fs:[0x124]
                    0x64, 0xa1, 0x24, 0x01, 0x00, 0x00,
                    // 0x5E: INT3
                    0xcc,
                    // 0x5F: NOP
                    0x90,
                    // 0x60: NOP
                    0x90,
                    // _skip_exit:
                    // 0x61: MOV       dword ptr [esp+0x8], eax
                    0x89, 0x44, 0x24, 0x08,
                    // 0x65: PUSH      ecx
                    0x51,
                    // 0x66: MOV       eax, 0xfffff800
                    0xb8, 0x00, 0xf8, 0xff, 0xff,
                    // ObDereferenceObject
                    // 0x6B: CALL      eax
                    0xff, 0xd0,
                    // 0x6D: MOV       eax, dword ptr [esp+0x8]
                    0x8b, 0x44, 0x24, 0x08,
                    // _cleanup_and_exit:
                    // 0x71: ADD       esp, 0x10
                    0x83, 0xc4, 0x10,
                    // 0x74: POP       edx
                    0x5a,
                    // 0x75: POP       ecx
                    0x59,
                    // 0x76: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x7B: JNZ       0x83
                    0x75, 0x06,
                    // 0x7D: ADD       esp, 0x04
                    0x83, 0xc4, 0x04,
                    // 0x80: RETN      0x0018
                    0xc2, 0x18, 0x00,
                    // _skip:
                    // 0x83: POP       eax
                    0x58,
                    // 0x84: JMP       0x85
                    0xe9, 0xfc, 0xff, 0xff, 0xff,
                },
                .HypercallOffset        = 0x5e,
                .RelocatedCodeOffset    = 0x84,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "PspSetContextThreadInternal",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinThrHandleThreadHijack,
        .PreCallback   = IntWinThrPatchThreadHijackHandler,
        .Tag           = detTagProcThrHijack,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion = DETOUR_MIN_VERSION_ANY,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x4a,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ecx
                    0x51,
                    // 0x02: MOV       ecx, dword ptr [esp+0xc]
                    0x8b, 0x4c, 0x24, 0x0c,
                    // 0x06: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x0C: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x0E: JNZ       0x16
                    0x75, 0x06,
                    // 0x10: MOV       eax, dword ptr [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // _attached:
                    // 0x16: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x1C: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x1E: BT        eax, 0x0b
                    0x0f, 0xba, 0xe0, 0x0b,
                    // 0x22: JNZ       0x43
                    0x75, 0x1f,
                    // 0x24: JNC       0x43
                    0x73, 0x1d,
                    // 0x26: MOV       eax, dword ptr fs:[0x124]
                    0x64, 0xa1, 0x24, 0x01, 0x00, 0x00,
                    // 0x2C: CMP       eax, dword ptr [esp+0xc]
                    0x3b, 0x44, 0x24, 0x0c,
                    // 0x30: JZ        0x43
                    0x74, 0x11,
                    // 0x32: INT3
                    0xcc,
                    // 0x33: NOP
                    0x90,
                    // 0x34: NOP
                    0x90,
                    // 0x35: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x3A: JNZ       0x43
                    0x75, 0x07,
                    // 0x3C: POP       ecx
                    0x59,
                    // 0x3D: ADD       esp, 0x04
                    0x83, 0xc4, 0x04,
                    // 0x40: RETN      0x0000
                    0xc2, 0x00, 0x00,
                    // <skip>:
                    // 0x43: POP       ecx
                    0x59,
                    // 0x44: POP       eax
                    0x58,
                    // 0x45: JMP       0x4a
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x32,
                .RelocatedCodeOffset    = 0x45,
            },
        }

    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "KiDispatchException",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinHandleException,
        .Tag           = detTagException,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_EVENT_PROCESS_CRASH,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x0F,
                .Code =
                {
                    // 0x00: CMP       dword ptr [esp+0x10], 0x01
                    0x83, 0x7C, 0x24, 0x10, 0x01,
                    // 0x05: JNZ       0xa
                    0x75, 0x03,
                    // 0x07: INT3
                    0xCC,
                    // 0x08: NOP
                    0x90,
                    // 0x09: NOP
                    0x90,
                    // 0x0A: JMP       0xf
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x07,
                .RelocatedCodeOffset    = 0x0A,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiInsertPrivateVad",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 18362,
        .Callback      = IntWinVadHandleInsertPrivate,
        .PreCallback   = IntWinVadPatchInsertPrivate,
        .Tag           = detTagVadInsertPriv,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 4,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x34,
                .Code =
                {
                    // 0x00: TEST      byte ptr [edi+0x17], 0x02
                    0xF6, 0x47, 0x17, 0x02,
                    // 0x04: JZ        0x2f
                    0x74, 0x29,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x0F: MOV       eax, dword ptr [ecx+0x50]
                    0x8b, 0x41, 0x50,
                    // 0x12: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x14: JNZ       0x1c
                    0x75, 0x06,
                    // 0x16: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x1C: MOV       eax, dword ptr [eax+0x16c]
                    0x8b, 0x80, 0x6c, 0x01, 0x00, 0x00,
                    // 0x22: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x24: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x28: POP       ecx
                    0x59,
                    // 0x29: POP       eax
                    0x58,
                    // 0x2A: JNZ       0x2f
                    0x75, 0x03,
                    // 0x2C: JNC       0x2f
                    0x73, 0x01,
                    // 0x2E: INT3
                    0xCC,
                    // 0x2F: JMP       0x34
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x2e,
                .RelocatedCodeOffset    = 0x2f,
            },

            {
                .MinVersion    = 9200,
                .MaxVersion    = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x1c,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: MOV       eax, dword ptr [esp+0x10]
                    0x8b, 0x44, 0x24, 0x10,
                    // 0x05: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x0B: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x0D: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x11: POP       eax
                    0x58,
                    // 0x12: JNZ       0x17
                    0x75, 0x03,
                    // 0x14: JNC       0x17
                    0x73, 0x01,
                    // 0x16: INT3
                    0xcc,
                    // 0x17: JMP       0x1c
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x16,
                .RelocatedCodeOffset    = 0x17,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x22,
                .Code =
                {
                    // 0x00: TEST      byte ptr [ecx+0x1c], 0x10
                    0xF6, 0x41, 0x1C, 0x10,
                    // 0x04: JZ        0x1d
                    0x74, 0x17,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: MOV       eax, dword ptr [esp+0x8]
                    0x8b, 0x44, 0x24, 0x08,
                    // 0x0B: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x11: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x13: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x17: POP       eax
                    0x58,
                    // 0x18: JNZ       0x1d
                    0x75, 0x03,
                    // 0x1A: JNC       0x1d
                    0x73, 0x01,
                    // 0x1C: INT3
                    0xcc,
                    // 0x1D: JMP       0x22
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1c,
                .RelocatedCodeOffset    = 0x1d,
            },

            {
                .MinVersion = 18362,
                .MaxVersion = 18362,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x22,
                .Code =
                {
                    // 0x00: TEST      byte ptr [ecx+0x1d], 0x01
                    0xF6, 0x41, 0x1d, 0x01,
                    // Flag is set in the MMVAD.MMVAD_SHORT.u (flags)
                    // 0x04: JZ        0x1d
                    0x74, 0x17,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: MOV       eax, dword ptr [esp+0x8]
                    0x8b, 0x44, 0x24, 0x08,
                    // 0x0B: MOV       eax, dword ptr [eax+0x17c]
                    0x8b, 0x80, 0x7c, 0x01, 0x00, 0x00,
                    // 0x11: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x13: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x17: POP       eax
                    0x58,
                    // 0x18: JNZ       0x1d
                    0x75, 0x03,
                    // 0x1A: JNC       0x1d
                    0x73, 0x01,
                    // 0x1C: INT3
                    0xcc,
                    // 0x1D: JMP       0x22
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset = 0x1c,
                .RelocatedCodeOffset = 0x1d,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiInsertVad",
        .MinVersion     = 18363,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntWinVadHandleInsert,
        .PreCallback    = IntWinVadPatchInsert,
        .Tag            = detTagVadInsert,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments      = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount  = 1,
        .Handlers =
        {
            {
                .MinVersion = 18363,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x1e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [ecx+0x1d], 0x01
                    0xF6, 0x41, 0x1D, 0x01,
                    // Flag is set in the MMVAD.MMVAD_SHORT.u (flags)
                    // 0x04: JZ        0x19
                    0x74, 0x13,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: MOV       eax, dword ptr [edx+0x17c]
                    0x8b, 0x82, 0x7c, 0x01, 0x00, 0x00,
                    // 0x0D: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x0F: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x13: POP       eax
                    0x58,
                    // 0x14: JNZ       0x19
                    0x75, 0x03,
                    // 0x16: JNC       0x19
                    0x73, 0x01,
                    // 0x18: INT3
                    0xcc,
                    // 0x19: JMP       0x1e
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset = 0x18,
                .RelocatedCodeOffset = 0x19,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiGetWsAndInsertVad",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 18362,
        .Callback      = IntWinVadHandleInsertMap,
        .PreCallback   = IntWinVadPatchInsertMap,
        .Tag           = detTagVadInsertMap,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 6,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x34,
                .Code =
                {
                    // 0x00: TEST      byte ptr [edi+0x17], 0x02
                    0xf6, 0x47, 0x17, 0x02,
                    // 0x04: JZ        0x2f
                    0x74, 0x29,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x0F: MOV       eax, dword ptr [ecx+0x50]
                    0x8b, 0x41, 0x50,
                    // 0x12: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x14: JNZ       0x1c
                    0x75, 0x06,
                    // 0x16: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x1C: MOV       eax, dword ptr [eax+0x16c]
                    0x8b, 0x80, 0x6c, 0x01, 0x00, 0x00,
                    // 0x22: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x24: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x28: POP       ecx
                    0x59,
                    // 0x29: POP       eax
                    0x58,
                    // 0x2A: JNZ       0x2f
                    0x75, 0x03,
                    // 0x2C: JNC       0x2f
                    0x73, 0x01,
                    // 0x2E: INT3
                    0xCC,
                    // 0x2F: JMP       0x34
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x2e,
                .RelocatedCodeOffset    = 0x2f,
            },

            {
                .MinVersion = 9200,
                .MaxVersion = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x37,
                .Code =
                {
                    // 0x00: TEST      byte ptr [eax+0x18], 0x10
                    0xf6, 0x40, 0x18, 0x10,
                    // 0x04: JZ        0x32
                    0x74, 0x2c,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x0F: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x15: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x17: JNZ       0x1f
                    0x75, 0x06,
                    // 0x19: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x1F: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x25: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x27: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x2B: POP       ecx
                    0x59,
                    // 0x2C: POP       eax
                    0x58,
                    // 0x2D: JNZ       0x32
                    0x75, 0x03,
                    // 0x2F: JNC       0x32
                    0x73, 0x01,
                    // 0x31: INT3
                    0xCC,
                    // 0x32: JMP       0x37
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x31,
                .RelocatedCodeOffset    = 0x32,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x37,
                .Code =
                {
                    // 0x00: TEST      byte ptr [ecx+0x1c], 0x10
                    0xf6, 0x41, 0x1c, 0x10,
                    // 0x04: JZ        0x32
                    0x74, 0x2c,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x0F: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x15: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x17: JNZ       0x1f
                    0x75, 0x06,
                    // 0x19: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x1F: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x25: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x27: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x2B: POP       ecx
                    0x59,
                    // 0x2C: POP       eax
                    0x58,
                    // 0x2D: JNZ       0x32
                    0x75, 0x03,
                    // 0x2F: JNC       0x32
                    0x73, 0x01,
                    // 0x31: INT3
                    0xCC,
                    // 0x32: JMP       0x37
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x31,
                .RelocatedCodeOffset    = 0x32,
            },

            {
                .MinVersion = 18362,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x37,
                .Code =
                {
                    // 0x00: TEST byte ptr [ecx+0x1d], 0x01
                    0xf6, 0x41, 0x1d, 0x1,
                    // 0x04: JZ        0x32
                    0x74, 0x2c,
                    // 0x06: PUSH      eax
                    0x50,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x0F: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x15: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x17: JNZ       0x1f
                    0x75, 0x06,
                    // 0x19: MOV       eax, dword ptr [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x1F: MOV       eax, dword ptr [eax+0x17c]
                    0x8b, 0x80, 0x7c, 0x01, 0x00, 0x00,
                    // 0x25: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x27: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x2B: POP       ecx
                    0x59,
                    // 0x2C: POP       eax
                    0x58,
                    // 0x2D: JNZ       0x32
                    0x75, 0x03,
                    // 0x2F: JNC       0x32
                    0x73, 0x01,
                    // 0x31: INT3
                    0xcc,
                    // 0x32: JMP       0x37
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset = 0x31,
                .RelocatedCodeOffset = 0x32,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiCommitExistingVad",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .PreCallback    = IntWinPatchVadHandleCommit,
        .Callback       = IntWinVadHandleCommit,
        .Tag            = detTagVadCommit,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments      = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount  = 1,
        .Handlers =
        {
            {
                .MinVersion = DETOUR_MIN_VERSION_ANY,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,
                .CodeLength = 0x3b,
                .Code =
                {
                    // VmProtection & (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                    // PAGE_EXECUTE_READ | PAGE_EXECUTE)
                    // 0x00: TEST      byte ptr [esp+0x0], 0xf0
                    0xf6, 0x44, 0x24, 0x00, 0xf0,
                    // 0x05: JZ        0x36
                    0x74, 0x2f,
                    // 0x07: PUSH      ecx
                    0x51,
                    // 0x08: PUSH      eax
                    0x50,
                    // ecx = Kpcr.Prcb.CurrentThread
                    // 0x09: MOV       ecx, dword ptr fs:[0x0]
                    0x64, 0x8b, 0x0d, 0x00, 0x00, 0x00, 0x00,
                    // eax = Thread.ApcState.AttachedProcess
                    // 0x10: MOV       eax, dword ptr [ecx+0x0]
                    0x8b, 0x81, 0x00, 0x00, 0x00, 0x00,
                    // 0x16: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x18: JNZ       0x20
                    0x75, 0x06,
                    // eax = Thread.Process
                    // 0x1A: MOV       eax, dword ptr [ecx+0x0]
                    0x8b, 0x81, 0x00, 0x00, 0x00, 0x00,
                    // cmp Process.ImageFileName[0], '*'
                    // 0x20: CMP       byte ptr [eax+0x0], 0x2a
                    0x80, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x2a,
                    // check if 0 != (Process.ImageFileName[1] & winProcExitVad)
                    // 0x27: BT        dword ptr [eax+0x0], 0x08
                    0x0f, 0xba, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x08,
                    // 0x2F: POP       eax
                    0x58,
                    // 0x30: POP       ecx
                    0x59,
                    // 0x31: JNZ       0x36
                    0x75, 0x03,
                    // 0x33: JNC       0x36
                    0x73, 0x01,
                    // 0x35: INT3
                    0xcc,
                    // 0x36: JMP       0x3b
                    0xe9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x35,
                .RelocatedCodeOffset    = 0x36,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiProtectVirtualMemory",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinVadHandleVirtualProtect,
        .PreCallback   = IntWinVadPatchVirtualProtect,
        .Tag           = detTagVmProtect,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 5,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x23,
                .Code =
                {
                    // 0x00: TEST      byte ptr [esp+0x10], 0xf0
                    0xF6, 0x44, 0x24, 0x10, 0xF0,
                    // 0x05: JZ        0x1e
                    0x74, 0x17,
                    // 0x07: PUSH      eax
                    0x50,
                    // 0x08: MOV       eax, dword ptr [esp+0x8]
                    0x8b, 0x44, 0x24, 0x08,
                    // 0x0C: MOV       eax, dword ptr [eax+0x16c]
                    0x8b, 0x80, 0x6c, 0x01, 0x00, 0x00,
                    // 0x12: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x14: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x18: POP       eax
                    0x58,
                    // 0x19: JNZ       0x1e
                    0x75, 0x03,
                    // 0x1B: JNC       0x1e
                    0x73, 0x01,
                    // 0x1D: INT3
                    0xcc,
                    // 0x1E: JMP       0x23
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1d,
                .RelocatedCodeOffset    = 0x1e,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x20,
                .Code =
                {
                    // 0x00: TEST      byte ptr [esp+0xc], 0xf0
                    0xF6, 0x44, 0x24, 0x0C, 0xF0,
                    // 0x05: JZ        0x1b
                    0x74, 0x14,
                    // 0x07: CMP       byte ptr [edx+0x170], 0x2a
                    0x80, 0xba, 0x70, 0x01, 0x00, 0x00, 0x2a,
                    // 0x0E: BT        dword ptr [edx+0x170], 0x08
                    0x0f, 0xba, 0xa2, 0x70, 0x01, 0x00, 0x00, 0x08,
                    // 0x16: JNZ       0x1b
                    0x75, 0x03,
                    // 0x18: JNC       0x1b
                    0x73, 0x01,
                    // 0x1A: INT3
                    0xcc,
                    // 0x1B: JMP       0x20
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1a,
                .RelocatedCodeOffset    = 0x1b,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiDeleteVirtualAddresses",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 16299,
        .Callback      = IntWinVadHandleDeleteVaRange,
        .PreCallback   = IntWinVadPatchDeleteVaRange,
        .Tag           = detTagVaDelete,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 4,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x2e,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ecx
                    0x51,
                    // 0x02: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x09: MOV       eax, dword ptr [ecx+0x50]
                    0x8b, 0x41, 0x50,
                    // 0x0C: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x0E: JNZ       0x16
                    0x75, 0x06,
                    // 0x10: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x16: MOV       eax, dword ptr [eax+0x16c]
                    0x8b, 0x80, 0x6c, 0x01, 0x00, 0x00,
                    // 0x1C: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x1E: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x22: POP       ecx
                    0x59,
                    // 0x23: POP       eax
                    0x58,
                    // 0x24: JNZ       0x29
                    0x75, 0x03,
                    // 0x26: JNC       0x29
                    0x73, 0x01,
                    // 0x28: INT3
                    0xCC,
                    // 0x29: JMP       0x2e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x28,
                .RelocatedCodeOffset    = 0x29,
            },

            {
                .MinVersion    = 9200,
                .MaxVersion    = 16299,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x31,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ecx
                    0x51,
                    // 0x02: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x09: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x0F: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x11: JNZ       0x19
                    0x75, 0x06,
                    // 0x13: MOV       eax, dword ptr [ecx+0x150]
                    0x8B, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x19: MOV       eax, dword ptr [eax+0x170]
                    0x8b, 0x80, 0x70, 0x01, 0x00, 0x00,
                    // 0x1F: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x21: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x25: POP       ecx
                    0x59,
                    // 0x26: POP       eax
                    0x58,
                    // 0x27: JNZ       0x2c
                    0x75, 0x03,
                    // 0x29: JNC       0x2c
                    0x73, 0x01,
                    // 0x2B: INT3
                    0xCC,
                    // 0x2C: JMP       0x31
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x2b,
                .RelocatedCodeOffset    = 0x2c,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiFinishVadDeletion",
        .MinVersion    = 17134,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinVadHandleFinishVadDeletion,
        .PreCallback   = IntWinVadPatchFinishVadDeletion,
        .Tag           = detTagFinishVadDeletion,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 17134,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x31,
                .Code =
                {
                    // 0x00: PUSH      eax
                    0x50,
                    // 0x01: PUSH      ecx
                    0x51,
                    // 0x02: MOV       ecx, dword ptr fs:[0x124]
                    0x64, 0x8b, 0x0d, 0x24, 0x01, 0x00, 0x00,
                    // 0x09: MOV       eax, dword ptr [ecx+0x80]
                    0x8b, 0x81, 0x80, 0x00, 0x00, 0x00,
                    // 0x0F: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x11: JNZ       0x19
                    0x75, 0x06,
                    // 0x13: MOV       eax, dword ptr [ecx+0x150]
                    0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x19: MOV       eax, dword ptr [eax+0x17c]
                    0x8b, 0x80, 0x7c, 0x01, 0x00, 0x00,
                    // 0x1F: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x21: BT        eax, 0x08
                    0x0f, 0xba, 0xe0, 0x08,
                    // 0x25: POP       ecx
                    0x59,
                    // 0x26: POP       eax
                    0x58,
                    // 0x27: JNZ       0x2c
                    0x75, 0x03,
                    // 0x29: JNC       0x2c
                    0x73, 0x01,
                    // 0x2B: INT3
                    0xcc,
                    // 0x2C: JMP       0x31
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x2b,
                .RelocatedCodeOffset    = 0x2c,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "NtSetSystemPowerState",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinPowHandlePowerStateChange,
        .Tag           = detTagPowerState,
        .Exported      = FALSE,
        .NotCritical   = TRUE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0xF,
                .Code =
                {
                    // 0x00: INT3
                    0xcc,
                    // 0x01: NOP
                    0x66, 0x66, 0x66, 0x66, 0x90,
                    // 0x06: NOP
                    0x66, 0x90,
                    // 0x08: NOP
                    0x66, 0x90,
                    // 0x0A: JMP       0xf
                    0xe9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0xA,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "KiDisplayBlueScreen",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntGuestUninitOnBugcheck,
        .Tag           = detTagCleanupMemDump,
        .Exported      = FALSE,
        .NotCritical   = TRUE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_BUGCHECK_CLEANUP,
        .Arguments     = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MmInSwapProcessHijack",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntWinProcSwapIn,
        .Tag            = detTagProcSwapIn,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount  = 1,
        .Handlers       =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {

                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset     = 0x0,
                .RelocatedCodeOffset = 0x3,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "KiOutSwapProcessesHijack",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .PreCallback    = IntWinProcPatchSwapOut32,
        .Callback       = IntWinProcSwapOut,
        .Tag            = detTagProcSwapOut,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN86,
        .HandlersCount  = 1,
        .Handlers       =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x14,
                .Code =
                {
                    // 0x00: PUSH       eax
                    0x50,
                    // 0x01: MOV        eax, DWORD PTR [edi + _EPROCESS.Flags]
                    0x8B, 0x87, 0x00, 0x00, 0x00, 0x00,
                    // 0x07: BT         eax, 0x07
                    0x0f, 0xba, 0xe0, 0x07,
                    // 0x0B: JNC        0x0E
                    0x73, 0x01,
                    // 0x0D: INT3
                    0xCC,
                    // 0x0E: POP        eax
                    0x58,
                    // 0x0F: JMP        0x10
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset     = 0x0D,
                .RelocatedCodeOffset = 0x0F,
            },
        },
    },
};

/// The number of functions to be hooked for 32-bit Windows guests.
const size_t gHookableApisX86Size = ARRAYSIZE(gHookableApisX86);


///
/// @brief  The functions to be hooked for 64-bit Windows guests
///
API_HOOK_DESCRIPTOR gHookableApisX64[]
__section(".detours") =
{
    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "ExAllocatePoolWithTag",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinPoolHandleAlloc,
        .Tag           = detTagPoolAlloc,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x37,
                .Code =
                {
                    // 0x00: CMP       r8d, 0xf6697244
                    0x41, 0x81, 0xF8, 0x44, 0x72, 0x69, 0xF6,
                    // 0x07: JZ        0x2f
                    0x74, 0x26,
                    // 0x09: CMP       r8d, 0x76697244
                    0x41, 0x81, 0xF8, 0x44, 0x72, 0x69, 0x76,
                    // 0x10: JZ        0x2f
                    0x74, 0x1D,
                    // 0x12: CMP       r8d, 0x69664d46
                    0x41, 0x81, 0xF8, 0x46, 0x4D, 0x66, 0x69,
                    // 0x19: JZ        0x2f
                    0x74, 0x14,
                    // 0x1B: CMP       r8d, 0x656b6f54
                    0x41, 0x81, 0xF8, 0x54, 0x6f, 0x6b, 0x65,
                    // 0x22: JZ        0x2f
                    0x74, 0x0B,
                    // 0x24: CMP       r8d, 0xe56b6f54
                    0x41, 0x81, 0xF8, 0x54, 0x6f, 0x6b, 0xe5,
                    // 0x2B: JZ        0x2f
                    0x74, 0x02,
                    // 0x2D: JMP       0x32
                    0xEB, 0x03,
                    // 0x2F: INT3
                    0xCC,
                    // 0x30: NOP
                    0x90,
                    // 0x31: NOP
                    0x90,
                    // 0x32: JMP       0x37
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset           = 0x2F,
                .RelocatedCodeOffset       = 0x32,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "ExFreePoolWithTag",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinPoolHandleFree,
        .Tag           = detTagPoolFree,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x22,
                .Code =
                {
                    // 0x00: CMP       edx, 0xf6697244
                    0x81, 0xFA, 0x44, 0x72, 0x69, 0xF6,
                    // 0x06: JZ        0x1a
                    0x74, 0x12,
                    // 0x08: CMP       edx, 0x76697244
                    0x81, 0xFA, 0x44, 0x72, 0x69, 0x76,
                    // 0x0E: JZ        0x1a
                    0x74, 0x0A,
                    // 0x10: CMP       edx, 0x69664d46
                    0x81, 0xFA, 0x46, 0x4D, 0x66, 0x69,
                    // 0x16: JZ        0x1a
                    0x74, 0x02,
                    // 0x18: JMP       0x1d
                    0xEB, 0x03,
                    // 0x1A: INT3
                    0xCC,
                    // 0x1B: NOP
                    0x90,
                    // 0x1C: NOP
                    0x90,
                    // 0x1D: JMP       0x22
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1A,
                .RelocatedCodeOffset    = 0x1D,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "KeBugCheckEx",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinBcHandleBugCheck,
        .Tag           = detTagBugcheck,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_BUGCHECK_CLEANUP | INTRO_OPT_EVENT_OS_CRASH,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "NtSetInformationProcess",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleInstrument,
        .PreCallback   = IntWinProcPrepareInstrument,
        .Tag           = detTagSetProcInformation,
        .Exported      = TRUE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0xb8,
                .Code =
                {
                    // 0x00: cmp    edx,0x28
                    0x83, 0xfa, 0x28,
                    // 0x03: jne    0xb3 <_irelevant>
                    0x0f, 0x85, 0xaa, 0x00, 0x00, 0x00,
                    // 0x09: push   rax
                    0x50,
                    // 0x0a: push   rcx
                    0x51,
                    // 0x0b: push   rdx
                    0x52,
                    // 0x0c: push   r8
                    0x41, 0x50,
                    // 0x0e: push   r9
                    0x41, 0x51,
                    // 0x10: push   r10
                    0x41, 0x52,
                    // 0x12: push   r11
                    0x41, 0x53,
                    // reserve space for locals
                    // 0x14: sub    rsp,0x10
                    0x48, 0x83, 0xec, 0x10,
                    // 0x18: mov    edx,0x10
                    0xba, 0x10, 0x00, 0x00, 0x00,
                    // PsProcessType
                    // 0x1d: movabs rax,0xfffff00000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff,
                    // 0x27: mov    r8,QWORD PTR [rax]
                    0x4c, 0x8b, 0x00,
                    // 0x2a: mov    r9,0x1
                    0x49, 0xc7, 0xc1, 0x01, 0x00, 0x00, 0x00,
                    // 0x31: lea    rax,[rsp+0x8]
                    0x48, 0x8d, 0x44, 0x24, 0x08,
                    // 0x36: push   0x0
                    0x6a, 0x00,
                    // 0x38: push   rax
                    0x50,
                    // ObReferenceObjectByHandle
                    // 0x39: movabs rax,0xfffff00000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff,
                    // 0x43: sub    rsp,0x20
                    0x48, 0x83, 0xec, 0x20,
                    // 0x47: call   rax
                    0xff, 0xd0,
                    // 0x49: add    rsp,0x30
                    0x48, 0x83, 0xc4, 0x30,
                    // 0x4d: test   eax,eax
                    0x85, 0xc0,
                    // 0x4f: jne    0x94 <_exit>
                    0x75, 0x43,
                    // 0x51: mov    rcx,QWORD PTR [rsp+0x8]
                    0x48, 0x8b, 0x4c, 0x24, 0x08,
                    // This offset will be overwritten by intro with the offset of `_EPROCESS.Spare`
                    // 0x56: mov    rax,QWORD PTR [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // 0x5d: cmp    al,0x2a
                    0x3c, 0x2a,
                    // 0x5f: bt     rax,0xd
                    0x48, 0x0f, 0xba, 0xe0, 0x0d,
                    // 0x64: jne    75 <_dereference_and_exit>
                    0x75, 0x0f,
                    // 0x66: jae    75 <_dereference_and_exit>
                    0x73, 0x0d,
                    // 0x68: mov    rdx,QWORD PTR [rsp+0x30]
                    0x48, 0x8b, 0x54, 0x24, 0x30,
                    // 0x6d: mov    r8,QWORD PTR [rsp+0x28]
                    0x4c, 0x8b, 0x44, 0x24, 0x28,

                    // 0x72 <_hypercall>:
                    // 0x72: int3
                    0xcc,
                    // 0x73: nop
                    0x90,
                    // 0x74: nop
                    0x90,

                    // 0x75 <_dereference_and_exit>:
                    // 0x75: mov    rcx,QWORD PTR [rsp+0x08]
                    0x48, 0x8b, 0x4c, 0x24, 0x08,
                    // 0x7a: mov    QWORD PTR [rsp+0x08],rax
                    0x48, 0x89, 0x44, 0x24, 0x08,
                    // ObDereferenceObject
                    // 0x7f: movabs rax,0xfffff00000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff,
                    // 0x89: sub    rsp,0x20
                    0x48, 0x83, 0xec, 0x20,
                    // 0x8d: call   rax
                    0xff, 0xd0,
                    // 0x8f: add    rsp,0x20
                    0x48, 0x83, 0xc4, 0x20,
                    // 0x93: mov    rax,QWORD PTR[rsp+0x08]
                    0x48, 0x8b, 0x44, 0x24, 0x08,

                    // 0x98 <_exit>:
                    // 0x98: add    rsp,0x10
                    0x48, 0x83, 0xc4, 0x10,
                    // 0x9c: pop    r11
                    0x41, 0x5b,
                    // 0x9e: pop    r10
                    0x41, 0x5a,
                    // 0xa0: pop    r9
                    0x41, 0x59,
                    // 0xa2: pop    r8
                    0x41, 0x58,
                    // 0xa4: pop    rdx
                    0x5a,
                    // 0xa5: pop    rcx
                    0x59,
                    // 0xa6: cmp    eax,0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0xab: jne    a2 <_allow>
                    0x75, 0x05,
                    // 0xad: add    rsp,0x8
                    0x48, 0x83, 0xc4, 0x08,
                    // 0xb1: ret
                    0xc3,

                    // 0xb2 <_allow>:
                    // 0xb2: pop    rax
                    0x58,

                    // 0xb3 <_irelevant>:
                    // 0xb3: jmp    a8 <_irelevant+0x5>
                    0xe9, 0x00, 0x00, 0x00, 0x00,

                },
                .HypercallOffset        = 0x72,
                .RelocatedCodeOffset    = 0xb3,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiProcessLoaderEntry",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntDriverLoadHandler,
        .Tag            = detTagModuleLoad,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers =
        {
            {
                .MinVersion = DETOUR_MIN_VERSION_ANY,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiUnloadSystemImage",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntDriverUnloadHandler,
        .Tag           = detTagModuleUnload,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x0F,
                .Code =
                {
                    // cmp LoadCount, 1
                    // 0x00: CMP       word ptr [rcx+0x6c], 0x01
                    0x66, 0x83, 0x79, 0x6C, 0x01,
                    // 0x05: JNZ       0xa
                    0x75, 0x03,
                    // 0x07: INT3
                    0xCC,
                    // 0x08: NOP
                    0x90,
                    // 0x09: NOP
                    0x90,
                    // 0x0A: JMP       0xf
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x07,
                .RelocatedCodeOffset    = 0x0A,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "PspInsertProcess",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleCreate,
        .Tag           = detTagProcCreate,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x0E,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: JMP       0x9
                    0xEB, 0x06,
                    // If we want to block a process, we increment the RIP from
                    // IntWinProcHandleCreate so that it points here.
                    // 0x03: MOV       eax, 0xc0000022
                    0xB8, 0x22, 0x00, 0x00, 0xC0,
                    // 0x08: RETN
                    0xC3,
                    // <call PspInsertProcess>
                    // 0x09: JMP       0xe
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x00,
                .RelocatedCodeOffset    = 0x09,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MmCleanProcessAddressSpace",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleTerminate,
        .Tag           = detTagProcTerminate,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = DETOUR_ENABLE_ALWAYS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0x3,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MmCopyVirtualMemory",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinProcHandleCopyMemory,
        .PreCallback   = IntWinProcPatchCopyMemoryDetour,
        .Tag           = detTagProcInject,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x53,
                .Code =
                {
                    // 0x00: CMP       rcx, r8
                    0x4c, 0x39, 0xc1,
                    // 0x03: JZ        0x4e
                    0x74, 0x49,
                    // 0x05: PUSH      rax
                    0x50,
                    // 0x06: PUSH      rbx
                    0x53,
                    // Is this a read or a write
                    // 0x07: MOV       rax, cr3
                    0x0f, 0x20, 0xd8,
                    // 0x0A: CMP       rax, qword ptr [r8+0x0]
                    0x49, 0x3b, 0x80, 0x00, 0x00, 0x00, 0x00,
                    // 0x11: JZ        0x2a
                    0x74, 0x17,
                    // _is_write:
                    // 0x13: CMP       byte ptr [r8+0x0], 0x2a
                    0x41, 0x80, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x2a,
                    // 0x1B: JNZ       0x4c
                    0x75, 0x2f,
                    // 0x1D: BT        dword ptr [r8+0x0], 0x09
                    0x41, 0x0f, 0xba, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x09,
                    // 0x26: JNC       0x4c
                    0x73, 0x24,
                    // 0x28: JMP       0x3d
                    0xeb, 0x13,
                    // _is_read:
                    // 0x2A: CMP       byte ptr [rcx+0x0], 0x2a
                    0x80, 0xb9, 0x00, 0x00, 0x00, 0x00, 0x2a,
                    // 0x31: JNZ       0x4c
                    0x75, 0x19,
                    // 0x33: BT        dword ptr [rcx+0x0], 0x0a
                    0x0f, 0xba, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x0a,
                    // 0x3B: JNC       0x4c
                    0x73, 0x0f,
                    // _do_int3:
                    // 0x3D: INT3
                    0xcc,
                    // 0x3E: NOP
                    0x90,
                    // 0x3F: NOP
                    0x90,
                    // 0x40: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x45: JNZ       0x4c
                    0x75, 0x05,
                    // 0x47: ADD       rsp, 0x10
                    0x48, 0x83, 0xc4, 0x10,
                    // 0x4B: RETN
                    0xc3,
                    // _continue_function:
                    // 0x4C: POP       rbx
                    0x5b,
                    // 0x4D: POP       rax
                    0x58,
                    // _skip_detour:
                    // 0x4E: JMP       0x53
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x3d,
                .RelocatedCodeOffset    = 0x4e,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "NtQueueApcThreadEx",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinThrHandleQueueApc,
        .PreCallback   = IntWinThrPrepareApcHandler,
        .Tag           = detTagProcQueueApc,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0xcf,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: PUSH      rcx
                    0x51,
                    // 0x02: PUSH      rdx
                    0x52,
                    // 0x03: PUSH      r8
                    0x41, 0x50,
                    // 0x05: PUSH      r9
                    0x41, 0x51,
                    // 0x07: PUSH      r10
                    0x41, 0x52,
                    // 0x09: PUSH      r11
                    0x41, 0x53,
                    // 0x0B: SUB       rsp, 0x20
                    0x48, 0x83, 0xec, 0x20,
                    // 0x0F: MOV       rax, 0xfffff80000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff,
                    // PsThreadType
                    // 0x19: MOV       r8, qword ptr [rax]
                    0x4c, 0x8b, 0x00,
                    // 0x1C: MOV       r9b, 0x01
                    0x41, 0xb1, 0x01,
                    // 0x1F: MOV       edx, 0x00000010
                    0xba, 0x10, 0x00, 0x00, 0x00,
                    // 0x24: LEA       rax, [rsp+0x8]
                    0x48, 0x8d, 0x44, 0x24, 0x08,
                    // 0x29: MOV       qword ptr [rsp+0x8], 0x00000000
                    0x48, 0xc7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00,
                    // 0x32: PUSH      0x00
                    0x6a, 0x00,
                    // 0x34: PUSH      rax
                    0x50,
                    // 0x35: SUB       rsp, 0x20
                    0x48, 0x83, 0xec, 0x20,
                    // 0x39: MOV       rax, 0xfffff80000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff,
                    // ObReferenceObject
                    // 0x43: CALL      rax
                    0xff, 0xd0,
                    // 0x45: ADD       rsp, 0x30
                    0x48, 0x83, 0xc4, 0x30,
                    // 0x49: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x4B: JNZ       0xaf
                    0x75, 0x62,
                    // 0x4D: MOV       rcx, qword ptr [rsp+0x8]
                    0x48, 0x8b, 0x4c, 0x24, 0x08,
                    // Victim thread obj
                    // 0x52: MOV       r9, qword ptr [rsp+0x30]
                    0x4c, 0x8b, 0x4c, 0x24, 0x30,
                    // 0x57: MOV       r8, qword ptr [rsp+0x38]
                    0x4c, 0x8b, 0x44, 0x24, 0x38,
                    // 0x5C: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // AttachedProcess
                    // 0x63: TEST      rax, rax
                    0x48, 0x85, 0xc0,
                    // 0x66: JNZ       0x6f
                    0x75, 0x07,
                    // 0x68: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // Process
                    // _attached:
                    // 0x6F: MOV       rax, qword ptr [rax+0x150]
                    0x48, 0x8b, 0x80, 0x50, 0x01, 0x00, 0x00,
                    // ImageFileName
                    // 0x76: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // Check for '*' in process name
                    // 0x78: BT        rax, 0x0c
                    0x48, 0x0f, 0xba, 0xe0, 0x0c,
                    // Check QueueApc protection flag
                    // 0x7D: MOV       rax, 0x00000000
                    0x48, 0xc7, 0xc0, 0x00, 0x00, 0x00, 0x00,
                    // 0x84: JNZ       0x94
                    0x75, 0x0e,
                    // 0x86: JNC       0x94
                    0x73, 0x0c,
                    // 0x88: MOV       rax, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x91: INT3
                    0xcc,
                    // 0x92: NOP
                    0x90,
                    // 0x93: NOP
                    0x90,
                    // _skip_exit:
                    // 0x94: MOV       qword ptr [rsp+0x10], rax
                    0x48, 0x89, 0x44, 0x24, 0x10,
                    // 0x99: MOV       rcx, qword ptr [rsp+0x8]
                    0x48, 0x8b, 0x4c, 0x24, 0x08,
                    // 0x9E: MOV       rax, 0xfffff80000000000
                    0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff,
                    // ObDereference
                    // 0xA8: CALL      rax
                    0xff, 0xd0,
                    // 0xAA: MOV       rax, qword ptr [rsp+0x10]
                    0x48, 0x8b, 0x44, 0x24, 0x10,
                    // _cleanup_and_exit:
                    // 0xAF: ADD       rsp, 0x20
                    0x48, 0x83, 0xc4, 0x20,
                    // 0xB3: POP       r11
                    0x41, 0x5b,
                    // 0xB5: POP       r10
                    0x41, 0x5a,
                    // 0xB7: POP       r9
                    0x41, 0x59,
                    // 0xB9: POP       r8
                    0x41, 0x58,
                    // 0xBB: POP       rdx
                    0x5a,
                    // 0xBC: POP       rcx
                    0x59,
                    // 0xBD: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0xC2: JNZ       0xc9
                    0x75, 0x05,
                    // 0xC4: ADD       rsp, 0x08
                    0x48, 0x83, 0xc4, 0x08,
                    // 0xC8: RETN
                    0xc3,
                    // _skip:
                    // 0xC9: POP       rax
                    0x58,
                    // 0xCA: JMP       0xcf
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x91,
                .RelocatedCodeOffset    = 0xca,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "PspSetContextThreadInternal",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinThrHandleThreadHijack,
        .PreCallback   = IntWinThrPatchThreadHijackHandler,
        .Tag           = detTagProcThrHijack,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x49,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // AttachedProcess
                    // 0x08: TEST      rax, rax
                    0x48, 0x85, 0xc0,
                    // 0x0B: JNZ       0x14
                    0x75, 0x07,
                    // 0x0D: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // Process
                    // _attached:
                    // 0x14: MOV       rax, qword ptr [rax+0x150]
                    0x48, 0x8b, 0x80, 0x50, 0x01, 0x00, 0x00,
                    // ImageFileName
                    // 0x1B: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // Check for "*" in process name
                    // 0x1D: BT        rax, 0x0b
                    0x48, 0x0f, 0xba, 0xe0, 0x0b,
                    // ThreadCtx protection flag
                    // 0x22: JNZ       0x43
                    0x75, 0x1f,
                    // 0x24: JNC       0x43
                    0x73, 0x1d,
                    // 0x26: MOV       rax, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x2F: CMP       rax, rcx
                    0x48, 0x39, 0xc8,
                    // 0x32: JZ        0x43
                    0x74, 0x0f,
                    // 0x34: INT3
                    0xcc,
                    // 0x35: NOP
                    0x90,
                    // 0x36: NOP
                    0x90,
                    // 0x37: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x3C: JNZ       0x43
                    0x75, 0x05,
                    // 0x3E: ADD       rsp, 0x08
                    0x48, 0x83, 0xc4, 0x08,
                    // 0x42: RETN
                    0xc3,
                    // <skip>:
                    // 0x43: POP       rax
                    0x58,
                    // 0x44: JMP       0x49
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x34,
                .RelocatedCodeOffset    = 0x44,
            },
        },
    },

    // This has the same functionality as PspSetContextThreadInternal, but for a WOW64 Process setting context on a
    // WOW64 victim, PspSetContextThreadInternal is saved only when XSAVE_STATE is set.
    // This function has the same PspWow64SetContextThreadOnAmd64 for NtBuildNumber < 10240, PspWowSetContextThread
    // for NtBuildNumber == 10240 and PspWow64SetContextThread for NtBuildNumber > 10240
    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "PspWow64SetContextThread",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinThrHandleThreadHijack,
        .PreCallback   = IntWinThrPatchThreadHijackHandler,
        .Tag           = detTagProcThrHijackWow64,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x49,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // AttachedProcess
                    // 0x08: TEST      rax, rax
                    0x48, 0x85, 0xc0,
                    // 0x0B: JNZ       0x14
                    0x75, 0x07,
                    // 0x0D: MOV       rax, qword ptr [rcx+0x150]
                    0x48, 0x8b, 0x81, 0x50, 0x01, 0x00, 0x00,
                    // Process
                    // _attached
                    // 0x14: MOV       rax, qword ptr [rax+0x150]
                    0x48, 0x8b, 0x80, 0x50, 0x01, 0x00, 0x00,
                    // ImageFileName
                    // 0x1B: CMP       al, 0x2a
                    0x3c, 0x2a,
                    // 0x1D: BT        rax, 0x0b
                    0x48, 0x0f, 0xba, 0xe0, 0x0b,
                    // ThreadCtx protection flag
                    // 0x22: JNZ       0x43
                    0x75, 0x1f,
                    // 0x24: JNC       0x43
                    0x73, 0x1d,
                    // 0x26: MOV       rax, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x2F: CMP       rax, rcx
                    0x48, 0x39, 0xc8,
                    // 0x32: JZ        0x43
                    0x74, 0x0f,
                    // 0x34: INT3
                    0xcc,
                    // 0x35: NOP
                    0x90,
                    // 0x36: NOP
                    0x90,
                    // 0x37: CMP       eax, 0xc0000022
                    0x3d, 0x22, 0x00, 0x00, 0xc0,
                    // 0x3C: JNZ       0x43
                    0x75, 0x05,
                    // 0x3E: ADD       rsp, 0x08
                    0x48, 0x83, 0xc4, 0x08,
                    // 0x42: RETN
                    0xc3,
                    // _skip:
                    // 0x43: POP       rax
                    0x58,
                    // 0x44: JMP       0x49
                    0xe9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x34,
                .RelocatedCodeOffset    = 0x44,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "KiDispatchException",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinHandleException,
        .Tag           = detTagException,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_EVENT_PROCESS_CRASH,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x0E,
                .Code =
                {
                    // 0x00: CMP       r9d, 0x00
                    0x41, 0x83, 0xf9, 0x00,
                    // 0x04: JZ        0x9
                    0x74, 0x03,
                    // 0x06: INT3
                    0xCC,
                    // 0x07: NOP
                    0x90,
                    // 0x08: NOP
                    0x90,
                    // 0x09: JMP       0xe
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x06,
                .RelocatedCodeOffset    = 0x09,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiInsertVad",
        .MinVersion    = 10240,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinVadHandleInsert,
        .PreCallback   = IntWinVadPatchInsert,
        .Tag           = detTagVadInsert,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 2,
        .Handlers =
        {
            {
                .MinVersion    = 10240,
                .MaxVersion    = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x1f,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x1a
                    0x74, 0x14,
                    // 0x06: CMP       byte ptr [rdx+0x448], 0x2a
                    0x80, 0xBA, 0x48, 0x04, 0x00, 0x00, 0x2A,
                    // 0x0D: BT        dword ptr [rdx+0x448], 0x08
                    0x0f, 0xba, 0xa2, 0x48, 0x04, 0x00, 0x00, 0x08,
                    // 0x15: JNZ       0x1a
                    0x75, 0x03,
                    // 0x17: JNC       0x1a
                    0x73, 0x01,
                    // 0x19: INT3
                    0xCC,
                    // 0x1A: JMP       0x1f
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x19,
                .RelocatedCodeOffset    = 0x1a,
            },

            {
                .MinVersion = 18362,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x1f,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x31], 0x01
                    0xF6, 0x41, 0x31, 0x01,
                    // 0x04: JZ        0x1a
                    0x74, 0x14,
                    // 0x06: CMP       byte ptr [rdx+0x448], 0x2a
                    0x80, 0xBA, 0x48, 0x04, 0x00, 0x00, 0x2A,
                    // 0x0D: BT        dword ptr [rdx+0x448], 0x08
                    0x0f, 0xba, 0xa2, 0x48, 0x04, 0x00, 0x00, 0x08,
                    // 0x15: JNZ       0x1a
                    0x75, 0x03,
                    // 0x17: JNC       0x1a
                    0x73, 0x01,
                    // 0x19: INT3
                    0xCC,
                    // 0x1A: JMP       0x1f
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset = 0x19,
                .RelocatedCodeOffset = 0x1a,
            },
        },
    },


    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiInsertPrivateVad",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 9600,
        .Callback      = IntWinVadHandleInsertPrivate,
        .PreCallback   = IntWinVadPatchInsertPrivate,
        .Tag           = detTagVadInsertPriv,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 3,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x2f], 0x02
                    0xF6, 0x41, 0x2F, 0x02,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0x70]
                    0x48, 0x8B, 0x81, 0x70, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x210]
                    0x48, 0x8B, 0x81, 0x10, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x2e0], 0x2a
                    0x80, 0xB8, 0xE0, 0x02, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x2e0], 0x08
                    0x0f, 0xba, 0xa0, 0xe0, 0x02, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },

            {
                .MinVersion    = 9200,
                .MaxVersion    = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x28], 0x10
                    0xF6, 0x41, 0x28, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x438], 0x2a
                    0x80, 0xB8, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x438], 0x08
                    0x0f, 0xba, 0xa0, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = 9600,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x21,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x1b
                    0x74, 0x15,
                    // 0x06: CMP       byte ptr [r8+0x438], 0x2a
                    0x41, 0x80, 0xB8, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x0E: BT        dword ptr [r8+0x438], 0x08
                    0x41, 0x0f, 0xba, 0xa0, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x17: JNZ       0x1c
                    0x75, 0x03,
                    // 0x19: JNC       0x1c
                    0x73, 0x01,
                    // 0x1B: INT3
                    0xCC,
                    // 0x1C: JMP       0x21
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1b,
                .RelocatedCodeOffset    = 0x1c,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiInsertPrivateVad",
        .MinVersion     = 17763,
        .MaxVersion     = 18362,
        .Callback       = IntWinVadHandleInsertPrivate,
        .PreCallback    = IntWinVadPatchInsertPrivate,
        .Tag            = detTagVadInsertPriv,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 2,
        .Handlers = {
            // Windows 10 RS5 17763
            {
                .MinVersion    = 17763,
                .MaxVersion    = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },
            // Windows 10 19H1
            {
                .MinVersion = 18362,
                .MaxVersion = 18362,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x31], 0x01
                    0xf6, 0x41, 0x31, 0x01,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset = 0x38,
                .RelocatedCodeOffset = 0x39,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiGetWsAndInsertVad",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 9600,
        .Callback      = IntWinVadHandleInsertMap,
        .PreCallback   = IntWinVadPatchInsertMap,
        .Tag           = detTagVadInsertMap,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 3,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x2f], 0x02
                    0xF6, 0x41, 0x2F, 0x02,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0x70]
                    0x48, 0x8B, 0x81, 0x70, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x210]
                    0x48, 0x8B, 0x81, 0x10, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x2e0], 0x2a
                    0x80, 0xB8, 0xE0, 0x02, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x2e0], 0x08
                    0x0f, 0xba, 0xa0, 0xe0, 0x02, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },

            {
                .MinVersion    = 9200,
                .MaxVersion    = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x28], 0x10
                    0xF6, 0x41, 0x28, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x438], 0x2a
                    0x80, 0xB8, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x438], 0x08
                    0x0f, 0xba, 0xa0, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = 9600,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x438], 0x2a
                    0x80, 0xB8, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x438], 0x08
                    0x0f, 0xba, 0xa0, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiGetWsAndInsertVad",
        .MinVersion     = 17763,
        .MaxVersion     = 18362,
        .Callback       = IntWinVadHandleInsertMap,
        .PreCallback    = IntWinVadPatchInsertMap,
        .Tag            = detTagVadInsertMap,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 2,
        .Handlers = {
            // Windows 10 RS5 17763
            {
                .MinVersion = 17763,
                .MaxVersion = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },
            {
                .MinVersion = 18362,
                .MaxVersion = 18362,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x31], 0x01
                    0xf6, 0x41, 0x31, 0x01,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset = 0x38,
                .RelocatedCodeOffset = 0x39,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MiCommitExistingVad",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .PreCallback    = IntWinPatchVadHandleCommit,
        .Callback       = IntWinVadHandleCommit,
        .Tag            = detTagVadCommit,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers =
        {
            {
                .MinVersion = DETOUR_MIN_VERSION_ANY,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,
                .CodeLength = 0x3e,
                .Code =
                {
                    // VmProtection & (PAGE_EXECUTE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                    // PAGE_EXECUTE_READ | PAGE_EXECUTE)
                    // 0x00: TEST      r9b, 0xf0
                    0x41, 0xf6, 0xc1, 0xf0,
                    // not executable, skip hook
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rcx
                    0x51,
                    // 0x07: PUSH      rax
                    0x50,
                    // rcx = Kpcr.Prcb.CurrentThread
                    // 0x08: MOV       rcx, qword ptr gs:[0x0]
                    0x65, 0x48, 0x8b, 0x0c, 0x25, 0x00, 0x00, 0x00, 0x00,
                    // rax = Thread.ApcState.AttachedProcess
                    // 0x11: MOV       rax, qword ptr [rcx+0x0]
                    0x48, 0x8b, 0x81, 0x00, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xc0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // rax = Thread.Process
                    // 0x1C: MOV       rax, qword ptr [rcx+0x0]
                    0x48, 0x8b, 0x81, 0x00, 0x00, 0x00, 0x00,
                    // cmp Process.ImageFileName[0], '*'
                    // 0x23: CMP       byte ptr [rax+0x0], 0x2a
                    0x80, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x2a,
                    // check if 0 != (Process.ImageFileName[1] & winProcExitVad)
                    // 0x2A: BT        dword ptr [rax+0x0], 0x08
                    0x0f, 0xba, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x08,
                    // 0x32: POP       rax
                    0x58,
                    // 0x33: POP       rcx
                    0x59,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xcc,
                    // 0x39: JMP       0x3e
                    0xe9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            }
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiProtectVirtualMemory",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinVadHandleVirtualProtect,
        .PreCallback   = IntWinVadPatchVirtualProtect,
        .Tag           = detTagVmProtect,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 5,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 9200,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x1f,
                .Code =
                {
                    // 0x00: TEST      r9b, 0xf0
                    0x41, 0xF6, 0xC1, 0xF0,
                    // 0x04: JZ        0x1a
                    0x74, 0x14,
                    // 0x06: CMP       byte ptr [rcx+0x2e0], 0x2a
                    0x80, 0xB9, 0xe0, 0x02, 0x00, 0x00, 0x2A,
                    // 0x0D: BT        dword ptr [rcx+0x2e0], 0x08
                    0x0f, 0xba, 0xa1, 0xe0, 0x02, 0x00, 0x00, 0x08,
                    // 0x15: JNZ       0x1a
                    0x75, 0x03,
                    // 0x17: JNC       0x1a
                    0x73, 0x01,
                    // 0x19: INT3
                    0xCC,
                    // 0x1A: JMP       0x1f
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x19,
                .RelocatedCodeOffset    = 0x1a,
            },

            {
                .MinVersion    = 9600,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x20,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rsp+0x28], 0xf0
                    0xF6, 0x44, 0x24, 0x28, 0xF0,
                    // 0x05: JZ        0x1b
                    0x74, 0x14,
                    // 0x07: CMP       byte ptr [rdx+0x438], 0x2a
                    0x80, 0xBA, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x0E: BT        dword ptr [rdx+0x438], 0x08
                    0x0f, 0xba, 0xa2, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x16: JNZ       0x1b
                    0x75, 0x03,
                    // 0x18: JNC       0x1b
                    0x73, 0x01,
                    // 0x1A: INT3
                    0xCC,
                    // 0x1B: JMP       0x20
                    0xE9, 0x00, 0x00, 0x00, 0x00,
                },
                .HypercallOffset        = 0x1a,
                .RelocatedCodeOffset    = 0x1b,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiDeleteVirtualAddresses",
        .MinVersion    = DETOUR_MIN_VERSION_ANY,
        .MaxVersion    = 16299,
        .Callback      = IntWinVadHandleDeleteVaRange,
        .PreCallback   = IntWinVadPatchDeleteVaRange,
        .Tag           = detTagVaDelete,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 4,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x38,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: PUSH      rcx
                    0x51,
                    // 0x02: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x0B: MOV       rax, qword ptr [rcx+0x70]
                    0x48, 0x8B, 0x81, 0x70, 0x00, 0x00, 0x00,
                    // 0x12: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x14: JNZ       0x1d
                    0x75, 0x07,
                    // 0x16: MOV       rax, qword ptr [rcx+0x210]
                    0x48, 0x8B, 0x81, 0x10, 0x02, 0x00, 0x00,
                    // 0x1D: CMP       byte ptr [rax+0x2e0], 0x2a
                    0x80, 0xB8, 0xE0, 0x02, 0x00, 0x00, 0x2A,
                    // 0x24: BT        dword ptr [rax+0x2e0], 0x08
                    0x0f, 0xba, 0xa0, 0xe0, 0x02, 0x00, 0x00, 0x08,
                    // 0x2C: POP       rcx
                    0x59,
                    // 0x2D: POP       rax
                    0x58,
                    // 0x2E: JNZ       0x33
                    0x75, 0x03,
                    // 0x30: JNC       0x33
                    0x73, 0x01,
                    // 0x32: INT3
                    0xCC,
                    // 0x33: JMP       0x38
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x32,
                .RelocatedCodeOffset    = 0x33,
            },

            {
                .MinVersion    = 9200,
                .MaxVersion    = 9600,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x38,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: PUSH      rcx
                    0x51,
                    // 0x02: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x0B: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x12: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x14: JNZ       0x1d
                    0x75, 0x07,
                    // 0x16: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x1D: CMP       byte ptr [rax+0x438], 0x2a
                    0x80, 0xB8, 0x38, 0x04, 0x00, 0x00, 0x2A,
                    // 0x24: BT        dword ptr [rax+0x438], 0x08
                    0x0f, 0xba, 0xa0, 0x38, 0x04, 0x00, 0x00, 0x08,
                    // 0x2C: POP       rcx
                    0x59,
                    // 0x2D: POP       rax
                    0x58,
                    // 0x2E: JNZ       0x33
                    0x75, 0x03,
                    // 0x30: JNC       0x33
                    0x73, 0x01,
                    // 0x32: INT3
                    0xCC,
                    // 0x33: JMP       0x38
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x32,
                .RelocatedCodeOffset    = 0x33,
            },

            {
                .MinVersion    = 10240,
                .MaxVersion    = 10240,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x38,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: PUSH      rcx
                    0x51,
                    // 0x02: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x0B: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x12: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x14: JNZ       0x1d
                    0x75, 0x07,
                    // 0x16: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x1D: CMP       byte ptr [rax+0x448], 0x2a
                    0x80, 0xB8, 0x48, 0x04, 0x00, 0x00, 0x2A,
                    // 0x24: BT        dword ptr [rax+0x448], 0x08
                    0x0f, 0xba, 0xa0, 0x48, 0x04, 0x00, 0x00, 0x08,
                    // 0x2C: POP       rcx
                    0x59,
                    // 0x2D: POP       rax
                    0x58,
                    // 0x2E: JNZ       0x33
                    0x75, 0x03,
                    // 0x30: JNC       0x33
                    0x73, 0x01,
                    // 0x32: INT3
                    0xCC,
                    // 0x33: JMP       0x38
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x32,
                .RelocatedCodeOffset    = 0x33,
            },

            {
                .MinVersion    = 10586,
                .MaxVersion    = 16299,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x38,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: PUSH      rcx
                    0x51,
                    // 0x02: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x0B: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x12: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x14: JNZ       0x1d
                    0x75, 0x07,
                    // 0x16: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x1D: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x24: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x2C: POP       rcx
                    0x59,
                    // 0x2D: POP       rax
                    0x58,
                    // 0x2E: JNZ       0x33
                    0x75, 0x03,
                    // 0x30: JNC       0x33
                    0x73, 0x01,
                    // 0x32: INT3
                    0xCC,
                    // 0x33: JMP       0x38
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x32,
                .RelocatedCodeOffset    = 0x33,
            },
        },
    },

    {
        .ModuleName    = u"ntoskrnl.exe",
        .FunctionName  = "MiFinishVadDeletion",
        .MinVersion    = 17134,
        .MaxVersion    = DETOUR_MAX_VERSION_ANY,
        .Callback      = IntWinVadHandleFinishVadDeletion,
        .PreCallback   = IntWinVadPatchFinishVadDeletion,
        .Tag           = detTagFinishVadDeletion,
        .Exported      = FALSE,
        .NotCritical   = FALSE,
        .DisableFlags  = 0,
        .EnableFlags   = INTRO_OPT_ENABLE_UM_PROTECTION | INTRO_OPT_ENABLE_MISC_EVENTS,
        .Arguments     = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 2,
        .Handlers =
        {
            {
                .MinVersion    = 17134,
                .MaxVersion    = 17763,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x30], 0x10
                    0xF6, 0x41, 0x30, 0x10,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset = 0x38,
                .RelocatedCodeOffset = 0x39,
            },
            // 19H1
            {
                .MinVersion = 18362,
                .MaxVersion = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x3e,
                .Code =
                {
                    // 0x00: TEST      byte ptr [rcx+0x31], 0x01
                    0xf6, 0x41, 0x31, 0x01,
                    // 0x04: JZ        0x39
                    0x74, 0x33,
                    // 0x06: PUSH      rax
                    0x50,
                    // 0x07: PUSH      rcx
                    0x51,
                    // 0x08: MOV       rcx, qword ptr gs:[0x188]
                    0x65, 0x48, 0x8B, 0x0C, 0x25, 0x88, 0x01, 0x00, 0x00,
                    // 0x11: MOV       rax, qword ptr [rcx+0xb8]
                    0x48, 0x8B, 0x81, 0xB8, 0x00, 0x00, 0x00,
                    // 0x18: TEST      eax, eax
                    0x85, 0xC0,
                    // 0x1A: JNZ       0x23
                    0x75, 0x07,
                    // 0x1C: MOV       rax, qword ptr [rcx+0x220]
                    0x48, 0x8B, 0x81, 0x20, 0x02, 0x00, 0x00,
                    // 0x23: CMP       byte ptr [rax+0x450], 0x2a
                    0x80, 0xB8, 0x50, 0x04, 0x00, 0x00, 0x2A,
                    // 0x2A: BT        dword ptr [rax+0x450], 0x08
                    0x0f, 0xba, 0xa0, 0x50, 0x04, 0x00, 0x00, 0x08,
                    // 0x32: POP       rcx
                    0x59,
                    // 0x33: POP       rax
                    0x58,
                    // 0x34: JNZ       0x39
                    0x75, 0x03,
                    // 0x36: JNC       0x39
                    0x73, 0x01,
                    // 0x38: INT3
                    0xCC,
                    // 0x39: JMP       0x3e
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x38,
                .RelocatedCodeOffset    = 0x39,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "NtSetSystemPowerState",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntWinPowHandlePowerStateChange,
        .Tag            = detTagPowerState,
        .Exported       = FALSE,
        .NotCritical    = TRUE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers =
        {
            {
                .MinVersion     = DETOUR_MIN_VERSION_ANY,
                .MaxVersion     = DETOUR_MAX_VERSION_ANY,
                .HypercallType  = hypercallTypeInt3,

                .CodeLength = 0xF,
                .Code =
                {
                    // 0x00: INT3
                    0xcc,
                    // 0x01: NOP
                    0x66, 0x66, 0x66, 0x66, 0x90,
                    // 0x06: NOP
                    0x66, 0x90,
                    // 0x08: NOP
                    0x66, 0x90,
                    // 0x0A: JMP       0xf
                    0xe9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0x0,
                .RelocatedCodeOffset    = 0xA,
                .PublicDataOffsets = {
                    {
                        .PublicDataName = "5bytenop",
                        .PublicDataOffset = 0x1,
                        .PublicDataSize = 0x5
                    },
                    {
                        .PublicDataName = "spinwait",
                        .PublicDataOffset = 0x6,
                        .PublicDataSize = 0x4
                    },
                },
                .NrPublicDataOffsets    = 2,
            },
        },
    },

    /// IMPORTANT: Functions that may not be hooked on resume from hibernation must be the last ones hooked! This
    /// allows the hook handlers to be placed at deterministic addresses inside the slack space, on both normal
    /// boot and resume from hibernation; if optional functions are hooked during normal boot but not during
    /// resume, this will shift all hook handlers, thus allowing any saved RIPs to point inside the wrong handler.

    //
    // Monstrous hack on order to avoid reads made by RtlpVirtualUnwind...
    //
    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind1",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind1,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x81,
                .Code =
                {
                    // 0x00: CLI
                    0xFA,
                    // 0x01: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x03: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x09: JZ        0x79
                    0x74, 0x6E,
                    // 0x0B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x0D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x13: JZ        0x79
                    0x74, 0x64,
                    // 0x15: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x17: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x1D: JZ        0x79
                    0x74, 0x5A,
                    // 0x1F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x21: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x27: JZ        0x79
                    0x74, 0x50,
                    // 0x29: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x2B: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x31: JZ        0x79
                    0x74, 0x46,
                    // 0x33: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x35: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x3B: JZ        0x79
                    0x74, 0x3C,
                    // 0x3D: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x3F: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x45: JZ        0x79
                    0x74, 0x32,
                    // 0x47: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x49: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x4F: JZ        0x79
                    0x74, 0x28,
                    // 0x51: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x53: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x59: JZ        0x79
                    0x74, 0x1E,
                    // 0x5B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x5D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x63: JZ        0x79
                    0x74, 0x14,
                    // 0x65: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x67: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x6D: JZ        0x79
                    0x74, 0x0A,
                    // 0x6F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x71: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x77: JZ        0x79
                    0x74, 0x00,
                    // 0x79: STI
                    0xFB,
                    // 0x7A: JZ        0x7e
                    0x74, 0x02,
                    // mov al, [rcx] comes here, it is two bytes
                    // the rest of the instructions come here.
                    // 0x7C: JMP       0x81
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x7C,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind2",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind2,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x81,
                .Code =
                {
                    // 0x00: CLI
                    0xFA,
                    // 0x01: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x03: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x09: JZ        0x79
                    0x74, 0x6E,
                    // 0x0B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x0D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x13: JZ        0x79
                    0x74, 0x64,
                    // 0x15: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x17: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x1D: JZ        0x79
                    0x74, 0x5A,
                    // 0x1F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x21: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x27: JZ        0x79
                    0x74, 0x50,
                    // 0x29: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x2B: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x31: JZ        0x79
                    0x74, 0x46,
                    // 0x33: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x35: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x3B: JZ        0x79
                    0x74, 0x3C,
                    // 0x3D: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x3F: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x45: JZ        0x79
                    0x74, 0x32,
                    // 0x47: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x49: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x4F: JZ        0x79
                    0x74, 0x28,
                    // 0x51: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x53: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x59: JZ        0x79
                    0x74, 0x1E,
                    // 0x5B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x5D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x63: JZ        0x79
                    0x74, 0x14,
                    // 0x65: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x67: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x6D: JZ        0x79
                    0x74, 0x0A,
                    // 0x6F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x71: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x77: JZ        0x79
                    0x74, 0x00,
                    // 0x79: STI
                    0xFB,
                    // 0x7A: JZ        0x7f
                    0x74, 0x03,
                    // mov     al, [rcx+1] comes here, 3 bytes
                    // 0x7C: JMP       0x81
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x7C,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind3",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind3,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion = 7600,
                .MaxVersion    = 7602,

                .HypercallType = hypercallTypeInt3,
                .CodeLength = 0x81,
                .Code =
                {
                    // 0x00: CLI
                    0xFA,
                    // 0x01: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x03: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x09: JZ        0x79
                    0x74, 0x6E,
                    // 0x0B: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x0D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x13: JZ        0x79
                    0x74, 0x64,
                    // 0x15: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x17: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x1D: JZ        0x79
                    0x74, 0x5A,
                    // 0x1F: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x21: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x27: JZ        0x79
                    0x74, 0x50,
                    // 0x29: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x2B: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x31: JZ        0x79
                    0x74, 0x46,
                    // 0x33: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x35: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x3B: JZ        0x79
                    0x74, 0x3C,
                    // 0x3D: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x3F: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x45: JZ        0x79
                    0x74, 0x32,
                    // 0x47: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x49: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x4F: JZ        0x79
                    0x74, 0x28,
                    // 0x51: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x53: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x59: JZ        0x79
                    0x74, 0x1E,
                    // 0x5B: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x5D: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x63: JZ        0x79
                    0x74, 0x14,
                    // 0x65: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x67: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x6D: JZ        0x79
                    0x74, 0x0A,
                    // 0x6F: MOV       dl, 0x00
                    0xB2, 0x00,
                    // 0x71: CMP       ecx, 0x00000000
                    0x81, 0xF9, 0x00, 0x00, 0x00, 0x00,
                    // 0x77: JZ        0x79
                    0x74, 0x00,
                    // 0x79: STI
                    0xFB,
                    // 0x7A: JZ        0x7e
                    0x74, 0x02,
                    // mov     dl, [rcx] 2 bytes
                    // 0x7C: JMP       0x81
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x7C,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind4",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind4,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x81,
                .Code =
                {
                    // 0x00: CLI
                    0xFA,
                    // 0x01: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x03: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x09: JZ        0x79
                    0x74, 0x6E,
                    // 0x0B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x0D: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x13: JZ        0x79
                    0x74, 0x64,
                    // 0x15: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x17: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x1D: JZ        0x79
                    0x74, 0x5A,
                    // 0x1F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x21: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x27: JZ        0x79
                    0x74, 0x50,
                    // 0x29: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x2B: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x31: JZ        0x79
                    0x74, 0x46,
                    // 0x33: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x35: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x3B: JZ        0x79
                    0x74, 0x3C,
                    // 0x3D: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x3F: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x45: JZ        0x79
                    0x74, 0x32,
                    // 0x47: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x49: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x4F: JZ        0x79
                    0x74, 0x28,
                    // 0x51: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x53: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x59: JZ        0x79
                    0x74, 0x1E,
                    // 0x5B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x5D: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x63: JZ        0x79
                    0x74, 0x14,
                    // 0x65: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x67: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x6D: JZ        0x79
                    0x74, 0x0A,
                    // 0x6F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x71: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x77: JZ        0x79
                    0x74, 0x00,
                    // 0x79: STI
                    0xFB,
                    // 0x7A: JZ        0x7f
                    0x74, 0x03,
                    // mov     al, [rbp+1]
                    // 0x7C: JMP       0x81
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x7C,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind5",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind5,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion = 7600,
                .MaxVersion    = 7602,

                .HypercallType = hypercallTypeInt3,
                .CodeLength = 0x89,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: CLI
                    0xFA,
                    // 0x02: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x08: JNZ       0x12
                    0x75, 0x08,
                    // 0x0A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x0C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x0E: STI
                    0xFB,
                    // 0x0F: POP       rax
                    0x58,
                    // 0x10: JMP       0x88
                    0xEB, 0x76,
                    // 0x12: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x18: JNZ       0x22
                    0x75, 0x08,
                    // 0x1A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x1C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x1E: STI
                    0xFB,
                    // 0x1F: POP       rax
                    0x58,
                    // 0x20: JMP       0x88
                    0xEB, 0x66,
                    // 0x22: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x28: JNZ       0x32
                    0x75, 0x08,
                    // 0x2A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x2C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x2E: STI
                    0xFB,
                    // 0x2F: POP       rax
                    0x58,
                    // 0x30: JMP       0x88
                    0xEB, 0x56,
                    // 0x32: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x38: JNZ       0x42
                    0x75, 0x08,
                    // 0x3A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x3C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x3E: STI
                    0xFB,
                    // 0x3F: POP       rax
                    0x58,
                    // 0x40: JMP       0x88
                    0xEB, 0x46,
                    // 0x42: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x48: JNZ       0x52
                    0x75, 0x08,
                    // 0x4A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x4C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x4E: STI
                    0xFB,
                    // 0x4F: POP       rax
                    0x58,
                    // 0x50: JMP       0x88
                    0xEB, 0x36,
                    // 0x52: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x58: JNZ       0x62
                    0x75, 0x08,
                    // 0x5A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x5C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x5E: STI
                    0xFB,
                    // 0x5F: POP       rax
                    0x58,
                    // 0x60: JMP       0x88
                    0xEB, 0x26,
                    // 0x62: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x68: JNZ       0x72
                    0x75, 0x08,
                    // 0x6A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x6C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x6E: STI
                    0xFB,
                    // 0x6F: POP       rax
                    0x58,
                    // 0x70: JMP       0x88
                    0xEB, 0x16,
                    // 0x72: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x78: JNZ       0x82
                    0x75, 0x08,
                    // 0x7A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x7C: CMP       al, 0x48
                    0x3C, 0x48,
                    // 0x7E: STI
                    0xFB,
                    // 0x7F: POP       rax
                    0x58,
                    // 0x80: JMP       0x88
                    0xEB, 0x06,
                    // 0x82: STI
                    0xFB,
                    // 0x83: POP       rax
                    0x58,
                    // 4 bytes of CMP [rbp], imm comes here
                    // 0x84: JMP       0x89
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x84,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind6",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind6,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x81,
                .Code =
                {
                    // 0x00: CLI
                    0xFA,
                    // 0x01: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x03: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x09: JZ        0x79
                    0x74, 0x6E,
                    // 0x0B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x0D: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x13: JZ        0x79
                    0x74, 0x64,
                    // 0x15: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x17: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x1D: JZ        0x79
                    0x74, 0x5A,
                    // 0x1F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x21: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x27: JZ        0x79
                    0x74, 0x50,
                    // 0x29: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x2B: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x31: JZ        0x79
                    0x74, 0x46,
                    // 0x33: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x35: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x3B: JZ        0x79
                    0x74, 0x3C,
                    // 0x3D: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x3F: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x45: JZ        0x79
                    0x74, 0x32,
                    // 0x47: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x49: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x4F: JZ        0x79
                    0x74, 0x28,
                    // 0x51: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x53: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x59: JZ        0x79
                    0x74, 0x1E,
                    // 0x5B: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x5D: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x63: JZ        0x79
                    0x74, 0x14,
                    // 0x65: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x67: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x6D: JZ        0x79
                    0x74, 0x0A,
                    // 0x6F: MOV       al, 0x00
                    0xB0, 0x00,
                    // 0x71: CMP       ebp, 0x00000000
                    0x81, 0xFD, 0x00, 0x00, 0x00, 0x00,
                    // 0x77: JZ        0x79
                    0x74, 0x00,
                    // 0x79: STI
                    0xFB,
                    // 0x7A: JZ        0x7f
                    0x74, 0x03,
                    // mov     al, [rbp + 0]
                    // 0x7C: JMP       0x81
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x7C,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind7",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind7,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x89,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: CLI
                    0xFA,
                    // 0x02: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x08: JNZ       0x12
                    0x75, 0x08,
                    // 0x0A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x0C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x0E: STI
                    0xFB,
                    // 0x0F: POP       rax
                    0x58,
                    // 0x10: JMP       0x88
                    0xEB, 0x76,
                    // 0x12: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x18: JNZ       0x22
                    0x75, 0x08,
                    // 0x1A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x1C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x1E: STI
                    0xFB,
                    // 0x1F: POP       rax
                    0x58,
                    // 0x20: JMP       0x88
                    0xEB, 0x66,
                    // 0x22: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x28: JNZ       0x32
                    0x75, 0x08,
                    // 0x2A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x2C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x2E: STI
                    0xFB,
                    // 0x2F: POP       rax
                    0x58,
                    // 0x30: JMP       0x88
                    0xEB, 0x56,
                    // 0x32: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x38: JNZ       0x42
                    0x75, 0x08,
                    // 0x3A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x3C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x3E: STI
                    0xFB,
                    // 0x3F: POP       rax
                    0x58,
                    // 0x40: JMP       0x88
                    0xEB, 0x46,
                    // 0x42: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x48: JNZ       0x52
                    0x75, 0x08,
                    // 0x4A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x4C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x4E: STI
                    0xFB,
                    // 0x4F: POP       rax
                    0x58,
                    // 0x50: JMP       0x88
                    0xEB, 0x36,
                    // 0x52: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x58: JNZ       0x62
                    0x75, 0x08,
                    // 0x5A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x5C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x5E: STI
                    0xFB,
                    // 0x5F: POP       rax
                    0x58,
                    // 0x60: JMP       0x88
                    0xEB, 0x26,
                    // 0x62: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x68: JNZ       0x72
                    0x75, 0x08,
                    // 0x6A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x6C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x6E: STI
                    0xFB,
                    // 0x6F: POP       rax
                    0x58,
                    // 0x70: JMP       0x88
                    0xEB, 0x16,
                    // 0x72: CMP       ebp, 0xbdbdbdbd
                    0x81, 0xFD, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x78: JNZ       0x82
                    0x75, 0x08,
                    // 0x7A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x7C: CMP       al, 0x8d
                    0x3C, 0x8D,
                    // 0x7E: STI
                    0xFB,
                    // 0x7F: POP       rax
                    0x58,
                    // 0x80: JMP       0x88
                    0xEB, 0x06,
                    // 0x82: STI
                    0xFB,
                    // 0x83: POP       rax
                    0x58,
                    // 4 bytes of CMP [rbp], imm comes here
                    // 0x84: JMP       0x89
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x84,
            },
        },
    },

    {
        .ModuleName = u"ntoskrnl.exe",
        .FunctionName = "RtlpVirtualUnwind8",
        .MinVersion = 7600,
        .MaxVersion = 7602,
        .Callback = NULL,
        .Tag = detTagRtlVirtualUnwind8,
        .Exported = FALSE,
        .NotCritical = TRUE,
        .DisableFlags = 0,
        .EnableFlags = DETOUR_ENABLE_ALWAYS,
        .Arguments = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount = 1,
        .Handlers =
        {
            {
                .MinVersion    = 7600,
                .MaxVersion    = 7602,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x89,
                .Code =
                {
                    // 0x00: PUSH      rax
                    0x50,
                    // 0x01: CLI
                    0xFA,
                    // 0x02: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x08: JNZ       0x12
                    0x75, 0x08,
                    // 0x0A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x0C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x0E: STI
                    0xFB,
                    // 0x0F: POP       rax
                    0x58,
                    // 0x10: JMP       0x88
                    0xEB, 0x76,
                    // 0x12: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x18: JNZ       0x22
                    0x75, 0x08,
                    // 0x1A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x1C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x1E: STI
                    0xFB,
                    // 0x1F: POP       rax
                    0x58,
                    // 0x20: JMP       0x88
                    0xEB, 0x66,
                    // 0x22: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x28: JNZ       0x32
                    0x75, 0x08,
                    // 0x2A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x2C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x2E: STI
                    0xFB,
                    // 0x2F: POP       rax
                    0x58,
                    // 0x30: JMP       0x88
                    0xEB, 0x56,
                    // 0x32: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x38: JNZ       0x42
                    0x75, 0x08,
                    // 0x3A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x3C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x3E: STI
                    0xFB,
                    // 0x3F: POP       rax
                    0x58,
                    // 0x40: JMP       0x88
                    0xEB, 0x46,
                    // 0x42: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x48: JNZ       0x52
                    0x75, 0x08,
                    // 0x4A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x4C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x4E: STI
                    0xFB,
                    // 0x4F: POP       rax
                    0x58,
                    // 0x50: JMP       0x88
                    0xEB, 0x36,
                    // 0x52: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x58: JNZ       0x62
                    0x75, 0x08,
                    // 0x5A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x5C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x5E: STI
                    0xFB,
                    // 0x5F: POP       rax
                    0x58,
                    // 0x60: JMP       0x88
                    0xEB, 0x26,
                    // 0x62: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x68: JNZ       0x72
                    0x75, 0x08,
                    // 0x6A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x6C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x6E: STI
                    0xFB,
                    // 0x6F: POP       rax
                    0x58,
                    // 0x70: JMP       0x88
                    0xEB, 0x16,
                    // 0x72: CMP       ecx, 0xbdbdbdbd
                    0x81, 0xF9, 0xBD, 0xBD, 0xBD, 0xBD,
                    // 0x78: JNZ       0x82
                    0x75, 0x08,
                    // 0x7A: MOV       al, 0xbd
                    0xB0, 0xBD,
                    // 0x7C: CMP       al, 0xff
                    0x3C, 0xFF,
                    // 0x7E: STI
                    0xFB,
                    // 0x7F: POP       rax
                    0x58,
                    // 0x80: JMP       0x88
                    0xEB, 0x06,
                    // 0x82: STI
                    0xFB,
                    // 0x83: POP       rax
                    0x58,
                    // 4 bytes of CMP [rbp], imm comes here
                    // 0x84: JMP       0x89
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset        = 0xFF,
                .RelocatedCodeOffset    = 0x84,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "KiDisplayBlueScreen",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntGuestUninitOnBugcheck,
        .Tag            = detTagCleanupMemDump,
        .Exported       = FALSE,
        .NotCritical    = TRUE,
        .DisableFlags   = 0,
        .EnableFlags    = INTRO_OPT_BUGCHECK_CLEANUP,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers       =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset     = 0x0,
                .RelocatedCodeOffset = 0x3,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "MmInSwapProcessHijack",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .Callback       = IntWinProcSwapIn,
        .Tag            = detTagProcSwapIn,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers       =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x8,
                .Code =
                {
                    // 0x00: INT3
                    0xCC,
                    // 0x01: NOP
                    0x90,
                    // 0x02: NOP
                    0x90,
                    // 0x03: JMP       0x8
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset     = 0x0,
                .RelocatedCodeOffset = 0x3,
            },
        },
    },

    {
        .ModuleName     = u"ntoskrnl.exe",
        .FunctionName   = "KiOutSwapProcessesHijack",
        .MinVersion     = DETOUR_MIN_VERSION_ANY,
        .MaxVersion     = DETOUR_MAX_VERSION_ANY,
        .PreCallback    = IntWinProcPatchSwapOut64,
        .Callback       = IntWinProcSwapOut,
        .Tag            = detTagProcSwapOut,
        .Exported       = FALSE,
        .NotCritical    = FALSE,
        .DisableFlags   = 0,
        .EnableFlags    = DETOUR_ENABLE_ALWAYS,
        .Arguments      = DET_ARGS_DEFAULT_WIN64,
        .HandlersCount  = 1,
        .Handlers       =
        {
            {
                .MinVersion    = DETOUR_MIN_VERSION_ANY,
                .MaxVersion    = DETOUR_MAX_VERSION_ANY,
                .HypercallType = hypercallTypeInt3,

                .CodeLength = 0x16,
                .Code =
                {
                    // 0x00: PUSH       rax
                    0x50,
                    // 0x01: MOV        rax, QWORD PTR [rbx + _EPROCESS.Flags]
                    0x48, 0x8B, 0x83, 0x00, 0x00, 0x00, 0x00,
                    // 0x08: BT         rax, 0x07
                    0x48, 0x0f, 0xba, 0xe0, 0x07,
                    // 0x0D: JNC        0x10
                    0x73, 0x01,
                    // 0x0F: INT3
                    0xCC,
                    // 0x10: POP        rax
                    0x58,
                    // 0x11: JMP        0x16
                    0xE9, 0x00, 0x00, 0x00, 0x00
                },
                .HypercallOffset     = 0x0F,
                .RelocatedCodeOffset = 0x11,
            },
        },
    },
};

/// The number of functions to be hooked for 64-bit Windows guests.
const size_t gHookableApisX64Size = ARRAYSIZE(gHookableApisX64);

