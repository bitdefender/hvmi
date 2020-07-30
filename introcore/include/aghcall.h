/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _AGHCALL_H_
#define _AGHCALL_H_

///
/// @file aghcall.h
///
/// @brief This file contains the private, undocumented hypercalls. They are used only by the loaders and the
/// agent driver.
///
/// Agent hypercall codes. Generic hypercall interface on Xen:
/// x86: EAX = 34, EBX = 24, ECX = 0, args in EDX, ESI, EDI
/// x64: RAX = 34, RDI = 24, RSI = 0, args in RDX, RCX, RBX
/// RDX/EDX will contain agent/introspection specific hypercall code. RCX/ESI and RBX/EDI will contain additional
/// arguments, specific to the agent hypercall code specified in RDX/EDX.
///
/// 1. Stage 1 Loader hypercalls (identified using the RIP)
/// 2. Stage 2 Loader hypercalls (identified using the RIP and tokens)
/// 3. Driver Agent Hypercalls (identified using the RIP and hypercall code):
///

#define AGENT_HCALL_FETCH_CMD       1   ///< Used to get the command structure for the agent.
#define AGENT_HCALL_FETCH_CHUNK     2   ///< Used to get the remediation agent data.
#define AGENT_HCALL_MOD_BASE        3   ///< Used to get the base of the module indicated by edi/rcx.
#define AGENT_HCALL_OWN_BASE        4   ///< Used to get the base of the agent module.
#define AGENT_HCALL_VE              5   ///< Used to get a generically piece of data inside a pre-allocated region.
#define AGENT_HCALL_PT              6   ///< Used to get the PT cache agent.
#define AGENT_HCALL_VCPUID          7   ///< Used to get the ID of the current VCPU.
#define AGENT_HCALL_SYS_LNK         9   ///< Used to get a kernel syscall linkage address.


/// Generic error signaling hypercall.
#define AGENT_HCALL_ERROR           ((DWORD)-1)

#define AGENT_MAX_COMMAND_LINE_LENGTH  1024
#define AGENT_MAX_AGENT_NAME_LENGTH    32

///
/// Possible agent types. Note that not all of them are supported, but they are defined for future use.
///
typedef enum _AGENT_TYPE
{
    AGENT_TYPE_FILE,            ///< File agent. A file will be dropped inside the guest.
    AGENT_TYPE_PROCESS,         ///< Process agent. A process will be injected & started inside the guest.
    AGENT_TYPE_LIBRARY,         ///< A DLL will be injected inside a process. NOT USED!
    AGENT_TYPE_BINARY,          ///< A binary blob of code will be injected and started in the kernel. NOT USED!
    AGENT_TYPE_DRIVER,          ///< A driver will be injected and started inside the kernel. NOT USED!
    AGENT_TYPE_BREAKPOINT,      ///< A single breakpoint will be injected.
    AGENT_TYPE_VE_LOADER,       ///< The VE agent loader.
    AGENT_TYPE_VE_UNLOADER,     ///< The VE agent unloader.
    AGENT_TYPE_PT_LOADER,       ///< The PT filter loader.
    AGENT_TYPE_PT_UNLOADER,     ///< The PT filter unloader.
} AGENT_TYPE;


/// Agent command structure version. Increment this whenever modifying the #AGENT_COMMAND structure.
#define AGENT_COMMAND_VERSION       3


///
/// Structure used by the introbootdrv to request a command from Introcore. The first hypercall issued by
/// introbootdrv will request this data, which tells it what to do.
///
typedef struct _AGENT_COMMAND
{
    unsigned int        Version;    ///< Structure version. Check out #AGENT_COMMAND_VERSION.
    unsigned int        Type;       ///< The agent type. One of #AGENT_TYPE.
    unsigned int        Pid;        ///< The process PID from which to start a process agent.
    unsigned int        Synched;    ///< Always FALSE for now. Will not wait for the process agent to finish.
    unsigned int        Size;       ///< The size of the agent.
    unsigned int        Flags;      ///< Note used.
    unsigned long long  Pointer;    ///< A pointer to the agent contents in guest memory.
    unsigned int        Agid;       ///< Internal use; IT'S NOT the agent tag.

    /// The agent name. This will be the file name or the process name.
    char                Name[AGENT_MAX_AGENT_NAME_LENGTH];

    /// Command line arguments used by the injected process. It is limited to #AGENT_MAX_COMMAND_LINE_LENGTH bytes.
    char                Args[AGENT_MAX_COMMAND_LINE_LENGTH];
} AGENT_COMMAND, *PAGENT_COMMAND;

#endif // _AGHCALL_H_
