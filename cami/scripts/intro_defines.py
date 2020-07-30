#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#

defines = {
    "MAX_VERSION_STRING_SIZE"     : 64,
    "CAMI_MAGIC_WORD"             : 0x494d4143  # CAMI
    }

version_any = {
    "WIN_PATTERN_MIN_VERSION_ANY" : 0,
    "WIN_PATTERN_MAX_VERSION_ANY" : 0xFFFFFFFF
    }

section_hints = {
    "supported_os": 0x0001,
    "syscalls"    : 0x0002,
    "dist_sigs"   : 0x0004,
    "linux"       : 0x0200,
    "windows"     : 0x0100,
    }

process_options_flags = {
    "name_utf16": 0x0001,
}

# those defines, save the stack ones, match the REG_* from disasm/registers.h
detour_args = {
    # describes arguments passed through GPRs.
    "DET_ARG_RAX": 0,
    "DET_ARG_RCX": 1,
    "DET_ARG_RDX": 2,
    "DET_ARG_RBX": 3,
    "DET_ARG_RSP": 4,
    "DET_ARG_RBP": 5,
    "DET_ARG_RSI": 6,
    "DET_ARG_RDI": 7,
    "DET_ARG_R8": 8,
    "DET_ARG_R9": 9,
    "DET_ARG_R10": 10,
    "DET_ARG_R11": 11,
    "DET_ARG_R12": 12,
    "DET_ARG_R13": 13,
    "DET_ARG_R14": 14,
    "DET_ARG_R15": 15,
    # describes arguments passed through the stack.
    "DET_ARG_STACK0": 0x0FFFF,
    "DET_ARG_STACK1": 0x1FFFF,
    "DET_ARG_STACK2": 0x2FFFF,
    "DET_ARG_STACK3": 0x3FFFF,
    "DET_ARG_STACK4": 0x4FFFF,
    "DET_ARG_STACK5": 0x5FFFF,
    "DET_ARG_STACK6": 0x6FFFF,
    "DET_ARG_STACK7": 0x7FFFF,
    "DET_ARG_STACK8": 0x8FFFF,
    "DET_ARG_STACK9": 0x9FFFF,
    "DET_ARG_STACK10": 0xAFFFF,
    "DET_ARG_STACK11": 0xBFFFF,
    "DET_ARG_STACK12": 0xCFFFF,
    "DET_ARG_STACK13": 0xDFFFF,
    "DET_ARG_STACK14": 0xEFFFF,
    "DET_ARG_STACK15": 0xFFFFF,
    "DET_ARGS_MAX": 8,
}


intro_options = {
    "NONE"                           : 0x000000000000000,
    "PROT_KM_NT"                     : 0x0000000000000001,
    "PROT_KM_HAL"                    : 0x0000000000000002,
    "PROT_KM_SSDT"                   : 0x0000000000000004,
    "PROT_KM_IDT"                    : 0x0000000000000008,
    "PROT_KM_HDT"                    : 0x0000000000000010,
    "PROT_KM_SYSTEM_CR3"             : 0x0000000000000020,
    "PROT_KM_TOKENS"                 : 0x0000000000000040,
    "PROT_KM_NT_DRIVERS"             : 0x0000000000000080,
    "PROT_KM_AV_DRIVERS"             : 0x0000000000000100,
    "PROT_KM_XEN_DRIVERS"            : 0x0000000000000200,
    "PROT_KM_DRVOBJ"                 : 0x0000000000000400,
    "PROT_KM_CR4"                    : 0x0000000000000800,
    "PROT_KM_MSR_SYSCALL"            : 0x0000000000001000,
    "PROT_KM_IDTR"                   : 0x0000000000002000,
    "PROT_KM_HAL_HEAP_EXEC"          : 0x0000000000004000,
    "PROT_KM_HAL_INT_CTRL"           : 0x0000000000008000,

    "PROT_UM_MISC_PROCS"             : 0x0000000000010000,
    "PROT_UM_SYS_PROCS"              : 0x0000000000020000,
    "PROT_KM_SELF_MAP_ENTRY"         : 0x0000000000040000,
    "PROT_KM_GDTR"                   : 0x0000000000080000,

    "EVENT_PROCESSES"                : 0x0000000000100000,
    "EVENT_MODULES"                  : 0x0000000000200000,
    "EVENT_OS_CRASH"                 : 0x0000000000400000,
    "EVENT_PROCESS_CRASH"            : 0x0000000000800000,

    "AGENT_INJECTION"                : 0x0000000001000000,
    "FULL_PATH"                      : 0x0000000002000000,
    "KM_BETA_DETECTIONS"             : 0x0000000004000000,
    "NOTIFY_ENGINES"                 : 0x0000000008000000,
    "IN_GUEST_PT_FILTER"             : 0x0000000010000000,
    "BUGCHECK_CLEANUP"               : 0x0000000020000000,
    "SYSPROC_BETA_DETECTIONS"        : 0x0000000040000000,
    "VE"                             : 0x0000000080000000,
    "ENABLE_CONNECTION_EVENTS"       : 0x0000000100000000,

    "PROT_KM_LOGGER_CONTEXT"         : 0x0000000200000000,

    "DPI_DEBUG"                      : 0x0000000400000000,
    "DPI_STACK_PIVOT"                : 0x0000000800000000,
    "DPI_TOKEN_STEAL"                : 0x0000001000000000,
    "DPI_HEAP_SPRAY"                 : 0x0000002000000000,
    "NT_EAT_READS"                   : 0x0000004000000000,

# Process options
    "RESERVED_1"                     : 0x00000001,
    "RESERVED_2"                     : 0x00000002,
    "HOOKS"                          : 0x00000004,
    "CORE_HOOKS"                     : 0x00000004,
    "UNPACK"                         : 0x00000008,
    "WRITE_MEM"                      : 0x00000010,
    "WSOCK_HOOKS"                    : 0x00000020,
    "EXPLOIT"                        : 0x00000040,
    "SET_THREAD_CTX"                 : 0x00000080,
    "QUEUE_APC"                      : 0x00000100,
    "PREVENT_CHILD_CREATION"         : 0x00000200,
    "DOUBLE_AGENT"                   : 0x00000400,
    "ENG_CMD_LINE"                   : 0x00000800,
    
    "REMEDIATE"                      : 0x20000000,
    "KILL_ON_EXPLOIT"                : 0x40000000,
    "BETA"                           : 0x80000000,
    
# Shemu options
    "NOP_SLED"                       : 0x00000001,
    "LOAD_RIP"                       : 0x00000002,
    "WRITE_SELF"                     : 0x00000004,
    "TIB_ACCESS"                     : 0x00000008,
    "SYSCALL"                        : 0x00000010,
    "STACK_STR"                      : 0x00000020,
}
