/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _DEFS_H_
#define _DEES_H_

enum pid_type
{
    PIDTYPE_PID,
    PIDTYPE_TGID,
    PIDTYPE_PGID,
    PIDTYPE_SID,
    PIDTYPE_MAX,
};

enum jump_label_type {
    JUMP_LABEL_NOP = 0,
    JUMP_LABEL_JMP,
};


#define VM_READ                     0x00000001
#define VM_WRITE                    0x00000002
#define VM_EXEC                     0x00000004
#define VM_SHARED                   0x00000008

// limits for mprotect() etc
#define VM_MAYREAD                  0x00000010
#define VM_MAYWRITE                 0x00000020
#define VM_MAYEXEC                  0x00000040
#define VM_MAYSHARE                 0x00000080

#define VM_GROWSDOWN                0x00000100  // general info on the segment
#define VM_UFFD_MISSING             0x00000200  // missing pages tracking
#define VM_PFNMAP                   0x00000400  // Page-ranges managed without "struct page", just pure PFN
#define VM_DENYWRITE                0x00000800  // ETXTBSY on write attempts
#define VM_UFFD_WP                  0x00001000  // write-protect pages tracking

#define VM_LOCKED                   0x00002000
#define VM_IO                       0x00004000  // Memory mapped I/O or similar

// Used by sys_madvise()
#define VM_SEQ_READ                 0x00008000  // App will access data sequentially
#define VM_RAND_READ                0x00010000  // App will not benefit from clustered reads

#define VM_DONTCOPY                 0x00020000  // Do not copy this vma on fork
#define VM_DONTEXPAND               0x00040000  // Cannot expand with mremap()
#define VM_LOCKONFAULT              0x00080000  // Lock the pages covered when they are faulted in
#define VM_ACCOUNT                  0x00100000  // Is a VM accounted object
#define VM_NORESERVE                0x00200000  // should the VM suppress accounting
#define VM_HUGETLB                  0x00400000  // Huge TLB Page VM
#define VM_ARCH_1                   0x01000000  // Architecture-specific flag
#define VM_ARCH_2                   0x02000000
#define VM_DONTDUMP                 0x04000000  // Do not include in the core dump

#define VM_SOFTDIRTY                0x08000000  // Not soft dirty clean area

#define VM_MIXEDMAP                 0x10000000  // Can contain "struct page" and pure PFN pages
#define VM_HUGEPAGE                 0x20000000  // MADV_HUGEPAGE marked this vma
#define VM_NOHUGEPAGE               0x40000000  // MADV_NOHUGEPAGE marked this vma
#define VM_MERGEABLE                0x80000000  // KSM may merge identical pages

#define PTRACE_TRACEME              0
#define PTRACE_PEEKTEXT             1
#define PTRACE_PEEKDATA             2
#define PTRACE_PEEKUSR              3
#define PTRACE_POKETEXT             4
#define PTRACE_POKEDATA             5
#define PTRACE_POKEUSR              6
#define PTRACE_CONT                 7
#define PTRACE_KILL                 8
#define PTRACE_SINGLESTEP           9

#define PTRACE_GETREGS              12
#define PTRACE_SETREGS              13
#define PTRACE_GETFPREGS            14
#define PTRACE_SETFPREGS            15
#define PTRACE_GETFPXREGS           18
#define PTRACE_SETFPXREGS           19

#define PTRACE_ATTACH               16
#define PTRACE_DETACH               17

#define PTRACE_SYSCALL              24

#endif // _DEFS_H_
