/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
//
// Contains various defines & structures (that aren't changed often) form the linux kernel,
// adapted for using by introspection.
//
#ifndef _LIXDEFS_H_
#define _LIXDEFS_H_

//
// fork() flags
//
#define CSIGNAL                     0x000000ff  // signal mask to be sent at exit
#define CLONE_VM                    0x00000100  // set if VM shared between processes
#define CLONE_FS                    0x00000200  // set if fs info shared between processes
#define CLONE_FILES                 0x00000400  // set if open files shared between processes
#define CLONE_SIGHAND               0x00000800  // set if signal handlers and blocked signals shared
#define CLONE_PTRACE                0x00002000  // set if we want to let tracing continue on the child too
#define CLONE_VFORK                 0x00004000  // set if the parent wants the child to wake it up on mm_release
#define CLONE_PARENT                0x00008000  // set if we want to have the same parent as the cloner
#define CLONE_THREAD                0x00010000  // Same thread group?
#define CLONE_NEWNS                 0x00020000  // New namespace group?
#define CLONE_SYSVSEM               0x00040000  // share system V SEM_UNDO semantics
#define CLONE_SETTLS                0x00080000  // create a new TLS for the child
#define CLONE_PARENT_SETTID         0x00100000  // set the TID in the parent
#define CLONE_CHILD_CLEARTID        0x00200000  // clear the TID in the child
#define CLONE_DETACHED              0x00400000  // Unused, ignored
#define CLONE_UNTRACED              0x00800000  // set if the tracing process can't force CLONE_PTRACE on this clone
#define CLONE_CHILD_SETTID          0x01000000  // set the TID in the child
#define CLONE_NEWUTS                0x04000000  // New utsname group?
#define CLONE_NEWIPC                0x08000000  // New ipcs
#define CLONE_NEWUSER               0x10000000  // New user namespace
#define CLONE_NEWPID                0x20000000  // New pid namespace
#define CLONE_NEWNET                0x40000000  // New network namespace
#define CLONE_IO                    0x80000000  // Clone io context


// currently active flags
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



//
// Self reference
//
#define LINUX_PROC_SELF_REFERENCE   "/proc/self/exe"
#define LINUX_PROC_DIR              "/proc/"


//
// ptrace requests
//
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


//
// Used for task_struct->flags
//
#define PF_EXITING                  0x00000004  // getting shut down
#define PF_EXITPIDONE               0x00000008  // pi exit done on shut down
#define PF_VCPU                     0x00000010  // I'm a virtual CPU
#define PF_WQ_WORKER                0x00000020  // I'm a workqueue worker
#define PF_FORKNOEXEC               0x00000040  // forked but didn't exec
#define PF_MCE_PROCESS              0x00000080  // process policy on mce errors
#define PF_SUPERPRIV                0x00000100  // used super-user privileges
#define PF_DUMPCORE                 0x00000200  // dumped core
#define PF_SIGNALED                 0x00000400  // killed by a signal
#define PF_MEMALLOC                 0x00000800  // Allocating memory
#define PF_NPROC_EXCEEDED           0x00001000  // set_user noticed that RLIMIT_NPROC was exceeded
#define PF_USED_MATH                0x00002000  // if unset the fpu must be initialized before use
#define PF_USED_ASYNC               0x00004000  // used async_schedule*(), used by module init
#define PF_NOFREEZE                 0x00008000  // this thread should not be frozen
#define PF_FROZEN                   0x00010000  // frozen for system suspend
#define PF_FSTRANS                  0x00020000  // inside a filesystem transaction
#define PF_KSWAPD                   0x00040000  // I am kswapd
#define PF_MEMALLOC_NOIO            0x00080000  // Allocating memory without IO involved
#define PF_LESS_THROTTLE            0x00100000  // Throttle me less: I clean memory
#define PF_KTHREAD                  0x00200000  // I am a kernel thread
#define PF_RANDOMIZE                0x00400000  // randomize virtual address space
#define PF_SWAPWRITE                0x00800000  // Allowed to write to swap
#define PF_NO_SETAFFINITY           0x04000000  // Userland is not allowed to meddle with cpus_allowed
#define PF_MCE_EARLY                0x08000000  // Early kill for mce process policy
#define PF_MUTEX_TESTER             0x20000000  // Thread belongs to the rt mutex tester
#define PF_FREEZER_SKIP             0x40000000  // Freezer should not count it as freezable
#define PF_SUSPEND_TASK             0x80000000  // this thread called freeze_processes and should not be frozen


//
// sizeof buf inside the linux_binprm
//
#define BINPRM_BUF_SIZE             128


//
// Some errno
//
#ifndef EACCES
#define EACCES                      13
#endif


//
// This is the old-old version of the utsname().
// Does anybody ever compile with this ?!
//
typedef struct _LIX_UTSNAME_OLDOLD
{
    CHAR    SysName[9];
    CHAR    NodeName[9];
    CHAR    Release[9];
    CHAR    Version[9];
    CHAR    Machine[9];
} LIX_UTSNAME_OLDOLD;


//
// This is the old and the new version of the utsname().
// Don't ask why the old and the new are the same in every way...
//
typedef struct _LIX_UTSNAME
{
    CHAR    SysName[65];    // Always "Linux"...
    CHAR    NodeName[65];   // At init may be "(none)" or NULL
    CHAR    Release[65];    // ie. "3.10.0-123.6.3.el7.x86_64"
    CHAR    Version[65];    // ie. "#1 SMP Wed Aug 6 21:12:36 UTC 2014"
    CHAR    Machine[65];    // ie. "x86_64"
} LIX_UTSNAME;


#if !defined(NSIG) && !defined(SIGHUP)
#define NSIG                32

#define SIGHUP              1
#define SIGINT              2
#define SIGQUIT             3
#define SIGILL              4
#define SIGTRAP             5
#define SIGABRT             6
#define SIGIOT              6
#define SIGBUS              7
#define SIGFPE              8
#define SIGKILL             9
#define SIGUSR1             10
#define SIGSEGV             11
#define SIGUSR2             12
#define SIGPIPE             13
#define SIGALRM             14
#define SIGTERM             15
#define SIGSTKFLT           16
#define SIGCHLD             17
#define SIGCONT             18
#define SIGSTOP             19
#define SIGTSTP             20
#define SIGTTIN             21
#define SIGTTOU             22
#define SIGURG              23
#define SIGXCPU             24
#define SIGXFSZ             25
#define SIGVTALRM           26
#define SIGPROF             27
#define SIGWINCH            28
#define SIGIO               29
#define SIGPOLL             SIGIO
// #define SIGLOST             29
#define SIGPWR              30
#define SIGSYS              31
#define SIGUNUSED           31
// These should not be considered constants from userland.
#define SIGRTMIN            32
#define SIGRTMAX            _NSIG
#endif

#define S_IFMT      00170000
#define S_IFSOCK    0140000
#define S_IFLNK     0120000
#define S_IFREG     0100000
#define S_IFBLK     0060000
#define S_IFDIR     0040000
#define S_IFCHR     0020000
#define S_IFIFO     0010000
#define S_ISUID     0004000
#define S_ISGID     0002000
#define S_ISVTX     0001000

#define S_ISLNK(m)  (((m) & S_IFMT) == S_IFLNK)
#define S_ISREG(m)  (((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)  (((m) & S_IFMT) == S_IFDIR)
#define S_ISCHR(m)  (((m) & S_IFMT) == S_IFCHR)
#define S_ISBLK(m)  (((m) & S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m) & S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

#define S_IRWXU     00700
#define S_IRUSR     00400
#define S_IWUSR     00200
#define S_IXUSR     00100

#define S_IRWXG     00070
#define S_IRGRP     00040
#define S_IWGRP     00020
#define S_IXGRP     00010

#define S_IRWXO     00007
#define S_IROTH     00004
#define S_IWOTH     00002
#define S_IXOTH     00001

enum
{
    UNAME26             = 0x0020000,
    ADDR_NO_RANDOMIZE   = 0x0040000,
    FDPIC_FUNCPTRS      = 0x0080000,
    MMAP_PAGE_ZERO      = 0x0100000,
    ADDR_COMPAT_LAYOUT  = 0x0200000,
    READ_IMPLIES_EXEC   = 0x0400000,
    ADDR_LIMIT_32BIT    = 0x0800000,
    SHORT_INODE         = 0x1000000,
    WHOLE_SECONDS       = 0x2000000,
    STICKY_TIMEOUTS     = 0x4000000,
    ADDR_LIMIT_3GB      = 0x8000000,
};

#define PER_CLEAR_ON_SETID (READ_IMPLIES_EXEC  |        \
                            ADDR_NO_RANDOMIZE  |        \
                            ADDR_COMPAT_LAYOUT |        \
                            MMAP_PAGE_ZERO)

#define LIX_PTI_PGTABLE_SWITCH_BIT      12      ///< The bit marking whether the kernel memory is mapped in a PGD.

#define MAX_ERRNO       4095
#define IS_ERR(x)       ((UINT64)(void *)(x) >= (UINT64)-MAX_ERRNO)

typedef enum _LIX_SOCK_STATE
{
    LIX_TCP_ESTABLISHED = 1,
    LIX_TCP_SYN_SENT,
    LIX_TCP_SYN_RECV,
    LIX_TCP_FIN_WAIT1,
    LIX_TCP_FIN_WAIT2,
    LIX_TCP_TIME_WAIT,
    LIX_TCP_CLOSE,
    LIX_TCP_CLOSE_WAIT,
    LIX_TCP_LAST_ACK,
    LIX_TCP_LISTEN,
    LIX_TCP_CLOSING,        // Not a valid state
    LIX_TCP_NEW_SYN_RECV,

    LIX_TCP_MAX_STATES      // Leave at end
} LIX_SOCK_STATE;

typedef struct _LIX_RB_NODE
{
    QWORD ParentColor;
    QWORD Right;
    QWORD Left;
} LIX_RB_NODE;


typedef struct _LIX_TRAP_FRAME
{
    // Don't trust these since they may not be saved
    QWORD R15;
    QWORD R14;
    QWORD R13;
    QWORD R12;
    QWORD Rbp;
    QWORD Rbx;

    // Always saved
    QWORD R11;
    QWORD R10;
    QWORD R9;
    QWORD R8;
    QWORD Rax;
    QWORD Rcx;
    QWORD Rdx;
    QWORD Rsi;
    QWORD Rdi;

    // Syscall number
    QWORD OrigRax;

    // Return frame
    QWORD Rip;
    QWORD Cs;
    QWORD Rflags;
    QWORD Rsp;
    QWORD Ss;

} LIX_TRAP_FRAME;


#endif // _LIXDEFS_H_
