/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdint.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#define MAX_ERRNO            4095
#define GFP_KERNEL           0x14000c0

#define O_RDONLY         00000000
#define O_WRONLY         00000001
#define O_RDWR           00000002
#define O_CREAT          00000100
#define O_EXCL           00000200
#define O_TRUNC          00001000

#define S_IRWXU          00700
#define S_IRUSR          00400
#define S_IWUSR          00200
#define S_IXUSR          00100
#define S_IRWXG          00070
#define S_IRGRP          00040
#define S_IWGRP          00020
#define S_IXGRP          00010
#define S_IRWXO          00007
#define S_IROTH          00004
#define S_IWOTH          00002
#define S_IXOTH          00001

#define UMH_NO_WAIT          0
#define UMH_WAIT_EXEC        1
#define UMH_WAIT_PROC        2
#define UMH_KILLABLE         4
#define LIX_NAME_MAX         128

#define KERNEL_VERSION(K, Patch, Sublevel)    ((Sublevel) | ((Patch) << 16) | ((K) << 24))

# define __unreachable  __builtin_unreachable()
# define __likely(x)    __builtin_expect(!!(x), 1)
# define __unlikely(x)  __builtin_expect(!!(x), 0)

#define IS_ERR_VALUE(x) __unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

#define BIT(x)                  (1ULL << (x))
#define UNUSED_PARAMETER(P)     ((void)(P))
#define PAGE_SIZE               0x1000

// The default alignment of agents should be 1, since we don't have that much space and speed insn't a real issue
#define __fn_aligned        __attribute__((aligned(1)))
#define __fn_save_all       __attribute__((no_caller_saved_registers))

#define __section(S)        __attribute__((section (S)))

#define __default_fn_attr   __fn_save_all __fn_aligned
#define __fn_naked          __attribute__((naked))
#define __fn_section(x)     __attribute__((__section__(x)))

#define __aligned(x)          __attribute__((aligned(x)))

///
/// @brief Creates a region for data.
///
/// @param[in]  x   The name of the section prefix.
///
#define __agent_data(x)         __section("." x "_data") __aligned(1)

///
/// @brief Creates a region for source-code.
///
/// @param[in]  x   The name of the section prefix.
///
#define __agent_text(x)         __default_fn_attr __section("." x "_text")

///
/// @brief Creates a section for trampoline.
///
/// @param[in]  x   The name of the section prefix.
///
#define __agent_trampoline(x)   __fn_naked __section("." x "_trampoline")

/// @brief Generates the exit asm-code using a label.
#define __agent_exit(x)             \
        asm(".global __exit_" x);   \
        asm("__exit_" x ":");       \
        asm("int3")

/// @brief Defines an asm string-symbol.
#define GNUASM_DEFINE_STR(SYMBOL, STR) \
    asm volatile ("#define " SYMBOL " " #STR);

/// @brief Defines an asm value.
#define GNUASM_DEFINE_VAL(SYMBOL, VALUE) \
    asm volatile ("#define " SYMBOL " %0" :: "n"(VALUE))

/// @brief Generates the exit asm-code for agents.
#define __exit              \
    asm(".global __exit");  \
    asm("__exit:");         \
    asm("int3")

/// @brief Pushes the exit address on the stack and jumps to the 'do_exit' function in order to terminate the thread.
#define __do_exit(address, do_exit_fn, vfree_fn)        \
    asm volatile("mov rdi, %[_address];"                \
                 "push  %[_do_exit_fn];"                \
                 "jmp %[_vfree_fn];"                    \
                 : : [_address] "rm" (address), [_do_exit_fn] "rm"(do_exit_fn), [_vfree_fn] "rm"(vfree_fn) :)


/// @brief Stores the 'param' in the 'r8' register
#define __breakpoint_param_1(param) \
    register size_t __p1 asm("r8") = (size_t)(param); asm volatile("" :: "r" (__p1));

/// @brief Stores the 'param' in the 'r9' register
#define __breakpoint_param_2(param) \
    register size_t __p2 asm("r9") = (size_t)(param); asm volatile("" :: "r" (__p2));

/// @brief Stores the 'param' in the 'r10' register
#define __breakpoint_param_3(param) \
    register size_t __p3 asm("r10") = (size_t)(param); asm volatile("" :: "r" (__p3));

/// @brief Stores the 'param' in the 'r11' register
#define __breakpoint_param_4(param) \
    register size_t __p4 asm("r11") = (size_t)(param); asm volatile("" :: "r" (__p4));

/// @brief Stores the 'param' in the 'r12' register
#define __breakpoint_param_5(param) \
    register size_t __p5 asm("r12") = (size_t)(param); asm volatile("" :: "r" (__p5));

/// @brief Stores the 'param' in the 'r13' register
#define __breakpoint_param_6(param) \
    register size_t __p6 asm("r13") = (size_t)(param); asm volatile("" :: "r" (__p6));

/// @brief Stores the 'param' in the 'r14' register
#define __breakpoint_param_7(param) \
    register size_t __p7 asm("r14") = (size_t)(param); asm volatile("" :: "r" (__p7));

/// @brief Stores the 'param' in the 'r15' register
#define __breakpoint_param_8(param) \
    register size_t __p8 asm("r15") = (size_t)(param); asm volatile("" :: "r" (__p8));


__default_fn_attr
static inline unsigned long breakpoint(unsigned long token)
///
/// @brief Generate INT3 instruction for hypercall.
///
{
    asm volatile("int3" : "+a"(token) : );
    return token;
}

/// @brief Hypercall using 1 argument.
#define breakpoint_1(token, p1)                         \
({                                                      \
    __breakpoint_param_1(p1);                           \
    breakpoint(token);                                  \
})


/// @brief Hypercall using 2 argument.
#define breakpoint_2(token, p1, p2)                     \
({                                                      \
    __breakpoint_param_1(p1);                           \
    __breakpoint_param_2(p2);                           \
    breakpoint(token);                                  \
})

/// @brief Hypercall using 3 argument.
#define breakpoint_3(token, p1, p2, p3)                 \
({                                                      \
    __breakpoint_param_1(p1);                           \
    __breakpoint_param_2(p2);                           \
    __breakpoint_param_3(p3);                           \
    breakpoint(token);                                  \
})

/// @brief Hypercall using 4 argument.
#define breakpoint_4(token, p1, p2, p3, p4)             \
({                                                      \
    __breakpoint_param_1(p1);                           \
    __breakpoint_param_2(p2);                           \
    __breakpoint_param_3(p3);                           \
    __breakpoint_param_4(p4);                           \
    breakpoint(token);                                  \
})

/// @brief Hypercall using 5 argument.
#define breakpoint_5(token, p1, p2, p3, p4, p5)         \
({                                                      \
    __breakpoint_param_1(p1);                           \
    __breakpoint_param_2(p2);                           \
    __breakpoint_param_3(p3);                           \
    __breakpoint_param_4(p4);                           \
    __breakpoint_param_5(p5);                           \
    breakpoint(token);                                  \
})

/// @brief Hypercall using 6 argument.
#define breakpoint_6(token, p1, p2, p3, p4, p5, p6)     \
({                                                      \
    __breakpoint_param_1(p1);                           \
    __breakpoint_param_2(p2);                           \
    __breakpoint_param_3(p3);                           \
    __breakpoint_param_4(p4);                           \
    __breakpoint_param_5(p5);                           \
    __breakpoint_param_6(p6);                           \
    breakpoint(token);                                  \
})

#endif // !_COMMON_H_
