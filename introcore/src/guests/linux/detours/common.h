/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _COMMON_H_
#define _COMMON_H_

#include "handlers.h"

#include <stdint.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#define __fn_aligned        __attribute__((aligned(16)))
#define __fn_save_all       __attribute__((no_caller_saved_registers))

#define __section(S)        __attribute__((section (S)))

#define __default_fn_attr   __fn_save_all __fn_aligned
#define __fn_naked          __attribute__((naked))

#define BIT(x)                  (1ULL << (x))
#define UNUSED_PARAMETER(P)     ((void)(P))
#define PAGE_SIZE               0x1000


#define get_jump_back_offset(fn_name)                       \
    (__builtin_offsetof(LIX_HYPERCALL_PAGE, Detours)        \
     + (det_ ## fn_name) * sizeof(LIX_GUEST_DETOUR)         \
     + __builtin_offsetof(LIX_GUEST_DETOUR, JumpBack))

#define get_detour_enable_offset(fn_name)                   \
    (__builtin_offsetof(LIX_HYPERCALL_PAGE, Detours)        \
    + (det_ ## fn_name) * sizeof(LIX_GUEST_DETOUR)          \
    + __builtin_offsetof(LIX_GUEST_DETOUR, EnableOptions))  \

#define GNUASM_DEFINE_STR(SYMBOL, STR) \
    asm volatile ("#define " SYMBOL " " #STR);

#define GNUASM_DEFINE_VAL(SYMBOL, VALUE) \
    asm volatile ("#define " SYMBOL " %0" :: "n"(VALUE))

#define def_detour_asm_vars(fn_name) \
    GNUASM_DEFINE_VAL(#fn_name "_jmp", get_jump_back_offset(fn_name))

#define def_detour_hijack_asm_vars(fn_name, hijack_fn_name) \
    GNUASM_DEFINE_VAL(#fn_name "_" # hijack_fn_name "_jmp", get_jump_back_offset(fn_name ## _ ## hijack_fn_name))

#define def_detour_vars(fn_name)    \
    extern void *fn_name ## _trampoline; extern void *fn_name ## _reloc

#define def_detour_hijack_vars(fn_name, fn_hijack_name) \
    extern void *fn_name ## _ ## fn_hijack_name ## _trampoline; extern void *fn_name ## _ ## fn_hijack_name ## _reloc
#define init_detour_field(fn_name)                              \
    [det_ ## fn_name] = {                                       \
        .Name = #fn_name,                                       \
        .HijackName[0] = '\0',                                  \
        .Address = (unsigned long)&fn_name  ## _trampoline,     \
        .RelocatedCode = (unsigned long)&fn_name  ## _reloc     \
    }

#define init_detour_hijack_field(fn_name, hijack_fn_name)                           \
    [det_ ## fn_name ## _ ## hijack_fn_name] = {                                    \
        .Name = #fn_name,                                                           \
        .HijackName = #hijack_fn_name,                                              \
        .Address = (unsigned long)&fn_name ##  _ ## hijack_fn_name ## _trampoline,  \
        .RelocatedCode = (unsigned long)&fn_name ## _ ## hijack_fn_name ## _reloc   \
    }

#define __vmcall_param_1(param) \
    register size_t __p1 asm("r8") = (size_t)(param); asm volatile("" :: "r" (__p1));

#define __vmcall_param_2(param) \
    register size_t __p2 asm("r9") = (size_t)(param); asm volatile("" :: "r" (__p2));

#define __vmcall_param_3(param) \
    register size_t __p3 asm("r10") = (size_t)(param); asm volatile("" :: "r" (__p3));

#define __vmcall_param_4(param) \
    register size_t __p4 asm("r11") = (size_t)(param); asm volatile("" :: "r" (__p4));

#define __vmcall_param_5(param) \
    register size_t __p5 asm("r12") = (size_t)(param); asm volatile("" :: "r" (__p5));

#define __vmcall_param_6(param) \
    register size_t __p6 asm("r13") = (size_t)(param); asm volatile("" :: "r" (__p6));

#define __vmcall_param_7(param) \
    register size_t __p7 asm("r14") = (size_t)(param); asm volatile("" :: "r" (__p7));

#define __vmcall_param_8(param) \
    register size_t __p8 asm("r15") = (size_t)(param); asm volatile("" :: "r" (__p8));


#define vmcall_1(id, p1)                        \
({                                              \
    __vmcall_param_1(p1);                       \
    vmcall(id);                                 \
})


#define vmcall_2(id, p1, p2)                    \
({                                              \
    __vmcall_param_1(p1);                       \
    __vmcall_param_2(p2);                       \
    vmcall(id);                                 \
})


#define vmcall_3(id, p1, p2, p3)                \
({                                              \
    __vmcall_param_1(p1);                       \
    __vmcall_param_2(p2);                       \
    __vmcall_param_3(p3);                       \
    vmcall(id);                                 \
})


#define vmcall_4(id, p1, p2, p3, p4)            \
({                                              \
    __vmcall_param_1(p1);                       \
    __vmcall_param_2(p2);                       \
    __vmcall_param_3(p3);                       \
    __vmcall_param_4(p4);                       \
    vmcall(id);                                 \
})


#define vmcall_5(id, p1, p2, p3, p4, p5)        \
({                                              \
    __vmcall_param_1(p1);                       \
    __vmcall_param_2(p2);                       \
    __vmcall_param_3(p3);                       \
    __vmcall_param_4(p4);                       \
    __vmcall_param_5(p5);                       \
    vmcall(id);                                 \
})


#define vmcall_6(id, p1, p2, p3, p4, p5, p6)    \
({                                              \
    __vmcall_param_1(p1);                       \
    __vmcall_param_2(p2);                       \
    __vmcall_param_3(p3);                       \
    __vmcall_param_4(p4);                       \
    __vmcall_param_5(p5);                       \
    __vmcall_param_6(p6);                       \
    vmcall(id);                                 \
})

#define __read_reg(reg) ({                               \
    unsigned long long val;                              \
    asm volatile("mov %0, " reg "\n\t" : "=r" (val));    \
    (unsigned long long)(val);                           \
})

#endif // _COMMON_H_
