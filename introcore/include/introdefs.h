/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRODEFS_H_
#define _INTRODEFS_H_

// Add the Doxygen groups here as it seems the best place to do so:

///
/// @defgroup   group_public Public
/// @brief      Public structures and constants
///

///
/// @defgroup   group_public_headers Public headers
/// @brief      Public headers, needed by an integrator
/// @ingroup    group_public
///

///
/// @defgroup   group_internal Internal
/// @brief      Internal structures and constants
///

#include "introtypes.h"
#include "intrinsics.h"

#define UNREFERENCED_PARAMETER(P)           ((void)(P))
#define UNREFERENCED_LOCAL_VARIABLE(V)      ((void)(V))

#ifndef __FILENAME__
# define __FILENAME__    __FILE__
#endif


#ifndef _MM_HINT_T0
# define _MM_HINT_T0         1
# define _MM_HINT_T1         2
# define _MM_HINT_T2         3
# define _MM_HINT_NTA        0
#endif


#if defined(INT_COMPILER_MSVC)
# define STATIC_ASSERT       static_assert
#elif defined(INT_COMPILER_GNUC)
# define STATIC_ASSERT       _Static_assert
#else
# define STATIC_ASSERT(Cond, Msg)
#endif

#ifdef DEBUG
# define ASSERT(x)                                      \
    do {                                                \
        if (!(x)) {                                     \
            LOG("[ASSERT] Assertion failure!\n");       \
            IntBugCheck();                              \
        }                                               \
    } while (0)
#else
# define ASSERT(x)
#endif

#if defined(INT_COMPILER_GNUC) || defined(INT_COMPILER_CLANG)
# define PRAGMA(x) _Pragma(#x)

# define WARNING_DISABLE(W) PRAGMA(GCC diagnostic push); PRAGMA(GCC diagnostic ignored W)

# define WARNING_RESTORE() PRAGMA(GCC diagnostic pop)

#elif defined(INT_COMPILER_MSVC)

# define WARNING_DISABLE(W)                     \
    __pragma(warning(push));                    \
    __pragma(warning(disable: ##W))

# define WARNING_RESTORE() __pragma(warning(pop))
#endif


// Annotation for functions that can be used on the timer (basically anything that doesn't pause the VCPUs)
#define TIMER_FRIENDLY

#ifndef __FILE_TAG__
# define __FILE_TAG__   0xffffeeee
#endif

#define ONE_KILOBYTE    1024ULL
#define ONE_MEGABYTE    (ONE_KILOBYTE * ONE_KILOBYTE)
#define ONE_GIGABYTE    (ONE_KILOBYTE * ONE_MEGABYTE)

#define NSEC_PER_SEC    (1000ULL * 1000ULL * 1000ULL)
#define USEC_PER_SEC    (1000ULL * 1000ULL)
#define NSEC_PER_USEC   1000ULL

#define NSEC_TO_SEC(nsec)   ((nsec) / NSEC_PER_SEC)
#define NSEC_TO_USEC(nsec)  ((nsec) / NSEC_PER_USEC)

#ifndef ARRAYSIZE
# define ARRAYSIZE(A)           (sizeof(A) / sizeof((A)[0]))
#endif

#define CWSTRLEN(Wstring)       ((sizeof(Wstring) - sizeof(WCHAR)) / sizeof(WCHAR))
#define CSTRLEN(String)         (sizeof(String) - sizeof(char))

// Helps to concatenate stuff
#define _PASTE(a,b)     a##b
#define PASTE(a,b)      _PASTE(a,b)


#ifdef INT_COMPILER_MSVC
# define MIN(a, b)                              ((a) < (b) ? (a) : (b))
# define MAX(a, b)                              ((a) > (b) ? (a) : (b))

# define __ROUND_MASK(what, to)                 (((to)-1))

# define ROUND_UP(what, to)                     ((((what) - 1) | __ROUND_MASK(what, to)) + 1)
# define ROUND_DOWN(what, to)                   ((what) & ~__ROUND_MASK(what, to))

# define ALIGN_UP(a, b)                         (((a) % (b) == 0) ? (a) : (((a) + ((b) - 1)) & (-(INT64)(b))))
# define ALIGN_DOWN(a, b)                       (((a) % (b) == 0) ? (a) : ((a) - ((a) % (b))))
# define IN_RANGE(x, start, end)                (((x) >= (start)) && ((x) < (end)))
# define IN_RANGE_INCLUSIVE(x, start, end)      (((x) >= (start)) && ((x) <= (end)))
# define IN_RANGE_LEN(x, start, len)            (((x) >= (start)) && ((x) < ((start) + (len))))
# define IN_RANGE_LEN_INCLUSIVE(x, start, len)  (((x) >= (start)) && ((x) <= ((start) + (len))))


# define RE32(x)                ((((x) & 0xFF) << 24) | \
                                (((x) & 0xFF00) << 8) | \
                                (((x) & 0xFF0000) >> 8) | \
                                (((x) & 0xFF000000) >> 24))


# define SIGN_EX_8(x)           ((x) & 0x00000080 ? 0xFFFFFFFFFFFFFF00 | (x) : (x))
# define SIGN_EX_16(x)          ((x) & 0x00008000 ? 0xFFFFFFFFFFFF0000 | (x) : (x))
# define SIGN_EX_32(x)          ((x) & 0x80000000 ? 0xFFFFFFFF00000000 | (x) : (x))
# define SIGN_EX(sz, x)         ((sz) == 1 ? SIGN_EX_8(x) : (sz) == 2 ? SIGN_EX_16(x) : (sz) == 4 ? SIGN_EX_32(x) : (x))

# define __unreachable
# define __likely(x)     (x)
# define __unlikely(x)   (x)

#else

# define MIN(a, b)                              \
    ({ __auto_type a_min_ = (a);                \
        __auto_type b_min_ = (b);               \
        (a_min_ < b_min_) ? a_min_ : b_min_; })

# define MAX(a, b)                              \
    ({ __auto_type a_max_ = (a);                \
        __auto_type b_max_ = (b);               \
        (a_max_ > b_max_) ? a_max_ : b_max_; })

# define __ROUND_MASK(what, to)         ((typeof(what))((to)-1))

# define ROUND_UP(what, to)             ((((what) - 1) | __ROUND_MASK(what, to)) + 1)
# define ROUND_DOWN(what, to)           ((what) & ~__ROUND_MASK(what, to))

# define __ALIGN(x, a)                  __ALIGN_MASK(x, (typeof(x))(a) - 1)
# define __ALIGN_MASK(x, mask)          (((x) + (mask)) & ~(mask))

# define ALIGN_UP(x, a)                 __ALIGN((x), (a))
# define ALIGN_DOWN(x, a)               __ALIGN((x) - ((a) - 1), (a))

# define IN_RANGE(x, start, end)                        \
    ({ __auto_type x_ir_ = (x);                         \
        ((x_ir_ >= (start)) && (x_ir_ < (end))); })

# define IN_RANGE_INCLUSIVE(x, start, end)              \
    ({ __auto_type x_ir_ = (x);                         \
        ((x_ir_ >= (start)) && (x_ir_ <= (end))); })

# define IN_RANGE_LEN(x, start, len)                                    \
    ({ __auto_type x_ir_ = (x);                                         \
        __auto_type start_ir_ = (start);                                \
        __auto_type len_ir_ = (len);                                    \
        ((x_ir_ >= start_ir_) && (x_ir_ < start_ir_ + len_ir_)); })

# define IN_RANGE_LEN_INCLUSIVE(x, start, len)                          \
    ({ __auto_type x_ir_ = (x);                                         \
        __auto_type start_ir_ = (start);                                \
        __auto_type len_ir_ = (len);                                    \
        ((x_ir_ >= start_ir_) && (x_ir_ <= start_ir_ + len_ir_)); })

# define RE32(x)                                                       \
    ({ __auto_type x_re32_ = (x);                                       \
        (((x_re32_ & 0xFF) << 24) | \
         ((x_re32_ & 0xFF00) << 8) | \
        ((x_re32_ & 0xFF0000) >> 8) | \
        ((x_re32_ & 0xFF000000) >> 24)) })

# define SIGN_EX_8(x)                                                   \
    ({ __auto_type x_se8_ = (x);                                        \
        ((x_se8_ & 0x00000080) ? (0xFFFFFFFFFFFFFF00 | x_se8_) : x_se8_); })

# define SIGN_EX_16(x)                                                   \
    ({ __auto_type x_se16_ = (x);                                       \
        ((x_se16_ & 0x00008000) ? (0xFFFFFFFFFFFF0000 | x_se16_) : x_se16_); })

# define SIGN_EX_32(x)                                                  \
    ({ __auto_type x_se32_ = (x);                                       \
        ((x_se32_ & 0x80000000) ? (0xFFFFFFFF00000000 | x_se32_) : x_se32_); })

# define SIGN_EX(sz, x)                                                 \
    ({ __auto_type x_se_ = (x);                                         \
        ((sz) == 1 ? SIGN_EX_8(x_se_) : (sz) == 2 ? SIGN_EX_16(x_se_) : (sz) == 4 ? SIGN_EX_32(x_se_) : x_se_); })

# define __unreachable  __builtin_unreachable()
# define __likely(x)    __builtin_expect(!!(x), 1)
# define __unlikely(x)  __builtin_expect(!!(x), 0)

#endif // INT_COMPILER_MSVC

#ifndef BIT
# define BIT(x)         (1ULL << (x))
#endif // BIT


#define INITIAL_CRC_VALUE           0xFFFFFFFF

// Will bug check if the condition is met
#define BUG_ON_ALWAYS(cond)                                         \
    do {                                                            \
        if (__unlikely((cond))) {                                   \
            IntBugCheck();                                          \
        }                                                           \
    } while (0)

#ifdef DEBUG
// Will bug check if the condition is met
#define BUG_ON(cond)        BUG_ON_ALWAYS(cond)
#else
// Does nothing on release, use BUG_ON_ALWAYS if you want to bug check on release as well
#define BUG_ON(cond)
#endif // DEBUG

#define FIELD_OFFSET(type, field)   ((SIZE_T)(&((type *)0)->field))

#endif // _INTRODEFS_H_
