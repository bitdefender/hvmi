/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTROTYPES_H_
#define _INTROTYPES_H_

#include "env.h"

#ifndef INT_COMPILER_MSVC
#include "compiler-gnu.h"
#else
#include "compiler-msvc.h"
#endif

#include "intro_types.h"

#if !defined(_M_X64) && !defined(_M_AMD64) && !defined(__amd64__) && \
    !defined(__amd64) && !defined(__x86_64__) && !defined(__x86_64) && !defined(__LP64__)
#    error "Unsupported architecture"
#endif

#if defined(__MINGW32__) || defined(__MINGW64__)
#    error "MINGW builds are not supported for now"
#endif

#ifdef __CYGWIN__
#    error "CYGWIN builds are not supported for now"
#endif

#define BYTE_MAX                UINT8_MAX
#define WORD_MAX                UINT16_MAX
#define DWORD_MAX               UINT32_MAX
#define QWORD_MAX               UINT64_MAX

//
// Some useful attributes (should be in introdefs.h really, but they make more sense here since some of them
// apply to types).
//
// See the following links for more details:
// https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html#Common-Function-Attributes
// https://gcc.gnu.org/onlinedocs/gcc/Common-Variable-Attributes.html#Common-Variable-Attributes
// https://gcc.gnu.org/onlinedocs/gcc/Common-Type-Attributes.html#Common-Type-Attributes
//
#ifndef INT_COMPILER_MSVC
# define __pure         __attribute__((pure))
# define __section(x)   __attribute__((section (x)))
# define __must_check   __attribute__((warn_unused_result))
# define __nonstring    __attribute__((nonstring))
# define __noreturn     __attribute__((noreturn))
#else
# define __attribute__(x)
# define __pure
# define __section(Name)
# define __must_check
# define __nonstring
# define __nonnull(...)
# define __noreturn      __declspec(noreturn)
#endif

#define __forceinline       __attribute__((always_inline)) inline

#include "introstatus.h"
#include "introlists.h"
#include "intro_types.h"

#include "glueiface.h"
#include "upperiface.h"

typedef INTSTATUS
(*PFUNC_IterateListCallback)(
    _In_ QWORD Node,
    _In_ QWORD Aux
    );

#endif /* _INTROTYPES_H_ */
