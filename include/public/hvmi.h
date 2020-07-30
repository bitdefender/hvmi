/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __HVMI_H__
#define __HVMI_H__

#include <hvmi/env.h>

#ifndef __likely
    #ifdef INT_COMPILER_MSVC
        #define __likely( expr ) ( expr )
    #else
        #define __likely( expr ) __builtin_expect( !!( expr ), 1 )
    #endif // !INT_COMPILER_MSVC
#endif // !__likely

#include <hvmi/intro_sal.h>
#include <hvmi/intro_types.h>
#include <hvmi/introstatus.h>
#include <hvmi/upperiface.h>
#include <hvmi/glueiface.h>

#endif // __HVMI_H__
