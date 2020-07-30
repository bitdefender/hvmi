/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __INTROCORE_H_INCLUDED__
#define __INTROCORE_H_INCLUDED__

//
// This header is not part of the HVMI SDK. It is, if you will, a helper:
// it pulls in all different introcore headers in order to make integration
// a bit easier.
//

#ifndef __likely
#ifdef __GNUC__
#define __likely( expr ) __builtin_expect( !!( expr ), 1 )
#else
#define __likely( expr ) ( expr )
#endif
#endif

#include <hvmi/intro_types.h>
#include <hvmi/introstatus.h>
#include <hvmi/upperiface.h>
#include <hvmi/glueiface.h>

#endif // __INTROCORE_H_INCLUDED__
