/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _ENV_H_
#define _ENV_H_

///
/// @file       env.h
/// @ingroup    group_public_headers
///

#if defined(_MSC_VER)
#define INT_COMPILER_MSVC
#elif defined(__clang__)
#define INT_COMPILER_CLANG
#elif defined(__GNUC__)
#define INT_COMPILER_GNUC
#else
#error "Unsupported compiler"
#endif

#if defined(__unix__) || defined(__unix)
#define INT_UNIX
#elif defined(_WIN32) || defined(_WIN64)
#define INT_WINDOWS
#endif

#if defined(_DEBUG) || defined(_DBG) || defined (DEBUG) || defined(DBG)
#define INT_DEBUG_BUILD
#endif
#if defined(_RELEASE) || defined (_NDEBUG) || defined(RELEASE) || defined (NDEBUG)
#define INT_RELEASE_BUILD
#endif

#endif // _ENV_H_
