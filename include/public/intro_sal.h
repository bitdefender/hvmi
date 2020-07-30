/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _INTRO_SAL_H_
#define _INTRO_SAL_H_

///
/// @file       intro_sal.h
/// @ingroup    group_public_headers
/// @brief      Dummy SAL definitions for build environments were SAL is not available.
///

// Dummy SAL definitions
#define _Return_type_success_( expr )
#define _In_opt_
#define _In_z_
#define _In_opt_z_
#define _Outptr_
#define _Inout_
#define _In_
#define _Out_
#define _At_( expr, arg )
#define _Outptr_result_bytebuffer_( expr )
#define _In_reads_bytes_( expr )
#define _When_( expr, arg )
#define _In_reads_( expr )
#define _Out_writes_( expr )
#define _Out_writes_to_( expr, expr2 )
#define _Out_opt_
#define _Inout_opt_
#define _Inout_updates_( expr )
#define _Inout_updates_bytes_( expr )
#define _Acquires_lock_( expr )
#define _Releases_lock_( expr )
#define _In_reads_z_( expr )
#define _Out_writes_z_( expr )
#define _Out_writes_bytes_( expr )
#define _Outptr_opt_
#define _Function_class_( expr )
#define _Field_size_( expr )
#define _In_bytecount_( expr )
#define _In_reads_or_z_( expr )
#define _Analysis_assume_lock_held_( expr )
#define _Inout_updates_all_( expr )
#define _Analysis_assume_( expr )
#define _Success_( expr )

#endif // !_INTRO_SAL_H_
