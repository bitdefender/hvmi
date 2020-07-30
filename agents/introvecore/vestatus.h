/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _VESTATUS_H_
#define _VESTATUS_H_

#define ST_VE_FACILITY                          0x00E70000

#define ST_VE_SUCCESS                           0x28E70000
#define ST_VE_INFORMATIONAL                     0x68E70000
#define ST_VE_WARNING                           0xA8E70000
#define ST_VE_ERROR                             0xE8E70000

// Page walk statuses
#define STATUS_NO_MAPPING_STRUCTURES            ((NTSTATUS)ST_VE_ERROR|0x00000013L)
#define STATUS_PAGE_NOT_PRESENT                 ((NTSTATUS)ST_VE_ERROR|0x00000016L)

// Heap statuses
#define STATUS_HEAP_NO_FREE_CHUNK_FOUND         ((NTSTATUS)ST_VE_ERROR|0x00000031L)
#define STATUS_HEAP_LAST_FIT_INDEX_NOT_SET      ((NTSTATUS)ST_VE_ERROR|0x00000032L)

// HV statuses
#define STATUS_HV_INVEPT_FAILED                 ((NTSTATUS)ST_VE_ERROR|0x00000080L)

// Misc
#define STATUS_DISASM_ERROR                     ((NTSTATUS)ST_VE_ERROR|0x00000100L)



#endif // _VESTATUS_H_