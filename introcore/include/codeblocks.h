/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _CODEBLOCKS_H_
#define _CODEBLOCKS_H_

#include "exceptions.h"


///
/// This defines how "aggressive" the pattern extraction should be.
///
typedef enum
{
    cbLevelNormal = 1,  ///< This includes instructions until #codeInsBt.
    cbLevelMedium,      ///< This includes instructions until #codeInsFlags.
} CB_EXTRACT_LEVEL;


///
/// Defines the instruction types that are included in the blocks.
///
typedef enum
{
    codeInsInvalid = 0,         ///< Not really used, only to signal an error.
    codeInsJc,                  ///< Conditional jump, of any kind, including loop.
    codeInsJmp,                 ///< Non-conditional jump, of any kind.
    codeInsCall,                ///< Call, of any kind.
    codeInsRet,                 ///< Ret, of any kind.
    codeInsStr,                 ///< Some sort of string instruction - lods, stos, scas, movs.
    codeInsXchg,                ///< Exchange instruction, including xchg, xadd, cmpxchg, cmpxchg8b/16b.
    codeInsBt,                  ///< Bit manipulation instruction - bt, bts, btr, btc.
    codeInsMovReg,              ///< A mov involving only registers.
    codeInsMovMem,              ///< A mov involving memory (either as the destination or as the source).
    codeInsMovImm,              ///< A mov using immediate value.
    codeInsMovFsGs,             ///< A mov using a segment:offset.
    codeInsFlags,               ///< Push/Pop flags.
} CODE_INS;


/// Number of chunks (CODE_INS) per codeblock.
#define CODE_BLOCK_CHUNKS_COUNT             8


///
/// Describes a single normalized code block. This is just a "passing" structure. From this it will be built a
/// CODE_SIGNATURE structure that will be matched against the databases (or inserted into one). Each codeblock is a
/// series of patterns that will be computed into a hash. A signature will consist of a few hashes like this.
///
typedef struct _CODE_BLOCK
{
    DWORD           OffsetStart;        ///< The start of the extracted codeblock (not actually relevant)
    DWORD           Hash;               ///< The hash will be computed on Chunks array.
    WORD            Size;               ///< Code block size, in patterns.
    BYTE            PivotInstruction;   ///< This indicates the first instruction type inside the code block.
    /// @brief  The actual #CODE_INS values representing the instruction pattern.
    BYTE            Chunks[CODE_BLOCK_CHUNKS_COUNT];
} CODE_BLOCK, *PCODE_BLOCK;


#pragma pack(push)
#pragma pack(1)

///
/// This structure describes an instruction inside a pattern.
///
typedef struct _CODE_BLOCK_PATTERN
{
    DWORD Offset;   ///< The offset of the instruction in the page.
    BYTE  Value;    ///< The #CODE_INS value describing the instruction type.
} CODE_BLOCK_PATTERN, *PCODE_BLOCK_PATTERN;
#pragma pack(pop)


//
// API
//
INTSTATUS
IntFragExtractPattern(
    _In_reads_(MaxBufferSize) BYTE *Buffer,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _In_ DWORD PatternSize,
    _Out_writes_to_(PatternSize, *TotalExtracted) BYTE *Pattern,
    _Out_ DWORD *TotalExtracted,
    _Inout_ DWORD *TotalParsed
    );

INTSTATUS
IntFragExtractCodeBlocks(
    _In_reads_(MaxBufferSize) BYTE *Buffer,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _Inout_ DWORD *HashesCount,
    _Out_writes_(*HashesCount) DWORD *Hashes
    );

__pure INTSTATUS
IntFragMatchSignature(
    _In_ const DWORD *Hashes,
    _In_ DWORD CodeBlocksCount,
    _In_ const SIG_CODEBLOCKS *ExceptionSignature
    );

INTSTATUS
IntFragExtractCodePattern(
    _In_ PBYTE Buffer,
    _In_ DWORD StartOffset,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _In_ DWORD PatternSize,
    _Out_writes_to_(PatternSize, *TotalExtracted) CODE_BLOCK_PATTERN *Pattern,
    _Out_ DWORD *TotalExtracted
    );

INTSTATUS
IntFragDumpBlocks(
    _In_ PBYTE Buffer,
    _In_ QWORD StartAddress,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _In_ QWORD Rip,
    _In_ BOOLEAN ReturnRip
    );

#endif // _CODEBLOCKS_H_
