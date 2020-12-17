/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "codeblocks.h"
#include "crc32.h"
#include "decoder.h"
#include "utils.h"


///
/// @file codeblocks.c
///
/// @brief Handle x86 code normalization & block hashes extraction.
///
/// This module parses a stream of x86 instructions, it decodes each instruction, it normalizes them (it converts
/// the decoded instructions to a single-byte value representing the generic type of the instruction), and then
/// computes hashes (CRC32) on blocks of such single-byte normalized instructions. Only a few instructions are
/// parsed and normalized (for example, branches, returns, string operations, mov, etc.). The general operation is:
/// 1. Disassemble each instruction inside the stream;
/// 2. For each instruction, output a normalized #CODE_INS value; other instructions will simply be ignored;
/// 3. Once a list of #CODE_INS is extracted from the instruction stream, find pivots, which are fixed instruction
/// types (#codeInsJmp, #codeInsCall, #codeInsMovMem, #codeInsMovFsGs);
/// 4. Starting with each pivot instruction, compute a CRC32 on a block of #CODE_BLOCK_CHUNKS_COUNT values from
/// the pattern.
/// The extracted hashes will then be used in exception signatures. The rationale behind this is that they are
/// specific enough because they include a significant chunk of instructions, but they are resilient to minor
/// code changes, such as recompiling, where only the used registers are modified.
///



static CHAR gCbLog[512]; ///< Used to format log lines containing code-blocks.


DWORD
IntFragHandleCommon(
    _In_reads_(BufSize) const BYTE *Buffer,
    _In_ size_t BufSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _Out_ DWORD *Pattern
    )
///
/// @brief Extract a pattern of instructions without using the disassembler.
///
/// This function leverages the fact that the majority of instructions that compose code-blocks are easy to decode
/// without a disassembler. Therefore, it handles the most common cases without decoding the instruction, by using
/// large switch-case/if-else statements.
///
/// NOTE: The instructions that have the 0x66 prefixes is not handled yet.
///
/// @param[in]  Buffer          The code buffer to be parsed.
/// @param[in]  BufSize         Buffer size, in bytes.
/// @param[in]  CsType          Operating mode, should #IG_CS_TYPE_32B or #IG_CS_TYPE_64B.
/// @param[in]  ExtractLevel    How aggressive the extraction should be.
/// @param[out] Pattern         Will contain, upon return, the #CODE_INS type associated with the instruction
///                             present at Buffer.
///
/// @returns The length of the parsed instruction, or 0 if the instruction could not be parsed.
///
{
    *Pattern = codeInsInvalid;

    if (IG_CS_TYPE_16B == CsType)
    {
        return 0;
    }

#define IS_REX_PREFIX(b)        ((ND_PREFIX_REX_MIN <= (b)) && ((b) <= ND_PREFIX_REX_MAX))

    if (0 == BufSize)
    {
        return 0;
    }

    // Try common patterns (both x86 and x64)
    if (0x90 == *Buffer || 0xcc == *Buffer)
    {
        // NOP/INT3
        return 1;
    }
    else if (BufSize >= 2 &&
             (0x84 == Buffer[0] || 0x85 == Buffer[0]) &&
             (0xc0 <= Buffer[1]))
    {
        // TEST reg8/32, reg8/32
        return 2;
    }
    else if (BufSize >= 2 &&
             0xcd == *Buffer)
    {
        // INT imm8
        return 2;
    }
    else if (0xc3 == *Buffer || 0xcb == *Buffer)
    {
        *Pattern = codeInsRet;
        return 1;
    }
    else if (BufSize >= 5 &&
             0xe8 == *Buffer)
    {
        *Pattern = codeInsCall;
        return 5;
    }
    else if (BufSize >= 6 &&
             0xff == Buffer[0] && 0x15 == Buffer[1])
    {
        *Pattern = codeInsCall;
        return 6;
    }
    else if (BufSize >= 5 &&
             0xe9 == *Buffer)
    {
        *Pattern = codeInsJmp;
        return 5;
    }
    else if (BufSize >= 2 &&
             0xeb == *Buffer)
    {
        *Pattern = codeInsJmp;
        return 2;
    }
    else if (BufSize >= 2 &&
             (0x70 <= *Buffer && *Buffer <= 0x7f))
    {
        *Pattern = codeInsJc;
        return 2;
    }
    else if (BufSize >= 3 &&
             (0xc2 == *Buffer || 0xca == *Buffer))
    {
        *Pattern = codeInsRet;
        return 3;
    }
    else if (0xaa <= *Buffer && *Buffer <= 0xad)
    {
        *Pattern = codeInsStr;
        return 1;
    }
    else if (0x9c == *Buffer || 0x9d == *Buffer)
    {
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsFlags;
        }
        return 1;
    }
    else if (0x91 <= *Buffer && *Buffer <= 0x97)
    {
        *Pattern = codeInsXchg;
        return 1;
    }
    else if (BufSize >= 2 &&
             (0xb0 <= *Buffer && *Buffer <= 0xb7))
    {
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsMovImm;
        }

        return 2;
    }
    else if (BufSize >= 5 &&
             (0xb8 <= *Buffer && *Buffer <= 0xbf))
    {
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsMovImm;
        }

        return 5;
    }
    else if (0x50 <= *Buffer && *Buffer <= 0x5f)
    {
        // PUSH/POP
        return 1;
    }
    else if (BufSize >= 2 &&
             0xa8 == *Buffer)
    {
        // TEST al, imm8
        return 2;
    }
    else if (BufSize >= 3 &&
             0xf6 == Buffer[0] &&
             (0xc0 <= Buffer[1] && Buffer[1] <= 0xcf))
    {
        // TEST reg4, imm8
        return 3;
    }
    else if (0x98 == *Buffer || 0x99 == *Buffer)
    {
        // CBW/CWDE or CWD/CDQ
        return 1;
    }
    else if (BufSize >= 5 &&
             0xa9 == *Buffer)
    {
        // TEST eax, imm32
        return 5;
    }
    else if (BufSize >= 2 &&
             0x00 == Buffer[0] && 0x00 == Buffer[1])
    {
        // NULL bytes, very common
        return 2;
    }
    else if (BufSize >= 3 &&
             (0x83 == Buffer[0] && (0xe0 <= Buffer[1] && Buffer[1] <= 0xe3)))
    {
        // AND eax/ecx/edx/ebx, imm8
        return 3;
    }
    else if (BufSize >= 2 &&
             0x33 == Buffer[0] &&
             0xc0 <= Buffer[1])
    {
        // XOR reg32, reg32
        return 2;
    }
    else if (BufSize >= 4 &&
             0x89 == Buffer[0] && 0x24 == Buffer[2] &&
             (0x4c == Buffer[1] ||
              0x5c == Buffer[1] ||
              0x6c == Buffer[1] ||
              0x7c == Buffer[1] ||
              0x44 == Buffer[1] ||
              0x54 == Buffer[1] ||
              0x64 == Buffer[1] ||
              0x74 == Buffer[1]))
    {
        // MOV [rsp + imm8], reg32
        // MOV reg32, [rsp + imm8]
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsMovMem;
        }

        return 4;
    }
    else if (BufSize >= 7 &&
             0x89 == Buffer[0] && 0x24 == Buffer[2] &&
             (0x8c == Buffer[1] ||
              0x9c == Buffer[1] ||
              0xac == Buffer[1] ||
              0xbc == Buffer[1] ||
              0x84 == Buffer[1] ||
              0x94 == Buffer[1] ||
              0xa4 == Buffer[1] ||
              0xb4 == Buffer[1]))
    {
        // MOV [rsp + imm32], reg32
        // MOV reg32, [rsp + imm32]
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsMovMem;
        }

        return 7;
    }
    else if (BufSize >= 6 &&
             0x81 == Buffer[0] && 0xc4 == Buffer[1])
    {
        // ADD rsp, imm32
        return 6;
    }
    else if (BufSize >= 3 &&
             0x83 == Buffer[0] && 0xc4 == Buffer[1])
    {
        // ADD rsp, imm8
        return 3;
    }
    else if (BufSize >= 6 &&
             0x81 == Buffer[0] && 0xec == Buffer[1])
    {
        // SUB rsp, imm32
        return 6;
    }
    else if (BufSize >= 3 &&
             0x83 == Buffer[0] && 0xec == Buffer[1])
    {
        // SUB rsp, imm8
        return 3;
    }
    else if (BufSize >= 2 &&
             (0x8b == Buffer[0] || 0x89 == Buffer[0]) &&
             0xc0 <= Buffer[1])
    {
        // MOV reg32, reg32
        if (ExtractLevel >= cbLevelMedium)
        {
            *Pattern = codeInsMovReg;
        }

        return 2;
    }
    else if (BufSize >= 6 &&
             0x0f == *Buffer &&
             (0x80 <= Buffer[1] && Buffer[1] <= 0x8f))
    {
        *Pattern = codeInsJc;
        return 6;
    }
    else if (BufSize >= 2 &&
             0xff == Buffer[0] &&
             (0xc0 <= Buffer[1] && Buffer[1] <= 0xcf))
    {
        // INC/DEC reg32
        return 2;
    }
    else if (BufSize >= 2 &&
             0x3b == Buffer[0] &&
             0xc0 <= Buffer[1])
    {
        // CMP reg32, reg32
        return 2;
    }

    if (IG_CS_TYPE_32B == CsType)
    {
        if (0x40 <= *Buffer && *Buffer <= 0x4f)
        {
            // INC/DEC on 32-bit
            return 1;
        }
    }
    else if (IG_CS_TYPE_64B == CsType)
    {
        if (BufSize >= 4 &&
            0x48 == Buffer[0] && 0x83 == Buffer[1] && 0xc4 == Buffer[2])
        {
            // ADD rsp, imm8
            return 4;
        }
        else if (BufSize >= 7 &&
                 0x48 == Buffer[0] && 0x81 == Buffer[1] && 0xec == Buffer[2])
        {
            // SUB rsp, imm32
            return 7;
        }
        else if (BufSize >= 5 &&
                 (0x48 == Buffer[0] || 0x4c == Buffer[0]) &&
                 (0x89 == Buffer[1] || 0x8b == Buffer[1]) &&
                 0x24 == Buffer[3] &&
                 (0x4c == Buffer[2] ||
                  0x5c == Buffer[2] ||
                  0x6c == Buffer[2] ||
                  0x7c == Buffer[2] ||
                  0x44 == Buffer[2] ||
                  0x54 == Buffer[2] ||
                  0x64 == Buffer[2] ||
                  0x74 == Buffer[2]))
        {
            // MOV [rsp + imm8], reg64
            // MOV reg64, [rsp + imm8]
            if (ExtractLevel >= cbLevelMedium)
            {
                *Pattern = codeInsMovMem;
            }

            return 5;
        }
        else if (BufSize >= 8 &&
                 (0x48 == Buffer[0] || 0x4c == Buffer[0]) &&
                 (0x89 == Buffer[1] || 0x8b == Buffer[1]) &&
                 0x24 == Buffer[3] &&
                 (0x8c == Buffer[2] ||
                  0x9c == Buffer[2] ||
                  0xac == Buffer[2] ||
                  0xbc == Buffer[2] ||
                  0x84 == Buffer[2] ||
                  0x94 == Buffer[2] ||
                  0xa4 == Buffer[2] ||
                  0xb4 == Buffer[2]))
        {
            // MOV [rsp + imm32], reg64
            // MOV reg64, [rsp + imm32]
            if (ExtractLevel >= cbLevelMedium)
            {
                *Pattern = codeInsMovMem;
            }

            return 8;
        }
        else if (BufSize >= 4
                 && 0x48 == Buffer[0] && 0x83 == Buffer[1] && 0xec == Buffer[2])
        {
            // SUB rsp, imm8
            return 4;
        }
        else if (IS_REX_PREFIX(*Buffer))
        {
            if (BufSize >= 3 &&
                0x33 == Buffer[1] &&
                0xc0 <= Buffer[2])
            {
                // XOR reg64, reg64
                return 3;
            }
            else if (BufSize >= 3 &&
                     0x3b == Buffer[1] &&
                     0xc0 <= Buffer[2])
            {
                // CMP reg64, reg64
                return 3;
            }
            else if (BufSize >= 3 &&
                     0xff == Buffer[1] &&
                     (0xc0 <= Buffer[2] && Buffer[2] <= 0xcf))
            {
                // INC/DEC reg32/reg64
                return 3;
            }
            else if (BufSize >= 6 &&
                     0 == (*Buffer & BIT(3)) &&
                     (0xb8 <= Buffer[1] && Buffer[1] <= 0xbf))
            {
                if (ExtractLevel >= cbLevelMedium)
                {
                    *Pattern = codeInsMovImm;
                }

                return 6;
            }
            else if (BufSize >= 10 &&
                     0 != (*Buffer & BIT(3)) &&
                     (0xb8 <= Buffer[1] && Buffer[1] <= 0xbf))
            {
                if (ExtractLevel >= cbLevelMedium)
                {
                    *Pattern = codeInsMovImm;
                }

                return 10;
            }
            else if (BufSize >= 4 &&
                     0x8d == Buffer[1] &&
                     (0x45 == Buffer[2] ||
                      0x55 == Buffer[2]))
            {
                // LEA reg64, [reg64 + imm8]
                return 4;
            }
            else if (BufSize >= 5 &&
                     0x8d == Buffer[1] &&
                     0x24 == Buffer[3] &&
                     (0x44 == Buffer[2] ||
                      0x4c == Buffer[2] ||
                      0x54 == Buffer[2] ||
                      0x5c == Buffer[2]))
            {
                // LEA reg64, [rsp + imm8]
                return 5;
            }
            else if (BufSize >= 3 &&
                     (0x8b == Buffer[1] || 0x89 == Buffer[1]) &&
                     0xc0 <= Buffer[2])
            {
                // MOV reg32/64, reg32/64
                if (ExtractLevel >= cbLevelMedium)
                {
                    *Pattern = codeInsMovReg;
                }

                return 3;
            }
            else if (BufSize >= 3 &&
                     ((0x84 == Buffer[1] || 0x85 == Buffer[1]) &&
                      (0xc0 <= Buffer[2])))
            {
                // TEST reg64, reg64
                return 3;
            }
            else if (BufSize >= 6 &&
                     0xa9 == Buffer[1])
            {
                // TEST eax/rax, imm32
                return 6;
            }
            else if (BufSize >= 2 &&
                     (0x98 == Buffer[1] || 0x99 == Buffer[1]))
            {
                // CBW/CWDE or CWD/CDQ
                return 2;
            }
            else if (BufSize >= 2 &&
                     (0x50 <= Buffer[1] && Buffer[1] <= 0x5f))
            {
                // PUSH/POP on 64-bit with REX prefix
                return 2;
            }
        }
    }

    return 0;
}


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
    )
///
/// @brief Extract a pattern of code-blocks from the given code buffer.
///
/// This function will parse the provided code buffer, and it will extract a pattern of #CODE_INS values representing
/// the relevant instructions located inside the buffer. The pattern can then be used to compute hashes (code-blocks).
/// This function will use the disassembler to decode each instruction inside the Buffer, and depending on the
/// instruction type, a #CODE_INS value will be outputted inside the Pattern buffer. This function may also call the
/// optimized #IntFragHandleCommon function which will try to handle the current instruction without calling the
/// disassembler, but if it fails, it will still rely on it.
///
/// @param[in]  Buffer          The code buffer to be parsed.
/// @param[in]  MaxBufferSize   The size of the code buffer.
/// @param[in]  CsType          Operating mode, should be #IG_CS_TYPE_32B or #IG_CS_TYPE_64B.
/// @param[in]  ExtractLevel    #cbLevelNormal or #cbLevelMedium.
/// @param[in]  PatternSize     Maximum size of the pattern.
/// @param[out] Pattern         The pattern of instructions located in Buffer.
/// @param[out] TotalExtracted  Number of #CODE_INS values extracted from the Buffer into Pattern.
/// @param[in, out] TotalParsed Will add to this variable the total size in bytes parsed from Buffer.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If the buffer is too small (the last instructions cannot be parsed).
///
{
    INSTRUX instrux;
    DWORD i;
    const BYTE *end;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == PatternSize)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL == Pattern)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    if (NULL == TotalExtracted)
    {
        return INT_STATUS_INVALID_PARAMETER_7;
    }

    if (NULL == TotalParsed)
    {
        return INT_STATUS_INVALID_PARAMETER_8;
    }

    if (MaxBufferSize <= ND_MAX_INSTRUCTION_LENGTH)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    end = Buffer + MaxBufferSize;
    i = 0;

    if (IG_CS_TYPE_16B == CsType)
    {
        // Log this since it shouldn't really happen
        WARNING("[WARNING] Extracting codeblocks for 16 bit!\n");
    }

    while ((Buffer < end) && (i < PatternSize))
    {
        NDSTATUS ndstatus;
        DWORD pattern, skipSize;
        CODE_INS oldPattern;

        skipSize = IntFragHandleCommon(Buffer, end - Buffer, CsType, ExtractLevel, &pattern);
        if (skipSize)
        {
            if (pattern != codeInsInvalid)
            {
                Pattern[i++] = (BYTE)pattern;
            }

            Buffer += skipSize;
            *TotalParsed += skipSize;

            continue;
        }
        else
        {
            pattern = codeInsInvalid;
        }

        ndstatus = IntDecDecodeInstructionFromBuffer(Buffer - skipSize, end - Buffer - skipSize, CsType, &instrux);
        if (__unlikely(ndstatus == ND_STATUS_BUFFER_TOO_SMALL))
        {
            // There is no point in going further, the rest of the instructions will be garbage
            break;
        }
        else if (__unlikely(!ND_SUCCESS(ndstatus)))
        {
            Buffer += 1;
            *TotalParsed += 1;
            continue;
        }

        if (Buffer + instrux.Length >= end)
        {
            break;
        }

        oldPattern = codeInsInvalid;

        if (instrux.Instruction == ND_INS_Jcc)
        {
            // NOTE: a lot of strings will be interpreted as this! But not that critical,
            // since it's not used as a pivot...
            oldPattern = codeInsJc;
        }
        else if (instrux.Instruction == ND_INS_JMPE ||
                 instrux.Instruction == ND_INS_JMPFD ||
                 instrux.Instruction == ND_INS_JMPFI ||
                 instrux.Instruction == ND_INS_JMPNI ||
                 instrux.Instruction == ND_INS_JMPNR)
        {
            oldPattern = codeInsJmp;
        }
        else if (instrux.Instruction == ND_INS_CALLFD ||
                 instrux.Instruction == ND_INS_CALLFI ||
                 instrux.Instruction == ND_INS_CALLNI ||
                 instrux.Instruction == ND_INS_CALLNR)
        {
            oldPattern = codeInsCall;
        }
        else if (instrux.Instruction == ND_INS_RETF ||
                 instrux.Instruction == ND_INS_RETN)
        {
            oldPattern = codeInsRet;
        }
        else if (instrux.Instruction == ND_INS_STOS ||
                 instrux.Instruction == ND_INS_LODS)
        {
            oldPattern = codeInsStr;
        }
        else if (instrux.Instruction == ND_INS_XCHG ||
                 instrux.Instruction == ND_INS_CMPXCHG)
        {
            oldPattern = codeInsXchg;
        }
        else if (instrux.Instruction == ND_INS_BT ||
                 instrux.Instruction == ND_INS_BTC ||
                 instrux.Instruction == ND_INS_BTR ||
                 instrux.Instruction == ND_INS_BTS)
        {
            oldPattern = codeInsBt;
        }

        // If we are at the normal level, go to the next instruction, don't extract further
        if (ExtractLevel == cbLevelNormal)
        {
            goto _next_instruction;
        }

        if (instrux.Instruction == ND_INS_MOV)
        {
            if (instrux.Operands[0].Type == ND_OP_REG &&
                instrux.Operands[1].Type == ND_OP_REG)
            {
                oldPattern = codeInsMovReg;
            }
            else if (instrux.Operands[0].Type == ND_OP_MEM ||
                     instrux.Operands[1].Type == ND_OP_MEM)
            {
                oldPattern = codeInsMovMem;
            }
            else if (instrux.HasImm1)
            {
                oldPattern = codeInsMovImm;
            }
            else if (instrux.Seg == ND_PREFIX_G2_SEG_FS ||
                     instrux.Seg == ND_PREFIX_G2_SEG_GS)
            {
                oldPattern = codeInsMovFsGs;
            }
        }
        else if (instrux.Instruction == ND_INS_PUSHF ||
                 instrux.Instruction == ND_INS_POPF)
        {
            oldPattern = codeInsFlags;
        }

        // We are done with the medium level
        if (ExtractLevel == cbLevelMedium)
        {
            goto _next_instruction;
        }

_next_instruction:
        if (skipSize && ((DWORD)oldPattern != pattern))
        {
            ERROR("[ERROR] [CRITICAL] Pattern was %02d but we returned %02d.."
                  "The MALWARE / ROOTKIT below is most probably a FP!\n",
                  oldPattern,
                  pattern);

            IntDumpInstruction(&instrux, 0);
        }

        if (!skipSize && oldPattern != codeInsInvalid)
        {
            Pattern[i++] = oldPattern;
        }

        if (!skipSize)
        {
            Buffer += instrux.Length;
            *TotalParsed += instrux.Length;
        }
    }

    // Caused infinite loop in IntFragExtractBlocks because it remained blocked at 0xffc
    if (Buffer <= end)
    {
        *TotalParsed = MaxBufferSize;
    }

    *TotalExtracted = i;

    return INT_STATUS_SUCCESS;
}


//
// IntFragExtractCodeBlocks
//
INTSTATUS
IntFragExtractCodeBlocks(
    _In_reads_(MaxBufferSize) BYTE *Buffer,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _Inout_ DWORD *HashesCount,
    _Out_writes_(*HashesCount) DWORD *Hashes
    )
///
/// @brief Extract a block of code-block hashes from the given code buffer.
///
/// This function will parse the provided code buffer, and it will extract a pattern of #CODE_INS values representing
/// the relevant instructions located inside the buffer. Once the pattern has been extracted, it will parse it, and
/// it will compute hashes on blocks of #CODE_BLOCK_CHUNKS_COUNT patterns, starting with a pivot instruction, which
/// can be a #codeInsJmp, #codeInsCall or mov that involves memory or fs/gs segments.
///
/// @param[in]  Buffer          The code buffer to be parsed.
/// @param[in]  MaxBufferSize   The size of the code buffer.
/// @param[in]  CsType          Operating mode, should be #IG_CS_TYPE_32B or #IG_CS_TYPE_64B.
/// @param[in]  ExtractLevel    #cbLevelNormal or #cbLevelMedium.
/// @param[in, out] HashesCount Will add to this variable the total number of hashes extracted.
/// @param[out] Hashes          Will contain upon successful return the extracted hashes.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_NOT_FOUND If no hash could be extracted.
///
{
    BYTE pattern[PAGE_SIZE / 4];
    DWORD i, j, totalParsed, currentHash, sizeToParse;
    INTSTATUS status;
    BYTE chunks[CODE_BLOCK_CHUNKS_COUNT] = { 0 };

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (MaxBufferSize <= ND_MAX_INSTRUCTION_LENGTH)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == HashesCount || 0 == *HashesCount)
    {
        return INT_STATUS_INVALID_PARAMETER_5;
    }

    if (NULL == Hashes)
    {
        return INT_STATUS_INVALID_PARAMETER_6;
    }

    currentHash = 0;
    totalParsed = 0;
    sizeToParse = MaxBufferSize - ND_MAX_INSTRUCTION_LENGTH;

    // Don't search for more than 1024 (INTRO_PAGE_SIZE / 4) patterns at a time (maximum in a page filled with
    // 4-byte instructions). If there are more patterns than this, assume there is something wrong with that page.
    status = INT_STATUS_NOT_FOUND;

    // We parse the whole buffer or till we found as many codeblocks as we requested
    while (totalParsed < sizeToParse && currentHash < *HashesCount)
    {
        DWORD patternSize = 0;

        status = IntFragExtractPattern(Buffer + totalParsed,
                                       sizeToParse - totalParsed,
                                       CsType,
                                       ExtractLevel,
                                       PAGE_SIZE / 4,
                                       pattern,
                                       &patternSize,
                                       &totalParsed);
        if (!INT_SUCCESS(status))
        {
            if (status == INT_STATUS_DATA_BUFFER_TOO_SMALL)
            {
                WARNING("[WARNNING] Buffer too small to extract codeblocks (size %d): 0x%08x\n",
                        sizeToParse - totalParsed,
                        status);

                status = INT_STATUS_SUCCESS;
            }
            else
            {
                ERROR("[ERROR] IntFragExtractCodePattern: 0x%08x\n", status);
            }

            goto leave;
        }

        for (i = 0; i < patternSize; i++)
        {
            // Search for a pivot instruction:
            // NORMAL - a jmp of any kind or a call
            // MEDIUM - previous + a move that involves memory, or FS/GS segments
            if (cbLevelNormal == ExtractLevel &&
                (codeInsCall != pattern[i] &&
                 codeInsJmp != pattern[i]))
            {
                continue;
            }

            if (cbLevelMedium == ExtractLevel &&
                (codeInsCall != pattern[i] &&
                 codeInsJmp != pattern[i] &&
                 codeInsMovMem != pattern[i] &&
                 codeInsMovFsGs != pattern[i]))
            {
                continue;
            }

            // We found a pivot so extract a codeblock from here
            for (j = 0; (j < CODE_BLOCK_CHUNKS_COUNT) && ((i + j) < patternSize); j++)
            {
                if (chunks[j] != 0)
                {
                    continue;
                }

                chunks[j] = pattern[i + j];
            }

            // We didn't fill the last codeblock, so don't extract the next pattern if we can;
            // fill the rest and only then calculate an hash
            if (chunks[CODE_BLOCK_CHUNKS_COUNT - 1] == 0)
            {
                break;
            }

            // We found our chunks, so calculate a hash
            Hashes[currentHash] = Crc32Compute(chunks, CODE_BLOCK_CHUNKS_COUNT, INITIAL_CRC_VALUE);

            // Reset the chunks for the next calculation
            memzero(chunks, CODE_BLOCK_CHUNKS_COUNT);

            // Advance to the next codeblock or exit if we reached our target
            if (++currentHash == *HashesCount)
            {
                status = INT_STATUS_SUCCESS;
                goto leave;
            }
        }
    }

leave:
    if (INT_SUCCESS(status))
    {
        if (currentHash > 0)
        {
            UtilQuickSort(Hashes, currentHash, sizeof(DWORD));

            *HashesCount = currentHash;
        }
        else
        {
            status = INT_STATUS_NOT_FOUND;
        }
    }

    return status;
}


__pure INTSTATUS
IntFragMatchSignature(
    _In_ const DWORD *Hashes,
    _In_ DWORD CodeBlocksCount,
    _In_ const SIG_CODEBLOCKS *ExceptionSignature
    )
///
/// @brief Match a block of code-block hashes against a list of code-block exception signatures.
///
/// This function will attempt to match the code-blocks located in the Hashes variable against the code-block signature
/// list inside ExceptionSignature.
///
/// @param[in]  Hashes              The list of hashes to be matched.
/// @param[in]  CodeBlocksCount     Number of hashes in Hashes.
/// @param[in]  ExceptionSignature  the exception signature containing the hashes to match against.
///
/// @retval #INT_STATUS_SIGNATURE_MATCHED If the Hashes block matches a signature inside ExceptionSignature.
/// @retval #INT_STATUS_SIGNATURE_NOT_FOUND If no match is found.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
///
{
    DWORD i;
    const SIG_CODEBLOCK_HASH *pSigHash;

    if (NULL == Hashes)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == CodeBlocksCount)
    {
        return INT_STATUS_INVALID_PARAMETER_2;
    }

    if (NULL == ExceptionSignature)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pSigHash = (const SIG_CODEBLOCK_HASH *)ExceptionSignature->Object;
    for (i = 0; i < ExceptionSignature->ListsCount; i++)
    {
        DWORD hashSize = sizeof(*pSigHash) + pSigHash->Count * sizeof(DWORD);
        DWORD j, remaining, currentCb;

        remaining = ExceptionSignature->Score;
        currentCb = 0;

        for (j = 0; j < pSigHash->Count; j++)
        {
            for (; currentCb < CodeBlocksCount; currentCb++)
            {
                if (pSigHash->Hashes[j] < Hashes[currentCb])
                {
                    break;          // no point in going further, since the hashes are sorted
                }
                else if (pSigHash->Hashes[j] == Hashes[currentCb])
                {
                    remaining--;
                    break;          // go to the next hash in pSigHashes
                }
            }
        }

        if ((int)remaining <= 0)
        {
            // Found our signature
            return INT_STATUS_SIGNATURE_MATCHED;
        }

        // advance to the next hash list
        pSigHash = (const SIG_CODEBLOCK_HASH *)((const BYTE *)pSigHash + hashSize);
    }

    return INT_STATUS_SIGNATURE_NOT_FOUND;
}


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
    )
///
/// @brief Extract a pattern of code-blocks from the given code buffer.
///
/// This function will parse the provided code buffer, and it will extract a pattern of #CODE_INS values representing
/// the relevant instructions located inside the buffer. The pattern can then be used to compute hashes (code-blocks).
/// This function will use the disassembler to decode each instruction inside the Buffer, and depending on the
/// instruction type, a #CODE_INS value will be outputted inside the Pattern buffer. This function may also call the
/// optimized #IntFragHandleCommon function which will try to handle the current instruction without calling the
/// disassembler, but if it fails, it will still rely on it.
///
/// @param[in]  Buffer          The code buffer to be parsed.
/// @param[in]  StartOffset     The offset to start the parsing at.
/// @param[in]  MaxBufferSize   The size of the code buffer.
/// @param[in]  CsType          Operating mode, should be #IG_CS_TYPE_32B or #IG_CS_TYPE_64B.
/// @param[in]  ExtractLevel    #cbLevelNormal or #cbLevelMedium.
/// @param[in]  PatternSize     Maximum size of the pattern.
/// @param[out] Pattern         The pattern of instructions located in Buffer.
/// @param[out] TotalExtracted  Number of #CODE_INS values extracted from the Buffer into Pattern.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If the buffer is too small (the last instructions cannot be parsed).
///
{
    INSTRUX instrux;
    DWORD i, currentOffset;
    PBYTE end;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (NULL == TotalExtracted)
    {
        return INT_STATUS_INVALID_PARAMETER_8;
    }

    if (NULL == Pattern)
    {
        return INT_STATUS_INVALID_PARAMETER_7;
    }

    if (MaxBufferSize <= ND_MAX_INSTRUCTION_LENGTH)
    {
        return INT_STATUS_DATA_BUFFER_TOO_SMALL;
    }

    end = Buffer + MaxBufferSize - ND_MAX_INSTRUCTION_LENGTH;
    i = 0;
    currentOffset = StartOffset;

    if (IG_CS_TYPE_16B == CsType)
    {
        // Log this since it shouldn't really happen
        WARNING("[WARNING] Extracting codeblocks for 16 bit!\n");
    }

    *TotalExtracted = 0;

    while ((Buffer < end) && (i < PatternSize))
    {
        NDSTATUS ndstatus;

        ndstatus = IntDecDecodeInstructionFromBuffer(Buffer, (size_t)(end - Buffer), CsType, &instrux);
        if (!ND_SUCCESS(ndstatus))
        {
            Buffer++;
            currentOffset++;
            continue;
        }

        if (Buffer + instrux.Length >= end)
        {
            break;
        }

        if (instrux.Instruction == ND_INS_Jcc)
        {
            Pattern[i].Value = codeInsJc;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_JMPE ||
                 instrux.Instruction == ND_INS_JMPFD ||
                 instrux.Instruction == ND_INS_JMPFI ||
                 instrux.Instruction == ND_INS_JMPNI ||
                 instrux.Instruction == ND_INS_JMPNR)
        {
            Pattern[i].Value = codeInsJmp;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_CALLFD ||
                 instrux.Instruction == ND_INS_CALLFI ||
                 instrux.Instruction == ND_INS_CALLNI ||
                 instrux.Instruction == ND_INS_CALLNR)
        {
            Pattern[i].Value = codeInsCall;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_RETF ||
                 instrux.Instruction == ND_INS_RETN)
        {
            Pattern[i].Value = codeInsRet;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_STOS ||
                 instrux.Instruction == ND_INS_LODS)
        {
            Pattern[i].Value = codeInsStr;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_XCHG ||
                 instrux.Instruction == ND_INS_CMPXCHG)
        {
            Pattern[i].Value = codeInsXchg;
            Pattern[i++].Offset = currentOffset;
        }
        else if (instrux.Instruction == ND_INS_BT ||
                 instrux.Instruction == ND_INS_BTC ||
                 instrux.Instruction == ND_INS_BTR ||
                 instrux.Instruction == ND_INS_BTS)
        {
            Pattern[i].Value = codeInsBt;
            Pattern[i++].Offset = currentOffset;
        }

        // If we are at the normal level, go to the next instruction, don't extract further
        if (ExtractLevel == cbLevelNormal)
        {
            goto _next_instruction;
        }

        if (instrux.Instruction == ND_INS_MOV)
        {
            if (instrux.Operands[0].Type == ND_OP_REG &&
                instrux.Operands[1].Type == ND_OP_REG)
            {
                Pattern[i].Value = codeInsMovReg;
                Pattern[i++].Offset = currentOffset;
            }
            else if (instrux.Operands[0].Type == ND_OP_MEM ||
                     instrux.Operands[1].Type == ND_OP_MEM)
            {
                Pattern[i].Value = codeInsMovMem;
                Pattern[i++].Offset = currentOffset;
            }
            else if (instrux.HasImm1)
            {
                Pattern[i].Value = codeInsMovImm;
                Pattern[i++].Offset = currentOffset;
            }
            else if (instrux.Seg == ND_PREFIX_G2_SEG_FS ||
                     instrux.Seg == ND_PREFIX_G2_SEG_GS)
            {
                Pattern[i].Value = codeInsMovFsGs;
                Pattern[i++].Offset = currentOffset;
            }
        }
        else if (instrux.Instruction == ND_INS_PUSHF ||
                 instrux.Instruction == ND_INS_POPF)
        {
            Pattern[i].Value = codeInsFlags;
            Pattern[i++].Offset = currentOffset;
        }

        // We are done with the medium level
        if (ExtractLevel == cbLevelMedium)
        {
            goto _next_instruction;
        }

_next_instruction:
        Buffer += instrux.Length;
        currentOffset += instrux.Length;
    }

    *TotalExtracted = i;

    return INT_STATUS_SUCCESS;
}


static void
IntFragLogCodeBlocks(
    _In_ CODE_BLOCK *CodeBlock,
    _In_ DWORD Count,
    _In_ QWORD Rip,
    _In_ DWORD RipOffset,
    _In_ BOOLEAN ReturnRip,
    _In_ DWORD ElemLine
    )
///
/// @brief Log a block of code-blocks.
///
/// @param[in]  CodeBlock   The list of code-blocks.
/// @param[in]  Count       Number of code-blocks.
/// @param[in]  Rip         The Rip the code-blocks start at.
/// @param[in]  RipOffset   Rip page offset (low 12 bits of Rip).
/// @param[in]  ReturnRip   The return Rip.
/// @param[in]  ElemLine    Number of elements to dump on one line.
///
{
    DWORD previousOffset;
    int ret;
    int maxLength = sizeof(gCbLog);
    CHAR *pCbLine = NULL;
    BOOLEAN loggedRip = FALSE;

    if (Count == 0)
    {
        return;
    }

    //
    // Compute a hash on the extracted codeblocks
    //
    previousOffset = CodeBlock[0].OffsetStart;
    for (DWORD i = 0; i < Count; i++)
    {
        if (i % ElemLine == 0)
        {
            if (i > 0)
            {
                // Log formatted codeblocks line
                // Remove comma
                *(pCbLine - 2) = ' ';
                LOG("%s\n", gCbLog);
            }

            // Start formatting a new codeblocks line
            pCbLine = gCbLog;
            maxLength = sizeof(gCbLog);

            ret = snprintf(pCbLine, maxLength, "[CODEBLOCKS] ");
            if (ret < 0 || ret >= maxLength)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, maxLength);
                return;
            }
            else
            {
                pCbLine += ret;
                maxLength -= ret;
            }
        }

        CodeBlock[i].Hash = Crc32Compute(CodeBlock[i].Chunks, CODE_BLOCK_CHUNKS_COUNT, INITIAL_CRC_VALUE);

        if (!loggedRip && ((previousOffset <= RipOffset && RipOffset <= CodeBlock[i].OffsetStart) ||
                           (i == 0 && CodeBlock[i].OffsetStart >= RipOffset) ||
                           (i == Count - 1)))
        {

            ret = snprintf(pCbLine, maxLength, "(%7s->0x%016llx), ", ReturnRip ? "Ret RIP" : "RIP", Rip);
            if (ret < 0 || ret >= maxLength)
            {
                ERROR("[ERROR] snprintf error: %d, size %d\n", ret, maxLength);
                return;
            }
            else
            {
                pCbLine += ret;
                maxLength -= ret;
            }

            loggedRip = TRUE;
        }

        ret = snprintf(pCbLine, maxLength, "0x%08x (0x%03x, %9s), ", CodeBlock[i].Hash, CodeBlock[i].OffsetStart,
                       (CodeBlock[i].PivotInstruction == codeInsCall) ? "CALL" :
                       (CodeBlock[i].PivotInstruction == codeInsJmp) ? "JMP" :
                       (CodeBlock[i].PivotInstruction == codeInsMovMem) ? "MOV MEM" :
                       (CodeBlock[i].PivotInstruction == codeInsMovFsGs) ? "MOV FS/GS" : "INVALID");
        if (ret < 0 || ret >= maxLength)
        {
            ERROR("[ERROR] snprintf error: %d, size %d\n", ret, maxLength);
            return;
        }
        else
        {
            pCbLine += ret;
            maxLength -= ret;
        }

        previousOffset = CodeBlock[i].OffsetStart;
    }

    *(pCbLine - 2) = ' ';
    LOG("%s\n", gCbLog);
}


INTSTATUS
IntFragDumpBlocks(
    _In_ PBYTE Buffer,
    _In_ QWORD StartAddress,
    _In_ DWORD MaxBufferSize,
    _In_ IG_CS_TYPE CsType,
    _In_ CB_EXTRACT_LEVEL ExtractLevel,
    _In_ QWORD Rip,
    _In_ BOOLEAN ReturnRip
    )
///
/// @brief Dumps code-blocks that can then be used to generate an exception signature.
///
/// @param[in]  Buffer          The code buffer to be parsed.
/// @param[in]  StartAddress    The offset to start the parsing at.
/// @param[in]  MaxBufferSize   The size of the code buffer.
/// @param[in]  CsType          Operating mode, should be #IG_CS_TYPE_32B or #IG_CS_TYPE_64B.
/// @param[in]  ExtractLevel    #cbLevelNormal or #cbLevelMedium.
/// @param[in]  Rip             The current Rip.
/// @param[in]  ReturnRip       The return Rip.
///
/// @retval #INT_STATUS_SUCCESS On success.
/// @retval #INT_STATUS_INVALID_PARAMETER If an invalid parameter is supplied.
/// @retval #INT_STATUS_INSUFFICIENT_RESOURCES If a memory alloc fails.
/// @retval #INT_STATUS_DATA_BUFFER_TOO_SMALL If at least #CODE_BLOCK_CHUNKS_COUNT could not be extracted.
///
{
    PCODE_BLOCK_PATTERN pattern;
    PCODE_BLOCK pCdBlk;
    DWORD i, j, patternSize, currentCb, previousOffset;
    DWORD cbCount, ripOffset;
    INTSTATUS status;

    if (NULL == Buffer)
    {
        return INT_STATUS_INVALID_PARAMETER_1;
    }

    if (0 == MaxBufferSize)
    {
        return INT_STATUS_INVALID_PARAMETER_3;
    }

    pCdBlk = NULL;
    pattern = NULL;
    patternSize = currentCb = previousOffset = 0;
    cbCount = PAGE_SIZE / sizeof(CODE_BLOCK);
    ripOffset = Rip & PAGE_OFFSET;

    pCdBlk = HpAllocWithTag(PAGE_SIZE, IC_TAG_CDBK);
    if (NULL == pCdBlk)
    {
        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    pattern = HpAllocWithTag(PAGE_SIZE, IC_TAG_CDBK);
    if (NULL == pattern)
    {
        HpFreeAndNullWithTag(&pCdBlk, IC_TAG_CDBK);

        return INT_STATUS_INSUFFICIENT_RESOURCES;
    }

    status = IntFragExtractCodePattern(Buffer,
                                       StartAddress & PAGE_OFFSET,
                                       MaxBufferSize,
                                       CsType,
                                       ExtractLevel,
                                       PAGE_SIZE / sizeof(CODE_BLOCK_PATTERN),
                                       pattern,
                                       &patternSize);
    if (!INT_SUCCESS(status))
    {
        if (status == INT_STATUS_DATA_BUFFER_TOO_SMALL)
        {
            WARNING("[WARNNING] Buffer too small to extract codeblocks (size %d): 0x%08x\n", MaxBufferSize, status);
        }
        else
        {
            ERROR("[ERROR] IntFragExtractCodePattern: 0x%08x\n", status);
        }

        goto leave;
    }

    if (patternSize < CODE_BLOCK_CHUNKS_COUNT)
    {
        WARNING("[WARNING] Could not extract enough code-blocks: %d\n", patternSize);
        status = INT_STATUS_DATA_BUFFER_TOO_SMALL;
        goto leave;
    }

    for (i = 0; i < patternSize - CODE_BLOCK_CHUNKS_COUNT; i++)
    {
        if (cbLevelNormal == ExtractLevel &&
            (codeInsCall != pattern[i].Value &&
             codeInsJmp != pattern[i].Value))
        {
            continue;
        }

        if (cbLevelMedium == ExtractLevel &&
            (codeInsCall != pattern[i].Value &&
             codeInsJmp != pattern[i].Value &&
             codeInsMovMem != pattern[i].Value &&
             codeInsMovFsGs != pattern[i].Value))
        {
            continue;
        }

        pCdBlk[currentCb].PivotInstruction = pattern[i].Value;
        pCdBlk[currentCb].OffsetStart = pattern[i].Offset;

        // Extract from offset, CODE_BLOCK_CHUNKS_COUNT forward
        for (j = 0; j < CODE_BLOCK_CHUNKS_COUNT; j++)
        {
            pCdBlk[currentCb].Chunks[j] = pattern[i + j].Value;
            pCdBlk[currentCb].Size++;
        }

        // Exit if we reached our target
        if (++currentCb >= cbCount)
        {
            break;
        }
    }

    IntFragLogCodeBlocks(pCdBlk, currentCb, Rip, ripOffset, ReturnRip, 8);

leave:
    HpFreeAndNullWithTag(&pCdBlk, IC_TAG_CDBK);
    HpFreeAndNullWithTag(&pattern, IC_TAG_CDBK);

    return status;
}
