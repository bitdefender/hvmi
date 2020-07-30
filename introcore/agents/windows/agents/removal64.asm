;-----------------------------------------------------------------------------
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
; Imports of any kind
            extern      MessageBoxA
            extern      ExitProcess

;-----------------------------------------------------------------------------
; Sections
            section .data

message     db       "Hello world from the removal tool!",0
title       db       "Removal tool",0

            section .text

_start:
            sub     rsp, 0x28

            xor     rcx, rcx
            lea     rdx, [message]
            lea     r8, [title]
            xor     r9, r9
            call    MessageBoxA

            xor     rcx, rcx
            call    ExitProcess