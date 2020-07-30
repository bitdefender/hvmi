;-----------------------------------------------------------------------------
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
; Imports of any kind
            extern      _MessageBoxA@16
            extern      _ExitProcess@4

;-----------------------------------------------------------------------------
; Sections
            section .data

message     db       "Hello world from the removal tool!",0
title       db       "Removal tool",0

            section .text
            
_start:
            push    0
            push    title
            push    message
            push    0
            call    _MessageBoxA@16

            push    0
            call    _ExitProcess@4