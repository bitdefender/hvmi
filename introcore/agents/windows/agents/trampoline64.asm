;-----------------------------------------------------------------------------
            [bits 64]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:     ; Bootstrap entry code. Executed when detouring execution towards our code.
            push        rax             ; Save RAX.
            push        rdi             ; Save RDI.
            push        rsi             ; Save RSI.
            mov         eax, 34         ; This magic will do a VMCALL inside intro.
            mov         edi, 24         ; SubOp.
            xor         esi, esi        ; Clear RSI.
            vmcall                      ; Invoke the HV.
            mov         rax, rsi
            pop         rsi
            pop         rdi
            test        rax, rax
            jz          _skip
            call        rax             ; On VM-Entry, the HV will store in rax the function address.
_skip:
            pop         rax             ; Restore RAX.
            retn                        ; And return to the interrupted code - the HV will fix the stack ([rsp] -= 5)
_stop:      ; Bootstrap stop code. Executed when the thread finished execution. This is needed, in order to be able to
            ; free the allocated slack space for the stage 2 loader.
            push        rdi
            push        rsi
            mov         eax, 34
            mov         edi, 24
            xor         esi, esi
            vmcall
            pop         rsi
            pop         rdi
            xor         eax, eax
            retn