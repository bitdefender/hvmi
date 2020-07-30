;-----------------------------------------------------------------------------
            [bits 64]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:     ; Bootstrap entry code. Executed when detouring execution towards our code.
            push        rax             ; Save RAX.
            int3
            test        rax, rax
            jz          _skip
            call        rax             ; On VM-Entry, the HV will store in rax the function address.
_skip:
            pop         rax             ; Restore RAX.
            retn                        ; And return to the interrupted code - the HV will fix the stack ([rsp] -= 5)
_stop:      ; Bootstrap stop code. Executed when the thread finished execution. This is needed, in order to be able to
            ; free the allocated slack space for the stage 2 loader.
            int3
            xor         eax, eax
            retn