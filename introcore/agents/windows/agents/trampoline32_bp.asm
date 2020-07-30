;-----------------------------------------------------------------------------
            [bits 32]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:     ; Bootstrap entry code. Executed when detouring execution towards our code.
            push        eax             ; Save RAX.
            int3
            test        eax, eax
            jz          _skip
            call        eax             ; On VM-Entry, the HV will store in rax the function address.
_skip:
            pop         eax             ; Restore RAX.
            retn                        ; And return to the interrupted code - the HV will fix the stack ([rsp] -= 5)
_stop:      ; Bootstrap stop code. Executed when the thread finished execution. This is needed, in order to be able to
            ; free the allocated slack space for the stage 2 loader.
            int3
            xor         eax, eax
            retn