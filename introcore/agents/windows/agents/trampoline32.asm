;-----------------------------------------------------------------------------
            [bits 32]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:     ; Bootstrap entry code. Executed when detouring execution towards our code.
            push        eax             ; Save EAX.
            push        ebx             ; Save EBX.
            push        ecx             ; Save ECX.
            mov         eax, 34         ; This magic will do a VMCALL inside intro.
            mov         ebx, 24         ; SubOp for the intro specific VMCALL.
            xor         ecx, ecx        ; ECX must be 0, for Xen compatibility.
            vmcall                      ; Invoke the HV.
            mov         eax, ecx
            pop         ecx
            pop         ebx
            test        eax, eax
            jz          _skip
            call        eax             ; On VM-Entry, the HV will store in rax the function address.
_skip:
            pop         eax             ; Restore RAX.
            retn                        ; And return to the interrupted code - the HV will fix the stack ([rsp] -= 5)
_stop:      ; Bootstrap stop code. Executed when the thread finished execution. This is needed, in order to be able to
            ; free the allocated slack space for the stage 2 loader.
            push        ebx
            push        ecx
            mov         eax, 34
            mov         ebx, 24
            xor         ecx, ecx
            vmcall
            pop         ecx
            pop         ebx
            xor         eax, eax
            retn