;-----------------------------------------------------------------------------
            [bits 64]
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:
            push    rcx
            push    rdx
            push    rbx
            push    rsi
            push    rdi

            mov     rax, rcx ; Magic/tag
            mov     rcx, rdx ; Maximum size
            mov     rdx, r8  ; Buffer address
            mov     rbx, r9  ; Hypercall value
            mov     rsi, [rsp + 80]
            mov     rdi, [rsp + 88]

            vmcall
            
            mov     rax, rdx

            pop     rdi
            pop     rsi
            pop     rbx
            pop     rdx
            pop     rcx

            retn