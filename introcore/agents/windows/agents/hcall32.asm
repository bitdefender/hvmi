;-----------------------------------------------------------------------------
            [bits 32]
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
_start:     push    ebp
            mov     ebp, esp

            push    ecx
            push    edx
            push    ebx
            push    esi
            push    edi

            mov     eax, [ebp + 8]
            mov     ecx, [ebp + 12]
            mov     edx, [ebp + 16]
            mov     ebx, [ebp + 20]
            mov     esi, [ebp + 24]
            mov     edi, [ebp + 28]

            vmcall
            
            mov     eax, edx

            pop     edi
            pop     esi
            pop     ebx
            pop     edx
            pop     ecx

            pop     ebp

            retn    24