[bits 32]

section .text

global _IntroCall32

; [esp + 4] = pointer to the agent context
; [esp + 8] = task id
_IntroCall32:
; EAX = 34
; EBX = 24
; ECX = 0
; EDX = AGENT_HCALL_*
; ESI = pointer to the event structure

    mov     edi, edi
    push    ebp
    mov     ebp, esp

    push    eax         ; save EAX
    push    ebx         ; save EBX
    push    ecx         ; save ECX
    push    edx         ; save EDX
    push    esi         ; save ESI

    mov     eax, 34     ; magic
    mov     ebx, 24     ; SubOp
    xor     ecx, ecx    ; clear ECX
    mov     edx, [esp + 0x20]   ; Hcall
    mov     esi, [esp + 0x1C]   ; Message

    vmcall              ; notify the HV, hcall at [esp + 0x20], message at [esp + 0x1C]

    pop     esi         ; restore ESI
    pop     edx         ; restore EDX
    pop     ecx         ; restore ECX
    pop     ebx         ; restore EBX
    pop     eax         ; restore EAX

    mov     esp, ebp
    pop     ebp

    retn
