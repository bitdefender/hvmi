[bits 64]

section .text

global IntroCall64

; RCX = pointer to the software list
; RDX = task id
IntroCall64:
; RAX = 34
; RDI = 24
; RSI = 0
; RDX = AGENT_HCALL_*
; RBX = pointer to a event structure

    push    rax         ; save RAX
    push    rdi         ; save RDI
    push    rsi         ; save RSI
    push    rbx         ; save RBX
    
    mov     eax, 34     ; magic
    mov     edi, 24     ; SubOp
    xor     rsi, rsi    ; clear RSI
    mov     rbx, rcx    ; Message
    ; RDX already contains the hcall number

    vmcall              ; notify the HV

    pop     rbx         ; restore RBX
    pop     rsi         ; restore RSI
    pop     rdi         ; restore RDI
    pop     rax         ; restore RAX

    retn
