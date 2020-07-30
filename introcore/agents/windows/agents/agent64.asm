;-----------------------------------------------------------------------------
            [bits 64]
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
                     ; Save all registers - we don't know who and what state we've interrupted.
                     push        rax
                     push        rcx
                     push        rdx
                     push        rbx
                     push        rbp
                     push        rsi
                     push        rdi
                     push        r8
                     push        r9
                     push        r10
                     push        r11
                     push        r12
                     push        r13
                     push        r14
                     push        r15

                     ; The stack must be kept 16-bytes aligned. If we're not 16-bytes aligned here, do it.
                     xor         r14,r14
                     test        rsp, 0xF
                     jz          _start
                     mov         r14, 0x8
                     sub         rsp, r14

_start:
                     ; The stack is 16-bytes aligned here.

                     ; Alloc the agent buffer
                     xor         ecx, ecx                               ; Alloc in nonpaged pool
                     mov         edx, dword [rel dwAgentSize]           ; The size, as given by the introcore
                     mov         r8d, dword [rel dwAgentTag]            ; The tag, ad given by the introcore
                     sub         rsp, 0x20                              ; Alloc shadow stack space.
                     call        qword [rel ExAllocatePoolWithTag]      ; Alloc the agent space
                     add         rsp, 0x20
                     
                     add         rsp, r14                               ; Introcore may decide to de-alloc the bootstrap, so put the stack as it was before.
                     
                     xor         rsi, rsi
                     test        rax, rax
                     jnz          _signal_alloc

                     mov         rsi, 0xC000009A
_signal_alloc:
                     mov         rcx, rax                               ; Save return address in rcx
                     mov         rdx, qword [rel token1]                ; Token in edx
                     int3                                               ; Signal introcore that the buffer has been allocated
                     
                     sub         rsp, r14                               ; Re-align the stack to 16 bytes

                     mov         r15, rcx                               ; Copy back the buffer address
                     mov         r13, r15                               ; Keep the copy in r13 so that we can de-alloc it if thread creation fails (r13 non-volatile, should be OK)
                     mov         r8d, dword [rel dwAgentEp]
                     add         r15, r8

                     ; Create a thread inside the agent. an even number of 8 bytes must be allocated on the stack, as it must
                     ; be kept 16-bytes aligned.
                     sub         rsp, 8
                     mov         rcx, rsp
                     mov         edx, 0x001F0000                        ; Desired access
                     xor         r8, r8                                 ; object attributes
                     xor         r9, r9                                 ; process handle
                     push        r15                                    ; start context
                     lea         rax, [rel ThreadHandler]               ; The entry point
                     push        rax                                    ; thread function/agent entry point
                     push        0
                     sub         rsp, 8 * 4
                     call        qword [rel PsCreateSystemThread]       ; Create the thread!
                     add         rsp, 8 * 8                             ; Clear the stack - 7 arguments + the thread handle

                     test        eax, eax
                     jns         _notify_intro_thread
                     
                     push        rax
                     sub         rsp, 0x28                              ; 0x28 because 0x20 is for the shadow stack space, and 0x8 in order to keep the stack aligned to 16 bytes (as we previously pushed RAX)
                     mov         rcx, r13                               ; r13 is the previously saved copy of the allocated agent address
                     mov         edx, dword [rel dwAgentTag]
                     call        qword [rel ExFreePoolWithTag]
                     add         rsp, 0x28
                     pop         rax
                     
_notify_intro_thread:
                     ; Restore the stack, as we previously aligned it.
                     add         rsp, r14
                     mov         rcx, rax
                     mov         rdx, qword [rel token2]
                     int3                                               ; Notify that the thread has been started

                     ; Restore every saved register - this will be done by the HVI. Also, jumping to the
                     ; interrupted code will also be done by the HVI.
                     ;pop         r15
                     ;pop         r14
                     ;pop         r13
                     ;pop         r12
                     ;pop         r11
                     ;pop         r10
                     ;pop         r9
                     ;pop         r8
                     ;pop         rdi
                     ;pop         rsi
                     ;pop         rbp
                     ;pop         rbx
                     ;pop         rdx
                     ;pop         rcx
                     ;pop         rax

                     ; Jump back to the original code that we interrupted.
                     ;ret

;================================================================================================================================
ThreadHandler:       ; On entry, the stack is not 16 bytes aligned. On each call, the stack must be aligned before the call;
                     ; the call will push 8 more bytes on the stack, unaligning it.
                     ; IMPORTANT: Save any non-volatile register that is used here (http://msdn.microsoft.com/en-us/library/9z1stfyw.aspx)
                     ; RAX, RCX, RDX, R8, R9, R10 and R11 can be safely modified.
_spin:               pause
                     cmp         dword [rel dwSemaphore], 0
                     jz          _spin

                     ; Save RCX - this also aligns the stack.
                     push        rcx
                     ; Alloc shadow stack space.
                     sub         rsp, 0x20
                     ; Aligned stack here.
                     call        rcx
                     ; Restore RCX, as it may have been modified.
                     mov         rcx, qword [rsp + 0x20]

                     ; Zero out the agent region.
                     push        rdi
                     mov         rdi, rcx
                     mov         ecx, dword [rel dwAgentEp]
                     sub         rdi, rcx
                     mov         r8, rdi
                     mov         ecx, dword [rel dwAgentSize]
                     xor         eax, eax
                     rep         stosb
                     mov         rcx, r8
                     pop         rdi

                     ; Free the driver memory.
                     mov         edx, dword [rel dwAgentTag]
                     call        qword [rel ExFreePoolWithTag]

                     ; Clear out the stack.
                     add         rsp, 0x28

                     ; We're done here. We can do the cleanup now.
                     mov         rdx, qword [rel token3]
                     int3

                     ; Jump back to the trampoline. We're done.
                     jmp         qword [rel jumpback]

                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
;================================================================================================================================



; These variables will be filled by the introspection engine upon initialization.
ExAllocatePoolWithTag    dq          0
ExFreePoolWithTag        dq          0
PsCreateSystemThread     dq          0

; These will be filled in by the introspection engine on agent injection
dwAgentSize              dd          0
dwAgentTag               dd          0
dwAgentEp                dd          0
dwSemaphore              dd          0
token1                   dq          0
token2                   dq          0
token3                   dq          0
jumpback                 dq          0
reserved                 dq          0