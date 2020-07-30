;-----------------------------------------------------------------------------
            [bits 32]
; Global symbols
            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
                     ; Save all registers - we don't know who and what state we've interrupted.
                     pusha
                     
_start:              mov         ebp, 0xBDBDBDBD
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop
                     nop

                     ; Alloc the agent buffer
                     push        dword [ebp + dwAgentTag]
                     push        dword [ebp + dwAgentSize]
                     push        0
                     call        dword [ebp + ExAllocatePoolWithTag]    ; Alloc the agent space

                     xor         esi, esi
                     test        eax, eax
                     jnz          _signal_alloc

                     mov         esi, 0xC000009A
_signal_alloc:
                     mov         ecx, eax                               ; Save return address in edx
                     mov         edx, dword [ebp + token1]              ; Token in edx
                     int3                                               ; Signal introcore that the buffer has been allocated

                     mov         eax, ecx                               ; Copy back the buffer address
                     mov         esi, eax                               ; Keep the copy in esi so that we can de-alloc it if thread creation fails (esi non-volatile, should be OK)
                     mov         ebx, dword [ebp + dwAgentEp]
                     add         eax, ebx

                     ; Create a thread inside the agent
                     sub         esp, 8
                     push        eax
                     lea         ecx, [ebp + ThreadHandler]
                     push        ecx
                     push        0
                     push        0
                     push        0
                     push        0x001F0000
                     lea         ecx, [esp + 24]
                     push        ecx
                     call        dword [ebp + PsCreateSystemThread]     ; Create the thread!
                     add         esp, 8
                     
                     test        eax, eax
                     jns         _notify_intro_thread

                     push        eax
                     push        dword [ebp + dwAgentTag]
                     push        esi                                    ; esi is the previously saved copy of the allocated agent address
                     call        dword [ebp + ExFreePoolWithTag]
                     pop         eax

_notify_intro_thread:
                     mov         ecx, eax
                     mov         edx, dword [ebp + token2]
                     int3                                             ; Notify that the thread has been started

                     ; Restore every saved register - this will be done by HVI.
                     ;popa

                     ; Jump back to the original code that we interrupted.
                     ;ret
;================================================================================================================================
ThreadHandler:
                     pusha

                     call        _next2
_next2:              pop         ebp
                     sub         ebp, _next2

_spin:               pause
                     cmp         dword [ebp + dwSemaphore], 0
                     jz          _spin

                     mov         ecx, dword [esp + 32 + 4] ; Get the handler routine

                     ; simply call the agent code
                     push        ecx
                     sub         esp, 8                ; 2 arguments for the driver - none of them should be used!
                     call        ecx
                     mov         ecx, dword [esp]      ; Restore the EP address. 8 bytes will be unloaded from the stack by the driver function.

                     mov         edi, ecx
                     sub         edi, dword [ebp + dwAgentEp]
                     mov         esi, edi
                     mov         ecx, dword [ebp + dwAgentSize]
                     xor         eax, eax
                     rep         stosb

                     push        dword [ebp + dwAgentTag]
                     push        esi
                     call        dword [ebp + ExFreePoolWithTag]

                     add         esp, 4

                     ; we're done here. We can do the cleanup now.
                     mov         edx, dword [ebp + token3]
                     int3

                     mov         eax, dword [ebp + jumpback]
                     mov         dword [esp + 0x1C], eax

                     popa

                     jmp         eax

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
                     nop
                     nop
                     nop
;================================================================================================================================



; These variables will be filled by the introspection engine upon initialization.
ExAllocatePoolWithTag    dd          0
ExFreePoolWithTag        dd          0
PsCreateSystemThread     dd          0

; These will be filled in by the introspection engine on agent injection
dwAgentSize              dd          0
dwAgentTag               dd          0
dwAgentEp                dd          0
dwSemaphore              dd          0
token1                   dd          0
token2                   dd          0
token3                   dd          0
jumpback                 dd          0
reserved                 dd          0

