; Exception stubs.
global VeCoreVirtualizationExceptionHandlerNoKPTI
global VeCoreVirtualizationExceptionHandlerKPTI
global VeCoreVirtualizationExceptionHandler
global VeCoreExecuteInstruction
global VeCoreInstructionsTable

global VeCoreProtectedEptIndex
global VeCoreUntrustedEptIndex
global VeCoreJumpToKiKernelExit
global VeCoreJumpToReplacedCode
global VeCoreReplacedCode
global VeCpuMap

extern VirtualizationExceptionHandler

%define vmfunc      db 0x0f, 0x01, 0xd4

extern VeCoreVePages

    section .data

bUseIBRS            db      0
bUseSTIBP           db      0
bUseIBPB            db      0
bUseMDCLEAR         db      0
bSpectreMitInit     db      0

    ; This section contains the mapping between the kernel PCR (IA32_GS_BASE/IA32_KERNEL_GS_BASE) and the #VE info
    ; page. There isn't any other reliable way of determining the CPU number, as the ID between what we see from HVI
    ; and what the guest sees may differ.
    section VECPUMAP

VeCpuMap:
times 64 dd 0x0

    ; This section will be mapped Executable is both EPT views.
    section VESTUB


;
; This handler is used by the Windows 7, 8, 8.1, TH1, TH2, RS1 and RS2, no KPTI - these versions are not aware of the
; VirtualizationException, and as such it is treated just like any unexpected interrupt. The Windows stub is:
; PUSH 0x14
; PUSH rbp
; JMP KiUnexpectedInterrupt
;
VeCoreVirtualizationExceptionHandlerNoKPTI:
    cmp         byte [rsp + 8], 0x14    ; Make sure this is indeed #VE.
    jne         _not_ve                 ; If it's not, we can return to the original KiIsrThunk handler.
    add         rsp, 16                 ; Otherwise, clear the stack
    jmp         VeCoreVirtualizationExceptionHandler


;
; This handler is used by the Windows 7, 8, 8.1, TH1, TH2, RS1 and RS2, with KPTI - these versions are not aware of the
; VirtualizationException, but since KPTI is no, the stub is different than when KPTI is off:
; PUSH 0x14
; JMP KiIstLinkage
;
VeCoreVirtualizationExceptionHandlerKPTI:
    cmp         byte [rsp], 0x14        ; Make sure this is indeed #VE.
    jne         _not_ve                 ; If it's not, we can return to the original KiIsrThunk handler.
    add         rsp, 8                  ; Otherwise, clear the stack
    jmp         VeCoreVirtualizationExceptionHandler


;
; VeCoreVirtualizationExceptionHandler
;
VeCoreVirtualizationExceptionHandler:
    ; Save rax & rcx. We can't do this after VMFUNC, because we need them for the VMFUNC (eax = leaf function, 
    ; ecx - EPTP index if eax is 0).
    push        rax
    push        rcx

    ; Switch into the protected view
    xor         eax, eax

    ; mov ecx, 1 - protected EPT index.
    db 0xB9                             ; MOV ecx, imm32 opcode
VeCoreProtectedEptIndex:
    db 0x01, 0x00, 0x00, 0x00           ; imm32 - the ept index
    vmfunc

    ; Load a known, good RFLAGS value.
    push        2
    popfq

    ; Right here, we're inside the protected view, but we're still with the old, untrusted stack.
    push        rdx
    push        rbx

    mov         eax, 0x50
    lsl         eax, eax
    mov         edx, eax
    and         edx, 0x3FF
    shl         edx, 6
    shr         eax, 0xE
    or          eax, edx
    lea         rbx, [rel VeCpuMap]
    mov         ebx, [rbx + rax * 4]
    shl         rbx, 12

    ; Compute the address of the #VE info page for this CPU.
    lea         rcx, [rel VeCoreVePages]
    add         rcx, rbx

    ; Save the rest of the registers and those that have been saved already, inside the #VE information page.
    mov         rax, [rsp + 0x18]
    mov         qword [rcx + 0x30], rax     ; Save RAX.
    mov         rax, [rsp + 0x10]
    mov         qword [rcx + 0x38], rax     ; Save RCX.
    mov         rax, [rsp + 0x8]
    mov         qword [rcx + 0x40], rax     ; Save RDX.
    mov         rax, [rsp + 0x0]
    mov         qword [rcx + 0x48], rax     ; Save RBX.
    
    ; We want to save thge original RSP, as if the #VE didn't take place. We have to skip what we've saved
    ; (RAX, RCX, RDX, RBX) and the saved RIP, CS and RFLAGS. Note that we do not have to deal with stack
    ; switching, as we're in long mode and the SS/RSP are always saved on the stack.
    mov         rax, [rsp + 0x38]
    mov         [rcx + 0x50], rax           ; Save the saved RSP.
    mov         rax, [rsp + 0x40]
    mov         [rcx + 0xE8], rax           ; Save the saved SS.

_stack_done:
    ; Save the rest of the GPRs.
    mov         [rcx + 0x58], rbp           ; RBP
    mov         [rcx + 0x60], rsi           ; RSI
    mov         [rcx + 0x68], rdi           ; RDI
    mov         [rcx + 0x70], r8            ; R8
    mov         [rcx + 0x78], r9            ; R9
    mov         [rcx + 0x80], r10           ; R10
    mov         [rcx + 0x88], r11           ; R11
    mov         [rcx + 0x90], r12           ; R12
    mov         [rcx + 0x98], r13           ; R13
    mov         [rcx + 0xA0], r14           ; R14
    mov         [rcx + 0xA8], r15           ; R15
    mov         rax, [rsp + 0x20]           ; RIP
    mov         [rcx + 0xB0], rax
    mov         rax, [rsp + 0x28]           ; CS
    mov         [rcx + 0xB8], rax
    mov         rax, [rsp + 0x30]           ; RFLAGS
    mov         [rcx + 0xC0], rax
    mov         rax, cr0
    mov         [rcx + 0xC8], rax           ; CR0
    mov         rax, cr3
    mov         [rcx + 0xD0], rax           ; CR3
    mov         rax, cr4
    mov         [rcx + 0xD8], rax           ; CR4
    mov         rax, dr7
    mov         [rcx + 0xE0], rax           ; DR7

    ; Save the MXCSR and the XMM registers.
    stmxcsr     [rcx + 0xF0]                ; MXCSR
    movdqa      [rcx + 0x100], xmm0
    movdqa      [rcx + 0x110], xmm1
    movdqa      [rcx + 0x120], xmm2
    movdqa      [rcx + 0x130], xmm3
    movdqa      [rcx + 0x140], xmm4
    movdqa      [rcx + 0x150], xmm5
    movdqa      [rcx + 0x160], xmm6
    movdqa      [rcx + 0x170], xmm7
    movdqa      [rcx + 0x180], xmm8
    movdqa      [rcx + 0x190], xmm9
    movdqa      [rcx + 0x1A0], xmm10
    movdqa      [rcx + 0x1B0], xmm11
    movdqa      [rcx + 0x1C0], xmm12
    movdqa      [rcx + 0x1D0], xmm13
    movdqa      [rcx + 0x1E0], xmm14
    movdqa      [rcx + 0x1F0], xmm15

    ; Save the current stack.
    mov         [rcx + 0x208], rsp
    
    ; Switch the stack to something we can trust.
    mov         rsp, [rcx + 0x200]


    ; From here on, function calls are safe, as we're on the protected stack.
    ; ================================================================================================================
    ;jmp         _skip_spectre_mitigations

    push        rcx

    ; Enable Spectre mitigations, if required.
    cmp         byte [rel bSpectreMitInit], 1
    je          _spectre_mit_initialized


    ; Check for IBRS, IBPD, STIBP and MDCLEAR support.
    mov         eax, 7
    xor         ecx, ecx
    cpuid

    bt          edx, 26
    setc        [rel bUseIBRS]
    setc        [rel bUseIBPB]
    bt          edx, 27
    setc        [rel bUseSTIBP]
    bt          edx, 10
    setc        [rel bUseMDCLEAR]

    mov         byte [rel bSpectreMitInit], 1

    ; Check if IA32_ARCH_CAPABILITIES for fixed side-channels.
    bt          edx, 29
    jnc         _spectre_mit_initialized

    mov         ecx, 0x10A
    rdmsr

    ; Check if IA32_ARCH_CAPABILITIES[5]: MDS_NO is set
    bt          eax, 5
    jnc         _spectre_mit_initialized

    ; MDS_NO is set, no need to use MD_CLEAR.
    mov         byte [rel bUseMDCLEAR], 0


_spectre_mit_initialized:
    ;
    ; As described in the Indirect Branch Restricted Speculation (IBRS) overview, enabling IBRS prevents software 
    ; operating on one logical processor from controlling the predicted targets of indirect branches executed on another
    ; logical processor. For that reason, it is not necessary to enable STIBP when IBRS is enabled.
    ;
    cmp         byte [rel bUseIBRS], 0
    je          _no_IBRS

    mov         eax, 1
    xor         edx, edx
    mov         ecx, 0x48
    wrmsr

_no_IBRS:
    cmp         byte [rel bUseIBPB], 0
    je          _no_IBPB

    ; IBPB - Indirect Branch Predictor Barrier
    mov         eax, 1
    xor         edx, edx
    mov         ecx, 0x49
    wrmsr
_no_IBPB:

    pop         rcx


    ; Do the RSB stuffing.
rsb_stuff_00:
    call        rsb_stuff_1e
rsb_stuff_01:
    add         rsp, 8
    call        rsb_stuff_1f
rsb_stuff_02:
    add         rsp, 8
    call        rsb_stuff_01
rsb_stuff_03:
    add         rsp, 8
    call        rsb_stuff_02
rsb_stuff_04:
    add         rsp, 8
    call        rsb_stuff_03
rsb_stuff_05:
    add         rsp, 8
    call        rsb_stuff_04
rsb_stuff_06:
    add         rsp, 8
    call        rsb_stuff_05
rsb_stuff_07:
    add         rsp, 8
    call        rsb_stuff_06
rsb_stuff_08:
    add         rsp, 8
    call        rsb_stuff_07
rsb_stuff_09:
    add         rsp, 8
    call        rsb_stuff_08
rsb_stuff_0a:
    add         rsp, 8
    call        rsb_stuff_09
rsb_stuff_0b:
    add         rsp, 8
    call        rsb_stuff_0a
rsb_stuff_0c:
    add         rsp, 8
    call        rsb_stuff_0b
rsb_stuff_0d:
    add         rsp, 8
    call        rsb_stuff_0c
rsb_stuff_0e:
    add         rsp, 8
    call        rsb_stuff_0d
rsb_stuff_0f:
    add         rsp, 8
    call        rsb_stuff_0e
rsb_stuff_10:
    add         rsp, 8
    call        rsb_stuff_0f
rsb_stuff_11:
    add         rsp, 8
    call        rsb_stuff_10
rsb_stuff_12:
    add         rsp, 8
    call        rsb_stuff_11
rsb_stuff_13:
    add         rsp, 8
    call        rsb_stuff_12
rsb_stuff_14:
    add         rsp, 8
    call        rsb_stuff_13
rsb_stuff_15:
    add         rsp, 8
    call        rsb_stuff_14
rsb_stuff_16:
    add         rsp, 8
    call        rsb_stuff_15
rsb_stuff_17:
    add         rsp, 8
    call        rsb_stuff_16
rsb_stuff_18:
    add         rsp, 8
    call        rsb_stuff_17
rsb_stuff_19:
    add         rsp, 8
    call        rsb_stuff_18
rsb_stuff_1a:
    add         rsp, 8
    call        rsb_stuff_19
rsb_stuff_1b:
    add         rsp, 8
    call        rsb_stuff_1a
rsb_stuff_1c:
    add         rsp, 8
    call        rsb_stuff_1b
rsb_stuff_1d:
    add         rsp, 8
    call        rsb_stuff_1c
rsb_stuff_1e:
    add         rsp, 8
    call        rsb_stuff_1d
rsb_stuff_1f:
    add         rsp, 8
    lfence

    ; Call the #VE C handler.
_skip_spectre_mitigations:

    ; Save RCX for the return.
    push        rcx
    
    ; Alloc shadow space.
    sub         rsp, 0x20
    
    ; Call the handler
    call        VirtualizationExceptionHandler
    
    ; Free shadow space.
    add         rsp, 0x20
    
    ; Restore the Per-CPU data.
    pop         rcx
    
    ; ================================================================================================================
    ; Restore CPU state: GPRs and extended state and the stack. We don't need to restore control/debug registers.

    ; Restore the original stack.
    mov         rsp, [rcx + 0x208]

    ; Restore the XMM registers.
    movdqa      xmm0, [rcx + 0x100]
    movdqa      xmm1, [rcx + 0x110]
    movdqa      xmm2, [rcx + 0x120]
    movdqa      xmm3, [rcx + 0x130]
    movdqa      xmm4, [rcx + 0x140]
    movdqa      xmm5, [rcx + 0x150]
    movdqa      xmm6, [rcx + 0x160]
    movdqa      xmm7, [rcx + 0x170]
    movdqa      xmm8, [rcx + 0x180]
    movdqa      xmm9, [rcx + 0x190]
    movdqa      xmm10, [rcx + 0x1A0]
    movdqa      xmm11, [rcx + 0x1B0]
    movdqa      xmm12, [rcx + 0x1C0]
    movdqa      xmm13, [rcx + 0x1D0]
    movdqa      xmm14, [rcx + 0x1E0]
    movdqa      xmm15, [rcx + 0x1F0]
    ldmxcsr     [rcx + 0xF0]

    ; Restore the original GPRs
    mov         rbp, [rcx + 0x58]           ; RBP
    mov         rsi, [rcx + 0x60]           ; RSI
    mov         rdi, [rcx + 0x68]           ; RDI
    mov         r8,  [rcx + 0x70]           ; R8
    mov         r9,  [rcx + 0x78]           ; R9
    mov         r10, [rcx + 0x80]           ; R10
    mov         r11, [rcx + 0x88]           ; R11
    mov         r12, [rcx + 0x90]           ; R12
    mov         r13, [rcx + 0x98]           ; R13
    mov         r14, [rcx + 0xA0]           ; R14
    mov         r15, [rcx + 0xA8]           ; R15
    ; No need to restore CR0, CR3, CR4, DR7, as they aren't modified.

    ; RAX, RCX, RDX & RBX are special - they need to be restored on the stack.
    mov         rax, [rcx + 0x30]
    mov         [rsp + 0x18], rax           ; RAX
    mov         rax, [rcx + 0x38]
    mov         [rsp + 0x10], rax           ; RCX
    mov         rax, [rcx + 0x40]
    mov         [rsp + 0x08], rax           ; RDX
    mov         rax, [rcx + 0x48]
    mov         [rsp + 0x00], rax           ; RBX
    
    ; Restore the RIP, CS, SS, RSP & RFLAGS - they may have been modified as part of the #VE handling.
    mov         rax, [rcx + 0x50]           ; RSP
    mov         [rsp + 0x38], rax
    mov         rax, [rcx + 0xB0]           ; RIP
    mov         [rsp + 0x20], rax
    mov         rax, [rcx + 0xB8]           ; CS
    mov         [rsp + 0x28], rax
    mov         rax, [rcx + 0xC0]           ; RFLAGS
    mov         [rsp + 0x30], rax

    cmp         byte [rel bUseMDCLEAR], 0
    je          _skip_mds_mitigation

    push        0
    mov         word [rsp], ds
    verw        word [rsp]
    add         rsp, 8

_skip_mds_mitigation:
    ; Restore RBX & RDX.
    pop         rbx                         ; rip = rsp+0x18
    pop         rdx                         ; rip = rsp+0x10

    ; Switch into the previous view.
    xor         eax, eax
    ; We can accept #VE again.
    mov         dword [rcx + 4], 0
    ; At offset 0x20 in the #VE info page lies the EPTP index where the fault took place. We switch back into that.
    ; However, due to an errat present on Xeon Gold 5118 CPUs, which causes #VEs to be delivered with wrong EPTP index
    ; saved inside the #VE info page (always 0), we cannot rely on that value to switch back to the original EPT.
    ;mov         rcx, qword [rcx + 0x20]

    db 0xB9                                 ; MOV ecx, imm32 opcode
VeCoreUntrustedEptIndex:
    db 0x00, 0x00, 0x00, 0x00               ; imm32 - the ept index
    vmfunc

    ; Restore RCX & RAX.
    pop         rcx                         ; rip = rsp+0x08
    pop         rax                         ; rip = rsp+0x00

    ; We have the following cases:
    ; 1) if CS bit 1 is not set, regardless of KPTI, the exit came from kernel-mode and we should not do
    ;    swapgs/KiKernelExit
    ; 2) if KPTI is installed, but not activated, the VE came from user-mode (bit 1 is set) and the GS_BASE msr is
    ;    from kernel then introcore will patch VeCoreJumpBack with NOPs (so we will do the swapgs instruction and then
    ;    iretq)
    ; 3) if KPTI is installed, activated, the VE came from user-mode and the GS_BASE msr is from kernel then introcore
    ;    will patch VeCoreJumpBack with the KiKernelExit address, which is the right way to exit from kernel in this
    ;    case
    ; 4) if KPTI is not installed, we already jumped in our handler from the kernel #VE handler, so no swapgs was made
    ;    thus, the GS_BASE msr will point into user mode (bit 63 is not set), and we should not do swapgs again
    ; All the other cases will not happen as they should not be possible

    bt          qword [rsp + 0x8], 1       ; Check if the CS is user-mode (bit 1 will be set, as ring is 3 = 0b11)
    jnc         _no_swapgs                 ; Kernel CS - no need for swapgs

    push        rax
    push        rdx
    push        rcx
    mov         ecx, 0xC0000101
    rdmsr
    shl         rdx, 32
    or          rax, rdx
    pop         rcx ; rip = rsp + 0x10
    pop         rdx ; rip = rsp + 0x8

    ; If KPTI is on and the event came from user-mode, the GS will point inside kernel, due to the CR3 switch.
    bt          rax, 63                     ; Check if the GS points in kernel (MSB is set)
    pop         rax
    jnc         _no_swapgs                  ; Not set - GS base points in user - no need for swapgs
    
    ; Jump back to the KiExitKernel stub.
VeCoreJumpToKiKernelExit:
    call        _capture_spec1
    lfence
_capture_spec1:
    mov         dword [rsp], 0
    mov         dword [rsp + 4], 0
    ret

    swapgs
_no_swapgs:
    ; Return. We're done!
    iretq

    ;
    ; Jump back to the original handler. We must execute the old code and than branch to the original KiIsrLinkage.
    ;
_not_ve:
VeCoreReplacedCode:
    ; Old handler.
    times 0x40 db 0x90

    ; Jump back, retpoline.
VeCoreJumpToReplacedCode:
    call        _capture_spec2
    lfence
_capture_spec2:
    mov         dword [rsp], 0
    mov         dword [rsp + 4], 0
    ret





    section VEINS

    ; We'll have 64 x 1 pages used to translate instructions. We reserve one page for each supported CPU.
VeCoreInstructionsTable:
    ;times 0x40000 db 0x90

;
; VeCoreExecuteInstruction
; in: rcx = VCPU state
; in: rdx = instruction address in VeCoreInstructionsTable
;
VeCoreExecuteInstruction:
    ; Save the current registers state
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
    pushfq

    ; Transplant the guest flags into current flags
    mov         rax, [rcx + 0xC0]
    and         rax, 0x8FF
    mov         rdx, [rsp]
    and         edx, 0xFFFFF700
    or          edx, eax
    push        rdx
    popfq

    ; Load the guest registers state.
    mov         rax, [rcx + 0x30]
    mov         rdx, [rcx + 0x40]
    mov         rbx, [rcx + 0x48]
    mov         rbp, [rcx + 0x58]
    mov         rsi, [rcx + 0x60]
    mov         rdi, [rcx + 0x68]
    mov         r8,  [rcx + 0x70]
    mov         r9,  [rcx + 0x78]
    mov         r10, [rcx + 0x80]
    mov         r11, [rcx + 0x88]
    mov         r12, [rcx + 0x90]
    mov         r13, [rcx + 0x98]
    mov         r14, [rcx + 0xA0]
    mov         r15, [rcx + 0xA8]

    ; Save the CPU state and load the original RCX
    push        rcx
    mov         rcx, [rcx + 0x38]

    ; RDX contains the address of the instruction inside the VeCoreInstructionsTable, but RDX was previously pushed.
    call        qword [rsp + 0x70]

    ; Restore the CPU state and save the new RCX on the stack
    xchg        rcx, [rsp]
    mov         [rcx + 0x30], rax
    pop         rax
    mov         [rcx + 0x38], rax
    mov         [rcx + 0x40], rdx
    mov         [rcx + 0x48], rbx
    mov         [rcx + 0x58], rbp
    mov         [rcx + 0x60], rsi
    mov         [rcx + 0x68], rdi
    mov         [rcx + 0x70], r8
    mov         [rcx + 0x78], r9
    mov         [rcx + 0x80], r10
    mov         [rcx + 0x88], r11
    mov         [rcx + 0x90], r12
    mov         [rcx + 0x98], r13
    mov         [rcx + 0xA0], r14
    mov         [rcx + 0xA8], r15

    ; Transplant the guest flags into current flags
    pushfq
    pop         rax
    and         rax, 0x8FF
    mov         rdx, [rcx + 0xC0]
    and         edx, 0xFFFFF700
    or          edx, eax
    mov         [rcx + 0xC0], rdx

    ; Restore the state.
    popfq
    pop         r15
    pop         r14
    pop         r13
    pop         r12
    pop         r11
    pop         r10
    pop         r9
    pop         r8
    pop         rdi
    pop         rsi
    pop         rbp
    pop         rbx
    pop         rdx
    pop         rcx
    pop         rax
    retn
