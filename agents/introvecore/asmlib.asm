; VMCALL/VMFUNC.
global AsmVmcall

; Spin-locks.
global AsmSpinLockAcquire
global AsmSpinLockRelease
global AsmRwSpinLockAcquireShared
global AsmRwSpinLockAcquireExclusive
global AsmRwSpinLockReleaseShared
global AsmRwSpinLockReleaseExclusive

    section .text


;
; AsmSpinLockAcquire
;
AsmSpinLockAcquire:
    ; rcx points to the spinlock.
_try_acquire:
    lock bts    dword [rcx], 0
    jnc         _acquired
    pause
    jmp         _try_acquire
_acquired:
    retn


;
; AsmSpinLockRelease
;
AsmSpinLockRelease:
    ; rcx points to the spinlock.
    lock btr    dword [rcx], 0
    retn


;
; AsmRwSpinLockAcquireShared
;
AsmRwSpinLockAcquireShared:
    ; rcx points to the spinlock; We support up to 4G concurent acquires.
_try_acquire_rw_shared:
    ; Make sure the lock is not 0xFFFFFFFF; this means thay either there are too many shared acquires, or a single
    ; exclusive acquire.
    mov         eax, dword [rcx]
    cmp         eax, 0xFFFFFFFF
    jz          _retry_rw_shared
    mov         edx, eax
    inc         edx
    lock cmpxchg dword [rcx], edx
    jz          _acquired_rw_shared
_retry_rw_shared:
    pause
    jmp         _try_acquire_rw_shared
    
_acquired_rw_shared:
    retn


;
; AsmRwSpinLockReleaseShared
;
AsmRwSpinLockReleaseShared:
    ; rcx points to the spinlock; We support up to 4G concurent acquires.
    ; We assume the lock has been correctly acquired
    lock dec    dword [rcx]
    retn


;
; AsmRwSpinLockAcquireExclusive
;
AsmRwSpinLockAcquireExclusive:
    ; rcx points to the spinlock; We support up to 4G concurent acquires.
_try_acquire_rw_exclusive:
    ; Make sure the lock is 0: no shared & no exclusive acquires have been made.
    mov         eax, dword [rcx]
    cmp         eax, 0
    jnz         _retry_rw_exclusive
    mov         edx, 0xFFFFFFFF
    lock cmpxchg dword [rcx], edx
    jz          _acquired_rw_exclusive
_retry_rw_exclusive:
    pause
    jmp         _try_acquire_rw_exclusive
    
_acquired_rw_exclusive:
    retn


;
; AsmRwSpinLockReleaseExclusive
;
AsmRwSpinLockReleaseExclusive:
    ; rcx points to the spinlock; We support up to 4G concurent acquires.
    ; We assume the lock has been correctly acquired
    mov         dword [rcx], 0
    retn


;
; AsmVmcall
;
AsmVmcall:
    push        rbp
    mov         rbp, rsp
    
    sub         rsp, 0x20
    
    mov         [rsp + 0x00], rcx
    mov         [rsp + 0x08], rdx
    mov         [rsp + 0x10], r8
    mov         [rsp + 0x18], r9
    
    push        rcx
    push        rdx
    push        rbx
    push        rsi
    push        rdi
    
    mov         rax, [rcx]
    mov         rbx, [rdx]
    mov         rcx, [r8]
    mov         rdx, [r9]
    mov         rdi, [rbp + 0x30]
    mov         rdi, [rdi]
    mov         rsi, [rbp + 0x38]
    mov         rsi, [rsi]
    
    vmcall
    
    mov         r8, [rsp + 0x28 + 0x00]
    mov         [r8], rax
    mov         r8, [rsp + 0x28 + 0x08]
    mov         [r8], rbx
    mov         r8, [rsp + 0x28 + 0x10]
    mov         [r8], rcx
    mov         r8, [rsp + 0x28 + 0x18]
    mov         [r8], rdx
    mov         r8, [rbp + 0x30]
    mov         [r8], rdi
    mov         r8, [rbp + 0x38]
    mov         [r8], rsi
    
    pop         rdi
    pop         rsi
    pop         rbx
    pop         rdx
    pop         rcx
    
    add         rsp, 0x20

    pop         rbp
    retn
