
            global  _start
            
            [bits 64]
            
            ; These can be fine-tuned.
            
            ; We can handle a maximum of 256 handlers with the same 
            ; low 6 bits (bits 0:5 of the RIP).
            ; Since we use the low 6 bits, it means that we will have up to
            ; 64 (pages) x 256 (handlers per page) = 16384 different handlers.
max_hnds    equ     256                     ; Per page.

            ; The table size is a cache indexed using bits 0:5 of the
            ; RIP saved by the INT 20. The indexed bucket is a page 
            ; containing up to 256 handlers. 
table_size  equ     64 * max_hnds * 16      ; Total size.

            ; The total size of the handlers will be 64 pages * 256 entries
            ; per page * max 48 bytes per handler.
handlers_size equ   64 * max_hnds * 48      ; Total handlers size.

            ; The cache has 2MB. It is organized as 512 4K pages.
            ; Initialy, we use bits 12:20 of the PT GPA to find 
            ; the bucket where the GPA is. Then we REPNE SCASQ for
            ; the GPA inside that page.
cache_size  equ     0x200000

            ; The memtable section will be 64K in size.
memtable_size equ   0x10000


;==============================================================================
            section .text

            ;
            ; First of all, the main INT 20 handler: search an appropriate 
            ; handler using the saved RIP.
            ;
_start:     ;int3
            
            ; Placeholder for the return address to the handler.
            push    0
            push    rax
            push    rcx
            push    rdi
            pushfq
            
            ; Table base - contains tuples of (rip, handler).
            lea     rdi, [rel table]
            mov     ecx, max_hnds
            ; Get the RIP from the stack.
            mov     rax, [rsp + 0x28]
            and     eax, 0x3F
            shl     eax, 12
            add     rdi, rax
            mov     rax, [rsp + 0x28]
_find_handler:
            cmp     [rdi], rax
            jz      _found_handler
            add     rdi, 16
            dec     ecx
            jnz     _find_handler
            
            ; No handler found, this is bad...
            ;cli
            ;hlt
            int3
            
_found_handler:
            ; The handler is the next qword inside the table.
            mov     rax, [rdi + 8]
            ; Save the RIP handler on the stack; we will RET to it.
            mov     [rsp + 0x20], rax
            
            ; Restore saved registers and jump to the proper handler.
            popfq
            pop     rdi
            pop     rcx
            pop     rax
            
            ; This will return to the 0 which was replaced with the address of
            ; the actual handler for this particular instruction.
            ret
            
            
            
            
;==============================================================================
            section .main
            
            ; Easier to pass them on the stack. 
            ; Input:  [RBP +  0] - new value
            ; Input:  [RBP +  8] - old value
            ; Input:  [RBP + 16] - accessed GLA
            ; Input:  [RBP + 24] - accessed GLA displacement
            ; Input:  [RBP + 32] - IF indicator
            ; Return: Nothing. Will do a VMEXIT if the modification is worthy.
            
new         equ     0x00
old         equ     0x08
gla         equ     0x10
disp        equ     0x18
ifind       equ     0x20

sv_rip      equ     0x28
sv_cs       equ     0x30
sv_flags    equ     0x38
sv_rsp      equ     0x40
sv_ss       equ     0x48

CheckModification:
            ; Save registers.
            push    rax
            push    rcx
            push    rdx
            push    rbx
            push    rbp
            push    rsi
            push    rdi
            push    r8
            push    r9
            push    r10
            push    r11
            push    r12
            push    r13
            push    r14
            push    r15
            
            ; Establish a local working frame.
            lea     rbp, [rsp + 0x78]
            
            ; Save the modified flags from the handler.
            pushfq
            pop     rax
            mov     rcx, qword [rbp + sv_flags]
            ; Clear everything except for the reserved bits and CF, PF, AF, ZF, SF, OF
            and     rax, 0x8FF
            ; Clear the CF, PF, AF, ZF, SF, OF flags
            and     ecx, 0xFFFFF700
            ; Update the new flags.
            or      rax, rcx
            ; Commit them.
            mov     qword [rbp + sv_flags], rax


            ;
            ; Step 1. Check if this is a self-mapped entry, and check if 
            ; it points in kernel or user.
            ;
_check_selfmap:
            ; Make sure this is a self-map entry. If it isn't, bail out.
            ; The PML4 index must point to an entry which maps the PML4.
            mov     rax, [rbp + gla]
            shr     rax, 39
            and     rax, 0x1ff
            cmp     eax, dword [rel self_map]
            ; No self map, bail out.
            jne     _done_no_exit_unlock
            ; NOTE: Since we already check that the GLA is self-map in the CheckLock function, this
            ; jne should never be taken. The code could be removed altogether.
            
            ; Now see if it is kernel or user.
            ; Bit 38 is the highest bit inside the PDP index. Since PML4 index
            ; already points inside the PML4 self map, it means that the PDP 
            ; index points in PML4 as well. All we have to do is see if it 
            ; points in the last 256 entries, which are either kernel, either
            ; self map which will lead to a higher level table.
            bt      qword [rbp + gla], 38
            ; This is a kernel entry, check if the modification is relevant
            ; and then check the cache.
            jc      _check_relevance
            
            
            ;
            ; Step 2. We know from the above test that this is a user entry,
            ; so check if the current process is protected or not.
            ;
_check_process:
            ; Get the current thread. Important note: we know for sure that
            ; GS points inside kernel, since we intercept kernel instructions.
            mov     rcx, qword [gs:0x188]           
            ; Get the AttachedProcess from the APC state.
            mov     ebx, dword [rel attached_offs]
            mov     rax, qword [rcx + rbx]
            ; If not null, we have an attached process, check it.
            test    rax, rax
            jnz     _attached_process
            ; Not attached, get the process from the thread.
            mov     ebx, dword [rel process_offs]
            mov     rax, qword [rcx + rbx]
_attached_process:           
            ; Check if the process is protected.
            mov     ebx, dword [rel name_offs]
            cmp     byte [rax + rbx], '*'
            ; Current process not protected, bail out.
            jnz     _done_no_exit_unlock
            

            ;
            ; Step 3. Check if this is a relevant modification
            ;
_check_relevance:            
            mov     rax, [rbp + new]
            mov     rcx, [rbp + old]
            xor     rax, rcx
            mov     rcx, qword [rel rel_bits]
            test    rax, rcx
            ; No relevant bit modified, leave.
            jz      _done_no_exit_unlock
            ; Make sure we don't exit if both entries are invalid
            bt      qword [rbp + new], 0
            jc      _check_pt_cache
            bt      qword [rbp + old], 0
            ; Even if apparently a relevant bit was modified, the entries are
            ; both invalid, so no need to exit.
            jnc     _done_no_exit_unlock

            
            ;
            ; Step 4. Check if the current accessed page table is protected.
            ;
_check_pt_cache:            
            ;int3
            mov     rax, [rbp + gla]
            add     rax, [rbp + disp]
            mov     rcx, rax
            mov     rbx, 0xffffff8000000000
            and     rax, rbx
            mov     rbx, 0x0000fffffffff000
            and     rcx, rbx
            shr     rcx, 9
            or      rax, rcx
            ; RAX is now the physical address of the modified page-table.
            mov     rax, qword [rax]
            mov     rbx, 0x000FFFFFFFFFF000
            and     rax, rbx
            ; Store the offset as well.
            mov     rbx, [rbp + gla]
            add     rbx, [rbp + disp]
            and     rbx, 0x00000fff
            or      rax, rbx
            mov     rbx, rax
            
            ; Now scan the cache for this physical PT!
            lea     rdi, [rel cache]
            and     rax, 0x1FF000
            add     rdi, rax
            mov     rax, rbx
            and     rax, 0xfffffffffffff000
            mov     rcx, 512
            cld
            repne scasq
            jz      _done_no_exit_unlock
           

_done_do_exit:
            mov     eax, 0x22
            mov     edi, 0x18
            xor     esi, esi
            ; R8  = modified GLA
            mov     r8, [rbp + gla]
            add     r8, [rbp + disp]
            ; R9  = modified GPA
            mov     r9, rbx
            ; r10 = new value
            mov     r10, [rbp + new]
            ; r11 = old value
            mov     r11, [rbp + old]
            ; Do the vmcall!
            vmcall
            
            ; From here on, we're done.
            
_done_no_exit_unlock:
            ; Release the lock.
            lock btr qword [rel glock], 0
            
            ; Restore everything.
            pop     r15
            pop     r14
            pop     r13
            pop     r12
            pop     r11
            pop     r10
            pop     r9
            pop     r8
            pop     rdi
            pop     rsi
            pop     rbp
            pop     rbx
            pop     rdx
            pop     rcx
            pop     rax
            
            ; No worry about the flags, they're on the stack.
            add     rsp, 0x28
            
            ; Done, we can leave.
            iretq
            
            
;==============================================================================
            section .lock
            
CheckLock:  
            ; Stack when entering this function:
            ; int 14h frame (RIP, CS, RFLAGS, RSP, SS)
            ; 0/1 (IF indicator)
            ; displacement
            ; GLA
            ; return address to the instruction handler
            pushfq
            push    rax

            ; Get the GLA base.
            mov     rax, qword [rsp + 0x18]
            ; Add the displacement.
            add     rax, qword [rsp + 0x20]

            ; Try acquiring the lock.
_use_lock:  lock bts qword [rel glock], 0
            jc      _use_lock

            ; Check PML4, to make sure the entry is present and valid.
            push    rdx
            push    rcx
            mov     rdx, 0xffff000000000000
            mov     ecx, dword [rel self_map]
            shl     rcx, 12
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            mov     rcx, rax
            shr     rcx, (12 + 9 + 9 + 9)
            and     rcx, 0x1ff
            shl     rcx, 3
            or      rdx, rcx
            test    qword [rdx], 2          ; Test the write bit.
            bt      qword [rdx], 0          ; Test the present bit.
            pop     rcx
            pop     rdx
            jnc     _remove_instruction     ; PML4 entry is NOT present.
            jz      _remove_instruction     ; PML4 entry is NOT writable.

            ; Check PDP, to make sure the entry is present and valid.
            push    rdx
            push    rcx
            mov     rdx, 0xffff000000000000
            mov     ecx, dword [rel self_map]
            shl     rcx, 12 + 9
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            mov     rcx, rax
            shr     rcx, (12 + 9 + 9)
            and     rcx, 0x3FFFF
            shl     rcx, 3
            or      rdx, rcx
            test    qword [rdx], 2          ; Test the write bit.
            bt      qword [rdx], 0          ; Test the present bit.
            pop     rcx
            pop     rdx
            jnc     _remove_instruction     ; PDP entry is NOT present.
            jz      _remove_instruction     ; PDP entry is NOT writable.

            ; Check PD, to make sure the entry is present and valid.
            push    rdx
            push    rcx
            mov     rdx, 0xffff000000000000
            mov     ecx, dword [rel self_map]
            shl     rcx, 12 + 9 + 9
            or      rdx, rcx
            shl     rcx, 9
            or      rdx, rcx
            mov     rcx, rax
            shr     rcx, (12 + 9)
            and     rcx, 0x7FFFFFF
            shl     rcx, 3
            or      rdx, rcx
            test    qword [rdx], 2          ; Test the write bit.
            bt      qword [rdx], 0          ; Test the present bit.
            pop     rcx
            pop     rdx
            jnc     _remove_instruction     ; PD entry is NOT present.
            jz      _remove_instruction     ; PD entry is NOT writable.

            ; Check PT, to make sure the entry is present and valid.
            push    rdx
            push    rcx
            mov     rdx, 0xffff000000000000
            mov     ecx, dword [rel self_map]
            shl     rcx, 12 + 9 + 9 + 9
            or      rdx, rcx
            mov     rcx, rax
            shr     rcx, 12
            push    rbx
            mov     rbx, 0xFFFFFFFFF
            and     rcx, rbx
            pop     rbx
            shl     rcx, 3
            or      rdx, rcx
            test    qword [rdx], 2          ; Test the write bit.
            bt      qword [rdx], 0          ; Test the present bit.
            pop     rcx
            pop     rdx
            jnc     _remove_instruction     ; PT entry is NOT present.
            jz      _remove_instruction     ; PT entry is NOT writable.

_done_check:
            ; The instruction is legit, go on.
            pop     rax
            popfq
            retn


_remove_instruction:
            push    rdi
            push    rsi
            push    r8
            push    r9
            
            mov     eax, 0x22
            mov     edi, 0x18
            xor     esi, esi
            ; R8  = 0
            xor     r8, r8
            ; r9 = the RIP of the instruction to be removed.
            mov     r9, [rsp + 0x50]
            ; Do the vmcall!
            vmcall
            
            pop     r9
            pop     r8
            pop     rsi
            pop     rdi
            pop     rax
            popfq
            
            ; Release the lock.
            lock btr qword [rel glock], 0
            
            ; Clean up the stack.
            add     rsp, 0x20
            
            ; Return to the intercepted instruction, which has been restored via the VMCALL above.
            iretq


;==============================================================================
            section .data
            
glock       dq      0            
            
            
;==============================================================================
            section .rdata
        
            ; The self map index inside the PML4.
self_map    dd      0

            ; Reserved for future use.
reserved    dd      0

            ; Relevant bits inside page-table entries - if the bits listed here
            ; are modified, we will do a VM-Exit
rel_bits    dq      0

            ; Attached process offset inside KTHREAD
attached_offs dd    0

            ; Process offset inside KTHREAD
process_offs dd     0

            ; Image name offset inside EPROCESS
name_offs   dd      0



;==============================================================================
            section .handler    code
            
            ; This will contain AAAAAAL the handlers.
times handlers_size db 0xCC  


;==============================================================================
            section .memtbl     code
            
            ; Used to relocate mem-tables; since we modify so many kernel
            ; instructions, we will hit inside many switch - case statements, 
            ; so we need to relocate.
times memtable_size db 0xCC         
            
            
;==============================================================================
            section .cache      bss

            ; This is the 2 MB cache
cache:      resb cache_size


;==============================================================================
            section .table      bss
            
            ; This is the RIP -> HANDLER table. For each modified instruction
            ; we establish a distinct handler.
table:      resb table_size          
