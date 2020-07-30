;-----------------------------------------------------------------------------
            [bits 64]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
            ; Note: RSI, RDI, RBX, RBP and R12-R15 are callee saved (if used).
_start:
            push        rdi
            push        rsi
            push        rbp
            push        rbx

            ; Alloc space on the stack for the function pointers and the kernel base
            sub         rsp, 0x28
            mov         rbp, rsp

            lea         rcx, [rel name_ntdll]
            call        locate_module
            mov         [rbp + mod_ntdll], rax
            test        rax, rax
            jz          _exit_fail

            ; Fetch the LdrLoadDll function
            lea         rcx, [rel name_LdrLoadDll]
            mov         rdx, [rbp + mod_ntdll]
            call        locate_func
            mov         [rbp + fn_LdrLoadDll], rax
            test        rax, rax
            jz          _exit_fail

            ; Load the library!
            sub         rsp, 0x10
            ;mov         dword [rsp + 8], 0x10000000 ; LOAD_LIBRARY_SEARCH_SYSTEM32
            mov         dword [rsp + 8], 8 ; LOAD_LIBRARY_SEARCH_SYSTEM32
            lea         rcx, [rel uni_name]
            mov         qword [rel dll_name + 8], rcx
            ;lea         rcx, [rel uni_path]
            lea         rdx, [rsp + 8]
            lea         r8, [rel dll_name]
            lea         r9, [rsp]
            sub         rsp, 0x20
            call        qword [rbp + fn_LdrLoadDll]
            add         rsp, 0x30

_exit_fail:
            add         rsp, 0x28

            pop         rbx
            pop         rbp
            pop         rsi
            pop         rdi

            retn

            int3
            ud2


;
; Input:  ECX - the module base name
; Output: EAX - the module base address
;
locate_module:
            push        rbx
            push        rsi
            push        rdi

            mov         rdx, qword [gs:0x60] ; Get the PEB from TEB
            mov         rdx, [rdx + 0x18]  ; Get LDR from PEB
            lea         rdi, [rdx + 0x20]  ; RDI = in-load order, points to the list head
            mov         rdx, [rdx + 0x20]  ; RDX is now the first module

process_dll:
            push        rdi
            push        rcx

            mov         rsi, qword [rdx + 0x50] ; UNICODE_STRING FullDllName;
            mov         rdi, rcx           ; The searched DLL name

            ; Compare the names.
            xor         ecx, ecx
compare_names:
            cmp         cx, word [rdx + 0x4A]
            jz          compare_names_done
            mov         al, [rsi + rcx]
            cmp         al, 'A'
            jb          _skip_to_lower
            cmp         al, 'Z'
            ja          _skip_to_lower
            add         al, 0x20
_skip_to_lower:
            cmp         al, [rdi + rcx]
            jnz         compare_names_done

            inc         ecx
            jmp         compare_names

compare_names_done:
            pop         rcx
            pop         rdi
            mov         rax, qword [rdx + 0x20] ; DllBase

            jz          done

next_dll:   mov         rdx, [rdx]        ; Flink in LDR module entry
            cmp         rdx, rdi
            jnz         process_dll

            ; Done, nothing found. :(
            xor         rax, rax

done:       pop         rdi
            pop         rsi
            pop         rbx

            retn


;
; Input:  RCX - the function name
; Input:  RDX - the module base
; Output: RAX - the function address, or 0 if not found.
;
locate_func:
            push        rbx
            push        rsi
            push        rdi

            mov         rdi, rcx          ; Save function name in RDI - will remain here

            mov         eax, [rdx + 0x3C] ; Offset to PE header
            add         rax, rdx          ; RAX points to the PE header
            add         rax, 4            ; RAX points to the file header
            add         rax, 20           ; Size of file header
            mov         eax, [rax + 112]  ; EAT RVA from the data directory
            test        eax, eax
            jz          exit_fn_fail

            add         rax, rdx          ; EAX points to the export directory
            push        rax               ; Save EAT address

            mov         ecx, [rax + 0x18] ; Number of names
            mov         ebx, [rax + 0x20] ; RVA to names array
            add         rbx, rdx          ; Now ad`dress to names array

loop_names: jecxz       done_loop_names
            dec         ecx

            mov         esi, [rbx + rcx * 4] ; esi is now rva to name
            add         rsi, rdx          ; Add image base, we want memory address of the name


            push        rcx
            push        rax

            xor         ecx, ecx
compare_fn_name:
            mov         al, [rsi + rcx]
            cmp         al, [rdi + rcx]
            jnz         fn_match_done
            test        al, al
            jz          fn_match_done
            cmp         byte [rdi + rcx], 0
            jz          fn_match_done
            inc         ecx
            jmp         compare_fn_name

fn_match_done:
            pop         rax
            pop         rcx

            jnz         loop_names        ; Nope, keep searching


            ; Bingo! Function found, now locate its address.
            pop         rax               ; Restore RAX - it points to our EAT
            mov         ebx, [rax + 0x24] ; RVA to ordinals array
            add         rbx, rdx           ; Add image base
            movzx       ecx, word [rbx + rcx * 2]; Get the name ordinal

            mov         ebx, [rax + 0x1C] ; RVA to functions array
            add         rbx, rdx           ; Add image base
            mov         eax, [rbx + rcx * 4] ; Get the function RVA
            add         rax, rdx          ; Now we have the function address
            jmp         exit_fn

done_loop_names:
            pop         rax
exit_fn_fail:
            xor         eax, eax
exit_fn:
            pop         rdi
            pop         rsi
            pop         rbx

            retn


fn_LdrLoadDll                equ  0
fn_Reserved                  equ  8
mod_ntdll                    equ  16

name_ntdll                   dw   __utf16__('ntdll.dll'),0
name_LdrLoadDll              db   "LdrLoadDll",0
dll_name                     dw   24, 26
                             dd   0
                             dq   0
uni_name                     dw   __utf16__('dummylib.dll'),0
uni_path                     dw   __utf16__('\\??\c:\windows\system32\dummylib.dll'),0