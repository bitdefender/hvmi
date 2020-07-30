            [bits 64]

            global      _start

            section .code

            ; Note: RSI, RDI, RBX, RBP and R12-R15 are callee saved (if used).
_start:
            push        rdi
            push        rsi
            push        rbp
            push        rbx

            ; Alloc space on the stack for the function pointers and the kernel base
            sub         rsp, 0x38
            mov         rbp, rsp

            lea         rcx, [rel name_kernel]
            call        locate_module
            mov         [rbp + mod_kernel32], rax
            test        rax, rax
            jz          _exit_fail

            ; Fetch the CreateProcess function
            lea         rcx, [rel name_CreateProcessA]
            mov         rdx, [rbp + mod_kernel32]
            call        locate_func
            mov         [rbp + fn_CreateProcessA], rax
            test        rax, rax
            jz          _exit_fail

            ; Fetch the WaitForSingleObject function
            lea         rcx, [rel name_WaitForSingleObject]
            mov         rdx, [rbp + mod_kernel32]
            call        locate_func
            mov         [rbp + fn_WaitForSingleObject], rax
            test        rax, rax
            jz          _exit_fail

            ; Fetch the CloseHandle function
            lea         rcx, [rel name_CloseHandle]
            mov         rdx, [rbp + mod_kernel32]
            call        locate_func
            mov         [rbp + fn_CloseHandle], rax
            test        rax, rax
            jz          _exit_fail

            ; Fetch the DeleteFileA function
            lea         rcx, [rel name_DeleteFileA]
            mov         rdx, [rbp + mod_kernel32]
            call        locate_func
            mov         [rbp + fn_DeleteFileA], rax
            test        rax, rax
            jz          _exit_fail
            
            ; Fetch the VirtualFree function
            lea         rcx, [rel name_VirtualFree]
            mov         rdx, [rbp + mod_kernel32]
            call        locate_func
            mov         [rbp + fn_VirtualFree], rax
            test        rax, rax
            jz          _exit_fail

            ; Prepare CreateProcessA structures
            sub         rsp, 104 + 24 ; Alloc space for the STARTUPINFO & PROCESS_INFORMATION (104 + 24 bytes)
            xor         al, al
            mov         rdi, rsp
            mov         ecx, 104 + 24
            rep         stosb         ; Zero out the memory
            mov         rdi, rsp      ; Save it in RDI

            ; Init the STARTUPINFO structure
            mov         dword [rdi + 24], 104 ; Save the STARTUPINFO structure size - the cb field
            lea         rcx, [rel desktop]
            mov         qword [rdi + 24 + 16], rcx ; Set the lpDesktop field to point to the default desktop - we start our cleaner
                                      ; from a SYSTEM process, but we want GUI!
            ; Save arguments
            push        rdi           ; LPPROCESS_INFORMATION
            lea         rcx, [rdi + 24]
            push        rcx           ; LPSTARTUPINFO
            push        0             ; LPCTSTR lpCurrentDirectory
            push        0             ; LPVOID lpEnvironment
            push        0             ; DWORD dwCreationFlags
            push        0             ; BOOL bInheritHandles
            xor         r9, r9
            push        0             ; LPSECURITY_ATTRIBUTES lpThreadAttributes
            xor         r8, r8
            push        0             ; LPSECURITY_ATTRIBUTES lpProcessAttributes
            lea         rdx, [rel process_name]
_go_to_cmd: cmp         byte [rdx], 0
            jz          _cmd_found
            inc         rdx
            jmp         _go_to_cmd
_cmd_found: inc         rdx
            push        0             ; LPTSTR lpCommandLine
            lea         rcx, [rel process_name]
            push        0             ; LPCTSTR lpApplicationName
            call        [rbp + fn_CreateProcessA]

            ; Clean up the stack
            add         rsp, 8 * 10

            ; Check for success
            test        rax, rax
            jz          _exit_fail2


            sub         rsp, 0x20
            mov         rcx, qword [rdi]
            mov         edx, 0xFFFFFFFF
            call        qword [rbp + fn_WaitForSingleObject]

            ; Close the handles
            mov         rcx, qword [rdi + 0]
            call        qword [rbp + fn_CloseHandle]

            mov         rcx, qword [rdi + 8]
            call        qword [rbp + fn_CloseHandle]

            ; Delete the file. The file name comes right after the command line.
            lea         rcx, [rel process_name]
            call        qword [rbp + fn_DeleteFileA]
            add         rsp, 0x20
            
            ; Overwrite any error code that may have appeared until now - we managed to run the agent, 
            ; so we don't care about any errors here.
            mov         dword [gs:0x68], 0

            ; Remove PROCESS_INFORMATION and STARTUPINFO from the stack
_exit_fail2:
            add         rsp, 104 + 24
            
            cmp         dword [gs:0x68], 0
            jz          _no_error
            call        report_error
_no_error:            

           ; Prepare the VirtualFree arguments. NOTE: In case of failure, fn_VirtualFree will be the retn address.
            lea         rcx, [rel _start]
            xor         edx, edx
            mov         r8d, 0x8000
            mov         rax, qword [rbp + fn_VirtualFree]

            add         rsp, 0x38

            pop         rbx
            pop         rbp
            pop         rsi
            pop         rdi

            ; Free the memory & leave!
            jmp         rax

_exit_fail:
            add         rsp, 0x38
            
            mov         dword [gs:0x68], 0x32
            call        report_error

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
            add         rbx, rdx          ; Now address to names array

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

report_error:
            push        rax
            push        rcx
            push        rdx
            push        rbx
            push        rsi
            push        rdi
            
            mov         eax, 34
            mov         edi, 24
            mov         esi, 0
            mov         edx, 753200
            mov         ecx, dword [rel agent_id]
            mov         ebx, [gs:0x68]
            vmcall

            pop         rdi
            pop         rsi
            pop         rbx
            pop         rdx
            pop         rcx
            pop         rax
            ret

fn_CreateProcessA            equ  0
fn_WaitForSingleObject       equ  8
fn_CloseHandle               equ  16
fn_DeleteFileA               equ  24
fn_VirtualFree               equ  32
fn_Reserved                  equ  40
mod_kernel32                 equ  48

name_kernel                  dw   __utf16__('kernel32.dll'),0
name_CreateProcessA          db   "CreateProcessA",0
name_WaitForSingleObject     db   "WaitForSingleObject",0
name_CloseHandle             db   "CloseHandle",0
name_DeleteFileA             db   "DeleteFileA",0
name_VirtualFree             db   "VirtualFree",0
desktop                      db   "winsta0\default",0,0,0,0,0,0,0,0,0,0,0,0
agent_id                     dd   0
process_name:
command_line: