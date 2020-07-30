            [bits 32]

            global      _start

            section .code

            ; Note: ESI, EDI, EBX and EBP are callee saved (if used).
_start:     push        edi
            push        esi
            push        ebp
            push        ebx

            mov         ebp, 0xBDBDBDBD
            nop
            nop
            nop
            nop
            nop
            nop
            nop

            ; Alloc space on the stack for the function pointers and the kernel base
            sub         esp, 0x20
            mov         ebx, esp

            lea         ecx, [ebp + name_kernel]
            call        locate_module
            mov         [ebx + mod_kernel32], eax
            test        eax, eax
            jz          _exit_fail
            
            lea         ecx, [ebp + name_ntdll]
            call        locate_module
            mov         [ebx + mod_ntdll], eax
            test        eax, eax
            jz          _exit_fail

            ; Fetch the CreateProcess function
            lea         ecx, [ebp + name_CreateProcessA]
            mov         edx, [ebx + mod_kernel32]
            call        locate_func
            mov         [ebx + fn_CreateProcessA], eax
            test        eax, eax
            jz          _exit_fail

            ; Fetch the WaitForSingleObject function
            lea         ecx, [ebp + name_WaitForSingleObject]
            mov         edx, [ebx + mod_kernel32]
            call        locate_func
            mov         [ebx + fn_WaitForSingleObject], eax
            test        eax, eax
            jz          _exit_fail

             ; Fetch the CloseHandle function
            lea         ecx, [ebp + name_CloseHandle]
            mov         edx, [ebx + mod_kernel32]
            call        locate_func
            mov         [ebx + fn_CloseHandle], eax
            test        eax, eax
            jz          _exit_fail
            
            ; Fetch the DeleteFileA function
            lea         ecx, [ebp + name_DeleteFileA]
            mov         edx, [ebx + mod_kernel32]
            call        locate_func
            mov         [ebx + fn_DeleteFileA], eax
            test        eax, eax
            jz          _exit_fail
            
            ; Fetch the VirtualFree function
            lea         ecx, [ebp + name_VirtualFree]
            mov         edx, [ebx + mod_kernel32]
            call        locate_func
            mov         [ebx + fn_VirtualFree], eax
            test        eax, eax
            jz          _exit_fail
            
            ; Fetch the ExitThread function
            lea         ecx, [ebp + name_ExitThread]
            mov         edx, [ebx + mod_ntdll]
            call        locate_func
            mov         [ebx + fn_ExitThread], eax
            test        eax, eax
            jz          _exit_fail

            ; Prepare CreateProcessA structures
            sub         esp, 68 + 16 ; Alloc space for the STARTUPINFO & PROCESS_INFORMATION (68 + 16 bytes)
            xor         al, al
            mov         edi, esp
            mov         ecx, 68 + 16
            rep         stosb         ; Zero out the memory
            mov         edi, esp      ; Save it in EDI

            ; Init the STARTUPINFO structure
            mov         dword [edi + 16], 68 ; Save the STARTUPINFO structure size - the cb field
            lea         ecx, [ebp + desktop]
            mov         dword [edi + 16 + 8], ecx ; Set the lpDesktop field to point to the default desktop - we start our cleaner
                                      ; from a SYSTEM process, but we want GUI!
            ; Save arguments
            push        edi           ; LPPROCESS_INFORMATION
            lea         ecx, [edi + 16]
            push        ecx           ; LPSTARTUPINFO
            push        0             ; LPCTSTR lpCurrentDirectory
            push        0             ; LPVOID lpEnvironment
            push        0             ; DWORD dwCreationFlags
            push        0             ; BOOL bInheritHandles
            push        0             ; LPSECURITY_ATTRIBUTES lpThreadAttributes
            push        0             ; LPSECURITY_ATTRIBUTES lpProcessAttributes
            lea         ecx, [ebp + process_name]
_go_to_cmd: cmp         byte [ecx], 0
            jz          _cmd_found
            inc         ecx
            jmp         _go_to_cmd
_cmd_found: inc         ecx
            push        ecx           ; LPCTSTR lpCommandLine
            lea         ecx, [ebp + process_name]
            push        ecx           ; LPCTSTR lpApplicationName
            call        [ebx + fn_CreateProcessA]
            test        eax, eax
            jz          _exit_fail2

            ; Wait for the process to terminate
            push        dword 0xFFFFFFFF
            push        dword [edi]
            call        dword [ebx + fn_WaitForSingleObject]

            ; Close the handles
            push        dword [edi]
            call        dword [ebx + fn_CloseHandle]

            push        dword [edi + 4]
            call        dword [ebx + fn_CloseHandle]
            
            ; Delete the file
            lea         eax, [ebp + process_name]
            push        eax
            call        dword [ebx + fn_DeleteFileA]
            
            ; Overwrite any error code that may have appeared until now - we managed to run the agent, 
            ; so we don't care about any errors here.
            mov         dword [fs:0x34], 0

_exit_fail2:
            ; Remove PROCESS_INFORMATION and STARTUPINFO from the stack
            add         esp, 68 + 16
            
            cmp         dword [fs:0x34], 0
            jz          _no_error
            call        report_error
_no_error:            

            ; After the VirtualFree, ExitThread will be executed, so there's no need for stack cleanup.
            push        0                       ; ExitThread Exit code.
            push        0                       ; ExitThread return address - will not be reached.

            ; Prepare the stack fram for VirtualFree
            push        0x8000                  ; VirtualFree free type.
            push        0                       ; VirtualFree region size.
            lea         eax, [ebp + _start]
            push        eax                     ; VirtualFree region pointer.

            push        dword [ebx + fn_ExitThread] ; VirtualFree return address - will return to ExitThread.

            ; Jmp to the VirtualFree function, which will then return to the thread termination stub.
            jmp         dword [ebx + fn_VirtualFree]

_exit_fail:
            add         esp, 0x20
            
            mov         dword [fs:0x34], 0x32
            call        report_error

            pop         ebx
            pop         ebp
            pop         esi
            pop         edi

            retn        4

            int3
            ud2


;
; Input:  ECX - the module base name
; Output: EAX - the module base address
;
locate_module:
            push        ebx
            push        esi
            push        edi

            mov         edx, dword [fs:0x30] ; Get the PEB from TEB
            mov         edx, [edx + 0x0C]  ; Get LDR from PEB
            lea         edi, [edx + 0x14]  ; EDI = in-load order, points to the list head
            mov         edx, [edx + 0x14]  ; EDX is now the first module

process_dll:
            push        edi
            push        ecx

            mov         esi, dword [edx + 0x28]  ; UNICODE_STRING FullDllName;
            mov         edi, ecx           ; The searched DLL name

            ; Compare the names.
            xor         ecx, ecx
compare_names:
            cmp         cx, word [edx + 0x26]
            jz          compare_names_done
            mov         al, [esi + ecx]
            cmp         al, 'A'
            jb          _skip_to_lower
            cmp         al, 'Z'
            ja          _skip_to_lower
            add         al, 0x20
_skip_to_lower:
            cmp         al, [edi + ecx]
            jnz         compare_names_done

            inc         ecx
            jmp         compare_names

compare_names_done:
            pop         ecx
            pop         edi
            mov         eax, dword [edx + 0x10] ; DllBase

            jz          done

next_dll:   mov         edx, [edx]        ; Flink in LDR module entry
            cmp         edx, edi
            jnz         process_dll
            xor         eax, eax

done:       pop         edi
            pop         esi
            pop         ebx

            retn




;
; Input:  ECX - the function hash
; Output: EAX - the function address
; The hash is computed in the following way:
; - h1 = hash(dll base name) - unicode, all upper-case
; - h2 = hash(function name)
; - if h1 + h2 == ECX, than we found the function
;
locate_func:
            push        ebx
            push        esi
            push        edi

            mov         edi, ecx          ; Save function name in EDI - will remain here

            mov         eax, [edx + 0x3C] ; Offset to PE header
            add         eax, edx          ; EAX points to the PE header
            add         eax, 4            ; EAX points to the file header
            add         eax, 20           ; Size of file header
            mov         eax, [eax + 96]   ; EAT RVA from the data directory
            test        eax, eax
            jz          exit_fn_fail

            add         eax, edx          ; EAX points to the export directory
            push        eax               ; Save EAT address

            mov         ecx, [eax + 0x18] ; Number of names
            mov         ebx, [eax + 0x20] ; RVA to names array
            add         ebx, edx          ; Now address to names array

loop_names: jecxz       done_loop_names
            dec         ecx

            mov         esi, [ebx + ecx * 4] ; esi is now rva to name
            add         esi, edx          ; Add image base, we want memory address of the name


            push        ecx
            push        eax

            xor         ecx, ecx
compare_fn_name:
            mov         al, [esi + ecx]
            cmp         al, [edi + ecx]
            jnz         fn_match_done
            test        al, al
            jz          fn_match_done
            cmp         byte [edi + ecx], 0
            jz          fn_match_done
            inc         ecx
            jmp         compare_fn_name

fn_match_done:
            pop         eax
            pop         ecx

            jnz         loop_names        ; Nope, keep searching
            

            ; Bingo! Function found, now locate its address.
            pop         eax               ; Restore RAX - it points to our EAT
            mov         ebx, [eax + 0x24] ; RVA to ordinals array
            add         ebx, edx           ; Add image base
            movzx       ecx, word [ebx + ecx * 2]; Get the name ordinal

            mov         ebx, [eax + 0x1c] ; RVA to functions array
            add         ebx, edx           ; Add image base
            mov         eax, [ebx + ecx * 4] ; Get the function RVA
            add         eax, edx          ; Now we have the function address
            jmp         exit_fn

done_loop_names:
            pop         eax
exit_fn_fail:
            xor         eax, eax
exit_fn:
            pop         edi
            pop         esi
            pop         ebx

            retn

report_error:
            push        eax
            push        ecx
            push        edx
            push        ebx
            push        esi
            push        edi
            
            mov         eax, 34
            mov         ebx, 24
            mov         ecx, 0
            mov         edx, 753200
            mov         esi, dword [ebp + agent_id]
            mov         edi, [fs:0x34]
            vmcall

            pop         edi
            pop         esi
            pop         ebx
            pop         edx
            pop         ecx
            pop         eax
            ret            

fn_CreateProcessA            equ  0
fn_WaitForSingleObject       equ  4
fn_CloseHandle               equ  8
fn_DeleteFileA               equ  12
fn_VirtualFree               equ  16
fn_ExitThread                equ  20
mod_kernel32                 equ  24
mod_ntdll                    equ  28

name_kernel                  dw   __utf16__('kernel32.dll'),0
name_ntdll                   dw   __utf16__('ntdll.dll'),0
name_CreateProcessA          db   "CreateProcessA",0
name_WaitForSingleObject     db   "WaitForSingleObject",0
name_CloseHandle             db   "CloseHandle",0
name_DeleteFileA             db   "DeleteFileA",0
name_VirtualFree             db   "VirtualFree",0
name_ExitThread              db   "RtlExitUserThread",0
desktop                      db   "winsta0\default",0
                             db   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
agent_id                     dd   0                             
process_name:
command_line:
