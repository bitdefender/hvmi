;-----------------------------------------------------------------------------
            [bits 32]

            global      _start

;-----------------------------------------------------------------------------
            section .code

;================================================================================================================================
            ; Note: ESI, EDI, EBX and EBP are callee saved (if used).
_start:     push        edi
            push        esi
            push        ebp
            push        ebx

            call        _next
_next:      pop         ebp
            sub         ebp, _next
            
            ; Alloc space on the stack for the function pointers and the kernel base
            sub			esp, 0x8
            mov			ebx, esp

            lea         ecx, [ebp + name_ntdll]
            call        locate_module
            mov         [ebx + mod_ntdll], eax
            test        eax, eax
            jz          _exit_fail

            ; Fetch the LdrLoadDll function
            lea         ecx, [ebp + name_LdrLoadDll]
            mov         edx, [ebx + mod_ntdll]
            call        locate_func
            mov         [ebx + fn_LdrLoadDll], eax
            test        eax, eax
            jz          _exit_fail
            
            ; Load the library!
            lea         ecx, [ebp + uni_name]
            mov         dword [ebp + dll_name + 4], ecx

            sub         esp, 4
            push        esp
            lea         ecx, [ebp + dll_name]
            push        ecx
            push        0
            push        0
            call        dword [ebx + fn_LdrLoadDll]
            add         esp, 4

_exit_fail:
            add         esp, 0x8

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


fn_LdrLoadDll                equ  0
mod_ntdll                    equ  4
name_ntdll                   db   "n",0,"t",0,"d",0,"l",0,"l",0,".",0,"d",0,"l",0,"l",0,0,0,0,0,0,0,0,0
name_LdrLoadDll              db   "LdrLoadDll",0
dll_name                     dw   24, 26
                             dd   0
uni_name                     db   "d",0,"u",0,"m",0,"m",0,"y",0,"l",0,"i",0,"b",0,".",0,"d",0,"l",0,"l",0,0,0