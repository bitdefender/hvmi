#include "handlers.s"

.text
.code64
.intel_syntax noprefix

.macro generate_reloc_code fn_name
    \fn_name\(_reloc):
        .rept 16
        nop
        .endr
.endm

.macro call_with_return fn_name
    push rax
    call \fn_name
    test eax, eax
    jnz _direct_ret
    pop rax
.endm


.macro call_with_param1_override fn_name
    mov rdi, rax
    pop rax
.endm


.macro jmp_back offset
    jmpq [rip + hypercall_info + \offset]
.endm


/* simple trampoline: calls the C function; executes the original instr and jumps back */
.macro __def_tramp fn_name call_fn offset
    .align 8
    \fn_name\(_trampoline):
        call \call_fn
        generate_reloc_code \fn_name
        jmp_back \offset
.endm

.macro __def_tramp_pre_callback pre_callback fn_name call_fn offset
    .align 8
    \fn_name\(_trampoline):
        call \pre_callback
        call \call_fn
        generate_reloc_code \fn_name
        jmp_back \offset
.endm

.macro def_tramp fn_name offset
    __def_tramp \fn_name \fn_name \offset
.endm

.macro def_tramp_pre_callback pre_callback fn_name offset
    __def_tramp_pre_callback \pre_callback \fn_name \fn_name \offset
.endm


/*
 * when two functions with different names have the same implementation
 * we need 2 trampolines, but both call the same C function
 */
.macro def_tramp_fn fn_name call_fn offset
    __def_tramp \fn_name \call_fn \offset
.endm

.macro def_tramp_fn_pre_callback pre_callback fn_name call_fn offset
    __def_tramp_pre_callback \pre_callback \fn_name \call_fn \offset
.endm

.macro def_tramp_fn_hijack fn_name hijack_fn_name call_fn offset
    __def_tramp \fn_name\(_)\hijack_fn_name \call_fn \offset
.endm

/* expects hvmi to tell it to just return */
.macro __def_tramp_skip fn_name call_fn offset
    .align 8
    \fn_name\(_trampoline):
        call_with_return \call_fn
        generate_reloc_code \fn_name
        jmp_back \offset
.endm


.macro def_tramp_skip fn_name offset
    __def_tramp_skip \fn_name \fn_name \offset
.endm


.macro def_tramp_skip_fn fn_name call_fn offset
    __def_tramp_skip \fn_name \call_fn \offset
.endm


/* `reg` will be replaced with whatever the introcore returns */
.macro def_tramp_param_override reg fn_name offset
    .align 8
    \fn_name\(_trampoline):
        push rax
        call \fn_name
        mov \reg, rax
        pop rax
        generate_reloc_code \fn_name
        jmp_back \offset
.endm


.macro __def_tramp_ret fn_name call_fn saved_param_count offset
    .align 8
    \fn_name\(_trampoline):
        .rept \saved_param_count + 1
        push rsp
        subq [rsp], 0x08
        .endr

        call \(pre_)\call_fn

        cmpq [rsp], 0
        jg \fn_name\(_skip)

        push rax
        push rax
        lea rax, [rip + \fn_name\(_return)]
        mov [rsp + 8], rax
        pop rax

        jmp \fn_name\(_asm_jmp)

        \fn_name\(_skip):
            add rsp, (\saved_param_count + 1) * 8

        \fn_name\(_asm_jmp):
            generate_reloc_code \fn_name
            jmp_back \offset

    \fn_name\(_return):
        call \call_fn
        add rsp, (\saved_param_count + 1) * 8
        ret
.endm


.macro def_tramp_ret fn_name saved_param_count offset
    __def_tramp_ret \fn_name \fn_name \saved_param_count \offset
.endm


.macro def_tramp_ret_fn fn_name call_fn saved_param_count offset
    __def_tramp_ret \fn_name \call_fn \saved_param_count \offset
.endm


_direct_ret:
    add rsp, 8
    ret

def_tramp                   commit_creds                            commit_creds_jmp

def_tramp                   arch_jump_label_transform               arch_jump_label_transform_jmp

def_tramp                   module_param_sysfs_setup                module_param_sysfs_setup_jmp
def_tramp                   module_param_sysfs_remove               module_param_sysfs_remove_jmp

def_tramp                   wake_up_new_task                        wake_up_new_task_jmp
def_tramp_skip              flush_old_exec                          flush_old_exec_jmp
def_tramp                   do_exit                                 do_exit_jmp

def_tramp_skip              arch_ptrace                             arch_ptrace_jmp
def_tramp_skip_fn           compat_arch_ptrace      arch_ptrace     compat_arch_ptrace_jmp
def_tramp_skip              process_vm_rw_core                      process_vm_rw_core_jmp

def_tramp                   __vma_link_rb                           __vma_link_rb_jmp
def_tramp                   change_protection                       change_protection_jmp

def_tramp_ret               vma_adjust                          3   vma_adjust_jmp
def_tramp_ret_fn            __vma_adjust            vma_adjust  3   __vma_adjust_jmp

def_tramp                   vma_rb_erase                            vma_rb_erase_jmp
def_tramp_fn                __vma_rb_erase          vma_rb_erase    __vma_rb_erase_jmp

def_tramp                   expand_downwards                        expand_downwards_jmp

def_tramp                   text_poke                               text_poke_jmp
def_tramp_fn                __text_poke             text_poke       __text_poke_jmp

def_tramp                   ftrace_write                            ftrace_write_jmp

def_tramp_pre_callback      store_regs              panic                                           panic_jmp
def_tramp_fn_pre_callback   store_regs              crash_kexec     panic                           crash_kexec_jmp

def_tramp                   __access_remote_vm                      __access_remote_vm_jmp

def_tramp_param_override    rdi complete_signal complete_signal_jmp

def_tramp_fn_hijack mprotect_fixup  vma_wants_writenotify   mprotect_fixup_vma_wants_writenotify    mprotect_fixup_vma_wants_writenotify_jmp
def_tramp_fn_hijack do_munmap       rb_erase                do_munmap_rb_erase                      do_munmap_rb_erase_jmp
def_tramp_fn_hijack vma_adjust      rb_erase                vma_adjust_rb_erase                     vma_adjust_rb_erase_jmp



