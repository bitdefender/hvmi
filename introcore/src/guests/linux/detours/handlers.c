/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#include "handlers.h"
#include "defs.h"
#include "common.h"

#include "hvmi.h"

struct inactive_task_frame {
    unsigned long r15;
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long bx;

    unsigned long bp;
    unsigned long ret_addr;
};


def_detour_vars(commit_creds);
def_detour_vars(arch_jump_label_transform);
def_detour_vars(module_param_sysfs_setup);
def_detour_vars(module_param_sysfs_remove);
def_detour_vars(wake_up_new_task);
def_detour_vars(flush_old_exec);
def_detour_vars(do_exit);
def_detour_vars(arch_ptrace);
def_detour_vars(compat_arch_ptrace);
def_detour_vars(process_vm_rw_core);
def_detour_vars(__vma_link_rb);
def_detour_vars(change_protection);
def_detour_vars(vma_adjust);
def_detour_vars(__vma_adjust);
def_detour_vars(vma_rb_erase);
def_detour_vars(__vma_rb_erase);
def_detour_vars(expand_downwards);
def_detour_vars(complete_signal);
def_detour_vars(text_poke);
def_detour_vars(__text_poke);
def_detour_vars(ftrace_write);
def_detour_vars(panic);
def_detour_vars(crash_kexec);
def_detour_vars(__access_remote_vm);
def_detour_hijack_vars(mprotect_fixup, vma_wants_writenotify);
def_detour_hijack_vars(do_munmap, rb_erase);
def_detour_hijack_vars(vma_adjust, rb_erase);


LIX_HYPERCALL_PAGE hypercall_info __section(".detours") = {
    .DetoursCount = det_max_id,
    .Detours = {
        init_detour_field(commit_creds),
        init_detour_field(arch_jump_label_transform),
        init_detour_field(module_param_sysfs_setup),
        init_detour_field(module_param_sysfs_remove),
        init_detour_field(wake_up_new_task),
        init_detour_field(flush_old_exec),
        init_detour_field(do_exit),
        init_detour_field(arch_ptrace),
        init_detour_field(compat_arch_ptrace),
        init_detour_field(process_vm_rw_core),
        init_detour_field(__vma_link_rb),
        init_detour_field(change_protection),
        init_detour_field(vma_adjust),
        init_detour_field(__vma_adjust),
        init_detour_field(vma_rb_erase),
        init_detour_field(__vma_rb_erase),
        init_detour_field(expand_downwards),
        init_detour_field(complete_signal),
        init_detour_field(text_poke),
        init_detour_field(__text_poke),
        init_detour_field(ftrace_write),
        init_detour_field(panic),
        init_detour_field(crash_kexec),
        init_detour_field(__access_remote_vm),
        init_detour_hijack_field(mprotect_fixup, vma_wants_writenotify),
        init_detour_hijack_field(do_munmap, rb_erase),
        init_detour_hijack_field(vma_adjust, rb_erase),
    },
};

//
// Helper functions
//


#define current_task \
({                                                                                                              \
    void *ret;                                                                                                  \
    asm volatile("mov %[ret], gs:[%[value]]"                                                                    \
                 : [ret] "=r" (ret)                                                                             \
                 : [value] "rm" ((unsigned long long)hypercall_info.OsSpecificFields.CurrentTaskOffset) : );    \
    (void *)ret;                                                                                                \
})


#define current_cpu \
({                                                                                                              \
    uint32_t ret;                                                                                               \
    asm volatile("mov %[ret], gs:[%[value]]"                                                                    \
                 : [ret] "=r" (ret)                                                                             \
                 : [value] "rm" ((unsigned long long)hypercall_info.OsSpecificFields.CurrentCpuOffset) : );     \
    ret;                                                                                                        \
})


__default_fn_attr
static bool is_detour_enabled(DETOUR_ID id)
{
    return  (hypercall_info.Detours[id].EnableOptions == -1ULL)
        || ((hypercall_info.Detours[id].EnableOptions & hypercall_info.ProtectionOptions) != 0);
}


__default_fn_attr
static size_t vmcall(DETOUR_ID id)
{
    if (!is_detour_enabled(id)) {
        return 0;
    }

    size_t _out_value = 34, _out_param = 0;

    asm volatile("vmcall" : "+S" (_out_param), "+a"(_out_value) : "D"(24), "b"(id): );

    // Used to clean the stack of the interrupted task
    volatile struct inactive_task_frame _reserved = { 0 };
    (void)(_reserved);

    return _out_param;
}


__default_fn_attr
char *d_path(void *path_struct)
{
    void *path = (void *)((unsigned long)hypercall_info.OsSpecificFields.PercpuMemPtr + (current_cpu * PAGE_SIZE));

    return hypercall_info.OsSpecificFields.DPathFnPtr(path_struct, path, PAGE_SIZE);
}


__default_fn_attr
void *_memcpy (void *dest, const void *src, size_t len)
{
    char *d = dest;
    const char *s = src;

    while (len--)
    {
        *d++ = *s++;
    }

    return dest;
}


__default_fn_attr
void store_regs(void)
{
    IG_ARCH_REGS regs;

    regs.Rax = __read_reg("rax");
    regs.Rcx = __read_reg("rcx");
    regs.Rdx = __read_reg("rdx");
    regs.Rbx = __read_reg("rbx");
    regs.Rsp = __read_reg("rsp");
    regs.Rbp = __read_reg("rbp");
    regs.Rsi = __read_reg("rsi");
    regs.Rdi = __read_reg("rdi");
    regs.R8 = __read_reg("r8");
    regs.R9 = __read_reg("r9");
    regs.R10 = __read_reg("r10");
    regs.R11 = __read_reg("r11");
    regs.R12 = __read_reg("r12");
    regs.R13 = __read_reg("r13");
    regs.R14 = __read_reg("r14");
    regs.R15 = __read_reg("r15");

    void *dst = (void *)((unsigned long)hypercall_info.OsSpecificFields.PercpuMemPtr + (current_cpu * PAGE_SIZE));
    _memcpy(dst, &regs, sizeof(regs));
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void commit_creds (long *creds)
{
    void *current = current_task;
    uint32_t *in_execve = (uint32_t *)((unsigned long)(current) + hypercall_info.OsSpecificFields.Task.InExecve);

    if ((*in_execve & BIT(hypercall_info.OsSpecificFields.Task.InExecveBit))) {
        return;
    }

    vmcall_2(det_commit_creds, current, creds);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void module_param_sysfs_setup(void *module)
{
    vmcall_1(det_module_param_sysfs_setup, module);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void module_param_sysfs_remove(void *module)
{
    vmcall_1(det_module_param_sysfs_remove, module);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void wake_up_new_task(long task)
{
    vmcall_2(det_wake_up_new_task, current_task, task);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
int flush_old_exec(long binprm)
{
    unsigned long file = *(unsigned long *)(binprm + hypercall_info.OsSpecificFields.Binprm.FileOffset);
    unsigned long path_struct = 0;

    if (!file) {
        goto _vmcall;
    }

    path_struct = file + hypercall_info.OsSpecificFields.File.PathOffset;

_vmcall:
    return vmcall_3(det_flush_old_exec, current_task, binprm, d_path((void *)path_struct));
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void do_exit(long code)
{
    vmcall_2(det_do_exit, current_task, code);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
long arch_ptrace(long child, long request)
{
    if (request == PTRACE_POKEDATA
        || request == PTRACE_POKETEXT
        || request == PTRACE_SETFPREGS
        || request == PTRACE_SETFPXREGS
        || request == PTRACE_SETREGS)
    {
        return vmcall_2(det_arch_ptrace, child, request);
    }

    return 0;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
size_t process_vm_rw_core(int pid, void *iter, void *rvec, unsigned long riovcnt,
    unsigned long flags, int vm_write)
{
    if (!vm_write) {
        return 0;
    }

    return vmcall_2(det_process_vm_rw_core, current_task, pid);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void __vma_link_rb(void *mm, void *vma, void **rb_link, void *rb_parent)
{
    long mm_flags = *(long *)((long)(mm) + hypercall_info.OsSpecificFields.Mm.FlagsOffset);

    if (!(mm_flags & BIT(hypercall_info.OsSpecificFields.Mm.ProtectionBit))) {
        return;
    }

    long file = *(long *)((long)(vma) + hypercall_info.OsSpecificFields.Vma.FileOffset);
    if (file) {
        return;
    }

    long vm_flags = *(long *)((long)(vma) + hypercall_info.OsSpecificFields.Vma.FlagsOffset);
    if (!(vm_flags & VM_EXEC)) {
        return;
    }

    vmcall_2(det___vma_link_rb, vma, mm);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void change_protection(long vma, unsigned long start, unsigned long end,
    unsigned long newprot, int dirty_accountable, int prot_numa)
{
    long file = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FileOffset);
    if (file) {
        return;
    }

    long mm = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.MmOffset);
    long mm_flags = *(long *)(mm + hypercall_info.OsSpecificFields.Mm.FlagsOffset);

    if (!(mm_flags & BIT(hypercall_info.OsSpecificFields.Mm.ProtectionBit))) {
        return;
    }

    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);

    if (((vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit)) && !(vm_flags & VM_EXEC))
        || (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit)) && (vm_flags & VM_EXEC))) {

        // Either we protected it and now the X bit will be removed, or we didn't and now the X bit will be set
        vmcall_2(det_change_protection, vma, mm);
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void pre_vma_adjust(long vma, unsigned long start, unsigned long end,
    unsigned long pgoff, void *insert, void *expand,
    long *skip_call, long *saved_vma, long *next, long *prev)
{
    *skip_call = 1;

    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);
    if (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit))) {
        return;
    }

    *saved_vma = vma;
    *next = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.VmNextOffset);
    *prev = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.VmPrevOffset);
    *skip_call = 0;

    return;
}


__default_fn_attr
void vma_adjust(long _vma, unsigned long _start, unsigned long _end,
    unsigned long _pgoff, void *_insert, void *_expand,
    long *_skip_call, long saved_vma, long next, long prev)
{
    long svma = saved_vma;
    long mm = *(long *)(saved_vma + hypercall_info.OsSpecificFields.Vma.MmOffset);

    vmcall_4(det_vma_adjust, svma, mm, next, prev);
    vmcall_4(det___vma_adjust, svma, mm, next, prev);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void vma_rb_erase(long vma, void *root)
{
    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);
    if (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit))) {
        return;
    }

    vmcall_2(det_vma_rb_erase, vma, *(long *)(vma + hypercall_info.OsSpecificFields.Vma.MmOffset));
    vmcall_2(det___vma_rb_erase, vma, *(long *)(vma + hypercall_info.OsSpecificFields.Vma.MmOffset));
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void expand_downwards(long vma, unsigned long address)
{
    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);
    if (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit))) {
        return;
    }

    vmcall_3(det_expand_downwards, vma, *(long *)(vma + hypercall_info.OsSpecificFields.Vma.MmOffset), address);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
int complete_signal(int sig, void *task, enum pid_type type)
{
    if (sig != SIGQUIT
        && sig != SIGILL
        && sig != SIGIOT
        && sig != SIGBUS
        && sig != SIGFPE
        && sig != SIGSEGV) {

        return sig;
    }

    int new_sig = vmcall_3(det_complete_signal, task, sig, type);
    return new_sig ? new_sig : sig;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void text_poke(void *addr, const void *opcode, size_t len)
{
    vmcall_3(det_text_poke, addr, opcode, len);
    vmcall_3(det___text_poke, addr, opcode, len);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void ftrace_write(unsigned long ip, const char *val, int size)
{
    vmcall_3(det_ftrace_write, ip, val, size);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void panic(const char *fmt)
{
    vmcall(det_panic);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void arch_jump_label_transform(void *entry, enum jump_label_type type)
{
    vmcall_2(det_arch_jump_label_transform, entry, type);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void __access_remote_vm(void *task, void *mm, unsigned long addr,
    void *buf, int len, unsigned int gup_flags)
{
    if ((gup_flags & 1) == 0) {
        return;
    }

    vmcall_5(det___access_remote_vm, mm, addr, buf, len, gup_flags);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void do_munmap_rb_erase(unsigned long vma_vm_rb, unsigned long mm_mm_rb)
{
    unsigned long vma = vma_vm_rb - hypercall_info.OsSpecificFields.Vma.Rb;
    unsigned long mm = mm_mm_rb - hypercall_info.OsSpecificFields.Mm.Rb;
    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);

    if (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit))) {
        return;
    }

    vmcall_2(det_do_munmap_rb_erase, vma, mm);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void vma_adjust_rb_erase(unsigned long vma_vm_rb, unsigned long mm_mm_rb)
{
    unsigned long vma = vma_vm_rb - hypercall_info.OsSpecificFields.Vma.Rb;
    unsigned long mm = mm_mm_rb - hypercall_info.OsSpecificFields.Mm.Rb;
    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);

    if (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit))) {
        return;
    }

    vmcall_2(det_vma_adjust_rb_erase, vma, mm);
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////
__default_fn_attr
void mprotect_fixup_vma_wants_writenotify(unsigned long vma)
{
    long file = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FileOffset);
    if (file) {
        return;
    }

    long mm = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.MmOffset);
    long mm_flags = *(long *)(mm + hypercall_info.OsSpecificFields.Mm.FlagsOffset);

    if (!(mm_flags & BIT(hypercall_info.OsSpecificFields.Mm.ProtectionBit))) {
        return;
    }

    long vm_flags = *(long *)(vma + hypercall_info.OsSpecificFields.Vma.FlagsOffset);

    if (((vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit)) && !(vm_flags & VM_EXEC))
        || (!(vm_flags & BIT(hypercall_info.OsSpecificFields.Vma.ProtectionBit)) && (vm_flags & VM_EXEC))) {

        // Either we protected it and now the X bit will be removed, or we didn't and now the X bit will be set
        vmcall_2(det_mprotect_fixup_vma_wants_writenotify, vma, mm);
    }
}


// Will be droped by the compiler, but will generate usefull #defines for asm
void __asm_defines(void)
{
    def_detour_asm_vars(commit_creds);
    def_detour_asm_vars(arch_jump_label_transform);
    def_detour_asm_vars(module_param_sysfs_setup);
    def_detour_asm_vars(module_param_sysfs_remove);
    def_detour_asm_vars(wake_up_new_task);
    def_detour_asm_vars(flush_old_exec);
    def_detour_asm_vars(do_exit);
    def_detour_asm_vars(arch_ptrace);
    def_detour_asm_vars(compat_arch_ptrace);
    def_detour_asm_vars(process_vm_rw_core);
    def_detour_asm_vars(__vma_link_rb);
    def_detour_asm_vars(change_protection);
    def_detour_asm_vars(vma_adjust);
    def_detour_asm_vars(__vma_adjust);
    def_detour_asm_vars(vma_rb_erase);
    def_detour_asm_vars(__vma_rb_erase);
    def_detour_asm_vars(expand_downwards);
    def_detour_asm_vars(complete_signal);
    def_detour_asm_vars(text_poke);
    def_detour_asm_vars(__text_poke);
    def_detour_asm_vars(ftrace_write);
    def_detour_asm_vars(panic);
    def_detour_asm_vars(crash_kexec);
    def_detour_asm_vars(__access_remote_vm);

    def_detour_hijack_asm_vars(mprotect_fixup, vma_wants_writenotify);
    def_detour_hijack_asm_vars(do_munmap, rb_erase);
    def_detour_hijack_asm_vars(vma_adjust, rb_erase);
}


