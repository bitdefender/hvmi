/*
 * Copyright (c) 2020 Bitdefender
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef VMCALL_H
#define VMCALL_H

#define MAGIC 34
#define SUB_OP 24

/*
 * TODO: Add another version of this vmcall for the 32-bit protocol using the
 * code from `comm_intro32.yasm' as guideline.
 */
#define vmcall(magic, sub_op, msg, hcall_num)           \
    __asm__ volatile("vmcall"                           \
                      :                                 \
                      : "a"((magic)),                   \
                      "D"((sub_op)),                    \
                      "S"(0),                           \
                      "b"((msg)),                       \
                      "d"((hcall_num)))

static inline
void
intro_call(
    void *data,
    size_t agent_hcall
    )
{
    vmcall(MAGIC, SUB_OP, data, agent_hcall);
}


#endif /* VMCALL_H */
