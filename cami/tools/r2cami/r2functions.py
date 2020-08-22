#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""

"""

import pybddisasm
from pybddisasm.bddisasm import *
from collections import namedtuple
from functools import partial
import r2wrapper

Wildcard = namedtuple('Wildcard', 'offset length')

def place_wildcards(nd_instr):

    wildcards = [
        Wildcard('DispOffset', 'DispLength'),
        Wildcard('AddrOffset', 'AddrLength'),
        Wildcard('MoffsetOffset', 'MoffsetLength'),
        Wildcard('Imm1Offset', 'Imm1Length'),
        Wildcard('Imm2Offset', 'Imm2Length'),
        Wildcard('Imm3Offset', 'Imm3Length'),
        Wildcard('RelOffsOffset', 'RelOffsLength')
        ]

    wordarr = [i for i in nd_instr.InstructionBytes[0:nd_instr.Length]]

    for w in wildcards:
        if nd_instr.__dict__[w.offset] != 0:
            lower = nd_instr.__dict__[w.offset]
            upper = lower + nd_instr.__dict__[w.length]
            
            wordarr[lower:upper] = [0x100] * (upper - lower)

    return wordarr

Instruction = namedtuple('Instruction', 'instruction_bytes text')

def gen_instructions(bytear, bits):
    i = 0
    
    def decode_wrapper():
        return nd_decode(bytear[i:], bits, bits)

    for nd_instr in iter(partial(decode_wrapper), None):
        yield nd_instr
        i += nd_instr.Length

def get_pattern_signature(bytear, bits):
    pattern = []
    for i in gen_instructions(bytear, bits):
        pattern.append(Instruction(place_wildcards(i), i.Text))

    return pattern

def get_syscall_number(bytear, bits):
    mov_rax = None

    for i in gen_instructions(bytear, bits):
        if mov_rax and i.Mnemonic == 'SYSCALL' or i.Mnemonic == 'SYSENTER':
            return mov_rax.Immediate1
        elif i.Mnemonic == 'MOV' and 'reg' == i.Operands[0]['Type'] and i.HasImm1:
            mov_rax = i

    raise LookupError("Failed to find syscall number")

