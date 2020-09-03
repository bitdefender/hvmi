#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""

"""

import r2wrapper
from collections import namedtuple
from functools import lru_cache
import sys
import re

StructSearcher = namedtuple('StructSearcher', 'unnamed index entry')

class StructFactory():

    def __init__(self, robj):
        self.robj = robj

    def get_struct_searcher(self, name, unnamed_index=0):
        unnamed = name in ['<unnamed-tag>', '<anonymous-tag>']
        it = reversed(list(enumerate(self.robj.types[:unnamed_index] if unnamed else self.robj.types)))

        for i, e in it:
            if e['type'] == 'structure' and e['name'] == name and e['size'] != 0:
                return StructSearcher(unnamed_index - i if unnamed else 0, i, e)

        raise LookupError(f"Failed to find structure {name} starting from {unnamed_index}")

    def get_struct_from_struct_searcher(self, struct_searcher):
        u, i, s = struct_searcher

        struct = StructType(s['name'], s['size'])

        for f in reversed(s['members']):
            sp = f['member_type'].split(' ')

            if sp[0] in ['struct', 'union'] and '*' not in sp[1]:
                # TODO: maybe handle arrays. we don't need to right now since we don't and likely won't
                # ever need to get the offset of, for exampe, STRUCT.SomeArrayOfStructs[12].SomeField.
                # If we will need to, just get the offset of `SomeArrayOfStructs`, the index (12), and 
                # the offset of `SomeField`.
                # All in all, handling arrays is quite complicated and really not needed for the purpose
                # of this project...
                r = re.compile(r'\[.*\]')
                sp[1] = re.sub(r, '', sp[1])
                ss = self.get_struct_searcher(sp[1], i - u)
                u += ss.unnamed
                struct.add_struct_field(f, self.get_struct_from_struct_searcher(ss))
            elif sp[0] in ['bitfield']:
                struct.add_bitfield_field(f, sp[-1], self.robj.size_for_basic_type(f['member_type']))
            else:
                struct.add_field(f, self.robj.size_for_basic_type(f['member_type']))

        return struct

    @lru_cache(maxsize=32)
    def get_struct(self, name):
        return self.get_struct_from_struct_searcher(self.get_struct_searcher(name))

class Field():

    def __init__(self, offset, name, type):
        self.offset = offset
        self.name = name
        self.type = type

    def __repr__(self):
        return f"Field(offset={self.offset}, name={self.name}, type={str(self.type)})"


class BasicType():
    
    def __init__(self, name, size):
        self.name = name
        self.size = size

    def __repr__(self):
        return f"BasicType(name={self.name}, size={self.size})"

class BitfieldType():

    def __init__(self, bit_idx, bit_cnt):
        self.bit_idx = bit_idx
        self.bit_cnt = bit_cnt

    def __repr__(self):
        return f"BitfieldType(bit_idx={self.bit_idx}, bit_cnt={self.bit_cnt})"

class StructType():

    def __init__(self, name, size):
        self.name = name
        self.size = size
        self.fields = []

    def add_struct_field(self, field, struct):
        off = int(field['offset'])
        self.fields.insert(0, Field(off, field['member_name'], struct))

    def add_field(self, field, size):
        off = int(field['offset'])
        f = Field(off, field['member_name'], BasicType(field['member_type'], size))
        self.fields.insert(0, f)

    def add_bitfield_field(self, field, bit_cnt, size):
        off = int(field['offset'])
        bit_cnt = int(bit_cnt)

        for f in self.fields:
            if not isinstance(f.type, BitfieldType) or f.offset != off:
                break

            f.type.bit_idx += bit_cnt

        f = Field(off, field['member_name'], BitfieldType(0, bit_cnt))
        self.fields.insert(0, f)

    def gen_fields(self, names):
        if not isinstance(names, list):
            raise TypeError(f"names must be a ['list', 'of', 'strings'], not {type(names)}")
        
        for f in self.fields:
            if f.name == names[0]:
                yield f
                break
        else:
            raise LookupError(f"failed to find {names[0]} in {self.name}")

        if len(names) > 1:
            yield from f.type.gen_fields(names[1:])

    def get_field(self, names):
        return list(self.gen_fields(names))[-1]

    def get_field_offset(self, names):
        off = 0
        for f in self.gen_fields(names):
            off += f.offset
        return off

    def get_r2_pf(self):
        raise NotImplementedError
    
    def __repr__(self):
        s = f"StructType(name={self.name}, size={self.size}, fields=["
        for f in self.fields:
            s += str(f) + (", " if f is not self.fields[-1] else "]")
        return s

