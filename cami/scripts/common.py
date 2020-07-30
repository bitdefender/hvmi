#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import yaml
import struct
import os
import sys
from intro_defines import section_hints
from collections import namedtuple
from objects import CamiYAMLObject, CamiObject, CamiDataTable, CamiAtom, FilePointerException

syscall_hints = {
    "IG_GUEST_WINDOWS": 1,
    "IG_GUEST_LINUX": 2,
    "LOC_SYSENTER": 1,
    "LOC_SYSCALL": 2,
    "SYSCALL_SIG_FLAG_KPTI": 0x80000000,
}

global_intro_options = None

Structure = namedtuple("Structure", ["name", "members"])

with open("tags.yaml", "r") as f:
    structures = yaml.load(f, Loader=yaml.Loader)

    for key, value in structures.items():
        structures[key] = [Structure(struct["Name"], struct["Members"]) for struct in structures[key]]


class CodePattern(CamiYAMLObject, CamiObject):
    yaml_tag = "!code_pattern"

    def post_create(self, state):
        self._pattern = [word for instruction in state["code"] for word in instruction]

    def get_binary(self):
        """ Get the binary form of this object."""

        assert len(self._pattern) <= 128

        rtr = bytes()

        for word in self._pattern:
            rtr += struct.pack("<H", word)
        return rtr

    def get_count(self):
        """ Returns the length of this pattern. (count of items(e.g. len(code), not the binary size!) """

        return len(self._pattern)

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Invalid comparison between %s and %s" % (type(self), type(other)))
        return self.__dict__ == other.__dict__

    def serialize(self, start):
        """  Generate the body of this pattern

        First, set the file pointer given as argument, and if this raises an FilePointerException
        this means that this object has been already generated and we don't need to do this again.

        Args:
            start: The offset in the file where this object will be placed

        Returns:
            bytes: - This object in it's binary form or an empty bytes object if the code has already been placed in the file
        """

        try:
            self.set_file_pointer(start)
        except FilePointerException:
            return bytes()

        return self.get_binary()


class PatternSignature(CamiYAMLObject, CamiAtom):
    yaml_tag = "!pattern_signature"
    """
        struct _CAMI_PATTERN_SIGNATURE
        {
            DWORD       SignatureId;
            DWORD       Offset;
            DWORD       Flags;
            WORD        _Reserved;
            WORD        PatternLength;
            DWORD       PatternOffset;

            DWORD       _Reserved1;
            QWORD       _Reserved2;
        }
    """
    descriptor_layout = "<IIIHHIIQ"

    def get_flags_from_list(self, lst):

        if type(lst) is not list:
            return lst

        flags = 0

        for flag in lst:
            flags |= syscall_hints[flag]

        return flags

    def post_create(self, state):
        """ The YAML constructor for this object. """

        self.id = self.get_flags_from_list(self.id)
        self.flags = self.get_flags_from_list(self.flags)

    def get_descriptor(self):
        return struct.pack(
            self.descriptor_layout,
            self.id,
            self.offset,
            self.flags,
            0,
            self.pattern.get_count(),
            self.pattern.get_file_pointer(),
            0,
            0,
        )

    def serialize(self, start):
        return self.pattern.serialize(start)


class SyscallPattern(PatternSignature):
    yaml_tag = "!syscall_pattern"


class SyscallsList(CamiDataTable):
    section_hint = section_hints["syscalls"]
    entry_type = SyscallPattern


class OpaqueFields(CamiYAMLObject, CamiAtom, CamiObject):
    yaml_tag = "!opaque_fields"
    """
    typedef struct _CAMI_OPAQUE_STRUCTURE
    {
        DWORD   Members;             // A filepointer to members of this function. (pointer to a DWORD[] array)
        DWORD   MembersCount;        // How many members are available for this structure
    } CAMI_OPAQUE_STRUCTURE, *PCAMI_OPAQUE_STRUCTURE;
    """
    descriptor_layout = "<II"

    def __init__(self):
        self.fields = {}

    def post_create(self, state):
        self.fields = {}
        self.fields.update(state)

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Invalid comparison between %s and %s" % (type(self), type(other)))
        return self.__dict__ == other.__dict__

    def set_tags(self, tags):
        self._tags = tags

    def get_count(self):
        """ Get the fields count """
        return len(self._tags)

    def get_binary(self):
        """ Get the binary representation of this fields

        We are doing this here (not in serialize) in order to simplify the code

        Returns:
            bytes: - A bytes() object with the field value of each tag or 0 if it doesn't exists.
        """
        data = bytes()

        for tag in self._tags:
            value = 0
            if tag in self.fields.keys():
                value = self.fields[tag]
            try:
                data += struct.pack("<I", value)
            except struct.error as e:
                raise TypeError(f"expected integer value for {tag} but got {type(value)}: {value}")

        return data

    def get_descriptor(self):
        return struct.pack(self.descriptor_layout, self.get_file_pointer(), self.get_count())

    def serialize(self, start):
        """ Sets the file pointer of this object and returns its binary reprezentation.

        May return an empty bytes() object if this fields are already in the update file.
        """
        try:
            self.set_file_pointer(start)
        except FilePointerException:
            return bytes()

        return self.get_binary()


class StructuresList(CamiYAMLObject, CamiDataTable):
    yaml_tag = "!opaque_structures"
    entry_type = OpaqueFields
    all_structs = []

    def post_create(self, state):
        CamiDataTable.__init__(self)

        for struct in structures[self.type]:
            if struct.name in self.os_structs.keys():
                entry = self.os_structs[struct.name]
            else:
                if struct.name != "NsProxy":
                    print("Warning: this os doesn't have fields for stucture {}".format(struct.name))
                entry = OpaqueFields()

            entry.set_tags(struct.members)

            # Make sure we don't dump duplicated structures
            try:
                idx = StructuresList.all_structs.index(entry)
                entry = StructuresList.all_structs[idx]
            except ValueError:
                StructuresList.all_structs.append(entry)

            self.add_entry(entry)


class IntrocoreVersion(CamiYAMLObject):
    yaml_tag = "!introcore_version"

    def __init__(self, value):
        self.version = value
        (self.build, self.revision, self.minor, self.major) = struct.unpack("<HHHH", struct.pack("<Q", self.version))

    def post_create(self, state):
        self.version = struct.unpack("<Q", struct.pack("<HHHH", self.build, self.revision, self.minor, self.major))[0]

    def __repr__(self):
        if 0xFFFF == self.major:
            return "MAX_ANY"
        elif 0 == self.major:
            return "MIN_ANY"

        return "%u.%u.%u.%u (0x%lx)" % (self.major, self.minor, self.revision, self.build, self.version,)

    def min_version():
        return IntrocoreVersion(0)

    def max_version():
        return IntrocoreVersion((1 << 64) - 1)

    def get_raw(self):
        return self.version
