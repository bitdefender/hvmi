#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import struct
import yaml
from intro_defines import defines, section_hints


class CamiYAMLObject(yaml.YAMLObject):
    """
    Every object created from an .yaml file should extend this class.

    Please do not overwrite __setstate__ method!!! Instead, implement post_create.

    """

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.post_create(state)
        _save_object(self)

    # overwritable
    def post_create(self, state):
        pass


__objects = {}


def _save_object(obj):
    tp = type(obj)
    if tp in __objects:
        if obj not in __objects[tp]:
            __objects[tp].append(obj)
    else:
        __objects[tp] = [obj]


def get_all_objects(tp):
    try:
        return __objects[tp]
    except KeyError:
        return []


class CamiParsableObject:
    def serialize(self, start):
        raise NotImplementedError


class FilePointerException(Exception):
    pass


class CamiObject(CamiParsableObject):

    _file_pointer = None

    def set_file_pointer(self, file_pointer):
        if self._file_pointer is not None:
            raise FilePointerException("File pointer already set!")

        self._file_pointer = file_pointer

    def get_file_pointer(self):
        if self._file_pointer is None:
            raise FilePointerException("File pointer not set!")

        return self._file_pointer


class FileHeader(CamiObject):
    """
        struct _CAMI_HEADER
        {
            DWORD Magic;

            struct
            {
                DWORD Minor;
                DWORD Major;
            } Version;

            DWORD BuildNumber;

            DWORD FileSize;
            DWORD NumberOfSections;
            DWORD PointerToSectionsHeaders;
        }
    """

    struct_layout = "<IIIIIII"

    def __init__(self, buildnumber, version):
        self.magic = defines["CAMI_MAGIC_WORD"]
        self.buildnumber = buildnumber
        self.version = version
        self.filesize = 0

    def set_sections(self, sections):
        self.sections = sections

    def get_binary_size(self):
        return struct.calcsize(self.struct_layout)

    def get_binary(self):
        return struct.pack(
            self.struct_layout,
            self.magic,
            self.version[1],
            self.version[0],
            self.buildnumber,
            self.filesize,
            self.sections.get_entry_count(),
            self.sections.get_file_pointer(),
        )

    def serialize(self, start):
        self.set_file_pointer(start)

        data = self.sections.serialize(start + self.get_binary_size())

        self.filesize = self.get_binary_size() + len(data)

        return self.get_binary() + data


class SectionsTable(CamiObject):
    """
        struct _CAMI_SECTION_HEADER
        {
            DWORD Hint;
            DWORD EntryCount;
            DWORD _Reserved;
            DWORD DescriptorTable;
        }
    """

    entry_layout = "<IIII"

    def create_entry(self, hint, entry_count, data_table):
        """ Generate a sections table entry

        Args:
            hint: The section hint. Must be a combination of values from intro_defines.section_hints dict.
            entry_count: How many entries are in the CamiDataTable
            data_table: CamiDataTable with entries describing section data

        Returns:
            bytes: args packed in a binary form.
        """
        return struct.pack(self.entry_layout, hint, entry_count, 0, data_table)

    def __init__(self):
        self._sections = []

    def add_section(self, section):
        if section in self._sections:
            raise Exception("Section is already in section_table")

        self._sections.append(section)

    def get_entry_count(self):
        return len(self._sections)

    def get_binary_size(self):
        return struct.calcsize(self.entry_layout) * self.get_entry_count()

    def get_binary(self):
        rtr = bytes()
        for section in self._sections:
            rtr += self.create_entry(section.section_hint, section.get_entry_count(), section.get_file_pointer())
        return rtr

    def serialize(self, start):
        self.set_file_pointer(start)
        start += self.get_binary_size()

        data = bytes()
        for section in self._sections:
            data += section.serialize(start + len(data))

        return self.get_binary() + data


class CamiAtom(CamiParsableObject):
    """ This is an abstract class which describes a CamiDataTable entry"""

    def get_descriptor(self):
        raise NotImplementedError


class CamiDataTable(CamiObject):
    def __init__(self, entries=[]):
        if not issubclass(self.entry_type, CamiAtom):
            raise Exception("CamiDataTable entry must be a CamiAtom")

        self._entries = []
        self.set_entries(entries)

    def process_list(self):
        """
        This is an abstract method which is called before serializing the list.
        """
        pass

    def _check_type(self, obj):
        if not issubclass(type(obj), self.entry_type):
            raise Exception("Invalid object type. Expected %s (or a subclass), got %s." % (self.entry_type, type(obj)))

    def set_entries(self, entries):
        for entry in entries:
            self._check_type(entry)

        self._entries = []
        self._entries.extend(entries)

    def get_entries(self):
        return self._entries

    def add_entry(self, entry):
        self._check_type(entry)

        self._entries.append(entry)

    def get_entry_count(self):
        return len(self._entries)

    def get_binary_size(self):
        return len(self._entries) * struct.calcsize(self.entry_type.descriptor_layout)

    def get_binary(self):
        rtr = bytes()
        for entry in self._entries:
            rtr += entry.get_descriptor()
        return rtr

    def __eq__(self, other):
        return type(self) == type(other) and self._entries == other._entries

    def __repr__(self):
        r = self.__class__.__name__ + "(0x%lx)" % id(self) + " : "

        if not self._entries:
            r += "Empty"

        for entry in self._entries:
            r += "<" + repr(entry) + "> "

        return r

    def serialize(self, start):
        try:
            self.set_file_pointer(start)
        except FilePointerException:
            return bytes()

        self.process_list()

        start += self.get_binary_size()

        raw = bytes()
        for entry in self._entries:
            raw += entry.serialize(start + len(raw))

        return self.get_binary() + raw
