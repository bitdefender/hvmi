#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import yaml
import struct
import os
import crc32
import intro_defines
from objects import CamiYAMLObject, CamiObject, CamiDataTable, CamiAtom, FilePointerException, get_all_objects

options = {}

known_encodings = ["utf-8", "utf-16"]


class GlobalIntrocoreOptions(CamiYAMLObject):
    yaml_tag = u'!global_introcore_options'

    def post_create(self, state):
        if "globals" in options:
            raise Exception("Global options already loaded")
        options["globals"] = {}
        options["globals"].update(state)


class ProcessOptions(CamiYAMLObject, CamiAtom):
    """
	typedef struct _CAMI_PROC_PROT_OPTIONS
	{
		union
		{
			WCHAR    Name16[32];
			CHAR     Name8[64];
		}
		DWORD    OptionsOffset;
		DWORD    Flags;

		QWORD   _Reserved1;
		DWORD   _Reserved2;
		DWORD   _Reserved3;

	} CAMI_PROC_PROT_OPTIONS;
	"""

    yaml_tag = "!process_options"

    descriptor_layout = "<64sIIQII"

    encoding = "utf-8"

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Unsupported comparison between {} and {}".format(type(self), type(other)))
        return self.__dict__ == other.__dict__

    def get_descriptor(self):
        if self.encoding not in known_encodings:
            raise Exception("Invalid encoding: {}".format(encoding))

        flags = 0
        skip = 0

        if self.encoding == "utf-16":
            flags |= intro_defines.process_options_flags["name_utf16"]
            skip = 2

        return struct.pack(
            self.descriptor_layout,
            bytes(self.name, self.encoding)[skip:],
            self.options.get_file_pointer(),
            flags,
            0,
            0,
            0,
        )

    def serialize(self, start):
        return self.options.serialize(start)

    def __repr__(self):
        return self.name + ", " + repr(self.options)


class ProcessOptionsList(CamiDataTable):
    entry_type = ProcessOptions


class Options:
    def __init__(self):
        self.core_options = IntrocoreOptions()
        self.shemu_options = IntrocoreOptions()
        self.proc_options = ProcessOptionsList()

    def apply(self, other):
        self.core_options.apply(other.core_options)
        self.shemu_options.apply(other.shemu_options)
        for opt_to_apply in other.proc_options.get_entries():
            found = False

            for opt in self.proc_options.get_entries():
                if opt.name == opt_to_apply.name:
                    opt.options.apply(opt_to_apply.options)
                    found = True

            if not found:
                self.proc_options.add_entry(opt_to_apply)


class GlobalOptions(Options, CamiYAMLObject):
    yaml_tag = "!global_options"

    def post_create(self, state):
        self.proc_options = ProcessOptionsList()
        self.proc_options.set_entries(state["proc_options"])

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Unsupported comparison between {} and {}".format(type(self), type(other)))
        return self.__dict__ == other.__dict__


class OsOptions(Options, CamiYAMLObject, CamiObject):
    yaml_tag = "!os_options"
    """
    typedef struct _CAMI_CUSTOM_OS_PROTECTION
    {
        DWORD CoreOptionsOffset;    // Intro core options. Filepointer to a CAMI_PROT_OPTIONS structure
        DWORD ProcOptionsCount;     // Proc options count
        DWORD ProcOptionsTable;     // Process protection options. Pointer to a CAMI_PROC_PROT_OPTIONS[] array
        DWORD ShemuOptions;         // Shemu options. Filepointer to a CAMI_PROT_OPTIONS structure
        QWORD _Reserved2;
    } CAMI_CUSTOM_OS_PROTECTION;
    """
    descriptor_layout = "<IIIIQ"

    def __init__(self, other):
        self.core_options = other.core_options
        self.proc_options = other.proc_options
        self.shemu_options = other.shemu_options
        self.version = None
        self.os_type = None

    def post_create(self, state):
        self.proc_options = ProcessOptionsList()
        self.proc_options.set_entries(state["proc_options"])

    def get_binary_size(self):
        return struct.calcsize(self.descriptor_layout)

    def get_binary(self):
        return struct.pack(
            self.descriptor_layout,
            self.core_options.get_file_pointer(),
            self.proc_options.get_entry_count(),
            self.proc_options.get_file_pointer(),
            self.shemu_options.get_file_pointer(),
            0,
        )

    def serialize(self, start):
        try:
            self.set_file_pointer(start)
            data = self.core_options.serialize(start + self.get_binary_size())
            data += self.proc_options.serialize(start + self.get_binary_size() + len(data))
            data += self.shemu_options.serialize(start + self.get_binary_size() + len(data))
            return self.get_binary() + data
        except FilePointerException:
            return bytes()

    def __repr__(self):
        return "Core: " + repr(self.core_options) + " Process: " + repr(self.proc_options) + \
               " Shemu: " + repr(self.shemu_options)


class IntrocoreOptions(CamiYAMLObject, CamiObject):
    yaml_tag = "!options_control"
    """
    typedef struct _CAMI_PROT_OPTIONS
    {
        QWORD   ForceOff;           // Options which will be disabled
        QWORD   ForceBeta;          // Options beta only
        QWORD   ForceFeedback;      // Options feedback only
        QWORD   ForceOn;            // Options which will be enabled by default
        DWORD  _Reserved2;
        DWORD  _Reserved3;
    } CAMI_PROT_OPTIONS;
    """

    descriptor_layout = "<QQQQII"

    def __init__(self):
        self.force_off = 0
        self.force_beta = 0
        self.force_feedback = 0
        self.force_on = 0

    def get_options_value(self, opts_list):
        opts = 0

        for opt in opts_list:
            opts |= intro_defines.intro_options[opt]

        return opts

    def post_create(self, state):
        self.force_off = self.get_options_value(self.force_off)
        self.force_beta = self.get_options_value(self.force_beta)
        self.force_feedback = self.get_options_value(self.force_feedback)
        self.force_on = self.get_options_value(self.force_on)

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Unsupported comparison between {} and {}".format(type(self), type(other)))

        return self.__dict__ == other.__dict__

    def __repr__(self):
        return "off: 0x%lx beta: 0x%lx feedback: 0x%lx on: 0x%lx" % (
            self.force_off,
            self.force_beta,
            self.force_feedback,
            self.force_on,
        )

    def apply(self, other):
        self.force_off |= other.force_off
        self.force_beta |= other.force_beta
        self.force_feedback |= other.force_feedback
        self.force_on |= other.force_on

    def get_binary(self):
        # if you add any other fields make sure you update the if statement in serialize
        return struct.pack(
            self.descriptor_layout, self.force_off, self.force_beta, self.force_feedback, self.force_on, 0, 0,
        )

    def serialize(self, start):
        try:
            self.set_file_pointer(start)

            return self.get_binary()

        except FilePointerException:
            pass

        return bytes()


def apply_globals():
    global options

    # first apply global intro options to os type specific options
    options["globals"]["linux"].apply(options["globals"]["common"])
    options["globals"]["windows"].apply(options["globals"]["common"])

    # then apply the os type specific options to each os
    for os_options in options["per_os"]:
        os_options.apply(options["globals"][os_options.os_type])


def create_global_defaults():
    global options
    if "globals" in options:
        # global options are loaded. no need to create defaults
        return

    options["globals"] = {}
    options["globals"]["common"] = GlobalOptions()
    options["globals"]["linux"] = GlobalOptions()
    options["globals"]["windows"] = GlobalOptions()


def create_defaults():
    global options

    options["default"] = {}
    options["default"]["linux"] = OsOptions(options["globals"]["linux"])

    if options["globals"]["linux"] == options["globals"]["windows"]:
        options["default"]["windows"] = options["default"]["linux"]

    else:
        options["default"]["windows"] = OsOptions(options["globals"]["windows"])


def create_per_os_options_list():
    global options

    options["per_os"] = []

    try:
        options["per_os"].extend(get_all_objects(OsOptions))
    except KeyError:
        # This is fine. It means no custom options have been set (or at least loaded).
        pass


def get_options_for_os_version(version):
    global options

    if options is None:
        raise Exception("Intro options not loaded!")

    for os_options in options["per_os"]:
        if os_options.version == version:
            return os_options

    if type(version) is str:
        return options["default"]["linux"]

    elif type(version) is tuple:
        return options["default"]["windows"]

    raise Exception("Unknown os type for version {} ({})".format(version, type(version)))


def craft_options():
    create_global_defaults()

    create_per_os_options_list()

    apply_globals()

    create_defaults()
