#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import yaml
import struct
import os
import crc32
from options import get_options_for_os_version
from objects import CamiYAMLObject, CamiObject, CamiAtom, CamiDataTable, FilePointerException, get_all_objects
from common import IntrocoreVersion
from intro_defines import section_hints, defines, detour_args, version_any


class WinSupportedOs(CamiYAMLObject, CamiAtom):
    min_intro_ver = IntrocoreVersion.min_version()
    max_intro_ver = IntrocoreVersion.max_version()

    yaml_tag = "!intro_update_win_supported_os"
    """
        struct _CAMI_WIN_DESCRIPTOR
        {
            DWORD   BuildNumber;                            // Buildnumber for this Windows OS
            BOOLEAN Kpti;                                   // If this OS has Kpti support.
            BOOLEAN Is64;                                   // If this OS is 64 bits.

            WORD    _Reserved1;                             // Alignment mostly, but may become useful.

            QWORD   MinIntroVersion;                        // Minimum introcore version which supports this OS
            QWORD   MaxIntroVersion;                        // Maximum introcore version which supports this OS

            DWORD   KmStructuresCount;                      // KM opaque fields count
            DWORD   KmStructuresTable;                      // KM opaque fields file pointer. (pointer to a CAMI_OPAQUE_STRUCTURE[] array

            DWORD   UmStructuresCount;                      // UM opaque fields count
            DWORD   UmStructuresTable;                      // UM opaque fields file pointer (pointer to a CAMI_OPAQUE_STRUCTURE[] array

            DWORD   FunctionCount;                          // Functions count
            DWORD   FunctionTable;                          // Functions file pointer. (pointer to a CAMI_WIN_FUNCTION[] array.

            DWORD   CustomProtectionOffset;                 // Protection flags for this os. (pointer to a CAMI_CUSTOM_PROTECTION struct)

            DWORD   VersionStringOffset;
            DWORD   _Reserved3;
            DWORD   _Reserved4;
        }
    """
    descriptor_layout = "<IBBHQQIIIIIIIIII"


    def post_create(self, state):
        if hasattr(self, "functions"):
            self.functions = WinOsFunctionsTable(state["functions"])

    def set_um_fields(self, um_fields_list):
        """ Set the UM fields for this OS

        We have to do this by hand because a set of um fields apply to a lot of supported OS versions.
        This method will iterate the um_fields_list and find the suitable one for this OS.

        Args:
            um_fields_list: A list of WinOsUmFields.

        Raises:
            Exception: If multiple or none um_fields match this OS version.
        """

        if hasattr(self, "um_fields"):
            return

        found = None

        for um in um_fields_list:
            if self.is_64 == um.is64 and self.build_number >= um.min_ver and self.build_number <= um.max_ver:
                if found is not None:
                    raise Exception(
                        "Found duplicated UM fields for build_number %d, is_64: %r" % (self.build_number, self.is_64)
                    )
                found = um.fields

        if found is None:
            raise Exception("Could not find um for build_number %d, is_64: %d" % (self.build_number, self.is_64))

        self.um_fields = found

    def set_functions(self, functions):
        """ Set the functions for this OS

        Given the list of functions, this method will filter it and will keep only the function with patterns and
        arguments needed for this OS and will create the final form of the functions attribute a.k.a. a CamiDataTable instead
        of a python list.

        Args:
            functions: A list of WinFunction
        """

        if hasattr(self, "functions"):
            return

        funcs = WinOsFunctionsTable()

        print("Functions for Windows OS {} (is 64: {})".format(self.build_number, self.is_64))

        for function in functions:
            new_func = function.get_function_for_os(self)

            if new_func is not None:
                funcs.add_entry(new_func)

                print(
                    "\t- {} with {} patterns and arguments: {}".format(
                        new_func.name.ljust(30),
                        str(new_func.patterns.get_entry_count()).rjust(2),
                        new_func.arguments.args,
                    ).expandtabs()
                )

        self.functions = funcs

    def get_descriptor(self):
        """ Generate the CamiDataTable entry for this OS version

        Returns:
            bytes: the CamiDataTable entry (a _CAMI_WIN_DESCRIPTOR structure)

        Raises:
            FilePointerException: If this method is called before generating its body with serialize()
        """

        print(
            "Windows OS {} (kpti: {}, 64: {})".format(
                str(self.build_number).ljust(5), str(self.kpti_installed).ljust(5), str(self.is_64).ljust(5),
            )
        )
        print("\t- Options: ", self.intro_options)
        print("\t- Min intro version: ", self.min_intro_ver)
        print("\t- Max intro version: ", self.max_intro_ver)
        return struct.pack(
            self.descriptor_layout,
            self.build_number,
            self.kpti_installed,
            self.is_64,
            0,
            self.min_intro_ver.get_raw(),
            self.max_intro_ver.get_raw(),
            self.km_fields.get_entry_count(),
            self.km_fields.get_file_pointer(),
            self.um_fields.get_entry_count(),
            self.um_fields.get_file_pointer(),
            self.functions.get_entry_count(),
            self.functions.get_file_pointer(),
            self.intro_options.get_file_pointer(),
            self.version_string.get_file_pointer(),
            0,
            0,
        )  # reserved

    def serialize(self, start):
        """ Generate the body of this OS in it's binary form.

        Here we are also setting the functions and usermode fields if they are empty.

        Args:
            start: The offset in the file where this os body will be placed

        Returns:
            bytes: The body of this OS: um and km fields + functions

        """

        self.intro_options = get_options_for_os_version((self.build_number, self.kpti_installed, self.is_64))
        self.set_functions(get_all_objects(WinFunction))
        self.set_um_fields(get_all_objects(WinOsUmFields))

        data = self.km_fields.serialize(start)
        data += self.um_fields.serialize(start + len(data))
        data += self.functions.serialize(start + len(data))
        data += self.intro_options.serialize(start + len(data))
        data += self.version_string.serialize(start + len(data))
        return data


class WinVersionString(CamiYAMLObject, CamiObject):
    yaml_tag = "!intro_update_win_version_string"

    descriptor_layout = "<Q{}sQ{}s".format(defines["MAX_VERSION_STRING_SIZE"], defines["MAX_VERSION_STRING_SIZE"])

    def serialize(self, start):
        self.set_file_pointer(start)
        size = len(self.version_string) + 1
        if size > (defines["MAX_VERSION_STRING_SIZE"] - 1):
            raise Exception("String is too big!")

        size_server = len(self.server_version_string) + 1
        if size_server > (defines["MAX_VERSION_STRING_SIZE"] - 1):
            raise Exception("String for server is too big!")

        return struct.pack(
            self.descriptor_layout,
            size,
            bytes(self.version_string, "utf-8"),
            size_server,
            bytes(self.server_version_string, "utf-8"),
        )


class WinOsUmFields(CamiYAMLObject):
    yaml_tag = "!intro_update_win_um_fields"


class WinFunction(CamiYAMLObject, CamiAtom):
    yaml_tag = "!intro_update_win_function"
    """
        struct _CAMI_WIN_FUNCTION
        {
            DWORD   NameHash;

            DWORD   PatternsCount;
            DWORD   PatternsTable;

            DWORD   ArgumentsCount;
            DWORD   ArgumentsTable;

            QWORD   _Reserved1;
            DWORD   _Reserved2;
            DWORD   _Reserved3;
        }

    """

    g_patterns_list = []
    descriptor_layout = "<IIIIIQII"

    def __init__(self, other):
        """ This is basically a copy constructor.

        We don't use deepcopy because we don't want to duplicate the patterns or arguments

        Args:
            other: Another WinFunction object

        Attributes:
            name: The function name
            patterns: A table* with the patterns for this function.
            arguments: A WinFunctionArgument with the arguments for this function.

        Notes:
            * Depending on how the object was created, table could mean:
                - A python list, if the object was created by the YAML loader. This is an intermediate form and should
                  be transformed in a CamiDataTable.
                - A CamiDataTable, if the object was created by get_function_for_os()

        """

        if type(self) != type(other):
            raise Exception("Invalid object type sent to {} copy constructor: {}".format(type(self), type(other)))

        self.__dict__.update(other.__dict__)

    def post_create(self, state):
        """ This is the YAML constructor

        Args:
            state: The YAML file in a dictionary form
        """

        # We are doing this because some functions don't have custom arguments
        if not hasattr(self, "arguments"):
            self.arguments = []

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Invalid comparison between %s and %s" % (type(self), type(other)))

        # this is a rudimentary comparison but it's enough for our needs
        return self.__dict__ == other.__dict__

    def get_function_for_os(self, os):
        """ Create another instance of this object which only contains patterns and arguments suitable for the given OS

        This method will filter the attributes of this function and will create another object which
        will contain only the patterns & arguments which are suitable for the given OS. This method should
        be called for object which are in the intermediate form described above.

        Args:
            os: A SupportedOsWin object

        Returns:
            - Another instance of this object containing only the patterns and arguments needed by the given OS.
            - None, if the functions has no patterns for the given OS or the function is for 64bits OSs and the OS is
            a 32bits one (or vice versa).

        Raises:
            Exception: If there are multiple arguments for this OS. (Maybe we can shall our own exception class ?? )
        """

        if self.guest64 != os.is_64:
            return None

        new_patterns = []
        new_arguments = None

        for pattern in self.patterns:
            if os.build_number >= pattern.min_ver and os.build_number <= pattern.max_ver:
                new_patterns.append(pattern)

        for arguments in self.arguments:
            if os.build_number >= arguments.min_ver and os.build_number <= arguments.max_ver:
                if new_arguments is None:
                    new_arguments = arguments
                else:
                    raise Exception("Found more arguments for function {}, 64: {}".format(self.name, self.guest64))

        if len(new_patterns) == 0:
            return None

        new_patterns = sorted(new_patterns, key=lambda x: x.max_ver - x.min_ver)

        new_function = WinFunction(self)

        if new_arguments is None:
            new_function.arguments = WinFunctionArgument()
        else:
            new_function.arguments = new_arguments

        new_function.patterns = WinFunctionsPatternsTable()
        new_function.patterns.set_entries(new_patterns)

        try:
            idx = self.g_patterns_list.index(new_function.patterns)
            new_function.patterns = self.g_patterns_list[idx]
        except ValueError:
            self.g_patterns_list.append(new_function.patterns)

        return new_function

    def get_descriptor(self):
        """ Generate the CamiDataTable entry for this function

        Returns:
            bytes: the CamiDataTable entry (a _CAMI_WIN_FUNCTION structure)

        Raises:
            FilePointerException: If this method is called before generating the binary form of its
            code (with serialize)
        """
        return struct.pack(
            self.descriptor_layout,
            crc32.crc32(self.name),
            self.patterns.get_entry_count(),
            self.patterns.get_file_pointer(),
            self.arguments.get_count(),
            self.arguments.get_file_pointer(),
            0,
            0,
            0,
        )

    def serialize(self, start):
        """ Generate the body of this function in it's binary form.

        Get the binary form of this function's body by packing it's arguments and patterns.

        Args:
            start: The offset in the file where this function will be placed

        Returns:
            bytes: The body of this function containing the arguments and patterns

        """

        data = self.arguments.serialize(start)
        return data + self.patterns.serialize(start + len(data))


class WinFunctionPattern(CamiYAMLObject, CamiAtom):
    yaml_tag = "!intro_update_win_pattern"
    """
        struct _CAMI_WIN_PATTERN
        {
            CHAR    SectionHint[8];
            DWORD   HashLength;
            DWORD   HashOffset;

            DWORD   _Reserved1;
            DWORD   _Reserved2;
        }
    """
    descriptor_layout = "<8sIIII"

    def post_create(self, state):
        """ The YAML constructor for this object

        Args:
            state: The YAML file in a dictionary form
        """

        if self.min_ver in version_any.keys():
            self.min_ver = version_any[self.min_ver]

        if self.max_ver in version_any.keys():
            self.max_ver = version_any[self.max_ver]

        if self.section_hint is None:
            self.section_hint = ""

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Invalid comparison between %s and %s" % (type(self), type(other)))

        # this is a rudimentary comparison but it's enough for our needs
        return self.__dict__ == other.__dict__

    def get_descriptor(self):
        """ Generate the CamiDataTable entry for this pattern

        Returns:
            bytes: the CamiDataTable entry (a _CAMI_WIN_PATTERN structure)

        Raises:
            FilePointerException: If this method is called before generating the binary form
            of the pattern code. (with serialize)
        """

        return struct.pack(
            self.descriptor_layout,
            bytes(self.section_hint, "utf-8"),
            self.pattern.get_count(),
            self.pattern.get_file_pointer(),
            0,
            0,
        )

    def serialize(self, start):
        """ Genereate the body of this pattern in it's binary form

        Get the binary form of this pattern's body by packing it's code.

        Args:
            start: The offset in the file where this pattern will be placed

        Returns:
            bytes: The body of this pattern (the code)

        """

        return self.pattern.serialize(start)


class WinFunctionArgument(CamiYAMLObject, CamiObject):
    yaml_tag = "!intro_update_win_args"

    def post_create(self, state):

        if self.min_ver in version_any.keys():
            self.min_ver = version_any[self.min_ver]

        if self.max_ver in version_any.keys():
            self.max_ver = version_any[self.max_ver]

    def __init__(self):
        """ Constructor for this object.

        We need this for functions without custom arguments in order to simplify the code

        Attributes:
            min_ver: Minimum build_number required for this list of arguments
            max_ver: Maximum build_number supported by this list of arguments

        """

        self.args = []

    def get_count(self):
        """ Returns the length of the arguments list """

        return len(self.args)

    def get_binary(self):
        """ Pack the arguments in a bytes object

        We are doing this here (not in serialize) in order to simplify the code

        Returns:
            bytes: The arguments in a binary form (can be empty)

        May raise KeyError if there are unknown arguments in the YAML file.
        """

        c_struct = bytes()

        # make sure we don't put more arguments than introcore could use
        assert len(self.args) <= detour_args["DET_ARGS_MAX"]

        for arg in self.args:
            c_struct += struct.pack("<I", detour_args[arg])

        return c_struct

    def serialize(self, start):
        """ Returns the bytes object of the arguments list

        The return value can be an empty bytes() object if this list of arguments is already in the file
        """

        try:
            self.set_file_pointer(start)
        except FilePointerException:
            return bytes()

        return self.get_binary()


class WinSupportedOsTable(CamiDataTable):
    section_hint = section_hints["supported_os"] | section_hints["windows"]
    entry_type = WinSupportedOs

    def process_list(self):
        self._entries.sort(key=lambda os: os.build_number)

class WinOsFunctionsTable(CamiDataTable):
    # no section hint needed
    entry_type = WinFunction


class WinFunctionsPatternsTable(CamiDataTable):
    # no section hint needed
    entry_type = WinFunctionPattern
