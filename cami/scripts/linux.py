#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import yaml
import struct
import os
import crc32
from objects import CamiDataTable, CamiAtom, FilePointerException, CamiYAMLObject
from common import PatternSignature, IntrocoreVersion
from options import get_options_for_os_version
from intro_defines import section_hints, defines


class LixSupportedOS(CamiYAMLObject, CamiAtom):
    yaml_tag = "!intro_update_lix_supported_os"
    descriptor_layout = '<{}sQQIIIIIIII'.format(defines["MAX_VERSION_STRING_SIZE"])

    min_intro_ver = IntrocoreVersion.min_version()
    max_intro_ver = IntrocoreVersion.max_version()

    """
    typedef struct _CAMI_LIX_DESCRIPTOR
    {
        CHAR    VersionString[MAX_VERSION_STRING_SIZE]; // The versions string used to match this OS

        QWORD   MinIntroVersion;                        // Minimum introcore version which supports this OS
        QWORD   MaxIntroVersion;                        // Maximum introcore version which supports this OS

        DWORD   StructuresCount;                        // Opaque structures count
        DWORD   StructuresTable;                        // Opaque structures file pointer. (pointer to a CAMI_OPQUE_STRUCTURE[] array)

        DWORD   HooksCount;                             // Hooked functions count
        DWORD   HooksTable;                             // Hooked functions file pointer. (pointer to a CAMI_LIX_HOOK[] array)

        DWORD   CustomProtectionOffset;                 // Protection flags for this os. (pointer to a CAMI_CUSTOM_PROTECTION struct)

        DWORD   _Reserved1;
        DWORD   _Reserved2;
        DWORD   _Reserved3;
    } CAMI_LIX_DESCRIPTOR, *PCAMI_LIX_DESCRIPTOR;
    """

    def post_create(self, state):
        """ The YAML constructor for this object """

        # convert python list to a LixOsHooksList object
        self.hooks = LixOsHooksList(self.hooks)

    def get_descriptor(self):
        print("Linux OS %s:" % self.version)
        print("\t- Options:", self.intro_options)
        print("\t- Min intro version: ", self.min_intro_ver)
        print("\t- Max intro version: ", self.max_intro_ver)
        print("\t- Hooks count: ", self.hooks.get_entry_count())

        return struct.pack(
            self.descriptor_layout,
            bytes(self.version, "utf-8"),
            self.min_intro_ver.get_raw(),
            self.max_intro_ver.get_raw(),
            self.fields.get_entry_count(),
            self.fields.get_file_pointer(),
            self.hooks.get_entry_count(),
            self.hooks.get_file_pointer(),
            self.intro_options.get_file_pointer(),
            0,
            0,
            0,
        )  # reserved

    def serialize(self, start):
        self.intro_options = get_options_for_os_version(self.version)

        data = self.fields.serialize(start)
        data += self.hooks.serialize(start + len(data))
        data += self.intro_options.serialize(start + len(data))
        return data


class LixFunctionHook(CamiYAMLObject, CamiAtom):
    yaml_tag = u'!intro_update_lix_hook'

    """
	typedef struct _CAMI_LIX_HOOK
	{
		DWORD   NameHash;                               // Function name hash.
		BYTE    HookHandler;                            // The hook handler index from the API_HOOK_DESCRIPTOR
		BYTE    SkipOnBoot;                             // TRUE if this function should not be hooked on boot
		WORD    _Reserved1;
		DWORD   _Reserved2;
	} CAMI_LIX_HOOK, *PCAMI_LIX_HOOK;

    """
    descriptor_layout = '<IBBHI'

    def __eq__(self, other):
        if type(self) != type(other):
            raise Exception("Unsupported comparison between %s and %s" % (type(self), type(other)))

        return self.name == other.name and self.handler == other.handler and self.skip_on_boot == other.skip_on_boot

    def get_descriptor(self):
        return struct.pack(self.descriptor_layout, crc32.crc32(self.name), self.handler, self.skip_on_boot, 0, 0)

    def serialize(self, start):
        return bytes()


class LixDistSigs(PatternSignature):
    # Just a wrapper for PatternSignature to be able to retrieve the signatures from the global list
    yaml_tag = u'!linux_dist_signature'


class LixSupportedOSList(CamiDataTable):
    section_hint = section_hints["supported_os"] | section_hints["linux"]
    entry_type = LixSupportedOS


class LixDistSignaturesList(CamiDataTable):
    section_hint = section_hints["linux"] | section_hints["dist_sigs"]
    entry_type = PatternSignature


class LixOsHooksList(CamiDataTable):
    # no section hint
    entry_type = LixFunctionHook
