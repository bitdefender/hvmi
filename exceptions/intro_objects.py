#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import struct
import re
from abc import ABCMeta, abstractmethod

import excfg
import crc32

# Note: We cannot use os.path here since it's os specific and we must be able to run
# this both on windows & linux

DEFAULT_FLAGS = {
    "SignatureFlags": "32 64",
    "UserExceptionFlags": "32 64",
    "KernelExceptionFlags": "32 64",
    "HeaderMagic": 0x414E5845,  # 'EXNA'
}

IMAGE_BASE_NAME_LEN = 14
LIX_COMM_LEN = 15
SIG_IDS = dict()


def is_path(name):
    """ Returns True if the given name is a path. Does not validate if the path
    is correct except basic invalid characters. """
    if name is None or len(name) < 3:
        return False

    # if ('"' in name) or ('<' in name) or ('>' in name) or \
    #     ('|' in name) or ('*' in name):
    #     return False

    if name.startswith("\\") or name.startswith("/"):
        # \sysroot\etc\a.exe, /home/user/a.out, \??\C:\Program Files\a.exe, etc.
        return True
    if str.isalpha(name[0]) and name[1] == ":" and name[2] == "\\":
        # C:\Program Files, D:\Program Files, etc.
        return True

    return False


def get_name_from_path(path):
    """ Given a path, returns the name of the file (the last part in the path).
    The path must not end with a separator ('\\' on windows, '/' on linux).

    Returns a string containing the name. """

    if not is_path(path):
        return path

    last = path.rfind("\\")
    if last == -1:
        last = path.rfind("/")

    if last == -1:
        raise ValueError("Path %s is not containing any name!" % path)

    if last == len(path) - 1:
        raise ValueError("Path %s ends with separator!" % path)

    return path[last + 1 :]


def unsigned(val):
    return int(val & 0xFFFFFFFF)


def cmp_unsigned(val1, val2):
    """ Compares 'val1' and 'val2' as unsigned numbers. Respects the
    unix 'cmp' function return values (-1, 0, 1). """
    val1 = unsigned(val1)
    val2 = unsigned(val2)

    if val1 > val2:
        return 1

    if val1 < val2:
        return -1

    return 0


def cmp_string(val1, val2):
    """ Compares 'val1' and 'val2' as unsigned numbers. Respects the
    unix 'cmp' function return values (-1, 0, 1). """

    if val1 > val2:
        return 1

    if val1 < val2:
        return -1

    return 0


def get_binary_name(name, cls, wide=True, trim=0):
    """ Returns the binary hash of the given name. This function also checks
    the predefined names in the config file based on the `cls` argument.
    If `wide` is True, then it will convert the name to the wide (utf-16)
    format.
    If trim is != 0, then it will trim the name to `trim` chars. """

    if not name:
        return int(-1)

    if cls is KernelException:
        predefined = excfg.get("Predefined", "kernel-mode")
    elif cls is UserException:
        predefined = excfg.get("Predefined", "user-mode")
    elif cls is KernelUserException:
        predefined = excfg.get("Predefined", "kenrel-user-mode")
    elif cls is Signature:
        predefined = excfg.get("Predefined", "signature")
    else:
        raise ValueError("Invalid class %s" % cls)

    if name in predefined:
        return predefined[name]

    if trim:
        return crc32.crc32(name[:trim], wide=wide)

    return crc32.crc32(name, wide=wide)


def get_binary_flags(flags, cls):
    """ Returns the binary representation of the given flags.

    If the `cls` is a UserException then it will use the values from 'user-mode'
    config flags and the 'common' ones.
    If the `cls` is a KernelException then it will use the values from
    'kernel-mode' config flags and the 'common' ones.
    If the `cls` is a UserException then it will use the values from
    'signatures' config flags. The 'common' ones are ignored. """

    cfg_cflags = excfg.get("Flags", "common")

    if cls is KernelException:
        cfg_flags = excfg.get("Flags", "kernel-mode")
    elif cls is UserException or cls is UserGlobException:
        cfg_flags = excfg.get("Flags", "user-mode")
    elif cls is KernelUserException:
        cfg_flags = excfg.get("Flags", "user-mode")
        cfg_flags.update(excfg.get("Flags", "kernel-mode"))
        cfg_flags.update(excfg.get("Flags", "kernel-user-mode"))
    elif cls is Signature:
        cfg_flags = excfg.get("Flags", "signatures")
        cfg_cflags = []
    else:
        raise ValueError("Invalid class %s" % cls)

    bin_flags = 0
    for flag in flags.split(" "):
        if flag in cfg_flags:
            bin_flags = bin_flags | cfg_flags[flag]
        elif flag in cfg_cflags:
            bin_flags = bin_flags | cfg_cflags[flag]
        else:
            raise ValueError("Invalid flag " + flag)

    return bin_flags


def get_sig_id(sig_id, sig_type, create_new=True):
    """ If we don't have this signature in the hash_map, then add it this way;
    if we request the id of a signature at different times and from different
    functions, we will get either a new one, or the old one. """

    if sig_type == 0 and sig_id not in SIG_IDS:
        raise ValueError("invalid signature type")

    if sig_id not in SIG_IDS:
        if not create_new:
            raise ValueError("Signature %s not present!" % sig_id)

        new_id = len(SIG_IDS) + 1
        new_id += (sig_type << 22)

        SIG_IDS[sig_id] = new_id

    elif create_new:
            raise ValueError("Duplicated signature found", sig_id)

    return SIG_IDS[sig_id]


def get_binary_signatures(signatures):
    """ Returns a sorted list containing the binary id of each signature. For
    more details see `get_sig_id`. """

    if not signatures:
        return []

    return sorted([get_sig_id(sig, 0, False) for sig in signatures])


class IntroObject(metaclass=ABCMeta):
    """ Just an interface containing method for dumping objects in binary
    or textual form. """

    @abstractmethod
    def get_binary_header(self):
        """ Returns the binary header, dependent on the object type. """
        raise NotImplementedError

    @abstractmethod
    def get_binary(self):
        """ Returns the binary contents, dependent on the object type. """
        raise NotImplementedError

    def _cmp(self, other):
        """ Will be replaced below, and each of '__lt__', etc. will call the
        proper '_cmp' method. """
        raise NotImplementedError

    def __lt__(self, other):
        return self._cmp(other) < 0

    def __le__(self, other):
        return self._cmp(other) <= 0

    def __gt__(self, other):
        return self._cmp(other) > 0

    def __ge__(self, other):
        return self._cmp(other) > 0

    def __eq__(self, other):
        return self._cmp(other) == 0

    def __ne__(self, other):
        return self._cmp(other) != 0


class IntroFileHeader(IntroObject):
    """ Represent the header of the exceptions file. This is written only once,
    at the begining. """

    def __init__(self, km_count, um_count, kum_count, umgb_count, sig_count, build):
        self.km_count = km_count
        self.um_count = um_count
        self.kum_count = kum_count
        self.umgb_count = umgb_count
        self.sig_count = sig_count
        self.build = build

    def get_binary(self):
        """ Returns a binary string containing the values from the tuple.

        The format is as follows:
        - HeaderMagic[32]
        - VersionMajor[16]
        - VersionMinor[16]
        - KernelExceptionsCount[32]
        - UserExceptionsCount[32]
        - SignaturesCount[32]
        - BuildNumber[32]
        - UserGlobExceptionCount[32]
        - Reserved1[2 * 32] """

        return struct.pack(
            "<IHHIIIIIII",
            DEFAULT_FLAGS["HeaderMagic"],
            excfg.get("Version", "Major"),
            excfg.get("Version", "Minor"),
            self.km_count,
            self.um_count,
            self.sig_count,
            self.build,
            self.umgb_count,
            self.kum_count,
            0,
        )

    def _cmp(self, other):
        """ Not implemented in this class. """
        return NotImplemented

    def get_binary_header(self):
        """ Not implemented in this class. """
        return NotImplemented


class KernelException(IntroObject):
    """ Represents a kernel-mode exception. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values.

        Raises ValueError if anything is not valid. """

        if not self.originator and self.object_type not in ("token-privs", "security-descriptor", "acl-edit", "sud-modification"):
            raise ValueError("originator cannot be missing!")

        if not self.object_type:
            raise ValueError("object type cannot be missing!")

        if not self.victim and self.object_type in (
            "driver",
            "driver imports",
            "driver code",
            "driver data",
            "driver resources",
            "drvobj",
            "fastio",
            "driver exports",
            "token-privs",
            "security-descriptor",
            "acl-edit",
            "sud-modification"
        ):
            raise ValueError("Type %s requires a victim name!" % self.object_type)

        if self.victim and self.object_type in ("msr", "ssdt", "cr4", "idt", "idt-reg", "gdt-reg", "infinity-hook", "hal-perf-counter", "interrupt-obj"):
            raise ValueError("Type %s must miss victim name!" % self.object_type)

        if self.flags is None:
            # if no flags are given, then use the default ones
            self.flags = DEFAULT_FLAGS["KernelExceptionFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

        flagsl = self.flags.split(" ")

        if self.object_type == "cr4":
            if ("smep" not in flagsl) and ("smap" not in flagsl):
                raise ValueError("Type cr4 must flags must contain smap/smep!")

        if not any(word in flagsl for word in ("read", "write", "exec")):
            self.flags += " write"

        if ("non-driver" in flagsl) and ("return-drv" not in flagsl):
            # non-driver implies return-drv
            self.flags += " return-drv"

        if "return-drv" in flagsl:
            raise ValueError('"return-drv" is now obsolete. Please use "return"!')

        # We moved return to the common area, so add return-drv if needed (for now)
        if "return" in flagsl:
            self.flags += " return-drv"

        if "integrity" in flagsl and self.object_type in ("token-privs", "sud-modification"):
            if self.originator:
                raise ValueError("Type %s with integrity flag must not have originator!" % self.object_type)
            self.originator = "-"
            self.originator_name = "-"
        elif self.object_type in ("token-privs",) and not self.originator:
            raise ValueError("Originator cannot be missing for %s without integrity flag!" % self.object_type)

        if self.object_type in ("security-descriptor", "acl-edit"):
            if "integrity" in flagsl:
                if self.originator:
                    raise ValueError("Type %s with integrity flag must not have originator!" % self.object_type)
                self.originator = "-"
                self.originator_name = "-"
            else: 
                raise ValueError("%s only works with integrity flag for now!" % self.object_type)

        # sanitize the input
        if "linux" in self.flags:
            self.victim = self.victim if self.victim else "*"
        else:
            self.originator = self.originator.lower()
            self.originator_name = self.originator_name.lower()
            
            # for sud fields we need case sensitive hashes
            if self.object_type in ("sud-modification",):
                self.victim = self.victim if self.victim else "*"
            else:
                self.victim = self.victim.lower() if self.victim else "*"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields.

        'originator' field will be separeted into path + name. If only a name
        is given then path will be equal with the name. """

        self.binary["object"] = excfg.get("Types", "kernel-mode")[self.object_type]

        if self.originator != self.originator_name:
            bin_name = get_binary_name(self.originator_name, KernelException)
        else:
            bin_name = get_binary_name(self.originator_name, KernelException)

        self.binary["name"] = bin_name
        self.binary["path"] = -1

        if self.object_type in ("sud-modification"):
            self.binary["victim"] = get_binary_name(self.victim, KernelException, wide=False)
        elif self.object_type in ("token-privs", "security-descriptor", "acl-edit"):
            self.binary["victim"] = get_binary_name(self.victim, KernelException, wide=False, trim=IMAGE_BASE_NAME_LEN)
        else:
            self.binary["victim"] = get_binary_name(self.victim, KernelException)

        self.binary["flags"] = get_binary_flags(self.flags, KernelException)
        self.binary["signatures"] = get_binary_signatures(self.signatures)

    def __init__(self, originator=None, object_type=None, victim=None, flags=None, signatures=None, **kwargs):
        self.originator = originator
        self.originator_name = get_name_from_path(self.originator)
        self.object_type = object_type
        self.victim = victim
        self.flags = flags
        self.signatures = signatures
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Compares two KernelExceptions. The fields are compared in order:
        - originator path, originator name, object, victim, flags
        - signatures is ignored! """

        value = cmp_unsigned(self.binary["path"], other.binary["path"])
        if value:
            return value

        value = cmp_unsigned(self.binary["name"], other.binary["name"])
        if value:
            return value

        value = cmp_unsigned(self.binary["object"], other.binary["object"])
        if value:
            return value

        value = cmp_unsigned(self.binary["victim"], other.binary["victim"])
        if value:
            return value

        value = cmp_unsigned(self.binary["flags"], other.binary["flags"])
        if value:
            return value

        return 0

    def __str__(self):
        ret_str = "'%s' (%08x), '%s' (%08x), '%s' (%08x), '%s' (%02d), '%s' (%08x)" % (
            self.originator,
            self.binary["path"],
            self.originator_name,
            self.binary["name"],
            self.victim,
            self.binary["victim"],
            self.object_type,
            self.binary["object"],
            self.flags,
            self.binary["flags"],
        )

        if self.signatures:
            ret_str += ", %r (%r)" % (self.signatures, self.binary["signatures"])

        return ret_str

    def get_binary_header(self):
        """ Returns a binary string representing the header of the user-mode
        exception.

        The format it's as follows:
        - type[8] = 1
        - size[16] = 20 + len(sigs) * 4 """

        sigs = len(self.signatures) if self.signatures else 0

        return struct.pack("<BH", 1, 20 + (sigs * 4))

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        kernel-mode exception.

        The format it's as follows:
        - name[32]
        - path[32]
        - victim[32],
        - flags[32]
        - reserved[8]
        - type[8]
        - sig_count[16]
        - sigs-array[32 * sig_count]

        name, path  - a CRC32 will be applied to them
        victim      - same as name and path
        object_type - the corresponding value in the hash map
        flags       - an OR with the values from the hash map
        signatures  - the strings will be converted into unique numeric ids """

        packed_sigs = bytes()
        for sig in self.binary["signatures"]:
            packed_sigs += struct.pack("<I", int(sig & 0xFFFFFFFF))

        # The '& 0xffffffff' is a quick hack to force unsigned numbers
        return (
            struct.pack(
                "<IIIIBBH",
                unsigned(self.binary["name"]),
                unsigned(self.binary["path"]),
                unsigned(self.binary["victim"]),
                unsigned(self.binary["flags"]),
                0,  # The reserved byte
                unsigned(self.binary["object"]),
                unsigned(len(self.binary["signatures"])),
            )
            + packed_sigs
        )


class UserException(IntroObject):
    """ Represents a user-mode exception. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values.

        Raises ValueError if anything is not valid. """

        if not self.originator:
            raise ValueError("Originator cannot be missing!")

        if not self.object_type:
            raise ValueError("Object type cannot be missing!")

        if not self.victim and self.object_type in ("process", "module", "module imports"):
            raise ValueError("Type %s requires a victim name!" % self.object_type)

        if self.victim and self.victim != "*" and self.object_type == "nx_zone":
            raise ValueError("Type %s must miss victim name!" % self.object_type)

        if not self.process and self.object_type in ("module", "module imports"):
            raise ValueError("Process cannot be missing for %s!" % self.object_type)

        if self.process and self.object_type == "process":
            raise ValueError("Process must be missing for %s!" % self.object_type)

        if self.flags is None:
            self.flags = DEFAULT_FLAGS["UserExceptionFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

        flagsl = self.flags.split(" ")

        if not any(word in flagsl for word in ['read', 'write', 'exec']):
            if self.object_type == 'nx_zone' or self.object_type == 'process-creation' or self.object_type == 'process-creation-dpi':
                self.flags += ' exec'
            else:
                self.flags += " write"

        flagsl = self.flags.split(" ")

        # a small sanity check
        if self.object_type == "nx_zone" and "exec" not in flagsl:
            raise ValueError("nx_zone must have exec flag set: %s" % self.flags)

        # sanitize the input
        if "linux" in self.flags:
            self.victim = self.victim if self.victim else "*"
            self.process = self.process if self.process else None
        else:
            self.originator = self.originator.lower()
            self.victim = self.victim.lower() if self.victim else "*"
            self.process = self.process.lower() if self.process else None

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["object"] = excfg.get("Types", "user-mode")[self.object_type]

        if self.object_type in (
            'process', 'thread-context', 'peb32', 'peb64', 'apc-thread', 'process-creation', 'process-creation-dpi', 'instrumentation-callback') and 'module-load' not in self.flags:
            if "linux" in self.flags:
                self.binary['originator'] = get_binary_name(self.originator, UserException,
                                                        wide=False, trim=LIX_COMM_LEN)
            else:
                self.binary['originator'] = get_binary_name(self.originator, UserException,
                                                        wide=False, trim=IMAGE_BASE_NAME_LEN)
        else:
            self.binary["originator"] = get_binary_name(self.originator, UserException)

        if self.object_type in ('process', 'thread-context', 'peb32', 'peb64', 'apc-thread', 'process-creation', 'double-agent', 'process-creation-dpi', 'instrumentation-callback'):
            if "linux" in self.flags:
                self.binary['victim'] = get_binary_name(self.victim, UserException,
                                                    wide=False, trim=LIX_COMM_LEN)
            else:
                self.binary['victim'] = get_binary_name(self.victim, UserException,
                                                    wide=False, trim=IMAGE_BASE_NAME_LEN)
        else:
            self.binary["victim"] = get_binary_name(self.victim, UserException)

        if self.process:
            self.binary["process"] = get_binary_name(
                self.process, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN
            )
        else:
            self.binary["process"] = 0

        self.binary["flags"] = get_binary_flags(self.flags, UserException)
        self.binary["signatures"] = get_binary_signatures(self.signatures)

    def _fix_name(self, name):
        if not name:
            return name

        if name[0] == "*" and "\\x" in name:
            new_name = b""
            i = 0
            while i < len(name):
                # Let it crash in case i + 4 > len(name)... it's invalid after all
                if name[i] == "\\" and name[i + 1] == "x":
                    new_name += bytes([int(name[i + 2 : i + 4], 16)])

                    i += 4
                    continue
                else:
                    new_name += name[i].encode()

                i += 1

            return new_name

        return name

    def _fix_json_names(self):
        self.originator = self._fix_name(self.originator)
        self.victim = self._fix_name(self.victim)
        self.process = self._fix_name(self.process)

    def __init__(
        self,
        originator,
        object_type,
        victim=None,
        process=None,
        flags=None,
        signatures=None,
        **kwargs
    ):
        self.originator = originator
        self.object_type = object_type
        self.victim = victim
        self.process = process
        self.flags = flags
        self.signatures = signatures
        self.binary = {}

        self._validate_args()

        self._fix_json_names()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Compares two UserExceptions by the binary value of the fields.
        The fields are compared in the following order:
        - originator, object, victim, process, flags.
        - signatures is ignored! """

        value = cmp_unsigned(self.binary["originator"], other.binary["originator"])
        if value:
            return value

        value = cmp_unsigned(self.binary["object"], other.binary["object"])
        if value:
            return value

        value = cmp_unsigned(self.binary["victim"], other.binary["victim"])
        if value:
            return value

        value = cmp_unsigned(self.binary["process"], other.binary["process"])
        if value:
            return value

        value = cmp_unsigned(self.binary["flags"], other.binary["flags"])
        if value:
            return value

        return 0

    def __str__(self):
        ret_str = "'%s' (%08x), '%s' (%08x), '%s' (%08x), '%s' (%02d), '%s' (%08x)" % (
            self.originator,
            self.binary["originator"],
            self.victim,
            self.binary["victim"],
            self.process,
            self.binary["process"],
            self.object_type,
            self.binary["object"],
            self.flags,
            self.binary["flags"],
        )

        if self.signatures:
            ret_str += ", %r (%r)" % (self.signatures, self.binary["signatures"])

        return ret_str

    def get_binary_header(self):
        """ Returns a binary string representing the header of the user-mode
        exception.

        The format it's as follows:
        - type[8] = 2
        - size[16] = 20 + len(sigs) * 4 """

        sigs = len(self.signatures) if self.signatures else 0

        return struct.pack("<BH", 2, 20 + (sigs * 4))

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        user-mode exception.

        The format it's as follows:
        - originator[32]
        - victim[32]
        - process[32],
        - flags[32]
        - reserved[8]
        - type[8]
        - sig_count[8]
        - sigs-array[32 * sig_count]

        process     - truncated to 15 chars (including NULL terminator)
        victim    - if object_type is 'process' then it will be truncated same as 'process'
        originator, - same as victim
        object_type - the corresponding value in the hash map
        flags       - an OR with the values from the hash map
        signatures  - the strings will be converted into unique numeric ids """

        packed_sigs = bytes()
        for sig in self.binary["signatures"]:
            packed_sigs += struct.pack("<I", unsigned(sig))

        if "ignore" in self.flags:
            print(self)

        # The '& 0xffffffff' is a quick hack to force unsigned numbers
        return (
            struct.pack(
                "<IIIIBBH",
                unsigned(self.binary["originator"]),
                unsigned(self.binary["victim"]),
                unsigned(self.binary["process"]),
                unsigned(self.binary["flags"]),
                0,  # The reserved byte
                unsigned(self.binary["object"]),
                unsigned(len(self.binary["signatures"])),
            )
            + packed_sigs
        )


class UserApcException(IntroObject):
    """ Represents a user-mode exception. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values.

        Raises ValueError if anything is not valid. """

        if not self.originator:
            raise ValueError("Originator cannot be missing!")

        if not self.object_type:
            raise ValueError("Object type cannot be missing!")

        if not self.victim and self.object_type in ("process", "module", "module imports"):
            raise ValueError("Type %s requires a victim name!" % self.object_type)

        if self.victim and self.object_type == "nx_zone":
            raise ValueError("Type %s must miss victim name!" % self.object_type)

        if not self.process and self.object_type in ("module", "module imports"):
            raise ValueError("Process cannot be missing for %s!" % self.object_type)

        if self.process and self.object_type == "process":
            raise ValueError("Process must be missing for %s!" % self.object_type)

        if self.flags is None:
            self.flags = DEFAULT_FLAGS["UserExceptionFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

        flagsl = self.flags.split(" ")

        if not any(word in flagsl for word in ["read", "write", "exec"]):
            if self.object_type == "nx_zone":
                self.flags += " exec"
            else:
                self.flags += " write"

        flagsl = self.flags.split(" ")

        # a small sanity check
        if self.object_type == "nx_zone" and "exec" not in flagsl:
            raise ValueError("nx_zone must have exec flag set: %s" % self.flags)

        # sanitize the input
        if "linux" in self.flags:
            self.victim = self.victim if self.victim else "*"
            self.process = self.process if self.process else None
        else:
            self.originator = self.originator.lower()
            self.victim = self.victim.lower() if self.victim else "*"
            self.process = self.process.lower() if self.process else None

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["object"] = excfg.get("Types", "user-mode")[self.object_type]

        if (
            self.object_type in ("process", "thread-context", "peb32", "peb64", "apc-thread", "double-agent", "instrumentation-callback")
            and "module-load" not in self.flags
        ):
            self.binary["originator"] = get_binary_name(
                self.originator, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN
            )
        else:
            self.binary["originator"] = get_binary_name(self.originator, UserException)

        if self.object_type in ("process", "thread-context", "peb32", "peb64", "apc-thread", "double-agent", "instrumentation-callback"):
            self.binary["victim"] = get_binary_name(
                self.victim, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN
            )
        else:
            self.binary["victim"] = get_binary_name(self.victim, UserException)

        if self.process:
            self.binary["process"] = get_binary_name(
                self.process, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN
            )
        else:
            self.binary["process"] = 0

        self.binary["flags"] = get_binary_flags(self.flags, UserException)
        self.binary["signatures"] = get_binary_signatures(self.signatures)

    def __init__(
        self,
        originator,
        object_type,
        victim=None,
        process=None,
        flags=None,
        signatures=None,
        **kwargs
    ):
        self.originator = originator
        self.object_type = object_type
        self.victim = victim
        self.process = process
        self.flags = flags
        self.signatures = signatures
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Compares two UserExceptions by the binary value of the fields.
        The fields are compared in the following order:
        - originator, object, victim, process, flags.
        - signatures is ignored! """

        value = cmp_unsigned(self.binary["originator"], other.binary["originator"])
        if value:
            return value

        value = cmp_unsigned(self.binary["object"], other.binary["object"])
        if value:
            return value

        value = cmp_unsigned(self.binary["victim"], other.binary["victim"])
        if value:
            return value

        value = cmp_unsigned(self.binary["process"], other.binary["process"])
        if value:
            return value

        value = cmp_unsigned(self.binary["flags"], other.binary["flags"])
        if value:
            return value

        return 0

    def __str__(self):
        ret_str = "'%s' (%08x), '%s' (%08x), '%s' (%08x), '%s' (%02d), '%s' (%08x)" % (
            self.originator,
            self.binary["originator"],
            self.victim,
            self.binary["victim"],
            self.process,
            self.binary["process"],
            self.object_type,
            self.binary["object"],
            self.flags,
            self.binary["flags"],
        )

        if self.signatures:
            ret_str += ", %r (%r)" % (self.signatures, self.binary["signatures"])

        return ret_str

    def get_binary_header(self):
        """ Returns a binary string representing the header of the user-mode
        exception.

        The format it's as follows:
        - type[8] = 9
        - size[16] = 20 + len(sigs) * 4 """

        sigs = len(self.signatures) if self.signatures else 0

        return struct.pack("<BH", 9, 20 + (sigs * 4))

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        user-mode exception.

        The format it's as follows:
        - originator[32]
        - victim[32]
        - process[32],
        - flags[32]
        - reserved[8]
        - type[8]
        - sig_count[8]
        - sigs-array[32 * sig_count]

        process     - truncated to 15 chars (including NULL terminator)
        victim    - if object_type is 'process' then it will be truncated same as 'process'
        originator, - same as victim
        object_type - the corresponding value in the hash map
        flags       - an OR with the values from the hash map
        signatures  - the strings will be converted into unique numeric ids """

        packed_sigs = bytes()
        for sig in self.binary["signatures"]:
            packed_sigs += struct.pack("<I", unsigned(sig))

        if "ignore" in self.flags:
            print(self)

        # The '& 0xffffffff' is a quick hack to force unsigned numbers
        return (
            struct.pack(
                "<IIIIBBH",
                unsigned(self.binary["originator"]),
                unsigned(self.binary["victim"]),
                unsigned(self.binary["process"]),
                unsigned(self.binary["flags"]),
                0,  # The reserved byte
                unsigned(self.binary["object"]),
                unsigned(len(self.binary["signatures"])),
            )
            + packed_sigs
        )


class UserGlobException(IntroObject):
    """ Represents a user-mode exception (glob match). For more details about it's
    implementation see `get_binary`. """

    def _validate_glob(self, pattern):
        pattern_chars = re.sub(r"\[[^]]+\]|\?", "", pattern)
        items = re.findall(r"\[[^]]+\]|\?", pattern)
        if len(pattern_chars) + len(items) > IMAGE_BASE_NAME_LEN:
            raise ValueError("Pattern too long: %s" % pattern)

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values.

        Raises ValueError if anything is not valid. """

        glob_items = ["*", "[", "]", "?", "\\\\"]

        if not self.originator:
            raise ValueError("Originator cannot be missing!")

        if not self.object_type:
            raise ValueError("Object type cannot be missing!")

        if not self.victim and self.object_type in ("process", "module", "module imports"):
            raise ValueError("Type %s requires a victim name!" % self.object_type)

        if self.victim and self.object_type == "nx_zone":
            raise ValueError("Type %s must miss victim name!" % self.object_type)

        if not self.process and self.object_type in ("module", "module imports"):
            raise ValueError("Process cannot be missing for %s!" % self.object_type)

        if self.process and self.object_type == "process":
            raise ValueError("Process must be missing for %s!" % self.object_type)

        self.process = self.process if self.process else ""

        if not any(item in self.originator + self.victim + self.process for item in glob_items):
            raise ValueError(
                "At least one field (process, originator, victim) must contain glob items(*, ?, [, ] )."
            )

        if self.process:
            self._validate_glob(self.process)
        if self.victim:
            self._validate_glob(self.victim)
        if self.originator:
            self._validate_glob(self.originator)

        if self.flags is None:
            self.flags = DEFAULT_FLAGS["UserExceptionFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

        flagsl = self.flags.split(" ")

        if not any(word in flagsl for word in ["read", "write", "exec"]):
            if self.object_type == "nx_zone" or self.object_type == 'process-creation' or self.object_type == 'process-creation-dpi':
                self.flags += " exec"
            else:
                self.flags += " write"

        flagsl = self.flags.split(" ")

        # a small sanity check
        if self.object_type == "nx_zone" and "exec" not in flagsl:
            raise ValueError("nx_zone must have exec flag set: %s" % self.flags)

        self.victim = self.victim if self.victim else "*"
        self.process = self.process if self.process != "" else "*"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["object"] = excfg.get("Types", "user-mode")[self.object_type]

        if self.object_type in ("process", "thread-context") and "module-load" not in self.flags:
            self.binary["originator"] = self.originator
        else:
            self.binary["originator"] = self.originator

        if self.object_type in ("process", "thread-context"):
            self.binary["victim"] = self.victim
        else:
            self.binary["victim"] = self.victim

        if self.process:
            self.binary["process"] = self.process
        else:
            self.binary["process"] = "*"

        self.binary["flags"] = get_binary_flags(self.flags, UserGlobException)
        self.binary["signatures"] = get_binary_signatures(self.signatures)

    def __init__(
        self,
        originator,
        object_type,
        victim=None,
        process=None,
        flags=None,
        signatures=None,
        **kwargs
    ):
        self.originator = originator
        self.object_type = object_type
        self.victim = victim
        self.process = process
        self.flags = flags
        self.signatures = signatures
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Compares two UserGlobException by the binary value of the fields.
        The fields are compared in the following order:
        - originator, object, victim, process, flags.
        - signatures is ignored! """

        value = cmp_string(self.binary["originator"], other.binary["originator"])
        if value:
            return value

        value = cmp_string(self.binary["object"], other.binary["object"])
        if value:
            return value

        value = cmp_string(self.binary["victim"], other.binary["victim"])
        if value:
            return value

        value = cmp_string(self.binary["process"], other.binary["process"])
        if value:
            return value

        value = cmp_unsigned(self.binary["flags"], other.binary["flags"])
        if value:
            return value

        return 0

    def __str__(self):
        ret_str = "'%s' (%s), '%s' (%s), '%s' (%s), '%s' (%02d), '%s' (%08x)" % (
            self.originator,
            self.binary["originator"],
            self.victim,
            self.binary["victim"],
            self.process,
            self.binary["process"],
            self.object_type,
            self.binary["object"],
            self.flags,
            self.binary["flags"],
        )

        if self.signatures:
            ret_str += ", %r (%r)" % (self.signatures, self.binary["signatures"])

        return ret_str

    def get_binary_header(self):
        """ Returns a binary string representing the header of the user-mode (glob match)
        exception.

        The format it's as follows:
        - type[8] = 6
        - size[16] = 8 + len(originator) + len(victim) + len(process) len(sigs) * 4 """

        sigs = len(self.signatures) if self.signatures else 0

        len_victim = len(self.victim) + 1 if self.victim else 0
        len_originator = len(self.originator) + 1 if self.originator else 0
        len_process = len(self.process) + 1 if self.process else 0

        size = 8 + len_originator + len_victim + len_process

        return struct.pack("<BH", 6, size + (sigs * 4))

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        user-mode exception (glob match).

        The format it's as follows:
        - flags[32]
        - reserved[8]
        - type[8]
        - sig_count[8]
        - originator[32]
        - victim[32]
        - process[32],
        - sigs-array[32 * sig_count]

        process     - regex
        victim      - regex
        originator  - regex
        object_type - the corresponding value in the hash map
        flags       - an OR with the values from the hash map
        signatures  - the strings will be converted into unique numeric ids """

        packed_sigs = bytes()
        for sig in self.binary["signatures"]:
            packed_sigs += struct.pack("<I", unsigned(sig))

        if "ignore" in self.flags:
            print(self)

        # The '& 0xffffffff' is a quick hack to force unsigned numbers
        return (
            struct.pack(
                "<IBBH%ds%ds%ds"
                % (
                    len(self.binary["originator"]) + 1,  # add NULL-terminator
                    len(self.binary["victim"]) + 1,  # add NULL-terminator
                    len(self.binary["process"]) + 1,
                ),  # add NULL-terminator
                unsigned(self.binary["flags"]),
                0,  # The reserved byte
                unsigned(self.binary["object"]),
                unsigned(len(self.binary["signatures"])),
                bytes(self.binary["originator"], "utf-8"),
                bytes(self.binary["victim"], "utf-8"),
                bytes(self.binary["process"], "utf-8"),
            )
            + packed_sigs
        )


class KernelUserException(IntroObject):
    """ Represents a kernel-user exception. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values.

        Raises ValueError if anything is not valid. """

        if not self.originator:
            raise ValueError("Originator cannot be missing!")

        if not self.object_type:
            raise ValueError("Object type cannot be missing!")

        if not self.victim:
            raise ValueError("Victim cannot be missing!" % self.object_type)

        if self.flags is None:
            # if no flags are given, then use the default ones
            self.flags = DEFAULT_FLAGS["KernelExceptionFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

        flagsl = self.flags.split(" ")

        if not any(word in flagsl for word in ("read", "write", "exec")):
            self.flags += " write"

        if ("non-driver" in flagsl) and ("return-drv" not in flagsl):
            # non-driver implies return-drv
            self.flags += " return-drv"

        if "return" in flagsl:
            self.flags += " return-drv"

        if "user" in flagsl and "kernel" in flagsl:
            raise ValueError("Both user and kernel injection flags were given!")

        if "linux" in self.flags:
            self.victim = self.victim if self.victim else "*"
            self.originator = self.originator if self.originator else "*"
            self.process = self.process if self.process else "*"
        else:
            self.originator = self.originator.lower()
            self.victim = self.victim.lower() if self.victim else "*"
            self.process = self.process.lower() if self.process else "*"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields.

        'originator' field will be separeted into path + name. If only a name
        is given then path will be equal with the name. """

        self.binary["object"] = excfg.get("Types", "kernel-user-mode")[self.object_type]

        if "user" in self.flags:
            self.binary["originator"] = get_binary_name(self.originator, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN)
        else:
            self.binary["originator"] = get_binary_name(self.originator, KernelException)

        self.binary["victim"] = get_binary_name(self.victim, UserException)

        self.binary["flags"] = get_binary_flags(self.flags, KernelUserException)
        self.binary["signatures"] = get_binary_signatures(self.signatures)
        self.binary["process"] = get_binary_name(self.process, UserException, wide=False, trim=IMAGE_BASE_NAME_LEN)

    def __init__(self, process=None, originator=None, object_type=None, victim=None, flags=None, signatures=None, **kwargs):
        self.originator = originator
        self.object_type = object_type
        self.process = process
        self.victim = victim
        self.flags = flags
        self.signatures = signatures
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Compares two KernelExceptions. The fields are compared in order:
        - originator path, originator name, object, victim, flags
        - signatures is ignored! """

        value = cmp_unsigned(self.binary["originator"], other.binary["originator"])
        if value:
            return value

        value = cmp_unsigned(self.binary["process"], other.binary["process"])
        if value:
            return value

        value = cmp_unsigned(self.binary["object"], other.binary["object"])
        if value:
            return value

        value = cmp_unsigned(self.binary["victim"], other.binary["victim"])
        if value:
            return value

        value = cmp_unsigned(self.binary["flags"], other.binary["flags"])
        if value:
            return value

        return 0

    def __str__(self):
        ret_str = "'%s' (%08x), '%s' (%08x), '%s' (%08x), '%s' (%02d), '%s' (%08x)" % (
            self.process,
            self.binary["process"],
            self.originator,
            self.binary["originator"],
            self.victim,
            self.binary["victim"],
            self.object_type,
            self.binary["object"],
            self.flags,
            self.binary["flags"],
        )

        if self.signatures:
            ret_str += ", %r (%r)" % (self.signatures, self.binary["signatures"])

        return ret_str

    def get_binary_header(self):
        """ Returns a binary string representing the header of the user-mode
        exception.

        The format it's as follows:
        - type[8] = 1
        - size[16] = 20 + len(sigs) * 4 """

        sigs = len(self.signatures) if self.signatures else 0

        return struct.pack("<BH", 14, 20 + (sigs * 4))

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        kernel-mode exception.

        The format it's as follows:
        - name[32]
        - path[32]
        - victim[32],
        - flags[32]
        - reserved[8]
        - type[8]
        - sig_count[16]
        - sigs-array[32 * sig_count]

        name, path  - a CRC32 will be applied to them
        victim      - same as name and path
        object_type - the corresponding value in the hash map
        flags       - an OR with the values from the hash map
        signatures  - the strings will be converted into unique numeric ids """

        packed_sigs = bytes()
        for sig in self.binary["signatures"]:
            packed_sigs += struct.pack("<I", int(sig & 0xFFFFFFFF))

        # The '& 0xffffffff' is a quick hack to force unsigned numbers
        return (
            struct.pack(
                "<IIIIBBH",
                unsigned(self.binary["originator"]),
                unsigned(self.binary["victim"]),
                unsigned(self.binary["process"]),
                unsigned(self.binary["flags"]),
                0,  # The reserved byte
                unsigned(self.binary["object"]),
                unsigned(len(self.binary["signatures"])),
            )
            + packed_sigs
        )




class Signature(IntroObject):
    """ Represents an exception signature. For more details about it's implementation see it's
    subclasses. """

    def _cmp(self, other):
        pass

    def get_binary_header(self):
        pass

    def get_binary(self):
        pass


class ExportSignature(Signature):
    """ Represents an export signature. For more details about it's implementation see
    `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError("id is required!")

        if not self.hashes:
            raise ValueError("hashes is required!")

        if not self.library:
            raise ValueError("library is required!")

        if not self.flags:
            self.flags = DEFAULT_FLAGS["SignatureFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "export"))

        self.binary["flags"] = get_binary_flags(self.flags, Signature)

        self.binary["library"] = get_binary_name(self.library, UserException, wide=True)

        self.binary["hashes"] = []

        for hl in self.hashes:
            int_hash_list = []
            int_hash_list.append(
                {
                    "name": get_binary_name(hl["name"], Signature, wide=False),
                    "delta": int(hl["delta"]),
                }
            )

            self.binary["hashes"].append(int_hash_list)

    def __init__(self, sig_id, hashes, library, flags=None, **kwargs):
        self.sig_id = sig_id
        self.library = library
        self.hashes = hashes
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary["id"], other.binary["id"])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), '%s' (%08x), %r" % (
            self.sig_id,
            self.binary["id"],
            self.library,
            self.binary["library"],
            self.flags,
            self.binary["flags"],
            self.binary["hashes"],
        )

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 3
        - size[16] = 12/10 + len(hashes) + hash_size * total_size_of_hashes """

        struct_size = 16

        hashes_size = len(self.hashes) * 8

        return struct.pack("<BH", 4, struct_size + hashes_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - score[8]
        - hash_list_count[8]
        - hash-list-array[32 * hash_count] """

        packed_hashes = bytes()
        for hash_list in self.binary["hashes"]:
            for helem in hash_list:
                packed_hashes += struct.pack("<HHI", helem["delta"], 0, unsigned(helem["name"]))

        return (
            struct.pack(
                "<IIIBBBB",
                unsigned(self.binary["id"]),
                unsigned(self.binary["flags"]),
                unsigned(self.binary["library"]),
                unsigned(len(self.binary["hashes"])),
                0,
                0,
                0,
            )
            + packed_hashes
        )


class ValueSignature(Signature):
    """ Represents a value signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError("id is required!")

        if self.score == 0:
            raise ValueError("score is required!")

        if not self.hashes:
            raise ValueError("hashes is required!")

        if not self.flags:
            self.flags = DEFAULT_FLAGS["SignatureFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "value"))

        self.binary["flags"] = get_binary_flags(self.flags, Signature)

        self.binary["hashes"] = []

        for hlist in self.hashes:
            int_hash_list = []

            inj_hash = hlist
            inj_hash["hash"] = int(hlist["hash"], 16)

            int_hash_list.append(inj_hash)

            self.binary["hashes"].append(int_hash_list)

    def __init__(self, sig_id, hashes, score=0, flags=None, **kwargs):
        self.sig_id = sig_id
        self.score = score
        self.hashes = hashes
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary["id"], other.binary["id"])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), %02d, %r" % (
            self.sig_id,
            self.binary["id"],
            self.flags,
            self.binary["flags"],
            self.score,
            self.binary["hashes"],
        )

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 3
        - size[16] = 12/10 + len(hashes) + hash_size * total_size_of_hashes """

        struct_size = 12

        hashes_size = len(self.hashes) * 12

        return struct.pack("<BH", 5, struct_size + hashes_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - score[8]
        - hash_list_count[8]
        - hash-list-array[32 * hash_count] """

        packed_hashes = bytes()
        for hash_list in self.binary["hashes"]:
            for he in hash_list:
                packed_hashes += struct.pack("<HHII", he["offset"], he["size"], 0, he["hash"])

        return (
            struct.pack(
                "<IIBBBB",
                unsigned(self.binary["id"]),
                unsigned(self.binary["flags"]),
                unsigned(self.score),
                unsigned(len(self.binary["hashes"])),
                0,
                0,
            )
            + packed_hashes
        )


class CbSignature(Signature):
    """ Represents a codeblocks signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError("id is required!")

        if self.score == 0:
            raise ValueError("score is required!")

        if not self.hashes:
            raise ValueError("hashes is required!")

        if not self.flags:
            self.flags = DEFAULT_FLAGS["SignatureFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "codeblocks"))

        self.binary["flags"] = get_binary_flags(self.flags, Signature)

        self.binary["hashes"] = []

        for hl in self.hashes:
            int_hash_list = []

            for he in hl:
                int_hash_list.append(int(he, 16))

            int_hash_list.sort()

            self.binary["hashes"].append(int_hash_list)

    def __init__(self, sig_id, hashes, score=0, flags=None, **kwargs):
        self.sig_id = sig_id
        self.score = score
        self.hashes = hashes
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary["id"], other.binary["id"])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), %02d, %r" % (
            self.sig_id,
            self.binary["id"],
            self.flags,
            self.binary["flags"],
            self.score,
            self.binary["hashes"],
        )

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 3
        - size[16] = 12/10 + len(hashes) + hash_size * total_size_of_hashes """

        struct_size = 10

        hashes_size = 0

        for hash_list in self.hashes:
            hashes_size += len(hash_list) * 4
        hashes_size += len(self.hashes)

        return struct.pack("<BH", 3, struct_size + hashes_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - score[8]
        - hash_list_count[8]
        - hash-list-array[32 * hash_count] """

        packed_hashes = bytes()
        for hash_list in self.binary["hashes"]:
            packed_hashes += struct.pack("B", len(hash_list))
            for helem in hash_list:
                packed_hashes += struct.pack("<I", helem)

        return (
            struct.pack(
                "<IIBB",
                unsigned(self.binary["id"]),
                unsigned(self.binary["flags"]),
                unsigned(self.score),
                unsigned(len(self.binary["hashes"])),
            )
            + packed_hashes
        )


class ValueCodeSignature(Signature):
    """ Represents a value code extended(pattern) signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError("id is required!")

        if not self.offset:
            self.offset = 0

        if self.offset > 32767:
            raise ValueError("required offset >= 32767 (MAX_INT16)")

        if self.offset < -32768:
            raise ValueError("required offset <= -32768 (MIN_INT16)")

        if not self.pattern:
            raise ValueError("pattern is required!")

        if not self.flags:
            self.flags = DEFAULT_FLAGS["SignatureFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "value-code"))

        self.binary["flags"] = get_binary_flags(self.flags, Signature)

        self.binary["pattern"] = list()

        for pattern_elem in self.pattern:
            self.binary["pattern"].append(int(pattern_elem, 16))

    def __init__(self, sig_id, pattern, offset, flags=None, **kwargs):
        self.sig_id = sig_id
        self.offset = offset
        self.pattern = pattern
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary["id"], other.binary["id"])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), %02d, %r" % (
            self.sig_id,
            self.binary["id"],
            self.flags,
            self.binary["flags"],
            self.offset,
            self.binary["pattern"],
        )

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 8
        - size[16] = 12 + pattern_items * sizeof_pattern_item """

        struct_size = 12

        pattern_size = len(self.pattern) * 2

        print(pattern_size)

        return struct.pack("<BH", 8, struct_size + pattern_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - offset[16]
        - length[16]
        - pattern-array[16 * pattern_items] """

        packed_pattern = bytes()
        for pattern_elem in self.binary["pattern"]:
            packed_pattern += struct.pack("<H", pattern_elem)

        return (
            struct.pack(
                "<IIhH",
                unsigned(self.binary["id"]),
                unsigned(self.binary["flags"]),
                self.offset,
                unsigned(len(self.binary["pattern"])),
            )
            + packed_pattern
        )


class IdtSignature(Signature):
    """ Represents an idt signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError("id is required!")

        if self.entry is None:
            raise ValueError("entry is required!")

        if not self.flags:
            self.flags = DEFAULT_FLAGS["SignatureFlags"]
        elif not any(arch in self.flags for arch in ["32", "64"]):
            self.flags += " 32 64"

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "idt"))

        self.binary["flags"] = get_binary_flags(self.flags, Signature)

        self.binary["entry"] = self.entry

    def __init__(self, sig_id, entry, flags=None, **kwargs):
        self.sig_id = sig_id
        self.entry = entry
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary["id"], other.binary["id"])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), %02d, (%02d)" % (
            self.sig_id,
            self.binary["id"],
            self.flags,
            self.binary["flags"],
            self.entry,
            self.binary["entry"],
        )

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 10
        - size[16] = 10/12"""

        struct_size = 12

        return struct.pack("<BH", 10, struct_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - entry[1]
        - _reserved[3]
        """

        return struct.pack(
            "<IIBBBB",
            unsigned(self.binary["id"]),
            unsigned(self.binary["flags"]),
            unsigned(self.entry),
            0,
            0,
            0,
        )


class VersionOsSignature(Signature):
    """ Represents a version os signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError('id is required!')

        if self.minimum is None:
            raise ValueError('minimum version is required!')

        if '.' in self.minimum and '.' not in self.maximum:
            raise ValueError('invalid os version format!')

        if '.' not in self.minimum and '.' in self.maximum:
            raise ValueError('invalid os version format!')

        if '.' in self.minimum and len(self.minimum.split('.')) != 3:
            raise ValueError('invalid os version format!')

        if self.maximum is None:
            raise ValueError('maximum version is required!')

        if '.' in self.maximum and len(self.maximum.split('.')) != 3:
            raise ValueError('invalid os version format!')

        if not self.flags:
            self.flags = DEFAULT_FLAGS['SignatureFlags']
        elif not any(arch in self.flags for arch in ['32', '64']):
            self.flags += ' 32 64'

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary['id'] = self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "version-os"))


        self.binary['flags'] = get_binary_flags(self.flags, Signature)

        if '.' in self.minimum:
            values = list()
            for item in self.minimum.split('.'):
                if item == '*':
                    values.append(0)
                else:
                    values.append(unsigned(int(item)))

            self.binary["minimum"] = {"version" : values[0], "patch" : values[1], "sublevel" :
                                      values[2]}

        else:
            if self.minimum == '*':
                self.binary['minimum'] = {"value" : 0}
            else:
                self.binary['minimum'] = {"value" : unsigned(int(self.minimum))}

        if '.' in self.maximum:
            values = list()
            for item in self.maximum.split('.'):
                if item == '*':
                    values.append(0xffff)
                else:
                    values.append(unsigned(int(item)))

            self.binary["maximum"] = {"version" : values[0], "patch" : values[1], "sublevel" :
                                      values[2]}
        else:
            if self.maximum == '*':
                self.binary['maximum'] = {"value" : 0xffff}
            else:
                self.binary['maximum'] = {"value" : unsigned(int(self.maximum))}


    def __init__(self, sig_id, minimum, maximum, flags=None, **kwargs):
        self.sig_id = sig_id
        self.minimum = minimum
        self.maximum = maximum
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary['id'], other.binary['id'])

    def __str__(self):
        if 'value' in self.binary['minimum']:
            return "'%s' (%04d), '%s' (%04x),  %s (0x%04x), '%s' (0x%04x)" % (self.sig_id, self.binary['id'],
                                                                              self.flags, self.binary['flags'],
                                                                              self.minimum, self.binary['minimum']['value'],
                                                                              self.maximum, self.binary['maximum']['value'])
        else:
            return "'%s' (%04d), '%s' (%04x),  '%s' (%d.%d.%d), '%s' (%d.%d.%d)" % (self.sig_id, self.binary['id'],
                    self.flags, self.binary['flags'], self.minimum, self.binary['minimum']['version'],
                    self.binary['minimum']['patch'], self.binary['minimum']['sublevel'],
                    self.maximum, self.binary['maximum']['version'], self.binary['maximum']['patch'], self.binary['maximum']['sublevel'])


    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 11
        - size[16] = 10/12"""

        struct_size = 24

        return struct.pack('<BH', 11, struct_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - minimum[32]
        - maximum[32]
        """

        if 'value' in self.binary["minimum"]:
            return struct.pack('<IIQQ',
                                unsigned(self.binary['id']),
                                unsigned(self.binary['flags']),
                                unsigned(self.binary['minimum']['value']),
                                unsigned(self.binary['maximum']['value']))
        else:
            return struct.pack('<IIBBHHBBBBHHBB',
                               unsigned(self.binary['id']),
                               unsigned(self.binary['flags']),
                               unsigned(self.binary['minimum']['version']),
                               unsigned(self.binary['minimum']['patch']),
                               unsigned(self.binary['minimum']['sublevel']),
                               0,
                               0,
                               0,
                               unsigned(self.binary['maximum']['version']),
                               unsigned(self.binary['maximum']['patch']),
                               unsigned(self.binary['maximum']['sublevel']),
                               0xffff,
                               0,
                               0)


class VersionIntroSignature(Signature):
    """ Represents a version os signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError('id is required!')

        if self.minimum is None:
            raise ValueError('minimum version is required!')

        if '.' not in self.minimum:
            raise ValueError('invalid intro version format!')

        if len(self.minimum.split('.')) != 3:
            raise ValueError('invalid intro version format!')

        if self.maximum is None:
            raise ValueError('maximum version is required!')

        if '.' not in self.maximum:
            raise ValueError('invalid intro version format!')

        if len(self.maximum.split('.')) != 3:
            raise ValueError('invalid intro version format!')

        if not self.flags:
            self.flags = DEFAULT_FLAGS['SignatureFlags']
        elif not any(arch in self.flags for arch in ['32', '64']):
            self.flags += ' 32 64'

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary['id'] = self.binary["id"] = get_sig_id(self.sig_id, excfg.get("SignatureType", "version-intro"))

        self.binary['flags'] = get_binary_flags(self.flags, Signature)

        if '.' in self.minimum:
            values = list()
            for item in self.minimum.split('.'):
                if item == '*':
                    values.append(0)
                else:
                    values.append(unsigned(int(item)))

            self.binary["minimum"] = {"major" : values[0], "minor" : values[1], "revision":
                                      values[2]}

        if '.' in self.maximum:
            values = list()
            for item in self.maximum.split('.'):
                if item == '*':
                    values.append(0xffff)
                else:
                    values.append(unsigned(int(item)))

            self.binary["maximum"] = {"major" : values[0], "minor" : values[1], "revision":
                                      values[2]}

    def __init__(self, sig_id, minimum, maximum, flags=None, **kwargs):
        self.sig_id = sig_id
        self.minimum = minimum
        self.maximum = maximum
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary['id'], other.binary['id'])

    def __str__(self):
        return "'%s' (%03d), '%s' (%08x), '%s' (%d.%d.%d), '%s' (%d.%d.%d)" % (self.sig_id, self.binary['id'],
        self.flags, self.binary['flags'], self.minimum, self.binary['minimum']["major"], self.binary["minimum"]["minor"], self.binary["minimum"]["revision"],
        self.maximum, self.binary['maximum']["major"], self.binary["maximum"]['minor'], self.binary["maximum"]["revision"])

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 12
        - size[16] = 10/12"""

        struct_size = 24

        return struct.pack('<BH', 12, struct_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - min[32]
        - max[32]
        """

        return struct.pack('<IIHHHHHHHH',
                           unsigned(self.binary['id']),
                           unsigned(self.binary['flags']),
                           unsigned(self.binary['minimum']['major']),
                           unsigned(self.binary['minimum']['minor']),
                           unsigned(self.binary['minimum']['revision']),
                           0x0,
                           unsigned(self.binary['maximum']['major']),
                           unsigned(self.binary['maximum']['minor']),
                           unsigned(self.binary['maximum']['revision']),
                           0xffff)


class ProcessCreationSignature(Signature):
    """ Represents a process-creaation signature. For more details about it's
    implementation see `get_binary`. """

    def _validate_args(self):
        """ Validates that the values are good. If they are missing, they will
        be initialized with the default values. """

        if not self.sig_id:
            raise ValueError('id is required!')

        if self.create_mask is None:
            raise ValueError('create-mask is required!')

        if not self.flags:
            self.flags = DEFAULT_FLAGS['SignatureFlags']
        elif not any(arch in self.flags for arch in ['32', '64']):
            self.flags += ' 32 64'

    def _complete_binary_args(self):
        """ Complete self.binary dictionary with the binary representations
        of the self fields. """

        self.binary['id'] = get_sig_id(self.sig_id, excfg.get("SignatureType", "process-creation"))

        self.binary['flags'] = get_binary_flags(self.flags, Signature)

        self.binary['create-mask'] = 0

        for flag in self.create_mask:
            print(excfg.get("ProcessCreationFlags", flag))
            self.binary['create-mask'] = self.binary['create-mask'] | int(excfg.get("ProcessCreationFlags", flag), 16)

    def __init__(self, sig_id, create_mask, flags=None, **kwargs):
        self.sig_id = sig_id
        self.create_mask = create_mask
        self.flags = flags
        self.binary = {}

        self._validate_args()

        self._complete_binary_args()

    def _cmp(self, other):
        """ Signatures must have an unique ID. So we can safely compare them
        based on ID only. """

        return cmp_unsigned(self.binary['id'], other.binary['id'])

    def __str__(self):
        return "'%s' (%04d), '%s' (%08x), '%s' (0x%08x) " % (self.sig_id, self.binary['id'],
        self.flags, self.binary['flags'], self.create_mask, self.binary["create-mask"])

    def get_binary_header(self):
        """ Returns a binary string representing the header of the signature

        The format it's as follows:
        - type[8] = 12
        - size[16] = 10/12"""

        struct_size = 24

        return struct.pack('<BH', 13, struct_size)

    def get_binary(self):
        """ Returns a binary string containing the binary representation of the
        signature.

        The format it's as follows:
        - id[32]
        - flags[32]
        - create-mask[32]
        """

        return struct.pack('<IIIIII',
                           unsigned(self.binary['id']),
                           unsigned(self.binary['flags']),
                           unsigned(self.binary["create-mask"]),
                           0,
                           0,
                           0)


