#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import json

from enum import Enum, auto

class SignatureJson:
    def __init__(self):
        self.Type = None
        self.Signatures = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=False, indent=4)


class ExceptionJson:
    def __init__(self):
        self.Type = None
        self.Exceptions = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=False, indent=4)

class ExportHash:
    def __init__(self, n, d):
        self.name = n
        self.delta = d

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=False, indent=4)

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=False, indent=4)


class ExportSignature:
    def __init__(self):
        self.sig_id = None
        self.sig_type = "export"
        self.flags = None
        self.library = None
        self.hashes = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__,  sort_keys=False, indent=4)


    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)


class IdtSignature:
    def __init__(self):
        self.sig_id = None
        self.sig_type = "idt"
        self.flags = None
        self.entry = None

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)



class CodeBlocksSignature:
    def __init__(self):
        self.sig_type = "codeblocks"
        self.sig_id = None
        self.flags = None
        self.score = None
        self.hashes = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)


    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)

class DpiSignature:
    def __init__(self):
        self.sig_type = "process-creation"
        self.sig_id = None
        self.flags = None
        self.create_mask = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)


    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)


class UserModeException:
    def __init__(self):
        self.process = None
        self.originator = None
        self.victim = None
        self.flags = None
        self.object_type = None
        self.signature = list()

    def __repr__(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)


class KernelModeException:
    def __init__(self):
        self.originator = None
        self.victim = None
        self.object_type = None
        self.flags = None
        self.signature = list()

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)

class KernelUserModeException:
    def __init__(self):
        self.process = None
        self.originator = None
        self.victim = None
        self.object_type = None
        self.flags = None
        self.signature = list()

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=False, indent=4)




EPT_HOOK_NONE = 0
EPT_HOOK_READ = 1
EPT_HOOK_WRITE = 2
EPT_HOOK_EXECUTE = 4

class ProcessCreationFlagsEnum(Enum):
    processCreationDebug            = 0x00000001,
    processCreationPivotedStack     = 0x00000002,
    processCreationStolenToken      = 0x00000004,
    processCreationHeapSpray        = 0x00000008,
    processCreationSecDesc          = 0x00000040,
    processCreationAclEdit          = 0x00000080

class IntroEventEnum(Enum):
    introEventEptViolation                  = 1
    introEventMsrViolation                  = 2
    introEventCrViolation                   = 3
    introEventIntegrityViolation            = 5
    introEventInjectionViolation            = 7
    introEventDtrViolation                  = 8
    introEventProcessCreationViolation      = 16
    introEventModuleLoadViolation           = 17


class KmObjectType(Enum):
    kmObjNone = 0
    kmObjAny = auto()
    kmObjDriver = auto()
    kmObjDriverImports = auto()
    kmObjDriverCode = auto()
    kmObjDriverData = auto()
    kmObjDriverResource = auto()
    kmObjSsdt = auto()
    kmObjDrvObj = auto()
    kmObjFastIo = auto()
    kmObjMsr = auto()
    kmObjCr4 = auto()
    kmObjHalHeap = auto()
    kmObjSelfMapEntry = auto()
    kmObjIdt = auto()
    kmObjIdtr = auto()
    kmObjGdtr = auto()
    kmObjLoggerCtx = auto()
    kmObjDriverExports = auto()
    kmObjSecDesc = auto()
    kmObjAclEdit = auto()

class UmObjectType(Enum):
    umObjNone  = 0
    umObjAny = auto()
    umObjProcess = auto()
    umObjModule = auto()
    umObjModuleImports = auto()
    umObjNxZone = auto()
    umObjModuleExports = auto()
    umObjProcessThreadContext = auto()
    umObjProcessPeb32 = auto()
    umObjProcessPeb64 = auto()
    umObjProcessApcThread = auto()
    umObjProcessCreation = auto()
    umObjModuleLoad = auto()
    umObjProcessCreationDpi = auto()

class KmUmObjectType(Enum):
    kmUmObjNone  = 0
    kmUmObjAny = auto()
    kmUmObjModule = auto()
    kmUmObjModuleImports = auto()
    kmUmObjModuleExports = auto()

class UmExcNameEnum(Enum):
    umExcNameAny = 0
    umExcNameOwn = auto()
    umExcNameVdso = auto()
    umExcNameVsyscall = auto()

    umExcNameNone = auto()

class KmExecNameEnum(Enum):
    kmExcNameAny = 0
    kmExcNameOwn = auto()
    kmExcNameKernel = auto()
    kmExcNameHal = auto()
    kmExcNameNone = auto()
    kmExcNameVdso = auto()
    kmExcNameVsyscall = auto()

    kmExcNameVeAgent = auto()

class ExecFlagEnum(Enum):
    execFlagFeedback            = 0x00000001,
    execFlag32                  = 0x00000002,
    execFlag64                  = 0x00000004,
    execFlagInit                = 0x00000008,
    execFlagReturn              = 0x00000010,
    execFlagLinux               = 0x00000080,
    execFlagRead                = 0x10000000,
    execFlagWrite               = 0x20000000,
    execFlagExecute             = 0x40000000,
    execFlagIgnore              = 0x80000000,
    execKmFlagNonDriver         = 0x00000100,
    execKmFlagReturnDrv         = 0x00000200,
    execKmFlagSmap              = 0x00000400,
    execKmFlagSmep              = 0x00000800,
    execKmFlagIntegrity         = 0x00001000,
    execUmFlagSysProc           = 0x00000100,
    execUmFlagChildProc         = 0x00000200,
    execUmFlagOnetime           = 0x10000800,
    execUmFlagLikeApphelp       = 0x10001000,
    execUmFlagModuleLoad        = 0x00004000,


class GuestTypeEnum(Enum):
    guestTypeUnknown = 0
    guestTypeWindows = 1
    guestTypeLinux   = 2

um_obj_type = {
        UmObjectType.umObjNone                  : "none",
        UmObjectType.umObjAny                   : "any",
        UmObjectType.umObjProcess               : "process",
        UmObjectType.umObjModule                : "module",
        UmObjectType.umObjModuleImports         : "module imports",
        UmObjectType.umObjNxZone                : "nx_zone",
        UmObjectType.umObjModuleExports         : "module exports",
        UmObjectType.umObjProcessThreadContext  : "thread-context",
        UmObjectType.umObjProcessPeb32          : "peb32",
        UmObjectType.umObjProcessPeb64          : "peb64",
        UmObjectType.umObjProcessApcThread      : "apc-thread",
        UmObjectType.umObjProcessCreation       : "process-creation",
        UmObjectType.umObjModuleLoad            : "double-agent",
        UmObjectType.umObjProcessCreationDpi    : "process-creation-dpi",
}

km_um_obj_type = {
        KmUmObjectType.kmUmObjNone                  : "none",
        KmUmObjectType.kmUmObjAny                   : "any",
        KmUmObjectType.kmUmObjModule                : "module",
        KmUmObjectType.kmUmObjModuleImports         : "module imports",
        KmUmObjectType.kmUmObjModuleExports         : "module exports",
}

km_obj_type = {
        KmObjectType.kmObjNone               : "none",
        KmObjectType.kmObjAny                : "any",
        KmObjectType.kmObjDriver             : "driver",
        KmObjectType.kmObjDriverImports      : "driver imports",
        KmObjectType.kmObjDriverCode         : "driver code",
        KmObjectType.kmObjDriverData         : "driver data",
        KmObjectType.kmObjDriverResource     : "driver resources",
        KmObjectType.kmObjSsdt               : "ssdt",
        KmObjectType.kmObjDrvObj             : "drvobj",
        KmObjectType.kmObjFastIo             : "fastio",
        KmObjectType.kmObjMsr                : "msr",
        KmObjectType.kmObjCr4                : "cr4",
        KmObjectType.kmObjHalHeap            : "hal-heap",
        KmObjectType.kmObjSelfMapEntry       : "self-map",
        KmObjectType.kmObjIdt                : "idt",
        KmObjectType.kmObjIdtr               : "idt-reg",
        KmObjectType.kmObjGdtr               : "gdt-reg",
        KmObjectType.kmObjLoggerCtx          : "infinity-hook",
        KmObjectType.kmObjDriverExports      : "driver exports",
        KmObjectType.kmObjSecDesc            : "security-descriptor",
        KmObjectType.kmObjAclEdit            : "acl-edit"
}

um_exc_name = {
        UmExcNameEnum.umExcNameAny      :   "*",
        UmExcNameEnum.umExcNameOwn      :   "[own]",
        UmExcNameEnum.umExcNameVdso     :   "[vdso]",
        UmExcNameEnum.umExcNameVsyscall :   "[vsyscall]",

        UmExcNameEnum.umExcNameNone       :   "-"
}

km_exec_name = {
        KmExecNameEnum.kmExcNameAny : "*",
        KmExecNameEnum.kmExcNameOwn : "[own]",
        KmExecNameEnum.kmExcNameKernel : "[kernel]",
        KmExecNameEnum.kmExcNameHal : "[hal]",
        KmExecNameEnum.kmExcNameNone : "-",
        KmExecNameEnum.kmExcNameVdso : "[vdso]",
        KmExecNameEnum.kmExcNameVsyscall : "[vsyscall]",

        KmExecNameEnum.kmExcNameVeAgent : "",
}

exec_flags = {
        ExecFlagEnum.execFlagFeedback           : "feedback",
        ExecFlagEnum.execFlag32                 : "32",
        ExecFlagEnum.execFlag64                 : "64",
        ExecFlagEnum.execFlagInit               : "init",
        ExecFlagEnum.execFlagReturn             : "return",
        ExecFlagEnum.execFlagLinux              : "linux",
        ExecFlagEnum.execFlagRead               : "read",
        ExecFlagEnum.execFlagWrite              : "write",
        ExecFlagEnum.execFlagExecute            : "exec",
        ExecFlagEnum.execFlagIgnore             : "ignore",
        ExecFlagEnum.execKmFlagNonDriver        : "non-driver",
        ExecFlagEnum.execKmFlagReturnDrv        : "return-drv",
        ExecFlagEnum.execKmFlagSmap             : "smap",
        ExecFlagEnum.execKmFlagSmep             : "smep",
        ExecFlagEnum.execKmFlagIntegrity        : "integrity",
        ExecFlagEnum.execUmFlagSysProc          : "system-process",
        ExecFlagEnum.execUmFlagChildProc        : "child",
        ExecFlagEnum.execUmFlagOnetime          : "one-time",
        ExecFlagEnum.execUmFlagLikeApphelp      : "like-apphelp",
        ExecFlagEnum.execUmFlagModuleLoad       : "module-load",
}

um_process_creation_flags = {
    ProcessCreationFlagsEnum.processCreationDebug            : "debug",
    ProcessCreationFlagsEnum.processCreationPivotedStack     : "pivoted-stack",
    ProcessCreationFlagsEnum.processCreationStolenToken      : "stolen-token",
    ProcessCreationFlagsEnum.processCreationHeapSpray        : "heap-spray",
    ProcessCreationFlagsEnum.processCreationSecDesc          : "security-descriptor",
    ProcessCreationFlagsEnum.processCreationAclEdit          : "acl-edit"
}

ZONE_LIB_IMPORTS        = 0x000000001
ZONE_LIB_EXPORTS        = 0x000000002
ZONE_LIB_CODE           = 0x000000004
ZONE_LIB_DATA           = 0x000000008
ZONE_LIB_RESOURCES      = 0x000000010
ZONE_PROC_THREAD_CTX    = 0x000000020
ZONE_PROC_THREAD_APC    = 0x000000040
ZONE_DEP_EXECUTION      = 0x000000080
ZONE_MODULE_LOAD        = 0x000000100
ZONE_WRITE              = 0x010000000
ZONE_READ               = 0x020000000
ZONE_EXECUTE            = 0x040000000
ZONE_INTEGRITY          = 0x100000000


