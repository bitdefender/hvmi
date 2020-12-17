#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
from enum import IntEnum, auto
import struct

class ZoneTypeEnum(IntEnum):
    Ept = auto()
    Msr = auto()
    Cr = auto()
    Integrity = auto()
    Process = auto()
    Dtr = auto()


class IntroObjectTypeEnum(IntEnum):
    Invalid = 0,
    Raw = auto()
    Internal = auto()
    Ssdt = auto()
    FastIoDispatch = auto()
    DriverObject = auto()
    KmModule = auto()
    Idt = auto()
    Gdt = auto()
    KmUnpack = auto()
    Process = auto()
    UmInternal = auto()
    UmUnpack = auto()
    UmHeap = auto()
    UmStack = auto()
    UmGenericNxZone = auto()
    UmModule = auto()
    DetourRead = auto()
    TokenPtr = auto()
    HalDispatchTable = auto()
    HalIntController = auto()
    SelfMapEntry = auto()
    HalHeap = auto()
    Vdso = auto()
    Vsyscall = auto()
    ExTable = auto()
    VeAgent = auto()
    Idtr = auto()
    Gdtr = auto()
    ProcessCreation = auto()
    ExecSuspiciousDll = auto()
    KmLoggerContext = auto()
    ProcessCreationDpi = auto()
    TokenPrivs = auto()
    SharedUserData = auto()
    SecDesc = auto()
    AclEdit = auto()
    Test = auto()
    Unknown = auto()


class InjectionTypeEnum(IntEnum):
    injectionViolationWrite = 0,
    injectionViolationRead = auto()
    injectionViolationSetContextThread = auto()
    injectionViolationQueueApcThread = auto()


description_zone_type = {
    ZoneTypeEnum.Ept : "Ept",
    ZoneTypeEnum.Msr : "Msr",
    ZoneTypeEnum.Cr : "Cr",
    ZoneTypeEnum.Integrity : "Intergity",
    ZoneTypeEnum.Process : "Process",
    ZoneTypeEnum.Dtr : "Dtr",
}

description_intro_type = {
    IntroObjectTypeEnum.Invalid : "Invalid",
    IntroObjectTypeEnum.Raw : "Raw",
    IntroObjectTypeEnum.Internal : "Internal",
    IntroObjectTypeEnum.Ssdt : "Ssdt",
    IntroObjectTypeEnum.FastIoDispatch : "FastIoDispatch",
    IntroObjectTypeEnum.DriverObject : "DriverObject",
    IntroObjectTypeEnum.KmModule : "KmModule",
    IntroObjectTypeEnum.Idt : "Idt",
    IntroObjectTypeEnum.Gdt : "Gdt",
    IntroObjectTypeEnum.KmUnpack : "KmUnpack",
    IntroObjectTypeEnum.Process : "Process",
    IntroObjectTypeEnum.UmInternal : "UmInternal",
    IntroObjectTypeEnum.UmUnpack : "UmUnpack",
    IntroObjectTypeEnum.UmHeap : "UmHeap",
    IntroObjectTypeEnum.UmStack : "UmStack",
    IntroObjectTypeEnum.UmGenericNxZone : "UmGenericNxZone",
    IntroObjectTypeEnum.UmModule : "UmModule",
    IntroObjectTypeEnum.DetourRead : "DetourRead",
    IntroObjectTypeEnum.TokenPtr : "TokenPtr",
    IntroObjectTypeEnum.HalDispatchTable : "HalDispatchTable",
    IntroObjectTypeEnum.HalIntController : "HalIntController",
    IntroObjectTypeEnum.SelfMapEntry : "SelfMapEntry",
    IntroObjectTypeEnum.HalHeap : "HalHeap",
    IntroObjectTypeEnum.Vdso : "Vdso",
    IntroObjectTypeEnum.Vsyscall : "Vsyscall",
    IntroObjectTypeEnum.ExTable : "ExTable",
    IntroObjectTypeEnum.VeAgent : "VeAgent",
    IntroObjectTypeEnum.Idtr : "Idtr",
    IntroObjectTypeEnum.Gdtr : "Gdtr",
    IntroObjectTypeEnum.ProcessCreation : "ProcessCreation",
    IntroObjectTypeEnum.ExecSuspiciousDll : "ExecSuspiciousDll",
    IntroObjectTypeEnum.KmLoggerContext : "KmLoggerContext",
    IntroObjectTypeEnum.ProcessCreationDpi : "ProcessCreationDpi",
    IntroObjectTypeEnum.TokenPrivs : "Token Privs",
    IntroObjectTypeEnum.SharedUserData : "Shared User Data",
    IntroObjectTypeEnum.SecDesc : "Security Descriptor",
    IntroObjectTypeEnum.AclEdit : "Acl Edit",
    IntroObjectTypeEnum.Unknown : "Unknown",
    }

class Header:
    def __init__(self):
        pass

class ObjectHeader:
    def __init__(self, version, type, size):
        self._version = version
        self._type = type
        self._size = size
        self._description = None

    def get_size(self):
        return self._size

    def get_type(self):
        return self._type

    def set_description(self, description):
        self._description = description

    def __repr__(self):
        return f"Object header -> Version: {self._version}, Type: '{self._description}' ({self._type}), Size: {self._size}"

class Cr:
    def __init__(self, cr):
        self._cr = cr

        self._object_type = None

    def __repr__(self):
        str = f"\tCr: 0x{self._cr:016x}"

        return str

class Msr:
    def __init__(self, msr):
        self._msr = msr

        self._object_type = None

    def __repr__(self):
        str = f"\tMsr: 0x{self._msr:016x}"

        return str

class Idt:
    def __init__(self, entry):
        self._entry = entry

        self._object_type = None

    def __repr__(self):
        str = f"\tEntry: {self._entry}"

        return str

class Dtr:
    def __init__(self, dtr):
        self._dtr = dtr

        self._object_type = None

    def __repr__(self):
        str = f"\tDtr: 0x{self._dtr}"

        return str

class Ept:
    def __init__(self, gva, gpa, type):
        self._gva = gva
        self._gpa = gpa
        self._type = type
        self._type_description_array = {0 : "None", 1 : "Read", 2 : "Write", 4 : "Execute"}
        self._type_description = self._type_description_array[self._type]

        self._object_type = None

    def __repr__(self):
        str = f"\tGva: 0x{self._gva:016x}\n"
        str += f"\tGpa: 0x{self._gpa:016x}\n"
        str += f"\tType: {self._type_description} ({self._type})"
        return str


class Injection:
    def __init__(self, gva, length, type):
        self._gva = gva
        self._length = length
        self._type = type

        self._object_type = None

    def __repr__(self):
        str = f"\tGva : 0x{self._gva:016x}\n"
        str += f"\tLength: {self._length}\n"
        str += f"\tType: {self._type}"
        return str

class RawDump:
    def __init__(self):
        self._length = None
        self._raw = None

        self._object_type = None

    def __repr__(self):
        str = f"\t Length: {self._length}\n"
        str += f"\t Raw: {self._raw}"

        return str

class RipCode:
    def __init__(self):
        self._cs_type = None
        self._length = None
        self._rip_code = None

        self._object_type = None

    def __repr__(self):
        str = f"\tCs Type: {self._cs_type}\n"
        str += f"\tLength: {self._length}\n"
        str += "\tRip Code:\n"
        str += "".join("{:02x}".format(c) for c in self._rip_code)
        str += "\n"

        return str


class Victim:
    def __init__(self, object_type, zone_type, zone_flags):
        try:
            self._intro_object_type = IntroObjectTypeEnum(object_type)
        except ValueError:
            self._intro_object_type = IntroObjectTypeEnum.Unknown

        self._intro_object_type_description = description_intro_type[self._intro_object_type]
        self._zone_type = ZoneTypeEnum(zone_type)
        self._zone_type_description = description_zone_type[self._zone_type]
        self._zone_flags = zone_flags

        self._object_type = None

    def __repr__(self):
        str = f"\tObject type: {self._intro_object_type_description} ({self._intro_object_type})\n"
        str += f"\tZone type: {self._zone_type_description} ({self._zone_type})\n"
        str += f"\tZone Flags: 0x{self._zone_flags:08x}"

        return str

class LixTask:
    def __init__(self, gva, real_parent, actual_parent, parent, mm_gva, cr3, pid, tgid, flags):
        self._gva = gva
        self._real_parent = real_parent
        self._actual_parent = actual_parent
        self._parent = parent
        self._mm_gva = mm_gva
        self._cr3 = cr3
        self._pid = pid
        self._tgid = tgid
        self._flags = flags
        self._name = None
        self._path = None
        self._cmd_line = None

        self._object_type = None

    def __repr__(self):
        str = f"\tName: '{self._name}\n"
        str += f"\tPath: '{self._path}'\n"
        str += f"\tCommand line: '{self._cmd_line}'\n"
        str += f"\tGva : {self._gva:016x}\n"
        str += f"\tReal parent: {self._real_parent:016x}\n"
        str += f"\tActual parent: {self._actual_parent:016x}\n"
        str += f"\tMm : {self._mm_gva:016x}\n"
        str += f"\tCr3: {self._cr3:016x}\n"
        str += f"\tPid: {self._pid}\n"
        str += f"\tTgid: {self._tgid}\n"
        str += f"\tFlags: {self._flags: 08x}"

        return str

class WinProcess:
    def __init__(
        self, eprocess, parent, real_parent, cr3, user_cr3, pid, peb64, peb32, main_module, flags
    ):
        self._eprocess = eprocess
        self._parent = parent
        self._real_parent = real_parent
        self._cr3 = cr3
        self._user_cr3 = user_cr3
        self._pid = pid
        self._peb64 = peb64
        self._peb32 = peb32
        self._main_module = main_module
        self._flags = flags

        self._name = None
        self._path = None
        self._cmd_line = None

        self._object_type = None

    def __repr__(self):
        str = f"\tProcess '{self._name}'\n"
        str += f"\tPath: '{self._path}'\n"
        str += f"\tCommand line: '{self._cmd_line}'\n"
        str += f"\tEprocess: 0x{self._eprocess:016x}\n"
        str += f"\tParent: 0x{self._parent:016x}\n"
        str += f"\tReal parent: 0x{self._real_parent:016x}\n"
        str += f"\tCr3: 0x{self._cr3:016x}\n"
        str += f"\tUser Cr3: 0x{self._user_cr3:016x}\n"
        str += f"\tPid: {self._pid}\n"
        str += f"\tPeb32: 0x{self._peb32:016x}\n"
        str += f"\tPeb64: 0x{self._peb64:016x}\n"
        str += f"\tMain module: 0x{self._main_module:016x}\n"
        str += f"\tFlags: 0x{self._flags:08x}"

        return str


class WinModule:
    def __init__(self, virt_base, size):
        self._virt_base = virt_base
        self._size = size
        self._path = None

        self._object_type = None

    def __repr__(self):
        str = f"\tVirtual base: 0x{self._virt_base:016x}\n"
        str += f"\tSize: 0x{self._size:08x}\n"
        str += f"\tPath: '{self._path}'"

        return str

class WinVad:
    def __init__(self, start, end, gva, vad_prot, vad_type, prot, exec_count, flags):
        self._start = start
        self._end = end
        self._gva = gva
        self._vad_prot = vad_prot
        self._vad_type = vad_type
        self._prot = prot
        self._exec_count = exec_count
        self._flags = flags

        self._path = ""

        self._object_type = None

    def __repr__(self):
        str = f"\tPath'{self._path}' \n"
        str +=f"\tStart: 0x{self._start:016x}\n"
        str +=f"\tEnd: 0x{self._end:016x}\n"
        str +=f"\tGva: {self._gva:08x}\n"
        str +=f"\tVad protection: {self._vad_prot:08x}\n"
        str +=f"\tProtection: 0x{self._prot:04x}\n"
        str +=f"\tVad Type: {self._vad_type}\n"
        str +=f"\tProtection: {self._exec_count}\n"
        str +=f"\tFlags: 0x{self._flags:08x}"

        return str


class LixVma:
    def __init__(self, start, end, gva, flags, file):
        self._start = start
        self._end = end
        self._gva = gva
        self._flags = flags
        self._file = file

        self._path = ""

        self._object_type = None

    def __repr__(self):
        str = f"\tPath'{self._path}' \n"
        str +=f"\tStart: 0x{self._start:016x}\n"
        str +=f"\tEnd: 0x{self._end:016x}\n"
        str +=f"\tGva: {self._gva:08x}\n"
        str +=f"\tFlags: 0x{self._flags:08x}\n"
        str +=f"\File: 0x{self._file:016x}"

        return str


class WinKernelDriver:
    def __init__(self, timestamp):
        self._time_stamp = timestamp
        self._path = None

        self._object_type = None

    def __repr__(self):
        str = f"\tTime Stamp : {self._time_stamp}\n"
        str += f"\tPath: '{self._path}'"

        return str


class WinDrvObject:
    def __init__(self, gva, gpa, fastio_addr):
        self._gva = gva
        self._gpa = gpa
        self._fastio_addr = fastio_addr
        self._name = None

        self._object_type = None

    def __repr__(self):
        str = f"\tGva: 0x{self._gva:016x}\n"
        str += f"\tGpa: 0x{self._gpa:016x}\n"
        str += f"\tFast IO Address: 0x{self._fastio_addr:016x}\n"
        str += f"\tName: {self._name}"

        return str

class LixKernelModule:
    def __init__(self, init_layout_base, init_layout_size, init_layout_text_size, init_layout_ro_size, core_layout_base, core_layout_size, core_layout_text_size, core_layout_ro_size):

        self._init_layout_base = init_layout_base
        self._init_layout_size = init_layout_size
        self._init_layout_text_size = init_layout_text_size
        self._init_layout_ro_size = init_layout_ro_size

        self._core_layout_base = core_layout_base
        self._core_layout_size = core_layout_size
        self._core_layout_text_size = core_layout_text_size
        self._core_layout_ro_size = core_layout_ro_size

        self._path = None

        self._object_type = None

    def __repr__(self):
        str = f"\tPath: '{self._path}'\n"
        str += f"\tInit Layout Base: 0x{self._init_layout_base:016x}\n"
        str += f"\tInit Layout Size: 0x{self._init_layout_size:08x}\n"
        str += f"\tInit Layout Text Size: 0x{self._init_layout_text_size:08x}\n"
        str += f"\tInit Layout RoSize: 0x{self._init_layout_text_size:08x}\n"

        str += f"\tCore Layout Base: 0x{self._core_layout_base:016x}\n"
        str += f"\tCore Layout Size: 0x{self._core_layout_size:08x}\n"
        str += f"\tCore Layout Text Size: 0x{self._core_layout_text_size:08x}\n"
        str += f"\tCore Layout RoSize: 0x{self._core_layout_text_size:08x}"

        return str

class KernelDriver:
    def __init__(self, object_gva, base_va, size, entry_point):
        self._object_gva = object_gva
        self._base_va = base_va
        self._size = size
        self._entry_point = entry_point
        self._section = None

        self._object_type = None

    def __repr__(self):
        str = f"\tObject Gva: 0x{self._object_gva:016x}\n"
        str += f"\tBase VA: 0x{self._base_va:016x}\n"
        str += f"\tSize: 0x{self._size:08x}\n"
        str += f"\tEntry point: 0x{self._entry_point:016x}\n"
        str += f"\tSection: {self._section}"

        return str

class Instrux:
    def __init__(self):
        self._rip = None
        self._bytes = None

        self._object_type = None

    def __repr__(self):
        str = f"\tRIP: 0x{self._rip:016x}\n"
        str += f"\tBytes: {self._bytes}"

        return str

class Export:
    def __init(self):
        self._count = None
        self._delta = None
        self._exports = None

        self._object_type = None

    def __repr__(self):
        str = f"\tDelta: {self._delta}\n"
        for item in self._exports:
            str += f"\t-> {item}\n"

        return str

class Dpi:
    def __init(self):
        self._flags = None

        self._object_type = None

    def __repr__(self):
        str = f"\tFlags: {self._flags}\n"

        return str

class DpiWinDebug:
    def __init__(self, debugger):
        self._debugger = debugger

        self._object_type = None

    def __repr__(self):
        str = f"\t Debugger: 0x{self._debugger:016x}"

        return str

class DpiWinStolenToken:
    def __init__(self, stolen_from):
        self._stolen_from = stolen_from

        self._object_type = None

    def __repr__(self):
        str = f"\t Stolen From: 0x{self._stolen_from:016x}"

        return str

class DpiWinHeapSpray:
    def __init__(self):
        self._heap_pages = None
        self._shellcode_flags = None
        self._detected_page = None
        self._max_heap_val_page_content = None

        self._object_type = None

    def __repr__(self):
        str = f"\t Shellcode flag: 0x{self._shellcode_flags:016x}\n"
        str += f"\t Heap pages:"
        str += "".join("{:04x} ".format(c) for c in self._heap_pages)
        str += "\n"

        str += f"\t Detected Page:"
        str += "".join("{:02x}".format(c) for c in self._detected_page)
        str += "\n"

        str += f"\t Max heap value page content:"
        str += "".join("{:02x}".format(c) for c in self._max_heap_val_page_content)
        str += "\n"

        return str

class DpiWinStartThread:
    def __init__(self, shellcode_flags, start_address):
        self._shellcode_flags = shellcode_flags
        self._start_address = start_address
        self._start_page = None

        self._object_type = None

    def __repr__(self):
        str = f"\t Shellcode flag: 0x{self._shellcode_flags:016x}\n"
        str += f"\t Start Address: 0x{self._start_address:016x}\n"

        str += f"\t Start page"
        str += "".join("{:02x}".format(c) for c in self._start_page)
        str += "\n"

        return str

class DpiWinTokenPrivs:
    def __init__(self, old_enabled, new_enabled, old_present, new_present):
        self._old_enabled = old_enabled
        self._new_enabled = new_enabled
        self._old_present = old_present
        self._new_present = new_present

        self._object_type = None

    def __repr__(self):
        str = f"\t Old Enabled: 0x{self._old_enabled:016x}\n"
        str += f"\t New Enabled: 0x{self._new_enabled:016x}\n"

        str += f"\t Old Present: 0x{self._old_present:016x}\n"
        str += f"\t New Present: 0x{self._new_present:016x}\n"

        return str

class DpiWinPivotedStack:
    def __init__(self, current_stack, stack_base, stack_limit, wow64_current_stack, wow64_stack_base, wow64_stack_limit):
        self._current_stack = current_stack
        self._stack_base = stack_base
        self._stack_limit = stack_limit

        self._wow64_current_stack = wow64_current_stack
        self._wow64_stack_base = wow64_stack_base
        self._wow64_stack_limit = wow64_stack_limit

        self._trap_frame_content = None

        self._arch = None

        self._object_type = None

    def __repr__(self):
        str = f"\t Current stack: 0x{self._current_stack:016x}\n"
        str += f"\t Stack base: 0x{self._stack_base:016x}\n"
        str += f"\t Stack limit: 0x{self._stack_limit:016x}\n"

        str += f"\t WOW64 Current stack: 0x{self._wow64_current_stack:016x}\n"
        str += f"\t WOW64 Stack base: 0x{self._wow64_stack_base:016x}\n"
        str += f"\t WOW64 Stack limit: 0x{self._wow64_stack_limit:016x}\n"

        if self._arch:
            fmt = "<QQQQQBBBBLQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQHHHHQQQQQQQHBBHHLLQHHL"

            (p1home, p2home, p3home, p4home,
            p5, pmode, pirql, find, eact, mxcsr,
            rax, rcx, rdx, r8, r9, r10, r11, gsbase,
            xmm0lo, xmm0hi, xmm1lo, xmm1hi, xmm2lo,
            xmm2hi, xmm3lo, xmm3hi, xmm4lo, xmm4hi,
            xmm5lo, xmm5hi, faddr, dr0, dr1, dr2, dr3,
            dr6, dr7, dbgctl, branchrip, branchfrom, excrip, excfromrip,
            ds, es, fs, gs, trapframe, rbx, rdi, rsi, rbp,
            errcode, rip, cs, _, _, _, _, eflags, _, rsp, ss, _,
            _) = struct.unpack(fmt, self._trap_frame_content[0:400])

            str += f"\t Rax = {rax:016x}\n"
            str += f"\t Rbx = {rbx:016x}\n"
            str += f"\t Rcx = {rcx:016x}\n"
            str += f"\t Rdx = {rdx:016x}\n"
            str += f"\t R8 = {r8:016x}\n"
            str += f"\t R9 = {r9:016x}\n"
            str += f"\t R10 = {r10:016x}\n"
            str += f"\t R11 = {r11:016x}\n"
            str += f"\t Rsi = {rsi:016x}\n"
            str += f"\t Rdi = {rdi:016x}\n"
            str += f"\t Rbp = {rbp:016x}\n"
            str += f"\t Rip = {rip:016x}\n"
            str += f"\t Rsp = {rsp:016x}\n"
            str += f"\t CS = {cs:016x}\n"
            str += f"\t SS = {ss:016x}\n"
            str += f"\t Eflags = {eflags:016x}\n"
            str += f"\t DS = {ds:016x}\n"
            str += f"\t ES = {es:016x}\n"
            str += f"\t FS = {fs:016x}\n"
            str += f"\t GS = {gs:016x}\n"
            str += f"\t GsBase = {gsbase:016x}\n"
            str += f"\t TrapFrame = {trapframe:016x}\n"
        else:
            fmt = "<LLLHBBLLLLLLLLLLLLLBBBBLLLLLLLLLLLLLLLLL"

            (dbgebp, dbgeip, dbgargmark, tempsegcs, logging, ftype, tempesp,
            dr0, dr1, dr2, dr3, dr6, dr7, gs, es, ds, edx, ecx, eax, ppmode,
            eqdpc, _, _, mxcsr, exlist, fs, edi, esi, ebx, ebp, errcode, eip,
            cs, eflags, esp, ss, v86es, v86ds, v86fs,
            v86gs) = struct.unpack(fmt, self._trap_frame_content[0:140])

            str += f"\t Eax = {eax:08x}\n"
            str += f"\t Ebx = {ebx:08x}\n"
            str += f"\t Ecx = {ecx:08x}\n"
            str += f"\t Edx = {edx:08x}\n"
            str += f"\t Esi = {esi:08x}\n"
            str += f"\t Edi = {edi:08x}\n"
            str += f"\t Ebp = {ebp:08x}\n"
            str += f"\t Eip = {eip:08x}\n"
            str += f"\t Esp = {esp:08x}\n"
            str += f"\t CS = {cs:08x}\n"
            str += f"\t SS = {ss:08x}\n"
            str += f"\t Eflags = {eflags:08x}\n"
            str += f"\t DS = {ds:08x}\n"
            str += f"\t ES = {es:08x}\n"
            str += f"\t FS = {fs:08x}\n"
            str += f"\t GS = {gs:08x}\n"

        return str

class DpiWinSecDesc:
    def __init__(self, stolen_from, old_ptr, new_ptr, old_sacl, old_dacl, new_sacl, new_dacl):
        self._stolen_from = stolen_from
        self._old_ptr = old_ptr
        self._new_ptr = new_ptr
        self._old_sacl = struct.unpack('bbhhh', old_sacl.to_bytes(8, byteorder='little'))
        self._old_dacl = struct.unpack('bbhhh', old_dacl.to_bytes(8, byteorder='little'))
        self._new_sacl = struct.unpack('bbhhh', new_sacl.to_bytes(8, byteorder='little'))
        self._new_dacl = struct.unpack('bbhhh', new_dacl.to_bytes(8, byteorder='little'))

        self._object_type = None

    def __repr__(self):
        str = f"\t Stolen from EPROCESS: 0x{self._stolen_from:016x}\n"

        str += f"\t Old pointer value: 0x{self._old_ptr:016x}\n"
        str += f"\t New pointer value: 0x{self._new_ptr:016x}\n"

        str += f"\t Old SACL AclRevison:0x{self._old_sacl[0]:02x}"
        str += f" AclSize:0x{(self._old_sacl[2]):04x}"
        str += f" AceCount:0x{(self._old_sacl[3]):04x}\n"

        str += f"\t New SACL AclRevison:0x{self._new_sacl[0]:02x}"
        str += f" AclSize:0x{(self._new_sacl[2]):04x}"
        str += f" AceCount:0x{(self._new_sacl[3]):04x}\n"

        str += f"\t Old DACL AclRevison:0x{self._old_dacl[0]:02x}"
        str += f" AclSize:0x{(self._old_dacl[2]):04x}"
        str += f" AceCount:0x{(self._old_dacl[3]):04x}\n"

        str += f"\t New DACL AclRevison:0x{self._new_dacl[0]:02x}"
        str += f" AclSize:0x{(self._new_dacl[2]):04x}"
        str += f" AceCount:0x{(self._new_dacl[3]):04x}\n"

        return str

class DpiWinAclEdit:
    def __init__(self, old_sacl, old_dacl, new_sacl, new_dacl):
        self._old_sacl = struct.unpack('bbhhh', old_sacl.to_bytes(8, byteorder='little'))
        self._old_dacl = struct.unpack('bbhhh', old_dacl.to_bytes(8, byteorder='little'))
        self._new_sacl = struct.unpack('bbhhh', new_sacl.to_bytes(8, byteorder='little'))
        self._new_dacl = struct.unpack('bbhhh', new_dacl.to_bytes(8, byteorder='little'))

        self._object_type = None

    def __repr__(self):
        str = f"\t Old SACL AclRevison:0x{self._old_sacl[0]:02x}"
        str += f" AclSize:0x{(self._old_sacl[2]):04x}"
        str += f" AceCount:0x{(self._old_sacl[3]):04x}\n"

        str += f"\t New SACL AclRevison:0x{self._new_sacl[0]:02x}"
        str += f" AclSize:0x{(self._new_sacl[2]):04x}"
        str += f" AceCount:0x{(self._new_sacl[3]):04x}\n"

        str += f"\t Old DACL AclRevison:0x{self._old_dacl[0]:02x}"
        str += f" AclSize:0x{(self._old_dacl[2]):04x}"
        str += f" AceCount:0x{(self._old_dacl[3]):04x}\n"

        str += f"\t New DACL AclRevison:0x{self._new_dacl[0]:02x}"
        str += f" AclSize:0x{(self._new_dacl[2]):04x}"
        str += f" AceCount:0x{(self._new_dacl[3]):04x}\n"

        return str

class WriteInfo:
    def __init__(self):
        self._access_size = None
        self._old_value = list()
        self._new_value = list()

        self._object_type = None

    def __repr__(self):
        str = f"\tAccess size: {self._access_size}\n"
        str += f"\tOld Value:\n"
        for val in self._old_value:
            str += "\t\t0x%x \n" % (val)

        str += f"\tNew Value:\n"
        for val in self._new_value:
            str += "\t\t0x%x \n" % (val)

        return str

class ReadInfo:
    def __init__(self):
        self._access_size = None
        self._value = list()

        self._object_type = None

    def __repr__(self):
        str = f"\tAccess size: {self._access_size}\n"
        str += f"\tValue:\n"
        for val in self._old_value:
            str += "\t\t0x%x \n" % (val)

        return str

class ExecInfo:
    def __init__(self, rsp, length, stack_base, stack_limit):
        self._rsp = rsp
        self._length = length
        self._stack_base = stack_base
        self._stack_limit = stack_limit

        self._object_type = None

    def __repr__(self):
        str = f"\tRSP: {self._rsp}\n"
        str += f"\tIntruction Length: 0x{self._length:016x}\n"
        str += f"\tStack Base: 0x{self._stack_base:016x}\n"
        str += f"\tStack Limit: 0x{self._stack_limit:016x}\n"

        return str

class CodeBlocks:
    def __init__(self, start_address, rip, rip_cb_index):
        self._start_address = start_address
        self._rip = rip
        self._rip_cb_index = rip_cb_index
        self._count = None
        self._content = list()

        self._object_type = None

    def __repr__(self):
        str = f"\tStart address: 0x{self._start_address:016x}\n"
        str += f"\tRip: 0x{self._rip:016x}\n"
        str += f"\tIndex: 0x{self._rip_cb_index:016x}\n"
        str += f"\tCount: {self._count}\n"
        str += f"\tCodeblocks:\n"
        index = 0
        for item in self._content:
            if index == self._rip_cb_index:
                str += "\t\t0x%x <-- Rip\n" % (item)
            else:
                str += "\t\t0x%x\n" % (item)
            index +=1
        str += "\n"

        return str

class ArchRegs:
    def __init__(self, rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15, cr2, flags, dr7, rip, cr0, cr4, cr3, cr8, idt_base, idt_limit, gdt_base, gdt_limit):
        self._rax = rax
        self._rcx = rcx
        self._rdx = rdx
        self._rbx = rbx
        self._rsp = rsp
        self._rbp = rbp
        self._rsi = rsi
        self._rdi = rdi
        self._r8 = r8
        self._r9 = r9
        self._r10 = r10
        self._r11 = r11
        self._r12 = r12
        self._r13 = r13
        self._r14 = r14
        self._r15 = r15
        self._cr2 = cr2
        self._flags = flags
        self._dr7 = dr7
        self._rip = rip
        self._cr0 = cr0
        self._cr4 = cr4
        self._cr3 = cr3
        self._cr8 = cr8
        self._idt_base = idt_base
        self._idt_limit = idt_limit
        self._gdt_base = gdt_base
        self._gdt_limit = gdt_limit

        self._object_type = None

    def __repr__(self):
        str = f"\tRax: 0x{self._rax:016x}\n"
        str += f"\tRcx: 0x{self._rcx:016x}\n"
        str += f"\tRdx: 0x{self._rdx:016x}\n"
        str += f"\tRbx: 0x{self._rbx:016x}\n"
        str += f"\tRsp: 0x{self._rsp:016x}\n"
        str += f"\tRbp: 0x{self._rbp:016x}\n"
        str += f"\tRsi: 0x{self._rsi:016x}\n"
        str += f"\tRdi: 0x{self._rdi:016x}\n"
        str += f"\tR8: 0x{self._r8:016x}\n"
        str += f"\tR9: 0x{self._r8:016x}\n"
        str += f"\tR10: 0x{self._r10:016x}\n"
        str += f"\tR11: 0x{self._r11:016x}\n"
        str += f"\tR12: 0x{self._r12:016x}\n"
        str += f"\tR13: 0x{self._r13:016x}\n"
        str += f"\tR14: 0x{self._r14:016x}\n"
        str += f"\tR15: 0x{self._r15:016x}\n"
        str += f"\tCr2: 0x{self._cr2:016x}\n"
        str += f"\tFlags: 0x{self._flags:016x}\n"
        str += f"\tDr7: 0x{self._dr7:016x}\n"
        str += f"\tRip: 0x{self._rip:016x}\n"
        str += f"\tCr0: 0x{self._cr0:016x}\n"
        str += f"\tCr4: 0x{self._cr4:016x}\n"
        str += f"\tCr3: 0x{self._cr3:016x}\n"
        str += f"\tCr8: 0x{self._cr8:016x}\n"
        str += f"\tIdtBase: 0x{self._idt_base:016x}\n"
        str += f"\tIdtLimit: 0x{self._idt_limit:016x}\n"
        str += f"\tGdtBase: 0x{self._gdt_base:016x}\n"
        str += f"\tGdtLimit: 0x{self._gdt_limit:016x}"

        return str
