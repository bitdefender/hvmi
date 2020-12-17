#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import base64
import sys
import struct
import argparse

from enum import Enum, auto
from objects import *

class EnumObjects(Enum):
    intObjStartOriginator = auto()
    intObjEndOriginator = auto()
    intObjStartVictim = auto()
    intObjEndVictim = auto()
    intObjStartMisc = auto()
    intObjEndMisc = auto ()

    intObjVictim = auto()

    intObjEpt = auto()
    intObjMsr = auto()
    intObjCr = auto()
    intObjDtr = auto()
    intObjIdt = auto()
    intObjIntegrity = auto()
    intObjInjection = auto()

    intObjWinProcess = auto()
    intObjWinProcessParent = auto()
    intObjLixProcess = auto()
    intObjLixProcessParent = auto()

    intObjKernelDriver = auto()
    intObjKernelDriverReturn = auto()
    intObjWinKernelDriver = auto()
    intObjWinKernelDriverReturn = auto()
    intObjLixKernelModule = auto()
    intObjLixKernelModuleReturn = auto()

    intObjKernelDrvObject = auto()

    intObjWinVad = auto()
    intObjLixVma = auto()

    intObjWinModule = auto()
    intObjWinModuleReturn = auto()

    intObjInstrux = auto()
    intObjWriteInfo = auto()
    intObjReadInfo = auto()
    intObjExecInfo = auto()
    intObjArchRegs = auto()
    intObjCodeBlocks = auto()
    intObjRipCode = auto()
    intObjRawDump = auto()
    intObjExport = auto()
    intObjDpi = auto()
    intObjDpiWinDebug = auto()
    intObjDpiWinPivotedStack = auto()
    intObjDpiWinStolenToken = auto()
    intObjDpiWinTokenPrivs = auto()
    intObjDpiWinThreadStart = auto()
    intObjDpiWinHeapSpray = auto()
    intObjDpiWinSecDesc = auto()
    intObjDpiWinAclEdit = auto()


class StateObject(Enum):
    stateUnknown = auto()
    stateOriginator = auto()
    stateVictim = auto()
    stateMisc = auto()


description_objects = {
    EnumObjects.intObjStartOriginator : "Start Originator Object Event",
    EnumObjects.intObjEndOriginator : "End Originator Object Event",
    EnumObjects.intObjStartVictim : "Start Victim Object Event",
    EnumObjects.intObjEndVictim : "End Victim Object Event",
    EnumObjects.intObjStartMisc : "Start Misc Object Event",
    EnumObjects.intObjEndMisc : "End Misc Object Event",

    EnumObjects.intObjVictim : "Victim Object",

    EnumObjects.intObjEpt : "Ept Object",
    EnumObjects.intObjMsr : "Msr Object",
    EnumObjects.intObjCr : "Cr Object",
    EnumObjects.intObjDtr : "Dtr Object",
    EnumObjects.intObjIdt : "Idt Object",
    EnumObjects.intObjIntegrity : "Integrity Object",
    EnumObjects.intObjInjection : "Injection Object",

    EnumObjects.intObjWinProcess : "Windows Process Object",
    EnumObjects.intObjWinProcessParent : "Windows Parent Process Object",
    EnumObjects.intObjLixProcess : "Linux Task Object",
    EnumObjects.intObjLixProcessParent : "Linux Task Parent Object",

    EnumObjects.intObjKernelDriver : "Kernel Driver Object",
    EnumObjects.intObjKernelDriverReturn : "Kernel Driver Return Object",
    EnumObjects.intObjWinKernelDriver : "Windows Kernel Driver Object",
    EnumObjects.intObjWinKernelDriverReturn : "Windows Kernel Driver Return Object",
    EnumObjects.intObjLixKernelModule : "Linux Kernel Module Object",
    EnumObjects.intObjLixKernelModuleReturn : "Linux Kernel Module Return Object",
    EnumObjects.intObjKernelDrvObject : "Kernel Driver Object",

    EnumObjects.intObjWinVad : "Windows Vad Object",
    EnumObjects.intObjLixVma : "Linux Vma Object",

    EnumObjects.intObjWinModule : "Windows Module Object",
    EnumObjects.intObjWinModuleReturn : "Windows Module Retrun Object",

    EnumObjects.intObjInstrux : "Instrux Object",
    EnumObjects.intObjWriteInfo : "Write Info Object",
    EnumObjects.intObjReadInfo : "Read Info Object",
    EnumObjects.intObjExecInfo : "Exec Info Object",
    EnumObjects.intObjArchRegs : "Arch Regs Object",
    EnumObjects.intObjCodeBlocks : "Code Blocks Object",
    EnumObjects.intObjRipCode : "Rip Code Object",
    EnumObjects.intObjRawDump : "Raw Dump Object",
    EnumObjects.intObjExport : "Export Object",
    EnumObjects.intObjDpi : "DPI Object",

    EnumObjects.intObjDpiWinDebug : "Windows DPI Debug Object",
    EnumObjects.intObjDpiWinPivotedStack : "Windows DPI Pivoted Stack Object",
    EnumObjects.intObjDpiWinStolenToken : "Windows DPI Stolen Token Object",
    EnumObjects.intObjDpiWinTokenPrivs : "Windows DPI Token Privs Object",
    EnumObjects.intObjDpiWinThreadStart : "Windows DPI Start Thread Object",
    EnumObjects.intObjDpiWinHeapSpray : "Windows DPI Heap Spray Object",
    EnumObjects.intObjDpiWinSecDesc : "Windows DPI Security Descriptor Object",
    EnumObjects.intObjDpiWinAclEdit : "Windows DPI Acl Edit Object",
}


class String:
    def __init__(self, data):
        self._data = data
        self._offset = 0
        self._size = 0
        self._str_length = None
        self._str_encode = None
        self._str_content = None
        self._encode_enum = { 0 : 'utf-8', 1 : 'utf-16'}

        self._run()

    def _length(self):
        fmt = "<I"
        self._str_length = struct.unpack_from(fmt, self._data, self._offset)[0]
        self._offset += struct.calcsize(fmt)
        self._size +=  struct.calcsize(fmt)

    def _encode(self):
        fmt = "<B"
        self._str_encode = struct.unpack_from(fmt, self._data, self._offset)[0]
        self._offset += struct.calcsize(fmt)
        self._size +=  struct.calcsize(fmt)

    def _content(self):
        fmt = "<%ds" % (self._str_length)
        self._str_content = struct.unpack_from(fmt, self._data, self._offset)[0].decode(self._encode_enum[self._str_encode])
        self._offset += struct.calcsize(fmt)
        self._size += struct.calcsize(fmt)

    def _run(self):
        self._length()
        self._encode()
        self._content()


class Header:
    def __init__(self, type, guest, event, size, arch):
        self._type = type
        self._size = size
        self._guest = guest
        self._event = event
        self._arch = arch
        self._type_description_array = { 0 : "Kernel-Mode", 1 : "User-Mode", 2 : "Kernel-User Mode"}
        self._guest_description_array = {0 : "Unknown", 1 : "Windows", 2 : "Linux"}
        self._arch_description_array = { 0 : "x86", 1 : "x64"}
        self._type_description = self._type_description_array[self._type]
        self._guest_description = self._guest_description_array[self._guest]
        self._arch_description = self._arch_description_array[self._arch]

    def __repr__(self):
        str = f"\tType: {self._type_description} ({self._type})\n"
        str += f"\tSize: {self._size}\n"
        str += f"\tGuest: {self._guest_description} ({self._guest})\n"
        str += f"\tArch: {self._arch_description} ({self._arch})\n"
        str += f"\tEvent: {self._event}"

        return str

class Deserializer:
    def __init__(self, args):
        self._data = args.content
        self._args = args
        self._raw = None
        self._size = None
        self._crt_offset = None
        self._descriptions = None
        self._callbacks = None
        self._file_header = None
        self._state = StateObject.stateUnknown

        self._exception_obj = None

        self._init()
        self._init_exception_object()

    def _init_exception_object(self):
        self._exception_obj = {"Header" : dict(), "Originator" : list(), "Victim" : list(), "Misc" : list()}

    def _init(self):
        self._raw = base64.b64decode(self._data)
        self._crt_offset = 0
        self._size = len(self._raw)
        print("Data length: %d" % (len(self._data)))
        print("Raw length: %d" % (len(self._raw)))

        self._descriptions = description_objects
        self._callbacks = {
                EnumObjects.intObjStartOriginator : { 1 : self._start_originator},
                EnumObjects.intObjEndOriginator : { 1 : self._end_originator},
                EnumObjects.intObjStartVictim : { 1 : self._start_victim},
                EnumObjects.intObjEndVictim : { 1 : self._end_victim},
                EnumObjects.intObjStartMisc : { 1 : self._start_misc},
                EnumObjects.intObjEndMisc : { 1 : self._end_misc},

                EnumObjects.intObjVictim : { 1 : self._victim},

                EnumObjects.intObjEpt : { 1 : self._ept},
                EnumObjects.intObjMsr : { 1 : self._msr},
                EnumObjects.intObjCr : { 1 : self._cr},
                EnumObjects.intObjDtr : { 1 : self._dtr},
                EnumObjects.intObjIdt : { 1 : self._idt},
                EnumObjects.intObjIntegrity : { 1 : self._integrity},
                EnumObjects.intObjInjection : { 1 : self._injection},

                EnumObjects.intObjWinProcess : { 1 : self._win_process},
                EnumObjects.intObjWinProcessParent : { 1 : self._win_process},
                EnumObjects.intObjLixProcess : { 1 : self._lix_task},
                EnumObjects.intObjLixProcessParent : { 1 : self._lix_task},

                EnumObjects.intObjKernelDriver : { 1 : self._kernel_driver},
                EnumObjects.intObjKernelDriverReturn : { 1 : self._kernel_driver},
                EnumObjects.intObjWinKernelDriver : { 1 : self._win_kernel_driver},
                EnumObjects.intObjWinKernelDriverReturn : { 1 : self._win_kernel_driver},
                EnumObjects.intObjLixKernelModule : { 1 : self._lix_kernel_module},
                EnumObjects.intObjLixKernelModuleReturn : { 1 : self._lix_kernel_module},
                EnumObjects.intObjKernelDrvObject : { 1 : self._win_drv_object},

                EnumObjects.intObjWinVad : { 1 : self._win_vad},
                EnumObjects.intObjLixVma : { 1 : self._lix_vma},

                EnumObjects.intObjWinModule : { 1 : self._win_module},
                EnumObjects.intObjWinModuleReturn : { 1 : self._win_module},

                EnumObjects.intObjInstrux : { 1 : self._instrux},
                EnumObjects.intObjWriteInfo : { 1 : self._write_info},
                EnumObjects.intObjReadInfo : { 1 : self._read_info},
                EnumObjects.intObjExecInfo : { 1 : self._exec_info},
                EnumObjects.intObjArchRegs : {1 : self._arch_regs},
                EnumObjects.intObjCodeBlocks : {1 : self._code_blocks},
                EnumObjects.intObjRipCode : { 1 : self._rip_code},
                EnumObjects.intObjRawDump : { 1 : self._raw_dump},
                EnumObjects.intObjExport : { 1 : self._export},
                EnumObjects.intObjDpi : { 1 : self._dpi},

                EnumObjects.intObjDpiWinDebug : { 1 : self._dpi_win_debug },
                EnumObjects.intObjDpiWinPivotedStack : { 1 : self._dpi_win_pivoted_stack },
                EnumObjects.intObjDpiWinStolenToken : { 1 : self._dpi_win_stolen_token },
                EnumObjects.intObjDpiWinTokenPrivs : { 1 : self._dpi_win_tokens_privs },
                EnumObjects.intObjDpiWinThreadStart : { 1 : self._dpi_win_thread_start },
                EnumObjects.intObjDpiWinHeapSpray : { 1 : self._dpi_win_heap_spray },
                EnumObjects.intObjDpiWinSecDesc : { 1 : self._dpi_win_sec_desc },
                EnumObjects.intObjDpiWinAclEdit : { 1 : self._dpi_win_acl_edit },
     }

    def _description(self, enum):
        return self._descriptions[enum]

    def _callback(self, enum, version):
        return self._callbacks[enum][version]()

    def _read_data(self, fmt, offset):
        return struct.unpack_from(fmt, self._crt_raw(), offset)

    def _inc_offset(self, value):
        self._crt_offset += value

    def _crt_raw(self, offset = 0):
        return self._raw[self._crt_offset + offset:]

    def _calc_size(self, fmt):
        return struct.calcsize(fmt)

    def _add_exception_object(self, obj):
        if self._state == StateObject.stateVictim:
            self._exception_obj["Victim"].append(obj)
            return

        if self._state == StateObject.stateOriginator:
            self._exception_obj["Originator"].append(obj)
            return

        if self._state == StateObject.stateMisc:
            self._exception_obj["Misc"].append(obj)
            return

    def _object_header(self):
        offset = 0
        fmt = "<IHH"
        obj = ObjectHeader(*self._read_data(fmt, offset))
        obj.set_description(self._description(EnumObjects(obj.get_type())))

        self._inc_offset(struct.calcsize(fmt))

        return obj

    def _object_enum(self, value):
        return EnumObjects(value)

    def _start_originator(self):
        self._state = StateObject.stateOriginator
        return "-" * 20 + " Originator " + "-" * 20

    def _end_originator(self):
        self._state = StateObject.stateUnknown
        return "-" * 20 + "  " + "-" * 20

    def _start_victim(self):
        self._state = StateObject.stateVictim
        return "-" * 20 + " Victim " + "-" * 20

    def _end_victim(self):
        self._state = StateObject.stateUnknown
        return "-" * 20 + "  " + "-" * 20

    def _start_misc(self):
        self._state = StateObject.stateMisc
        return "-" * 20 + " Victim " + "-" * 20

    def _end_misc(self):
        self._state = StateObject.stateUnknown
        return "-" * 20 + "  " + "-" * 20

    def _integrity(self):
        return "Not implemented"

    def _ept(self):
        offset = 0
        fmt = "<QQB"
        obj = Ept(*self._read_data(fmt, offset))

        return obj

    def _cr(self):
        offset = 0
        fmt = "<I"
        obj = Cr(*self._read_data(fmt, offset))

        return obj

    def _msr(self):
        offset = 0
        fmt = "<I"
        obj = Msr(*self._read_data(fmt, offset))

        return obj

    def _dtr(self):
        offset = 0
        fmt = "<I"
        obj = Dtr(*self._read_data(fmt, offset))

        return obj

    def _idt(self):
        offset = 0
        fmt = "<I"
        obj = Idt(*self._read_data(fmt, offset))

        return obj

    def _victim(self):
        offset = 0
        fmt = "<IIQ"

        obj = Victim(*self._read_data(fmt, offset))

        return obj

    def _injection(self):
        offset = 0
        fmt = "<QII"
        obj = Injection(*self._read_data(fmt, offset))

        return obj

    def _kernel_driver(self):
        offset = 0
        fmt = "<QQQQ"
        obj = KernelDriver(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._section = s._str_content
        offset += s._size

        return obj

    def _win_kernel_driver(self):
        offset = 0
        fmt = "<I"
        obj = WinKernelDriver(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        return obj

    def _win_drv_object(self):
        offset = 0
        fmt = "<QQQ"
        obj = WinDrvObject(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._name= s._str_content
        offset += s._size

        return obj

    def _lix_kernel_module(self):
        offset = 0
        fmt = "<QIIIQIII"
        obj = LixKernelModule(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        return obj

    def _lix_task(self):
        offset = 0
        fmt = "<QQQQQQIII"

        obj = LixTask(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._name = s._str_content
        offset += s._size

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        s = String(self._crt_raw(offset))
        obj._cmd_line = s._str_content
        offset += s._size

        return obj

    def _win_process(self):
        offset = 0
        fmt = "<QQQQQIQQQQ"
        obj = WinProcess(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._name = s._str_content
        offset += s._size

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        s = String(self._crt_raw(offset))
        obj._cmd_line = s._str_content
        offset += s._size

        return obj

    def _lix_vma(self):
        offset = 0
        fmt = "<QQQQQ"
        obj = LixVma(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        return obj

    def _win_vad(self):
        offset = 0
        fmt = "<QQQIIIII"
        obj = WinVad(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        return obj

    def _win_module(self):
        offset = 0
        fmt = "<QI"
        obj = WinModule(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        s = String(self._crt_raw(offset))
        obj._path = s._str_content
        offset += s._size

        return obj

    def _raw_dump(self):
        obj = RawDump()
        offset = 0
        fmt = "<I"
        length = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)
        fmt = "%dB" % (length)
        if length:
            obj._raw = self._read_data(fmt, offset)
            offset += struct.calcsize(fmt)

        return obj

    def _rip_code(self):
        obj = RipCode()
        offset = 0
        fmt = "<I"
        obj._cs_type = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        fmt = "<I"
        length = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)
        fmt = "%dB" % (length)
        if length:
            obj._rip_code = self._read_data(fmt, offset)
            offset += struct.calcsize(fmt)

        return obj

    def _instrux(self):
        obj = Instrux()
        offset = 0
        fmt = "<Q"
        obj._rip = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        fmt = "<16B"
        obj._bytes = self._read_data(fmt, offset)

        return obj

    def _arch_regs(self):
        offset = 0
        fmt = "<28Q"
        obj = ArchRegs(*self._read_data(fmt, offset))

        return obj

    def _code_blocks(self):
        offset = 0
        fmt = "<QQI"
        obj = CodeBlocks(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        fmt = "<I"
        obj._count = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        fmt = "<%dI" % (obj._count)
        if obj._count:
            obj._content = self._read_data(fmt, offset)

        return obj

    def _write_info(self):
        offset = 0
        obj = WriteInfo()
        fmt = "<I"
        obj._access_size = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        for index in range(0, 8):
            fmt = "<Q"
            obj._old_value.append(self._read_data(fmt, offset)[0])
            offset += struct.calcsize(fmt)

        for index in range(0, 8):
            fmt = "<Q"
            obj._new_value.append(self._read_data(fmt, offset)[0])
            offset += struct.calcsize(fmt)

        return obj

    def _read_info(self):
        offset = 0
        obj = ReadInfo()
        fmt = "<I"
        obj._access_size = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        for index in range(0, 8):
            fmt = "<Q"
            obj.value.append(self._read_data(fmt, offset)[0])
            offset += struct.calcsize(fmt)

        return obj

    def _exec_info(self):
        offset = 0
        fmt = "<QQQQ"
        obj = ExecInfo(*self._read_data(fmt, offset))

        return obj

    def _export(self):
        offset = 0
        obj = Export()
        fmt = "<I"
        obj._count = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        fmt = "<I"
        obj._delta = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        obj._exports = list()
        for index in range(0, obj._count):
            str = String(self._crt_raw(offset))
            obj._exports.append(str._str_content)
            offset += str._size

        return obj

    def _dpi(self):
        offset = 0
        obj = Dpi()
        fmt = "<I"
        obj._flags = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_pivoted_stack(self):
        offset = 0
        fmt = "<QQQQQQ"
        obj = DpiWinPivotedStack(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        obj._trap_frame_content = self._raw[self._crt_offset + offset: self._crt_offset + offset + 512]

        obj._arch = self._file_header._arch

        return obj

    def _dpi_win_debug(self):
        offset = 0
        fmt = "<Q"
        obj = DpiWinDebug(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_stolen_token(self):
        offset = 0
        fmt = "<Q"
        obj = DpiWinStolenToken(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_tokens_privs(self):
        offset = 0
        fmt = "<QQQQ"
        obj = DpiWinTokenPrivs(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_thread_start(self):
        offset = 0
        fmt = "<QQ"
        obj = DpiWinStartThread(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        fmt = "%dB" % 0x1000
        obj._start_page = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_heap_spray(self):
        offset = 0
        obj = DpiWinHeapSpray()

        fmt = "<%dI" % 0xF
        obj._heap_pages = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)

        fmt = "<Q"
        obj._shellcode_flags = self._read_data(fmt, offset)[0]
        offset += struct.calcsize(fmt)

        fmt = "%dB" % 0x1000
        obj._detected_page = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)

        fmt = "%dB" % 0x1000
        obj._max_heap_val_page_content = self._read_data(fmt, offset)
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_sec_desc(self):
        offset = 0
        fmt = "<QQQQQQQ"
        obj = DpiWinSecDesc(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        return obj

    def _dpi_win_acl_edit(self):
        offset = 0
        fmt = "<QQQQ"
        obj = DpiWinAclEdit(*self._read_data(fmt, offset))
        offset += struct.calcsize(fmt)

        return obj

    def _header(self):
        offset = 0
        fmt = "<IIIHI"
        obj = Header(*self._read_data(fmt, offset))

        self._inc_offset(struct.calcsize(fmt))

        return obj

    def run(self):
        self._file_header = self._header()
        if self._args.alert:
            print(self._file_header)

        self._exception_obj["Header"]["Type"] = self._file_header._type
        self._exception_obj["Header"]["Guest"] = self._file_header._guest
        self._exception_obj["Header"]["Event"] = self._file_header._event

        while self._crt_offset < self._size:
            header = self._object_header()
            obj = self._callback(self._object_enum(header._type), header._version)
            if not isinstance(obj, str):
                obj._object_type = EnumObjects(header._type)

            if self._args.exception and not isinstance(obj, str):
                self._add_exception_object(obj)

            self._inc_offset(header._size)
            if self._args.alert:
                print(header)
                print(obj)
