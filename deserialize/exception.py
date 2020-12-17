#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import json

from enum import Enum, auto
from objects import *

from exobj import *
from deserializer import *


class Exception:
    def __init__(self, data):
        self._data = data
        self._originator = self._data["Originator"]
        self._victim = self._data["Victim"]
        self._misc = self._data["Misc"]
        self._header = self._data["Header"]

        self._callback = {
                IntroEventEnum.introEventEptViolation              : self._ept,
                IntroEventEnum.introEventMsrViolation              : self._msr,
                IntroEventEnum.introEventCrViolation               : self._cr,
                IntroEventEnum.introEventIntegrityViolation        : self._integrity,
                IntroEventEnum.introEventInjectionViolation        : self._injection,
                IntroEventEnum.introEventDtrViolation              : self._dtr,
                IntroEventEnum.introEventProcessCreationViolation  : self._process_creation,
                IntroEventEnum.introEventModuleLoadViolation       : self._module_load
        }

        self._exception_json = ExceptionJson()
        self._signature_json = SignatureJson()

        self._init()

    def _init(self):
        self._exception_json.Type = self._alert_type()
        self._signature_json.Type = self._alert_type()

    def _alert_type(self):
        return {0 : "kernel", 1 : "user", 2 : "kernel-user"}[self._data["Header"]["Type"]];

    def _process_name(self, data):
        for item in data:
            if isinstance(item, WinProcess) and item._object_type == EnumObjects.intObjWinProcess:
                return item._name
            if isinstance(item, LixTask) and item._object_type == EnumObjects.intObjLixProcess:
                return item._name

    def _win_module_name(self, data):
        for item in data:
            print(globals())
            if isinstance(item, WinModule) and item._object_type == EnumObjects.intObjWinModule:
                return item._path.split("/")[-1]

    def _win_module_name_return(self, data):
        for item in data:
            if isinstance(item, WinModule) and item._object_type == EnumObjects.intObjWinModuleReturn:
                return item._path.split("/")[-1]

    def _victim_object(self):
        for item in self._victim:
            if isinstance(item, Victim):
                return item
        raise ValueError("Victim object not found!")

    def _object_type(self, type):
        self._exception["Exception"][self._exception_index]["object_type"] = KmExceptionType(type)

    def _kernel_driver_name_original(self, data):
        for item in data:
            if isinstance(item, WinKernelDriver) and item._object_type == EnumObjects.intObjWinKernelDriver:
                return item._path.split("\\")[-1]
            if isinstance(item, LixKernelModule) and item._object_type == EnumObjects.intObjLixKernelModule:
                return item._path.split("\\")[-1]
        return None

    def _kernel_driver_object_name(self, data):
        for item in data:
            if isinstance(item, WinDrvObject):
                return item._name
        return None

    def _kernel_driver_obj_name(self, data):
        for item in data:
            if isinstance(item, WinDrvObj):
                return item._name
        return None

    def _kernel_driver_return_name(self, data):
        for item in data:
            if isinstance(item, WinKernelDriver) and item._object_type == EnumObjects.intObjWinKernelDriverReturn:
                return item._path.split("\\")[-1]
            if isinstance(item, LixKernelModule) and item._object_type == EnumObjects.intObjLixKernelModuleReturn:
                return item._path.split("\\")[-1]
        return None

    def _kernel_driver_name(self, data):
        name = self._kernel_driver_return_name(data)
        if not name:
            name = self._kernel_driver_return_name(data)
        return name.rstrip('\x00')

    def _flags_guest(self):
        if GuestTypeEnum(self._header["Guest"]) == GuestTypeEnum.guestTypeLinux:
            return " linux "
        else:
            return " "

    def _flags_append(self, *flags):
        arr = " "
        for flag in flags:
            arr += exec_flags[flag]
            arr += " "

        return arr

    def _cr_object(self, data):
        for item in self._victim:
            if isinstance(item, Cr):
                return item
        return None

    def _msr_object(self, data):
        for item in data:
            if isinstance(item, Msr):
                return item
        return None

    def _ept_km(self):
        victim = self._victim_object()
        ept = self._ept_object(self._victim)

        obj = KernelModeException()
        obj.flags = self._flags_guest()
        obj.flags = self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)
        obj.flags += self._flags_ept(ept._type)

        obj.originator = self._kernel_driver_name(self._originator)

        if victim._intro_object_type in [IntroObjectTypeEnum.KmModule, IntroObjectTypeEnum.Ssdt, IntroObjectTypeEnum.Vdso, IntroObjectTypeEnum.Vsyscall]:
            if victim._intro_object_type == IntroObjectTypeEnum.Vdso:
                obj.victim = self._exec_name(KmExecNameEnum.kmExcNameVdso)
            elif victim._intro_object_type == IntroObjectTypeEnum.Vsyscall:
                obj.victim = self._exec_name(KmExecNameEnum.kmExcNameVsyscall)
            else:
                obj.victim = self._kernel_driver_name_original(self._victim)

            if victim._intro_object_type == IntroObjectTypeEnum.Ssdt:
                obj.object_type = self._object_type(KmObjectType.kmObjSsdt)

            if victim._zone_flags & ZONE_LIB_IMPORTS:
                obj.object_type = self._object_type(KmObjectType.kmObjDriverImports)
            elif victim._zone_flags & ZONE_LIB_EXPORTS:
                obj.object_type = self._object_type(KmObjectType.kmObjDriverExports)
            elif victim._zone_flags & ZONE_LIB_CODE:
                obj.object_type = self._object_type(KmObjectType.kmObjDriverCode)
            elif victim._zone_flags & ZONE_LIB_DATA:
                obj.object_type = self._object_type(KmObjectType.kmObjDriverData)
            elif victim._zone_flags & ZONE_LIB_RESOURCES:
                obj.object_type = self._object_type(KmObjectType.kmObjDriverResource)
            else:
                raise ValueError("Invalid intro object type!")

        elif victim._intro_object_type in [IntroObjectTypeEnum.DriverObject, IntroObjectTypeEnum.FastIoDispatch]:
            obj.victim = self._kernel_driver_object_name(self._victim)

            if victim._intro_object_type == IntroObjectTypeEnum.DriverObject:
                obj.object_type = self._object_type(KmObjectType.kmObjDrvObj)
            if victim._object_type == IntroObjectTypeEnum.FastIoDispatch:
                obj.object_type = self._object_type(KmObjectType.kmObjFastIo)

        elif victim._intro_object_type == IntroObjectTypeEnum.Idt:
            obj.victim = self._exec_name(KmExecNameEnum.kmExcNameAny)
            obj.object_type = self._object_type(KmObjectType.kmObjIdt)

        elif victim._intro_object_type in IntroObjectTypeEnum.KmLoggerContext:
            obj.victim = self._exec_name(KmExecNameEnum.kmExcNameAny)
            obj.object_type = self._object_type(KmObjectType.kmObjLoggerCtx)
        else:
            raise ValueError("Invalid intro object type!")

        idt = self._idt_signature()
        if idt:
            self._signature_append(idt)
            obj.signature.append(idt.sig_id)

        codeblocks = self._codeblock_signature()
        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)

        self._exception_json.Exceptions.append(obj)

    def _ept_km_um(self):
        victim = self._victim_object()
        ept = self._ept_object(self._misc)

        obj = KernelUserModeException()
        obj.flags = self._flags_guest()
        obj.flags = self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)
        obj.flags += self._flags_ept(ept._type)

        obj.originator = self._kernel_driver_name(self._originator)

        if victim._intro_object_type in [IntroObjectTypeEnum.UmModule]:
            if victim._zone_flags & ZONE_LIB_IMPORTS:
                obj.object_type = self._object_type(KmUmObjectType.kmUmObjModuleImports)
            elif victim._zone_flags & ZONE_LIB_EXPORTS:
                obj.object_type = self._object_type(KmUmObjectType.kmUmObjModuleExports)
            else:
                obj.object_type = self._object_type(KmUmObjectType.kmUmObjModule)
        else:
            raise ValueError("Invalid victim type %d!", victim._object_type)

        if ept._type != EPT_HOOK_EXECUTE:
            obj.victim = self._module_name_original(self._victim)
        else:
            obj.victim = self._exec_name(UmExcNameEnum.umExcNameNone)

        obj.process = self._process_name(self._victim)
        if not obj.process:
            raise ValueError("Invalid process!")

        codeblocks = self._codeblock_signature()
        export = self._export_signature()

        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)
        if export:
            obj.signature.append(export.sig_id)
            self._signature_append(export)

        self._exception_json.Exceptions.append(obj)

    def _injection_object(self, data):
        for item in data:
            if isinstance(item, Injection):
                return item
        return  None

    def _library_name_original(self, data):
        for item in data:
            if isinstance(item, WinModule):
                return item._path.split('\\')[-1].rstrip('\x00')
        return None


    def _module_name_original(self, data):
        for item in data:
            if isinstance(item, WinModule) and item._object_type == EnumObjects.intObjWinModule:
                return item._path.split('\\')[-1].rstrip('\x00')
        return None

    def _module_name_return(self, data):
        for item in data:
            if isinstance(item, WinModule) and item._object_type == EnumObjects.intObjWinModule:
                    return item._path.split('\\')[-1].rstrip('\x00')
        return None

    def _module_name(self, data):
        name = self._module_name_original(data)
        if not name:
            name = self._module_name_return(data)
        return name

    def _process_name(self, data):
        for item in data:
            if isinstance(item, WinProcess) and item._object_type == EnumObjects.intObjWinProcess:
                return item._name.split('\\')[-1].rstrip('\x00')

            if isinstance(item, LixTask) and item._object_type == EnumObjects.intObjLixProcess:
                return item._name.split('\\')[-1].rstrip('\x00')

        return None

    def _dpi_object(self, data):
        for item in data:
            if isinstance(item, Dpi):
                return item

        return None

    def _ept(self):
        { 0 : self._ept_km , 1 : self._ept_um, 2 : self._ept_km_um }[self._header["Type"]]()


    def _ept_object(self, data):
        for item in data:
            if isinstance(item, Ept):
                return item
        raise ValueError("Ept object not found!")

    def _object_type_um(self, type):
        return um_obj_type[type]

    def _object_type_km(self, type):
        return km_obj_type[type]

    def _object_type_km_um(self, type):
        return km_um_obj_type[type]

    def _object_type(self, type):
        return { 0 : self._object_type_km , 1 : self._object_type_um, 2: self._object_type_km_um}[self._header["Type"]](type)

    def _exec_name_um(self, type):
        return um_exc_name[type]

    def _exec_name_km(self, type):
        return km_exec_name[type]

    def _exec_name(self, type):
        return { 0 : self._exec_name_km , 1 : self._exec_name_um }[self._header["Type"]](type)

    def _flags_ept(self, type):
        return { EPT_HOOK_NONE : "" ,
            EPT_HOOK_READ : self._flags_append(ExecFlagEnum.execFlagRead),
            EPT_HOOK_WRITE : self._flags_append(ExecFlagEnum.execFlagWrite),
            EPT_HOOK_EXECUTE : self._flags_append(ExecFlagEnum.execFlagExecute),
            }[type]

    def _signature_append(self, obj):
        self._signature_json.Signatures.append(obj)


    def _integrity(self):
        victim = self._victim_object()

        obj = KernelModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagWrite, ExecFlagEnum.execKmFlagIntegrity)
        obj.object_type = self._object_type(KmObjectType.kmObjNone)

        if victim._intro_object_type == IntroObjectTypeEnum.DriverObject:
            obj.object_type = self._object_type(KmObjectType.kmObjDrvObj)

        if victim._intro_object_type == IntroObjectTypeEnum.FastIoDispatch:
            obj.object_type = self._object_type(KmObjectType.kmObjFastIo)

        if victim._intro_object_type == IntroObjectTypeEnum.KmLoggerContext:
            obj.object_type = self._object_type(KmObjectType.kmObjLoggerCtx)

        if victim._intro_object_type == IntroObjectTypeEnum.SecDesc:
            obj.object_type = self._object_type(KmObjectType.kmObjSecDesc)

        if victim._intro_object_type == IntroObjectTypeEnum.AclEdit:
            obj.object_type = self._object_type(KmObjectType.kmObjAclEdit)

        obj.originator = self._kernel_driver_name_original(self._originator)

        if victim._intro_object_type != IntroObjectTypeEnum.KmLoggerContext:
            obj.victim = self._kernel_driver_object_name(self._victim)
        else:
            obj.victim = self._kernel_driver_name_original(self._victim)

        self._exception_json.Exceptions.append(obj)

    def _dtr(self):
        victim = self._victim_object()
        if not victim:
            raise ValueError("Unknown Dtr object!")

        obj = KernelModeException()

        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagWrite)
        obj.object_type = self._object_type(KmObjectType.kmObjNone)

        if victim._intro_object_type == IntroObjectTypeEnum.Gdtr:
            obj.object_type = self._object_type(KmObjectType.kmObjGdtr)

        if victim._intro_object_type == IntroObjectTypeEnum.Idtr:
            obj.object_type = self._object_type(KmObjectType.kmObjIdtr)

        obj.originator = self._kernel_driver_name_original(self._originator)
        obj.victim = self._exec_name(KmExecNameEnum.kmExcNameAny)

        codeblocks = self._codeblock_signature()
        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)

        self._exception_json.Exceptions.append(obj)


    def _msr(self):
        msr = self._msr_object(self._victim)
        if not msr:
            raise ValueError("Unknown Msr object!")

        obj = KernelModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagWrite)
        obj.object_type = self._object_type(KmObjectType.kmObjMsr)

        obj.originator = self._kernel_driver_name_original(self._originator)
        obj.victim = self._exec_name(KmExecNameEnum.kmExcNameAny)

        codeblocks = self._codeblock_signature()
        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)

        self._exception_json.Exceptions.append(obj)


    def _cr(self):
        cr = self._cr_object(self._victim)
        if not cr:
            raise ValueError("Unknown Cr object!")

        obj = KernelModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagWrite,
                                        ExecFlagEnum.execKmFlagSmap, ExecFlagEnum.execKmFlagSmep)

        obj.originator = self._kernel_driver_name_original(self._originator)
        obj.victim = self._exec_name(KmExecNameEnum.kmExcNameAny)
        obj.object_type = self._object_type(KmObjectType.kmObjCr4)

        codeblocks = self._codeblock_signature()

        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)

        self._exception_json.Exceptions.append(obj)


    def _process_creation(self):
        obj = UserModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagExecute);

        dpi = self._dpi_object(self._misc)
        if dpi:
            obj.object_type = self._object_type(UmObjectType.umObjProcessCreationDpi)
        else:
            obj.object_type = self._object_type(UmObjectType.umObjProcessCreation)

        obj.process = self._exec_name(UmExcNameEnum.umExcNameAny)
        obj.originator = self._process_name(self._originator)
        obj.victim = self._process_name(self._victim)

        signature = self._dpi_signature()
        if signature:
            self._signature_append(signature)
            obj.signature.append(signature.sig_id)

        self._exception_json.Exceptions.append(obj)


    def _module_load(self):
        obj = UserModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64, ExecFlagEnum.execFlagWrite)

        obj.object_type = self._object_type(UmObjectType.umObjModuleLoad)

        obj.process =  self._process_name(self._victim)
        obj.originator = self._process_name(self._originator)
        obj.victim = self._module_name_original(self._victim)

        self._exception_json.Exceptions.append(obj)


    def _injection(self):
        injection = self._injection_object(self._misc)
        if not injection:
            raise ValueError("Unknown injection object!")

        obj = UserModeException()
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)

        obj.object_type = self._object_type(UmObjectType.umObjNone)

        obj.process =  self._exec_name(UmExcNameEnum.umExcNameAny)
        obj.originator = self._process_name(self._originator)
        obj.victim = self._process_name(self._victim)

        if injection._type == InjectionTypeEnum.injectionViolationRead:
            obj.flags += self._flags_append(ExecFlagEnum.execFlagRead)
            obj.object_type = self._object_type(UmObjectType.umObjProcess)

        if injection._type == InjectionTypeEnum.injectionViolationWrite:
            obj.flags += self._flags_append(ExecFlagEnum.execFlagWrite)
            obj.object_type = self._object_type(UmObjectType.umObjProcess)

        if injection._type == InjectionTypeEnum.injectionViolationQueueApcThread:
            obj.object_type = self._object_type(UmObjectType.umObjProcessApcThread)

        if injection._type == InjectionTypeEnum.injectionViolationSetContextThread:
            obj.object_type = self._object_type(UmObjectType.umObjProcessThreadContext)

        export = self._export_signature()

        if export:
            obj.signature.append(export.sig_id)
            self._signature_append(export)

        self._exception_json.Exceptions.append(obj)

    def _ept_um(self):
        victim = self._victim_object()
        if not victim:
            raise ValueError("Unknown victim object!")
        ept = self._ept_object(self._misc)
        if not ept:
            raise ValueError("Unknown ept object!")

        obj = UserModeException()
        obj.object_type = self._object_type(UmObjectType.umObjNone)
        obj.flags = self._flags_guest()
        obj.flags += self._flags_ept(ept._type)
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)

        if victim._intro_object_type == IntroObjectTypeEnum.UmModule:
            if victim._zone_flags & ZONE_LIB_IMPORTS:
                obj.object_type = self._object_type(UmObjectType.umObjModuleImports)
            elif victim._zone_flags & ZONE_LIB_EXPORTS:
                obj.object_type = self._object_type(UmObjectType.umObjModuleExports)
            else:
                obj.object_type = self._object_type(UmObjectType.umObjModule)
        else:
            obj.object_type = self._object_type(UmObjectType.umObjProcess)

        if ept._type != EPT_HOOK_EXECUTE:
            obj.originator = self._module_name(self._originator)
            obj.victim = self._module_name_original(self._victim)
        else:
            obj.originator = self._exec_name(UmExcNameEnum.umExcNameAny)
            obj.victim = self._exec_name(UmExcNameEnum.umExcNameNone)

        obj.process = self._process_name(self._originator)

        codeblocks = self._codeblock_signature()
        export = self._export_signature()

        if codeblocks:
            self._signature_append(codeblocks)
            obj.signature.append(codeblocks.sig_id)
        if export:
            obj.signature.append(export.sig_id)
            self._signature_append(export)

        self._exception_json.Exceptions.append(obj)

    def _export_obj(self):
        for item in self._misc:
            if isinstance(item, Export):
                return item
        return None

    def _export_signature(self):
        export = self._export_obj()
        if not export:
            return None

        obj = ExportSignature()
        obj.sig_id = "export-sig"
        obj.library = self._library_name_original(self._victim)
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)

        for item in export._exports:
            data = ExportHash(item, export._delta)
            obj.hashes.append(data)

        return obj

    def _idt_object(self):
        for item in self._victim:
            if isinstance(item, Idt):
                return item
        return None

    def _idt_signature(self):
        idt = self._idt_object()
        if not idt:
            return None

        obj = IdtSignature()
        obj.sig_id = "idt-sig"
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)
        obj.entry = idt._entry

        return obj

    def _codeblocks_object(self):
        for item in self._misc:
            if isinstance(item, CodeBlocks):
                return item

        return None

    def _codeblock_signature(self):
        min_cb = 6
        codeblocks = self._codeblocks_object()
        if not codeblocks:
            return None

        obj = CodeBlocksSignature()
        obj.sig_id = "codeblocks-sig"

        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)

        offset = 0
        exec_alert = False      # todo -> get from ept alert
        if not exec_alert:
            if codeblocks._rip_cb_index < (min_cb // 2):
                offset = 0
            elif codeblocks._rip_cb_index + min_cb // 2 >= codeblocks._count:
                if codeblocks._count >= min_cb:
                    offset = codeblocks._count - min_cb
                else:
                    offset = 0
            else:
                offset = codeblocks._rip_cb_index - (min_cb // 2)

        count = min(codeblocks._count, min_cb)
        if count == 0:
            return None

        obj.score = max(count - 1, 1)

        obj.hashes = list(codeblocks._content[offset:offset + count])
        obj.hashes.sort()

        obj.hashes = [str(hex(x)) for x in obj.hashes]

        return obj

    def _dpi_signature(self):
        dpi = self._dpi_object(self._misc)
        if not dpi:
            return None

        obj = DpiSignature()
        obj.sig_id = "process-creation-sig"
        obj.flags = self._flags_guest()
        obj.flags += self._flags_append(ExecFlagEnum.execFlag32, ExecFlagEnum.execFlag64)

        print("0000000")
        print(ProcessCreationFlagsEnum.processCreationDebug.value[0])

        print("0000000")

        if dpi._flags & ProcessCreationFlagsEnum.processCreationDebug.value[0]:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationDebug])

        if dpi._flags & ProcessCreationFlagsEnum.processCreationStolenToken.value[0]:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationStolenToken])

        if dpi._flags & ProcessCreationFlagsEnum.processCreationPivotedStack.value[0]:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationPivotedStack])

        if dpi._flags & ProcessCreationFlagsEnum.processCreationHeapSpray.value:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationHeapSpray])
            
        if dpi._flags & ProcessCreationFlagsEnum.processCreationSecDesc.value:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationSecDesc])

        if dpi._flags & ProcessCreationFlagsEnum.processCreationAclEdit.value:
            obj.create_mask.append(um_process_creation_flags[ProcessCreationFlagsEnum.processCreationAclEdit])

        return obj

    def run(self):
        print("Guest: %d, Type %d, Event: %d" % (self._header["Guest"], self._header["Type"], self._header["Event"]))
        event = IntroEventEnum(self._header["Event"])
        self._callback[event]()

        print("-" * 20 + " Exception JSON " + "-" * 20)
        print(self._exception_json)
        print("-" * 60)

        print("-" * 20 + " Signature JSON " + "-" * 20)
        print(self._signature_json)
        print("-" * 60)
