#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
"""

"""

import r2wrapper
import r2structs
import r2functions
from collections import namedtuple
import sys
import argparse

CamiNtoskrnl = namedtuple('CamiNtoskrnl', 'robj struct_factory ntbuildnumber kpti guest64')
CamiNtdll = namedtuple('CamiNtdll', 'robj guest64')
CamiFieldGroup = namedtuple('CamiFieldGroup', 'name fields')
CamiField = namedtuple('CamiField', 'name struct type value')
CamiFunction = namedtuple('CamiFunction', 'name args32 args64')
CamiArguments = namedtuple('CamiArgument', 'minver list')

km_fields = [
    CamiFieldGroup('Process', [
        CamiField('Cr3',                  '_EPROCESS',        'offset',   ['Pcb', 'DirectoryTableBase']),
        CamiField('UserCr3',              '_EPROCESS',        'offset',   ['Pcb', 'UserDirectoryTableBase']),
        CamiField('KexecOptions',         '_EPROCESS',        'offset',   ['Pcb', 'Flags']),
        CamiField('ListEntry',            '_EPROCESS',        'offset',   ['ActiveProcessLinks']),
        CamiField('Name',                 '_EPROCESS',        'offset',   ['ImageFileName']),
        CamiField('SectionBase',          '_EPROCESS',        'offset',   ['SectionBaseAddress']),
        CamiField('Id',                   '_EPROCESS',        'offset',   ['UniqueProcessId']),
        CamiField('ParentPid',            '_EPROCESS',        'offset',   ['InheritedFromUniqueProcessId']),
        CamiField('VadRoot',              '_EPROCESS',        'offset',   ['VadRoot']),
        CamiField('CreateTime',           '_EPROCESS',        'offset',   ['CreateTime']),
        CamiField('ExitStatus',           '_EPROCESS',        'offset',   ['ExitStatus']),
        CamiField('Token',                '_EPROCESS',        'offset',   ['Token']),
        CamiField('ObjectTable',          '_EPROCESS',        'offset',   ['ObjectTable']),
        CamiField('Peb',                  '_EPROCESS',        'offset',   ['Peb']),
        CamiField('ThreadListHead',       '_EPROCESS',        'offset',   ['Pcb', 'ThreadListHead']),
        CamiField('WoW64',                '_EPROCESS',        'offset',   ['WoW64Process']),
        CamiField('Flags',                '_EPROCESS',        'offset',   ['Flags']),
        CamiField('Flags3',               '_EPROCESS',        'offset',   ['Flags3']),
        CamiField('MitigationFlags',      '_EPROCESS',        'offset',   ['MitigationFlags']),
        CamiField('MitigationFlags2',     '_EPROCESS',        'offset',   ['MitigationFlags2']),
        CamiField('DebugPort',            '_EPROCESS',        'offset',   ['DebugPort']),
        CamiField('Spare',                '_EPROCESS',        'offset',   ['Pcb', 'Spare1']),
        ]),
    CamiFieldGroup('Thread', [
        CamiField('Process',              '_ETHREAD',         'offset',   ['Tcb', 'Process']),
        CamiField('ThreadListEntry',      '_ETHREAD',         'offset',   ['Tcb', 'ThreadListEntry']),
        CamiField('KernelStack',          '_ETHREAD',         'offset',   ['Tcb', 'KernelStack']),
        CamiField('StackBase',            '_ETHREAD',         'offset',   ['Tcb', 'StackBase']),
        CamiField('StackLimit',           '_ETHREAD',         'offset',   ['Tcb', 'StackLimit']),
        CamiField('State',                '_ETHREAD',         'offset',   ['Tcb', 'State']),
        CamiField('WaitReason',           '_ETHREAD',         'offset',   ['Tcb', 'WaitReason']),
        CamiField('AttachedProcess',      '_ETHREAD',         'offset',   ['Tcb', 'ApcState', 'Process']),
        CamiField('Teb',                  '_ETHREAD',         'offset',   ['Tcb', 'Teb']),
        CamiField('Id',                   '_ETHREAD',         'offset',   ['Cid', 'UniqueThread']),
        CamiField('ClientSecurity',       '_ETHREAD',         'offset',   ['ClientSecurity']),
        CamiField('TrapFrame',            '_ETHREAD',         'offset',   ['Tcb', 'TrapFrame']),
        ]),
    CamiFieldGroup('DrvObj', [
        CamiField('Size',                 '_DRIVER_OBJECT',   'sizeof',   None),
        CamiField('FiodispSize',          '_FAST_IO_DISPATCH','sizeof',   None),
        CamiField('AllocationGap',        None,               'constant', [0x28, 0x50]),
        CamiField('Fiodisp',              '_DRIVER_OBJECT',   'offset',   ['FastIoDispatch']),
        CamiField('Start',                '_DRIVER_OBJECT',   'offset',   ['DriverStart']),
        ]),
    CamiFieldGroup('Pcr', [
        CamiField('CurrentThread',        '_KPCR',            'offset',   ['Prcb', 'CurrentThread']),
        CamiField('UserTime',             '_KPCR',            'offset',   ['Prcb', 'UserTime']),
        ]),
    CamiFieldGroup('PoolDescriptor', [
        CamiField('TotalBytes',           '_POOL_DESCRIPTOR', 'offset',   ['BytesAllocated']),
        CamiField('NppSize',              None,               'constant', [2147483648, 2147483648]),
        ]),
    CamiFieldGroup('Mmpfn', [
        CamiField('Size',                 '_MMPFN',           'sizeof',   None),
        CamiField('Pte',                  '_MMPFN',           'offset',   ['PteAddress']),
        CamiField('RefCount',             '_MMPFN',           'offset',   ['u3', 'ReferenceCount']),
        CamiField('Flags',                '_MMPFN',           'offset',   ['u3', 'e1']),
        CamiField('PaeSize',              '_MMPFN',           'sizeof',   None),
        CamiField('PaePte',               '_MMPFN',           'offset',   ['PteAddress']),
        CamiField('PaeRefCount',          '_MMPFN',           'offset',   ['u3', 'ReferenceCount']),
        CamiField('PaeFlags',             '_MMPFN',           'offset',   ['u3', 'e1']),
        ]),
    CamiFieldGroup('Token', [
        CamiField('Privs',                '_TOKEN',           'offset',   ['Privileges']),
        CamiField('UserCount',            '_TOKEN',           'offset',   ['UserAndGroupCount']),
        CamiField('RestrictedCount',      '_TOKEN',           'offset',   ['RestrictedSidCount']),
        CamiField('Users',                '_TOKEN',           'offset',   ['UserAndGroups']),
        CamiField('RestrictedSids',       '_TOKEN',           'offset',   ['RestrictedSids']),
        ]),
    CamiFieldGroup('Ungrouped', [
        CamiField('CtlAreaFile',          '_CONTROL_AREA',    'offset',   ['FilePointer']),
        CamiField('HandleTableTableCode', '_HANDLE_TABLE',    'offset',   ['TableCode']),
        CamiField('HalIntCtrlType',       None,               'constant', [0, 0]),
        CamiField('WmiGetClockOffset',    '_WMI_LOGGER_CONTEXT', 'offset',['GetCpuClock']),
        CamiField('EtwDbgDataSiloOffset', None,               'constant', [16, 16]),
        CamiField('EtwSignatureOffset',   None,               'constant', [4294967294, 4294967294]),
        CamiField('SubsectionCtlArea',    '_CONTROL_AREA',    'offset',   ['Subsection']),
        ]),
    CamiFieldGroup('EprocessFlags', [
        CamiField('NoDebugInherit',       '_EPROCESS',        'bitfield', ['NoDebugInherit']),
        CamiField('Exiting',              '_EPROCESS',        'bitfield', ['ProcessExiting']),
        CamiField('Delete',               '_EPROCESS',        'bitfield', ['ProcessDelete']),
        CamiField('3Crashed',             '_EPROCESS',        'bitfield', ['Crashed']),
        CamiField('VmDeleted',            '_EPROCESS',        'bitfield', ['VmDeleted']),
        CamiField('HasAddrSpace',         '_EPROCESS',        'bitfield', ['HasAddressSpace']),
        ]),
    CamiFieldGroup('VadShort', [
        CamiField('Parent',               '_MMVAD_SHORT',     'offset',   ['VadNode', 'ParentValue']),
        CamiField('Left',                 '_MMVAD_SHORT',     'offset',   ['VadNode', 'Left']),
        CamiField('Right',                '_MMVAD_SHORT',     'offset',   ['VadNode', 'Right']),
        CamiField('StartingVpn',          '_MMVAD_SHORT',     'offset',   ['StartingVpn']),
        CamiField('StartingVpnHigh',      '_MMVAD_SHORT',     'offset',   ['StartingVpnHigh']),
        CamiField('EndingVpn',            '_MMVAD_SHORT',     'offset',   ['EndingVpn']),
        CamiField('EndingVpnHigh',        '_MMVAD_SHORT',     'offset',   ['EndingVpnHigh']),
        CamiField('Flags',                '_MMVAD_SHORT',     'offset',   ['u', 'VadFlags']),
        CamiField('FlagsSize',            '_MMVAD_FLAGS',     'sizeof',   None),
        CamiField('VpnSize',              '_MMVAD_SHORT',     'sizeof',   ['StartingVpn']),
        CamiField('Size',                 '_MMVAD_SHORT',     'sizeof',   None),
        ]),
    CamiFieldGroup('VadLong', [
        CamiField('Subsection',           '_MMVAD',           'offset',   ['Subsection']),
        ]),
    CamiFieldGroup('VadFlags', [
        CamiField('TypeShift',            '_MMVAD_FLAGS',     'bitpos',   ['VadType']),
        CamiField('TypeMask',             '_MMVAD_FLAGS',     'bitmask',  ['VadType']),
        CamiField('ProtectionShift',      '_MMVAD_FLAGS',     'bitpos',   ['Protection']),
        CamiField('ProtectionMask',       '_MMVAD_FLAGS',     'bitmask',  ['Protection']),
        CamiField('NoChangeBit',          '_MMVAD_FLAGS',     'bitpos',   ['NoChange']),
        CamiField('PrivateFixup',         '_MMVAD_FLAGS',     'bitpos',   ['PrivateFixup']),
        CamiField('DeleteInProgress',     '_MMVAD_FLAGS',     'bitpos',   ['DeleteInProgress']),
        ]),
    CamiFieldGroup('SyscallNumbers', [
        CamiField('NtWriteVirtualMemory', None,               'syscall',  None),
        CamiField('NtProtectVirtualMemory', None,             'syscall',  None),
        CamiField('NtCreateThreadEx',     None,               'syscall',  None),
        ]),
    CamiFieldGroup('FileObject', [
        CamiField('NameBuffer',           '_FILE_OBJECT',     'offset',   ['FileName', 'Buffer']),
        CamiField('NameLength',           '_FILE_OBJECT',     'offset',   ['FileName', 'Length']),
        ])
    ]

um_fields = [
    CamiFieldGroup('Peb', [
        CamiField('64Size', '_PEB',   'sizeof', None),
        CamiField('32Size', '_PEB32', 'sizeof', None)
        ]),
    CamiFieldGroup('Teb', [
        CamiField('64Size', '_TEB',   'sizeof', None),
        CamiField('32Size', '_TEB32', 'sizeof', None),
        CamiField('Wow64SaveArea', None, 'constant', [0x1488, 0x1488]),
        CamiField('Wow64StackInSaveArea', None, 'constant', [0xc8, 0xc8]),
        ])
    ]

functions = [
    CamiFunction('KeBugCheck2', [], []),
    CamiFunction('MiInsertVad', 
        [
            CamiArguments(18363, ['DET_ARG_RCX', 'DET_ARG_RDX'])
        ],
        []
        ),
    CamiFunction('KiDispatchException',
        [
            CamiArguments(0, ['DET_ARG_STACK1', 'DET_ARG_STACK2', 'DET_ARG_STACK3', 'DET_ARG_STACK4'])
        ],
        []
        ),
    CamiFunction('KiDisplayBlueScreen', [], []),
    CamiFunction('MiCommitExistingVad',
        [
            CamiArguments(9600, ['DET_ARG_RCX', 'DET_ARG_RDX', 'DET_ARG_STACK1', 'DET_ARG_STACK2']),
            CamiArguments(0, ['DET_ARG_STACK1', 'DET_ARG_STACK2', 'DET_ARG_STACK3', 'DET_ARG_STACK4'])
        ],
        []
        ),
    CamiFunction('MiDeleteVirtualAddresses',
        [
            CamiArguments(9600, ['DET_ARG_RCX', 'DET_ARG_RDX']),
            CamiArguments(9200, ['DET_ARG_STACK1', 'DET_ARG_RCX']),
            CamiArguments(0, ['DET_ARG_STACK1', 'DET_ARG_STACK2'])
        ],
        []
        ),
    CamiFunction('MiFinishVadDeletion',
        [
            CamiArguments(0, ['DET_ARG_RDX', 'DET_ARG_STACK1'])
        ],
        [
            CamiArguments(0, ['DET_ARG_RDX', 'DET_ARG_R8'])
        ],
        ),
    CamiFunction('MiGetWsAndInsertVad',
        [
            CamiArguments(9600, ['DET_ARG_RCX']),
            CamiArguments(9200, ['DET_ARG_RAX']),
            CamiArguments(0, ['DET_ARG_RDI'])
        ],
        []
        ),
    CamiFunction('MiInitializeLoadedModuleList', [], []),
    CamiFunction('MiInsertPrivateVad',
        [
            CamiArguments(9600, ['DET_ARG_RCX']),
            CamiArguments(9200, ['DET_ARG_STACK1']),
            CamiArguments(0, ['DET_ARG_RDI'])
        ],
        []
        ),
    CamiFunction('MiInsertVad',
        [
            CamiArguments(18363, ['DET_ARG_RCX', 'DET_ARG_RDX']),
        ],
        []
        ),
    CamiFunction('MiProcessLoaderEntry',
        [
            CamiArguments(9600, ['DET_ARG_RCX', 'DET_ARG_RDX']),
            CamiArguments(9200, ['DET_ARG_RSI', 'DET_ARG_STACK1']),
            CamiArguments(0, ['DET_ARG_STACK1', 'DET_ARG_STACK2'])
        ],
        []
        ),
    CamiFunction('MiUnloadSystemImage',
        [
            CamiArguments(9600, ['DET_ARG_RCX']),
            CamiArguments(0, ['DET_ARG_STACK1'])
        ],
        []
        ),
    CamiFunction('MmCleanProcessAddressSpace',
        [
            CamiArguments(9600, ['DET_ARG_RCX']),
            CamiArguments(9200, ['DET_ARG_STACK1']),
            CamiArguments(0, ['DET_ARG_RAX'])
        ],
        []
        ),
    CamiFunction('MmCopyVirtualMemory',
        [
            CamiArguments(0, ['DET_ARG_STACK4', 'DET_ARG_STACK5', 'DET_ARG_STACK6', 'DET_ARG_STACK7', 'DET_ARG_STACK8'])
        ],
        [
            CamiArguments(0, ['DET_ARG_RCX', 'DET_ARG_RDX', 'DET_ARG_R8', 'DET_ARG_R9', 'DET_ARG_STACK7'])
        ]
        ),
    CamiFunction('NtQueueApcThreadEx',
        [
            CamiArguments(0, ['DET_ARG_RCX', 'DET_ARG_STACK10', 'DET_ARG_STACK11', 'DET_ARG_RAX'])
        ],
        [
            CamiArguments(0, ['DET_ARG_RCX',  'DET_ARG_R8', 'DET_ARG_R9', 'DET_ARG_RAX'])
        ]
        ),
    CamiFunction('NtSetSystemPowerState', [], []),
    CamiFunction('PspInsertProcess',
        [
            CamiArguments(9600, ['DET_ARG_RCX', 'DET_ARG_RDX', 'DET_ARG_STACK3']),
            CamiArguments(9200, ['DET_ARG_RDI', 'DET_ARG_STACK1', 'DET_ARG_STACK4']),
            CamiArguments(0, ['DET_ARG_RAX', 'DET_ARG_STACK1', 'DET_ARG_STACK5'])
        ],
        [
            CamiArguments(9200, ['DET_ARG_RCX', 'DET_ARG_RDX', 'DET_ARG_STACK6']),
            CamiArguments(0, ['DET_ARG_RCX', 'DET_ARG_RDX', 'DET_ARG_STACK5'])
        ]
        ),
    CamiFunction('PspSetContextThreadInternal',
        [
            CamiArguments(19041, ['DET_ARG_RCX', 'DET_ARG_RDX']),
            CamiArguments(18362, ['DET_ARG_STACK3', 'DET_ARG_STACK4']),
            CamiArguments(10586, ['DET_ARG_RCX', 'DET_ARG_RDX']),
            CamiArguments(10000, ['DET_ARG_STACK3', 'DET_ARG_STACK4']),
            CamiArguments(9600, ['DET_ARG_RCX', 'DET_ARG_RDX']),
            CamiArguments(0, ['DET_ARG_STACK3', 'DET_ARG_STACK4']),
        ],
        []
        ),
    CamiFunction('PspWow64SetContextThread', [], []),
    CamiFunction('RtlpVirtualUnwind1', [], []),
    CamiFunction('RtlpVirtualUnwind2', [], []),
    CamiFunction('RtlpVirtualUnwind3', [], []),
    CamiFunction('RtlpVirtualUnwind4', [], []),
    CamiFunction('RtlpVirtualUnwind5', [], []),
    CamiFunction('RtlpVirtualUnwind6', [], []),
    CamiFunction('RtlpVirtualUnwind7', [], []),
    CamiFunction('RtlpVirtualUnwind8', [], [])
    ]

syscalls = [
    'KiFastCallEntry',      # x86
    'KiFastCallentry',      # x86 KPTI
    'KiSystemCall64',       # x86_64
    'KiSystemCall64Shadow'  # x86_64 KPTI
    ]

def bytes_to_int(bytear):
    res = 0

    for i, n in enumerate(bytear):
        res += (int(n) << (i * 8))

    return res

def get_fields_support(fields, ntkrnl, ntdll):
    struct_factory = ntkrnl.struct_factory

    for group in fields:
        print(f"\n{' ' * 8}{group.name}: !opaque_fields")

        for field in group.fields:
            value = 0

            try:
                if field.type == 'offset':
                    value = struct_factory.get_struct(field.struct).get_field_offset(field.value)
                if field.type == 'sizeof':
                    s = struct_factory.get_struct(field.struct)
                    value = s.size if field.value is None else s.get_field(field.value).type.size
                if field.type == 'constant':
                    value = field.value[0] if ntkrnl.guest64 else field.value[1]
                if field.type == 'bitfield':
                    b = struct_factory.get_struct(field.struct).get_field(field.value).type
                    value = ((1 << b.bit_cnt) - 1) << b.bit_idx
                if field.type == 'bitmask':
                    b = struct_factory.get_struct(field.struct).get_field(field.value).type
                    value = ((1 << b.bit_cnt) - 1)
                if field.type == 'bitpos':
                    b = struct_factory.get_struct(field.struct).get_field(field.value).type
                    value = b.bit_idx
                if field.type == 'syscall':
                    b = ntdll.robj.read_bytes(f"pdb.{field.name}", 128)
                    value = r2functions.get_syscall_number(b, ntdll.guest64)
            except LookupError as e:
                print(f"Failed to find field ({str(e)}) for {str(field)} it may not be present for this os, or it might be present under a diffent name, check the pdb and modify the CamiField structures as necessary.", file=sys.stderr)

            print(f"{' ' * 12}{field.name}: {hex(value) if isinstance(value, int) else value}")

def get_km_support(krnl, ntdll):
    print(f"{' ' * 0}---")
    print(f"{' ' * 0}!intro_update_win_supported_os")
    print(f"{' ' * 0}build_number: {krnl.ntbuildnumber}")
    print(f"{' ' * 0}version_string: !intro_update_win_version_string")
    print(f"{' ' * 4}version_string: \"Windows {krnl.ntbuildnumber}\"")
    print(f"{' ' * 4}server_version_string: \"Windows Server {krnl.ntbuildnumber}\"")
    print(f"{' ' * 0}kpti_installed: {krnl.kpti}")
    print(f"{' ' * 0}is_64: {krnl.guest64}")

    print(f"{' ' * 0}km_fields: !opaque_structures")
    print(f"{' ' * 4}type: win_km_fields")
    print(f"{' ' * 4}os_structs:")

    get_fields_support(km_fields, krnl, ntdll)

def get_um_support(krnl, ntdll):
    print(f"{' ' * 0}---")
    print(f"{' ' * 0}!intro_update_win_um_fields")
    print(f"{' ' * 0}is64: {krnl.guest64}")
    print(f"{' ' * 0}min_ver: {krnl.ntbuildnumber}")
    print(f"{' ' * 0}max_ver: {krnl.ntbuildnumber}")

    print(f"{' ' * 0}fields: !opaque_structures")
    print(f"{' ' * 4}type: win_um_fields")
    print(f"{' ' * 4}os_structs:")

    get_fields_support(um_fields, krnl, ntdll)

def get_function_pattern(pattern):
    for i in pattern:
        s = f"{' ' * 16}- {i.instruction_bytes}"
        s += ' ' * (69 - len(s))
        s += f"# {i.text}"
        print(s)

def get_syscall(krnl):
    i = 2 if krnl.guest64 else 0
    i += 1 if krnl.kpti else 0

    try:
        pattern = r2functions.get_pattern_signature(krnl.robj.read_bytes(f"pdb.{syscalls[i]}", 128), krnl.robj.info.bin.bits)
    except LookupError as e:
        print(f"Failed to find syscall from {syscalls[i]}", file=sys.stderr)
        raise e

    print(f"{' ' * 0}---")
    print(f"{' ' * 0}-")
    print(f"{' ' * 4}!syscall_pattern")
    print(f"{' ' * 4}id: [ {'SYSCALL_SIG_FLAG_KPTI,' if krnl.kpti else ''} IG_GUEST_WINDOWS ]")
    print(f"{' ' * 4}flags: [ {'LOC_SYSCALL' if krnl.guest64 else 'LOC_SYSENTER'} ]")
    print(f"{' ' * 4}offset: 0")
    print(f"{' ' * 4}pattern: !code_pattern")
    print(f"{' ' * 8}code:")

    get_function_pattern(pattern)

def get_function(krnl, function):
    name = function.name
    args = next((a for a in (function.args64 if krnl.guest64 else function.args32) if a.minver <= krnl.ntbuildnumber), None)

    try:
        pattern = r2functions.get_pattern_signature(krnl.robj.read_bytes(f"pdb.{name}", 128), krnl.robj.info.bin.bits)
        section = krnl.robj.section(f"pdb.{name}").name
    except LookupError as e:
        print(f"Will ignore exception ({str(e)}) for {name} as it may not be present", file=sys.stderr)
        return

    print(f"{' ' * 0}---")
    print(f"{' ' * 0}!intro_update_win_function")
    print(f"{' ' * 0}name: {name}")
    print(f"{' ' * 0}guest64: {krnl.guest64}")

    if args is not None:
        print(f"{' ' * 0}arguments:")
        print(f"{' ' * 4}-")
        print(f"{' ' * 8}!intro_update_win_args")
        print(f"{' ' * 8}min_ver: {krnl.ntbuildnumber}")
        print(f"{' ' * 8}max_ver: {krnl.ntbuildnumber}")
        print(f"{' ' * 8}args:")
        for a in args.list:
            print(f"{' ' * 12}- {a}")

    print(f"{' ' * 0}patterns:")
    print(f"{' ' * 4}-")
    print(f"{' ' * 8}!intro_update_win_pattern")
    print(f"{' ' * 8}section_hint: {section}")
    print(f"{' ' * 8}min_ver: {krnl.ntbuildnumber}")
    print(f"{' ' * 8}max_ver: {krnl.ntbuildnumber}")
    print(f"{' ' * 8}pattern: !code_pattern")
    print(f"{' ' * 12}code:")

    get_function_pattern(pattern)

def get_function_support(krnl):
    for function in functions:
        get_function(krnl, function)

def get_ntkrnl_obj(kernel_file):
    robj = r2wrapper.R2Wrapper(kernel_file)
    ntbuildnumber = bytes_to_int(robj.read_bytes('sym.ntoskrnl.exe_NtBuildNumber', 2))

    kpti = False
    try:
        _ = robj.read_bytes('pdb.KiKvaShadow', 1)
        kpti = True
    except:
        pass

    sf = r2structs.StructFactory(robj)

    return CamiNtoskrnl(robj, sf, ntbuildnumber, kpti, robj.info.bin.bits == 64)

def get_ntdll_obj(ntdll_file):
    robj = r2wrapper.R2Wrapper(ntdll_file)

    return CamiNtdll(robj, robj.info.bin.bits)

def main(args):
    krnl = get_ntkrnl_obj(args.ntoskrnl)
    ntdll = get_ntdll_obj(args.ntdll)

    with open(args.outfile, 'w') as f:
        sys.stdout = f

        get_syscall(krnl)
        get_km_support(krnl, ntdll)
        get_um_support(krnl, ntdll)
        get_function_support(krnl)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create a cami support file')
    parser.add_argument('-k', '--ntoskrnl', action='store', help='Target ntoskrnl.exe', required=True)
    parser.add_argument('-n', '--ntdll', action='store', help='Target ndll.dll', required=True)
    parser.add_argument('-o', '--outfile', action='store', help='Output file', required=True)
    main(parser.parse_args(sys.argv[1:]))

