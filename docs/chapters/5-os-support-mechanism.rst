====================
OS Support Mechanism
====================

CAMI is an Introcore sub-module serving mainly as an information database specific to operating-systems. However, it may include other features to control Introspection behavior, such-as hooked kernel APIs or enforced options (forcing features to be on or off).
Introcore will not protect a guest VM without the OS support binary file.

General architecture
====================

On a base level, the OS specific information is stored in YAML files for easier maintenance. To serve them to Introcore in a safe and easy manner, these files are serialized into a binary file. The file binary is loaded in memory by the integrator and then handed-over to the introspection engine as parameters to the :code:`NewGuestNotification` API. The currently loaded update file can be updated with the :code:`UpdateSupport` API. However, the OS-specific part will not be updated, and Introcore must be restarted if an update is needed.

Dependencies
============

To build CAMI you need python 3 and the `PyYAML <https://pypi.org/project/PyYAML/)>`__ library:

.. code-block:: console

    python3 -m pip install pyyaml

Automatically Adding Support for an OS
======================================

Adding support for an OS requires creating an YAML formatted file containing all information needed by Introspection regarding that OS type.

Windows OS
----------

Generating a support file for a Windows OS requires `radare2 <https://github.com/radareorg/radare2>`__, and
the `r2pipe <https://pypi.org/project/r2pipe/>`__ python library, as well as the pydis python wrapper over the
`Bitdefender Disassembler <https://github.com/bitdefender/bddisasm>`__.

To generate the support file, supply the **ntoskrnl.exe** and the **ntdll.dll** available on that system to the **r2cami.py** script. This script will automatically download the debugging symbols and generate the support file. The script is found in the *cami/tools/r2cami* directory. The following is an example of how to create a support file:

.. code-block:: console

    python3 r2cami.py -k ntoskrnl.exe -n ntdll.dll -o windows_support.yaml

Linux OS
--------

On the Linux side, the debugging symbols must be downloaded manually as the mirror locations differ for each distribution. Once the debugging symbols are available, the **offsets.py** script from the *cami* directory will automatically generate a suitable yaml file for that kernel. This script requires both **gdb** and `pygdb <https://pypi.org/project/pygdb/>`__.

.. code-block:: console

    python3 offsets.py --kernel=vmlinux-4.9.0-11-amd64 --out linux_support.yaml

Manually Adding Support for an OS
=================================

Windows Guest
-------------

Adding Guest Field Offsets
~~~~~~~~~~~~~~~~~~~~~~~~~~

To add support for a new guest OS, one must create a new yaml file inside the *cami/windows/opaque_fields/km* and/or the *cami/windows/opaque_fields/um* for kernel and/or user mode fields.

Kernel mode fields
^^^^^^^^^^^^^^^^^^

The file will conventionally be named *windows_<nt_build_number>_x<arch>_kpti_<ON/OFF>.yml*. For example, *windows_7600_x64_kpti_OFF.yml* for Windows 7 x64 with KPTI disabled and no service pack installed.

.. note::

    The following examples do not necessarily contain valid offsets.

All yaml files must start with a :code:`---`.
The following line must contain a :code:`yaml_tag` describing the *python class* that will be responsible for parsing the current yaml structure. In this case, it is :code:`!intro_update_win_supported_os`.
The following 4 lines must contain the :code:`build_number`, :code:`kpti_installed`, :code:`version_string`, and :code:`is_64` fields (on separate lines), populated with required information, as follows:

.. code-block:: yaml

    ---
    !intro_update_win_supported_os
    build_number: 7600
    version_string: !intro_update_win_version_string
        version_string: "Windows 7 x64"
        server_version_string: "Windows Server 2008 R2 x64"
    kpti_installed: False
    is_64: True

The ::code:`version_string` contents are used by APIs like :code:`GetVersionString` and serve only an information purpose. :code:`server_version_string` serves the same purpose, but it is used for Windows Server editions. The contents are mandatory for generating a CAMI binary file.

Next, we populate the actual guest kernel mode fields. To do so, add the following lines:

.. code-block:: yaml

    km_fields: !opaque_structures
        type: win_km_fields
        os_structs:

The :code:`os_structs` field will be populated with more collections of fields. For example, we need more than one field from the :code:`EPROCESS` structure. Those fields are grouped under :code:`Process` as follows:

.. code-block:: yaml

    Process: !opaque_fields
        Cr3: 0x28
        UserCr3: 0x28
        KexecOptions: 0x1bf
        ...

The keen eye will notice the :code:`!opaque_fields` after each :code:`Process` and the :code:`!opaque_structures` after :code:`km_fields`. Those are the same as the :code:`yaml_tag` described at the beginning, and serve the same purpose - to tell the python class to which it belongs. Be sure to not forget about it.

The next tables describe all of the kernel mode fields, from which structure to extract them, and how to populate the yaml groups. All field offsets are relative to the start of the structure containing them.

Process
'''''''

Used to describe a :code:`EPROCESS` Windows kernel structure.

+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| CAMI field name    | Description                                                                                                                              |
+====================+==========================================================================================================================================+
| Cr3                | The offset of the :code:`Pcb.DirectoryTableBase` field.                                                                                  |
|                    | It contains the CR3 used by a process. If KPTI is active this will be the CR3 used in ring 0.                                            |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| UserCr3            | The offset of the :code:`Pcb.UserDirectoryTableBase` field.                                                                              |
|                    | If KPTI is active this will be the CR3 used in ring 3.                                                                                   |
|                    | For operating systems without KPTI this will be the same as :code:`**Cr3`                                                                |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| KexecOptions       | The offset of the :code:`**Pcb.Flags` field.                                                                                             |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| ListEntry          | The offset of the :code:`ActiveProcessLinks` field, containing the :code:`LIST_ENTRY` structure used for the global kernel process list. |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Name               | The offset of the :code:`**ImageFileName` field.                                                                                         |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| SectionBase        | The offset of the :code:`**SectionBaseAddress` field.                                                                                    |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Id                 | The offset of the :code:`UniqueProcessId` field.                                                                                         |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| ParentPid          | The offset of the :code:`InheritedFromUniqueProcessId` field.                                                                            |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| VadRoot            | The offset of the :code:`VadRoot` field.                                                                                                 |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| CreateTime         | The offset of the :code:`CreateTime` field.                                                                                              |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| ExitStatus         | The offset of the :code:`ExitStatus` field.                                                                                              |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Token              | The offset of the :code:`Token` field.                                                                                                   |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| ObjectTable        | The offset of the :code:`ObjectTable` field.                                                                                             |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Peb                | The offset of the :code:`Peb` field.                                                                                                     |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| ThreadListHead     | The offset of the :code:`Pcb.ThreadListHead` field.                                                                                      |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| WoW64              | The offset of the :code:`WoW64Process` field.                                                                                            |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Flags              | The offset of the :code:`Flags` field.                                                                                                   |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Flags3             | The offset of the :code:`Flags3` field.                                                                                                  |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| MitigationFlags    | The offset of the :code:`MitigationFlags` field.                                                                                         |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| MitigationFlags2   | The offset of the :code:`MitigationFlags2` field.                                                                                        |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| DebugPort          | The offset of the :code:`DebugPort` field.                                                                                               |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+
| Spare              | The offset of the :code:`Pcb.Spare1` field.                                                                                              |
+--------------------+------------------------------------------------------------------------------------------------------------------------------------------+


Thread
''''''

Used to describe a :code:`ETHREAD` Windows kernel structure.

+-------------------+-----------------------------------------------------------------+
| CAMI field name   | Description                                                     |
+===================+=================================================================+
| Process           | The offset of the :code:`Tcb.Process` field.                    |
+-------------------+-----------------------------------------------------------------+
| ThreadListEntry   | The offset of the :code:`Tcb.ThreadListEntry**` field.          |
+-------------------+-----------------------------------------------------------------+
| KernelStack       | The offset of the :code:`Tcb.KernelStack**` field.              |
+-------------------+-----------------------------------------------------------------+
| StackBase         | The offset of the :code:`Tcb.StackBase**` field.                |
+-------------------+-----------------------------------------------------------------+
| StackLimit        | The offset of the :code:`Tcb.StackLimit**` field.               |
+-------------------+-----------------------------------------------------------------+
| State             | The offset of the :code:`Tcb.State**` field.                    |
+-------------------+-----------------------------------------------------------------+
| WaitReason        | The offset of the :code:`Tcb.WaitReason**` field.               |
+-------------------+-----------------------------------------------------------------+
| AttachedProcess   | The offset of the :code:`Tcb.ApcState.AttachedProcess**` field. |
+-------------------+-----------------------------------------------------------------+
| Teb               | The offset of the :code:`Tcb.Teb**` field.                      |
+-------------------+-----------------------------------------------------------------+
| Id                | The offset of the :code:`Tcb.Cid.UniqueThread**` field.         |
+-------------------+-----------------------------------------------------------------+
| ClientSecurity    | The offset of the :code:`ClientSecurity**` field.               |
+-------------------+-----------------------------------------------------------------+
| TrapFrame         | The offset of the :code:`Tcb.TrapFrame**` field.                |
+-------------------+-----------------------------------------------------------------+
| Win32StartAddress | The offset of the :code:`Win32StartAddress**` field.            |
+-------------------+-----------------------------------------------------------------+
| PreviousMode      | The offset of the :code:`Tcb.PreviousMode**` field.             |
+-------------------+-----------------------------------------------------------------+


DrvObj
''''''

Used to describe a :code:`DRIVER_OBJECT` Windows kernel structure.

+-------------------+----------------------------------------------------------+
| CAMI field name   | Description                                              |
+===================+==========================================================+
| FiodispSize       | The size of the :code:`FAST_IO_DISPATCH` structure.      |
+-------------------+----------------------------------------------------------+
| Fiodisp           | The offset of the :code:`FastIoDispatch` field.          |
+-------------------+----------------------------------------------------------+
| AllocationGap     | The gap between the pool header and the driver object.   |
+-------------------+----------------------------------------------------------+
| Start             | The offset of the :code:`DriverObject` field.            |
+-------------------+----------------------------------------------------------+
| Size              | The size of the :code:`DRIVER_OBJECT` structure.         |
+-------------------+----------------------------------------------------------+

Pcr
'''

Used to describe a :code:`KPCR` Windows kernel structure.

+-------------------+-----------------------------------------------------+
| CAMI field name   | Description                                         |
+===================+=====================================================+
| CurrentThread     | The offset of the :code:`Pcrb.CurrentThread` field. |
+-------------------+-----------------------------------------------------+
| UserTime          | The offset of the :code:`Pcrb.UserTime` field.      |
+-------------------+-----------------------------------------------------+

PoolDescriptor
''''''''''''''

Used to describe a :code:`POOL_DESCRIPTOR` Windows kernel structure.

+-------------------+---------------------------------------------------------------------+
| CAMI field name   | Description                                                         |
+===================+=====================================================================+
| TotalBytes        | The offset of the :code:`BytesAllocated` field.                     |
+-------------------+---------------------------------------------------------------------+
| NppSize           | The size of the non paged pool (usually hard-coded to 0x80000000)   |
+-------------------+---------------------------------------------------------------------+

Mmpfn
'''''

Used to describe a :code:`MMPFN` Windows kernel structure.
Note that most fields have two versions; one for PAE, and another for non-PAE systems. For 64-bit Windows versions the PAE version is ignored. For 32-bit Windows versions Introcore selects the correct field based on how the OS is configured. The non-PAE version is invalid for 32-bit Windows versions newer than Windows 7 because, starting with Windows 8, systems without PAE are no longer supported by the Windows kernel.

+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| CAMI field name   | Description                                                                                                                     |
+===================+=================================================================================================================================+
| Size              | The size of the structure. Valid for 64-bit Windows versions and for 32-bit versions with PAE disabled.                         |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Pte               | The offset of the :code:`PteAddress` field. Valid for 64-bit Windows versions and for 32-bit versions with PAE disabled.        |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| RefCount          | The offset of the :code:`u3.ReferenceCount` field. Valid for 64-bit Windows versions and for 32-bit versions with PAE disabled. |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| Flags             | The offset of the :code:`u3.Flags` field. Valid for 64-bit Windows versions and for 32-bit versions with PAE disabled.          |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| PaeSize           | The size of the structure. Valid for 32-bit Windows versions with PAE enabled.                                                  |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| PaePte            | The offset of the :code:`PteAddress` field. Valid for 32-bit Windows versions with PAE enabled.                                 |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| PaeRefCount       | The offset of the :code:`u3.ReferenceCount` field. Valid for 32-bit Windows versions with PAE enabled.                          |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+
| PaeFlags          | The offset of the :code:`u3.Flags` field. Valid for 32-bit Windows versions with PAE enabled.                                   |
+-------------------+---------------------------------------------------------------------------------------------------------------------------------+


Token
'''''

Used to describe a :code:`TOKEN` Windows kernel structure.

+-------------------+-----------------------------------------------------+
| CAMI field name   | Description                                         |
+===================+=====================================================+
| Privs             | The offset of the :code:`Privileges` field.         |
+-------------------+-----------------------------------------------------+
| UserCount         | The offset of the :code:`UserAndGroupCount` field.  |
+-------------------+-----------------------------------------------------+
| RestricredCount   | The offset of the :code:`RestrictedSidCount` field. |
+-------------------+-----------------------------------------------------+
| Users             | The offset of the :code:`UserAndGroups` field.      |
+-------------------+-----------------------------------------------------+
| RestrictedSids    | The offset of the :code:`RestrictedSids` field.     |
+-------------------+-----------------------------------------------------+

Ungrouped
'''''''''

Used to describe certain fields that are not organized in a dedicated CAMI structure.

+--------------------------+------------------------------------------------------------------------------------------------------------------+
| CAMI field name          | Description                                                                                                      |
+==========================+==================================================================================================================+
| CtlAreaFile              | The offset of the :code:`FilePointer` field inside the :code:`CONTROL_AREA` Windows kernel structure.            |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| HandleTableTableCode     | The offset of the :code:`TableCode` field inside the :code:`HANDLE_TABLE` Windows kernel structure.              |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| reserved                 | No longer used. The file format still has this field to be backwards compatible with older Introcore versions.   |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| WmiGetClockOffset        | The offset of the :code:`GetCpuClock` field inside the :code:`WMI_LOGGER_CONTEXT` structure.                     |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| EtwDbgDataSiloOffset     | Offset of :code:`EtwDbgDataSilo` in :code:`EtwpDbgData`.                                                         |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| EtwSignatureOffset       | The offset relative to the :code:`EtwDebuggerData` structure at which the ETW signature is found                 |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| SubsectionCtlArea        | The offset of the :code:`ControlArea` field inside the :code:`SUBSECTION` Windows kernel structure.              |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| HalPerfCntFunctionOffset | The offset of the protected functions inside HalPerformanceCounter structure from Hal Heap.                      |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| RspOffsetOnZwCall        | The offset of RSP inside the fake trapframe constructed on a Zw* function call on x64 systems.                   |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| HalIntCtrlTypeMaxOffset  | The maximum offset of Type inside HalInterruptController.                                                        |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| HalIntCtrlTypeMinOffset  | The minimum offset of Type inside HalInterruptController.                                                        |
+--------------------------+------------------------------------------------------------------------------------------------------------------+
| SharedUserDataSize       | The size of the _KUSER_SHARED_DATA structure.                                                                    |
+--------------------------+------------------------------------------------------------------------------------------------------------------+


EprocessFlags
'''''''''''''

Used to describe bits inside the :code:`Flags` field of the :ref:`EPROCESS <chapters/5-os-support-mechanism:Process>` Windows kernel structure.

+-------------------+------------------------------------------------+
| CAMI field name   | Description                                    |
+===================+================================================+
| NoDebugInherit    | The index of the :code:`NoDebugInherit` flag.  |
+-------------------+------------------------------------------------+
| Exiting           | The index of the :code:`ProcessExiting` flag.  |
+-------------------+------------------------------------------------+
| Delete            | The index of the :code:`ProcessDelete` flag.   |
+-------------------+------------------------------------------------+
| 3Crashed          | The index of the :code:`Crashed` flag.         |
+-------------------+------------------------------------------------+
| VmDeleted         | The index of the :code:`VmDeleted` flag.       |
+-------------------+------------------------------------------------+
| HasAddrSpace      | The index of the :code:`HasAddressSpace` flag. |
+-------------------+------------------------------------------------+
| OutSwapped        | The index of the :code:`OutSwapped` flag.      |
+-------------------+------------------------------------------------+



VadShort
''''''''

The following values describe a :code:`MMVAD_SHORT` Windows kernel
structure. 

+-------------------+---------------------------------------------------------------------------------------------------------------------+
| CAMI field name   | Description                                                                                                         |
+===================+=====================================================================================================================+
| Parent            | The offset of :code:`VadNode.ParentValue` field.                                                                    |
|                   | :code:`VadNode` is a :code:`RTL_BALANCED_NODE` or a :code:`MM_AVL_NODE` structure included in :code:`MMVAD_SHORT`.  |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| Left              | The offset of :code:`VadNode.Left` field.                                                                           |
|                   | :code:`VadNode` is a :code:`RTL_BALANCED_NODE` or :code:`MM_AVL_NODE` structure included in :code:`MMVAD_SHORT`.    |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| Right             | The offset of :code:`VadNode.Right` field.                                                                          |
|                   | :code:`VadNode` is a :code:`RTL_BALANCED_NODE` or :code:`MM_AVL_NODE` structure included in :code:`MMVAD_SHORT`.    |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| StartingVpn       | The offset of the :code:`StartingVpn` field.                                                                        |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| StartingVpnHigh   | The offset of the :code:`StartingVpnHigh` field.                                                                    |
|                   | Not all Windows versions have this field. It is 0 if it is not present.                                             |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| EndingVpn         | The offset of the :code:`EndingVpn` field.                                                                          |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| EndingVpnHigh     | The offset of the :code:`EndingVpnHigh` field.                                                                      |
|                   | Not all Windows versions have this field. It is 0 if it is not present.                                             |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| Flags             | The offset of the :code:`VadFlags` field.                                                                           |
|                   | Note that this is included in the same union as :code:`LongFlags`.                                                  |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| FlagsSize         | The minimum size that needs to be read in order to properly parse the :code:`Flags` field.                          |
|                   | See :ref:`VadFlags <chapters/5-os-support-mechanism:VadFlags>`.                                                     |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| VpnSize           | The size of the :code:`StartingVpn` and :code:`EndingVpn` fields.                                                   |
|                   | :code:`StartingVpnHigh` and :code:`EndingVpnHigh` always have the size of one byte.                                 |
+-------------------+---------------------------------------------------------------------------------------------------------------------+
| Size              | The minimum size that needs to be read in order to properly parse a :code:`MMVAD_SHORT` structure.                  |
+-------------------+---------------------------------------------------------------------------------------------------------------------+

VadLong
'''''''

The following values describe a :code:`MMVAD` Windows kernel structure.

+-------------------+----------------------------------------------+
| CAMI field name   | Description                                  |
+===================+==============================================+
| Subsection        | The offset of the :code:`Subsection` field.  |
+-------------------+----------------------------------------------+

VadFlags
''''''''

The following values are used to parse the :code:`VadFlags` field of a :code:`MMVAD_SHORT` Windows kernel structure. Since :code:`VadFlags` is actually a bitfield, these are used to isolate parts of the field. Some of these fields work in pairs.

+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| CAMI field name                         | Description                                                                                                                                                                                                 |
+=========================================+=============================================================================================================================================================================================================+
| TypeShift / TypeMask pair               | Used to obtain the :code:`VadType` value.                                                                                                                                                                   |
|                                         | The raw :code:`VadFlags` value needs to be right-shifted with the :code:`TypeShift` value first, then the bits of the :code:`VadType` can be isolated by applying the :code:`TypeMask` mask.                |
+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| ProtectionShift / ProtectionMask pair   | Used to obtain the :code:`Protection` value.                                                                                                                                                                |
|                                         | The raw :code:`VadFlags` value needs to be right-shifted with the :code:`ProtectionShift` value first, then the bits of the :code:`Protection` can be isolated by applying the :code:`ProtectionMask` mask. |
+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| NoChangeBit                             | The index of the :code:`NoChange` flag. This is always one bit.                                                                                                                                             |
+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| PrivateFixup                            | Mask used to isolate the :code:`PrivateFixup` flag.                                                                                                                                                         |
|                                         | This is always one bit, but on certain Windows versions it is missing. It is 0 if it is not available.                                                                                                      |
+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| DeleteInProgress                        | Mask used to isolate the :code:`DeleteInProgress` flag.                                                                                                                                                     |
|                                         | This is always one bit, but on certain Windows version it is missing. It is 0 if it is not available.                                                                                                       |
+-----------------------------------------+-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

SyscallNumbers
''''''''''''''

The following values are syscall numbers used by introcore to link the syscall kernel linkage functions into the boot driver. The kernel linkages are :code:`Zw*` functions corresponding to the :code:`Nt*` ntdll exports.
Some aren't exported. so we search for them using the syscall number and a "constant" parttern signature.

+--------------------------------+-------------------------------------------------------+
| CAMI field name                | Description                                           |
+================================+=======================================================+
| :code:`NtWriteVirtualMemory`   | The syscall number of :code:`NtWriteVirtualMemory`.   |
+--------------------------------+-------------------------------------------------------+
| :code:`NtProtectVirtualMemory` | The syscall number of :code:`NtProtectVirtualMemory`. |
+--------------------------------+-------------------------------------------------------+
| :code:`NtCreateThreadEx`       | The syscall nubmer of :code:`NtCreateThreadEx`.       |
+--------------------------------+-------------------------------------------------------+

FileObject
''''''''''

This is used to describe a :code:`FILE_OBJECT` Windows kernel structure.

+-------------------+------------------------------------------------------------------------------------------------------------+
| CAMI field name   | Description                                                                                                |
+===================+============================================================================================================+
| NameBuffer        | The offsrt of the :code:`FileName.Buffer` field. :code:`FileName` is a :code:`UNICODE_STRING` structure.   |
+-------------------+------------------------------------------------------------------------------------------------------------+
| NameLength        | The offset of the :code:`FileName.Length` field. :code:`FileName` is a :code:`UNICODE_STRING` structure.   |
+-------------------+------------------------------------------------------------------------------------------------------------+

Windows kernel mode fields example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

After you're done, *windows_7600_x64_kpti_OFF.yml* should look like this:

.. code-block:: yaml

    ---
    !intro_update_win_supported_os
    build_number: 7600
    version_string: !intro_update_win_version_string
        version_string: "Windows 7 x64"
        server_version_string: "Windows Server 2008 R2 x64"
    kpti_installed: False
    is_64: True

    km_fields: !opaque_structures
        type: win_km_fields
        os_structs:

            Process: !opaque_fields
                Cr3: 0x28
                UserCr3: 0x28
                KexecOptions: 0xd2
                ListEntry: 0x188
                Name: 0x2e0
                SectionBase: 0x270
                Id: 0x180
                ParentPid: 0x290
                VadRoot: 0x448
                CreateTime: 0x168
                ExitStatus: 0x444
                Token: 0x208
                ObjectTable: 0x200
                Peb: 0x338
                ThreadListHead: 0x30
                WoW64: 0x320
                Flags: 0x440
                Flags3: 0x0
                MitigationFlags: 0x0
                MitigationFlags2: 0x0
                DebugPort: 0x1f0
                Spare: 0x2a0

            Thread: !opaque_fields
                Process: 0x210
                ThreadListEntry: 0x2f8
                KernelStack: 0x38
                StackBase: 0x278
                StackLimit: 0x30
                State: 0x164
                WaitReason: 0x26b
                AttachedProcess: 0x70
                Teb: 0xb8
                Id: 0x3c0
                ClientSecurity: 0x3e8
                TrapFrame: 0x1d8

            DrvObj: !opaque_fields
                Size: 0x150
                FiodispSize: 0xe0
                AllocationGap: 0x50
                Fiodisp: 0x50
                Start: 0x18

            Pcr: !opaque_fields
                CurrentThread: 0x188
                UserTime: 0x4888

            PoolDescriptor: !opaque_fields
                TotalBytes: 0x50
                NppSize: 0x80000000

            Mmpfn: !opaque_fields
                Size: 0x30
                Pte: 0x10
                RefCount: 0x18
                Flags: 0x1a
                PaeSize: 0x0
                PaePte: 0x0
                PaeRefCount: 0x0
                PaeFlags: 0x0

            Token: !opaque_fields
                Privs: 0x40
                UserCount: 0x78
                RestrictedCount: 0x7c
                Users: 0x90
                RestrictedSids: 0x98

            Ungrouped: !opaque_fields
                CtlAreaFile: 0x40
                HandleTableTableCode: 0x0
                HalIntCtrlType: 0x0
                WmiGetClockOffset: 0x18
                EtwDbgDataSiloOffset: 0x10
                # We want to treat it as "-2" so we send the unsigned int value which will be correctly treated by introcore
                EtwSignatureOffset: 0xFFFFFFFE
                SubsectionCtlArea: 0

            EprocessFlags: !opaque_fields
                NoDebugInherit: 0x2
                Exiting: 0x4
                Delete: 0x8
                3Crashed: 0x10
                VmDeleted: 0x20
                HasAddrSpace: 0x40000

            VadShort: !opaque_fields
                Parent: 0x0
                Left: 0x8
                Right: 0x10
                StartingVpn: 0x18
                StartingVpnHigh: 0x0
                EndingVpn: 0x20
                EndingVpnHigh: 0x0
                Flags: 0x28
                FlagsSize: 0x8
                VpnSize: 0x8
                Size: 0x30

            VadLong: !opaque_fields
                Subsection: 0x48

            VadFlags: !opaque_fields
                TypeShift: 0x34
                TypeMask: 0x7
                ProtectionShift: 0x38
                ProtectionMask: 0x1F
                NoChangeBit: 51
                PrivateFixup: 0x0
                DeleteInProgress: 0x0

            SyscallNumbers: !opaque_fields
                NtWriteVirtualMemory: 0x37
                NtProtectVirtualMemory: 0x4d
                NtCreateThreadEx: 0xa5

            FileObject: !opaque_fields
                NameBuffer: 0x60
                NameLength: 0x58

User mode fields
^^^^^^^^^^^^^^^^

The file will conventionally be named *windows_um_<version>_x<arch>.yml*. For example, *windows_um_7_x64.yml* for Windows 7 x64 7600, 7601, and 7602.

.. note::

    The following examples do not necessarily contain valid offsets.

All yaml files must start with a :code:`---`.
The following line must contain a :code:`yaml_tag` describing the *python class* that will be responsible for parsing the current yaml structure. In this case, it is :code:`!intro_update_win_um_fields`.
The following 3 lines must contain the :code:`is64`, :code:`min_ver`, and :code:`max_ver` fields (on separate lines). :code:`is_64` is **True** if the file contains information for a 64-bit system. :code:`min_ver` and :code:`max_ver` represent the minimum and the maximum operating system versions for which the information is valid. This interval is inclusive.

.. code-block:: yaml

    ---
    !intro_update_win_um_fields
    is64: True
    min_ver: 7600
    max_ver: 7602

Next, we populate the actual guest user mode fields. To do so, add the following lines:

.. code-block:: yaml

    fields: !opaque_structures
        type: win_um_fields
        os_structs:

The :code:`os_structs` field will be populated with more collections of fields. For example, we need more than one field from the :code:`LDR_DATA_TABLE_ENTRY` structure. Those fields are grouped under :code:`Dll` as follows:

.. code-block:: yaml

    Dll: !opaque_fields
        BaseOffsetInModule64: 0x30
        BaseOffsetInModule32: 0x18
        SizeOffsetInModule64: 0x40
        ...

The next tables describe all of the user mode fields, from which structure to extract them, and how to populate the yaml groups. All field offsets are relative to the start of the structure containing them.

Dll
'''

This is used to describe a :code:`LDR_DATA_TABLE_ENTRY` Windows structure.

+-----------------------+--------------------------------------------------------------------------+
| CAMI field name       | Description                                                              |
+=======================+==========================================================================+
| BaseOffsetInModule64  | The offset of the :code:`DllBase` field for 64-bit processes.            |
+-----------------------+--------------------------------------------------------------------------+
| BaseOffsetInModule32  | The offset of the :code:`DllBase` field for 32-bit processes.            |
+-----------------------+--------------------------------------------------------------------------+
| SizeOffsetInModule64  | The offset of the :code:`SizeOfImage` field field for 64-bit processes.  |
+-----------------------+--------------------------------------------------------------------------+
| SizeOffsetInModule32  | The offset of the :code:`SizeOfImage` field field for 64-bit processes.  |
+-----------------------+--------------------------------------------------------------------------+
| NameOffsetInModule64  | The offset of the :code:`FullDllName` field field for 64-bit processes.  |
+-----------------------+--------------------------------------------------------------------------+
| NameOffsetInModule32  | The offset of the :code:`FullDllName` field field for 64-bit processes.  |
+-----------------------+--------------------------------------------------------------------------+

Peb
'''

This is used to describe a :code:`PEB` Windows structure.

+-------------------+--------------------------------------------------------------------------------------+
| CAMI field name   | Description                                                                          |
+===================+======================================================================================+
| 64Size            | The size of the structure for 64-bit processes.                                      |
|                   | This is not the actual structure size, but the size that is relevant for Introcore.  |
+-------------------+--------------------------------------------------------------------------------------+
| 32Size            | The size of the structure for 32-bit processes.                                      |
|                   | This is not the actual structure size, but the size that is relevant for Introcore.  |
+-------------------+--------------------------------------------------------------------------------------+

Teb
'''

This is used to describe a :code:`TEB` Windows structure.

+----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| CAMI field name      | Description                                                                                                                                                  |
+======================+==============================================================================================================================================================+
| 64Size               | The size of the structure for 64-bit processes.                                                                                                              |
|                      | This is not the actual structure size, but the size that is relevant for Introcore.                                                                          |
+----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 32Size               | The size of the structure for 32-bit processes.                                                                                                              |
|                      | This is not the actual structure size, but the size that is relevant for Introcore.                                                                          |
+----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Wow64SaveArea        | The offset of the area in which a thread of a WoW64 application saves its general purpose registers when jumping to 64-bit code in order to issue a syscall. |
+----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Wow64StackInSaveArea | The offset of ESP in the :code:`Wow64SaveArea`.                                                                                                              |
+----------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+

Windows user mode fields example
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: yaml

    ---
    !intro_update_win_um_fields
    is64: True
    min_ver: 7600
    max_ver: 7602
    fields: !opaque_structures
        type: win_um_fields
        os_structs:

            Dll: !opaque_fields
                BaseOffsetInModule64: 0x30
                BaseOffsetInModule32: 0x18
                SizeOffsetInModule64: 0x40
                SizeOffsetInModule32: 0x20
                NameOffsetInModule64: 0x48
                NameOffsetInModule32: 0x24

            Peb: !opaque_fields
                64Size: 0x388
                32Size: 0x250

            Teb: !opaque_fields
                64Size: 0x20
                32Size: 0x20
                Wow64SaveArea: 0x1488
                Wow64StackInSaveArea: 0xc8

Adding new fields
~~~~~~~~~~~~~~~~~

New fields must be added in the *tags.yaml* file, and then the OS-specific configuration files must be changed to contain the fields. For technical documentation about this see the Doxygen documentation for the `guest support module <../_static/doxygen/html/group__group__guest__support.html>`__. 

The format of the *tags.yaml* file is the same as the previous :code:`os_structs`: the same groups, the same field names.

Function patterns
~~~~~~~~~~~~~~~~~

Function patterns are found in the *windows/functions* directory. Each function has a specific yaml file for 32-bit Windows versions and 64-bit Windows versions. One file can contain multiple patterns. These patterns are used by Introcore to find kernel APIs that will be :ref:`hooked <chapters/9-development-guideline:setting api hooks>`.

.. note::

    All of the following examples are based on the *KiDispatchException32.yml* file.

All yaml files must start with a :code:`---`.
The following line must contain a :code:`yaml_tag` describing the *python class* that will be responsible for parsing the current yaml structure. In this case, it is :code:`!intro_update_win_function`.
The following 2 lines contain the :code:`name` and :code:`guest64` fields. :code:`name` is used to identify the function, while :code:`guest64` is used to identify the guest architecture.

In our case, the first couple of lines look like this:

.. code-block:: yaml

    ---
    !intro_update_win_function
    name: KiDispatchException
    guest64: False

The :code:`arguments` field is optional and describes the arguments passed to introcore by the :ref:`hook handler <chapters/9-development-guideline:windows hook handlers>` and **not** the actual argument list of the function.
While these can be the same as the parameters the kernel API receives, the handler can pass different parameters. CAMI describes exactly what the handler will pass to Introcore. Arguments can be different for different Windows versions, so the first two fields that must be added are the :code:`min_ver` and :code:`max_ver` fields. These contain the minimum and maximum version for which the argument description is valid (the range is inclusive). :code:`WIN_PATTERN_MIN_VERSION_ANY` and :code:`WIN_PATTERN_MAX_VERSION_ANY` can be used to specify any version.

The next field, :code:`args`, is a list that describes the arguments used by Introcore in the order in which Introcore expects them. The list uses some predefined constants for describing the location of the arguments. For example, :code:`DET_ARG_RAX` is used for parameters passed using the :code:`RAX` register, while :code:`DET_ARG_STACK3` means that the argument is the third guest word on the stack.

.. code-block:: yaml

    arguments:
        -
            !intro_update_win_args
            min_ver: WIN_PATTERN_MIN_VERSION_ANY
            max_ver: WIN_PATTERN_MAX_VERSION_ANY

            args:
                - DET_ARG_STACK1       # Exception record GVA
                - DET_ARG_STACK2       # Exception frame GVA, or i think at least, not used in introcore
                - DET_ARG_STACK3       # Trap frame GVA
                - DET_ARG_STACK4       # Previous mode

In this example, there are 4 arguments valid for all windows versions. All of them are from the stack. 

Next, there is a list of patterns, with each element in the list having the :code:`!intro_update_win_pattern` tag.
Exactly as with the case of the arguments, these have a :code:`min_ver` and :code:`max_ver` pair of fields that are used to select the Windows version for which a pattern is available.
The :code:`section_hint` field is used as a hint by Introcore to first search the function in the given section.

Followed by those fields there's the actual pattern field with the yaml tag :code:`!code_pattern`. This field has a code field that contains a list of python-like lists describing instructions.

.. code-block:: yaml

    patterns:
        -
            !intro_update_win_pattern
            section_hint: .text
            min_ver: WIN_PATTERN_MIN_VERSION_ANY
            max_ver: 8000
            pattern: !code_pattern
                code:
                    - [0x68, 0x100, 0x100, 0x100, 0x100]                 #  push    0F8h
                    - [0x68, 0x100, 0x100, 0x100, 0x100]                 #  push    offset nt+0x5c50 (826984b0)
                    - [0xe8, 0x100, 0x100, 0x100, 0x100]                 #  call    nt!_SEH_prolog4_GS (826be8b0)
                    - [0x64, 0xa1, 0x20, 0x00, 0x00, 0x00]               #  mov     eax,dword ptr fs:[00000020h]
                    - [0xff, 0x80, 0x100, 0x100, 0x100, 0x100]           #  inc     dword ptr [eax+58Ch]
                    - [0xc7, 0x45, 0x100, 0x17, 0x00, 0x01, 0x00]        #  mov     dword ptr [ebp-20h],10017h
                    - [0x80, 0x7d, 0x100, 0x100]                         #  cmp     byte ptr [ebp+14h],1
                    - [0x74, 0x100]                                      #  je      nt!KiDispatchException+0x31 (826f34a2)
                    - [0x80, 0x3d, 0x100, 0x100, 0x100, 0x100, 0x00]     #  cmp     byte ptr [nt!KdDebuggerEnabled (827a4a4c)],0
                    - [0x74, 0x100]                                      #  je      nt!KiDispatchException+0x6b (826f34dc)
                    - [0xc7, 0x45, 0x100, 0x1f, 0x00, 0x01, 0x00]        #  mov     dword ptr [ebp-20h],1001Fh
                    - [0x80, 0x3d, 0x100, 0x100, 0x100, 0x100, 0x00]     #  cmp     byte ptr [nt!KeI386XMMIPresent (827a1158)],0
                    - [0x74, 0x100]                                      #  je      nt!KiDispatchException+0x48 (826f34b9)
                    - [0xc7, 0x45, 0x100, 0x3f, 0x00, 0x01, 0x00]        #  mov     dword ptr [ebp-20h],1003Fh
                    - [0xf7, 0x05, 0x100, 0x100, 0x100, 0x100, 0x00, 0x00, 0x40, 0x00] #  test    dword ptr [nt!KeFeatureBits (827a9a94)],400000h
                    - [0x74, 0x100]                                      #  je      nt!KiDispatchException+0x6b (826f34dc)
                    - [0xa1, 0x100, 0x100, 0x100, 0x100]                 #  mov     eax,dword ptr [nt!KeEnabledXStateFeatures (827a9b80)]
                    - [0x83, 0xe0, 0xfc]                                 #  and     eax,0FFFFFFFCh
                    - [0x0b, 0x05, 0x100, 0x100, 0x100, 0x100]           #  or      eax,dword ptr [nt!KeEnabledXStateFeatures+0x4 (827a9b84)]

In this example, there's a pattern valid for any Windows version up to *8000* that resides in the *.text* section.
Even if the pattern is used to search for a sequence of bytes, the :code:`0x100` value can be used as a wild-card for matching anything. This is useful for masking addresses that will change after every boot, or immediates that might slightly change between Windows versions.

Linux Guest
-----------

The file format for a Linux guest configuration file is similar to the :ref:`Windows <chapters/5-os-support-mechanism:Windows Guest>` one.
The file starts with the :code:`!intro_update_lix_supported_os` tag, followed by :code:`version`, which is a glob pattern, as in the following example. 
The glob format is slightly different from the standard: the :code:`[]` pattern is treated as a closed numeric interval (e.g. :code:`[12-14]` will match :code:`12`, :code:`13`, and :code:`14`).
If the left value is missing (e.g. :code:`[-15]`) it is assumed to be 0, and a missing right value (e.g. :code:`[15-]`) is assumed to be :code:`MAX_QWORD`.

.. code-block:: yaml

    !intro_update_lix_supported_os
    version: 4.9.0-[0-5]-amd64 *Debian*

The following lines contain the functions that will be hooked by Introcore.
Each element of the :code:`hooks` list must have the :code:`!intro_update_lix_hook` tag.
The :code:`handler` attribute tells Introcore which hook :ref:`handler <chapters/9-development-guideline:linux hook handlers>` should be used for this function.
The :code:`skip_on_boot` attribute is used on older Introcore versions to discern if a function can be hooked after the OS finishes the boot process.

.. code-block:: yaml

    hooks: !intro_update_lix_hooks
        - !intro_update_lix_hook
            run_init_process:
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            module_param_sysfs_setup:
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            module_param_sysfs_remove:
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            flush_old_exec:
            handler: 0
            skip_on_boot: 0

    # -- more functions --

The next part of the file contains kernel structure descriptions. The YAML member is called :code:`fields` and has the :code:`!opaque_structures` tag.
Opaque fields are grouped in structures. (see *tags.yaml* for a complete list of structures along with their fields).
If the value of a field is not specified then it will be automatically considered 0.

.. code-block:: yaml

    fields: !opaque_structures
        type: lix_fields
        os_structs:

            Info: !opaque_fields
                ThreadSize : 0x4000
                HasModuleLayout : 0x0001
                HasVdsoImageStruct : 0x0001

            Module: !opaque_fields
                ListOffset : 0x0008
                NameOffset : 0x0018
                SymbolsOffset : 0x00d0
                NumberOfSymbolsOffset : 0x00e0

    # -- more info --

In the end, your configuration file should look like this:

.. code-block:: yaml

    !intro_update_lix_supported_os
    version: 4.15.0-[24-]*Ubuntu*

    hooks:
        - !intro_update_lix_hook
            name: run_init_process
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: sched_init
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: module_param_sysfs_setup
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: module_param_sysfs_remove
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: flush_old_exec
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: do_exit
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: cgroup_post_fork
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: wake_up_new_task
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: arch_ptrace
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: compat_arch_ptrace
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: process_vm_rw_core*
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: __vma_link_rb
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: change_protection
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: __vma_adjust
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: __vma_rb_erase
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: expand_downwards
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: complete_signal
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: text_poke
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: commit_creds
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: ftrace_write
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: crash_kexec
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: panic
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: arch_jump_label_transform
            handler: 0
            skip_on_boot: 0

        - !intro_update_lix_hook
            name: __access_remote_vm
            handler: 0
            skip_on_boot: 0

    fields: !opaque_structures
        type: lix_fields
        os_structs:

            Info: !opaque_fields
                ThreadSize : 0x4000
                HasModuleLayout : 0x0001
                HasVdsoImageStruct : 0x0001
                HasSmallSlack : 0x0000
                HasKsymRelative : 0x0001
                HasKsymAbsolutePercpu : 0x0001
                HasKsymSize : 0x0000
                HasAlternateSyscall : 0x0001
                HasVdsoFixed : 0x0001
                HasVmaAdjustExpand : 0x0001

            Module: !opaque_fields
                ListOffset : 0x0008
                NameOffset : 0x0018
                SymbolsOffset : 0x00d0
                NumberOfSymbolsOffset : 0x00e0
                GplSymbolsOffset : 0x0118
                NumberOfGplSymbolsOffset : 0x0114
                InitOffset : 0x0178
                ModuleInitOffset : 0x0000
                ModuleCoreOffset : 0x0000
                InitSizeOffset : 0x0000
                CoreSizeOffset : 0x0000
                InitTextSizeOffset : 0x0000
                CoreTextSizeOffset : 0x0000
                InitRoSizeOffset : 0x0000
                CoreRoSizeOffset : 0x0000
                CoreLayoutOffset : 0x0180
                InitLayoutOffset : 0x01d0
                StateOffset : 0x0000
                Sizeof : 0x0340

            Binprm: !opaque_fields
                MmOffset : 0x0090
                FileOffset : 0x00a8
                CredOffset : 0x00b0
                FilenameOffset : 0x00c8
                InterpOffset : 0x00d0
                Vma : 0x0080
                Argc : 0x00c0
                Sizeof : 0x00f0

            Vma: !opaque_fields
                VmaStartOffset : 0x0000
                VmaEndOffset : 0x0008
                VmNextOffset : 0x0010
                VmPrevOffset : 0x0018
                RbNodeOffset : 0x0020
                MmOffset : 0x0040
                FlagsOffset : 0x0050
                FileOffset : 0x00a0

            Dentry: !opaque_fields
                ParentOffset : 0x0018
                NameOffset : 0x0020
                DinameOffset : 0x0038
                InodeOffset : 0x0030

            MmStruct: !opaque_fields
                PgdOffset : 0x0050
                MmUsersOffset : 0x0058
                MmListOffset : 0x0098
                StartCodeOffset : 0x00f0
                EndCodeOffset : 0x00f8
                StartDataOffset : 0x0100
                EndDataOffset : 0x0108
                FlagsOffset : 0x0370
                ExeFileOffset : 0x03a0
                VmaOffset : 0x0000
                StartStack: 0x0120
                RbNodeOffset : 0x0008

            TaskStruct: !opaque_fields
                StackOffset : 0x0018
                UsageOffset : 0x0020
                FlagsOffset : 0x0024
                TasksOffset : 0x07a8
                PidOffset : 0x08a8
                TgidOffset : 0x08ac
                RealParentOffset : 0x08b8
                ParentOffset : 0x08c0
                MmOffset : 0x07f8
                StartTimeOffset : 0x09d0
                CommOffset : 0x0a50
                SignalOffset : 0x0aa0
                ExitCodeOffset : 0x0848
                ThreadNodeOffset : 0x0000
                ThreadGroupOffset : 0x0000
                CredOffset : 0x0a40
                FsOffset : 0x0a88
                FilesOffset : 0x0a90
                NsProxyOffset : 0x0a98
                GroupLeader: 0x08e8
                InExecve: 0x0868
                ExitSignal: 0x084c
                ThreadStructSp : 0x0018
                AltStackSp: 0x0ae0

            Fs: !opaque_fields
                RootOffset : 0x0018
                PwdOffset : 0x0028
                Sizeof : 0x0038

            FdTable: !opaque_fields
                MaxFdsOffset : 0x0000
                FdOffset : 0x0008

            Files: !opaque_fields
                FdtOffset : 0x0020
                Sizeof : 0x02c0

            Inode: !opaque_fields
                ImodeOffset : 0x0000
                UidOffset   : 0x0004
                GidOffset   : 0x0008
                Sizeof : 0x0258

            Socket: !opaque_fields
                StateOffset : 0x0000
                TypeOffset : 0x0004
                FlagsOffset : 0x0008
                SkOffset : 0x0020

            Sock: !opaque_fields
                NumOffset : 0x000e
                DportOffset : 0x000c
                DaddrOffset : 0x0000
                RcvSaddrOffset : 0x0004
                FamilyOffset : 0x0010
                StateOffset : 0x0012
                ProtoOffset : 0x0028
                V6DaddrOffset : 0x0038
                V6RcvSaddrOffset : 0x0048
                Sizeof : 0x02c8

            Cred: !opaque_fields
                UsageOffset : 0x0000
                RcuOffset : 0x0098
                Sizeof : 0x00a8

            Ungrouped: !opaque_fields
                FileDentryOffset : 0x0018
                ProtoNameOffset : 0x0158
                SignalListHeadOffset : 0x0010
                SocketAllocVfsInodeOffset : 0x0030
                Running : 2
