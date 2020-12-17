====================
Exceptions Mechanism
====================

Purpose
=======

Introcore works by blocking malicious attempts of accessing guest memory. Sometimes, the operating system, drivers, or processes would display behavior which triggers such alerts - for example, browsers may wish to place hooks on certain API functions, or they may wish to execute JIT code from dynamically allocated memory regions - but which are, in fact, benign, and not indicative of an attack. In order to be able to distinguish such behavior from an attack, Introcore has an exception mechanism, which is used to whitelist legitimate accesses to protected structures. An exception can be added for each legitimate access made to a protected structure. They are written in a JSON format, and the exception files are compiled into a binary file which is loaded and used by Introcore. Exceptions can be added manually or automatically. The following sections will describe the format of the binary exceptions file, the format of exceptions and signatures and how to add new exceptions for legitimate behavior.

The binary exceptions file
==========================

Format
------

The exceptions binary file has the following header:

.. code-block:: c

    typedef struct _UPDATE_FILE_HEADER
    {
        DWORD Magic;

        struct
        {
            WORD Major;
            WORD Minor;
        } Version;

        DWORD KernelExceptionsCount;
        DWORD UserExceptionsCount;
        DWORD SignaturesCount;

        DWORD BuildNumber;

        DWORD UserExceptionsGlobCount;

        DWORD _Reserved[2];
    } UPDATE_FILE_HEADER, *PUPDATE_FILE_HEADER;

For the exceptions binary file to be considered valid, the header fields must have the following values:

- The value of the :code:`Magic` field must be ':code:`ANXE`'
- The value of the :code:`Version.Major` field must be equal to the major version used by the update mechanism (currently, 2)
- The value of the :code:`Version.Minor` field should be grater or equal than the minor version used by the update mechanism (currently, 2); if the :code:`Version.Minor` value is greater than the minor version used by the update mechanism, not all of the features of the exceptions may be available
- The value of the :code:`KernelExceptionsCount`, :code:`UserExceptionsCount` or :code:`KernelUserExceptionsCount` must be greater than 0

Introcore cannot directly read the exception file, it must be loaded by the integrator.

Loading the exceptions file
---------------------------

Exceptions can be loaded with the :code:`UpdateExceptions` API. This can be done any time after :code:`NewGuestNotification` returns success.

If no exception file is loaded Introcore will run in log-only mode regardless of the loaded policy, allowing every action done by the guest.

Reloading the exceptions file
-----------------------------

Currently loaded exceptions are removed when a new exception file is loaded with :code:`UpdateExceptions` API.
Custom exceptions added with :code:`AddExceptionFromAlert` are not removed. To remove these exceptions the :code:`RemoveException` or the :code:`FlushAlertExceptions` API can be used.

Generating the exceptions file
------------------------------

Exception files can be generated using the **exceptions.py** script found in the *exceptions* directory in the HVMI repository. 

The script takes the following arguments:

+-------------+-------------------------------------------------------------------------------------+
| Argument    | Description                                                                         |
+=============+=====================================================================================+
| --help      | Used to show the help.                                                              |
+-------------+-------------------------------------------------------------------------------------+
| --config    | Used to provide a custom config file.                                               |
|             |                                                                                     |
|             | The default config file is '*config.json*'.                                         |
+-------------+-------------------------------------------------------------------------------------+
| --output    | Used to provide the name of the output file.                                        |
|             |                                                                                     |
|             | The default output file name is '*exceptions.bin*'.                                 |
+-------------+-------------------------------------------------------------------------------------+
| --verbose   | Used to set the verbosity level (possible values: 0, 1, 2).                         |
|             |                                                                                     |
|             | The default value for verbosity level is 0.                                         |
+-------------+-------------------------------------------------------------------------------------+
| --build     | Used to provide the build number of the output binary file.                         |
|             |                                                                                     |
|             | The major/minor version is gathered from *config.json* file.                        |
+-------------+-------------------------------------------------------------------------------------+
| jsons       | The JSON/directory to parse for exceptions. Multiple directories can be provided.   |
+-------------+-------------------------------------------------------------------------------------+

Usage:

.. code-block:: console

    python3 exceptions.py --build=<build_number> --verbose=<verbosity level> --output=<output binary file> --config=<config file> <JSON/directory>

Sample exceptions for Windows 7 and Windows 10 RS5 are in the *exceptions/json* directory.

.. note::

    Introcore only works with the binary file, so make sure the binary file is re-generated after any JSON file is modified.

Generate a *cyclic redundancy check* (CRC-32)
---------------------------------------------

To generate a *cyclic redundancy check*, the **crc32.py** script from the *exceptions* directory can be used:

.. py:function:: crc32(buffer, wide=False, initial_crc=-1)

    :param buffer: The byte array for which the CRC-32 is generated
    :param bool wide: Must be set to True only if buffer contains a wide char array
    :param initial_crc: The first value of the computed CRC-32
    :return: The CRC-32 value

Usage from a python interpreter:

.. code-block:: console

    python3
    >>> import crc32
    >>> crc32.crc32(b'crc32')
    >>> 2524371900
    >>> hex(crc32.crc32(b'crc32')
    >>> '0x9676dbbc'

Adding Exceptions
=================

Dynamically adding an exception from an introspection violation alert
---------------------------------------------------------------------

Adding an exception
~~~~~~~~~~~~~~~~~~~

Exceptions can be added dynamically from Introspection :ref:`violations events <chapters/3-alerts-and-events:violations>` using the :code:`AddExceptionFromAlert` API. These exceptions must be reloaded every-time Introcore is reloaded.

Removing an exception
~~~~~~~~~~~~~~~~~~~~~

Removing a specific exception can be done with the :code:`RemoveException` API.

Removing all exceptions added from alerts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Removing all exceptions can be done with the :code:`FlushAlertExceptions` API. 

Manually adding an exception
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An exception is made up of an entry in the *exceptions file* and an optional entry in the *signatures file*.

.. note::

    The *exceptions.py* script accepts JSON files with comments - in this way, exception can have a description.

Exception file format
^^^^^^^^^^^^^^^^^^^^^

The exception file is a JSON with the following content:

.. code-block:: none

    {
        "Type": "<type>",
        "Exceptions": [
            <exceptions>
        ]
    }

The **Type** field may be one of the following:

.. list-table:: Type values
    :header-rows: 1

    * - **Type**
      - **Desscription**

    * - kernel
      - The file contains entries for only kernel-mode

    * - user
      - The file contains entries for only user-mode

    * - user-glob-match
      - The file contains entries for only user-mode that supports glob content (see `man glob <https://linux.die.net/man/3/glob>`__)

    * - kernel-user
      - The file contains entries for kernel-user violations.

Exception entry format
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: json

    {
        "originator": "<originator name>",
        "victim" : "<victim name>",
        "object_type": "<object type>",
        "flags": "<flags>",
        "signatures": [
            "<signature_id_1>",
            "<signature_id_2>,
            ...
            <signature_id_n>"
        ]
    }

The :code:`originator` field may be one of the following:

+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Kernel-Mode Originator   | Description                                                                                                                                                  |
+==========================+==============================================================================================================================================================+
| String                   | A string that contains the name of the *originator*                                                                                                          |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| \*                       | The *originator* name can be any string .                                                                                                                    |
|                          | If the originator name is missing, the '\*' identifier is not matching and the '-' identifier should be used.                                                |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| \-                       | The *originator* name is missing.                                                                                                                            |
|                          | This must be used for actions which are performed from anonymous code regions (for example dynamically allocated code, which does not belong to any module). |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| [kernel]                 | The *originator* name is the operating system's *kernel* name.                                                                                               |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| [hal]                    | The *originator* name is the operating system's *Hardware Abstraction Layer (HAL)* name.                                                                     |
|                          | Valid for only Windows guests.                                                                                                                               |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+

+--------------------------+--------------------------------------------------------------------------------------------------------------+
| User-Mode Originator     | Description                                                                                                  |
+==========================+==============================================================================================================+
| String                   | A string that contains the name of the *originator*.                                                         |
+--------------------------+--------------------------------------------------------------------------------------------------------------+
| \*                       | The *originator* name can be any string.                                                                     |
|                          | If the originator nameis missing, the '\*' identifier is not matching and the '-' identifier should be used. |
+--------------------------+--------------------------------------------------------------------------------------------------------------+
| \-                       | The *originator* name is missing.                                                                            |
+--------------------------+--------------------------------------------------------------------------------------------------------------+
| [vdso]                   | The *originator* is the operating system virtual dynamic shared object (vDSO) name                           |
|                          | Valid only for Linux guests.                                                                                 |
+--------------------------+--------------------------------------------------------------------------------------------------------------+
| [vsyscall]               | The *originator* is the operating system *vsyscall* (valid for only Linux guests).                           |
+--------------------------+--------------------------------------------------------------------------------------------------------------+

+-----------------------------+-------------------------------------------------------------------------------------------------------+
| User-Mode-Glob Originator   | Description                                                                                           |
+=============================+=======================================================================================================+
| String                      | A glob-string that contains the name of the *originator*.                                             |
+-----------------------------+-------------------------------------------------------------------------------------------------------+
| \*                          | The *originator* name can be any string.                                                              |
+-----------------------------+-------------------------------------------------------------------------------------------------------+
| \-                          | The *originator* name is missing.                                                                     |
|                             | If the originator name is missing, '\*' identifier is not matching and '-' identifier should be used. |
+-----------------------------+-------------------------------------------------------------------------------------------------------+
| [vdso]                      | The *originator* is the operating system's dynamic shared object (vDSO) name.                         |
|                             | Valid only for Linux guests.                                                                          |
+-----------------------------+-------------------------------------------------------------------------------------------------------+
| [vsyscall]                  | The *originator* is the operating system *vsyscall* (valid for only Linux guests).                    |
+-----------------------------+-------------------------------------------------------------------------------------------------------+

+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| Kernel-User Originator   | Description                                                                                                                                                  |
+==========================+==============================================================================================================================================================+
| String                   | A string that contains the name of the *originator*.                                                                                                         |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| \*                       | The *originator* name can be any string .                                                                                                                    |
|                          | If the originator name is missing, the '\*' identifier is not matching and the '-' identifier should be used.                                                |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| \-                       | The *originator* name is missing.                                                                                                                            |
|                          | This must be used for actions which are performed from anonymous code regions (for example dynamically allocated code, which does not belong to any module). |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+
| [kernel]                 | The *originator* name is the operating system's *kernel* name.                                                                                               |
+--------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------+

The :code:`victim` field may be one of the following:

+----------------------+----------------------------------------------------------------------------------------------------------------------+
| Kernel-Mode Victim   | Description                                                                                                          |
+======================+======================================================================================================================+
| String               | A string that contains the name of the *victim*.                                                                     |
+----------------------+----------------------------------------------------------------------------------------------------------------------+
| \*                   | The *victim* name can be any string.                                                                                 |
+----------------------+----------------------------------------------------------------------------------------------------------------------+
| [own]                | The *victim* name is any object belonging to current driver.                                                         |
+----------------------+----------------------------------------------------------------------------------------------------------------------+
| [kernel]             | The *victim* name is the operating system's *kernel* name.                                                           |
+----------------------+----------------------------------------------------------------------------------------------------------------------+
| [hal]                | The *victim* name is the operating system's *Hardware Abstraction Layer (HAL)* name (valid for only Windows guests). |
+----------------------+----------------------------------------------------------------------------------------------------------------------+

+--------------------+----------------------------------------------------------------------------------------------------------------------------+
| User-Mode Victim   | Description                                                                                                                |
+====================+============================================================================================================================+
| String             | A string that contains the name of the *victim*.                                                                           |
+--------------------+----------------------------------------------------------------------------------------------------------------------------+
| \*                 | The *victim* name can be any string.                                                                                       |
+--------------------+----------------------------------------------------------------------------------------------------------------------------+
| [own]              | The *victim* name is any object belonging to current process.                                                              |
+--------------------+----------------------------------------------------------------------------------------------------------------------------+
| [vdso]             | The *victim* is the operating system operating system's *dynamic shared object (vDSO)* name (valid for only Linux guests). |
+--------------------+----------------------------------------------------------------------------------------------------------------------------+
| [vsyscall]         | The *victim* is the operating system *vsyscall* (valid for only Linux guests).                                             |
+--------------------+----------------------------------------------------------------------------------------------------------------------------+

+----------------------+------------------------------------------------------------------+
| Kernel-User Victim   | Description                                                      |
+======================+==================================================================+
| String               | A string that contains the name of the *victim*.                 |
+----------------------+------------------------------------------------------------------+
| \*                   | The *victim* name can be any string.                             |
+----------------------+------------------------------------------------------------------+
| [kernel]             | The *victim* name is the operating system's *kernel* name.       |
+----------------------+------------------------------------------------------------------+

The :code:`object_type` field may be one of the following:

+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| Kernel-Mode Object Type   | Description                                                                                                     |
+===========================+=================================================================================================================+
| none                      | Invalid.                                                                                                        |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| any                       | The modified object is anything with the modified name.                                                         |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver                    | The modified object is anything inside a driver.                                                                |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver exports            | The modified object is only the driver's EAT.                                                                   |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver imports            | The modified object is only the driver's IAT.                                                                   |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver code               | The modified object is only the driver's code sections.                                                         |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver data               | The modified object is only the driver's data sections.                                                         |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| driver resources          | The modified object is only the driver's resources sections.                                                    |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| ssdt                      | The modified object is SSDT (valid only for windows guests).                                                    |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| drvobj                    | The modified object is anything inside the driver object (valid only for windows guest).                        |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| fastio                    | The modified object is anything inside the driver's fast IO dispatch table (valid only for windows guest).      |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| msr                       | The modified object is a MSR.                                                                                   |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| cr4                       | The modified object is SMEP and/or SMAP bits of  CR4.                                                           |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| hal-heap                  | The modified object is anything inside the *hal heap* zone (valid for only Windows guests).                     |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| self-map-entry            | The modified object is the *self map entry* inside PDBR (valid for only Windows guests).                        |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| idt                       | The modified object is any IDT entry.                                                                           |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| idt-reg                   | The modified object is IDTR.                                                                                    |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| gdt-reg                   | The modified object is GDTR.                                                                                    |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| infinity-hook             | The modified object is WMI\_LOGGER\_CONTEXT.GetCpuClock used by InfinityHook (valid only for windows guests).   |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| token-privs               | The modified object is the Privileges field of a TOKEN structure.                                               |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| sud-exec                  | The object allows SharedUserData executions from a kernel-mode.                                                 |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| hal-perf-counter          | The modified object is a HalPerformanceCounter function.                                                        |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| sud-modification          | The modified object is a field contained within SharedUserData or the zone filled with zero after the structure.|
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| security-descriptor       | The modified object is the security descriptor pointer (valid only for windows guests).                         |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| acl-edit                  | The modified object is an Access Control List - SACL/DACL (valid only for windows guests).                      |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+
| interrupt-obj             | The modified object is an interrupt object from KPRCB's InterruptObject array.                                  |
+---------------------------+-----------------------------------------------------------------------------------------------------------------+

+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| User-Mode Object Type   | Description                                                                                                                            |
+=========================+========================================================================================================================================+
| any                     | The modified object is any with the modified name.                                                                                     |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| process                 | The modified object is only another process (injection basically).                                                                     |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| module                  | The modified object is inside the process modules.                                                                                     |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| module imports          | The modified object is inside the process module's IAT.                                                                                |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| nx\_zone                | The modified object is a non-execute (NX) zone.                                                                                        |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| module exports          | The modified object is inside the process module's EAT.                                                                                |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| thread-context          | The modified object is anything inside the structure CONTEXT (valid only for windows guest).                                           |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| peb32                   | The modified object is anything inside of the *PEB32* structure                                                                        |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| peb64                   | The modified object is anything inside of the *PEB64* structure                                                                        |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| apc-thread              | The modified object is the thread which was performed an asynchronous procedure call on.                                               |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| process-creation        | The object only allows process creation.                                                                                               |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| double-agent            | The object allows only dlls which are detected as suspicous (e.g. module loads before kernel32.dll through double agent technique).    |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| process-creation-dpi    | The object allows only process creation with deep-process-inspection (DPI) flags.                                                      |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| sud-exec                | The object allows SharedUserData executions from an application.                                                                       |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+
| instrumentation-callback| The object allows instrumentation callbacks.                                                                                           |
+-------------------------+----------------------------------------------------------------------------------------------------------------------------------------+

+---------------------------+-----------------------------------------------------------+
| Kernel-User Object Type   | Description                                               |
+===========================+===========================================================+
| any                       | The modified object is any with the modified name.        |
+---------------------------+-----------------------------------------------------------+
| module                    | The modified object is inside the process modules.        |
+---------------------------+-----------------------------------------------------------+
| module imports            | The modified object is inside the process module's IAT.   |
+---------------------------+-----------------------------------------------------------+
| module exports            | The modified object is inside the process module's EAT.   |
+---------------------------+-----------------------------------------------------------+

The :code:`flags` field may be one of the following:

+---------------------+----------------------------------------------------------------------------+
| Kernel-Mode Flags   | Description                                                                |
+=====================+============================================================================+
| feedback            | The exception allows the violation and sends an event used for feedback.   |
+---------------------+----------------------------------------------------------------------------+
| 32                  | The exception is valid on only 32 bit systems.                             |
+---------------------+----------------------------------------------------------------------------+
| 64                  | The exception is valid on only 64 bit systems.                             |
+---------------------+----------------------------------------------------------------------------+
| init                | The exception will match only for the init phase of a driver.              |
+---------------------+----------------------------------------------------------------------------+
| linux               | The exception is valid for only Linux .                                    |
+---------------------+----------------------------------------------------------------------------+
| read                | The exception is valid for only read violation.                            |
+---------------------+----------------------------------------------------------------------------+
| write               | The exception is valid for only write violation.                           |
+---------------------+----------------------------------------------------------------------------+
| exec                | The exception is valid for only exec violation.                            |
+---------------------+----------------------------------------------------------------------------+
| non-driver          | The original RIP is outside a driver and it returns into a driver.         |
+---------------------+----------------------------------------------------------------------------+
| return-drv          | The exception will take into consideration the return driver.              |
+---------------------+----------------------------------------------------------------------------+
| smap                | The exception is valid for only CR4.SMAP write.                            |
+---------------------+----------------------------------------------------------------------------+
| smep                | The exception is valid for only CR4.SMEP write.                            |
+---------------------+----------------------------------------------------------------------------+
| integrity           | The exception is valid for only integrity zone.                            |
+---------------------+----------------------------------------------------------------------------+

+-------------------+---------------------------------------------------------------------------------------------+
| User-Mode Flags   | Description                                                                                 |
+===================+=============================================================================================+
| feedback          | The exception allows the violation and sends an event used for feedback.                    |
+-------------------+---------------------------------------------------------------------------------------------+
| 32                | The exception is valid on only 32 bit systems/processes.                                    |
+-------------------+---------------------------------------------------------------------------------------------+
| 64                | The exception is valid on only 64 bit systems/processes.                                    |
+-------------------+---------------------------------------------------------------------------------------------+
| init              | The exception will match for only the init phase of a process.                              |
+-------------------+---------------------------------------------------------------------------------------------+
| return            | The exception will take into consideration the return dll.                                  |
+-------------------+---------------------------------------------------------------------------------------------+
| linux             | The exception is valid for only Linux .                                                     |
+-------------------+---------------------------------------------------------------------------------------------+
| read              | The exception is valid for only read violation.                                             |
+-------------------+---------------------------------------------------------------------------------------------+
| write             | The exception is valid for only write violation.                                            |
+-------------------+---------------------------------------------------------------------------------------------+
| exec              | The exception is valid for only exec violation.                                             |
+-------------------+---------------------------------------------------------------------------------------------+
| system-process    | The exception is valid only if the originator process is a system process.                  |
+-------------------+---------------------------------------------------------------------------------------------+
| child             | The exception is valid only if the modified process is a child of the originator process.   |
+-------------------+---------------------------------------------------------------------------------------------+
| one-time          | The exception is valid only once.                                                           |
+-------------------+---------------------------------------------------------------------------------------------+
| like-apphelp      | The exception is valid only for *apphelp* process.                                          |
+-------------------+---------------------------------------------------------------------------------------------+

+---------------------+----------------------------------------------------------------------------+
| Kernel-Mode Flags   | Description                                                                |
+=====================+============================================================================+
| feedback            | The exception allows the violation and sends an event used for feedback.   |
+---------------------+----------------------------------------------------------------------------+
| 32                  | The exception is valid on only 32 bit systems.                             |
+---------------------+----------------------------------------------------------------------------+
| 64                  | The exception is valid on only 64 bit systems.                             |
+---------------------+----------------------------------------------------------------------------+
| init                | The exception will match for only the init phase of a driver.              |
+---------------------+----------------------------------------------------------------------------+
| linux               | The exception is valid for only Linux .                                    |
+---------------------+----------------------------------------------------------------------------+
| read                | The exception is valid for only read violation.                            |
+---------------------+----------------------------------------------------------------------------+
| write               | The exception is valid for only write violation.                           |
+---------------------+----------------------------------------------------------------------------+
| exec                | The exception is valid for only exec violation.                            |
+---------------------+----------------------------------------------------------------------------+
| return-drv          | The exception will take into consideration the return driver.              |
+---------------------+----------------------------------------------------------------------------+

Example
^^^^^^^

.. code-block:: none

    {
        "Type": "kernel",
        "Exceptions": [
            {
                "originator": "driver.sys",
                "victim": "*",
                "object_type": "driver imports",
                "flags": "64 write"
                "signatures": [
                    "signature_id"
                ]
            },

            {
                "originator": "[kernel]",
                "victim": "[own]",
                "object_type": "driver"
            },
    }

.. code-block:: none

    {
        "Type": "user",
        "Exceptions": [
            {
                "process": "process.exe",
                "originator": "process.exe",
                "victim": "library.dll",
                "object_type": "module",
                "flags": "return"
                "signatures": [
                    "process-writes-codeblocks"
                ]
            },

            {
                "originator": "process1.exe",
                "victim": "process2.exe",
                "object_type": "process",
                "flags" : "child"
            },
    }

.. code-block:: none

    {
        "Type": "kernel-user",
        "Exceptions": [
            {
                "process": "process.exe",
                "originator": "[kernel]",
                "victim": "library.dll",
                "object_type": "module",
                "flags": "return"
                "signatures": [
                    "writes-codeblocks",
                    "writes-exports"
                ]
            },
    }

Signature file format
^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    {
        "Type": "<type>",
        "Signatures": [
            <siganture 1>,
            <signature 2>,
            ...
            <signature n>
        ]
    }

The :code:`type` field may be one of the following:

+----------+---------------------------------------------------+
| Type     | Description                                       |
+==========+===================================================+
| kernel   | The file contains entries for only kernel-mode.   |
+----------+---------------------------------------------------+
| user     | The file contains entries for only user-mode.     |
+----------+---------------------------------------------------+

Signature entry format
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: none

    "Signatures": [
        {
            "sig_type": "<type>",
            "sig_id": "<id>",
            "flags" : <flags>,
            ...
            ]
        }
    ]

The :code:`type` field may be one of the following:

- Codeblocks
- Export
- Value
- Value Code
- IDT
- OS Version
- Introspection Version
- Process Creation DPI Flags

The :code:`id` field must be an unique string.

The :code:`flags` field may be one of the following:

+----------+--------------------------------------------------------------------------------------------------------+
| Flags    | Description                                                                                            |
+==========+========================================================================================================+
| 32       | The signature is valid on only 32 bit systems/processes.                                               |
+----------+--------------------------------------------------------------------------------------------------------+
| 64       | The signature is valid on only 64 bit systems/processes.                                               |
+----------+--------------------------------------------------------------------------------------------------------+
| medium   | The signature requires a medium level of extracted codeblocks (valid only for codeblocks signature).   |
+----------+--------------------------------------------------------------------------------------------------------+
| linux    | The signature is valid on  only Linux guests.                                                          |
+----------+--------------------------------------------------------------------------------------------------------+
| cli      | The process command line hash is used for the value field (valid only for value signature).            |
+----------+--------------------------------------------------------------------------------------------------------+

Signature Types
^^^^^^^^^^^^^^^

Codeblocks
''''''''''

.. code-block:: none

    {
        "sig_type": "codeblocks",
        "sig_id": "<id>",
        "score": <score>,
        "flags" : <flags>,
        "hashes": [
            <[list of hashes 1]>, <[list of hashes 2]>, ... <[list of hashes n]>
        ]
    }

- The :code:`score` field contains an integer that represents the number of (minimum) hashes from the :code:`hashes` field that need to match.
- The :code:`hashes` field contains a list of one or more *hashes list*; a *hash* entry is a DWORD value that represents *crc32* of an instruction. 

.. code-block:: none

    {
        "Type": "user",
        "Signatures": [
            {
                "sig_type": "codeblocks",
                "sig_id": "signature_codeblocs",
                "score": 3,
                "hashes": [
                    ["0x96cdfa4f", "0x4ead2c2a", "0x3c5d6c96", "0x692abaf9", "0x692abaf9", "0x85f1ff8f"],
                    ["0xd477aa4e", "0x96cdfa4f", "0x4ead2c2a", "0x3c5d6c96", "0x692abaf9", "0x8bc90a2b"],
                    ["0x49d4c934", "0x84ea3c56", "0x85f1ff8f", "0x9a2a6722", "0xcad991c2", "0x5d269c1b"],
                ]
            },
    }

Export
''''''

.. code-block:: none

    {
        "sig_type": "export",
        "sig_id": "<id>",
        "library": "<library name>",
        "hashes": [
            {
                "name": "<function name 1>",
                "delta": <delta 1>
            },
            {
                "name": "<function name 2>",
                "delta": <delta 2>
            },

            ...

            {
                "name": "<function name n>",
                "delta": <delta n>
            }
        ]
    }

- The :code:`library` field contains a string that represents the library name.
- The :code:`hashes` field contains a list of pairs: 

  - The :code:`name` field contains the name of one function from the specified :code:`library`.
  - The :code:`delta` field contains the maximum number of bytes that are modified (relative to the function address start).

.. code-block:: none

    {
        "Type": "user",
        "Signatures": [
            {
                "sig_type": "export",
                "sig_id": "exports_signature",
                "library": "ntdll.dll",
                "hashes": [
                    {
                        "name": "NtCreateKey",
                        "delta": 8
                    },

                    {
                        "name": "NtOpenKey",
                        "delta": 2
                    }
                ]
            }
        ]
    }

Value
'''''

.. code-block:: none

    {
        "sig_type": "value",
        "sig_id": "<id>",
        "score": <score>,
        "hashes": [
            {
                "offset": <offset 1>,
                "size": <size 1>,
                "hash": "<hash 1>"
            },
            {
                "offset": <offset 2>,
                "size": <size 2>,
                "hash": "<hash 2>"
            },
            ...
            {
                "offset": <offset n>,
                "size": <size n>,
                "hash": "<hash n>"
            }
        ]
    }

- The :code:`score` field contains an integer that represents the number of (minimum) hashes from the :code:`hashes` list that need to match.
- The :code:`hashes` field contains a list of pairs: 

  - The :code:`offset` field contains an integer that represents the offset from the beginning of the write.
  - The :code:`size` field contains an integer that represents the size of the write.
  - The :code:`hash` field contains a *crc32-hash* of the written memory zone.

.. code-block:: none

    {
        "Type": "user",
        "Signatures": [

            {
                "sig_type": "value",
                "sig_id": "value_signature",
                "score": 1,
                "hashes": [
                    {
                        "offset": 4,
                        "size": 5,
                        "hash": "0x34ca1b03"
                    },

                    {
                        "offset": 28,
                        "size": 16,
                        "hash": "0x34ca1b03"
                    }
                ]
            }
        ]
    }

Value Code
''''''''''

.. code-block:: none

    {
        "sig_type": "value-code",
        "sig_id": "<id>",
        "flags": "<flags>",
        "offset": <offset>,
        "pattern": [
            "<item1>",
            "<item2>",
            ...
            "<item n>"
        ]
    }

- The :code:`offset` entry contains an integer that represents the offset from the beginning of the write.
- The :code:`patern` entry contains a list of opcodes as strings representing instruction bytes. *0x100* can be used as a wild-card in order to match any value between *0x00* and *0xff* (inclusive).

.. code-block:: none

    {
        "Type": "user",
        "Signatures": [

            {
                "sig_type": "value-code",
                "sig_id": "value-code_signature",
                "offset": 0,
                "flags": "32 64",
                "pattern": [
                    "0xb8", "0x70", "0x100", "0x100", "0x100",  // MOV       eax, 0x1237125
                    "0xe9", "0x24", "0xff", "0xff", "0xff",     // JMP       0xffffff89
                ]
            },
        ]
    }

IDT 
''''

.. code-block:: none

    {
        "sig_type": "idt",
        "sig_id": "<id>,
        "entry": <entry>
    }

The :code:`entry` entry contains the IDT entry number.

.. code-block:: none

    {
        "Type": "kernel",
        "Signatures": [
            {
                "sig_type": "idt",
                "sig_id": "idt_signature",
                "entry": 4
            }
        ]
    }

Introspection Version
'''''''''''''''''''''

.. code-block:: none

    {
        "sig_type": "version-intro",
        "sig_id": "<signature id>",
        "flags": "<flags>",
        "minimum": "<major.minor.revision>",
        "maximum": "<major.minor.revision>"
    }

- The :code:`minimum` field contains the minimum introspection version.
- The :code:`maximum` field contains the maximum introspection version.

.. code-block:: none

    {
        "Type": "kernel",
        "Signatures": [
            {
                "sig_type": "version-intro",
                "sig_id": "version-intro_signature",
                "flags": "32 64",
                "minimum": "1.1.0",
                "maximum": "1.2.0"
            }
        ]
    }

OS Version
''''''''''

.. code-block:: none

    {
        "sig_type": "version-os",
        "sig_id": "<signature id>",
        "flags": "<flags>",
        "minimum": "<major.minor.revision>/<build number>",
        "maximum": "<major.minor.revision>/<build number>"
    }

- The :code:`minimum` field contains the minimum version.
- The :code:`maximum` field contains the maximum version.

.. note::

   - major.minor.revison format is used for Linux guests.
   - build number is used for Windows guests.

.. code-block:: none

    {
        "Type": "kernel",
        "Signatures": [
            {
                "sig_type": "version-os",
                "sig_id": "version-intro_signature",
                "flags": "32 64",
                "minimum": "14.0.0",
                "maximum": "15.2.0"
            }
        ]
    }
    
Process Creation DPI Flags
''''''''''''''''''''''''''

.. code-block:: none

    {
        "sig_type": "process-creations",
        "sig_id": "<signature id>",
        "flags": "<flags>",
        "create_mask": [
                "<dpi flag 1>",
                "<dpi flag 2>",
                ...
                "<dpi flag n>"
            ]
    }

- The :code:`create_mask` field contains a list of DPI flags that the current signature should match. The list of possible flags is:

  - :code:`debug` - for processes which are created being debugged.
  - :code:`pivoted-stack` - for processes which are created by a thread in the parent which has a pivoted stack.
  - :code:`stolen-token` - for processes which are created having a token belonging to another process.
  - :code:`heap-spray` - for process creation in which the parent seems to have been heap-sprayed.
  - :code:`token-privs` - for process creation where the parent has the privileges increased in a malicious manner.
  - :code:`thread-start` - when the thread which creates the process seem to have started in a section containing malicious code.
  - :code:`security-descriptor` - for process creation in which the parent has an altered security descriptor pointer.
  - :code:`acl-edit` - for process creation in which the parent has an altered ACL (SACL/DACL).

.. code-block:: none

    {
        "sig_type": "process-creation",
        "sig_id": "sig-pivoted-stack-dpi",
        "flags": "32 64",
        "create_mask": [
            "pivoted-stack"
        ]
    }

Adding an exception/signature from the Introspection log
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For any alert logged by the exception mechanism, a base64 string is also logged.

To generate the exception-signature JSON, the scripts in the *deserializer* (see :ref:`Deserializer <chapters/4-exceptions-mechanism:Deserializer>`) directory can be used.

The command line used to show the information about the alert and to show the exception JSON and the signature JSON is:

.. code-block:: console

    python3 main.py --content <base64 string> --exception

The output of the command line:

.. code-block:: none

    -------------------- Exception JSON --------------------
    {
        "Type": "kernel",
        "Exceptions": [
            {
                "originator": "originator.sys",
                "victim": "victim.sys",
                "object_type": "driver code",
                "flags": " 32 64  write ",
                "signature": [
                    "codeblocks-sig"
                ]
            }
        ]
    }
    -------------------- Signature JSON --------------------
    {
        "Type": "kernel",
        "Signatures": [
            {
                "sig_type": "codeblocks",
                "sig_id": "codeblocks-sig",
                "flags": "  32 64 ",
                "score": 5,
                "hashes": [
                    "0xbc24175",
                    "0x5934f12b",
                    "0x8984c1a8",
                    "0x987b230b",
                    "0xcfe6d14f",
                    "0xe44cc01d"
                ]
            }
        ]
    }

Deserializer
==========================

For any alert logged by the exception mechanism, a base64 string that contains the information about the alert, is also
logged.

In order to deserialize the logged base64 string, the scripts in the *deserializer* directory can be used.

The **main.py** script is the entry-point of the deserializer and it supports the following arguments:

+---------------+-----------------------------------------------------------------------------------------------------+
| Argument      | Description                                                                                         |
+===============+=====================================================================================================+
| --help        | Used to show the help.                                                                              |
+---------------+-----------------------------------------------------------------------------------------------------+
| --content     | Used to provide the base64 string.                                                                  |
+---------------+-----------------------------------------------------------------------------------------------------+
| --alert       | Used to parse the provided content and show the information about the alert.                        |
+---------------+-----------------------------------------------------------------------------------------------------+
| --exception   | Used to parse the provided content and show the generated exception JSON and the signature JSON.    |
+---------------+-----------------------------------------------------------------------------------------------------+


.. code-block:: console

    python3 main.py --content <base64 string> --alert

The output of the command line:

.. code-block:: console

    Object header -> Version: 1, Type: 'Start Originator Object Event' (1), Size: 0
    -------------------- Originator --------------------
    Object header -> Version: 1, Type: 'Kernel Driver Object' (17), Size: 45
            Object Gva: 0xffffffffa04e4400
            Base VA: 0xffffffffa04e0000
            Size: 0x0000543c
            Entry point: 0xffffffffa04e7000
            Section: text
    Object header -> Version: 1, Type: 'Linux Kernel Module Object' (20), Size: 49
            Path: 'driver'
            Init Layout Base: 0xffffffffa04e7000
            Init Layout Size: 0x000021a7
            Init Layout Text Size: 0x00001000
            Init Layout RoSize: 0x00001000
            Core Layout Base: 0xffffffffa04e0000
            Core Layout Size: 0x0000543c
            Core Layout Text Size: 0x00002000
            Core Layout RoSize: 0x00002000
    Object header -> Version: 1, Type: 'Kernel Driver Return Object' (18), Size: 45
            Object Gva: 0x0000000000000000
            Base VA: 0xffffffff81000000
            Size: 0x007d1000
            Entry point: 0x0000000000000000
            Section: text
    Object header -> Version: 1, Type: 'Linux Kernel Module Object' (20), Size: 51
            Path: 'kernel'
            Init Layout Base: 0x0000000000000000
            Init Layout Size: 0x00000000
            Init Layout Text Size: 0x00000000
            Init Layout RoSize: 0x00000000
            Core Layout Base: 0xffffffff81000000
            Core Layout Size: 0x00916000
            Core Layout Text Size: 0x00545bf1
            Core Layout RoSize: 0x00545bf1
    Object header -> Version: 1, Type: 'Instrux Object' (26), Size: 24
            RIP: 0xffffffffa04e0ccb
            Bytes: (65, 15, 182, 52, 36, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    Object header -> Version: 1, Type: 'End Originator Object Event' (2), Size: 0
    --------------------  --------------------
    Object header -> Version: 1, Type: 'Start Victim Object Event' (3), Size: 0
    -------------------- Victim --------------------
    Object header -> Version: 1, Type: 'Victim Object' (5), Size: 16
            Object type: KmModule (6)
            Zone type: Ept (1)
            Zone Flags: 0x20000004
    Object header -> Version: 1, Type: 'Ept Object' (6), Size: 16
            Gva: 0xffffffff81065000
            Gpa: 0x0000000001065000
    Object header -> Version: 1, Type: 'Write Info Object' (27), Size: 132
        Access size: 1
        Old Value: 0x000000006666000e
        New Value: 0x000000000000000e
    Object header -> Version: 1, Type: 'End Victim Object Event' (4), Size: 0
