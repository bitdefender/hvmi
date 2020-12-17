DLL hook protection
-------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_PROT_CORE_HOOKS**
    - **yes**
    - **no**
    - Hooking_
    - | Enable **hook protection** inside core Windows DLLs.
      | The protected DLLs are:
      | - ntdll.dll
      | - kernel32.dll
      | - kernelbase.dll
      | - user32.dll
      | - wow64.dll
      | - wow64win.dll
      | - wow64cpu.dll
      | Write attempts to these dlls will be blocked.

  * - **PROC_OPT_PROT_WSOCK_HOOKS**
    - **yes**
    - **no**
    - Hooking_
    - | Enable **hook prevention** inside core Windows network access libraries:
      | - wininet.dll
      | - ws2_32.dll
      | Write attempts to these dlls will be blocked.

Injection protection
--------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_PROT_WRITE_MEM**
    - **yes**
    - **yes**
    - Injection_
    - | Enables injection protection inside the target process, using the **WriteProcessMemory** technique (Windows).
      | Enables injection protection inside the target process, using the **process_vm_rw**, **__access_remote_vm** and **ptrace** (if the *PTRACE_POKETEXT* / *PTRACE_POKEDATA* request is used)  techniques (Linux).

  * - | **PROC_OPT_PROT_SET_THREAD_CTX**
      | **PROC_OPT_PROT_PTRACE**
    - **yes**
    - **yes**
    - Injection_
    - | Enables injection protection inside the target process, using the **SetThreadContext** technique (Windows).
      | Enables injection protection inside the target process, using the **ptrace** (if the *PTRACE_SETFPREGS* / *PTRACE_SETFPXREGS* / *PTRACE_SETREGS* request is used) technique (Linux).

  * - **PROC_OPT_PROT_QUEUE_APC**
    - **yes**
    - **no**
    - Injection_
    - Enable injection protection inside the target process, using the **QueueUserApc** technique (Windows).

  * - **PROC_OPT_PROT_DOUBLE_AGENT**
    - **yes**
    - **no**
    - Injection_
    - | Prevents module loads before **kernel32.dll**, in processes that load **kernel32.dll** (e.g. the processes from subsystem native will not load **kernel32.dll** at all).
      | It is used for **double agent** detection and prevention.

  * - **PROC_OPT_PROT_INSTRUMENT**
    - **yes**
    - **no**
    - Injection_
    - Enable injection protection inside the target process, using the instrumentation callback **NtSetInformationProcess** technique (Windows).
Exploit protection
------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_PROT_EXPLOIT**
    - **yes**
    - **yes**
    - `Exploit client`_
    - | Enable **generic exploit protection**
      | This covers any memory region inside the process address space, including stack and heaps.
      | Attempts to execute code from suspicious memory regions will be blocked.

Unpack detection
----------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_PROT_UNPACK**
    - **yes**
    - **no**
    - N/A
    - | Enable **unpack**/**decryption** events for the main module only.
      | This option does not block anything, instead provides hint with regard to packed/encrypted code.
      | This option can be used to detected unpacked/decrypted code in main process modules.

Misc protection
---------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_PROT_PREVENT_CHILD_CREATION**
    - **yes**
    - **yes**
    - `Exec API`_
    - | Prevents the process from creating **child processes** (other than instances of itself).
      | For example, we want to allow chrome.exe to create new chrome.exe processes (tabs/windows), but we want to prevent it from starting other processes.
      | Use it with care, as it is very prone to false-positives.

  * - **PROC_OPT_PROT_SCAN_CMD_LINE**
    - **yes**
    - **no**
    - | Scripting_
      | PowerShell_
    - The **command lines** of the processes protected with this flag will be sent to the **scan engines**, to be scanned for malware.

Misc process options
--------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Mitre
    - Description

  * - **PROC_OPT_KILL_ON_EXPLOIT**
    - **yes**
    - **yes**
    - N/A
    - | If set, **exploit detection** inside the given process will lead to **process termination** .
      | The process may not terminate immediately, depending how exceptions are handled, but the code stream that triggered the exploit detection is guaranteed to be terminated by an exception injection.

  * - **PROC_OPT_BETA**
    - **yes**
    - **yes**
    - N/A
    - | Enables **report only detections** for this process only
      | This will enable generation of events but without actually blocking them (very useful for untested processes).

.. _Hooking: https://attack.mitre.org/techniques/T1179/
.. _Injection: https://attack.mitre.org/techniques/T1055/
.. _Exploit client: https://attack.mitre.org/techniques/T1203/
.. _Exec API: https://attack.mitre.org/techniques/T1106/
.. _Scripting: https://attack.mitre.org/techniques/T1064/
.. _PowerShell: https://attack.mitre.org/techniques/T1086/
