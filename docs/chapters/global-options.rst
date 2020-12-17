Kernel protection options
-------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - | **INTRO_OPT_PROT_KM_NT**
      | **INTRO_OPT_PROT_KM_LX**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - Enable Windows **NT kernel image** protection (on Windows) or **Linux kernel image** protection (on Linux). Writes to these areas will be blocked.

  * - **INTRO_OPT_PROT_KM_SSDT**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable Windows **SSDT (System Service Dispatch Table)** protection. Modifications to the SSDT will be blocked.

  * - **INTRO_OPT_PROT_KM_VDSO**
    - **no**
    - **yes**
    - protection
    - Hooking_
    - Protect the **vDSO** page on Linux.

  * - **INTRO_OPT_PROT_KM_NT_EAT_READS**
    - **yes**
    - **no**
    - protection
    - `Exploit remote`_
    - Enables **NT EAT** read protection. Attempts to read the EAT from suspicious memory regions will be blocked.

  * - **INTRO_OPT_PROT_KM_LX_TEXT_READS**
    - **no**
    - **yes**
    - protection
    - `Exploit remote`_
    - Enable Linux kernel **_text** **section** read protection.

  * - **INTRO_OPT_PROT_KM_SUD_EXEC**
    - **yes**
    - **no**
    - protection
    - `Exploit remote`_
    - Enable execution prevention inside the **SharedUserData** page on Windows systems.

HAL protection options
----------------------

.. list-table:: 
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_KM_HAL**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable Windows **HAL (Hardware Abstraction Layer)** protection. Writes inside hal.dll will be blocked.

  * - **INTRO_OPT_PROT_KM_HAL_DISP_TABLE**
    - **yes**
    - **no**
    - protection
    - `Exploit privesc`_
    - Enable **HDT (Hal Dispatch Table)** protection for privilege-escalation detection. Modifications to the HDT will be blocked.

  * - **INTRO_OPT_PROT_KM_HAL_HEAP_EXEC**
    - **yes**
    - **no**
    - protection
    - `Exploit remote`_
    - Enable **HAL Heap** execution prevention. Attempts to execute code from the HAL heap region will be blocked.

  * - **INTRO_OPT_PROT_KM_HAL_INT_CTRL**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable **HAL Interrupt Controller** write protection. Attempts to modify pointers inside the HAL Interrupt Controller will be blocked.
    
  * - **INTRO_OPT_PROT_KM_HAL_PERF_CNT**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable **HAL Performance Counter** integrity protection. Modifications which are detected on the function pointer inside HalPerformanceCounter that gets called on KeQueryPerformanceCounter will be blocked.

Driver & driver object protection options
-----------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - | **INTRO_OPT_PROT_KM_NT_DRIVERS**
      | **INTRO_OPT_PROT_KM_LX_MODULES**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - | On Windows, enable **NT core drivers** protection. Modifications made to them will be blocked. 
      | The protected drivers are:
      | - iastor.sys
      | - ndis.sys
      | - netio.sys
      | - iastorV.sys
      | - iastorAV.sys
      | - disk.sys
      | - atapi.sys
      | - storahci.sys
      | - ataport.sys
      | - ntfs.sys
      | - tcpip.sys
      | - srv.sys
      | - srv2.sys
      | - srvnet.sys
      | On Linux, enables write protection for all loaded modules.

  * - **INTRO_OPT_PROT_KM_AV_DRIVERS**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - | Enable **Bitdefender drivers** protection. Modifications made to them will be blocked. 
      | The protected drivers are:
      | - avc3.sys 
      | - avckf.sys
      | - winguest.sys
      | - trufos.sys
      | - bdselfpr.sys
      | - gzflt.sys
      | - bdvedisk.sys
      | - bdsandbox.sys
      | - bdfndisf6.sys
      | - bdfwfpf.sys
      | - bdelam.sys
      | - bddci.sys
      | - edrsensor.sys
      | - ignis.sys
      | - gemma.sys

  * - **INTRO_OPT_PROT_KM_XEN_DRIVERS**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - | Enable **Xen drivers** protection. Modifications made to them will be blocked.
      | The protected drivers are:
      | - picadm.sys 
      | - ctxad.sys
      | - ctxusbb.sys
      | - ctxsmcdrv.sys
      | - picapar.sys
      | - picaser.sys
      | - picakbm.sys
      | - picakbf.sys
      | - picamouf.sys
      | - picaTwComms.sys
      | - picavc.sys
      | - picacdd2.sys
      | - picadd.sys

  * - **INTRO_OPT_PROT_KM_DRVOBJ**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - | Enable **Driver Object and Fast I/O Dispatch** protection for every protected driver. 
      | It must be used when a combination of **INTRO_OPT_PROT_KM_NT_DRIVERS**, **INTRO_OPT_PROT_KM_AV_DRIVERS**, and **INTRO_OPT_PROT_KM_XEN_DRIVERS** is used. 
      | Modifications to the IRP M/J functions or Fast I/O dispatch routines will be blocked.

CPU specific structures and registers
-------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_KM_IDT**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - | Enable **IDT (Interrupt Descriptor Table)** protection. Modifications to the IDT entries will be blocked. 
      | Note that this option only protects the IDT table, not the register.

  * - **INTRO_OPT_PROT_KM_IDTR**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - | Enable **IDTR** protection. Attempts to modify the IDTR via LIDT will be blocked. 
      | **Available starting with Xen 4.11.**

  * - **INTRO_OPT_PROT_KM_GDTR**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - | Enable **GDTR** protection. Attempts to modify the GDTR using LGDT will be blocked. 
      | **Available starting with Xen 4.11**.

  * - **INTRO_OPT_PROT_KM_CR4**
    - **yes**
    - **yes**
    - protection
    - | Rootkit_
      | `Exploit privesc`_
    - | Enable **CR4.SMEP (Supervisor Mode Execution Prevention)** and **CR4.SMAP (Supervisor Mode Access Prevention)** protection for privilege-escalation detection. 
      | Attempts to disable SMEP or SMAP will be blocked.

  * - **INTRO_OPT_PROT_KM_MSR_SYSCALL**
    - **yes**
    - **yes**
    - protection
    - Rootkit_
    - | Enable **SYSCALL/SYSENTER MSR** protection. Attempts to modify these MSRs will be blocked.
      | The protected MSRs are:
      | - IA32_SYSENTER_EIP 
      | - IA32_SYSENTER_ESP
      | - IA32_SYSENTER_CS
      | - IA32_STAR
      | - IA32_LSTAR

Misc integrity checks
---------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_KM_SYSTEM_CR3**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable **System process PDBR** protection. Changes of System CR3 will lead to an alert.

  * - **INTRO_OPT_PROT_KM_SELF_MAP_ENTRY**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - | Enable protection against writes on the **self-mapping entry in all the page tables** from the system, on x64 systems. 
      | It will protect this entry in the following way:
      | - For protected processes and the kernel page table on Windows < RS4 - EPT hook on the page table at the self-mapping index. 
      | - For unprotected processes on Windows < RS4 or all processes and kernel page table on Windows >= RS4 - Integrity checking once every second that the self map entry is not modified. Attempts to modify the self-map entry inside the Cr3 (for example, by making it accessible to user mode) will be blocked.

  * - **INTRO_OPT_PROT_KM_LOGGER_CONTEXT**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable the Windows kernel logger context protection against malicious modifications (most commonly known as infinity hook).
    
  * - **INTRO_OPT_PROT_KM_SUD_INTEGRITY**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable integrity checks over various SharedUserData fields, as well as the zero-filled zone after the SharedUserData structure.
    
  * - **INTRO_OPT_PROT_KM_INTERRUPT_OBJ**
    - **yes**
    - **no**
    - protection
    - Rootkit_
    - Enable protection against modifications of interrupt objects from KPRCB's InterruptObject.

Process credentials, tokens & privileges
----------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - | **INTRO_OPT_PROT_KM_TOKEN_PTR**
      | **INTRO_OPT_PROT_KM_CREDS**
    - **yes**
    - **yes**
    - protection
    - Token_
    - | Enable **process token pointer** (Windows) or **creds protection** (Linux) for privilege-escalation detection.
      | Processes which run with a stolen token or modified creds will trigger an alert.
      | This feature protects the token pointer inside the EPROCESS (on Windows) or the contents of the creds structure (on Linux).

  * - **INTRO_OPT_PROT_KM_TOKEN_PRIVS**
    - **yes**
    - **no**
    - protection
    - Token_
    - Enable **SEP_TOKEN_PRIVIELEGES** protection for each process. Suspicious modifications of the **Enabled**/**Present** bitmaps inside the TOKEN structure will be blocked.

  * - **INTRO_OPT_PROT_KM_SD_ACL**
    - **yes**
    - **no**
    - protection
    - Token_
    - Enable integrity protection for the **security descriptor pointer** and **Access Control List (ACL)** of each process. Suspicious modifications of the security desciptor pointer or the ACLs (SACL/DACL) pointed by it will be blocked.

Instrumentation based protection features
-----------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_KM_SWAPGS**
    - **yes**
    - **yes**
    - protection
    - N/A
    - | Enable SWAPGS vulnerability (CVE-2019-1125) mitigations. 
      | If enabled, Introcore will parse the  **Windows**/**Linux** kernel, it will identify vulnerable **SWAPGS** gadgets, and it will serialize them, thus mitigating the main attack vector for this vulnerability.
      | **This option cannot be toggled dynamically. To enable SWAPGS mitigation, this option must be set when starting Introcore. It will be disabled only when Introcore is unloaded. Changing this option requires an Introcore restart.**
      | **This option will not generate any kind of event. Since it mitigates a Spectre variant, there's no way to know if an attacker tried to exploit it or not.**

DPI - Deep Process Introspection options
----------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_DPI_DEBUG**
    - **yes**
    - **no**
    - protection
    - `Dev util`_
    - | Enable protection against malicious attempts of **starting a process as a debugged process**, which will allow the parent to control and inspect it. 
      | Applies to all processes, not just protected ones.

  * - **INTRO_OPT_PROT_DPI_STACK_PIVOT**
    - **yes**
    - **yes**
    - protection
    - `Exploit client`_
    - Enable protection against process creation with a **pivoted stack**.

  * - **INTRO_OPT_PROT_DPI_HEAP_SPRAY**
    - **yes**
    - **no**
    - protection
    - `Exploit client`_
    - Enable protection against process creation if the parent process heap contains patterns of a **heap spray attack**.

  * - **INTRO_OPT_PROT_DPI_TOKEN_STEAL**
    - **yes**
    - **yes**
    - protection
    - Token_
    - Enable protection against process creation with a **stolen token**.

  * - **INTRO_OPT_PROT_DPI_TOKEN_PRIVS**
    - **yes**
    - **no**
    - protection
    - Token_
    - Enable protection against process creation with manipulated **Present**/**Enabled bitmaps** inside the **token** structure of the parent process.

  * - **INTRO_OPT_PROT_DPI_THREAD_SHELL**
    - **yes**
    - **no**
    - protection
    - `Exploit client`_
    - Enable protection against process creation from a stray thread, which contains **shellcode-like code** (either dynamically injected, or as part of an exploit).

  * - **INTRO_OPT_PROT_DPI_SD_ACL**
    - **yes**
    - **no**
    - protection
    - Token_
    - Enable protection against process creation if the parent process has an altered **security descriptor pointer** or **Access Control List (ACL)** (SACL/DACL).

Process introspection and protection
------------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_PROT_UM_MISC_PROCS**
    - **yes**
    - **yes**
    - protection
    - See per process options.
    - | Enable **misc user-mode process** protection. 
      | Separate policy has to be applied for each protected process (by default, no user-mode process is protected, except when using **INTRO_OPT_PROT_UM_SYS_PROCS** - check the below option).

  * - **INTRO_OPT_PROT_UM_SYS_PROCS**
    - **yes**
    - **no**
    - protection
    - | Injection_
      | `Creds dump`_
    - | Enable **system process** protection against injections. Only for Windows guests.
      | In addition, enables mimikatz-like behavior (any read from within lsass.exe) prevention. 
      | The system processes are:
      | - smss.exe
      | - csrss.exe
      | - wininit.exe
      | - winlogon.exe
      | - lsass.exe
      | - services.exe
      | Attempts to **inject code or data** into these processes will be blocked.
      | Attempts to **read code or data** from lsass.exe will be blocked.

  * - **INTRO_OPT_NOTIFY_ENGINES**
    - **yes**
    - **yes**
    - protection
    - | Scripting_
      | PowerShell_
      | `Exploit client`_
    - | Enables engine scan. Certain buffers may then be sent to scanning engines, to be scanned for malware. 
      | Currently, the following types of buffers are supported:
      | - **Executed memory pages** - on execution attempts, the code buffer will be sent to the AM engines (if HVI doesn't detect something first). 
      | - **Process command lines** - if **PROC_OPT_PROT_SCAN_CMD_LINE** is set for a process, its command line will be read and sent to the AM engines.
      | **The engines will do the scan asynchronously. The scan result will be available later - during this time, the VM will continue to run; this means that HVI cannot block detections issued by the engines**.

Global protection control
-------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_KM_BETA_DETECTIONS**
    - **yes**
    - **yes**
    - option
    - N/A
    - Enable report-only mode for Kernel Mode. This means that KM alerts will be triggered normally, but no action will be blocked.

  * - **INTRO_OPT_SYSPROC_BETA_DETECTIONS**
    - **yes**
    - **no**
    - option
    - N/A
    - Enable beta detections (or report-only mode) for system processes. This means that system processes alerts will be triggered normally, but no action will be blocked.

Misc events generation
----------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_EVENT_PROCESSES**
    - **yes**
    - **yes**
    - event
    - N/A
    - Enable process creation and termination events on Windows and Linux.

  * - **INTRO_OPT_EVENT_MODULES**
    - **yes**
    - **yes**
    - event
    - N/A
    - | Enable drivers load and unload events on Windows and Linux. 
      | On Windows, it also enables dll load/unload events for protected processes.

  * - **INTRO_OPT_EVENT_OS_CRASH**
    - **yes**
    - **yes**
    - event
    - N/A
    - Enable Windows BSOD events and Linux kernel panic events.

  * - **INTRO_OPT_EVENT_PROCESS_CRASH**
    - **yes**
    - **yes**
    - event
    - N/A
    - Enable application crash events on Windows & Linux .

  * - **INTRO_OPT_EVENT_CONNECTIONS**
    - **yes**
    - **yes**
    - event
    - N/A
    - | Enable connection events on Windows & Linux.
      | Will only send TCP connections that are not in TIME_WAIT state.
      | **Currently, connection events are sent on exploit detections only, but the mechanism can be extended to send them any time**.

Misc options
------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_AGENT_INJECTION**
    - **yes**
    - **yes**
    - option
    - N/A
    - Enable agent injections. Agents must be manually injected when needed.

  * - **INTRO_OPT_FULL_PATH**
    - **yes**
    - **no**
    - option
    - N/A
    - Enable full-path protection for designated processes.

  * - | **INTRO_OPT_BUGCHECK_CLEANUP**
      | **INTRO_OPT_PANIC_CLEANUP**
    - **yes**
    - **yes**
    - option
    - N/A
    - | Enable memory dump cleanup, ensuring that all (or most of) the code that the introspection engine injects inside the host will not be saved in the memory dump.
      | It is recommended to be used on market builds. Most internal tests should be done with this option disabled.

Optimizations using in-guest agents
-----------------------------------

.. list-table::
  :header-rows: 1
  :widths: 6 1 1 1 2 8

  * - Option Name
    - Win
    - Lix
    - Type
    - Mitre
    - Description

  * - **INTRO_OPT_IN_GUEST_PT_FILTER**
    - **yes**
    - **no**
    - option
    - N/A
    - | Enable the in-guest page table filtering (without EPT hooks). 
      | Its use is recommended in order to avoid performance issues on Windows 10 RS4 x64.
      | Note that it can result in a loss of protection against certain type of attacks. Generally speaking, this flag should always be set and toggling it on and off a lot is not recommended.  
      | **This option is ignored on Linux and any Windows different from 10 RS4 x64**.

  * - **INTRO_OPT_VE**
    - **yes**
    - **no**
    - option
    - N/A
    - | Enable #VE-based in-guest agent. 
      | The agent filters page-table accesses and ensures increased performance, if **#VE** and **VMFUNC** features are present.
      | **If both INTRO_OPT_VE  and INTRO_OPT_IN_GUEST_PT_FILTER are set, Introcore will prefer using INTRO_OPT_VE, if #VE and VMFUNC features are present. Otherwise, it will use INTRO_OPT_IN_GUEST_PT_FILTER.**
      | **Xen >= 4.11 is required for this option to function. If #VE or VMFUNC features are not present, this option is ignored**.
      | **#VE filtering works only on 64 bit Windows, where the number of page-table accesses is very high. It is not yet needed on 32 bit Windows or Linux**.

.. _Rootkit: https://attack.mitre.org/techniques/T1014/
.. _Hooking: https://attack.mitre.org/techniques/T1179/
.. _Exploit remote: https://attack.mitre.org/techniques/T1210/
.. _Exploit privesc: https://attack.mitre.org/techniques/T1068/
.. _Token: https://attack.mitre.org/techniques/T1134/
.. _Dev util: https://attack.mitre.org/techniques/T1127/
.. _Exploit client: https://attack.mitre.org/techniques/T1203/
.. _Injection: https://attack.mitre.org/techniques/T1055/
.. _Creds dump: https://attack.mitre.org/techniques/T1003/
.. _Scripting: https://attack.mitre.org/techniques/T1064/
.. _PowerShell: https://attack.mitre.org/techniques/T1086/
