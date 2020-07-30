======================
Engines Scan Mechanism
======================

In some cases, the introspection module may leverage antimalware engines to provide an even better detection. Currently, the following scan requests are supported:

#. Process command line scanning - the command line of designated processes 
   (please see :ref:`PROC_OPT_PROT_SCAN_CMD_LINE <chapters/2-activation-and-protection-options:misc protection>` and 
   :ref:`INTRO_OPT_NOTIFY_ENGINES <chapters/2-activation-and-protection-options:process introspection and protection>`) 
   will be read and sent to the engines in order to be scanned.
#. Suspicious code execution scanning - when suspicious code is executed inside the memory of protected processes, 
   the introspection module schedules a scan (if the internal logic did not block the execution).

Activation Flags
================

#. :ref:`PROC_OPT_PROT_SCAN_CMD_LINE <chapters/2-activation-and-protection-options:misc protection>` – 
   This is a per-process flag, usually set on processes such as **powershell.exe** or **cmd.exe**. 
   If set, the introspection module will read the entire command line of the process in question 
   (using #PF injections) and schedule a scan.
#. :ref:`INTRO_OPT_NOTIFY_ENGINES <chapters/2-activation-and-protection-options:process introspection and protection>` – 
   This is the global flag that controls if suspicious code executions are sent to the scan engines.
   The introspection module already has internal logic used to detect malicious code executions (for 
   example, the RIP points inside a known stack), so the engines are used only if all the internal checks deem
   the code execution to be legitimate.

Sending a scan request
======================

Callback function
-----------------

The integrator must implement the :code:`NotifyScanEngines` function callback
(from `glueiface.h <../_static/doxygen/html/glueiface_8h.html>`__) to provide support for the scan engines.

.. note::

    This functionality is **optional** thus an integrator may decide not to use it.

Notification format
-------------------

Different structures (according to the scan type) are used, but all of them have an ENG_NOTIFICATION_HEADER_ as the first field.

.. note::

    The same structure will be returned via the result callback, therefore some of the fields must be populated by the integrator.

+-------------------+----------------------------------------------------------------------------+
| Parameter         | Description                                                                |
+===================+============================================================================+
| RequestedAction   | The action requested by the engines.                                       |
+-------------------+----------------------------------------------------------------------------+
| Type              | The notification type (code execution or command line scan).               |
+-------------------+----------------------------------------------------------------------------+
| OsType            | The operating system type (Windows/Linux).                                 |
+-------------------+----------------------------------------------------------------------------+
| DetectionName     | A NULL-terminated string with the name of the engines detection, if any.   |
+-------------------+----------------------------------------------------------------------------+
| EnginesVersion    | A NULL-terminated string with the version of the engines.                  |
+-------------------+----------------------------------------------------------------------------+

#. `Command line scan`_

   +---------------+------------------------------------------------------+
   | Parameter     | Description                                          |
   +===============+======================================================+
   | Header        | The previously defined header.                       |
   +---------------+------------------------------------------------------+
   | Parent        | The parent process that provided the command line.   |
   +---------------+------------------------------------------------------+
   | Child         | The child process that received the command line.    |
   +---------------+------------------------------------------------------+
   | CmdLine       | The command line to be scanned.                      |
   +---------------+------------------------------------------------------+
   | CmdLineSize   | The size of the command line buffer.                 |
   +---------------+------------------------------------------------------+

#. `Suspicious code execution scanning`_

   +-----------------+----------------------------------+
   | Parameter       | Description                      |
   +=================+==================================+
   | Header          | The previously defined header.   |
   +-----------------+----------------------------------+
   | ExecutionData   | Execution information.           |
   +-----------------+----------------------------------+

After allocating and filling the appropriate event structure, 
:code:`NotifyScanEngines` will be invoked so that a scan will be
scheduled. If the call to :code:`NotifyScanEngines` is successful, the
result callback must be invoked by the integrator (the :code:`ENG_NTOFICATION_*` 
structure is heap allocated and must be freed – otherwise a memory leak will occur).

Retrieving the scan result
==========================

Since the engines may introduce a significant performance penalty, the
scan is done in an asynchronous fashion, thus a completion callback is
required. The integrator must implement the following functions from the
`glue interface <../_static/doxygen/html/glueiface_8h.html>`__.

#. :code:`RegisterEnginesResultCallback`

   Introcore uses this to register a callback that will be invoked by the integrator when a scan is complete (usually, this step is done when initializing introcore).

#. :code:`UnregisterEnginesResultCalback`

   The introspection module uses this to remove the previously registered engines callback (usually, this step is done
   when uninitializing introcore).

The integrator must invoke the registered callback to provide the scan result.

.. _ENG_NOTIFICATION_HEADER: ../_static/doxygen/html/struct___e_n_g___n_o_t_i_f_i_c_a_t_i_o_n___h_e_a_d_e_r.html
.. _Command line scan: ../_static/doxygen/html/struct___e_n_g___n_o_t_i_f_i_c_a_t_i_o_n___c_m_d___l_i_n_e.html
.. _Suspicious code execution scanning: ../_static/doxygen/html/struct___e_n_g___n_o_t_i_f_i_c_a_t_i_o_n___c_o_d_e___e_x_e_c.html
