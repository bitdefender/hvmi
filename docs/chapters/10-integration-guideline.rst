=====================
Integration Guideline
=====================

Introcore can be used with any hypervisor that meets the :ref:`minimum requirements <chapters/1-overview:prerequisites from the hv>`.

There are two interfaces that must be implemented by an integrator:

- upper_, which exposes low level services to Introcore (for example, memory management or logging);
- glue_, which exposes guest management and virtualization APIs (for example, for querying the guest
  register state or for modifying EPT access rights);

These interfaces are defined in the Introcore public headers.

For an example, see the **daemon** directory in the `HVMI repository`_.

Public headers
==============

All the `public headers`_ can be found in the *include/public* directory in
the root of the repository, as well as in the *include* directory inside
an :ref:`Introcore SDK <chapters/1-overview:Linux Build>`.

The public headers are:

- `intro_types.h`_ - contains all the public definitions that are
  needed by an integrator, from the data types used by Introcore APIs
  to alert and event structures;
- `upperiface.h`_ - contains the definitions needed for the upper_ interface implementation;
- `glueiface.h`_ - contains the definitions needed for the glue_ interface implementation;
- `introstatus.h`_ - contains the definitions for the :code:`INTSTATUS` data type and possible
  return values for Introcore APIs.

These headers have dependencies on only standard C
headers: *stdef.h*, *stdint.h*, and *stdbool.h*.

There are two more headers included for convenience:

- `env.h`_ - used to detect the build environment; based on this,
  certain definitions might change to better fit a certain compiler,
  but no functionality should change;
- `intro_sal.h`_ - Introcore uses :ref:`SAL annotations <chapters/8-coding-style:microsoft sal>`,
  but the definitions are not always available (for example, for GCC).
  To ease the integration process, this header exposes dummy
  definitions for the SAL definitions used in the public headers.

The `intro_types.h`_ header defines some basic data types used by
Introcore, such as :code:`BOOLEAN`, :code:`BYTE`, :code:`DWORD`, etc, as well as
:code:`TRUE` and :code:`FALSE` values. If an integrator already has these
defined it can disable the Introcore definitions by defining :code:`INTROCORE_NOCOMPAT`
before including `intro_types.h`_.

Introcore also supports multiple integration environments, as discussed in
:ref:`Overall Architecture <chapters/1-overview:overall architecture>`.

The default :ref:`Linux build <chapters/1-overview:linux build>` settings assume that Introcore
will be used inside a SVA, while the default :ref:`Windows build <chapters/1-overview:windows build>`
settings assume that Introcore will run inside VMX root.
This can be controlled by defining (or not defining) :code:`USER_MODE` at build time.

Binaries
========

Introcore can be built both as a Linux library, as well as a 
Windows library with no external dependencies.
The only :ref:`dependencies <chapters/1-overview:project dependencies>` it has are statically linked in the binary.

After a successful build, the Introcore binary will be found in the *bin/x64/Debug*
or *bin/x64/Release* directory.

An integrator must be able to load this library, as well as a 
:ref:`guest support <chapters/5-os-support-mechanism:OS Support Mechanism>` file,
and optionally an :ref:`exceptions file <chapters/4-exceptions-mechanism:the binary exceptions file>`.

Upper Interface
===============

The upper interface exposes various low-level services to the
introspection engine. This must be fully implemented by an integrator.
It can be implemented without any support from the hypervisor. Technical
details about each API can be found in the `upperiface.h`_ documentation.
From a high level point of view, the following functionalities must be provided:

- Logging;
- Synchronization - this includes APIs for initializing, freeing,
  acquiring, and releasing locks;
- Memory management - this includes APIs for allocating and freeing
  memory, as well as querying the amount of free memory available to
  Introcore;
- Debugging.

.. note::

    The interface may change in time. Breaking changes are signaled by changing
    the :code:`UPPER_IFACE_VERSION_1` and :code:`UPPER_IFACE_VERSION_1_SIZE` 
    definitions in *upperiface.h*. Each instance of the interface must have the
    :code:`Version` and :code:`Size` fields set to these values. These will be
    checked at run time to ensure that the version of the library and the headers
    used by an integrator match and Introcore will refuse to load if incompatibilities
    are detected. 

Glue Interface
==============

The glue interface allows Introcore to communicate with the integrator
and the underlying hypervisor, as well as exposing APIs with which the
introspection engine can be controlled. It is split into two parts:

- The first part is implemented by the integrator and is used by
  Introcore to control certain aspects related to the guest management
  and virtualization features;
- The second part is implemented by Introcore and allows an integrator
  to control the introspection engine.

Technical details about each API can be found in the `glueiface.h`_ documentation.

From a high level point of view, the integrator must provide functionalities for:

- Querying the guest state, such as the register state, the CPU count, etc;
- Modifying the guest state;
- Querying support for certain virtualization features, such as #VE, SPP, etc;
- Notifying the integrator about alerts and events or error encountered by Introcore;
- Accessing guest memory;
- Querying and modifying EPT access rights;
- Activating or deactivating various VMEXITs (for example, for MSR accesses, INT3 executions, etc);
- Pausing and resuming VCPUs;
- Injecting exceptions inside the guest.

Most of these follow the requirements in the :ref:`Prerequisites from the HV <chapters/1-overview:prerequisites from the hv>` section.

From a high level point of view, Introcore exposes functionalities for:

- Starting and stopping the introspection process;
- Updating exceptions or CAMI files;
- Modifying the :ref:`protection policies and settings <chapters/2-activation-and-protection-options:Activation & Protection Options>`;
- Injecting agents;
- Querying information about the guest (such as the guest OS version).

.. note::

    The interface may change in time. Breaking changes are signaled by changing the
    :code:`GLUE_IFACE_VERSION_1` and :code:`GLUE_IFACE_VERSION_1_SIZE` definitions in
    *glueiface.h*. Each instance of the interface must have the :code:`Version` and
    :code:`Size` fields set to these values. These will be checked at run time to ensure
    that the version of the library and the headers used by an integrator
    match, and Introcore will refuse to load if incompatibilities are
    detected. 

Stand-alone functions
=====================

Apart from these interfaces, Introcore exposes a few other functions for
managing the library itself:

- :code:`IntInit` - used to initialize the library;
- :code:`IntPreInit` - used to ensure that the global library state is in a
  good state; should be called before calling :code:`IntInit`;
- :code:`IntUninit` - completely stops the introspection engine;
- :code:`IntCheckCompatibility` - can be used to check compatibility with
  the Introcore library.

.. _upper: ../_static/doxygen/html/struct___u_p_p_e_r___i_f_a_c_e.html
.. _glue: ../_static/doxygen/html/struct___g_l_u_e___i_f_a_c_e.html
.. _public headers: ../_static/doxygen/html/group__group__public__headers.html
.. _intro_types.h: ../_static/doxygen/html/intro__types_8h.html
.. _upperiface.h: ../_static/doxygen/html/upperiface_8h.html
.. _glueiface.h: ../_static/doxygen/html/glueiface_8h.html
.. _introstatus.h: ../_static/doxygen/html/introstatus_8h.html
.. _env.h: ../_static/doxygen/html/env_8h.html
.. _intro_sal.h: ../_static/doxygen/html/intro__sal_8h.html
.. _HVMI repository: https://github.com/hvmi/hvmi
