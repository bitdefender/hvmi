===============================
Activation & Protection Options
===============================

Global Introcore options
========================

The global options control most of the Introcore behavior - the kernel and the global protection policies. The options are given to the :code:`IntNewGuestNotification` API via the :code:`Options` argument. Global options can be dynamically modified, while the guest is running using the :code:`IntModifyDynamicOptions` API. 
The protection options are:

.. include:: global-options.rst

Process Options
===============

Per-process protection flags are set for each protected process, and they will be applied for every process which matches the indicated image name.

Adding protection for a process can be done using the :code:`IntAddRemoveProtectedProcessUtf8` and :code:`IntAddRemoveProtectedProcessUtf16` APIs. The :code:`FullPath` argument indicates the process path to be protected (the path may be missing, and only an image-name can be used).
The :code:`ProtectionMask` argument contains a combination of the following flags:

.. include:: process-options.rst

The indicated APIs can be used to add protection for processes that have already been started. In addition, the protection flags for active, protected processes can also be modified using the indicated flags. If any of these APIs is called two times for the same process, but with different options, the last call will be considered.
