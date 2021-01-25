# Handling Security Issues Discovered in the HVMI Project

HVMI is a complex piece of software, and like any other software, we cannot 
exclude the existence of potential security issues. In this regard, we advise
researchers to follow responsible disclosure and notify us before publicly 
disclosing any security issue, to give us the opportunity to fix it in any 
product that integrates the HVMI technology.

## How to Report a Security Issue

Identified security issues must be properly described, and steps of reproduction
must be provided. Proof of concepts are strongly encouraged, but not strictly
required, as long as the reproduction steps are clear, and we are able to 
reproduce the issue. Please make sure to include the following:

* Brief description of the problem
* The host hardware used (CPU type, installed memory, any other relevant info)
* The used Hypervisor (Xen, KVM, etc.)
* The affected operating system (type, version, architecture, version string, any other relevant info)
* The VM configuration, if the issue requires a VM to be reproduced (CPU topology, number of cores, RAM amount)
* Steps of reproduction
* Core dumps, memory dumps and any other useful information that can be used to triage and fix the issue
* Impact

For example, the following template could be used:
```
Brief description
Crash in libintrocore when loading malicious.dll inside opera.exe

Host hardware
CPU: Intel(R) Xeon(R) Gold 6254 CPU @ 3.10GHz, 72 cores
RAM: 766 GB

Hypervisor
Xen 4.12

Affected operating system
Windows 10 RS4 and Windows 10 RS5, 64 bit only

VM configuration
N/A (the bug reproduces no matter what configuration the VM has)

Steps of reproduction
1. Create a library named malicious.dll
2. Inject the library inside opera.exe
3. The libintrocore library crashes with a SEGFAULT

Impact
The issue easily leads to DoS, but it may be abused to create a RCE inside libintrocore.

Attached is the libintrocore core dump and a malicious.dll sample.
```


## Where to Report a Security Issue

Our security email address is `hvmi-security@bitdefender.com`. Please use the
following PGP key to encrypt your e-mail, and make sure to include your public 
key, in case we need to contact you for more info:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=aWng
-----END PGP PUBLIC KEY BLOCK----- 
```

## Rewarding the Security Researchers

While there are no bounties offered for issues discovered in this project, 
we do credit all the security researchers who contribute to making the 
project safer.