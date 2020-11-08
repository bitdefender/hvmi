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
Comment: User-ID:	hvmi-security <hvmi-security@bitdefender.com>
Comment: Created:	7/15/2020 2:01 PM
Comment: Expires:	7/15/2022 12:00 PM
Comment: Type:	2048-bit RSA (secret key available)
Comment: Usage:	Signing, Encryption, Certifying User-IDs
Comment: Fingerprint:	8FA363D0AD6F31067044FF4D6AA85FC4467740F2


mQENBF8O4fkBCADfjTRjJFXASxSm7D8ZOnHmmYh8Achg92P3UcWoYlnLo7rryTZV
7vv1LMwHpDXzbv3Za0vo0vbDtjmDC9PBHBo5CCIPOG0Bp4rhk889VZZoeyWs2sq+
SFfGSDkIeXc5JRXyAHfhyz8rJFVYU72R+0v62DPZLenoBgbFnY6yq5Xc8EMuwKPx
mgpg9J/jdLWy1mBN79ZQrCwp/ZKxBv7TR0quazY9K1WARUplWwVptnYJ0W/THnXe
qF0dggWayr6ASZhmyGZEiQFbkJpMzgCWr49CgjVfw1MXidH8bif9Y2Zsv3ATRNm+
TQMRlAsi+XlqO5Zcx+hnAOna6IRI6vFOli4LABEBAAG0LWh2bWktc2VjdXJpdHkg
PGh2bWktc2VjdXJpdHlAYml0ZGVmZW5kZXIuY29tPokBVAQTAQgAPhYhBI+jY9Ct
bzEGcET/TWqoX8RGd0DyBQJfDuH5AhsDBQkDwkqXBQsJCAcCBhUKCQgLAgQWAgMB
Ah4BAheAAAoJEGqoX8RGd0Dy4kMH/1wnPVqFBXOZcR2CRiWHExbIWwnzfDrYm/tE
ZzSof5QwSFN8DH8hLvNUcbflpkfgB0X8s6RjhCqbpfR/UyWmDNdsRPQ6AUh3aWUk
K5BFdIEQB+Aiv3CWOpIGSDMriKaAyxheuqaNvxTyat75XWvmK7OkkiVZZjx9Pooq
XFYOqSxDZxRwawQYlxXC9GNhXhtD4L8/n5RvB5Lc7coWas0jJKfrh+HTcR1+dybb
14HRBh/BU6P/NIn0quN5Gkukqiym/pR7MbfjfrBNibt1rcu9/sP/BzG0sNUHIxLV
aXczDEcqG7gtzIEHTma40+OIjchlsWKREDPHUryQ7pHcW8oRTJW5AQ0EXw7h+QEI
AL2/tnXRPYX2TEWac9G8bhaWhIoKxh62bQlStp+lG6jGsEGAjonhI+vTRb5I4e7z
bA89dHbt/CSyrngm8e+RbInZ7omVPT/QD+DcF+iV7O7DsUnANKamGSLkKbrSwQ+u
1ywVTVwF+kubNgluvG50tX3OdtSlQTbwZCPjvB6B5ORNq1lwFFuiF6XyG+sUHRBq
9YBUmfGsOS0WSP39Cb/ExGmLw4RnDWQJax7Z8oaKL6QKG3QoEUgP8BdRzgYLHgqH
F4mB5GaEqSK+IhZ3NPdWJbTmbBSRJM3xyCunWg4xCqTAyJw/PrTDGZNWPVFt/LQy
YhfI4GmH3RXO7gaq3ntvrK0AEQEAAYkBPAQYAQgAJhYhBI+jY9CtbzEGcET/TWqo
X8RGd0DyBQJfDuH5AhsMBQkDwkqXAAoJEGqoX8RGd0DyVVoH/0KmyKparR6UrtbD
Lv4eNOI58DypfY4jJ5mR5PWFH4ewPalu8Sw0Pa6ngI554OQ+0G0dYUXVViUCRnpN
TBs32NyOnRWH3vgLoYfhdG7qebO53IYgFwvCDRYWjrDVMgrlmFJIAcdHk1dsZ2mL
SFiM3wVmZeQhMExcDABlub8WItBvLo5QD/JJQ55ZlE/Z2DO7m7oOhsUAolp1W7Yq
72ITifuDrFrmgyq4B+jBqL55nnDDmXrGNrksj5tsgGUyq5tYKbRLYgqQ9lmNyNXE
nibaE27Tr1XnZLzcOMesjEpWBPL3l0Jwxru7pYqA3xWd/8wXZSf9HmJmyoUDXIDy
thGcFZM=
=vBFM
-----END PGP PUBLIC KEY BLOCK-----
```

## Rewarding the Security Researchers

While there are no bounties offered for issues discovered in this project, 
we do credit all the security researchers who contribute to making the 
project safer.