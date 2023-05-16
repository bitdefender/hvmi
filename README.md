# Hypervisor Memory Introspection

![logo](docs/chapters/images/hvmi-logo-main-color.png)

HVI stands for Hypervisor Introspection. The term is used interchangeably with HVMI, which is a bit more specific, and stands for Hypervisor Memory Introspection.

Virtual Machine Introspection is defined as the technique of analyzing the state and behavior of a guest virtual machine from outside of it. In addition, Introspection can also leverage virtualization extensions to provide security.

The main purpose of this project is to provide unmatched security from outside the virtual machine, by leveraging the hardware isolation provided by Intel VT-x. The main categories of attacks HVI prevents are:

- Binary exploits inside protected processes
- Code and data injection techniques inside protected processes
- Function hooks inside protected processes, on designated system DLLs
- Rootkits (various techniques are blocked, such as inline hooks inside the kernel or other drivers, SSDT hooks, Driver-object hooks, system register modifications, etc.)
- Kernel exploits
- Privilege escalation
- Credentials theft
- Deep process introspection (prevents process creation if the parent process has been compromised)
- Fileless malware (powershell command line scanning)

For more details check out the [HVMI specification](http://hvmi.readthedocs.io) and the [HVMI blog](https://bitdefender.github.io/hvmi-blog/).

## Supported hypervisors

HVMI can work on any hypervisor, as long the proper API is provided (which is documented [here](https://hvmi.readthedocs.io/en/latest/chapters/1-overview.html#prerequisites-from-the-hv)). Currently, it has been integrated and tested with the following hypervisors:
* [Napoca Hypervisor](https://github.com/bitdefender/napoca) - Bitdefender's bare-metal hypervisor for Intel CPUs
* [Xen](https://xenbits.xen.org) - the famous open source hypervisor
* [KVM](https://www.linux-kvm.org/page/Main_Page) - the Linux Kernel Virtual Machine

## Repository structure

- **introcore** - the introcore source code and header files
- **include** - the public header files and headers shared between multiple projects
- **cami** - the [Guest support mechanism](#Guest-support-mechanism) files
- **exceptions** - the [Exception](#Exceptions) files
- **agents** - the Windows special agents project files
- **docs** - the documentation
- **build_disasm** - the files used to build the [bddisasm](https://github.com/bitdefender/bddisasm) dependency
- **deserialize** - the deserializer scripts, used to extract useful information from serialized alerts
- **Doxygen** - the Doxygen settings
- **windows_build** - the scripts used during the [Windows build](#Windows-build)
- **daemon** - an integration example for Xen and KVM

## Quick start guide

- [HVMI demo setup on Xen](https://bitdefender.github.io/hvmi-blog/2020/08/10/getting-started-on-Xen.html).
- [HVMI demo setup on KVM](https://bitdefender.github.io/hvmi-blog/2020/08/10/getting-started-on-kvm.html).
- [Adding custom exceptions](https://bitdefender.github.io/hvmi-blog/2020/08/19/exceptions.html).

## Checkout

Get Introcore and all the dependencies by running:

```bash
git clone --recurse-submodules https://github.com/bitdefender/hvmi.git
```

This will clone the HVMI repository and the [bddisasm](https://github.com/bitdefender/bddisasm) submodule.

## Build

Introcore can be built both as a Windows DLL, and as a Linux library. Only the 64-bit configuration is supported.

### Linux build

To build the project on Linux you need:

- gcc >= 7.0
- cmake >= 3.13
- make

To integrate the library (`libintrocore.so`) you can use the `pkg-config` file (`introcore.pc`) that is generated by `cmake`.

Building Introcore is done by running cmake from the root of the repository:

```bash
# generate configuration
cmake -H. -G<generator> -B<build directory> -DCMAKE_BUILD_TYPE=<build type> -DCMAKE_INSTALL_PREFIX=<install prefix directory> -DCMAKE_LIBRARY_OUTPUT_DIRECTORY=<binary output directory> -DCMAKE_TOOLCHAIN_FILE=<toolchain>
```

The default value of `CMAKE_INSTALL_PREFIX` is `/usr/local/`.
The default value of `CMAKE_LIBRARY_OUTPUT_DIRECTORY` is `$project_dir/bin`.

#### Build for Debug

```bash
cmake -B_build -DCMAKE_BUILD_TYPE=Debug
cd _build
make
```

#### Build for Release

```bash
cmake -B_build -DCMAKE_BUILD_TYPE=Release
cd _build
make
```

#### Install

```bash
# install the introcore library (debug)
cd _build
make install
```

This builds the [bddisasm](https://github.com/bitdefender/bddisasm) dependency and then **libintrocore**, the [exception](#Exceptions) and the [guest support mechanism](#Guest-support-mechanism) files. Use `make introcore` to build just **libintrocore**. The resulting binaries will be in `bin/x64/Debug` or `bin/x64/Release`.

#### Generate an SDK

Generating an SDK that will contain **libintrocore** Debug and Release versions, and the public header files is done with:

```bash
mkdir _build
cd _build

cmake .. -B. -DCMAKE_BUILD_TYPE=Debug
make

cmake .. -B. -DCMAKE_BUILD_TYPE=Release
make

make package
```

This creates a ZIP file in the root of the repo that contains the latest **libintrocore** you’ve built, together with the header files from the `include/public` directory.

### Windows build

To build the project on Windows you need:

- [Visual Studio 2019](https://visualstudio.microsoft.com/vs/) with the **Desktop development with C++ workload**
- [Windows SDK 10.0.18362.0](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk/)
- [python 3.6 or newer](https://www.python.org/downloads/release/python-360/)

When you first open the `hvmi.sln` file, Visual Studio should prompt you to install any missing components. Building the introcore can be done directly from Visual Studio or with the `build.cmd` script:

```bash
# build for Debug
build.cmd Debug

# build for Release
build.cmd Release
```

This will create **introcore.dll** and **introcore.pdb** in `bin/x64/Debug` or `bin/x64/Release`.

CMake is not supported for Windows builds.

## Documentation

Introcore comes with Doxygen code documentation, and a specification built with [Sphinx](https://www.sphinx-doc.org/en/master/).

### Doxygen

For generating the Doxygen documentation on Linux, use:

```bash
cmake -B_build
cd _build
make doxy
```

For Windows, use:

```bash
make_doxy.cmd
```

Or invoke Doxygen directly:

```bash
doxygen Doxygen/Doxyfile
```

This assumes that you have [Doxygen](https://www.doxygen.nl/index.html) installed and in your path.

The Doxygen documentation will then be found in `docs/_static/Doxygen/html`.

## Specification

To build the specification you need:

- Python 3
- [Sphinx](https://www.sphinx-doc.org/en/master/)
- [sphinx-bootstrap-theme](https://github.com/ryan-roemer/sphinx-bootstrap-theme)

To generate the HTML version of the documentation:

```bash
cd docs
make html
```

This will also build the Doxygen documentation. The result will be in `docs/_build/html`.

## Exceptions

Introcore has an exception mechanism, which is used to whitelist legitimate accesses to protected structures.

Sample exception files that should work for out-of-box installations of Windows 7 (SP1 and SP2) and Windows 10 1809 (RS5) are included in the `exceptions` directory.

To generate the exceptions binary, use:

```bash
cmake -B_build
cd _build
make exceptions
```

For more information see [exceptions](exceptions/README.md).

## Guest support mechanism

Introcore needs to know certain information in order to properly hook and protect an operating system (for example, the layout of certain kernel structures, patterns for finding functions inside the guest memory, etc). These information are included in a CAMI data base file. Sample files that offer support for Windows 7 (SP1 and SP2), Windows 10 1809 (RS5), Ubuntu 18.04, and CentOS 8 can be found in the `cami` directory.

To generating the cami binary, use:

```bash
cmake -B_build
cd _build
make cami
```

For more information see [CAMI](cami/README.md).

## Contacting us

There are several ways to contact us:

- [The public HVMI Slack](https://kvm-vmi.slack.com) - [join here](https://kvm-vmi.herokuapp.com) the public Slack to discuss ideas publicly, or privately, with both Bitdefender developers and other members of the community
- Bitdefender HVMI OSS team contact - hvmi-oss@bitdefender.com - contact Bitdefender folks directly regarding any issue that is not well suited for public Slack discussions
- HVMI security - hvmi-security@bitdefender.com - report security issues and vulnerabilities; we kindly ask that you follow the guideline described [here](SECURITY.md)
