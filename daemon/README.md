# Hypervisor Memory Introspection Daemon

HVMID is an exemple of how libintrocore can be integrated into a working solution.

## Build

HVMID is built as a Linux daemon and is compatible with both `SysV` and `systemd` init systems.

### Dependencies

To build this project you need:

- g++ >= 7.0
- cmake >= 3.13
- make

The daemon also requires the following libraries to be installed:

- libintrocore
- [libbdvmi](https://github.com/bitdefender/libbdvmi)
- [libjsoncpp](https://github.com/open-source-parsers/jsoncpp)

### Install

Installing is as simple as running the following commands:

```bash
cmake -B_build
cd _build
make install
```

This will install the daemon on `/usr/local` hierarchy. This prefix may be modified by setting the CMAKE_INSTALL_PREFIX variable:

```bash
cmake -B_build -DCMAKE_INSTALL_PREFIX=/opt/hvmid
```

## Configuration

The daemon needs two configuration files located under the `$CMAKE_INSTALL_PREFIX/etc/hvmid` directory:

- `settings.json` controls several behaviours, such as page cache limit, beta mode or ignored domains.
- `policies/default.json` is the default policy which is initially applied to any domain hooked. This policy may may be overwritten if a file named `<uuid>.json` is present.

## Security issues

The sole purpose of this sub-project is to provide an example of how to integrate libintrocore. Therefore, no security issues are supported for this example.
