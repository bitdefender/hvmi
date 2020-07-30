# Exceptions

Introcore works by blocking malicious attempts of accessing guest memory. Sometimes, the operating system, drivers, or processes would display behavior which triggers such alerts - for example, browsers may wish to place hooks on certain API functions, or they may wish to execute JIT code from dynamically allocated memory regions - but which are, in fact, benign, and not indicative of an attack. In order to be able to distinguish such behavior from an attack, Introcore has an exception mechanism, which is used to whitelist legitimate accesses to protected structures.

An exception can be added for each legitimate access made to a protected structure. They are written in a JSON format, and the exception files are compiled into a binary file which is loaded and used by Introcore.

Exceptions can be added manually or automatically.

Without an exceptions fie loaded Introcore will allow every event.

Sample exception files that should work for out-of-box installations of Windows 7 (SP1 and SP2) and Windows 10 1809 (RS5) are included, as well as exceptions that should allow the Chrome browser to function properly while protected by Introcore.

## General architecture

Exception information is written in `json` files. However, in order to serve them to Introcore in a safer and easier manner, these files are serialized into a binary file which must be supplied to Introcore by the integrator during initialization. The currently loaded exception file can be updated at any time by the integrator.

## Building

Exception binary files are generated using python 3:

```bash
python3 exceptions.py jsons
```

The resulting binary will be named `exceptions.bin` and will be placed in the current directory.

Multiple directories can be used to store the `json` files. The `json` directory present here contains basic exceptions for Windows 7 (builds 7601 and 7602) and Windows 10 RS5 (build 17763). The major and minor exception version cab be specified by editing `config.json`:

```json
    "Version": {
        "Major": 2,
        "Minor": 2
    }
```

Note however that the current Introcore implementation will refuse to load an exception file with a major version number different than 2.2.
