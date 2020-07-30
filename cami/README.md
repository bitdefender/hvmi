# CAMI

CAMI is an Introcore submodule serving mainly as an OS specific info database. However, it may include other features that can control Introspection behavior such as hooked kernel APIs or enforced options (forcing features to be on/off). Introcore will not be able to protect any guest VM without the OS support binary file.

## General architecture

On a base level, the OS specific information is stored in YAML files for easier maintenance. However, in order to serve them to Introcore in a safer and easier manner, these files are serialized into a binary file which must be supplied to Introcore by the integrator during initialization.

## Building

CAMI binary files are generated using python 3. You will also need the [pyyaml](https://pypi.org/project/PyYAML/) library:

```bash
python3 -m pip install pyyaml
```

Generating a new binary file is done with the `scripts/main.py` script.

```bash
python3 scripts/main.py --major 1 --minor 4 --buildnumber 0 --sources=sources
```

On success, a file named `intro_live_update.bin` will appear in the curent directory.

While you can specify any value for the major and minor versions, the current Introcore implementation will not load any files with a version lower than 1.4.0.
