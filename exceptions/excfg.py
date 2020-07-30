#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import json


CONFIG = None


def _resolv_config_hexa():
    """ Parsed the config for the Flags section where the values are given in
    hexa instead of decimal and resolves them. """
    global CONFIG

    for mode in CONFIG["Flags"]:
        for field in CONFIG["Flags"][mode]:
            CONFIG["Flags"][mode][field] = int(CONFIG["Flags"][mode][field], 0)


def parse(cfg_file):
    """ Simply load the config files. """
    global CONFIG

    CONFIG = json.loads(cfg_file.read_text())

    _resolv_config_hexa()


def get(obj, value=None):
    if CONFIG is None:
        raise ValueError("Config not loaded")

    if obj not in CONFIG:
        raise KeyError("{} not present in config".format(obj))

    if not value:
        return CONFIG[obj]

    return CONFIG[obj][value]
