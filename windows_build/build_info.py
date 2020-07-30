#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import json


def check_build_info(data, needed_keys):
    success = True
    for needed_key in needed_keys:
        if needed_key not in data.keys():
            print(f"ERROR: Missing build information for {needed_key}")
            success = False

    return success


def read_build_info(path):
    print(f"Reading build information from {path}...")
    with open(path, mode="r") as info_file:
        data = json.load(info_file)
        return data


def write_build_info(path, build_info):
    print(f"Writting build information to {path}")
    with open(path, mode="w") as info_file:
        json.dump(build_info, info_file, sort_keys=True)

    print(f"Build information saved to {path}")
