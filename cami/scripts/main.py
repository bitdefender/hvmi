#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import sys
import linux
import common
import windows
import options
import os
import functools
import yaml

from objects import SectionsTable, FileHeader, get_all_objects


def build_argparser():
    parser = argparse.ArgumentParser(description="Cloud assisted memory introspection")

    parser.add_argument("-o", "--output", help="Output file", action="store", default="intro_live_update.bin")
    parser.add_argument("-b", "--buildnumber", help="Build number", action="store", type=int, default=0)
    parser.add_argument("-M", "--major", help="Major version", action="store", type=int, default=0)
    parser.add_argument("-m", "--minor", help="Minor version", action="store", type=int, default=0)
    parser.add_argument("-v", "--verbose", help="Verbose", action="store_true")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-w",
        "--win_support",
        help="Load support from given file",
        action="store",
        default=None
    )
    group.add_argument(
        "-s",
        "--sources",
        help="Path to directory which contains the YAML source files",
        action="store",
        default="sources"
    )
    return parser


def load_sources(location):
    for root, subfolders, files in os.walk(location):
        for file in files:
            if not file.endswith(".yaml"):
                print("File {} does not have .yaml extention. Will ignore!".format(file))
            else:
                # We have to trick the garbage collector here.
                for x in yaml.load_all(open(os.path.join(root, file), "r"), Loader=yaml.Loader):
                    pass
                print("Loaded ", file)

    options.craft_options()


def load_win_support(file):
    if not file.endswith(".yaml"):
        print("File {} does not have .yaml extention. Will ignore!".format(file))
    else:
        for x in yaml.load_all(open(file, "r"), Loader=yaml.Loader):
            pass
        print("Loaded ", file)
    options.craft_options()


if __name__ == "__main__":

    argparser = build_argparser()
    args = argparser.parse_args(sys.argv[1:])

    if None != args.win_support:
        load_win_support(args.win_support)
    else:
        load_sources(args.sources)

    syscalls = common.SyscallsList()
    syscalls.set_entries(get_all_objects(common.SyscallPattern))

    print("Loaded {} syscall patterns.".format(syscalls.get_entry_count()))

    lix_oses_list = linux.LixSupportedOSList()
    lix_oses_list.set_entries(get_all_objects(linux.LixSupportedOS))

    print("Loaded {} linux supported versions.".format(lix_oses_list.get_entry_count()))

    lix_dist_sigs = linux.LixDistSignaturesList()
    lix_dist_sigs.set_entries(get_all_objects(linux.LixDistSigs))

    print("Loaded {} linux dist signatures.".format(lix_dist_sigs.get_entry_count()))

    win_oses_list = windows.WinSupportedOsTable()
    win_oses_list.set_entries(get_all_objects(windows.WinSupportedOs))

    print("Loaded {} windows supported versions.".format(win_oses_list.get_entry_count()))

    sections_table = SectionsTable()
    sections_table.add_section(syscalls)
    sections_table.add_section(lix_oses_list)
    sections_table.add_section(win_oses_list)
    sections_table.add_section(lix_dist_sigs)

    file_header = FileHeader(args.buildnumber, (args.major, args.minor))
    file_header.set_sections(sections_table)

    stream = file_header.serialize(0)

    out_subdirs = list(os.path.split(args.output))[0:-1]
    out_dir = functools.reduce(lambda a, b: os.path.join(a, b), out_subdirs)

    if "" != out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(args.output, "wb") as f:
        f.write(stream)
