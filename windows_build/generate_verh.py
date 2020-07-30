#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import json
import pathlib
import sys

from build_info import check_build_info, read_build_info


def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ver-path", metavar="ver.h path", help="Path to ver.h file", required=True
    )

    parser.add_argument(
        "--in-file",
        metavar="info json",
        help="Path to the build info json file",
        required=True,
    )

    parser.add_argument(
        "--overwrite",
        help="Overwrite curent ver.h file. Default is False",
        action="store_true",
        default=False,
    )

    return parser


def main(argv):
    args = get_argparser().parse_args(argv)

    ver_file = pathlib.Path(args.ver_path)
    if ver_file.exists():
        if not args.overwrite:
            print(f"Version file at {ver_file} already exists! Will not overwrite it")
            return 0

        print(f"Version file at {ver_file} already exists! Will overwrite it")

    build_info = read_build_info(args.in_file)
    if not check_build_info(
        build_info,
        ["major", "minor", "revision", "build", "branch", "changeset", "build_machine"],
    ):
        print(f"ERROR: Incomplete build information")
        return 1

    major = build_info["major"]
    minor = build_info["minor"]
    revision = build_info["revision"]
    build = build_info["build"]
    branch = build_info["branch"]
    changeset = build_info["changeset"]
    build_machine = build_info["build_machine"]

    verh_contents = (
        f"#ifndef __VER_H__\n"
        f"#define __VER_H__\n"
        f"\n"
        f'#define INTRO_VERSION_BRANCH          "{branch}"\n'
        f'#define INTRO_VERSION_BUILDMACHINE    "{build_machine}"\n'
        f"#define INTRO_VERSION_BUILDNUMBER     {build}\n"
        f'#define INTRO_VERSION_CHANGESET       "{changeset}"\n'
        f"#define INTRO_VERSION_MAJOR           {major}\n"
        f"#define INTRO_VERSION_MINOR           {minor}\n"
        f"#define INTRO_VERSION_REVISION        {revision}\n"
        f"\n"
        f"#endif // !__VER_H__\n"
    )

    ver_parent = pathlib.Path(args.ver_path).parent
    ver_parent.mkdir(exist_ok=True)
    print(f"Will save info to {args.ver_path}")

    with open(args.ver_path, mode="w") as verfile:
        verfile.write(verh_contents)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
