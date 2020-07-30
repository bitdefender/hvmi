#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import pathlib
import subprocess
import sys
import platform
from build_info import write_build_info


def get_argparser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--meta-file", help="Path to the project-meta-info.in file", required=True
    )
    parser.add_argument("--build", help="Built number", required=False, default=None)
    parser.add_argument("--out", help="Path to the output JSON file", required=True)

    parser.add_argument(
        "--overwrite",
        help="Overwrite curent ver.h file. Default is False",
        action="store_true",
        default=False,
    )

    return parser


def get_version(metainfo):
    with open(metainfo, mode="r") as metafile:
        for line in metafile:
            if "project_version" in line:
                raw_ver = line.strip().split()[-1]
                ver_components = raw_ver.split(".")

                if len(ver_components) != 3:
                    return None

                major = ver_components[0]
                minor = ver_components[1]
                revision = ver_components[2].replace(")", "")

                return (major, minor, revision)

    return None


def get_git_branch():
    return (
        subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"])
        .decode("utf-8")
        .strip()
    )


def get_git_revision():
    return (
        subprocess.check_output(["git", "rev-parse", "--short", "HEAD"])
        .decode("utf-8")
        .strip()
    )


def get_git_commit_count():
    return (
        subprocess.check_output(["git", "rev-list", "--count", "HEAD"])
        .decode("utf-8")
        .strip()
    )


def get_machine_name():
    return platform.node()


def main(argv):
    args = get_argparser().parse_args(argv)

    out_file = pathlib.Path(args.out)
    if out_file.exists():
        if not args.overwrite:
            print(f"Version file at {out_file} already exists! Will not overwrite it")
            return 0

        print(f"Version file at {out_file} already exists! Will overwrite it")

    ver = get_version(args.meta_file)
    if not ver:
        print(f"ERROR: Coult not extract version info from {args.meta_file}")
        return 1

    (major, minor, revision) = ver
    build = args.build
    if build is None:
        # "Sensible" default for local builds
        build = get_git_commit_count()

    branch = get_git_branch()
    changeset = get_git_revision()

    build_machine = get_machine_name()

    build_info = {}
    build_info["major"] = major
    build_info["minor"] = minor
    build_info["revision"] = revision
    build_info["build"] = build
    build_info["changeset"] = changeset
    build_info["branch"] = branch
    build_info["build_machine"] = build_machine

    write_build_info(out_file, build_info)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
