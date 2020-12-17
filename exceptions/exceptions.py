#! python3
#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#

import sys
import json
import re

import argparse

from pathlib import Path

import excfg
from intro_objects import (
    KernelException,
    UserException,
    KernelUserException,
    UserGlobException,
    UserApcException,
    Signature,
    CbSignature,
    ValueSignature,
    ExportSignature,
    ValueCodeSignature,
    IntroFileHeader,
    IdtSignature,
    VersionOsSignature,
    VersionIntroSignature,
    ProcessCreationSignature
)

VERBOSE = 0


def signature_factory(json_sig):
    """ Poors man factory design pattern."""

    if "sig_type" not in json_sig:
        raise ValueError("Type of signature is required for %r!\n" % json_sig)

    sig_type = json_sig["sig_type"]

    if sig_type == "codeblocks":
        return CbSignature(**json_sig)
    elif sig_type == "export":
        return ExportSignature(**json_sig)
    elif sig_type == "value":
        return ValueSignature(**json_sig)
    elif sig_type == "value-code":
        return ValueCodeSignature(**json_sig)
    elif sig_type == "idt":
        return IdtSignature(**json_sig)
    elif sig_type == "version-os":
        return VersionOsSignature(**json_sig)
    elif sig_type == "version-intro":
        return VersionIntroSignature(**json_sig)
    elif sig_type == "process-creation":
        return ProcessCreationSignature(**json_sig)
    else:
        raise ValueError("Invalid signature type: %s" % sig_type)


def parse_json_object(json_object):
    """ Creates & returns a new KernelException/UserException/Signature from a json object. """
    if json_object["Type"] == "kernel" and "Exceptions" in json_object:
        return [KernelException(**d) for d in json_object["Exceptions"]]
    elif json_object["Type"] == "user" and "Exceptions" in json_object:
        return [UserException(**d) for d in json_object["Exceptions"]]
    elif json_object["Type"] == "user-glob-match" and "Exceptions" in json_object:
        return [UserGlobException(**d) for d in json_object["Exceptions"]]
    elif json_object["Type"] == "user-apc" and "Exceptions" in json_object:
        return [UserApcException(**d) for d in json_object["Exceptions"]]
    elif json_object["Type"] == "kernel-user" and "Exceptions" in json_object:
        return [KernelUserException(**d) for d in json_object["Exceptions"]]
    elif "Signatures" in json_object:
        return [signature_factory(d) for d in json_object["Signatures"]]

    raise ValueError("Invalid json object. Check the values of Type and Exceptions/Signatures")


def expand_exception(exception, attribute):
    """ Expand the given exception by the given attribute name.

    Returns a list containing all the exceptions after expanding. If the exception isn't to be
    expanded, then returns a list containing only that exception (but a list nontheless). """
    if attribute not in ("originator", "victim"):
        if isinstance(exception, KernelException):
            raise ValueError("We expand kernel exceptions only on victim or originator!")
        elif isinstance(exception, UserException) and attribute != "process":
            raise ValueError("We expand use exceptions only on victim, originator and process!")

    # Must we expand this exception ?
    if getattr(exception, attribute) not in excfg.get("Groups"):
        return [exception]

    ret_list = []
    # For each name in the group, generate a new one
    # A simple 'map' won't work since it will not give a flatten list
    for new_value in excfg.get("Groups", getattr(exception, attribute)):
        exc = exception.__dict__
        exc[attribute] = new_value

        if isinstance(exception, KernelException):
            ret_list.extend(expand_exception(KernelException(**exc), attribute))
        elif isinstance(exception, UserException):
            ret_list.extend(expand_exception(UserException(**exc), attribute))

    return ret_list


def expand_exceptions(exceptions):
    """ Expand the exception list, firts by the originator name, then by the victim name.

    Returns a list of exceptions (which cannot be expanded further). """
    exp_ex_originator = []
    exp_ex_victim = []
    exp_ex = []

    # First, extend by 'originator'
    for e in exceptions:
        if isinstance(e, (KernelException, UserException, KernelUserException, UserGlobException, UserApcException)):
            exp_ex_originator.extend(expand_exception(e, "originator"))
        elif isinstance(e, Signature):
            exp_ex_originator.append(e)
        else:
            raise ValueError("Invalid type in exceptions: %s!" % type(e))

    # Then, extend by the 'victim'
    for e in exp_ex_originator:
        if isinstance(e, (KernelException, UserException, KernelUserException, UserGlobException, UserApcException)):
            exp_ex_victim.extend(expand_exception(e, "victim"))
        elif isinstance(e, Signature):
            exp_ex_victim.append(e)
        else:
            raise ValueError("Invalid type in exceptions: %s!" % type(e))

    # Then, if needed, extend by the 'process'
    for e in exp_ex_victim:
        if isinstance(e, (UserException, UserGlobException, KernelUserException, UserApcException)):
            exp_ex.extend(expand_exception(e, "process"))
        elif isinstance(e, (KernelException, Signature)):
            exp_ex.append(e)
        else:
            raise ValueError("Invalid type in exceptions: %s!" % type(e))

    glob_items = ["*", "[", "]", "?", "\\\\"]

    kernel_exceptions = [e for e in exp_ex if isinstance(e, KernelException)]
    user_exceptions = [e for e in exp_ex if isinstance(e, (UserException, UserApcException))]
    kernel_user_exceptions = [e for e in exp_ex if isinstance(e, KernelUserException)]
    user_glob_exceptions_startswith_glob = [
        e
        for e in exp_ex
        if isinstance(e, UserGlobException) and e.originator.startswith(tuple(glob_items))
    ]
    user_glob_exceptions_not_startswith_glob = [
        e for e in exp_ex if isinstance(e, UserGlobException)
    ]
    signatures = [e for e in exp_ex if isinstance(e, Signature)]

    kernel_exceptions.sort()
    user_exceptions.sort()
    kernel_user_exceptions.sort()
    signatures.sort()

    user_glob_exceptions_not_startswith_glob.sort()
    user_glob_exceptions = list()
    user_glob_exceptions.extend(user_glob_exceptions_startswith_glob)
    user_glob_exceptions.extend(user_glob_exceptions_not_startswith_glob)

    return (kernel_exceptions, user_exceptions, kernel_user_exceptions, user_glob_exceptions, signatures)


def drop_unused_signatures(signatures, exceptions):
    for sig in signatures:
        found = False

        for exc in exceptions:
            if not exc.signatures:
                continue

            for e_sig in exc.binary["signatures"]:
                if sig.binary["id"] == e_sig:
                    found = True
                    break

        if not found:
            signatures.remove(sig)

            if VERBOSE >= 1:
                print("Remove unused signature", str(sig.sig_id))


def check_missing_signatures(signatures, exceptions):
    for exc in exceptions:
        if not exc.signatures:
            continue

        for e_sig_id in exc.binary["signatures"]:
            found = False

            for sig in signatures:
                if e_sig_id == sig.binary["id"]:
                    found = True
                    break

            if not found:
                raise ValueError("Signature %d not found in %r!" % (e_sig_id, exc.signatures))
                

def sanitize_json_file(json_file):
    """ I couldn't resist. Makes my job much more easier keeping the changes.

    Returns a string containing the file contents minus the comments. A comment is everything
    following a '//'. """
    return re.sub(r"\s*\/\/.*", "", json_file.read_text())


def parse_json_files(json_files):
    """ Will parse the given json files and returns a list of intro objects. """
    final = []
    for json_file in json_files:
        if VERBOSE >= 1:
            print("Loading file", json_file)

        json_object = json.loads(sanitize_json_file(json_file))

        if VERBOSE >= 1:
            print("Parsing file", json_file)

        final += parse_json_object(json_object)

        if VERBOSE >= 1:
            print("")

        del json_object

    return final


def run(json_files, args):
    """ Actually runs the program, after the command line arguments have been parsed. """
    excfg.parse(args.config)
    (kmex, umex, kumex, umgmex, sigs) = expand_exceptions(parse_json_files(json_files))

    drop_unused_signatures(sigs, kmex + umex + kumex + umgmex)
    check_missing_signatures(sigs, kmex + umex + kumex + umgmex)

    # So... don't ever open as 'w' if you plan to write any binary into it...
    # You can lose one hour of debugging wondering why is an extra byte on a
    # specific exception, every single time. That because the value 0x0a will
    # be written as 0x0d 0x0a. ('\n' -> '\r\n'). I fixed that once in perl i
    # think, and that time took more than one hour.
    with args.output.open("wb") as f:
        header = IntroFileHeader(len(kmex), len(umex), len (kumex), len(umgmex), len(sigs), int(args.build))
        f.write(header.get_binary())

        for e in kmex + umex + kumex + umgmex + sigs:
            if VERBOSE >= 2:
                print(e)
            f.write(e.get_binary_header())
            f.write(e.get_binary())

    if VERBOSE >= 1:
        print("")
        print("Generated %04d kernel exceptions" % len(kmex))
        print("Generated %04d user exceptions" % len(umex))
        print("Generated %04d kernel-user exceptions" % len(kumex))
        print("Generated %04d signatures" % len(sigs))
        print("-------------------------------")
        print("Total     %04d objects" % (len(kmex) + len(umex) + len(sigs)))


def get_argparser():
    """Get the argparse parser."""
    parser = argparse.ArgumentParser(prog="exceptions")
    parser.add_argument(
        "jsons", nargs="*", help="Jsons/Folders to parse for exceptions.", metavar=":jsons"
    )
    parser.add_argument(
        "-c",
        "--config",
        help="File where the configuration is.",
        action="store",
        default=Path("config.json"),
        type=Path,
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Filename to output to. Default: exceptions.bin",
        action="store",
        default=Path("exceptions.bin"),
        type=Path,
    )
    parser.add_argument(
        "-v", "--verbose", help="Verbosity level (0, 1 or 2)", action="store", default="0"
    )

    parser.add_argument("-b", "--build", help="Build number", action="store", default="0")

    return parser


def main():
    """ Main entrypoint. Parses the command line and runs the program. """
    global VERBOSE

    parser = get_argparser()
    args = parser.parse_args(sys.argv[1:])

    arg_paths = []
    for jarg in args.jsons:
        path = Path(jarg)

        if path.is_file():
            arg_paths.append(path)
        elif path.is_dir():
            for rfile in path.rglob("*"):
                if rfile.suffix == ".json":
                    data = json.loads(sanitize_json_file(rfile))
                    if 'Signatures' in data.keys():
                        arg_paths.insert(0, rfile)
                    else:
                        arg_paths.append(rfile)
                else:
                    print("Ignore unknown file:", rfile)
        else:
            print("Ignore unknown entity:", jarg)


    VERBOSE = int(args.verbose)

    if not arg_paths:
        parser.error("You must give at least one json file or folder.")

    run(arg_paths, args)


if __name__ == "__main__":
    main()
