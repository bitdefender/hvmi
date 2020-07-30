#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from deserializer import Deserializer
from exception import Exception

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--content", help="Base64 string")
    parser.add_argument("-a", "--alert", help="Show alert", action="store_true", default=False)
    parser.add_argument("-e", "--exception", help="Show exception", action="store_true", default=False)
    args = parser.parse_args()

    if not args.content:
        parser._print_message("Content arg not provided!\n")
        parser.print_help()
        return

    deserializer = Deserializer(args)

    if args.alert:
        deserializer.run()

    if args.exception:
        deserializer.run()
        exception = Exception(deserializer._exception_obj)
        exception.run()

if __name__ == "__main__":
    main()
