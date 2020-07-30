#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import os, re, sys

def main():
    out_file_path = sys.argv[1]
    out_file_name = out_file_path.split('/')[-1].upper().split('.')[0]

    f = open(out_file_path, 'wt')
    f.write('#ifndef _%s_H_\n' % (out_file_name))
    f.write('#define _%s_H_\n\n' % (out_file_name))

    for arg in sys.argv[2:]:
        in_file_path = arg.split()[0]
        array_name = arg.split()[1]
        data = open(in_file_path, 'rb').read()
        f.write('unsigned char %s[] =\n' % (array_name))
        f.write('{\n')
        i = 0
        for byte in data:
            if i == 0:
                f.write('    ')
            f.write('0x%02x, ' % byte)
            i += 1
            if i == 16:
                f.write('\n')
                i = 0
        if 0 != i:
            f.write('\n};\n\n')
        else:
            f.write('};\n\n')
    f.write('#endif //!_%s_H_\n' % (out_file_name))
    f.close()
main()
