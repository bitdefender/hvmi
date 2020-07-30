#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import os, re, sys

def write_start_guard(fd, name):
    fd.write('#ifndef _%s_H_\n' % (name))
    fd.write('#define _%s_H_\n' % (name))
    fd.write('\n')

def write_end_guard(fd, name):
    fd.write('#endif // !_%s_H_' % (name))
    fd.write('\n')

def main():
    out_src_file_path = sys.argv[2]
    src_file_name = out_src_file_path.split('/')[-1].upper().split('.')[0]
    out_hdr_file_path = sys.argv[1]
    hdr_file_name = out_hdr_file_path.split("/")[-1]

    fd_src = open(out_src_file_path, 'wt')
    fd_hdr = open(out_hdr_file_path, 'wt')

    write_start_guard(fd_hdr, hdr_file_name.split(".")[0].upper())

    if hdr_file_name != '':
        fd_src.write('#include "%s"' % (hdr_file_name));
        fd_src.write('\n')
        fd_src.write('\n')

    for arg in sys.argv[3:]:
        in_file_path = arg.split()[0]
        array_name = arg.split()[1]
        data = open(in_file_path, 'rb').read()
        fd_hdr.write("extern unsigned char %s[%d];" % (array_name, len(data)))
        fd_hdr.write("\n\n")
        fd_src.write('unsigned char %s[%d] =\n' % (array_name, len(data)))
        fd_src.write('{\n')
        i = 0
        for byte in data:
            if i == 0:
                fd_src.write('    ')
            fd_src.write('0x%02x, ' % byte)
            i += 1
            if i == 16:
                fd_src.write('\n')
                i = 0
        if 0 != i:
            fd_src.write('\n};\n\n')
        else:
            fd_src.write('};\n\n')

    write_end_guard(fd_hdr, hdr_file_name.split(".")[0].upper())

    fd_src.close()
    fd_hdr.close();

main()
