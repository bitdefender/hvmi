#
# Copyright (c) 2020 Bitdefender
# SPDX-License-Identifier: Apache-2.0
#
import sys, os, re

# Open & read the (binary) input file
data = open(sys.argv[1], 'rb').read()

# Prepare the output file
f = open(sys.argv[2], 'wt')

# Write the declaration
f.write('BYTE %s[%d] =\n' % (sys.argv[3], len(data)))
f.write('{\n')

# Now write the actual content
i = 0
for b in data:
    if 0 == i:
        f.write('    ')
    f.write('0x%02x, ' % b)
    i += 1
    if i == 16:
        f.write('\n')
        i = 0
if 0 != i:
    f.write('\n};\n\n')
else:
    f.write('};\n\n')

f.close()
