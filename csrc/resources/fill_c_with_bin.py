# -*- coding: utf-8 -*-
# @Author: Lorenzo
# @Date:   2019-02-01 11:55:19
# @Last Modified by:   Lorenzo
# @Last Modified time: 2019-02-01 12:33:12

import sys

c_file_template = sys.argv[1]
bin_file = sys.argv[2]

with open(bin_file, 'rb') as rr:
    binary_content = rr.read()

with open(c_file_template) as rr:
    c_source = rr.readlines()

start_fill = None
for line_n, line in enumerate(c_source):
    if line.startswith('const char'):
        start_fill = line_n + 1
        break
else:
    print('invalid c source')
    sys.exit(1)

c_bin_array = '    '
for byte_i, byte in enumerate(binary_content):
    if byte_i == len(binary_content) - 1:
        c_bin_array += '%3d\n' % byte    
    else:
        c_bin_array += '%3d, ' % byte
        if (byte_i % 12 == 11):
            c_bin_array += '\n    '

with open(c_file_template[:-len('.template.c')] + '.c', 'w+') as ww:
    ww.write('\n'.join(c_source[:start_fill]) + c_bin_array + '\n'.join(c_source[start_fill:]))


