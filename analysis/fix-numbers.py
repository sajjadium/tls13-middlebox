#!/usr/bin/python

import sys

l = []

for line in sys.stdin:
    if '#define' not in line:
        continue

    tokens = line.strip().replace("(", "").replace(")", "").replace("L", "").split()

#    print "%s\t%s" % (tokens[0], hex(-0x3000 + int(tokens[-1])).upper())

    l.append((tokens[1], int(tokens[-1])))

for x, y in sorted(l, key=lambda z: (int(z[1]), z[0])):
    print '%s\t%s' % (hex(y).lower(), x)

