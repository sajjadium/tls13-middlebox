#!/usr/bin/python

import sys

l = []

for line in sys.stdin:
#    if '*' in line or line.strip() == "":
#        continue

#    tokens = line.strip().replace("(", "").replace(")", "").replace(",", "").split()

#    print "%s\t%s" % (tokens[0], hex(-0x3000 + int(tokens[-1])).upper())

    l.append(line.strip().split())

for x, y in sorted(l, key=lambda z: (int(z[1], 16), z[0])):
    print '%s\t%s' % (y.lower(), x)

