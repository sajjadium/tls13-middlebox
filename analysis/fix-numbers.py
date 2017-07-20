#!/usr/bin/python

import sys

for line in sys.stdin:
    if '*' in line or line.strip() == "":
        continue

    tokens = line.strip().replace("(", "").replace(")", "").replace(",", "").split()

    print "%s\t%s" % (tokens[0], hex(-0x3000 + int(tokens[-1])).upper())

