#!/usr/bin/python

import sys
import json
import traceback

codes_desc = {}

for filename in ['nsprpub/pr/src/misc/prerr.properties', 'security/manager/locales/en-US/chrome/pipnss/nsserrors.properties']:
    with open('/Users/asajjad/firefox/mozilla-central/' + filename, 'r') as f:
        for line in f:
            if '=' not in line:
                continue

            tokens = line.strip().split('=')

            codes_desc[tokens[0].upper()] = tokens[1]

with open('/Users/asajjad/firefox/mozilla-central/js/xpconnect/src/xpc.msg', 'r') as f:
    for line in f:
        try:
            if 'XPC_MSG_DEF' not in line:
                continue

            tokens = line.strip().replace('XPC_MSG_DEF', '').replace('(', '').replace(')', '').replace(',', '\t\t\t', 1).split('\t\t\t')

            codes_desc[tokens[0].strip().upper()] = json.loads(tokens[1].strip())
        except:
            print >> sys.stderr, traceback.format_exc(), line, tokens

with open('codes.txt', 'r') as f:
    for line in f:
        tokens = line.strip().split()

        desc = "" if tokens[1].upper() not in codes_desc else codes_desc[tokens[1].upper()]

        print '%s\t%s\t%s' % (tokens[0].lower(), tokens[1].upper(), json.dumps(desc))

