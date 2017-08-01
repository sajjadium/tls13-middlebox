#!/usr/bin/python

import json
import sys
import traceback
import gzip

def intToHex(num):
    return hex(num) if num is not None else None

def getErrorString(status, error_code):
    if status in [0, None] and error_code in [0, None]:
        return "N/A"
    
    msg = []
    
    if status != 0 and status in error_messages:
        msg.extend(error_messages[status])

    if error_code != 0 and error_code in error_messages:
        for m in error_messages[error_code]:
            if m not in msg:
                msg.append(m)

    return json.dumps(msg)

def getRootCA(result):
    if "isBuiltInRoot" not in result:
        return "N/A"
    
    if result["isBuiltInRoot"]:
        return "Built-In"
    else:
        return "Middlebox"

error_messages = {}

with open("codes.txt", "r") as f:
    for line in f:
        tokens = line.strip().split()
        
        if int(tokens[0], 16) not in error_messages:
            error_messages[int(tokens[0], 16)] = []

        error_messages[int(tokens[0], 16)].append(tokens[1])

status_stats = {}
event_stats = {}

for line in sys.stdin:
    data = json.loads(line.strip())

    if data["payload"]["status"] not in status_stats:
        status_stats[data["payload"]["status"]] = 0

    status_stats[data["payload"]["status"]] += 1

    if data["payload"]["status"] != "finished":
        continue

    for test in sorted(data["payload"]["tests"], key=lambda x: x["website"]):
        #if test["result"]["event"] in ["load", "loadend"]:
        #    continue

        if test["result"]["event"] not in event_stats:
            event_stats[test["result"]["event"]] = 0

        event_stats[test["result"]["event"]] += 1

        status = test["result"]["status"] if "status" in test["result"] else None
        error_code = test["result"]["errorCode"] if "errorCode" in test["result"] else None
        '''
        print "%s\t%s\t%s\t%s\t%s\t%s" % \
              (data["id"], \
               "Yes" if data["payload"]["isNonBuiltInRootCertInstalled"] else "No", \
               test["website"], test["result"]["event"], \
               getRootCA(test["result"]),
               getErrorString(status, error_code))
        '''

print json.dumps(status_stats, indent=4, separators=(',', ': '))
print json.dumps(event_stats, indent=4, separators=(',', ': '))

