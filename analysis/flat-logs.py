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
        tokens = line.strip().split('\t')
        
        if int(tokens[0], 16) not in error_messages:
            error_messages[int(tokens[0], 16)] = []

        error_messages[int(tokens[0], 16)].append("%s (%s)" % (tokens[1], json.loads(tokens[2])))

with gzip.open("/Users/asajjad/logs-beta.flat.gz", "w") as outf:
    with gzip.open("/Users/asajjad/logs-beta.json.gz", "r") as f:
        for line in f:
            data = json.loads(line.strip())

            if data["payload"]["status"] != "finished":
                continue

            for test in sorted(data["payload"]["tests"], key=lambda x: x["website"]):
                status = test["result"]["status"] if "status" in test["result"] else None
                error_code = test["result"]["errorCode"] if "errorCode" in test["result"] else None

                print >> outf, "%s\t%s\t%s\t%s\t%s\t%s\t%s" % \
                      (data["id"], \
                       "Yes" if data["payload"]["isNonBuiltInRootCertInstalled"] else "No", \
                       test["website"],
                       test["result"]["protocolVersion"] if "protocolVersion" in test["result"] else "N/A",
                       test["result"]["event"], \
                       getRootCA(test["result"]),
                       getErrorString(status, error_code))

