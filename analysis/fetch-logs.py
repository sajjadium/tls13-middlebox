
from moztelemetry.dataset import Dataset
import json

dataset = Dataset.from_source('telemetry')

dataset = (dataset.where(docType='OTHER')
                  .where(appName='Firefox')
                  .where(appUpdateChannel='beta')
                  .where(submissionDate=lambda x: x >= '20170701'))

records = dataset.records(sc)

logs = records.filter(lambda x: x["meta"]["docType"] == "tls13-middlebox-beta")

json_logs = logs.map(json.dumps)

print json_logs.count()

# beta_logs = logs.take(10000000)
# beta_logs = logs.collect()



# hdfs dfs -copyToLocal tls13-middlebox-beta-logs . ; hdfs dfs -rm -r -f tls13-middlebox-beta-logs
json_logs.saveAsTextFile('tls13-middlebox-beta-logs')


def findErrors(x):
     return x["payload"]["status"] == "finished"

finished = logs.filter(lambda x: x["payload"]["status"] == "finished")

print finished.count()
finished_logs = finished.take(10000000)

with open('logs-beta-finished.json', 'w') as f:
    for l in finished_logs:
        print >> f, json.dumps(l)


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

error_messages = {}

with open("codes.txt", "r") as f:
    for line in f:
        tokens = line.strip().split()
        
        if int(tokens[0], 16) not in error_messages:
            error_messages[int(tokens[0], 16)] = []

        error_messages[int(tokens[0], 16)].append(tokens[1])

getErrorString(2152398878, None)


import sys
import traceback

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

with open("logs-beta.flat", "w") as outf:
#     print >> outf, "Client\tNon-BuiltIn Root Cert Installed\tWebsite\tChain Root Cert\tError Codes"
    
    with open("logs-beta-finished.json", "r") as f:
        for line in f:
            data = json.loads(line.strip())

            if data["payload"]["status"] != "finished":
                continue

            for test in sorted(data["payload"]["tests"], key=lambda x: x["website"]):
                if test["result"]["event"] in ["load", "loadend"]:
                    continue

                status = test["result"]["status"] if "status" in test["result"] else None
                error_code = test["result"]["errorCode"] if "errorCode" in test["result"] else None

                print >> outf, "%s\t%s\t%s\t%s\t%s\t%s" % \
                      (data["id"], \
                       "Yes" if data["payload"]["isNonBuiltInRootCertInstalled"] else "No", \
                       test["website"], test["result"]["event"], \
                       getRootCA(test["result"]),
                       getErrorString(status, error_code))





