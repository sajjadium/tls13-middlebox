
# coding: utf-8

# In[1]:

from moztelemetry.dataset import Dataset
import json

dataset = Dataset.from_source('telemetry')

dataset = (dataset.where(docType='OTHER')
                  .where(appName='Firefox')
                  .where(appUpdateChannel='beta')
                  .where(submissionDate=lambda x: x >= '20170712'))

records = dataset.records(sc)

logs = records.filter(lambda x: x["meta"]["docType"] == "tls13-middlebox-beta")

print logs.count()

beta_logs = logs.take(1000000)


# In[2]:

with open('beta-logs.json', 'w') as f:
    for l in beta_logs:
        print >> f, json.dumps(l)


# In[3]:




# In[39]:

import sys
import traceback

def intToHex(num):
    return hex(num) if num is not None else None

def getErrorString(ec):
    if ec in error_names:
        error_names[ec]
        
    return []

error_names = {}

with open("codes.txt", "r") as f:
    for line in f:
        tokens = line.strip().split()
        
        if int(tokens[0]) not in error_names:
            error_names[int(tokens[0])] = []
            
        error_names[int(tokens[0])].append(tokens[1])

security_states = set()
status = set()
errorCodes = set()
status_error_codes = set()

try:
    with open("beta-logs-finihsed.json", "r") as f:
        for line in f:
            data = json.loads(line.strip())

            for test in data["payload"]["tests"]:
                if "securityState" in test["result"]:
                    security_states.add(test["result"]["securityState"])
                
                s = (test["result"]["status"] if "status" in test["result"] else None)
                status.add(s)
                
                ec = (test["result"]["errorCode"] if "errorCode" in test["result"] else None)
                errorCodes.add(ec)
                
                status_error_codes.add((s, ec))
except:
    print >> sys.stderr, traceback.format_exc()
    print >> sys.stderr, json.dumps(data, indent=4, separators=(',', ': '))

print "securityState: ", [intToHex(x) for x in security_states]
print "status: ", [intToHex(x) for x in status]
print "errorCode: ", [intToHex(x) for x in errorCodes]

print "status errorCode pair: "

sorted_ = sorted([(x, y) for x, y in status_error_codes], key=lambda z: (z[0], z[1]))

for x, y in sorted_:
    print "%s (%s)\t%s (%s)" % (intToHex(x), getErrorString(x), intToHex(y), getErrorString(y))


# In[ ]:



