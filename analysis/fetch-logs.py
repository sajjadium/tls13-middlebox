
# coding: utf-8

# In[1]:

from moztelemetry.dataset import Dataset
import json

dataset = Dataset.from_source('telemetry')

dataset = (dataset.where(docType='OTHER')
                  .where(appName='Firefox')
                  .where(appUpdateChannel='nightly')
                  .where(submissionDate=lambda x: x >= '20170719'))

records = dataset.records(sc)

logs = records.filter(lambda x: x["meta"]["docType"] == "tls13-middlebox-beta")

print logs.count()

nightly_logs = logs.take(10000000)


# In[5]:




# In[2]:

# with open('beta-nightly.json', 'w') as f:
#     for l in nightly_logs:
#         print >> f, json.dumps(l)


# In[ ]:




# In[11]:

import sys
import traceback

def intToHex(num):
    return hex(num) if num is not None else None

def getErrorString(status, error_code):
    if status in [0, None] and error_code in [0, None]:
        return None
    
    msg = []
    
    if status != 0 and status in error_messages:
        msg.extend(error_messages[status])

    if error_code != 0 and error_code in error_messages:
        for m in error_messages[error_code]:
            if m not in msg:
                msg.append(m)

    return msg

error_messages = {}

with open("codes.txt", "r") as f:
    for line in f:
        tokens = line.strip().split()
        
        if int(tokens[0], 16) not in error_messages:
            error_messages[int(tokens[0], 16)] = []

        error_messages[int(tokens[0], 16)].append(tokens[1])

with open("logs-beta.flat", "w") as outf:    
    with open("logs-beta.json", "r") as f:
        for line in f:
            data = json.loads(line.strip())

            if data["payload"]["status"] != "finished":
                continue

            for test in data["payload"]["tests"]:
                if test["result"]["event"] in ["load", "loadend"]:
                    continue

                status = test["result"]["status"] if "status" in test["result"] else None
                error_code = test["result"]["errorCode"] if "errorCode" in test["result"] else None

                print >> outf, "%s\t%s\t%s\t%s\t%s" %                       (data["id"], test["website"], test["result"]["event"],                        json.dumps(test["result"]["isBuiltInRoot"] if "isBuiltInRoot" in test["result"] else None),                        json.dumps(getErrorString(status, error_code)))


# In[6]:




# In[ ]:



