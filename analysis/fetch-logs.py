from moztelemetry.dataset import Dataset

dataset = Dataset.from_source('telemetry')

dataset = (dataset.where(docType='OTHER')
                  .where(appName='Firefox')
                  .where(appUpdateChannel='beta')
                  .where(submissionDate=lambda x: x >= '20170701'))

records = dataset.records(sc)

logs = records.filter(lambda x: x["meta"]["docType"] == "tls13-middlebox-beta")

print logs.count()

print logs.take(10)
