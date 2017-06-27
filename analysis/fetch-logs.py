from moztelemetry.dataset import Dataset

dataset = Dataset.from_source('telemetry')

dataset = (dataset.where(docType='OTHER')
                  .where(appName='Firefox')
                  .where(appUpdateChannel='release')
                  .where(submissionDate=lambda x: x >= '20170605'))

logs = records.filter(lambda x: x["meta"]["docType"] == "tls13-middlebox")

logs.count()

logs.take(1)
