import boto3
from boto3.session import Session
import gzip
import StringIO
import pandas as pd
import json

class Bucket(object):
    AWS_ACCESS_KEY_ID = 'AKIAJW3HG3HBBBNWZLZA'
    AWS_SECRET_ACCESS_KEY = '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'
    CLOUDTRAIL_BUCKET = 'cloudtrail-netapphcl'
    TARGET_USER = 'portal.service'

    def __init__(self):
        self.session = Session(aws_access_key_id=Bucket.AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=Bucket.AWS_SECRET_ACCESS_KEY)
        self.s3 = self.session.resource('s3')
        self.bucket = self.s3.Bucket(Bucket.CLOUDTRAIL_BUCKET)
        self.df = pd.DataFrame(columns=['userName', 'eventName', 'requestParameters', 'errorCode', 'errorMessage', 'date'])

    def append(self, bucket_path):
        for file in self.bucket.objects.filter(Prefix=bucket_path):
            if file.key.endswith('.gz'):
                data_gz = StringIO.StringIO(file.get()['Body'].read())
                data = json.load(gzip.GzipFile(fileobj=data_gz))

                for record in data['Records']:
                    errorCode = record['errorCode'] if 'errorCode' in record.keys() else None
                    errorMessage = record['errorMessage'] if 'errorMessage' in record.keys() else None
                    if 'userName' in record['userIdentity'] and record['userIdentity']['userName'] == Bucket.TARGET_USER:
                        self.df.loc[len(self.df.index)] = [record['userIdentity']['userName'],
                                                      record['eventName'],
                                                      str(record['requestParameters']),
                                                      errorCode,
                                                      errorMessage,
                                                      record['eventTime']]

    def data(self):
        return self.df
