##########################################################
##
## File: Bucket.py
## Author: Stephen Dimig (hdimig@nc.rr.com)
## Description: This file contains the Bucket class which is a light weight
## abstraction of an AWS S3 bucket.
##
##########################################################

# AWS imports
import boto3
from boto3.session import Session

# Other imports
import gzip
import StringIO
import pandas as pd
import json

##
## Class: Bucket
## Description: This class is a light weight abstraction of an AWS S3 bucket.
##
class Bucket(object):
    # Constants
    AWS_ACCESS_KEY_ID = 'AKIAJWLDT4TBHPP3MXEA'
    AWS_SECRET_ACCESS_KEY = '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'
    CLOUDTRAIL_BUCKET = 'cloudtrail-netapphcl'
    TARGET_USER = 'portal.service'

    ##
    ## Name: __init__
    ## Description: Constructor
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def __init__(self):
        self.__initData__()
        self.df = pd.DataFrame(columns=['userName', 'eventName', 'requestParameters', 'errorCode', 'errorMessage', 'date'])

    ##
    ## Name: append
    ## Description: This method processes the files in bucket_path and appends them to the working
    ## dataframe
    ##
    ## Parameters:
    ## bucket_path - Path to directory containg log files in JSON format that have been zipped.
    ##
    ## Returns: None
    ##
    def append(self, bucket_path):
        # Process ech file in the bucket_path directory
        for file in self.__listBucketObjects__(bucket_path):
            # Make sure it is a log file
            if file.key.endswith('.gz'):
                data = self.__loadJsonData__(file)

                # Iterate over all records paying attention the errors.
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

    ##
    ## Name: __initData__
    ## Description: Private method whose sole purpose is to make it easier to mock.
    ##
    ## Parameters: None
    ##
    ## Returns:
    ## None
    ##
    def __initData__(self):
        self.session = Session(aws_access_key_id=Bucket.AWS_ACCESS_KEY_ID,
                               aws_secret_access_key=Bucket.AWS_SECRET_ACCESS_KEY)
        self.s3 = self.session.resource('s3')
        self.bucket = self.s3.Bucket(Bucket.CLOUDTRAIL_BUCKET)

    ##
    ## Name: __listBucketObjects__
    ## Description: Private method whose sole purpose is to make it easier to mock.
    ##
    ## Parameters: None
    ##
    ## Returns:
    ## List of bucket objects filtered by bucket_path.
    ##
    def __listBucketObjects__(self, bucket_path):
        return self.bucket.objects.filter(Prefix=bucket_path)

    ##
    ## Name: __loadJsonData__
    ## Description: Private method whose sole purpose is to make it easier to mock.
    ##
    ## Parameters: None
    ##
    ## Returns:
    ## JSON formatted log data is returned.
    ##
    def __loadJsonData__(self, file):
        # Use StringIO for filelike interface.
        data_gz = StringIO.StringIO(file.get()['Body'].read())

        # Ungzip file and parse JSON
        return json.load(gzip.GzipFile(fileobj=data_gz))


    ##
    ## Name: data
    ## Description: This method returns the working dataframe
    ##
    ## Parameters: None
    ##
    ## Returns:
    ## A reference to the working dataframe is returned.
    ##
    def data(self):
        return self.df
