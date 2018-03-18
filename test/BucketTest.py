##########################################################
##
## File: BucketTest.py
## Author: Stephen Dimig (hdimig@nc.rr.com)
## Description: This file contains tests for the Bucket class which is a light weight
## abstraction of an AWS S3 bucket.
##
## Normally I'd have a lot more tests. I wanted to demonstrate how I like to
## write tests and use ofMocking  in particular.
##
##########################################################

import unittest
from mock import MagicMock, patch
from Bucket import Bucket
import pandas as pd
import json

# Mock data for JSON formatted log
jsonData = '{"Records": [{"eventVersion": "1.05", "eventID": "305fef31-c3ac-47a8-af07-160d4fd3f473", "eventTime": "2018-03-06T23:58:55Z", "requestParameters": {"includeAllInstances": "False", "instancesSet": {"items": [{"instanceId": "i-025850b79e724b595"}]}, "filterSet": {}}, "eventType": "AwsApiCall", "responseElements": "None", "awsRegion": "us-east-1", "eventName": "DescribeInstanceStatus", "userIdentity": {"userName": "portal.service", "principalId": "AIDAJTZ5DVWI6LGV5S25G", "accessKeyId": "AKIAJ66ORGCPOVHWV5OQ", "type": "IAMUser", "arn": "arn:aws:iam::210811600188:user/jerimiah", "accountId": "210811600188"}, "eventSource": "ec2.amazonaws.com", "requestID": "318fa276-1277-4334-acd6-9cf3f2c1925f", "userAgent": "aws-sdk-java/1.11.225 Linux/3.10.0-514.el7.x86_64 OpenJDK_64-Bit_Server_VM/25.151-b12 java/1.8.0_151 scala/2.11.7", "sourceIPAddress": "216.240.30.23", "recipientAccountId": "210811600188"}]}'

# Not target user
jsonData_not_terget_user = '{"Records": [{"eventVersion": "1.05", "eventID": "305fef31-c3ac-47a8-af07-160d4fd3f473", "eventTime": "2018-03-06T23:58:55Z", "requestParameters": {"includeAllInstances": "False", "instancesSet": {"items": [{"instanceId": "i-025850b79e724b595"}]}, "filterSet": {}}, "eventType": "AwsApiCall", "responseElements": "None", "awsRegion": "us-east-1", "eventName": "DescribeInstanceStatus", "userIdentity": {"userName": "sdimig", "principalId": "AIDAJTZ5DVWI6LGV5S25G", "accessKeyId": "AKIAJ66ORGCPOVHWV5OQ", "type": "IAMUser", "arn": "arn:aws:iam::210811600188:user/jerimiah", "accountId": "210811600188"}, "eventSource": "ec2.amazonaws.com", "requestID": "318fa276-1277-4334-acd6-9cf3f2c1925f", "userAgent": "aws-sdk-java/1.11.225 Linux/3.10.0-514.el7.x86_64 OpenJDK_64-Bit_Server_VM/25.151-b12 java/1.8.0_151 scala/2.11.7", "sourceIPAddress": "216.240.30.23", "recipientAccountId": "210811600188"}]}'

# S3 object for mocking
class S3Object(object):
    def __init__(self):
        self.key = 'AWSLogs/210811600188/CloudTrail/us-east-1/2018/03/07/210811600188_CloudTrail_us-east-1_20180307T0000Z_94Ho1el0GhAzMMj2.json.gz'
        self.bucket_name='cloudtrail-netapphcl'

##
## Class: BucketTest
## Description: This class is a unit test driver for the Bucket class.
##
class BucketTest(unittest.TestCase):
    ##
    ## Name: setUp
    ## Description: Setup fixture for the BucketTest class
    ##
    ## Parameters:
    ## None
    ##
    @patch('Bucket.Bucket.__initData__')
    def setUp(self, mock1):
        mock1.return_value = None

    ##
    ## Name: testSuccess
    ## Description: Test the success leg for the Bucket class
    ##
    ## Parameters:
    ## None
    ##
    @patch('Bucket.Bucket.__listBucketObjects__')
    @patch('Bucket.Bucket.__loadJsonData__')
    def testSuccess(self, mock2, mock1):
        self.bucket = Bucket()
        mock1.return_value = [S3Object()]
        mock2.return_value = json.loads(jsonData)
        self.bucket.append('AWSLogs/210811600188/CloudTrail/us-east-1/2018/03/07')
        df = self.bucket.data()
        self.assertEqual(len(df.index), 1)
        self.assertEqual(df['userName'][0], Bucket.TARGET_USER)
        self.assertEqual(df['eventName'][0], "DescribeInstanceStatus")
        self.assertEqual(df['errorCode'][0], None)
        self.assertEqual(df['errorMessage'][0], None)
        self.assertEqual(df['date'][0], "2018-03-06T23:58:55Z")

    ##
    ## Name: testNotTargetUser
    ## Description: Test the case where it is a log entry not associated with the target user.
    ##
    ## Parameters:
    ## None
    ##
    @patch('Bucket.Bucket.__listBucketObjects__')
    @patch('Bucket.Bucket.__loadJsonData__')
    def testNotTargetUser(self, mock2, mock1):
        self.bucket = Bucket()
        mock1.return_value = [S3Object()]
        mock2.return_value = json.loads(jsonData_not_terget_user)
        self.bucket.append('AWSLogs/210811600188/CloudTrail/us-east-1/2018/03/07')
        df = self.bucket.data()
        self.assertEqual(len(df.index), 0)


if __name__ == '__main__':
    unittest.main()
