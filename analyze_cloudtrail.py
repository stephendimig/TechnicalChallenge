import argparse
import json
from pprint import pprint
import sys
import pandas as pd
from tabulate import tabulate
import glob
import boto3
from boto3.session import Session
import gzip
import StringIO

AWS_ACCESS_KEY_ID = 'AKIAISKYNJFFLMF57CTA'
AWS_SECRET_ACCESS_KEY = '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'
CLOUDTRAIL_BUCKET = 'cloudtrail-netapphcl'
CLOUDTRAIL_BUCKET_PATH_FMT = 'AWSLogs/210811600188/CloudTrail/{}/{:04}/{:02}/{:02}'

def main(argv):
    c_args = argparse.ArgumentParser(description='Explore Cloud Trail Logs')
    c_args.add_argument('--region', help='AWS region',
                        default="us-east-1", dest="region", required=False)
    c_args.add_argument('--date', help='Date in month/day/year format', default=None)
    cli_args = c_args.parse_args()
    region = cli_args.region
    date = cli_args.date

    if None == date:
        print "Error: missing parameter - date"
        exit(-1)

    date_arr = date.split('/')
    if len(date_arr) != 3:
        print "Error: incorrect format - date: " + date
        exit(-1)
    month = int(date_arr[-3])
    day = int(date_arr[-2])
    year = int(date_arr[-1])

    bucket_path = CLOUDTRAIL_BUCKET_PATH_FMT.format(region, year, month, day)
    print bucket_path

    session = Session(aws_access_key_id=AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3 = session.resource('s3')
    bucket = s3.Bucket(CLOUDTRAIL_BUCKET)

    df = pd.DataFrame(columns=['userName', 'eventName', 'requestParameters', 'errorCode', 'errorMessage', 'date'])

    for file in bucket.objects.filter(Prefix=bucket_path):
        if file.key.endswith('.gz'):
            print(file.key)
            data_gz = StringIO.StringIO(file.get()['Body'].read())
            data = json.load(gzip.GzipFile(fileobj=data_gz))
            
            for record in data['Records']:
                errorCode = record['errorCode'] if 'errorCode' in record.keys() else None
                errorMessage = record['errorMessage'] if 'errorMessage' in record.keys() else None
                if 'userName' in record['userIdentity'] and record['userIdentity']['userName'] == 'portal.service':
                    df.loc[len(df.index)] = [record['userIdentity']['userName'], record['eventName'], str(record['requestParameters']), errorCode, errorMessage, record['eventTime']]


    mydf = df.groupby(df['eventName']).count()
    print tabulate(mydf, headers=mydf.columns.values.tolist(), tablefmt='psql')

    mydf = df[df.errorCode != None]
    mydf = mydf.groupby([mydf['errorCode'], mydf['eventName']]).count()
    print tabulate(mydf, headers=mydf.columns.values.tolist(), tablefmt='psql')

if __name__ == '__main__':
    main(sys.argv[1:])