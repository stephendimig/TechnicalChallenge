import argparse
from pprint import pprint
import sys
import pandas as pd
from tabulate import tabulate
import glob
import datetime
import re
from Bucket import Bucket

CLOUDTRAIL_BUCKET_PATH_FMT = 'AWSLogs/210811600188/CloudTrail/{}/{:04}/{:02}/{:02}'

def eventSummary(df):
    mydf = df.groupby(df['eventName']).count()
    tempdf = pd.DataFrame(columns=['Event Name', 'Count'])
    counts = list(mydf['userName'])
    events = mydf.index.tolist()
    for count, event in zip(counts, events):
        tempdf.loc[len(tempdf.index)] = [event, count]
    print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')

def errorSummary(df):
    mydf = df[df.errorCode != None]
    mydf = mydf.groupby([mydf['errorCode'], mydf['eventName']]).count()
    tempdf = pd.DataFrame(columns=['Error Code / Event Name', 'Count'])
    counts = list(mydf['userName'])
    events = mydf.index.tolist()
    for count, event in zip(counts, events):
        tempdf.loc[len(tempdf.index)] = [event, count]
    print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')

def errorsByDateSummary(df):
    mydf = df[df.errorCode != None]
    mydf['date'] = pd.to_datetime(df['date']).apply(lambda x: x.date())
    mydf = mydf.groupby([mydf['date']]).count()
    tempdf = pd.DataFrame(columns=['Date', 'Count'])
    counts = list(mydf['userName'])
    dates = mydf.index.tolist()
    for count, date in zip(counts, dates):
        tempdf.loc[len(tempdf.index)] = [date, count]
    print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')

def main(argv):
    c_args = argparse.ArgumentParser(description='Explore Cloud Trail Logs')
    c_args.add_argument('--region', help='AWS region',
                        default="us-east-1", dest="region", required=False)
    c_args.add_argument('--start', help='Start date in month/day/year format', default=None)
    c_args.add_argument('--end', help='End date in month/day/year format', default=None)
    cli_args = c_args.parse_args()
    region = cli_args.region
    start = cli_args.start
    end = cli_args.end

    if None == start:
        print "Error: missing parameter - start"
        exit(-1)

    if not re.match(r'[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}', start):
        print "Error: incorrect format - start: " + start
        exit(-1)

    if None == end:
        print "Error: missing parameter - end"
        exit(-1)

    if not re.match(r'[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}', end):
        print "Error: incorrect format - end: " + end
        exit(-1)

    bucket = Bucket()
    start = datetime.datetime.strptime(start, "%m/%d/%Y")
    end = datetime.datetime.strptime(end, "%m/%d/%Y")
    date_list = [start + datetime.timedelta(days=x) for x in range(0, (end - start).days)]
    for date in date_list:
        date_arr = "{:%m/%d/%Y}".format(date).split('/')
        if len(date_arr) != 3:
            print "Error: incorrect format - date: " + date
            exit(-1)
        month = int(date_arr[-3])
        day = int(date_arr[-2])
        year = int(date_arr[-1])

        bucket_path = CLOUDTRAIL_BUCKET_PATH_FMT.format(region, year, month, day)
        bucket.append(bucket_path)

    df = bucket.data()

    eventSummary(df)

    errorSummary(df)

    errorsByDateSummary(df)

if __name__ == '__main__':
    main(sys.argv[1:])
