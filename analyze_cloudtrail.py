##########################################################
##
## File: analyze_cloudtrail.py
## Author: Stephen Dimig (hdimig@nc.rr.com)
## Description: This file is the main python script for generating analysis reports
## for cloudtrail data based on the following technical challenge.
##
## Technical Challenge: (Any language like - RUBY, PYTHON)
## Challenge is about parsing the logs files. Parse the
## Jenkins/system/webserver logs and look for specific words in the log like
## FATAL or ERROR and output it to another log.
## Consolidated view based on ERROR TYPE, DATE and # OF OCCURENCES in a Day.
##
## I chose to parse out AWS cloudtrail logs rather than a Jenkins/system/webserver logs mostly
## due to applicabity to my current role (ie; I can reuse this in my job if things don't work out).
##
## Usage:
## analyze_cloudtrail.py [--region <AWS region>] --start <Date in mm/dd/yyyy> --end <Date in mm/dd/yyyy> [--format <TEXT | HTML>]
## region - The target AWS region. Defults to us-east-1.
## start - Start date in mm/dd/yyyy format.
## end - End date in mm/dd/yyyy format.
## format - The output format either TEXT or HTML (case insensitive). Defaults to text.
##
## Output:
## This program outputs a table summary of the following data.
## 1. A summary of counts for each event type that occurred in the date range.
## 2. A summary of counts for each error that occurred in the date range grouped by error code and event type.
## 3. A summary of counts for each error that occurred in the date range grouped by error code and date.
##
## What I would Like to have added.
## 1. More tests
## 2. More matplotlib visualizations in the html format report. Report contains one.
## 3. A statistical summary (ie; percentage of each type of error, etc.)
##
##########################################################


# System imports
import argparse
from pprint import pprint
import sys
import datetime
import re

# Local imports
from Bucket import Bucket
from ReportFormatter import ReportFormatter, ReportFormatterFactory, ReportFormatterType

# Constants
CLOUDTRAIL_BUCKET_PATH_FMT = 'AWSLogs/210811600188/CloudTrail/{}/{:04}/{:02}/{:02}'

def main(argv):
    # Command line argument parsing
    c_args = argparse.ArgumentParser(description='Explore Cloud Trail Logs')
    c_args.add_argument('--region', help='AWS region',
                        default="us-east-1", dest="region", required=False)
    c_args.add_argument('--start', help='Start date in month/day/year format', default=None)
    c_args.add_argument('--end', help='End date in month/day/year format', default=None)
    c_args.add_argument('--format', help='Output format: TEXT | HTML. Case insensitive',
                        default="TEXT", dest="format", required=False)
    cli_args = c_args.parse_args()
    region = cli_args.region
    start = cli_args.start
    end = cli_args.end
    format = cli_args.format

    # Initializations
    formatter = ReportFormatterFactory.create(ReportFormatterType.fromString(format))
    bucket = Bucket()

    # Validity checks
    if None == start:
        print "Error: missing parameter - start"
        print cli_args.echo
        exit(-1)

    if not re.match(r'[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}', start):
        print "Error: incorrect date format - start: " + start
        print cli_args.echo
        exit(-1)

    if None == end:
        print "Error: missing parameter - end"
        print cli_args.echo
        exit(-1)

    if not re.match(r'[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}', end):
        print "Error: incorrect date format - end: " + end
        print cli_args.echo
        exit(-1)

    if None == formatter:
        print "Error: invalid format type - format: " + format
        print cli_args.echo
        exit(-1)

    # Main processing loop based on range of dates
    start = datetime.datetime.strptime(start, "%m/%d/%Y")
    end = datetime.datetime.strptime(end, "%m/%d/%Y")
    for date in [start + datetime.timedelta(days=x) for x in range(0, (end - start).days)]:
        date_arr = "{:%m/%d/%Y}".format(date).split('/')
        if len(date_arr) != 3:
            print "Error: incorrect format - date: " + date
            exit(-1)
        month = int(date_arr[-3])
        day = int(date_arr[-2])
        year = int(date_arr[-1])

        bucket_path = CLOUDTRAIL_BUCKET_PATH_FMT.format(region, year, month, day)
        bucket.append(bucket_path)

    # Output report
    df = bucket.data()
    formatter.printHeader()
    formatter.eventSummary(df)
    formatter.errorSummary(df)
    formatter.errorsByDateSummary(df)
    formatter.printTrailer()

if __name__ == '__main__':
    main(sys.argv[1:])
