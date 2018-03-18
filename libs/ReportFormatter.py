##########################################################
##
## File: ReportFormatter.py
## Author: Stephen Dimig (hdimig@nc.rr.com)
## Description: This file contains an implementation of the factory pattern
## for outputting the reports.
##
## ReportFormatterType - An enumeration specifying the output type.
## ReportFormatter - A base class with methods set u as pass through.
## TextFormatter - Outputs the report in text format.
## HtmlFormatter - Outputs the report in html format.
## ReportFormatterFactory - Creates a concrete ReportFormatter based on a type.
##
##########################################################

# Enumeration import
from enum import Enum

# Pandas related imports
import pandas as pd
from tabulate import tabulate

# Matplotlib includes
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import cStringIO
import urllib

##
## Class: ReportFormatterType
## Description: An enumeration used to specify the output type
##
class ReportFormatterType(Enum):
    TEXT = 1
    HTML = 2
    UNDEFINED = 3

    ##
    ## Name: __str__
    ## Description:
    ## Converts the enumerated type to a string value
    ##
    ## Parameters: None
    ##
    ## Returns:
    ## A string representation of the enumerated value.
    ##
    def __str__(self):
        val2str = {1: "TEXT", 2: "HTML", 3: "UNDEFINED"}
        return val2str[self.value]

    ##
    ## Name: fromString
    ## Description:
    ## Converts a string vale to an enumerated type
    ##
    ## Parameters:
    ## str - Astring representaion of the emumerated value.
    ##
    ## Returns:
    ## An enemerated value based on the string. UNDEFINED is returned as a default.
    ##
    @classmethod
    def fromString(cls, str):
        retval = "UNDEFINED"
        str2val = {"TEXT": ReportFormatterType.TEXT,
                   "HTML": ReportFormatterType.HTML,
                   "UNDEFINED": ReportFormatterType.UNDEFINED}

        if str.upper() in str2val.keys():
            retval = str2val[str.upper()]

        return retval

##
## Class: ReportFormatter
## Description: Base class for report formatters.
##
class ReportFormatter(object):
    ##
    ## Name: __init__
    ## Description: Constructor
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def __init__(self):
        pass

    ##
    ## Name: printHeader
    ## Description: Prints header info
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def printHeader(self):
        pass

    ##
    ## Name: eventSummary
    ## Description: Prints out a summary of counts based on event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def eventSummary(self, df):
        pass

    ##
    ## Name: errorSummary
    ## Description: Prints out a summary of counts based on error code / event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorSummary(self, df):
        pass

    ##
    ## Name: errorsByDateSummary
    ## Description: Prints out a summary of counts based on error code / date.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorsByDateSummary(self, df):
        pass

    ##
    ## Name: printTrailer
    ## Description: Prints trailer info
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def printTrailer(self):
        pass

##
## Class: TextFormatter
## Description: Concrete class that ouputs a text formatted report.
##
class TextFormatter(ReportFormatter):

    ##
    ## Name: __init__
    ## Description: Constructor
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def __init__(self):
        pass

    ##
    ## Name: eventSummary
    ## Description: Prints out a summary of counts based on event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def eventSummary(self, df):
        print 'Summary by Event Name:'
        mydf = df.groupby(df['eventName']).count()
        tempdf = pd.DataFrame(columns=['Event Name', 'Count'])
        counts = list(mydf['userName'])
        events = mydf.index.tolist()
        for count, event in zip(counts, events):
            tempdf.loc[len(tempdf.index)] = [event, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')
        print

    ##
    ## Name: errorSummary
    ## Description: Prints out a summary of counts based on error code / event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorSummary(self, df):
        print 'Summary by Error Code / Event Name:'
        mydf = df[df.errorCode != None]
        mydf = mydf.groupby([mydf['errorCode'], mydf['eventName']]).count()
        tempdf = pd.DataFrame(columns=['Error Code / Event Name', 'Count'])
        counts = list(mydf['userName'])
        events = mydf.index.tolist()
        for count, event in zip(counts, events):
            tempdf.loc[len(tempdf.index)] = [event, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')
        print

    ##
    ## Name: errorsByDateSummary
    ## Description: Prints out a summary of counts based on errors by date.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorsByDateSummary(self, df):
        print 'Summary of errors by Date:'
        mydf = df[df.errorCode != None]
        mydf['date'] = pd.to_datetime(df['date']).apply(lambda x: x.date())
        mydf = mydf.groupby([mydf['date']]).count()
        tempdf = pd.DataFrame(columns=['Date', 'Count'])
        counts = list(mydf['userName'])
        dates = mydf.index.tolist()
        for count, date in zip(counts, dates):
            tempdf.loc[len(tempdf.index)] = [date, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='psql')
        print

##
## Class: HtmlFormatter
## Description: Concrete class that ouputs a html formatted report.
##
class HtmlFormatter(ReportFormatter):
    ##
    ## Name: __init__
    ## Description: Constructor
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def __init__(self):
        pass

    ##
    ## Name: printHeader
    ## Description: Prints header info
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def printHeader(self):
        print '<html><head>'
        print '<meta content="text/html; charset=UTF-8" http-equiv="content-type">'
        print '<H1>' + 'AWS Cloudtrail Log Report' + '</H1>'

    ##
    ## Name: eventSummary
    ## Description: Prints out a summary of counts based on event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def eventSummary(self, df):
        print('<H2>Summary by Event Name:</H2>')
        mydf = df.groupby(df['eventName']).count()
        tempdf = pd.DataFrame(columns=['Event Name', 'Count'])
        counts = list(mydf['userName'])
        events = mydf.index.tolist()
        for count, event in zip(counts, events):
            tempdf.loc[len(tempdf.index)] = [event, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='html')
        print '<br \>'

    ##
    ## Name: errorSummary
    ## Description: Prints out a summary of counts based on error code / event type.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorSummary(self, df):
        print '<H2>Summary by Error Code / Event Name:</H2>'
        mydf = df[df.errorCode != None]
        mydf = mydf.groupby([mydf['errorCode'], mydf['eventName']]).count()
        tempdf = pd.DataFrame(columns=['Error Code / Event Name', 'Count'])
        counts = list(mydf['userName'])
        events = mydf.index.tolist()
        for count, event in zip(counts, events):
            tempdf.loc[len(tempdf.index)] = [event, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='html')
        print '<br \>'

    ##
    ## Name: errorsByDateSummary
    ## Description: Prints out a summary of counts based on error code / date.
    ##
    ## Parameters:
    ## df - dataframe that includes the AWS data
    ##
    ## Returns: None
    ##
    def errorsByDateSummary(self, df):
        print '<H2>Summary of errors by Date:</H2>'
        mydf = df[df.errorCode != None]
        mydf['date'] = pd.to_datetime(df['date']).apply(lambda x: x.date())
        mydf = mydf.groupby([mydf['date']]).count()
        tempdf = pd.DataFrame(columns=['Date', 'Count'])
        counts = list(mydf['userName'])
        dates = mydf.index.tolist()
        for count, date in zip(counts, dates):
            tempdf.loc[len(tempdf.index)] = [date, count]
        print tabulate(tempdf, headers=tempdf.columns.values.tolist(), tablefmt='html')
        print '<br \>'
        print self.plotSummary(tempdf)

    def plotSummary(self, mydf):
        # Create a plot.
        fig = plt.figure(figsize=(8, 8))

        # Now plot histogram by cloud provider
        plt.subplot(1, 1, 1)
        labels = mydf['Date']
        x = range(0, len(labels))
        y = mydf['Count']

        plt.title('Summary of errors by Date')
        plt.grid(True)
        b1 = plt.bar(x, y, align='center', alpha=0.5, color=['r', 'g', 'b'])
        plt.xticks(x, labels, rotation=45, ha='right')
        plt.ylabel('Errors')

        for i, v in enumerate(y):
            plt.text(i - 0.0375, v / 2, str(v), color='black', fontweight='bold')


        plt.tight_layout()
        ram = cStringIO.StringIO()
        plt.savefig(ram, format='png')
        data = ram.getvalue().encode('base64')
        return '<img src="data:image/png;base64,{}">'.format(urllib.quote(data.rstrip('\n')))

    ##
    ## Name: printTrailer
    ## Description: Prints trailer info
    ##
    ## Parameters: None
    ##
    ## Returns: None
    ##
    def printTrailer(self):
        print '</body></html>'

##
## Class: ReportFormatterFactory
## Description: Factory class that returns a report formatter based on a type
##
class ReportFormatterFactory(object):
    ##
    ## Name: create
    ## Description: Factory method that returns a report formatter based on a type
    ##
    ## Parameters:
    ## type - An enumerated value used to specify the type of report to format.
    ##
    ## Returns:
    ## A concrete ReportFormatter.
    ##
    @staticmethod
    def create(type):
        retval = None
        if ReportFormatterType.TEXT == type:
            retval = TextFormatter()
        elif ReportFormatterType.HTML == type:
            retval = HtmlFormatter()
        else:
            raise Exception('Error: invalid type - type=' + str(type))
        return retval