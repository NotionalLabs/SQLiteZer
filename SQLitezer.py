#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:        SQLitezer - Forensic SQLite Database Analyser and Reporting Tool
# Purpose:     Produces a csv-formatted report of each element in a database and
#              the associated metadata and content statistics (if appropriate).
#
# Author:      Jim Hung
#
# Created:     24/08/2013
# Licence:     Apache v2.0
#-------------------------------------------------------------------------------
import os
import sys
import argparse
import datetime
import time
import sqlite3
import logging
import csv
import struct

import NotionalSQLite

version = '0.3'
build = '20130921'

def main():
    startTime = datetime.datetime.now()
    startTimeStr = str(startTime)[:19].replace(":","-").replace(" ","_")

    outfile, infile = validateArgs()
    setupLogging(outfile)

    print "\n[CONFIGURATION]"
    logging.info(" Target Database: " + os.path.abspath(infile))
    logging.info(" Report File: " + os.path.abspath(outfile))

    print "\n <SETTING UP REPORT FILE...>"
    outcsv = csv.writer(open(outfile,"wb"))

    print "\n[DATABASE HEADER]"
    header = NotionalSQLite.NotionalSQLite(infile)
    if header.checkSignature():
        logging.info(" Signature check: Valid")
    else:
        logging.info(" Signature check: Invalid")
        logging.error("ERROR: Database is corrupt or encrypted - Signature: %s" % header.headerdict["sig"])
        logging.error("ERROR: Cannot continue - exiting.")
        sys.exit(1)

    transheaderdict = header.translateHeader()

    headerfields = (("Signature","sig"),
                    ("Page Size","pagesize"),
                    ("Read Format","readver"),
                    ("Write Format","writever"),
                    ("Max Reserved Bytes","maxpayload"),
                    ("Min Reserved Bytes","minpayload"),
                    ("Leaf Reserved Bytes","leafpayload"),
                    ("File Change Count","changecount"),
                    ("In-header DB Size","dbsize"),
                    ("Free Page List starting page","freepagelist"),
                    ("Total Free Pages","totalfreepage"),
                    ("Schema Cookie","schemacookie"),
                    ("Schema Format number","schemanum"),
                    ("Suggested cache size","defpagecache"),
                    ("Largest Root Page Number","bigroottree"),
                    ("Text Encoding","textencode"),
                    ("User Version","userver"),
                    ("Vacuum Settings","incvac"),
                    ("Expansion block","expansion"),
                    ("Valid-For Version","validfor"),
                    ("Last SQLite Version","sqlver"))

    outcsv.writerow(["{HEADER}"])
    outcsv.writerow(["Field Name","Raw Value","Translated Value"])
    for value in headerfields:
        print " %s: %s" % (value[0],transheaderdict[value[1]])
        outcsv.writerow((value[0],header.headerdict[value[1]],transheaderdict[value[1]]))

    print "\n[CONTENT ANALYSIS]"

    print "\n <CONNECTING TO DB...>"
    try:
        dbconn = sqlite3.connect(infile)
        dbcurs = dbconn.cursor()
    except:
        logging.error("Could not connect to SQLite DB - Exiting...")
        sys.exit(1)

    print "\n <GENERATING TABLE CONTENT REPORT>"
    elementCount, elementDict = getElements(dbcurs)

    print "\n[RESULTS]\n"

    logging.info("Total elements identified in database: %s" % str(elementCount))
    logging.info(" - # of Tables: %s" % str(len(elementDict["tables"])))
    logging.info(" - # of Indexes: %s" % str(len(elementDict["indexes"])))
    logging.info(" - # of Triggers: %s" % str(len(elementDict["triggers"])))
    logging.info(" - # of Views: %s" % str(len(elementDict["views"])))

    if (elementCount > 0):
        rowdata = list()
    # TABLES - Collect, Print, and Export.
        if len(elementDict["tables"]) > 0:
            for tablename in elementDict["tables"]:
                rowcount = getRowCount(tablename[0],dbcurs)
                rowdata.append([rowcount,0])

            row_format = "{:^4} {:<%s} {:<12}" % str(elementDict["maxtablenamelen"] + 1)
            column_header = ['#','Table Name', 'Row Count']
            column_divider = ['-','----------','---------']

            print "\n{TABLES}\n"
            print row_format.format(*column_header)
            print row_format.format(*column_divider)
            outcsv.writerow(["{TABLES}"])
            outcsv.writerow(["#","Table Name","Row Count","Rootpage","SQL Statement"])

            for table, row in zip(elementDict["tables"], rowdata):
                print row_format.format(elementDict["tables"].index(table)+1, table[0], *row)
                outcsv.writerow([elementDict["tables"].index(table)+1, table[0],row[0],table[2],table[3].replace(os.linesep,"")])

    # INDEXES - Collect, Print, and Export.
        if len(elementDict["indexes"]) > 0:
            row_format = "{:^4} {:<%s} {:<%s}" % (str(elementDict["maxindexnamelen"] + 5), str(elementDict["maxindextblnamelen"] + 1))
            column_header = ['#','Index Name', 'Associated Table']
            column_divider = ['-','----------','----------------']

            print "\n{INDEXES}\n"
            print row_format.format(*column_header)
            print row_format.format(*column_divider)
            outcsv.writerow(["{INDEXES}"])
            outcsv.writerow(["#","Index Name","Associated Table Name","Rootpage","SQL Statement"])

            for index in elementDict["indexes"]:
                if index[3] is None:
                    index[3] = "<EMPTY>"
                print row_format.format(elementDict["indexes"].index(index)+1, index[0], index[1])
                outcsv.writerow([elementDict["indexes"].index(index)+1,index[0],index[1],index[2],index[3].replace(os.linesep,"")])

    # TRIGGERS - Collect, Print, and Export.
        if len(elementDict["triggers"]) > 0:
            row_format = "{:^4} {:<15} {:<%s}" % (str(elementDict["maxtriggernamelen"] + 5))
            column_header = ['#','Triggering Type', 'Associated Table']
            column_divider = ['-','---------------','----------------']

            print "\n{TRIGGERS}\n"
            print row_format.format(*column_header)
            print row_format.format(*column_divider)
            outcsv.writerow(["{TRIGGERS}"])
            outcsv.writerow(["#","Triggering Type","Associated Table Name","Rootpage","SQL Statement"])

            for trigger in elementDict["triggers"]:
                print row_format.format(elementDict["triggers"].index(trigger)+1, trigger[0], trigger[1])
                outcsv.writerow([elementDict["triggers"].index(trigger)+1,trigger[0],trigger[1],trigger[2],trigger[3].replace(os.linesep,"")])

    # VIEWS - Collect, Print, and Export.
        if len(elementDict["views"]) > 0:
            for viewname in elementDict["views"]:
                rowcount = getRowCount(viewname[0],dbcurs)
                rowdata.append([rowcount,0])

            row_format = "{:^4} {:<%s} {:<12}" % str(elementDict["maxviewnamelen"] + 1)
            column_header = ['#','View Name', 'Row Count']
            column_divider = ['-','----------','---------']

            print "\n{VIEWS}\n"
            print row_format.format(*column_header)
            print row_format.format(*column_divider)
            outcsv.writerow(["{VIEWS}"])
            outcsv.writerow(["#","View Name","Row Count","Rootpage","SQL Statement"])

            for view, row in zip(elementDict["views"], rowdata):
                print row_format.format(elementDict["views"].index(view)+1, view[0], *row)
                outcsv.writerow([elementDict["views"].index(view)+1, view[0],row[0],view[2],view[3].replace(os.linesep,"")])

    else:
        logging.info("WARNING: Database does not contain any elements.")

    print ""
    logging.info("[REPORTING COMPLETED]")
    print ""
    logging.info("SQLiteZer took " + str(datetime.datetime.now()-startTime) + " to run.")

def getRowCount(tablename,dbcurs):
    """
    Return the number of rows in the table.
    """
    try:
        sqlquery = "SELECT count(*) FROM %s" % (tablename)
        dbcurs.execute(sqlquery)
    except sqlite3.OperationalError as e:
        logging.error('ERROR: The SQLite3 module encountered an error querying the table "%s" - check that you replaced the sqlite3.dll with the latest Amalgamation DLL from http://www.sqlite.org/download.html\nError: %s' % tablename,e)
        return 'ERROR'
    rowcount = dbcurs.fetchall()
    return rowcount[0][0]

def getElements(dbcurs):
    """
    Return a Dict of all elements in DB.
    """
    try:
        dbcurs.execute("SELECT * FROM sqlite_master")
        elementresults = dbcurs.fetchall()
    except sqlite3.OperationalError as e:
        logging.error('ERROR: The SQLite3 module encountered an error querying the master table - check that the database is not locked or in-use. The application cannot continue.\nError: %s' % e)
        sys.exit(1)

    elementdict = dict({"tables":list(),"indexes":list(),"triggers":list(),"views":list()})
    elementcount = 0
    tablenamelen = 0
    triggernamelen = 0
    indexnamelen = 0
    indextblnamelen = 0
    viewnamelen = 0
    viewtblnamelen = 0

    for element in elementresults:
        if element[0] == "table":
            elementdict["tables"].append([element[1],element[2],element[3], element[4]])
            if (len(element[1]) > tablenamelen):
                tablenamelen = len(element[1])
            elementcount += 1
        elif element[0] == "index":
            elementdict["indexes"].append([element[1],element[2],element[3], element[4]])
            if (len(element[1]) > indexnamelen):
                indexnamelen = len(element[1])
            if (len(element[2]) > indextblnamelen):
                indextblnamelen = len(element[2])
            elementcount += 1
        elif element[0] == "trigger":
            elementdict["triggers"].append([element[1],element[2],element[3], element[4]])
            if (len(element[1]) > triggernamelen):
                triggernamelen = len(element[1])
            elementcount += 1
        elif element[0] == "view":
            elementdict["views"].append([element[1],element[2],element[3], element[4]])
            if (len(element[1]) > viewnamelen):
                viewnamelen = len(element[1])
            if (len(element[2]) > viewtblnamelen):
                viewtblnamelen = len(element[2])
            elementcount += 1

    elementdict["maxtablenamelen"] = tablenamelen
    elementdict["maxindexnamelen"] = indexnamelen
    elementdict["maxindextblnamelen"] = indextblnamelen
    elementdict["maxtriggernamelen"] = triggernamelen
    elementdict["maxviewnamelen"] = viewnamelen
    elementdict["macviewtblnamelen"] = viewtblnamelen

    return elementcount, elementdict


def setupLogging(outfile):
    """
    Configure basic logging and populate the log with bibliographic info.
    """
    logfile = outfile + ".log"
    logging.basicConfig(filename=os.path.join(logfile),level=logging.DEBUG, format='%(asctime)s %(levelname)s: %(message)s', datefmt='%H:%M:%S')
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter('%(message)s'))
    logging.getLogger('').addHandler(console)
    logging.info("""\n   _____ ____    __    _ __    _____
  / ___// __ \  / /   (_) /___/__  / Notional Labs 2013
  \__ \/ / / / / /   / / __/ _ \/ / / _ \/ ___/
 ___/ / /_/ / / /___/ / /_/  __/ /_/  __/ /
/____/\___\_\/_____/_/\__/\___/____|___/_/
Forensic SQLite Database Analyser and Reporting Tool         """)
    print "------------------------------------------------------"
    logging.info("Version ["+version+"] Build ["+build+"] Author [James E. Hung]")
    print "------------------------------------------------------"
    #time.sleep(3)
    return

def validateArgs():
    """
    Validate arguments, .
    """
    parser = argparse.ArgumentParser(description="\nSQLite Reporter - 2013 Jim Hung, Notional-Labs.com")
    parser.add_argument('-o','--output', help='Output report file (CSV).', required=True)
    parser.add_argument('-i','--input', help='Target SQLite database file.', required=True)
    args = vars(parser.parse_args())

    try:
        with open(args['input']): pass
    except IOError:
        print "Target SQLite DB file does not exist or cannot be opened. Exiting..."
        sys.exit(1)

    return args['output'],args['input']

if __name__ == '__main__':
    main()
