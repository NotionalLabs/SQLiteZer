#-------------------------------------------------------------------------------
# Name:        Notional SQLite module
# Purpose:     Provides an object class for decoding and interpreting a SQLite
#              DB data from a forenic perspective. Note: this module does not
#              provide querying capabilities - it is for low-level analysis only.
#
# Author:      Notional-Labs.com
#
# Created:     30/08/2013
# Licence:     Apache V.2
#-------------------------------------------------------------------------------
import logging
import struct


class NotionalSQLite:
    """
    NotionalSQLite is used to store file structure information and provide
    convenience functions for parsing the contents.
    """
    _dbheaderfmt = ">16shbbbbbbiiiiiiiiiii24sii"
    _dictkeys = ["sig","pagesize","writever","readver","resspace","maxpayload",
                "minpayload","leafpayload","changecount","dbsize","freepagelist",
                "totalfreelist","schemacookie","schemanum","defpagecache",
                "bigroottree","textencode","userver","incvac","expansion",
                "validfor","sqlver"]

    headerdict = dict()
    headertransdict = dict()
    isDirty = bool()
    dbfile = None
    isWAL = False

    def __init__(self, filepath):

        for key in self._dictkeys:
            self.headertransdict[key] = "ERROR - call translateHeader() first."
            self.headerdict[key] = "ERROR - Could not read value."
        try:
            self.dbfile = open(filepath,"rb")
        except:
            logging.error("ERROR: Could not open database file")

        self._parseDBHeader();

    def _parseDBHeader(self):
        """
        Parse the SQLite 3 database header metadata and control information.
        Sets headerdict.
        """
        rawheader = self.dbfile.read(100)
        unpackedheader = struct.unpack(self._dbheaderfmt,rawheader)
        self.headerdict = dict(zip(self._dictkeys,list(unpackedheader)))
        if (self.headerdict["readver"] == 2) or (self.headerdict["writever"] == 2):
            self.isWAL = True

    def checkSignature(self):
        """
        Convenience function to perform signature check.
        Returns bool.
        """
        if self.headerdict["sig"] == "SQLite format 3\x00":
            return True
        else:
            return False

    def translateHeader(self):
        """
        Parse the unpacked header into human-readable values according to
        the format spec at: http://www.sqlite.org/fileformat.html
        Returns Dict.
        """
    # Magic Header String
        if self.headerdict["sig"] == 'SQLite format 3\x00':
            self.headertransdict["sig"] = self.headerdict["sig"]
        else:
            self.headertransdict["sig"] = ("Invalid Signature")
    # Page Size
        if self.headerdict["pagesize"] == 1:
            self.headertransdict["pagesize"] = "65536 - SQLite v.3.7.1 or greater"
        else:
            self.headertransdict["pagesize"] = str(self.headerdict["pagesize"])
    # File format version numbers
        if (self.headerdict["writever"] > 2) and (self.headerdict["readver"] in (1,2)):
            self.headertransdict["writever"] = "READ-ONLY"
            if self.headerdict["readver"] == 1:
                self.headertransdict["readver"] = "Legacy - Roll Back Journalling"
            else:
                self.headertransdict["readver"] = "WAL - Write Ahead Log Journalling"
        elif (self.headerdict["readver"] > 2):
            self.headertransdict["readver"] = "Read and Write Disabled."
            if self.headerdict["writever"] == 1:
                self.headertransdict["writever"] = "Legacy - Roll Back Journalling"
            else:
                self.headertransdict["writever"] = "WAL - Write Ahead Log Journalling"
        elif (self.headerdict["writever"] in (1,2)) and (self.headerdict["readver"] in (1,2)):
            if self.headerdict["readver"] == 1:
                self.headertransdict["readver"] = "Legacy - Roll Back Journalling"
            else:
                self.headertransdict["readver"] = "WAL - Write Ahead Log Journalling"
            if self.headerdict["writever"] == 1:
                self.headertransdict["writever"] = "Legacy - Roll Back Journalling"
            else:
                self.headertransdict["writever"] = "WAL - Write Ahead Log Journalling"
        else:
            self.headertransdict["readver"] = "Invalid Value: %s" % self.headerdict["readver"]
            self.headertransdict["writever"] = "Invalid Value: %s" % self.headerdict["writever"]
    # Reserved bytes per page
        self.headertransdict["resspace"] = str(self.headerdict["resspace"])
    # Payload fractions
        if (self.headerdict["maxpayload"] == 64):
            self.headertransdict["maxpayload"] = "64"
        else:
            self.headertransdict["maxpayload"] = "Invalid value: %s" % str(headerdict["maxpayload"])
        if (self.headerdict["minpayload"] == 32):
            self.headertransdict["minpayload"] = "32"
        else:
            self.headertransdict["minpayload"] = "Invalid value: %s" % str(headerdict["minpayload"])
        if (self.headerdict["leafpayload"] == 32):
            self.headertransdict["leafpayload"] = "32"
        else:
            self.headertransdict["leafpayload"] = "Invalid value: %s" % str(headerdict["leafpayload"])
    # File change counter
        self.headertransdict["changecount"] = str(self.headerdict["changecount"])
        if self.isWAL:
            self.headertransdict["changecount"] += " (WAL enabled - value may be inaccurate.)"
    # In-header Database Size
        if (self.headerdict["changecount"] == self.headerdict["validfor"]) and (self.headerdict["dbsize"] > 0):
            self.headertransdict["dbsize"] = str(self.headerdict["dbsize"]) + " page(s)"
        else:
            self.headertransdict["dbsize"] = "Invalid value: %s" % str(self.headerdict["dbsize"])
    # Free Page List page number
        self.headertransdict["freepagelist"] = str(self.headerdict["freepagelist"])
    # Schema cookie
        self.headertransdict["schemacookie"] = str(self.headerdict["schemacookie"])
    # Schema Format number
        if self.headerdict["schemanum"] == 1:
            self.headertransdict["schemanum"] = "1 - SQLite 3.0.0+ Compatible"
        elif self.headerdict["schemanum"] == 2:
            self.headertransdict["schemanum"] = "2 - SQLite 3.1.3+ Compatible"
        elif self.headerdict["schemanum"] == 3:
            self.headertransdict["schemanum"] = "3 - SQLite 3.1.4+ Compatible"
        elif self.headerdict["schemanum"] == 4:
            self.headertransdict["schemanum"] = "4 - SQLite 3.3.0+ Compatible"
        else:
            self.headertransdict["schemanum"] = "Invalid value: %s" % str(headerdict["schemanum"])
    # Suggested cache size
        self.headertransdict["defpagecache"] = str(self.headerdict["defpagecache"])
    # Largest Root Tree Page and Incremental Vacuum Settings
        if self.headerdict["bigroottree"] == 0:
            self.headertransdict["bigroottree"] = "0 - ptrmap pages disabled"
            if self.headerdict["incvac"] == 0:
                self.headertransdict["incvac"] = "0 - auto_vacuum mode"
            else:
                self.headertransdict["incvac"] = "Invalid mode: %s" % str(headerdict["incvac"])
        else:
            self.headertransdict["bigroottree"] = str(self.headerdict["bigroottree"])
            self.headertransdict["incvac"] = "%s - incremental_vacuum mode" % str(headerdict["incvac"])
    # Text Encoding
        if self.headerdict["textencode"] == 1:
            self.headertransdict["textencode"] = "UTF-8"
        elif self.headerdict["textencode"] == 2:
            self.headertransdict["textencode"] = "UTF-16LE"
        elif self.headerdict["textencode"] == 3:
            self.headertransdict["textencode"] = "UTF-16BE"
        else:
            self.headertransdict["textencode"] = "Invalid Encoding: %s" % self.headerdict["textencode"]
    # User Version
        self.headertransdict["userver"] = str(self.headerdict["userver"])
    # Expansion block
        self.headertransdict["expansion"] = ":".join("{:02x}".format(ord(c)) for c in self.headerdict["expansion"])
    # Version Valid For number
        self.headertransdict["validfor"] = self.headerdict["validfor"]
    # SQlite version number
        self.headertransdict["sqlver"] = self.headerdict["sqlver"]

        return self.headertransdict








