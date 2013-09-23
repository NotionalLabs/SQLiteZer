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
import os


class NotionalSQLite:
    """
    NotionalSQLite is used to store file structure information and provide
    convenience functions for parsing the contents.
    """
    _dbheaderfmt = ">16shbbbbbbiiiiiiiiiii24sii"
    _dictkeys = ["sig","pagesize","writever","readver","resspace","maxpayload",
                "minpayload","leafpayload","changecount","dbsize","freepagelist",
                "totalfreepage","schemacookie","schemanum","defpagecache",
                "bigroottree","textencode","userver","incvac","expansion",
                "validfor","sqlver"]

    headerdict = dict()
    headertransdict = dict()
    isDirty = bool()
    dbfile = None
    isWAL = False

    debug = 0

    def __init__(self, filepath):

        for key in self._dictkeys:
            self.headertransdict[key] = "ERROR - call translateHeader() first."
            self.headerdict[key] = "ERROR - Could not read value."
        try:
            self.dbfile = open(filepath,"rb")
        except:
            logging.error("ERROR: Could not open database file")

        self._parseDBHeader();

        if self.debug:

            """
            recordstartofs = 60783
            val,length = self._getVarIntOfs(recordstartofs)
            print "Record Length val: " + str(val)
            print "varint len: " + str(length)
            recordstartofs+=length
            val,length = self._getVarIntOfs(recordstartofs)
            print "Record Row ID: " + str(val)
            print "varint len: " + str(length)
            recordstartofs+=length
            val,length = self._getVarIntOfs(recordstartofs)
            print "Payload Header Length: " + str(val)
            print "varint len: " + str(length)
            recordstartofs+=length
            """

            print self._parseCell(60783)

            print self.mapPages(4096)

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

    def _parseCell(self,offset):
        """
        Parse a B-Tree Leaf Page Cell, given it's starting absolute byte offset.
        Pass absolute starting byte offset for the cell header.
        Returns the parsed cell as a list in the form:

        """
        celldatalist = list()
        cellheader,dataoffset,payloadlen,recordnum = self._parseCellHeader(offset)

        for field in cellheader:
            if field[0] == "NULL":
                celldatalist.append(recordnum)
            elif field[0] == "ST_INT8":
                self.dbfile.seek(dataoffset)
                celldatalist.append(ord(struct.unpack(">c",self.dbfile.read(1))[0]))
                dataoffset+=field[1]
            elif field[0] == "ST_INT16":
                self.dbfile.seek(dataoffset)
                celldatalist.append(struct.unpack(">h",self.dbfile.read(2))[0])
                dataoffset+=field[1]
            elif field[0] == "ST_INT32":
                self.dbfile.seek(dataoffset)
                celldatalist.append(struct.unpack(">i",self.dbfile.read(4))[0])
                dataoffset+=field[1]
            elif field[0] == "ST_INT48":
                self.dbfile.seek(dataoffset)
                celldatalist.append("ST_INT48 - NOT IMPLEMENTED!") # NOT IMPLEMENTED YET!
                dataoffset+=field[1]
            elif field[0] == "ST_INT64":
                self.dbfile.seek(dataoffset)
                celldatalist.append(struct.unpack(">q",self.dbfile.read(8))[0])
                dataoffset+=8
            elif field[0] == "ST_FLOAT":
                self.dbfile.seek(dataoffset)
                celldatalist.append(struct.unpack(">d",self.dbfile.read(8))[0])
                dataoffset+=8
            elif field[0] == "ST_C0":
                celldatalist.append("ST_C0 - NOT IMPLEMENTED!") # NOT IMPLEMENTED YET!
            elif field[0] == "ST_C1":
                celldatalist.append("ST_C0 - NOT IMPLEMENTED!") # NOT IMPLEMENTED YET!
            elif field[0] == "ST_BLOB":
                self.dbfile.seek(dataoffset)
                celldatalist.append(self.dbfile.read(field[1]))
                dataoffset+=field[1]
            elif field[0] == "ST_TEXT":
                self.dbfile.seek(dataoffset)
                celldatalist.append(struct.unpack("%ss" % str(field[1]),self.dbfile.read(field[1]))[0])
                dataoffset+=field[1]
            else:
                print field[0]

        return celldatalist


    def _parseCellHeader(self,offset):
        """
        Parse a B-Tree Leaf Page Cell Header, given it's starting absolute byte
        offset.
        Pass absolute starting byte offset for the cell header to be decoded.
        Returns tuple containing a list of tuples in the form
        [(String type,int length),...], and the starting offset of the payload
        fields.
        """
        headerlist = list()

        # Payload length
        payloadlen,length = self._getVarIntOfs(offset)
        offset+=length
        # Record Number
        recordnum,length = self._getVarIntOfs(offset)
        offset+=length
        # Payload Header Length
        payloadheaderlen,length = self._getVarIntOfs(offset)
        payloadheaderlenofs = offset + payloadheaderlen
        offset+=length
        # Payload Fields
        while offset < (payloadheaderlenofs):
            fieldtype,length = self._getVarIntOfs(offset)
            # Determine Serial Type
            if fieldtype == 0:
                headerlist.append(("NULL",0))
            elif fieldtype == 1:
                headerlist.append(("ST_INT8",1))
            elif fieldtype == 2:
                headerlist.append(("ST_INT16",2))
            elif fieldtype == 3:
                headerlist.append(("ST_INT24",3))
            elif fieldtype == 4:
                headerlist.append(("ST_INT32",4))
            elif fieldtype == 5:
                headerlist.append(("ST_INT48",6))
            elif fieldtype == 6:
                headerlist.append(("ST_INT64",8))
            elif fieldtype == 7:
                headerlist.append(("ST_FLOAT",8))
            elif fieldtype == 8:
                headerlist.append(("ST_C0",0))
            elif fieldtype == 9:
                headerlist.append(("ST_C1",0))
            elif fieldtype > 11:
                if (fieldtype%2) == 0:
                    headerlist.append(("ST_BLOB",(fieldtype-12)/2))
                else:
                    headerlist.append(("ST_TEXT",(fieldtype-13)/2))
            else:
                headerlist.append(("Reserved: %s" % str(fieldtype),0))
            offset+=length

        return headerlist, offset, payloadlen, recordnum

    def _getVarIntOfs(self,offset):
        """
        Decode Huffman-coded two's compliment integers used for storing 64-bit
        variable-length integers. Implements Mike Harrington's example technique
        for decoding SQLite VarInts (https://mobileforensics.wordpress.com/2011/
        09/17/huffman-coding-in-sqlite-a-primer-for-mobile-forensics/). SQLite
        spec allows for between 1-9 byte runs per VarInt - this method should
        scale to that size, despite such huge values being rare in practice.

        Pass starting byte offset to decode.
        Returns tuple(VarInt value and the VarInt length).
        """
        self.dbfile.seek(offset)
        varintlen = varintval = 0

        while True:
            if((ord(self.dbfile.read(1))&(1<<7))!=0):
                varintlen+=1
            else:
                varintlen+=1
                break
        self.dbfile.seek(offset)
        for i in reversed(range(0,varintlen)):
            if (i == 0):
                byteval = ord(self.dbfile.read(1))
                varintval+=byteval
            else:
                byteval = ord(self.dbfile.read(1))
                varintval+=(byteval - 128)*(2**(i*7))

        return varintval,varintlen

    def _getVarInt(self,bytestring):
        """
        As with _getVarIntOfs, but with an already-known length byte string.
        Example: result = _getVarInt(file.read(3))
        Warning: This methid will attempt to decode the bytestring regardless
        of whether it's a valid VarInt.
        Pass byte string to decode.
        Returns VarInt value.
        """
        varintlen = len(bytestring)
        varintval = bytestringpos = 0

        for i in reversed(range(0,varintlen)):
            if (i == 0):
                byteval = ord(bytestring[bytestringpos])
                varintval+=byteval
            else:
                byteval = ord(bytestring[bytestringpos])
                varintval+=(byteval - 128)*(2**(i*7))
            bytestringpos+=1

        return varintval,varintlen

    def mapPages(self,pagesize):
        """
        Debugging method to give a visual representation of the distribution of
        page types.
        Pass the pagesize value from the DB header.
        Returns a string.
        key:
        h = header page
        i = interior index b-tree page
        t = interior table b-tree page
        I = leaf index b-tree page
        T = leaf table b-tree page
        """
        offset = intindex = inttbl = leafindex = leaftbl = headercnt = overflow = 0
        pagemap = ""
        filesize = os.path.getsize(self.dbfile.name)
        while (offset < filesize):
            self.dbfile.seek(offset)
            flag = ord(self.dbfile.read(1))
            if (flag == 2):
                pagemap+="i"
                intindex+=1
            elif (flag == 5):
                pagemap+="t"
                inttbl+=1
            elif (flag == 10):
                pagemap+="I"
                leafindex+=1
            elif (flag == 13):
                pagemap+="T"
                leaftbl+=1
            elif (flag == 83):
                pagemap+="h"
                headercnt+=1
            else:
                pagemap+="o"
                overflow+=1
            offset+=(pagesize)
        print str(intindex)
        print str(inttbl)
        print str(leafindex)
        print str(leaftbl)
        print str(headercnt)
        print str(overflow)
        return pagemap

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
        if self.headerdict["pagesize"] == -32768:
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
    # Total Free Pages
        self.headertransdict["totalfreepage"] = str(self.headerdict["totalfreepage"])
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








