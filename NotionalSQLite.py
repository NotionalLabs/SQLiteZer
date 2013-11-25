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
import re
import unicodedata

class NotionalSQLite:
    """
    NotionalSQLite is used to store file structure information and provide
    convenience functions for parsing the contents.
    """
    _dbheaderfmt = ">16sHbbbbbbiiiiiiiiiii24sii"
    _dictkeys = ["sig","pagesize","writever","readver","resspace","maxpayload",
                "minpayload","leafpayload","changecount","dbsize","freepagelist",
                "totalfreepage","schemacookie","schemanum","defpagecache",
                "bigroottree","textencode","userver","incvac","expansion",
                "validfor","sqlver"]
    _btreetblleafheaderfmt = ">bsssbi"
    all_chars = (unichr(i) for i in xrange(0x110000))
    control_chars = ''.join(map(unichr, range(0,32) + range(127,160)))

    statuscode = 1
    headerdict = dict()
    headertransdict = dict()
    isDirty = bool()
    dbfile = None
    isWAL = False
    debug = False

    def __init__(self, filepath, debug):

        self.debug = debug

        for key in self._dictkeys:
            self.headertransdict[key] = "ERROR - call translateHeader() first."
            self.headerdict[key] = "ERROR - Could not read value."
        try:
            self.dbfile = open(filepath,"rb")
        except:
            logging.error("ERROR: Could not open database file")
            return

        self._parseDBHeader();

        if self.debug:
            pass

        self.statuscode = 0

    def _strip_nonprintable(self,s):
        control_char_re = re.compile('[%s]' % re.escape(self.control_chars))
        return control_char_re.sub('', s)

    def _parseTableLeafPageHeader(self,offset,pagesize):
        """
        Parse a binary-tree Table Leaf header given its starting (physical) offset.
        Pass physical offset to start of page (should be 0x0D) and page size from
        DB header. cell-pointers, freeblock lists, and the offset to unused area
        are relative offsets.
        Returns a dict of header field metadata, a list of (active) cell-pointers,
        a list of freeblocks, and the starting offset of the content area.
        """
        pageheader = dict()
        celllist = list()
        freeblklist = list()

        # Parse Page Header
        self.dbfile.seek(offset)
        pageheader['pagetype'] = ord(self.dbfile.read(1))
        pageheader['freeblockofs'] = struct.unpack(">h",self.dbfile.read(2))[0]
        pageheader['pagecellcount'] = struct.unpack(">h",self.dbfile.read(2))[0]
        pageheader['contentareaofs'] = struct.unpack(">h",self.dbfile.read(2))[0]
        pageheader['freebytefrags'] = ord(self.dbfile.read(1))

        # Parse Cell Pointer Array and note the start of cell content area
        for ptr in range(0,pageheader['pagecellcount']):
            celllist.append(struct.unpack(">h",self.dbfile.read(2))[0])
        cellptrendofs = self.dbfile.tell() - offset

        # Get Freeblock offsets
        self.dbfile.seek(offset+pageheader['freeblockofs'])
        freeblkptr = pageheader['freeblockofs']
        while freeblkptr != 0:
            freeblklist.append(freeblkptr)
            freeblkptr = struct.unpack(">h",self.dbfile.read(2))[0]
            self.dbfile.seek(offset+freeblkptr)

        return pageheader, celllist, freeblklist, cellptrendofs

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
            elif field[0] == "ST_INT24":
                self.dbfile.seek(dataoffset)
                celldatalist.append("ST_INT24 - NOT IMPLEMENTED!") # NOT IMPLEMENTED YET!
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

    def getPageTypeDict(self,pagesize):
        """
        Return a dict containing seperate lists of all Page type absolute
        starting offsets.
        """
        pagedict = dict()
        pagedict['intindex'] = list()
        pagedict['inttable'] = list()
        pagedict['leafindex'] = list()
        pagedict['leaftable'] = list()
        pagedict['overflow'] = list()
        offset = 0
        filesize = os.path.getsize(self.dbfile.name)

        while (offset < filesize):
            self.dbfile.seek(offset)
            flag = ord(self.dbfile.read(1))
            if (flag == 2):
                pagedict['intindex'].append(offset)
            elif (flag == 5):
                pagedict['inttable'].append(offset)
            elif (flag == 10):
                pagedict['leafindex'].append(offset)
            elif (flag == 13):
                pagedict['leaftable'].append(offset)
            elif (flag == 83):
                pass
            elif (flag == 0):
                pagedict['overflow'].append(offset)
            else:
                print "Invalid Page Type: %s (%s)" % (str(flag), str(offset))
                break
            offset+=pagesize
        return pagedict

    def getActiveRowContent(self, offset, pagesize):
        """
        Return a list of lists containing the content of all active cells in the
        page.
        """
        cellcontentlist = list()
        a,celllist,c,d = self._parseTableLeafPageHeader(offset,pagesize)
        for cell in celllist:
            cellcontentlist.append(self._parseCell(offset+cell))
        return cellcontentlist

    def getUnallocContent(self, offset, pagesize):
        """
        Return a list of lists containing the content of all unallocated areas
        in the page. All non-printable chars are stripped.
        """
        unalloclist = list()
        pageheader, celllist, freeblklist, cellptrendofs = self._parseTableLeafPageHeader(offset,pagesize)
        self.dbfile.seek(offset+cellptrendofs)
        length = pageheader['contentareaofs']-cellptrendofs
        unalloclist.append([offset+cellptrendofs,"Unallocated",length,self._strip_nonprintable(self.dbfile.read(length))])
        for freeblk in freeblklist:
            self.dbfile.seek(offset+freeblk+2) # skip past the 2-byte next freeblock ptr
            freeblklen = struct.unpack(">H",self.dbfile.read(2))[0]
            unalloclist.append([offset+freeblk,"Free Block",freeblklen,self._strip_nonprintable(self.dbfile.read(freeblklen-4))])
        return unalloclist

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
                pagemap+="O"
                overflow+=1
            offset+=(pagesize)
        total = intindex + inttbl + leafindex + leaftbl + headercnt + overflow
        return (pagemap,intindex,inttbl,leafindex,leaftbl,headercnt,overflow,total)

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
            self.headertransdict["schemanum"] = "Invalid value: %s" % str(self.headerdict["schemanum"])
    # Suggested cache size
        self.headertransdict["defpagecache"] = str(self.headerdict["defpagecache"])
    # Largest Root Tree Page and Incremental Vacuum Settings
        if self.headerdict["bigroottree"] == 0:
            self.headertransdict["bigroottree"] = "0 - ptrmap pages disabled"
            if self.headerdict["incvac"] == 0:
                self.headertransdict["incvac"] = "0 - auto_vacuum mode"
            else:
                self.headertransdict["incvac"] = "Invalid mode: %s" % str(self.headerdict["incvac"])
        else:
            self.headertransdict["bigroottree"] = str(self.headerdict["bigroottree"])
            self.headertransdict["incvac"] = "%s - incremental_vacuum mode" % str(self.headerdict["incvac"])
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








