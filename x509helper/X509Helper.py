from Imports import *

from X509ASN1 import Name,DirectoryString,AttributeType,AttributeTypeAndValue,AttributeValue,MAX,RDNSequence,RelativeDistinguishedName
from Logging import Logging

__id__ = "$Id: X509Helper.py 64 2014-03-19 04:32:43Z user $"

class X509Helper(Logging):
    """ 
    base class for X509HelperCertificate and X509HelperKey
    functions for formatting common fields, etc.
    """
    FILENAME_OCTETS = 6 # when producing suggested_filename, how many bytes of the modules to use in naming
    def __init__(self,logger=None,log_level=logging.CRITICAL,blacklist_file=""):
        self.modulus_blacklist = []
        self.modulus_blacklist_config_path = blacklist_file
        
        if logger == None:
            Logging.__init__(self,log_level)
        else:
            self.logger = logger
        
        self.load_modulus_blacklist()

    def load_modulus_blacklist(self):
        if not self.modulus_blacklist_config_path:
            return
        try:
            f = open(self.modulus_blacklist_config_path,"rb")
            for modulus_line in f.readlines():
                e = modulus_line
                e = e.strip("\n")
                e = e.upper()
                self.modulus_blacklist.append(e)
            f.close()
            self.logger.debug("Added %d items to modulus blacklist..."%(len(self.modulus_blacklist)))
        except Exception,e:
            self.logger.error("Fatal exception occurred while building blacklist...")
            self.logger.error(e)
            sys.exit(10)
            
    def is_blacklisted(self,modulus):
        return modulus.upper() in self.modulus_blacklist    
    
    def printable_modulus(self,der_decimal,columns=16,prefix="\t",use_colons=True):
        modulus = hex(der_decimal).rstrip("L").lstrip("0x")or "0"
        printable_modulus = ""
        for i in xrange(0,len(modulus),2):
            if i:
                if not (i % columns):
                    printable_modulus += "\n" + prefix
                else:
                    if use_colons:
                        printable_modulus += ":"
            else:
                printable_modulus += prefix
            printable_modulus += modulus[i:i+2]
        return printable_modulus
    
    def modulus_long_to_string(self,der_decimal):
        modulus = hex(der_decimal).rstrip("L").lstrip("0x")or "0"
        printable_modulus = ""
        for i in xrange(0,len(modulus),2):
            printable_modulus += modulus[i:i+2]
        return printable_modulus    
    
    def hexdump(self,data, addr=0, prefix="|___ ",width=32, attemptDeflate=False,heading=""):
        dump  = heading
        dump += "\n"
        
        dump  += prefix
        slice = ""
    
        for byte in data:
            if addr % width == 0:
                dump += " "
                for char in slice:
                    if ord(char) >= width and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."
                dump += "\n%s%04x: " % (prefix, addr)
                slice = ""
            dump  += "%02x " % ord(byte)
            slice += byte
            addr  += 1
        remainder = addr % width
        if remainder != 0:
            dump += "   " * (width - remainder) + " "
        for char in slice:
            if ord(char) >= width and ord(char) <= 126:
                dump += char
            else:
                dump += "."
        return dump + "\n"    
