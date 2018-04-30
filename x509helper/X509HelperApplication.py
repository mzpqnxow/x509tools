from Imports import *

from X509ASN1 import Name,DirectoryString,AttributeType,AttributeTypeAndValue,AttributeValue,MAX,RDNSequence,RelativeDistinguishedName

from Logging import Logging

from X509HelperCertificate import X509HelperCertificate
from X509HelperKey import X509HelperKey

__id__ = "$Id: X509HelperApplication.py 57 2014-03-19 03:26:46Z user $"

class X509HelperApplication(Logging):
    """
    custom driver for the X509HelperCertificate and X509HelperKey classes
    """
    SPINNER_SYMBOLS = "|/-\\"
    SPINNER_SPEED_DELAY = 0 # no delay
    
    def __init__(self,args,logger=None):
        self.args = args
        self.blacklist_file = self.args.blacklist_file
        self.input_directory = self.args.input_directory
        self.output_directory = self.args.output_directory
        self.verbosity = self.args.verbosity
        self.log_level = self.verbosity 
        
        self.found_keys = []
        self.found_certificates = []  
        
        self.spinner_speed_status=0
        self.spinner_status=0
        
        if logger == None:
            Logging.__init__(self,self.log_level)
        else:
            self.logger = logger
            
        self.validate_create_writable_directory_or_die(self.args.output_directory)
        self.validate_readable_directory_or_die(self.args.input_directory)
            
    def create_directory_or_die(self,directory):
        try:
            os.mkdir(directory)
            self.logger.critical("Success - created output directory '%s'"%(directory))
            return
        except OSError,e:
            self.logger.critical("Exception - mkdir")
            self.logger.critical(e)
            self.fatal("exiting...")
    
    def validate_create_writable_directory_or_die(self,directory):
        self.logger.debug("validating output directory")
        try:
            mode = os.stat(directory).st_mode
            if stat.S_ISDIR(mode):
                if not os.access(directory,os.W_OK):
                    self.logger.critical("Error - output directory '%s' is not writable by user"%(directory))
                    self.fatal("exiting...")
            else:
                self.logger.critical("Error - user specified '%s' for output directory but it isn't a directory"%(directory))
                self.fatal("exiting...")
        except OSError,e:
            if e.errno == errno.ENOENT:
                self.logger.critical("Exception - output directory '%s' doesn't exist"%(directory))
                try:
                    print ""
                    print ""
                    raw_input("Press enter to create the directory now, control-c to abort...")
                    print ""
                except KeyboardInterrupt,e:
                    print ""
                    self.fatal("exiting...")
                return self.create_directory_or_die(directory)
            else:
                self.logger.critical("Exception - general error")
                self.logger.critical(e)
                self.fatal("exiting...")    
    
    def validate_readable_directory_or_die(self,directory):
        self.logger.debug("validating input directory")
        try:
            mode = os.stat(directory).st_mode
            if stat.S_ISDIR(mode):
                if not os.access(directory,os.R_OK):
                    self.logger.critical("Error - output directory '%s' is not writable by user"%(directory))
                    self.fatal("exiting...")
            else:
                self.logger.critical("Error - user specified '%s' for input directory but it isn't a directory"%(directory))
                self.fatal("exiting...")
        except Exception,e:
            if e.errno == errno.ENOENT:
                self.logger.critical("Exception - input directory '%s' doesn't exist"%(directory))
            else:
                self.logger.critical("Exception - input directory '%s general error"%(directory))
                self.logger.critical(e)
            self.fatal("exiting...")        

    
    def try_cert(self,filename,blacklist_file,logger):
        self.logger.debug("trying %s as a certificate..."%(filename))
        cert = X509HelperCertificate(filename,blacklist_file=blacklist_file,logger=logger)            
        parsed_cert = cert.certificate()
        if parsed_cert:
            self.found_certificates.append(cert)
            return True
        else:
            return False
        
    def try_key(self,filename,blacklist_file,logger):
        self.logger.debug("trying %s as a key..."%(filename))        
        key = X509HelperKey(filename,blacklist_file=blacklist_file,logger=logger)            
        parsed_key = key.key()
        if parsed_key:
            self.found_keys.append(key)
            return True
        else:
            return False

    def spinner(self):
        self.spinner_speed_status += 1
        
        if self.spinner_speed_status < self.SPINNER_SPEED_DELAY:
            return
        
        self.spinner_speed_status = 0
        
        self.spinner_status += 1
        self.spinner_status = self.spinner_status % len(self.SPINNER_SYMBOLS)
        
        sys.stdout.write("\r[%c] %.4d/%.4d files processed ... P A R S I N G ..."%(self.SPINNER_SYMBOLS[self.spinner_status],self.total_input_files_processed,self.total_input_files))
        
        sys.stdout.flush() 
    
    def go(self):     
        directory_listing = os.listdir(self.input_directory)
        self.total_input_files = len(directory_listing)
        self.total_input_files_processed = 0
        
        for f in directory_listing:
            self.spinner()
            self.total_input_files_processed += 1
            self.logger.debug("processing %s"%(f))
            f = self.input_directory + f
            
            if self.try_cert(f,self.blacklist_file,self.logger): continue
            else: self.try_key(f,self.blacklist_file,self.logger)

        
        print ""
        print "DONE scanning '%s' for PEM format keys/certificates!"%(self.input_directory)
        print "Found %d keys, %d certificates!"%(len(self.found_keys),len(self.found_certificates))
        print ""
        
        report = ""
                
        for a in self.found_keys:
            report_line = a.write_to_file(dirname=self.output_directory)
            if report_line:
                report += report_line + "\n"
            
        for a in self.found_certificates:
            report_line = a.write_to_file(dirname=self.output_directory)
            if report_line:
                report += report_line + "\n"
        
        print ""
        print "List of certificates and keys discovered. Name consists of last 6 bytes of modulus."
        print "Sorted by filename for easy identification of matched key/certificate pairs."
        print ""
        r = report.split("\n")
        r.sort()    
        print "\n".join(r)    
