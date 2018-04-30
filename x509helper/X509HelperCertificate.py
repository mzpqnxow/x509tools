from Imports import *

from X509ASN1 import Name,DirectoryString,AttributeType,AttributeTypeAndValue,AttributeValue,MAX,RDNSequence,RelativeDistinguishedName
from Logging import Logging
from X509Helper import X509Helper

__id__ = "$Id: X509HelperCertificate.py 64 2014-03-19 04:32:43Z user $"

class X509HelperCertificate(X509Helper):
    def __init__(self,certificate_file,blacklist_file=None,logger=None):
        X509Helper.__init__(self,logger=logger,blacklist_file=blacklist_file)        
        self.certificate_pem_buffer = None
        self.certificate_pubkey_PKey = None
        self.certificate_pubkey_asn1 = None
        self.certificate_pubkey_der = None
        self.certificate_public_modulus = None
        self.certificate_public_exponent = None 
        self.text_subject = ""   
        
        self.subject_dict = {}
        self.certificate_file = certificate_file
        
        self.parsed_certificate = None        
        
        self.parse_certificate_file_universal()
            
    def __eq__(self, obj):
        if isinstance(obj,X509HelperKey):
            return obj.key_modulus == self.certificate_public_modulus and obj.key_public_exponent == self.certificate_public_exponent
        else:
            return False
        
    def OID_tuple_to_string(self,oid_tuple):
        i=0
        s=""
        for v in oid_tuple:
            if i:
                s = s + "."
            i += 1
            s = s + str(v)
        return s
        
    def certificate(self):
        return self.parsed_certificate
        
    def lookup_OID(self,oid_tuple):
        """
        map an OID in tuple form to a symbolic name- we know a few for 
        unknown OIDs, translate the OID to a string and use that a la OpenSSL

        a few universal OIDs and a bunch of Bloomberg specific ones Franko registered @ ISO
        1814 is the Bloomberg enterprise identifier. The numbers after can usually be guessed
        but the I went ahead and put the correct names in after locating the following header
        file in opengrok:
        
        https://code.dev.bloomberg.com/opengrok/xref/robo_svn/trunk/legacy/bbinc/Cinclude/sslplusextraoids.h
        
        """
        lookup = { 
        (2,5,4,10):"O", # Organization - http://www.oid-info.com/get/2.5.4.10
        (0,9,2342,19200300,100,1,1):"uid", # user id - http://www.oid-info.com/get/0.9.2342.19200300.100.1.1
        ###### Bloomberg Internal ###### 
        (1,3,6,1,4,1,1814,3,1,1):"uuid",        
        (1,3,6,1,4,1,1814,3,1,2):"serial",
        (1,3,6,1,4,1,1814,3,1,3):"password",        
        (1,3,6,1,4,1,1814,3,1,4):"user_firm",
        (1,3,6,1,4,1,1814,3,1,5):"real terminal cust",
        (1,3,6,1,4,1,1814,3,1,6):"login_session_subscription_id",
        (1,3,6,1,4,1,1814,3,1,7):"login_session_subscription_id_instance",
        (1,3,6,1,4,1,1814,3,1,8):"login_session_flags_string",
        (1,3,6,1,4,1,1814,3,1,9):"login_session_logical_terminal_subscription_id",
        (1,3,6,1,4,1,1814,3,1,10):"login_session_logical_terminal_subscription_id_instance",
        (1,3,6,1,4,1,1814,3,1,11):"login_session_secure_proxy_luw_string",
        (1,3,6,1,4,1,1814,3,1,12):"login_session_secure_proxy_luw_string",
        (1,3,6,1,4,1,1814,3,1,13):"login_session_real_terminal_firm_number",
        (1,3,6,1,4,1,1814,3,1,14):"login_session_user_customer_number",
        (1,3,6,1,4,1,1814,3,1,15):"terminal_master_tuid",
        (1,3,6,1,4,1,1814,3,1,16):"dual_primary_tuid",
        (1,3,6,1,4,1,1814,3,1,17):"dual_primary_serial"
        }
        
        if lookup.has_key(oid_tuple):
            name = lookup[oid_tuple] # some fields are known
        else:
            name = self.OID_tuple_to_string(oid_tuple) # just return the raw OID as a string
        return name
        
    def handle_custom_oids(self):
        """
        process self.subject (asn1/der) in order to produce a subject string for humans to read
        this is called for non-standard Sybject strings, especially the ones
        created by Bloomberg where custom OID extensions were placed into the
        Subject field.
        
        OpenSSL native can parse this fine, but python bindings can't, they assign the subject a field named 'UNDEF'
        it is OK if this function fails, it is just best effort to improve the 'UNDEF' description...
        
        this happens with at least the HFN cert, and a few others...
        """
        certType = Name()                    
        derData = self.subject.der()
        cert, rest = decode(derData,asn1Spec=certType)

        try:
            subject = ""
            extensions = cert.getComponentByPosition(0)     
            i=0
            while True:
                pair = extensions.getComponentByPosition(i)
                pair = pair.getComponentByPosition(0)
                name = pair.getComponentByPosition(0).asTuple()
                value = pair.getComponentByPosition(1).getComponent()
                
                name = self.lookup_OID(name)
                if i:
                    subject += "/"
                subject += "%s=%s"%(name,value)
                i = i + 1
        except Exception,e:
            self.logger.debug("expected exception, ignoring...")
            self.logger.debug(e)
        
        return subject
  
    def write_to_file(self,dirname=""):
        """ also sets self.summary """
        if dirname and not dirname.endswith("/"):
            dirname += "/"          
        
        try:
            os.stat(dirname+self.suggested_filename)
            return "" # dup, already processed this key
        except:
            pass # file doesn't exist, process this entry
            
        f = open(dirname+self.suggested_filename,"wb")
        f.write(self.certificate_pem_buffer.replace("\r\n","\n")+"\n") # dos2unix and add a trailing newline
        f.close() 
        
        self.summary = self.suggested_filename.ljust(25) + " - " + self.text_subject
        return self.summary
            
    def parse_subject_components(self):
        s = {}
        for c in self.subject_components:
            s[c[0]] = c[1]
        self.subject_components = s
                        
        if self.subject_components.has_key('UNDEF'):
            try:
                self.text_subject += self.handle_custom_oids()
            except Exception,e:
                self.logger.error("unexpected exception in handle_custom_oids!")
                self.text_subject += "UNDEF=0"
            
        else:
            for key in self.subject_components:
                self.text_subject += key + "=" + self.subject_components[key] + "/"
        return
            
    def get_subject_field(self,field):
        if self.subject_components.has_key(field):
            return self.subject_components[field]
        else:
            return None
        
    def der_cert_to_pem_cert(self,der_buffer):
        """
        Takes a certificate in binary DER format and returns the
        PEM version of it as a string.
        """        
        PEM_HEADER = "-----BEGIN CERTIFICATE-----"
        PEM_FOOTER = "-----END CERTIFICATE-----"
        f = str(base64.standard_b64encode(der_buffer))
        return (PEM_HEADER + '\n' +
                textwrap.fill(f, 64) + '\n' +
                PEM_FOOTER)        

    def parse_certificate_file_universal(self):
        try:
            self.logger.warning("OK, trying to process certificate file %s..."%(self.certificate_file))
            self.c = OpenSSL.crypto             
            self.certificate_buffer = open(self.certificate_file, "rb").read()
                        
            try: # assume it is PEM first
                self.x509_certificate = self.c.load_certificate(self.c.FILETYPE_PEM, self.certificate_buffer)
                self.certificate_pem_buffer = self.certificate_buffer
            except Exception,e: # not PEM, try to treat it as DER
                self.x509_certificate = None
                self.certificate_der_buffer = self.certificate_buffer
                self.certificate_pem_buffer = self.der_cert_to_pem_cert(self.certificate_der_buffer)
                        
            if not self.x509_certificate:
                self.x509_certificate = self.c.load_certificate(self.c.FILETYPE_PEM, self.certificate_pem_buffer) 
            
            self.certificate_pubkey_PKey = self.x509_certificate.get_pubkey() 
            
            self.subject = self.x509_certificate.get_subject()            
            self.subject_components = self.subject.get_components()
            
                        
            self.certificate_pubkey_asn1 = self.c.dump_privatekey(self.c.FILETYPE_ASN1, self.certificate_pubkey_PKey)
            self.certificate_pubkey_der=asn1.DerSequence()
            self.certificate_pubkey_der.decode(self.certificate_pubkey_asn1)
            self.certificate_public_modulus = self.certificate_pubkey_der[1]
            self.certificate_key_bitsize = self.certificate_public_modulus.bit_length()
            
            d = self.modulus_long_to_string(self.certificate_public_modulus)
            
            if self.is_blacklisted(d):
                self.logger.info("found blacklisted certificate...")                
                return
            
            self.certificate_printable_public_modulus = self.printable_modulus(self.certificate_pubkey_der[1])
            self.certificate_public_exponent = self.certificate_pubkey_der[2] 
            
            self.suggested_filename = self.certificate_printable_public_modulus.replace("\t","")
            self.suggested_filename = self.suggested_filename[len(self.suggested_filename)-(3*self.FILENAME_OCTETS)+1:]
            self.suggested_filename += ".cert" 
            self.suggested_filename = self.suggested_filename.replace(":","_")   
            self.suggested_filename = self.suggested_filename.replace("\r","")      
            self.suggested_filename = self.suggested_filename.replace("\n","")      
            
            
            self.parse_subject_components()   
                        
            self.parsed_certificate = {}
            self.parsed_certificate['key_bitsize'] = self.certificate_key_bitsize
            self.parsed_certificate['public_modulus'] = self.certificate_public_modulus
            self.parsed_certificate['text_subject'] = self.text_subject
            self.parsed_certificate['suggested_filename'] = self.suggested_filename

            self.logger.critical("Success - %s"%(self.text_subject))
            
            return
        
        except Exception,e:
            self.logger.warning(e)
            self.logger.warning( "Failure to parse %s as DER/PEM format certificate, skipping..."%(self.certificate_file))
            return
