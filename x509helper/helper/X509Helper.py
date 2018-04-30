from helper import Logging
import logging
import sys


class X509Helper(Logging):
    """
    base class for X509HelperCertificate and X509HelperKey
    functions for formatting common fieldsas errtc.
    """
    # when producing suggested_filename, how many bytes of the modules to use in naming
    FILENAME_OCTETS = 6

    def __init__(self, logger=None, log_level=logging.CRITICAL, blacklist_file=''):
        self.modulus_blacklist = []
        self.modulus_blacklist_config_path = blacklist_file

        if logger is None:
            Logging.__init__(self, log_level)
        else:
            self.logger = logger
        self.load_modulus_blacklist()

    def load_modulus_blacklist(self):
        if not self.modulus_blacklist_config_path:
            return
        try:
            f = open(self.modulus_blacklist_config_path, 'rb')
            for modulus_line in f.readlines():
                eline = modulus_line
                eline = eline.strip('\n')
                eline = eline.upper()
                self.modulus_blacklist.append(eline)
            f.close()
            self.logger.debug('Added {} items to modulus blacklist...'.format(len(self.modulus_blacklist)))
        except Exception as err:
            self.logger.error('Fatal exception occurred while building blacklist...')
            self.logger.error(err)
            sys.exit(10)

    def is_blacklisted(self, modulus):
        return modulus.upper() in self.modulus_blacklist

    def printable_modulus(self, der_decimal, columns=16, prefix='\t', use_colons=True):
        modulus = hex(der_decimal).rstrip('L').lstrip('0x')or '0'
        printable_modulus = ''
        for i in xrange(0, len(modulus), 2):
            if i:
                if not (i % columns):
                    printable_modulus += '\n' + prefix
                else:
                    if use_colons:
                        printable_modulus += ':'
            else:
                printable_modulus += prefix
            printable_modulus += modulus[i:i + 2]
        return printable_modulus

    def modulus_long_to_string(self, der_decimal):
        modulus = hex(der_decimal).rstrip('L').lstrip('0x')or '0'
        printable_modulus = ''
        for i in xrange(0, len(modulus), 2):
            printable_modulus += modulus[i:i + 2]
        return printable_modulus
