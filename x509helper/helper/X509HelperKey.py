import base64
import os
import textwrap

from Crypto.Util import asn1
import X509Helper
import X509HelperCertificate

import OpenSSL


class X509HelperKey(X509Helper.X509Helper):
    def __init__(self, key_file, blacklist_file=None, logger=None, password='password'):
        X509Helper.X509Helper.__init__(self, logger=logger, blacklist_file=blacklist_file)
        self.key_pem_buffer = None
        self.rsa_key = None
        self.key_private_asn1 = None
        self.key_private_der = None
        self.key_modulus = None
        self.key_public_exponent = None
        self.key_private_exponent = None
        self.key_private_prime1 = None
        self.key_private_prime2 = None
        self.key_private_exponent1 = None
        self.key_private_exponent2 = None
        self.key_private_coefficient = None
        self.key_file = key_file
        self.password = password

        if blacklist_file:
            self.modulus_blacklist_config_path = blacklist_file

        self.subjects = ''

        self.parsed_key = None
        self.parse_key_file_universal()

    def __eq__(self, obj):
        if isinstance(obj, X509HelperCertificate.X509HelperCertificate):
            return (
                (self.key_modulus == obj.certificate_public_modulus) and (
                    obj.certificate_public_exponent == self.key_public_exponent))
        else:
            return False

    def passwd_cb(self):
        self.logger.info('Returning password "{}"'.format(self.password))
        return self.password

    def der_key_to_pem_key(self, der_buffer):
        PEM_HEADER = '-----BEGIN RSA PRIVATE KEY-----'
        PEM_FOOTER = '-----END RSA PRIVATE KEY-----'

        f = str(base64.standard_b64encode(der_buffer))
        return (PEM_HEADER + '\n' + textwrap.fill(f, 64) + '\n' + PEM_FOOTER)

    def write_to_file(self, dirname=''):
        """ also sets self.subject """
        if dirname and not dirname.endswith('/'):
            dirname += '/'

        try:
            os.stat(os.path.join(dirname, self.suggested_filename))
            return ''  # dup, already processed this key
        except (IOError, OSError):
            pass  # file doesn't exist, process this entry

        with open(os.path.join(dirname, self.suggested_filename), 'wb') as filefd:
            # dos2unix and add a trailing newline
            filefd.write(self.key_pem_buffer.replace('\r\n', '\n') + '\n')

        self.subjects = self.suggested_filename.ljust(25) + ' - %d bit RSA Private Key (PEM format)'.format(self.key_bitsize)
        return self.subjects

    def key(self):
        return self.parsed_key

    def parse_key_file_universal(self):
        try:
            self.logger.info('Parsing key {}'.format(self.key_file))
            self.key_buffer = open(self.key_file, 'rb').read()
            self.crypto = OpenSSL.crypto

            try:
                self.logger.warning('Trying to load {} data as PEM...'.format(self.key_file))
                self.rsa_key = self.crypto.load_privatekey(self.crypto.FILETYPE_PEM, self.key_buffer, 'password')
                self.key_pem_buffer = self.key_buffer
            except Exception as err:
                pass

            if not self.rsa_key or not self.key_pem_buffer:
                try:
                    self.logger.warning('Trying to load {} data as DER...'.format(self.key_file))
                    self.rsa_key = self.crypto.load_privatekey(self.crypto.FILETYPE_ASN1, self.key_buffer, 'password')
                    self.key_pem_buffer = self.der_key_to_pem_key(self.key_buffer)
                except Exception as err:
                    self.logger.warning('Failure to parse {} as DER/PEM format key, skipping...'.format(self.key_file))
                    raise(err)

            self.key_bitsize = self.rsa_key.bits()
            self.key_private_asn1 = self.crypto.dump_privatekey(self.crypto.FILETYPE_ASN1, self.rsa_key)
            self.key_private_der = asn1.DerSequence()
            self.key_private_der.decode(self.key_private_asn1)
            self.key_modulus = self.key_private_der[1]
            self.key_printable_private_modulus = self.printable_modulus(self.key_modulus)

            d = self.modulus_long_to_string(self.key_modulus)

            if self.is_blacklisted(d):
                self.logger.info('found blacklisted key...')
                self.parsed_key = None
                return

            self.key_public_exponent = self.key_private_der[2]
            self.key_private_exponent = self.key_private_der[3]
            self.key_private_prime1 = self.key_private_der[4]
            self.key_private_prime2 = self.key_private_der[5]
            self.key_private_exponent1 = self.key_private_der[6]
            self.key_private_exponent2 = self.key_private_der[7]
            self.key_private_coefficient = self.key_private_der[8]

            self.suggested_filename = self.key_printable_private_modulus.replace('\t', '')
            self.suggested_filename = self.suggested_filename[len(
                self.suggested_filename) - (3 * self.FILENAME_OCTETS) + 1:]
            self.suggested_filename += '.key'
            self.suggested_filename = self.suggested_filename.replace(':', '_')
            self.suggested_filename = self.suggested_filename.replace('\r', '')
            self.suggested_filename = self.suggested_filename.replace('\n', '')

            self.parsed_key = {}
            self.parsed_key['public_exponent'] = self.key_public_exponent
            self.parsed_key['private_exponent'] = self.key_private_exponent
            self.parsed_key['private_prime1'] = self.key_private_prime1
            self.parsed_key['private_prime2'] = self.key_private_prime2
            self.parsed_key['private_exponent1'] = self.key_private_exponent1
            self.parsed_key['private_exponent2'] = self.key_private_exponent2
            self.parsed_key['private_coefficient'] = self.key_private_coefficient
            self.parsed_key['key_bitsize'] = self.key_bitsize
            self.parsed_key['suggested_filenmame'] = self.suggested_filename
            self.logger.critical('Success - %d bit RSA Private Key (PEM format)'.format(self.key_bitsize))
            return

        except Exception as err:
            self.parsed_key = None
            self.logger.debug(err)
            self.logger.debug('Exception with {} as an RSA key file, skipping...'.format(self.key_file))
            return
