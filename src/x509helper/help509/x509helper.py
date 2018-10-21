#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2011-2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms
"""
from Crypto.Util import asn1
import base64
import OpenSSL
import os
import textwrap
import logging
import sys
from logger import LoggingMixin


class X509Helper(LoggingMixin):
    """
    base class for X509HelperCertificate and X509HelperKey
    functions for formatting common fieldsas errtc.
    """
    # when producing suggested_filename, how many bytes of the modules to use
    # in naming
    FILENAME_OCTETS = 6

    def __init__(
            self,
            logger=None,
            log_level=logging.CRITICAL,
            blacklist_file=''):
        self.modulus_blacklist = []
        self.modulus_blacklist_config_path = blacklist_file

        if logger is None:
            LoggingMixin.__init__(self, log_level=log_level)
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
            self.logger.debug('Added {} items to modulus blacklist...'.format(
                len(self.modulus_blacklist)))
        except Exception as err:
            self.logger.error(
                'Fatal exception occurred while building blacklist...')
            self.logger.error(err)
            sys.exit(10)

    def is_blacklisted(self, modulus):
        return modulus.upper() in self.modulus_blacklist

    def printable_modulus(
            self,
            der_decimal,
            columns=16,
            prefix='\t',
            use_colons=True):
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


class X509HelperKey(X509Helper):
    def __init__(
            self,
            key_file,
            blacklist_file=None,
            logger=None,
            password='password'):
        X509Helper.__init__(
            self, logger=logger, blacklist_file=blacklist_file)
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
        if isinstance(obj, X509HelperCertificate):
            return ((self.key_modulus == obj.certificate_public_modulus) and (
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

        self.subjects = self.suggested_filename.ljust(
            25) + ' - %d bit RSA Private Key (PEM format)'.format(self.key_bitsize)
        return self.subjects

    def key(self):
        return self.parsed_key

    def parse_key_file_universal(self):
        try:
            self.logger.info('Parsing key {}'.format(self.key_file))
            self.key_buffer = open(self.key_file, 'rb').read()
            self.crypto = OpenSSL.crypto

            try:
                self.logger.warning(
                    'Trying to load {} data as PEM...'.format(
                        self.key_file))
                self.rsa_key = self.crypto.load_privatekey(
                    self.crypto.FILETYPE_PEM, self.key_buffer, 'password')
                self.key_pem_buffer = self.key_buffer
            except Exception as err:
                pass

            if not self.rsa_key or not self.key_pem_buffer:
                try:
                    self.logger.warning(
                        'Trying to load {} data as DER...'.format(
                            self.key_file))
                    self.rsa_key = self.crypto.load_privatekey(
                        self.crypto.FILETYPE_ASN1, self.key_buffer, 'password')
                    self.key_pem_buffer = self.der_key_to_pem_key(
                        self.key_buffer)
                except Exception as err:
                    self.logger.warning(
                        'Failure to parse {} as DER/PEM format key, skipping...'.format(self.key_file))
                    raise(err)

            self.key_bitsize = self.rsa_key.bits()
            self.key_private_asn1 = self.crypto.dump_privatekey(
                self.crypto.FILETYPE_ASN1, self.rsa_key)
            self.key_private_der = asn1.DerSequence()
            self.key_private_der.decode(self.key_private_asn1)
            self.key_modulus = self.key_private_der[1]
            self.key_printable_private_modulus = self.printable_modulus(
                self.key_modulus)

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

            self.suggested_filename = self.key_printable_private_modulus.replace(
                '\t', '')
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
            self.logger.critical(
                'Success - %d bit RSA Private Key (PEM format)'.format(self.key_bitsize))
            return

        except Exception as err:
            self.parsed_key = None
            self.logger.debug(err)
            self.logger.debug(
                'Exception with {} as an RSA key file, skipping...'.format(
                    self.key_file))
            return


class X509HelperCertificate(X509Helper):
    def __init__(self, certificate_file, blacklist_file=None, logger=None):
        X509Helper.__init__(self, logger=logger, blacklist_file=blacklist_file)
        self.certificate_pem_buffer = None
        self.certificate_pubkey_PKey = None
        self.certificate_pubkey_asn1 = None
        self.certificate_pubkey_der = None
        self.certificate_public_modulus = None
        self.certificate_public_exponent = None
        self.text_subject = ''
        self.subject_dict = {}
        self.certificate_file = certificate_file
        self.parsed_certificate = None
        self.parse_certificate_file_universal()

    def __eq__(self, obj):
        if isinstance(obj, X509HelperKey):
            return (obj.key_modulus == self.certificate_public_modulus) and (
                obj.key_public_exponent == self.certificate_public_exponent)
        else:
            return False

    def OID_tuple_to_string(self, oid_tuple):
        i = 0
        s = ''
        for v in oid_tuple:
            if i:
                s = s + '.'
            i += 1
            s = s + str(v)
        return s

    def certificate(self):
        return self.parsed_certificate

    def lookup_OID(self, oid_tuple):
        """Map an OID in tuple form to a symbolic name

        We know a few for unknown OIDs, translate the OID to a string and use that
        a la OpenSSL

        Fill these in yourself if you want, the documentation is listed in the comments
        """
        lookup = {
            # Organization - http://www.oid-info.com/get/2.5.4.10
            # http://www.oid-info.com/get/0.9.2342.19200300.100.1.1
            (2, ): 'ISO/ITU-T',
            (2, 5): 'X.500 Directory Services',
            (2, 5, 4): 'X.500 Attribute Types',
            (2, 5, 4, 0): 'id-at-objectClass',
            (2, 5, 4, 1): 'id-at-aliasedEntryName',
            (2, 5, 4, 2): 'id-at-knowldgeinformation',
            (2, 5, 4, 3): 'id-at-commonName',
            (2, 5, 4, 4): 'id-at-surname',
            (2, 5, 4, 5): 'id-at-serialNumber',
            (2, 5, 4, 6): 'id-at-countryName',
            (2, 5, 4, 7): 'id-at-localityName',
            (2, 5, 4, 8): 'id-at-stateOrProvinceName',
            (2, 5, 4, 9): 'id-at-streetAddress',
            (2, 5, 4, 10): 'id-at-organizationName',
            (2, 5, 4, 11): 'id-at-organizationalUnitName',
            (2, 5, 4, 12): 'id-at-title',
            (2, 5, 4, 13): 'id-at-description',
            (2, 5, 4, 14): 'id-at-searchGuide',
            (2, 5, 4, 15): 'id-at-businessCategory',
            (2, 5, 4, 16): 'id-at-postalAddress',
            (2, 5, 4, 17): 'id-at-postalCode',
            (2, 5, 4, 18): 'id-at-postOfficeBox',
            (2, 5, 4, 19): 'id-at-physicalDeliveryOfficeName',
            (2, 5, 4, 20): 'id-at-telephoneNumber',
            (2, 5, 4, 21): 'id-at-telexNumber',
            (2, 5, 4, 22): 'id-at-teletexTerminalIdentifier',
            (2, 5, 4, 23): 'id-at-facsimileTelephoneNumber',
            (2, 5, 4, 24): 'id-at-x121Address',
            (2, 5, 4, 25): 'id-at-internationalISDNNumber',
            (2, 5, 4, 26): 'id-at-registeredAddress',
            (2, 5, 4, 27): 'id-at-destinationIndicator',
            (2, 5, 4, 28): 'id-at-preferredDeliveryMethod',
            (2, 5, 4, 29): 'id-at-presentationAddress',
            (2, 5, 4, 30): 'id-at-supportedApplicationContext',
            (2, 5, 4, 31): 'id-at-member',
            (2, 5, 4, 32): 'id-at-owner',
            (2, 5, 4, 33): 'id-at-roleOccupant',
            (2, 5, 4, 34): 'id-at-seeAlso',
            (2, 5, 4, 35): 'id-at-userPassword',
            (2, 5, 4, 36): 'id-at-userCertificate',
            (2, 5, 4, 37): 'id-at-cACertificate',
            (2, 5, 4, 38): 'id-at-authorityRevocationList',
            (2, 5, 4, 39): 'id-at-certificateRevocationList',
            (2, 5, 4, 40): 'id-at-crossCertificatePair',
            (2, 5, 4, 41): 'id-at-name',
            (2, 5, 4, 42): 'id-at-givenName',
            (2, 5, 4, 43): 'id-at-initials',
            (2, 5, 4, 44): 'id-at-generationQualifier',
            (2, 5, 4, 45): 'id-at-uniqueIdentifier',
            (2, 5, 4, 46): 'id-at-dnQualifier',
            (2, 5, 4, 47): 'id-at-enhancedSearchGuide',
            (2, 5, 4, 48): 'id-at-protocolInformation',
            (2, 5, 4, 49): 'id-at-distinguishedName',
            (2, 5, 4, 50): 'id-at-uniqueMember',
            (2, 5, 4, 51): 'id-at-houseIdentifier',
            (2, 5, 4, 52): 'id-at-supportedAlgorithms',
            (2, 5, 4, 53): 'id-at-deltaRevocationList',
            (2, 5, 4, 58): 'Attribute Certificate attribute (id-at-attributeCertificate)',
            (2, 5, 4, 65): 'id-at-pseudonym'}

        return lookup.get(oid_tuple, self.OID_tuple_to_string(oid_tuple))

    def handle_custom_oids(self):
        """
        process self.subject (asn1/der) in order to produce a subject string for humans to read
        this is called for non-standard Sybject stringsas errspecially the custom OIDs

        OpenSSL native can parse this fine, but python bindings can't, they assign the subject a
        field named 'UNDEF' it is OK if this function fails, it is just best effort to improve
        the 'UNDEF' description...
        """
        certType = Name()
        derData = self.subject.der()
        cert, rest = asn1.codec.der.decoder(derData, asn1spec=certType)

        try:
            subject = ''
            extensions = cert.getComponentByPosition(0)
            i = 0
            while True:
                pair = extensions.getComponentByPosition(i)
                pair = pair.getComponentByPosition(0)
                name = pair.getComponentByPosition(0).asTuple()
                value = pair.getComponentByPosition(1).getComponent()

                name = self.lookup_OID(name)
                if i != 0:
                    subject += '/'
                subject += '{}={}'.format(name, value)
                i += 1
        except Exception as err:
            self.logger.debug('expected exception, ignoring...')
            self.logger.debug(err)

        return subject

    def write_to_file(self, dirname=''):
        """ also sets self.summary """
        if dirname and not dirname.endswith('/'):
            dirname += '/'

        try:
            os.stat(os.path.join(dirname, self.suggested_filename))
            return ''  # dup, already processed this key
        except (IOError, OSError):
            pass  # file doesn't exist, process this entry

        with open(os.path.join(dirname, self.suggested_filename), 'wb') as filefd:
            # dos2unix and add a trailing newline
            filefd.write(
                self.certificate_pem_buffer.replace(
                    '\r\n', '\n') + '\n')

        self.summary = self.suggested_filename.ljust(
            25) + ' - ' + self.text_subject
        return self.summary

    def parse_subject_components(self):
        s = {}
        for c in self.subject_components:
            s[c[0]] = c[1]
        self.subject_components = s

        if 'UNDEF' in self.subject_components:
            try:
                self.text_subject += self.handle_custom_oids()
            except Exception:
                self.logger.error(
                    'unexpected exception in handle_custom_oids!')
                self.text_subject += 'UNDEF=0'

        else:
            for key in self.subject_components:
                self.text_subject += key + '=' + \
                    self.subject_components[key] + '/'
        return

    def get_subject_field(self, field):
        if field in self.subject_components:
            return self.subject_components[field]
        else:
            return None

    def der_cert_to_pem_cert(self, der_buffer):
        """
        Takes a certificate in binary DER format and returns the
        PEM version of it as a string.
        """
        PEM_HEADER = '-----BEGIN CERTIFICATE-----'
        PEM_FOOTER = '-----END CERTIFICATE-----'
        b64 = str(base64.standard_b64encode(der_buffer))
        return (PEM_HEADER + '\n' + textwrap.fill(b64, 64) + '\n' + PEM_FOOTER)

    def parse_certificate_file_universal(self):
        try:
            self.logger.warning(
                'OK, trying to process certificate file %s...'.format(
                    self.certificate_file))
            self.c = OpenSSL.crypto
            self.certificate_buffer = open(
                self.certificate_file,
                'rb').read()

            try:  # assume it is PEM first
                self.x509_certificate = self.c.load_certificate(
                    self.c.FILETYPE_PEM,
                    self.certificate_buffer)
                self.certificate_pem_buffer = self.certificate_buffer
            except Exception as err:  # not PEM, try to treat it as DER
                self.x509_certificate = None
                self.certificate_der_buffer = self.certificate_buffer
                self.certificate_pem_buffer = self.der_cert_to_pem_cert(
                    self.certificate_der_buffer)

            if not self.x509_certificate:
                self.x509_certificate = self.c.load_certificate(
                    self.c.FILETYPE_PEM,
                    self.certificate_pem_buffer)

            self.certificate_pubkey_PKey = self.x509_certificate.get_pubkey()
            self.subject = self.x509_certificate.get_subject()
            self.subject_components = self.subject.get_components()
            self.certificate_pubkey_asn1 = self.c.dump_privatekey(
                self.c.FILETYPE_ASN1,
                self.certificate_pubkey_PKey)
            self.certificate_pubkey_der = asn1.DerSequence()
            self.certificate_pubkey_der.decode(self.certificate_pubkey_asn1)
            self.certificate_public_modulus = self.certificate_pubkey_der[1]
            self.certificate_key_bitsize = self.certificate_public_modulus.bit_length()

            d = self.modulus_long_to_string(self.certificate_public_modulus)

            if self.is_blacklisted(d):
                self.logger.info('found blacklisted certificate...')
                return

            self.certificate_printable_public_modulus = self.printable_modulus(
                self.certificate_pubkey_der[1])
            self.certificate_public_exponent = self.certificate_pubkey_der[2]

            self.suggested_filename = self.certificate_printable_public_modulus.replace(
                '\t', '')
            self.suggested_filename = self.suggested_filename[len(
                self.suggested_filename) - (3 * self.FILENAME_OCTETS) + 1:]
            self.suggested_filename += '.cert'
            self.suggested_filename = self.suggested_filename.replace(':', '_')
            self.suggested_filename = self.suggested_filename.replace('\r', '')
            self.suggested_filename = self.suggested_filename.replace('\n', '')
            self.parse_subject_components()
            self.parsed_certificate = {}
            self.parsed_certificate['key_bitsize'] = self.certificate_key_bitsize
            self.parsed_certificate['public_modulus'] = self.certificate_public_modulus
            self.parsed_certificate['text_subject'] = self.text_subject
            self.parsed_certificate['suggested_filename'] = self.suggested_filename
            self.logger.critical('Success - %s', self.text_subject)
            return

        except Exception as err:
            self.logger.warning(err)
            self.logger.warning(
                'Failure to parse {} as DER/PEM format certificate, skipping...'.format(
                    self.certificate_file))
            return
