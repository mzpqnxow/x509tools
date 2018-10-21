#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2011-2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms
"""
import errno
import os
import stat
import sys

from logger import LoggingMixin
from x509helper import X509HelperKey, X509HelperCertificate


class X509HelperApplication(LoggingMixin):
    """
    custom driver for the X509HelperCertificate and X509HelperKey classes
    """
    SPINNER_SYMBOLS = '|/-\\'
    SPINNER_SPEED_DELAY = 0  # no delay

    def __init__(self, args, logger=None):
        self.args = args
        self.blacklist_file = self.args.blacklist_file
        self.input_directory = self.args.input_directory
        self.output_directory = self.args.output_directory
        self.verbosity = self.args.verbosity
        self.log_level = self.verbosity

        self.found_keys = []
        self.found_certificates = []

        self.spinner_speed_status = 0
        self.spinner_status = 0

        if logger is None:
            LoggingMixin.__init__(self, self.log_level)
        else:
            self.logger = logger

        self.validate_create_writable_directory_or_die(
            self.args.output_directory)
        self.validate_readable_directory_or_die(self.args.input_directory)

    def create_directory_or_die(self, directory):
        try:
            os.mkdir(directory)
            self.logger.critical(
                'Success - created output directory "{}"'.format(directory))
            return
        except OSError as err:
            self.logger.critical('Exception - mkdir')
            self.logger.critical(err)
            self.fatal('exiting...')

    def validate_create_writable_directory_or_die(self, directory):
        self.logger.debug('validating output directory')
        try:
            mode = os.stat(directory).st_mode
            if stat.S_ISDIR(mode):
                if not os.access(directory, os.W_OK):
                    self.logger.critical(
                        'Error - output directory "{}" is not writable by user'.format(directory))
                    self.fatal('exiting...')
            else:
                self.logger.critical(
                    'Error - user specified "{}" for output directory but it is not a directory'.format(directory))
                self.fatal('exiting...')
        except OSError as err:
            if err.errno == errno.ENOENT:
                self.logger.critical(
                    'Exception - output directory "{}" does not exist'.format(directory))
                try:
                    print('')
                    print('')
                    raw_input(
                        'Press enter to create the directory now, control-c to abort...')
                    print('')
                except KeyboardInterrupt as err:
                    print('')
                    self.fatal('exiting...')
                return self.create_directory_or_die(directory)
            else:
                self.logger.critical('Exception - general error')
                self.logger.critical(err)
                self.fatal('exiting...')

    def validate_readable_directory_or_die(self, directory):
        self.logger.debug('validating input directory')
        try:
            mode = os.stat(directory).st_mode
            if stat.S_ISDIR(mode):
                if not os.access(directory, os.R_OK):
                    self.logger.critical(
                        'Error - output directory "{}" is not writable by user'.format(directory))
                    self.fatal('exiting...')
            else:
                self.logger.critical(
                    'Error - user specified "{}" for input directory but it is not a directory'.format(directory))
                self.fatal('exiting...')
        except Exception as err:
            if err.errno == errno.ENOENT:
                self.logger.critical(
                    'Exception - input directory "{}" does not exist'.format(directory))
            else:
                self.logger.critical(
                    'Exception - input directory "{}" general error'.format(directory))
                self.logger.critical(err)
            self.fatal('exiting...')

    def try_cert(self, filename, blacklist_file, logger):
        self.logger.debug('trying {} as a certificate...'.format(filename))
        cert = X509HelperCertificate(
            filename, blacklist_file=blacklist_file, logger=logger)
        parsed_cert = cert.certificate()
        if parsed_cert:
            self.found_certificates.append(cert)
            return True
        else:
            return False

    def try_key(self, filename, blacklist_file, logger):
        self.logger.debug('trying {} as a key...'.format(filename))
        key = X509HelperKey(
            filename,
            blacklist_file=blacklist_file,
            logger=logger)
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
        self.spinner_status = self.spinner_status % (len(self.SPINNER_SYMBOLS))
        sys.stdout.write(
            '\r[.formatc] .format.4d/.format.4d files processed ... P A R S I N G ...'.format(
                self.SPINNER_SYMBOLS[self.spinner_status],
                self.total_input_files_processed,
                self.total_input_files))
        sys.stdout.flush()

    def go(self):
        directory_listing = os.listdir(self.input_directory)
        self.total_input_files = len(directory_listing)
        self.total_input_files_processed = 0

        for file in directory_listing:
            self.spinner()
            self.total_input_files_processed += 1
            self.logger.debug('processing {}'.format(file))
            file = self.input_directory + file
            if self.try_cert(file, self.blacklist_file, self.logger):
                continue
            else:
                self.try_key(file, self.blacklist_file, self.logger)
        print('')
        print('DONE scanning "{}" for PEM format keys/certificates!'.format(self.input_directory))
        print('Found {} keys, {} certificates!'.format(
            len(self.found_keys), len(self.found_certificates)))
        print('')

        report = ''

        for key in self.found_keys:
            report_line = key.write_to_file(dirname=self.output_directory)
            if report_line:
                report += report_line + '\n'

        for cert in self.found_certificates:
            report_line = cert.write_to_file(dirname=self.output_directory)
            if report_line:
                report += report_line + '\n'

        print('')
        print('List of certificates and keys discovered. Name consists of last 6 bytes of modulus.')
        print(
            'Sorted by filename for easy identification of matched key/certificate pairs.')
        print('')
        r = report.split('\n')
        r.sort()
        print('\n'.join(r))
