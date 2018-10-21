#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms

Main interface for parsing, reporting on and sorting X509 certificates and keys
see X509HelperApplication.py for details...


TODO:
 * Deal with name conflict due to windows case insensitivity
 * Deal with uniqifying stuff before file writes

TODO
 * Does it make sense to load the blacklist file in every instantiation of key/cert? it might be slow...
 * Log parsed certs in blacklist format so future runs can ignore known certs
 * Parse as der first in the Key and Certificate classes for efficiency (lots of DER false positives need to be parsed)

"""
import argparse
import logging

from help509.x509helperapplication import X509HelperApplication


def parse_args():
    args = {}
    parser = argparse.ArgumentParser(
        description='sslhelper: make sense out of a directory full of valid and invalid DER and PEM files')

    parser.add_argument(
        '-o', '--output-directory',
        required=True,
        dest='output_directory',
        metavar="output directory",
        type=str,
        help='Directory where unique validated keys and certificates should be written to')
    parser.add_argument(
        '-i', '--input-directory',
        required=True,
        dest='input_directory',
        metavar="input directory",
        type=str,
        help='Directory containing files to examine for valid PEM/DER formatted keys/certificates')
    parser.add_argument(
        '-b',
        '--blacklist-file',
        dest='blacklist_file',
        metavar="blacklist file",
        default="",
        type=str,
        help='Filename of blacklist file which should contain a list of blacklisted modulus\' in openssl -modulus format')
    parser.add_argument(
        '-v', '--verbose',
        dest='verbosity',
        default=0,
        action="count",
        help="Verbosity level for output. Use up to 5 times for full debugging information")
    parser.add_argument(
        '-F',
        '--out-format',
        metavar="output format",
        dest='output_format',
        type=str,
        help='Output format for all validated certificates and keys (NOT IMPLEMENTED - WHY WOULD YOU WANT THIS ARE YOU AN IDIOT?)')

    args = parser.parse_args()

    if not args.output_directory.endswith("/"):
        args.output_directory += "/"

    if not args.input_directory.endswith("/"):
        args.input_directory += "/"

    if args.verbosity > 4:
        args.verbosity = 4
    args.verbosity *= 10
    if args.verbosity:
        args.verbosity = 50 - args.verbosity
    if not args.verbosity:
        args.verbosity = logging.CRITICAL
    return args


def main():
    args = parse_args()
    s = X509HelperApplication(args)
    s.go()


if __name__ == "__main__":
    main()
