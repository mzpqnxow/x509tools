#!/bin/bash
# Normally, foxconn_sample would be the output of x509dump from a running process
# This is just an example because I no longer have a Windows 7 VM to test on and
# I'm not sure if x509dump it will work on Windows 10. The x509helper tool will
# at least remain useful on any OS so long as you have a directory full of certs
# and keys. It will pair them up and rename them by thumbprint. Dependencies
# to be documented later (or read the source)
./x509helper.py -i ../foxconn_ca/ -o out
