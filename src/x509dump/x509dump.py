#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms

Main interface for scraping memory and identify certificates and keys in the following
formats:

1. DERP
2. PEM

PEM is easy. DER is pretty easy. BIGNUM was added, but the branch was lost. So no bignum/OpenSSL
native structure support. Add it yourself.
"""
from __future__ import print_function
import argparse
import errno
import logging
import os
import platform
import re
import stat
import struct
import sys
from winappdbg import win32


class Win32MemoryScraper(object):
    """Yeah, it is hacky, but there's enough validation that there aren't many
       false positives. If there are, x509helper.py will pick them up and eliminate
       them
    """
    DER_START_FINGERPRINT = "\x30\x82"
    DER_KEY_FINGERPRINT = "\x02\x01\x00"
    DER_CERT_FINGERPRINT = "\x30\x82"
    SPINNER_SYMBOLS = "|/-\\"
    SPINNER_SPEED_DELAY = 1000

    def __init__(self):
        """ Really asinine logging """
        self.logger = logging.getLogger(self.__class__.__name__)
        hlen = len(self.logger.handlers)
        if not hlen:
            self.stdout_log_handler = logging.StreamHandler(sys.stderr)
            formatter = logging.Formatter("\r%(funcName)s() - %(message)s")
            self.stdout_log_handler.setFormatter(formatter)
            logging.getLogger(
                self.__class__.__name__).addHandler(
                self.stdout_log_handler)
            self.logger = logging.getLogger(self.__class__.__name__)
            self.log_level = logging.ERROR
            self.logger.setLevel(self.log_level)

        if platform.system() != "Windows" or platform.release() != "7":
            self.logger.critical(
                'Error - Win32MemoryScraper class only tested/supported on Windows 7!')
            self.logger.critical(
                'Error - your platform is %s (%s)' %
                (platform.system(), platform.release()))
            self.fatal('exiting...')
        self.spinner_status = 0
        self.spinner_speed_status = 0
        self.spinner_visibile = False
        self.addr_max = 0x7ffffffc
        self.addr_min = 0x0
        self.curr_addr = 0x0
        self.args = None
        self.spinner_visible = False

    def regex_search_for_der(self, mbuf, base, output_directory):
        # we parse using some fuzzy assumptions that usually work out just fine
        # but these need to be validated at some point after they are dumped
        #  30 82 XX XX 02 01 00 - beginning of DER encoded key, XXXX is the length of the stream
        #  30 82 XX XX 30 82 - beginning of DER encoded cert, XXXX is the length of the stream
        # Sadly, bignum format is not currently supported, though it seems to be relatively
        # rare compared with PEM and DER (based on experience)
        match = "(?P<der_data>"
        match += br"\x30\x82"
        match += "(?P<der_len>"
        match += ".{2})"
        match += br"(?P<der_type>\x02\x01\x00|\x30\x82))"
        patt = re.compile(match, re.DOTALL)
        for f_iter in patt.finditer(mbuf):
            out_filename = hex(
                base + f_iter.start(0)).strip("L").lstrip("0x") + "-der"
            if f_iter.group('der_type') == self.DER_KEY_FINGERPRINT:
                self.logger.critical("dumping DER key".ljust(32))
                out_filename += ".key"
            elif f_iter.group('der_type') == self.DER_CERT_FINGERPRINT:
                self.logger.critical("dumping DER certificate".ljust(32))
                out_filename += ".cert"
            else:
                self.logger.critical("unexpected regex match".ljust(32))
                self.fatal("exiting...")

            _, der_len = f_iter.group('der_data'), f_iter.group('der_len')
            der_len = struct.unpack("!H", der_len)[0]
            der_len += 4
            der_buf = mbuf[f_iter.start(0):f_iter.start(0) + der_len]

            try:
                filefd = None
                filefd = open(output_directory + out_filename, "wb")
            except Exception as err:
                self.logger.critical(
                    'Exception - open({})'.format(output_directory + out_filename))
                self.logger.critical(err)
                self.fatal('exiting...')
            finally:
                if filefd is not None:
                    filefd.write(der_buf)
                    filefd.close()
        return

    def regex_search_for_pem(self, mbuf, base, output_directory):
        match = '(?P<pem_data>'
        match += r'-{5}BEGIN (?P<pem_data_type>\bPRIVATE KEY\b|\b'
        match += r'ENCRYPTED PRIVATE KEY\b|\bCERTIFICATE\b)-{5}\n'
        match += r'(?:[\w+/]{64}\n)+'
        match += r'(?:[\w+/=]{1,64}\n){0,1}'
        match += r'-{5}END (?P=pem_data_type)-{5})'

        patt = re.compile(match)
        for filefd in patt.finditer(mbuf):
            out_filename = hex(
                base + filefd.start(0)).strip("L").lstrip('0x') + '-pem'
            pem_data_type, pem_data = filefd.group(
                'pem_data_type'), filefd.group('pem_data')

            if pem_data_type == 'PRIVATE KEY':
                self.logger.critical('dumping PEM key'.ljust(32))
                out_filename += '-priv.key'
            elif pem_data_type == 'ENCRYPTED PRIVATE KEY':
                self.logger.critical('dumping PEM encrypted key'.ljust(32))
                out_filename += '-enc-priv.key'
            elif pem_data_type == 'CERTIFICATE':
                self.logger.critical('dumping PEM certificate'.ljust(32))
                out_filename += '.cert'
            else:
                self.logger.critical('unexpected regex match'.ljust(32))
                self.fatal('exiting...')
            try:
                filefd = None
                filefd = open(output_directory + out_filename, 'wb')
            except Exception as err:
                self.logger.critical('Exception - open({})'.format(
                    output_directory + out_filename))
                self.logger.critical(err)
                self.fatal("exiting...")
            finally:
                filefd.write(pem_data)
                filefd.close()
        return

    def hexdump(self, data, addr=0, prefix="|___ ", width=16, heading=""):
        dump = heading
        dump += '\n'
        dump += prefix
        text_slice = ''

        for byte in data:
            if addr % width == 0:
                dump += ' '
                for char in text_slice:
                    if ord(char) >= width and ord(char) <= 126:
                        dump += char
                    else:
                        dump += '.'
                dump += '\n%s%04x: ' % (prefix, addr)
                text_slice = ''
            dump += '%02x ' % ord(byte)
            text_slice += byte
            addr += 1
        remainder = addr % width
        if remainder != 0:
            dump += '    ' * (width - remainder) + ' '
        for char in text_slice:
            if ord(char) >= width and ord(char) <= 126:
                dump += char
            else:
                dump += '.'
        return dump + '\n'

    def create_directory_or_die(self, directory):
        try:
            os.mkdir(directory)
            self.logger.critical(
                'Success - created output directory "{}" '.format(directory))
            return
        except OSError as err:
            self.logger.critical('Exception - mkdir')
            self.logger.critical(err)
            self.fatal('exiting...')

    def validate_directory_or_die(self, directory):
        self.logger.debug('validating output directory')
        try:
            mode = os.stat(directory).st_mode
            if stat.S_ISDIR(mode):
                if not os.access(directory, os.W_OK):
                    self.logger.critical(
                        'Error - output directory "{}"" is not writable by user', directory)
                    self.fatal('exiting...')
            else:
                self.logger.critical(
                    'Error - user specified "%s" for output directory but it is not a directory',
                    directory)
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
                except KeyboardInterrupt:
                    print('')
                    self.fatal('exiting...')
                return self.create_directory_or_die(directory)
            else:
                self.logger.critical('Exception - general error')
                self.logger.critical(err)
                self.fatal('exiting...')

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description='Win32MemoryScraper: Search memory of a 32-bit Windows process for X509 certificates and keys in DER/PEM format and dump them to the disk.')
        parser.add_argument(
            '-p', '--pid',
            metavar="Process ID",
            dest='pid',
            type=int,
            help='Process ID to scrape for DER/PEM data')
        parser.add_argument(
            '-w', '--window-title',
            metavar='Window Title',
            dest='window_title',
            type=str,
            help='Window title of application to scrape for DER/PEM data')
        parser.add_argument(
            '-o', '--output-directory',
            required=True,
            dest='output_directory',
            metavar='output directory',
            type=str,
            help='Directory where scraped keys/certificates should be stored')
        parser.add_argument(
            '-v', '--verbose',
            dest='verbosity',
            default=0,
            action='count',
            help='Verbosity level for output. Use up to 5 times for full debugging information')

        self.args = parser.parse_args()

        # Really dumb stuff with logging, you can tell this code was written 5+
        # years ago :<
        if self.args.verbosity > 4:
            self.args.verbosity = 4
        self.args.verbosity *= 10
        if self.args.verbosity:
            self.args.verbosity = 50 - self.args.verbosity
        if not self.args.verbosity:
            self.args.verbosity = logging.CRITICAL

        self.log_level = self.args.verbosity
        self.logger.setLevel(self.log_level)

        if self.args.pid and self.args.window_title:
            parser.print_usage()
            parser.exit(
                'Error - cannot window title (-w) and pid (-p) options are mutually exclusive')
            parser.exit(9)

        if not self.args.output_directory.endswith('/'):
            self.args.output_directory += '/'

        self.logger.debug('validating output directory')
        self.validate_directory_or_die(self.args.output_directory)
        return

    def adjust_privilege(self, priv):
        try:
            flags = win32.TOKEN_ADJUST_PRIVILEGES | win32.TOKEN_QUERY
            htoken = win32.OpenProcessToken(win32.GetCurrentProcess(), flags)
            priv_value = win32.LookupPrivilegeValue(None, priv)
            new_privs = [(priv_value, win32.SE_PRIVILEGE_ENABLED)]
            win32.AdjustTokenPrivileges(htoken, new_privs)
            self.logger.debug(
                'Success - AdjustTokenPrivileges(%s)'.format(priv))
        except win32.WindowsError as err:
            self.logger.warning('Exception - AdjustTokenPrivileges')
            self.logger.warning(err)
        except Exception as err:
            self.logger.critical('Exception - general error')
            self.logger.critical(err)

    def get_process_name_by_pid(self, pid):
        try:
            process_hnd = win32.OpenProcess(
                win32.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        except Exception as err:
            self.logger.critical('Exception - OpenProcess({})'.format(pid))
            self.logger.critical(err)
            self.fatal('exiting...')
        self.logger.debug(
            'return QueryFullProcessImageNameA on handle for process %d'.format(pid))
        return win32.QueryFullProcessImageNameA(process_hnd, 0)

    def get_processes(self):
        process_list = {}
        self.logger.debug("EnumProcesses loop")
        for pid in win32.EnumProcesses():
            process_hnd = None
            if not pid:
                continue
            try:
                process_hnd = win32.OpenProcess(
                    win32.PROCESS_QUERY_INFORMATION, False, pid)
                self.logger.debug("Success - OpenProcess")
                process_list[pid] = win32.QueryFullProcessImageNameA(
                    process_hnd, 0)
                self.logger.debug("Success - QueryFullProcessImageNameA")
            except win32.WindowsError as err:
                if err.winerror == win32.ERROR_ACCESS_DENIED:
                    self.logger.debug(
                        "Exception - OpenProcess/QueryFullProcessImageNameA - ERROR_ACCESS_DENIED")
                    process_list[pid] = "ERROR_ACCESS_DENIED"
                else:
                    self.logger.critical(
                        "Exception - OpenProcess/QueryFullProcessImageNameA")
                    self.logger.critical(err)
            except Exception as err:
                self.logger.critical('Exception - general error')
                self.logger.critical(err)
                self.fatal('exiting...')
            finally:
                if process_hnd:
                    win32.CloseHandle(process_hnd)
        return process_list

    def fatal(self, msg):
        self.logger.critical(msg)
        sys.exit(13)

    def get_pid_by_window_title(self, title):
        """
        title is a str window title. return the window's pid
        exceptions are fatal
        """
        try:
            wnd_handle = win32.FindWindow(None, title)
            self.logger.debug('Success - FindWindow')
            pid = win32.GetWindowThreadProcessId(wnd_handle)
            self.logger.debug('Success - GetWindowThreadProcessId')
            self.logger.critical(
                'Success - using pid {} from window title "{}"'.format(pid[1], title))
            return pid[1]
        except win32.WindowsError as err:
            self.logger.critical(
                "Exception - FindWindow/GetWindowThreadProcessId")
            self.logger.critical(err)
            self.fatal("exiting...")
        except Exception as err:
            self.logger.critical("Exception - general error")
            self.logger.critical(err)
            self.fatal("exiting")

    def choose_from_proces(self):
        """
        present the user with a list of pids and executable names
        let them choose a pid
        """
        processes = self.get_processes()
        for pid in processes:
            self.logger.critical(str(pid).ljust(8) + processes[pid])

        pid = -1
        while pid not in processes:
            if pid != -1:
                self.logger.critical('Error - invalid PID entered')
            pid = raw_input('Enter PID> ')
            try:
                pid = int(pid.strip())
            except BaseException:
                pass
        return pid

    def spinner(self):
        self.spinner_speed_status += 1
        if self.spinner_speed_status < self.SPINNER_SPEED_DELAY:
            return
        else:
            if self.spinner_visibile:
                self.spinner_visible = False
            else:
                self.spinner_visibile = True
            self.spinner_speed_status = 0

        self.spinner_status += 1
        self.spinner_status = self.spinner_status % len(self.SPINNER_SYMBOLS)
        if self.spinner_visibile:
            sys.stdout.write('\r[%c] 0x%.8x/0x%.8x ... S E A R C H I N G ...'.format(
                self.SPINNER_SYMBOLS[self.spinner_status], self.curr_addr, self.addr_max))
        else:
            sys.stdout.write('\r[%c] 0x%.8x/0x%.8x ...                   ...'.format(
                self.SPINNER_SYMBOLS[self.spinner_status], self.curr_addr, self.addr_max))
        sys.stdout.flush()

    def scrape(self):
        self.parse_args()
        self.logger.debug('set log level to %d'.format(self.log_level))
        self.adjust_privilege('seDebugPrivilege')

        if not self.args.pid:
            if self.args.window_title:
                self.args.pid = self.get_pid_by_window_title(
                    self.args.window_title)
            else:
                self.args.pid = self.choose_from_proces()

        self.logger.critical(
            'Opening target process - OpenProcess(%d)'.format(self.args.pid))
        try:
            process_hnd = win32.OpenProcess(
                win32.PROCESS_ALL_ACCESS, 0, self.args.pid)
        except Exception as err:
            self.logger.critical('Exception - OpenProcess')
            self.logger.critical(err)
            self.fatal('exiting...')

        sysinfo = win32.GetSystemInfo()
        print(dir(sysinfo))
        dw_pagesize = sysinfo.dwPageSize
        self.logger.debug("Using page size 0x%x", dw_pagesize)
        self.curr_addr = self.addr_min
        self.logger.critical(
            'Beginning VirtualQueryEx/ReadProcessMemory loop (0x%x-0x%x)' %
            (self.curr_addr, self.addr_max))
        print('')
        while self.curr_addr < self.addr_max:
            self.spinner()
            try:
                page = win32.VirtualQueryEx(process_hnd, self.curr_addr)
            except Exception:
                self.logger.debug('Exception - VirtualQueryEx')
                self.curr_addr += dw_pagesize
                self.logger.debug('advancing to next memory page...')
                continue

            if not page.State & win32.MEM_COMMIT:
                self.curr_addr += dw_pagesize
                continue

            base_address = page.BaseAddress
            region_size = page.RegionSize
            try:
                mbuf = win32.ReadProcessMemory(
                    process_hnd, base_address, region_size)
            except Exception as err:
                self.logger.critical("Exception - ReadProcessMemory")
                self.curr_addr += dw_pagesize
                self.logger.debug("advancing to next memory page...")
                continue

            self.regex_search_for_pem(
                mbuf, base_address, self.args.output_directory)
            self.regex_search_for_der(
                mbuf, base_address, self.args.output_directory)
            self.curr_addr += region_size

        win32.CloseHandle(process_hnd)
        print(
            '\r\r[+] Search over process address range 0x%.8x-0x%.8x complete' %
            (self.addr_min, self.addr_max))
        print('')
        self.logger.critical('Search complete, exiting...')


def clean_screen_exit():
    print('\r' + ' '.rjust(64))
    print('')


def main():
    winscraiper = Win32MemoryScraper()
    winscraiper.scrape()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clean_screen_exit()
        print('Exiting on user control-c...')
