#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Copyright (C) 2011-2018
    Adam Greene <copyright@mzpqnxow.com>
Please see LICENSE or LICENSE.md for terms
"""
import logging
import sys


class LoggingMixin(object):
    """Really simple and not very well written Mixin for logging"""
    def __init__(self, log_level):
        self.log_level = log_level
        self.init_logging()

    def init_logging(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        if not len(self.logger.handlers):
            self.stdout_log_handler = logging.StreamHandler(sys.stderr)
            # formatter = logging.Formatter(
            #   "[%(levelname)s] %(asctime)s@%(name)s[%(lineno)s]::%(funcName)s() - %(message)s",
            #       datefmt='%Y-%m-%d')
            formatter = logging.Formatter(
                "\r%(funcName)s() - %(message)s", datefmt='%Y-%m-%d')
            self.stdout_log_handler.setFormatter(formatter)
            logging.getLogger(
                self.__class__.__name__).addHandler(
                self.stdout_log_handler)
            self.logger = logging.getLogger(self.__class__.__name__)
            self.logger.setLevel(self.log_level)
