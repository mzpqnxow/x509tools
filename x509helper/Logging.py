from Imports import *

__id__ = "$Id: Logging.py 57 2014-03-19 03:26:46Z user $"

class Logging(object):
    """
    barebones base class for logging functionality
    """
    def __init__(self,log_level):
        self.log_level = log_level
        self.init_logging()
    def init_logging(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        if not len(self.logger.handlers):
            self.stdout_log_handler = logging.StreamHandler(sys.stderr)
            #formatter = logging.Formatter("[%(levelname)s] %(asctime)s@%(name)s[%(lineno)s]::%(funcName)s() - %(message)s",datefmt='%Y-%m-%d')
            formatter = logging.Formatter("\r%(funcName)s() - %(message)s",datefmt='%Y-%m-%d')
            self.stdout_log_handler.setFormatter(formatter)
            logging.getLogger(self.__class__.__name__).addHandler(self.stdout_log_handler) 
            self.logger = logging.getLogger(self.__class__.__name__)
            self.logger.setLevel(self.log_level)  