import logging
from logging.handlers import TimedRotatingFileHandler
import os
from datetime import datetime
from traceback import format_exception


class SlingerLogger:
    """
    A logger class that sets up a daily rotating file logger.
    Attributes:
        logger (logging.Logger): The logger instance.
    Methods:
        __init__(log_folder, log_file_basename):
            Initializes the SlingerLogger with the specified log folder and log file base name.
        get_logger():
            Returns the logger instance.
    """
    def __init__(self, log_folder, log_file_basename):
        # Ensure the log folder exists
        os.makedirs(log_folder, exist_ok=True)
        
        # Full path for the log file with the base name
        log_file_path = os.path.join(log_folder, log_file_basename)

        # Set up the logger
        self.logger = logging.getLogger('DailyFileLogger')
        self.logger.setLevel(logging.DEBUG)

        # Create a handler for writing logs to a file with daily rotation
        handler = TimedRotatingFileHandler(log_file_path, when="midnight", interval=1, backupCount=7)
        handler.suffix = "%Y-%m-%d.log"  # Suffix for the log file
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

        self.logger.addHandler(handler)

    def get_logger(self):
        return self.logger



def error_logging(e):
    # e is sys.exc_info()
    exc_type, exc_value, exc_traceback = e
    tb_lines = format_exception(exc_type, exc_value, exc_traceback)
    error_message = ''.join(tb_lines)
    if "NoneType" in error_message:
        error_message = ""
    return error_message