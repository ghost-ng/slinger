import logging
from logging.handlers import TimedRotatingFileHandler
import os
from datetime import datetime


class SlingerLogger:
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



