import inspect
from slingerpkg.utils.logger import SlingerLogger, error_logging
from slingerpkg.var.config import config_vars
import os

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[0;32m'
    WARNING = '\033[91m'
    BLUE = '\033[0;34m'
    YELLOW = '\033[93m'
    FAIL = '\033[1;31m'
    ENDC = '\033[0m'

def get_config_value(key):
    try:
        for c in config_vars:
            if c["Name"].lower() == key.lower():
                return c["Value"]
        print_warning(f"Config variable {key} does not exist")
    except KeyError:
        print_warning(f"Config variable {key} does not exist")
        return


def print_block(msg, color=colors.YELLOW, block_char="*", max_width=50):
    """
    Prints a centered block with top and bottom borders only.
    Ensures borders expand at least 2 characters left and right beyond the message.

    Args:
        msg (str): The message to display.
        block_char (str): The character to use for the border.
        max_width (int): The maximum width of the block (default 50).
    """
    # Calculate the total width (message + 4 spaces for padding)
    required_width = len(msg) + 4

    # Truncate the message if necessary
    if required_width > max_width:
        max_msg_length = max_width - 7  # 3 for "..." and 4 for padding
        msg = msg[:max_msg_length] + "..."
        required_width = max_width

    # Calculate padding for centering
    padding = (required_width - len(msg)) // 2
    centered_msg = f"{' ' * padding}{msg}{' ' * (required_width - len(msg) - padding)}"

    # Print the block
    border = block_char * required_width
    print_log(f"{color}{border}{colors.ENDC}")  # Top border
    #print_log(centered_msg)  # Centered message
    print_log(f"{color}{centered_msg}{colors.ENDC}")
    #print_log(border)  # Bottom border
    print_log(f"{color}{border}{colors.ENDC}")




def print_log(msg="", end="\n"):
    #TODO: test codecs
    #print(msg.encode().decode(get_config_value("Codec")), end=end)

    print(msg, end=end)
    try:
        #TODO: test codecs
        #log.debug(msg.encode().decode(get_config_value("Codec")))
        log.debug(msg)
    except Exception as e:
        print_warning(f"Unable to write to log file: {e}")
        raise e

def print_good(msg):
    print_log(f"{colors.OKGREEN}[+] {msg}{colors.ENDC}")

def print_bad(msg):
    print_log(f"{colors.FAIL}[-] {msg}{colors.ENDC}")

def print_warning(msg):
    print_log(f"{colors.WARNING}[!] {msg}{colors.ENDC}")

def print_info(msg):
    print_log(f"{colors.HEADER}[*] {msg}{colors.ENDC}")

def print_debug(msg, e=None):
    # find the Debug Dict in config
    
    if e:
        verbose_trace = error_logging(e)
    else:
        verbose_trace = ""

    current_frame = inspect.currentframe().f_back

    line_number = current_frame.f_lineno

    module_name = inspect.getmodule(current_frame).__name__
    debug_msg = f"""
*********************************************
[DEBUG][{module_name}][Line {line_number}]:{colors.HEADER}{msg}{colors.ENDC}
{verbose_trace}
[DEBUG]{trace_print("Traceback (most recent call last):", trace_calls=True)}
*********************************************
"""

    if not get_config_value("Debug"):
        log.debug(debug_msg)
        return
    print_log(debug_msg)
 
def trace_print(*args, **kwargs):
    # Print the standard message
    #print_log(*args, **kwargs)

    # Check if tracing is requested
    if kwargs.get('trace_calls', False):
        # Create a stack trace from the current frame
        frame = inspect.currentframe().f_back

        # Initialize the message variable
        message = ""

        # Iterate over the frames and append the call series to the message
        message += "Call trace:\n"
        while frame:
            module = inspect.getmodule(frame)
            if module:
                module_name = module.__name__
            else:
                module_name = '(unknown module)'

            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            funcname = frame.f_code.co_name
            message += f"\t{module_name}: {funcname} in {filename}, line {lineno}\n"

            frame = frame.f_back

        # Return the message
        return message


log_location = os.path.expanduser(get_config_value('Logs_Folder'))
# Initialize the logger at the start of your application
log = SlingerLogger(log_location, "slingerlog").get_logger()

logwriter = log