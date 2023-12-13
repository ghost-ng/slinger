import inspect
from slinger.utils.logger import SlingerLogger
from slinger.var.config import config_vars




class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[0;32m'
    WARNING = '\033[91m'
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

def print_log(msg="", end="\n"):
    print(msg, end=end)
    try:
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

def print_debug(msg):
    # find the Debug Dict in config
    if not get_config_value("Debug"):
        return

    current_frame = inspect.currentframe().f_back

    # Get the line number from the frame
    line_number = current_frame.f_lineno

    # Get the name of the module from the frame
    module_name = inspect.getmodule(current_frame).__name__
    print_log("*********************************************")
    print_log(f"[DEBUG][{module_name}][Line {line_number}]:{msg}{colors.ENDC}")
    trace_print("Traceback (most recent call last):", trace_calls=True)
    print_log("*********************************************")

    print_log()
 
def trace_print(*args, **kwargs):
    # Print the standard message
    #print_log(*args, **kwargs)

    # Check if tracing is requested
    if kwargs.get('trace_calls', False):
        # Create a stack trace from the current frame
        frame = inspect.currentframe().f_back

        # Iterate over the frames and print the call series
        print_log("Call trace:")
        while frame:
            module = inspect.getmodule(frame)
            if module:
                module_name = module.__name__
            else:
                module_name = '(unknown module)'

            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            funcname = frame.f_code.co_name
            print_log(f"\t{module_name}: {funcname} in {filename}, line {lineno}")

            frame = frame.f_back


log_location = get_config_value("Logs_Folder")
# Initialize the logger at the start of your application
log = SlingerLogger(log_location, "slingerlog").get_logger()