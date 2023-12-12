import inspect
class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[0;32m'
    WARNING = '\033[91m'
    FAIL = '\033[1;31m'
    ENDC = '\033[0m'

def print_good(msg):
    print(f"{colors.OKGREEN}[+] {msg}{colors.ENDC}")

def print_bad(msg):
    print(f"{colors.FAIL}[-] {msg}{colors.ENDC}")

def print_warning(msg):
    print(f"{colors.WARNING}[!] {msg}{colors.ENDC}")

def print_info(msg):
    print(f"{colors.HEADER}[*] {msg}{colors.ENDC}")

def print_debug(msg):
    current_frame = inspect.currentframe().f_back

    # Get the line number from the frame
    line_number = current_frame.f_lineno

    # Get the name of the module from the frame
    module_name = inspect.getmodule(current_frame).__name__
    print(f"[DEBUG][{module_name}][Line {line_number}]:{msg}{colors.ENDC}")
    trace_print("Traceback (most recent call last):", trace_calls=True)
 
def trace_print(*args, **kwargs):
    # Print the standard message
    #print(*args, **kwargs)

    # Check if tracing is requested
    if kwargs.get('trace_calls', False):
        # Create a stack trace from the current frame
        frame = inspect.currentframe().f_back

        # Iterate over the frames and print the call series
        print("Call trace:")
        while frame:
            module = inspect.getmodule(frame)
            if module:
                module_name = module.__name__
            else:
                module_name = '(unknown module)'

            filename = frame.f_code.co_filename
            lineno = frame.f_lineno
            funcname = frame.f_code.co_name
            print(f"\t{module_name}: {funcname} in {filename}, line {lineno}")

            frame = frame.f_back
