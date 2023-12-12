
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
    print(f"[DEBUG] {msg}{colors.ENDC}")