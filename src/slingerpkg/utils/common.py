import string
import subprocess
import random
import datetime
import xml.etree.ElementTree as ET
import re
from impacket.dcerpc.v5 import rrp, srvs, wkst, tsch, scmr
from slingerpkg.utils.printlib import *
from slingerpkg.var.config import config_vars
from tabulate import tabulate
import sys
from contextlib import contextmanager

# dictionarty of UUID endpoints to plaintext names
uuid_endpoints = {
    srvs.MSRPC_UUID_SRVS: "srvs",
    wkst.MSRPC_UUID_WKST: "wkst",
    tsch.MSRPC_UUID_TSCHS: "tsch",
    scmr.MSRPC_UUID_SCMR: "scmr",
    rrp.MSRPC_UUID_RRP: "rrp",
}


def convert_to_bool(value):
    # Define strings that should be interpreted as True
    true_values = {"t", "tr", "true", "yes", "y", "1"}

    # Check if the value is a string and convert it to lowercase for comparison
    if isinstance(value, str):
        value = value.lower()
        return value in true_values

    # For non-string values, use the standard bool conversion
    return bool(value)


def reduce_slashes(paths):
    """
    Reduces all consecutive backslashes in each string of the list to a single backslash.

    :param paths: List of strings with paths
    :return: List of strings with reduced backslashes
    """
    if type(paths) is not list:
        return re.sub(r"\\+", r"\\", paths)
    if type(paths) is list:
        return [re.sub(r"\\+", r"\\", path) for path in paths]


def sizeof_fmt(num, suffix="B"):
    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, "Yi", suffix)


def run_local_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stdout:
        print_log(stdout.decode())
    if stderr:
        print_log(stderr.decode())


def remove_null_terminator(s):
    # Remove common null terminator patterns from the end of the string
    return re.sub(r"(\x00|\\0)$", "", s)


def escape_single_backslashes(path):
    # Replace single backslashes with double backslashes, but not already doubled ones
    return re.sub(r"(?<!\\)\\(?!\\)", r"\\\\", path)


def enum_struct(obj, indent=0):
    """Recursively enumerate and print the fields of a struct."""
    spacing = " " * indent
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, bytes):
                v = v.decode("utf-8", errors="replace")
            print(f"{spacing}{k}: {v}")
            if hasattr(v, "__dict__"):
                enum_struct(v, indent + 4)
    else:
        for k, v in obj.__dict__.items():
            if isinstance(v, bytes):
                v = v.decode("utf-8", errors="replace")
            print(f"{spacing}{k}: {v}")
            if hasattr(v, "__dict__"):
                enum_struct(v, indent + 4)
            elif hasattr(v, "fields"):
                print(f"{spacing}{k} (fields):")
                enum_struct(v.fields, indent + 4)
            elif hasattr(v, "structure"):
                print(f"{spacing}{k} (structure):")
                enum_struct(dict(v.structure), indent + 4)


def generate_random_date(lower_time_bound=None):
    if lower_time_bound is None:
        lower_time_bound = datetime.datetime.now() - datetime.timedelta(days=365)
    upper_time_bound = datetime.datetime.now()
    # lower_bound = upper_bound - datetime.timedelta(days=365)
    delta = upper_time_bound - lower_time_bound
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    random_date = lower_time_bound + datetime.timedelta(seconds=random_second)
    return random_date.strftime("%Y-%m-%dT%H:%M:%S")


def reformat_datetime(datetime_str):
    original_format = "%Y-%m-%d %H:%M:%S"  # Assuming the original format is "%Y-%m-%d %H:%M:%S"
    new_format = "%Y-%m-%dT%H:%M:%S"  # Desired format "%Y-%m-%dT%H:%M:%S"

    # Parse the original datetime string
    dt = datetime.datetime.strptime(datetime_str, original_format)

    # Convert the datetime object to the desired format
    formatted_datetime = dt.strftime(new_format)

    return formatted_datetime


def xml_escape(data):
    replace_table = {
        "&": "&amp;",
        '"': "&quot;",
        "'": "&apos;",
        ">": "&gt;",
        "<": "&lt;",
    }
    return "".join(replace_table.get(c, c) for c in data)


def generate_random_string(length=6, end=6):
    random.seed()
    # return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    return "".join(
        random.choices(string.ascii_letters + string.digits, k=random.randint(length, end))
    )


def validate_xml(xml_string):
    try:
        ET.fromstring(xml_string)
        print_log("XML is valid")
    except ET.ParseError as e:
        print_log(e)
        return False


def enter_interactive_debug_mode(local=None):
    import code
    import sys

    if local is None:
        local = {}

    # Combine globals and locals into one dictionary
    combined_scope = globals().copy()
    combined_scope.update(local)

    print_info("Entering interactive mode")

    # Save the original `sys.ps1` and `sys.stdout`
    original_ps1 = sys.ps1 if hasattr(sys, "ps1") else ">>> "
    original_stdout = sys.stdout

    class CustomStdout:
        def __init__(self, original_stdout):
            self.original_stdout = original_stdout

        def write(self, message):
            # Always write to stdout
            self.original_stdout.write(message)

        def flush(self):
            self.original_stdout.flush()

    def custom_exit():
        print_warning("Invalid Exit Caught")

    # Add custom exit handlers to the local scope
    combined_scope["exit"] = custom_exit
    combined_scope["quit"] = custom_exit

    try:
        # Override `sys.ps1` to include the warning message
        sys.ps1 = f"\n{colors.WARNING}[!] Reminder: Use Ctrl-D to exit interactive mode.{colors.ENDC}\n{original_ps1}"

        # Replace stdout to ensure clean output
        sys.stdout = CustomStdout(original_stdout)

        # Start the interactive session
        code.interact(
            banner=f"\n{colors.HEADER}[*] Interactive Debug Mode Activated{colors.ENDC}",
            local=combined_scope,
        )

    finally:
        # Restore the original settings
        sys.ps1 = original_ps1
        sys.stdout = original_stdout
        print_info("Exited interactive mode")


def get_config_value(key):
    try:
        for c in config_vars:
            if c["Name"].lower() == key.lower():
                return c["Value"]
        print_warning(f"Config variable '{key}' does not exist")
    except KeyError:
        print_warning(f"Config variable '{key}' does not exist")
        return


# function to set a value in the config dictionary
def set_config_value(key, value):
    try:
        for c in config_vars:
            if c["Name"].lower() == key.lower():
                if c["Type"] == "bool":
                    c["Value"] = convert_to_bool(value)
                elif c["Type"] == "int":
                    try:
                        c["Value"] = int(value)
                    except ValueError:
                        print_warning(f"Invalid value for '{key}', needs to be an integer")
                else:
                    c["Value"] = value

                print_log(f"{key} --> {str(c['Value'])}")

                return
        print_warning(f"Config variable '{key}' does not exist")
    except KeyError:
        print_warning(f"Config variable '{key}' does not exist")
        return


# function to display the current config
def show_config():
    # print the config in a tabulate table
    print_log(
        tabulate(
            [[c["Name"], c["Value"], c["Description"]] for c in config_vars],
            headers=["Name", "Value", "Description"],
        )
    )


class TeeOutput:
    def __init__(self, filename):
        self.file = open(filename, "a")  # Open file in append mode
        self.stdout = sys.stdout
        self.stderr = sys.stderr

    def write(self, data):
        self.stdout.write(data)  # Write to the console
        self.file.write(data)  # Write to the file

    def flush(self):
        self.stdout.flush()
        self.file.flush()

    def close(self):
        self.file.close()


@contextmanager
def tee_output(filename):
    if filename is None:
        yield
        return
    tee = TeeOutput(filename)
    sys.stdout = tee
    sys.stderr = tee
    try:
        yield
    finally:
        sys.stdout = tee.stdout
        sys.stderr = tee.stderr
        tee.close()
