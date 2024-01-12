import subprocess
import random
import datetime
import xml.etree.ElementTree as ET
import re
from impacket.dcerpc.v5 import rrp, srvs, wkst, tsch, scmr
from slingerpkg.utils.printlib import *
from slingerpkg.var.config import config_vars
from tabulate import tabulate

# dictionarty of UUID endpoints to plaintext names
uuid_endpoints = {
    srvs.MSRPC_UUID_SRVS: "srvs",
    wkst.MSRPC_UUID_WKST: "wkst",
    tsch.MSRPC_UUID_TSCHS: "tsch",
    scmr.MSRPC_UUID_SCMR: "scmr",
    rrp.MSRPC_UUID_RRP: "rrp"
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
        return re.sub(r'\\+', r'\\', paths)
    if type(paths) is list:
        return [re.sub(r'\\+', r'\\', path) for path in paths]

def sizeof_fmt(num, suffix='B'):
    for unit in ['','K','M','G','T','P','E','Z']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

def run_local_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    if stdout:
        print_log(stdout.decode())
    if stderr:
        print_log(stderr.decode())

def enum_struct(obj):
    for k,v in obj.__dict__.items():
        print(k ,v)
        if hasattr(v,'__dict__'):
            enum_struct(v)

def generate_random_date(lower_time_bound=None):
    if lower_time_bound is None:
        lower_time_bound = datetime.datetime.now() - datetime.timedelta(days=365)
    upper_time_bound = datetime.datetime.now()
    #lower_bound = upper_bound - datetime.timedelta(days=365)
    delta = upper_time_bound - lower_time_bound
    int_delta = (delta.days * 24 * 60 * 60) + delta.seconds
    random_second = random.randrange(int_delta)
    random_date = lower_time_bound + datetime.timedelta(seconds=random_second)
    return random_date.strftime("%Y-%m-%dT%H:%M:%S")

def xml_escape(data):
    replace_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&apos;",
            ">": "&gt;",
            "<": "&lt;",
            }
    return ''.join(replace_table.get(c, c) for c in data)




def validate_xml(xml_string):
    try:
        ET.fromstring(xml_string)
        print_log("XML is valid")
    except ET.ParseError as e:
        print_log(e)
        return False
    


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
    print_log(tabulate([[c["Name"], c["Value"], c["Description"]] for c in config_vars], headers=["Name", "Value", "Description"]))