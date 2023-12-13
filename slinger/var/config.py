from ..utils.printlib import *
from ..utils.common import convert_to_bool
from tabulate import tabulate



#dictionary of config variables
config = [
    {"Name": "Debug", "Value": True, "Description": "Enable debug messages", "Type": "bool"},
    {"Name": "History_Folder", "Value": "../cli_history", "Description": "Folder to store history files", "Type": "str"},
]

# function to set a value in the config dictionary
def set_config_value(key, value):
    try:
        for c in config:
            if c["Name"].lower() == key.lower():
                if c["Type"] == "bool":
                    c["Value"] = convert_to_bool(value)
                elif c["Type"] == "int":
                    try:
                        c["Value"] = int(value)
                    except ValueError:
                        print_warning(f"Invalid value for {key}, needs to be an integer")
                else:
                    c["Value"] = value
                
                print_std(f"{key} --> {str(c['Value'])}")
                
                return
        print_warning(f"Config variable {key} does not exist")
    except KeyError:
        print_warning(f"Config variable {key} does not exist")
        return
    

# function to display the current config
def show_config():
    # print the config in a tabulate table
    print_std(tabulate([[c["Name"], c["Value"], c["Description"]] for c in config], headers=["Name", "Value", "Description"]))
