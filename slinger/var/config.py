# Desc: Config variables for Slinger

#dictionary of config variables
config_vars = [
    {"Name": "Debug", "Value": False, "Description": "Enable debug messages", "Type": "bool"},
    {"Name": "Logs_Folder", "Value": "slinger/logs", "Description": "Folder to store history files", "Type": "str"},
    {"Name": "Codec", "Value": "utf-8", "Description": "Codec to use for print decoding", "Type": "str"},
]

logwriter = None
version = "0.1"
program_name = "Slinger"
smb_conn_timeout = 999999