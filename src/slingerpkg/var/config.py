from slingerpkg import __version__, __package__

#dictionary of config variables
config_vars = [
    {"Name": "Debug", "Value": False, "Description": "Enable debug messages", "Type": "bool"},
    {"Name": "Logs_Folder", "Value": "~/.slinger/logs", "Description": "Folder to store history files", "Type": "str"},
    {"Name": "History_File", "Value": "~/.slinger/history", "Description": "History file location", "Type": "str"},
    {"Name": "Codec", "Value": "utf-8", "Description": "Codec to use for print decoding", "Type": "str"},
    {"Name": "Plugin_Folder", "Value": "~/.slinger/plugins", "Description": "Folder to store plugins", "Type": "str"},
]

logwriter = None
version = __version__
program_name = __package__
smb_conn_timeout = 999999