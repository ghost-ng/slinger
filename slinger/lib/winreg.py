from ..utils.printlib import *
from .dcetransport import *
import traceback
from tabulate import tabulate
import os
import traceback
import datetime
from time import sleep
from ..utils.common import reduce_slashes

def extract_reg_values(input_text, keys):
    """
    Extracts values for specified keys from the provided text using regular expressions.

    Args:
    input_text (str): The text containing the key-value pairs.
    keys (list): A list of keys to extract values for.

    Returns:
    dict: A dictionary containing the keys and their extracted values.
    """
    values = {}
    for key in keys:
        # Construct a regex pattern for each key
        # This pattern looks for the key, followed by the REG type, and captures the value
        pattern = rf"{key}\s+REG_[A-Z_]+\s+([^\n]+)"
        match = re.search(pattern, input_text)
        if match:
            # Extract and store the value if the key is found
            values[key] = match.group(1).strip()
        else:
            # If the key is not found, store None
            values[key] = None
    return values


class winreg():
    def __init__(self):
        print_good("WinReg Module Loaded!")
        self.registry_used = False
        self.winreg_already_setup = False
        self.reg_tcpip = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\"
        self.reg_interface = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"

    

    def restore_registry(self):
        if self.dce_transport.rrpshouldStop:
            print_info("Restoring Remote Registry service to STOPPED state")
            self.stop_remote_registry()

    def enum_key_value(self, keyName):
        self.registry_used = True
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('winreg')

        
        print_info("Enumerating keys...")
        hKey = self.dce_transport._get_key_handle(keyName, bind=True)

        print(keyName)
        ans = self.dce_transport._get_key_values(hKey, bind=True)
        print(ans)

    def setup_remote_registry(self):

        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('svcctl')
        try:
            print_info("Starting Remote Registry service")
            self.registry_used = True
            response = self.dce_transport._start_service('RemoteRegistry')
            print_good("Remote Registry service started")
            
        except Exception as e:
            if "ERROR_SERVICE_ALREADY_RUNNING" in str(e):
                print_warning("RemoteRegistry Service already running")
                self.winreg_already_setup = True
                return
            
    def stop_remote_registry(self):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('svcctl')
        try:
            self.registry_used = True
            print_info("Stopping Remote Registry service")
            response = self.dce_transport._stop_service('RemoteRegistry')
            if response['ReturnCode'] == 0:
                print_good("Remote Registry service stopped")
            else:
                print_bad("Failed to stop Remote Registry service")
        except Exception as e:
            if "ERROR_SERVICE_NOT_ACTIVE" in str(e):
                print_warning("RemoteRegistry Service already stopped")
                return
    
    def enum_subkeys(self, keyName, return_list=False):
        self.registry_used = True
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('winreg')
        subkeys = self.dce_transport._enum_subkeys(keyName, bind=True)
        if not return_list:
            if subkeys:
                print('\n'.join(subkeys))
        else:
            return subkeys

    def ipconfig(self):
        # DhcpNameServer, DhcpIPAddress, DhcpSubnetMaskOpt, DhcpDefaultGateway, DhcpDomain, DhcpDomainName
        iface_banner = """
\tInterface:\t{interface}
\tDhcpServer:\t{DhcpNameServer}
\tDhcpIPAddress:\t{DhcpIPAddress}
\tDhcpSubnetMask:\t{DhcpSubnetMaskOpt}
\tDhcpDefaultGateway:\t{DhcpDefaultGateway}
\tDhcpDomain:\t{DhcpDomain}
"""

        self.registry_used = True
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('winreg')
        print_info("Enumerating IP Configuration...")
        subkeys = self.enum_subkeys(self.reg_interface, return_list=True)

        interface_keys = reduce_slashes(subkeys[0::])
        #print(interface_keys)
        keys_to_search = ["DhcpNameServer", "DhcpIPAddress", "DhcpSubnetMaskOpt", "DhcpDefaultGateway", "DhcpDomain"]

        for iface in interface_keys:
            #print_info("Interface: " + iface)
            hKey = self.dce_transport._get_key_handle(iface, bind=False)
            ans = self.dce_transport._get_key_values(hKey, hex_dump=False)
            values = extract_reg_values(ans, keys_to_search)
            _iface = iface.split("\\")[-1]
            print(iface_banner.format(interface=_iface, **values))

    def hostname(self):
        self.registry_used = True
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('winreg')
        hKey = self.dce_transport._get_key_handle(self.reg_tcpip, bind=True)
        ans = self.dce_transport._get_key_values(hKey)
        values = extract_reg_values(ans, ["Hostname"])
        print("Hostname:\t" + values["Hostname"])

    def add_reg_value(self, keyName, valueName, valueData, valueType="REG_SZ"):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('winreg')
        #hKey = self.dce_transport._get_key_handle(keyName, bind=True)

        # if valueType == "REG_SZ":
        #     valueType = rrp.REG_SZ
        # elif valueType == "REG_DWORD":
        #     valueType = rrp.REG_DWORD
        # elif valueType == "REG_BINARY":
        #     valueType = rrp.REG_BINARY
        # else:
        #     print_bad("Invalid value type")
        #     return
        
        self.dce_transport._reg_add(keyName, valueName, valueData, valueType)



