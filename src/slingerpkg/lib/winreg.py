import json
from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from tabulate import tabulate
from time import sleep
from slingerpkg.utils.common import reduce_slashes, enter_interactive_debug_mode
import datetime

import struct

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
    print_debug("Extracting values for keys: " + str(keys))
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
    #enter_interactive_mode(local=locals())
    return values


class winreg():
    """
    This class provides methods for interacting with the Windows Registry.
    """

    def __init__(self):
        print_debug("WinReg Module Loaded!")
        self.registry_used = False
        self.winreg_already_setup = False
        self.reg_tcpip = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\"
        self.reg_interface = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"
        self.fwrule = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules\\"
        self.fwpolicy_std = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\"
        self.portproxy_root = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\PortProxy\\"
        self.processor_info = "HKLM\\HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0\\"
        self.system_time = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Config"
        self.last_shutdown = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Windows"
        self.active_portfwd_rules = []
        self.titledb_list = []

    def enum_key_value(self, keyName, hex_dump=False, return_val=False, echo=True):
        """
        Enumerate the values of a given registry key.

        Args:
            keyName (str): The name of the registry key to enumerate.

        Returns:
            list: A list of values associated with the registry key.

        Raises:
            Exception: If there is an error while enumerating the key values.

        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')

        if echo:
            print_info("Enumerating Key: " + keyName)
        hKey = self.dce_transport._get_key_handle(keyName)

        ans = self.dce_transport._get_key_values(hKey, hex_dump=hex_dump)

        if not return_val:
            print_log(keyName)
            print_log(ans)
        else:
            return ans
       

    def setup_remote_registry(self, args):
        """
        Sets up the remote registry service.

        This method establishes a connection to the remote host and starts the Remote Registry service.
        If the service is already running, it sets a flag indicating that the setup has already been done.

        Raises:
            Exception: If there is an error starting the service.

        Returns:
            None
        """
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        try:
            print_info("Starting Remote Registry service")
            response = self.dce_transport._start_service('RemoteRegistry')
            if response == "DISABLED":
                print_info("Trying to enable the Remote Registry service")
                self.dcetransport._connect('winreg')
                ans = self.dce_transport._enable_service('RemoteRegistry')
            
                if ans != False:
                    print_good("Remote Registry service started")
                else:
                    print_bad("Failed to start Remote Registry service")
            
        except Exception as e:
            
            if "ERROR_SERVICE_ALREADY_RUNNING" in str(e):
                print_warning("RemoteRegistry Service already running")
                self.winreg_already_setup = True
                return
            else:
                print_debug(str(e), sys.exc_info())
    
    def reg_query_handler(self, args):
        if args.list:
            self.enum_subkeys(args.key)
        elif args.value:
            self.enum_key_value(args.key)
        elif args.key:
            try:
                self.enum_key_value(args.key)
                self.enum_subkeys(args.key)
            except Exception as e:
                if "ERROR_FILE_NOT_FOUND" in str(e):
                    print_bad("Registry key does not exist")
                elif "ERROR_BAD_PATHNAME" in str(e):
                    print_bad("Invalid registry path")
                else:
                    print_bad("Error querying registry key: " + str(e))
                    print_debug(str(e), sys.exc_info())
                    
    #elif args.command == "regset":

    def stop_remote_registry(self, args):
        """
        Stops the Remote Registry service.

        If the DCE transport is not already established, it will be created using the provided host, username, port, and connection parameters.
        The method then connects to the 'svcctl' service and attempts to stop the 'RemoteRegistry' service.
        If the service is successfully stopped, a success message is printed.
        If an error occurs or the service is already stopped, the corresponding message is printed.

        Returns:
            None
        """
        self.setup_dce_transport()
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
            print_debug(str(e), sys.exc_info())
            if "ERROR_SERVICE_NOT_ACTIVE" in str(e):
                print_warning("RemoteRegistry Service already stopped")
                return
    
    def enum_subkeys(self, keyName, return_list=False):
        """
        Enumerate subkeys under the specified key.

        Args:
            keyName (str): The name of the key to enumerate subkeys from.
            return_list (bool, optional): Whether to return the subkeys as a list. Defaults to False.

        Returns:
            list or None: The subkeys as a list if `return_list` is True, otherwise None.
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        subkeys = self.dce_transport._enum_subkeys(keyName)
        if not return_list:
            if subkeys:
                print_log('\n'.join(subkeys))
        else:
            return subkeys

    def ipconfig(self, args=None):
        """
        Retrieves and prints the IP configuration information for the current host.

        Returns:
            None
        """
        # DhcpNameServer, DhcpIPAddress, DhcpSubnetMaskOpt, DhcpDefaultGateway, DhcpDomain, DhcpDomainName
        iface_banner = """
    \tInterface:\t{interface}
    \tDhcpServer:\t{DhcpNameServer}
    \tDhcpIPAddress:\t{DhcpIPAddress}
    \tDhcpSubnetMask:\t{DhcpSubnetMaskOpt}
    \tDhcpDefaultGateway:\t{DhcpDefaultGateway}
    \tDhcpDomain:\t{DhcpDomain}
    """
        
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        print_info("Enumerating IP Configuration...")
        subkeys = self.enum_subkeys(self.reg_interface, return_list=True)

        interface_keys = reduce_slashes(subkeys[0::])
        #print_log(interface_keys)
        keys_to_search = ["DhcpNameServer", "DhcpIPAddress", "DhcpSubnetMaskOpt", "DhcpDefaultGateway", "DhcpDomain"]

        for iface in interface_keys:
            #print_info("Interface: " + iface)
            #self.dce_transport.bind_override = True
            #self.dce_transport._bind(rrp.MSRPC_UUID_RRP)
            #hKey = self.dce_transport._get_key_handle(iface, bind=True)
            #ans = self.dce_transport._get_key_values(hKey, hex_dump=False)
            ans = self.enum_key_value(iface, hex_dump=False, return_val=True)
            values = extract_reg_values(ans, keys_to_search)
            #print(values)
            _iface = iface.split("\\")[-1]
            print_log(iface_banner.format(interface=_iface, **values))

    def _sys_proc_info(self, args=None, echo=True):
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        ans = self.enum_key_value(self.processor_info, return_val=True, echo=echo)
        values = extract_reg_values(ans, ["ProcessorNameString", "Identifier", "VendorIdentifier"])        
        return values

    def _sys_time_info(self, args=None, echo=True):
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        ans = self.enum_key_value(self.system_time, return_val=True, echo=echo)
        values = extract_reg_values(ans, ["LastKnownGoodTime"])
        return values

    def _get_binary_value(self, keyName, valueName):
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        hKey = self.dce_transport._get_key_handle(keyName)
        ans = self.dce_transport._get_binary_value(hKey, valueName)

    def _sys_shutdown_info(self, args=None, hex_dump=True, echo=True):
        """
        Retrieves and displays the last shutdown time from the registry.

        Args:
            args: Optional arguments.
            hex_dump (bool): Whether to include a hex dump.
            echo (bool): Whether to print the result.

        Returns:
            str: The last shutdown time in a human-readable format, or an error message.
        """
        try:
            self.setup_dce_transport()
            self.dce_transport._connect('winreg')

            binary_data = self.dce_transport._get_binary_data(self.last_shutdown, "ShutdownTime")

            # Parse binary data (assume it's a FILETIME format)
            if binary_data:
                filetime = struct.unpack("<Q", binary_data)[0]
                unix_time = (filetime - 116444736000000000) // 10000000
                shutdown_time = datetime.datetime.fromtimestamp(unix_time).strftime("%Y-%m-%d %H:%M:%S")

                if echo:
                    print_info(f"Last Shutdown Time: {shutdown_time}")
                return shutdown_time
            else:
                raise ValueError("ShutdownTime data is empty or invalid.")

        except Exception as e:
            error_message = f"Failed to retrieve shutdown info: {str(e)}"
            print_debug(error_message, sys.exc_info())
            line_num = sys.exc_info()[-1].tb_lineno
            print_debug(f"Error occurred on line {line_num}")
            return error_message



    def hostname(self, args=None):
        """
        Retrieves the hostname from the Windows registry.

        Returns:
            None: Prints the hostname of the machine.

        Raises:
            Exception: If there is an error retrieving the hostname.
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        hKey = self.dce_transport._get_key_handle(self.reg_tcpip)
        ans = self.dce_transport._get_key_values(hKey)
        values = extract_reg_values(ans, ["Hostname"])
        print_log("Hostname:\t" + values["Hostname"])

    def add_reg_value_handler(self, args):
        self.add_reg_value(args.key, args.value, args.data, args.type)

    def add_reg_value(self, keyName, valueName, valueData, valueType="REG_SZ"):
        """
        Adds a registry value to the specified key.

        Args:
            keyName (str): The name of the key.
            valueName (str): The name of the value.
            valueData (str): The data to be stored in the value.
            valueType (str, optional): The type of the value. Defaults to "REG_SZ".

        Returns:
            None
        """
    
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        try:

            ans = self.dce_transport._reg_add(keyName, valueName, valueData, valueType)
            if ans:
                print_good(f"Added Value {valueName} to {reduce_slashes(keyName)}")
            else:
                print_bad(f"Failed to Add Value {valueName} to {keyName}")
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_FILE_NOT_FOUND" in str(e):
                print_warning(f"Key {keyName} does not exist")
                return
            else:
                print_bad(f"Failed to Add Value {valueName} to {keyName}")
                print_debug("Failed to Add Value", sys.exc_info())
                return



    def show_fw_rules(self, args=None):
        """
        Retrieves and prints the firewall rules for the current host.

        Returns:
            None
        """
        
        def parse_firewall_rules(rule_list):
            parsed_rules = []

            for rule in rule_list:
                # Split the rule into rule name and the rest of the content
                parts = rule.lstrip().split('\t', 1)
                rule_name = parts[0]
                rule_content = parts[1] if len(parts) > 1 else ''

                # Split the rest of the content into key-value pairs
                key_value_pairs = rule_content.split('|')

                # Initialize a dictionary to store the parsed values
                parsed_rule = {
                    'RuleName': rule_name,
                    'Action': None,
                    'Dir': None,
                    'Protocol': None,
                    'Profile': None,
                    'LPort': None,
                    'App': None,
                    'Svc': None,
                }

                # Iterate over each key-value pair
                for pair in key_value_pairs:
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        # Only add the specified fields to the dictionary
                        if key in parsed_rule:
                            parsed_rule[key] = value

                parsed_rules.append(parsed_rule)

            return parsed_rules
        
        
        
        ans = self.enum_key_value(self.fwrule, return_val=True)
        fwrules_list = ans.splitlines()
        #print(fwrules_list)
        #create dict RuleName, Action, Dir, Protocol, Profile, LPort, App, Svc, Desc
        parsed_rules = parse_firewall_rules(fwrules_list)

        # sort by Profile (str) then Dir (str) - reverse order
        parsed_rules.sort(key=lambda x: ((x['Profile'] if x['Profile'] is not None else '', x['Dir'] if x['Dir'] is not None else '')), reverse=True)
        print(tabulate(parsed_rules, headers="keys"))


    def reg_create_key(self, args):
        """
        Creates a registry key.

        Args:
            keyName (str): The name of the key to create.

        Returns:
            None
        """
        try:
            keyName = args.key
        except AttributeError:
            keyName = args
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        ans = self.dce_transport._reg_create_key(keyName)
        if ans:
            print_good(f"Created Key {keyName}")
        else:
            print_bad(f"Failed to Create Key {keyName}")


    def reg_delete_key(self, keyName):
        """
        Deletes a registry key.

        Args:
            keyName (str): The name of the key to delete.

        Returns:
            None
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        try:
            ans = self.dce_transport._reg_delete_key(keyName)
            if ans:
                print_good(f"Deleted Key {keyName}")
            else:
                print_bad(f"Failed to Delete Key {keyName}")
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_FILE_NOT_FOUND" in str(e):
                print_warning(f"Key {keyName} does not exist")
                return
            else:
                print_bad(f"Failed to Delete Key {keyName}")
                print_debug("Failed to Delete Key", sys.exc_info())
                return
    
    def reg_delete_handler(self, args):
        if args.value:
            self.del_reg_key_value(args.key, args.value)
        elif args.key:
            self.reg_delete_key(args.key)
        else:
            print_warning("Invalid arguments.  Usage: regdel -k <key> [-v <value>]")

    def del_reg_key_value(self, keyName, keyValue):
        """
        Deletes the specified registry key's value.

        Args:
            keyName (str): The name of the key to delete.

        Returns:
            None
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        try:
            ans = self.dce_transport._reg_delete_value(keyName, keyValue)
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_FILE_NOT_FOUND" in str(e):
                print_warning(f"Key {keyName} and value {keyValue} combination does not exist")
                print_debug(f"Key {keyName} and value {keyValue} combination does not exist", sys.exc_info())
                return
        if ans:
            print_good(f"Deleted Value {keyValue} from {keyName}")
        else:
            print_bad(f"Failed to Delete Value {keyValue} from {keyName}")

    def show_env_handler(self, args=None):
        ans = self.show_env()
        print_log(ans)

    def get_processor_architecture(self, args=None):
        """
        Retrieves the processor architecture from the Windows registry.

        Returns:
            str: The processor architecture of the machine.

        Raises:
            Exception: If there is an error retrieving the processor architecture.
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        ans = self.show_env(echo=False)
        values = extract_reg_values(ans, ["PROCESSOR_ARCHITECTURE"])
        if "64" in values["PROCESSOR_ARCHITECTURE"]:
            print_debug("Processor is 64-bit")
            return "64"
        else:
            print_debug("Processor is 32-bit")
            return "32"

    def show_env(self, echo=True):
        """
        Retrieves and prints the environment variables for the current host.

        Returns:
            None
        """
        self.registry_used = True
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        ans = self.enum_key_value("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\", return_val=True, echo=echo)
        return ans

    def does_key_exist(self, args):
        """
        Checks if the specified registry key exists.

        Args:
            keyName (str): The name of the key to check.

        Returns:
            bool: True if the key exists, False otherwise.
        """
        keyName = args.key
        try:
            _ = self.enum_key_value(keyName, return_val=True)
            print_debug(f"Key {keyName} exists")
            return True
        except Exception as e:
            print_debug(f"Key {keyName} does not exist", sys.exc_info())
            if "ERROR_FILE_NOT_FOUND" in str(e):
                return False
            else:
                print_debug("Unable to check if key exists", sys.exc_info())
                return False

    def port_fwd_rules_handler(self, args):
        if args.load:
            self.load_port_fwd_rules()
        else:
            self.print_portfwd_rules()

    def print_portfwd_rules(self, args=None):
        """
        Prints the current port forwarding rules.

        Returns:
            None
        """
        print_info("Current Port Forwarding Rules:")
        print(tabulate(self.active_portfwd_rules, headers="keys"))

    def add_port_fwd_rule(self, local, remote):
        """
        Adds a port forwarding rule.

        Args:
            listen_addr (str): The port to listen on.
            connect_addr (str): The address to connect to.

        Returns:
            None
        """
        # parse the local and remote ports and addresses
        try:
            listen_addr, listen_port = local.split(":")
            connect_addr, connect_port = remote.split(":")
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad("Invalid Local or Remote Address")
            return

        # check if portproxy\v4tov4 key exists
        subkeys = self.enum_subkeys(self.portproxy_root, return_list=True)
        # if not create it 
        if "v4tov4" not in subkeys:
            self.reg_create_key(self.portproxy_root + "v4tov4")
            self.reg_create_key(self.portproxy_root + "v4tov4\\tcp")
        
        # add the port forward rule
        keyName = self.portproxy_root + "\\v4tov4\\tcp"
        valueName = f"{listen_addr}/{listen_port}"
        valueData = f"{connect_addr}/{connect_port}"
        local = valueName.replace("/",":")
        remote = valueData.replace("/",":")
        print_info(f"Adding Port Forward Rule {local} -> {remote}")
        self.add_reg_value(keyName, valueName, valueData, valueType="REG_SZ")
        self.active_portfwd_rules.append({"Listen Address": listen_addr+":"+listen_port, "Connect Address": connect_addr+":"+connect_port})    

    def del_port_fwd_rule(self, local):
        """
        Deletes a port forwarding rule.

        Args:
            local_addr (str): The local address and port to listen on.

        Returns:
            None
        """
        # parse the local and remote ports and addresses
        listen_addr, listen_port = local.split(":")
        # check if portproxy\v4tov4 key exists
        key = self.portproxy_root
        print_debug("Searching in:" + key)
        subkeys = self.enum_subkeys(key, return_list=True)
        if "v4tov4" not in " ".join(subkeys):
            print_warning("No Port Forwarding Rules Found")
            #set the active_portfwd_rules to empty
            self.active_portfwd_rules = []
            return
        else:
            key = self.portproxy_root + "v4tov4\\tcp\\"
            print_debug("Searching in:" + key)
            values = self.enum_key_value(key, return_val=True)
            if len(values) == 0:
                print_warning("No Port Forwarding Rules Found")
                #set the active_portfwd_rules to empty
                self.active_portfwd_rules = []
                return
            else:
                values = values.splitlines()
                for rule in values:
                    rule = rule.strip()
                    #print(rule)
                    #0.0.0.0/8080    REG_SZ  127.0.0.1/44
                    rule_list = rule.split()
                    _listen_addr = rule_list[0].split("/")[0]
                    _listen_port = rule_list[0].split("/")[1]
                    print_info(f"Found Rule: {_listen_addr}:{_listen_port}")
                    print_info(f"Searching for Rule: {listen_addr}/{listen_port}")
                    if _listen_addr == listen_addr and _listen_port == listen_port:
                        #print("Found Rule")
                        #print(rule)
                        self.del_reg_key_value(self.portproxy_root + "v4tov4\\tcp\\", rule_list[0])
                        print_good(f"Deleted Port Forwarding Rule for {listen_addr}:{listen_port}")
                        self.active_portfwd_rules = [rule for rule in self.active_portfwd_rules if not (rule["Listen Address"] == listen_addr and rule["Listen Port"] == listen_port)]
                        if not self.check_port_fwd_rules():
                            self.reg_delete_key(self.portproxy_root + "v4tov4\\tcp\\")
                            self.reg_delete_key(self.portproxy_root + "v4tov4\\")
                        return
                print_warning(f"Port Forwarding Rule {listen_addr}:{listen_port} not found")
                return
    def check_port_fwd_rules(self):
        """
        Checks if there are any port forwarding rules.

        Returns:
            bool: True if there are port forwarding rules, False otherwise.
        """
        # check if portproxy\v4tov4 key exists
        subkeys = self.enum_subkeys(self.portproxy_root, return_list=True)
        subkeys = " ".join(subkeys)
        #print(subkeys)
        if "v4tov4" not in subkeys:
            print_debug("No Port Forwarding Rules Found")
            #set the active_portfwd_rules to empty
            self.active_portfwd_rules = []
            return False
        else:
            values = self.enum_key_value(self.portproxy_root + "v4tov4\\tcp", return_val=True)
            #print(values)
            if len(values) == 0:
                print_debug("No Port Forwarding Rules Found")
                #set the active_portfwd_rules to empty
                self.active_portfwd_rules = []
                return False
            else:
                return True

    def port_fwd_handler(self, args):
        if args.list:
            self.print_portfwd_rules()
        elif args.remove:
            self.del_port_fwd_rule(args.local)
        elif args.add:
            if not args.local or not args.remote:
                print_warning("Invalid arguments.  Usage: portfwd -l|-d|-a <local> <remote>")
                return
            self.add_port_fwd_rule(args.local, args.remote)
        elif args.load:
            r = self.load_port_fwd_rules()
            if r:
                self.print_portfwd_rules()
        else:
            print_warning("Invalid arguments.  Usage: portfwd -l|-d|-a <local> <remote>")

    def load_port_fwd_rules(self):
        # get the current rule set from the regsitry and load it into the active_portfwd_rules list
        # check if portproxy\v4tov4 key exists
        #print_warning("Not yet implemented")
        #return

        if self.check_port_fwd_rules() == False:
            print_warning("No Port Forwarding Rules Found")
            #set the active_portfwd_rules to empty
            self.active_portfwd_rules = []
            return False
        else:
            key = self.portproxy_root + "v4tov4\\tcp\\"
            values = self.enum_key_value(key, return_val=True)
            #print(values)
            #subkeys = self.enum_subkeys(self.portproxy_root + "v4tov4\\tcp\\", return_list=True)
            if len(values) == 0:
                print_warning("No Port Forwarding Rules Found")
                #set the active_portfwd_rules to empty
                self.active_portfwd_rules = []
                return False
            else:
                values = values.splitlines()
                for rule in values:
                    rule = rule.strip().split()
                    listen_addr, listen_port = rule[0].split("/")
                    connect_addr, connect_port = rule[2].split("/")
                    self.active_portfwd_rules.append({"Listen Address": listen_addr+":"+listen_port, "Connect Address": connect_addr+":"+connect_port})
                return True
    
    def store_title_db(self):
        """
        Retrieves and stores the Title Database (performance counters) in a list.

        Returns:
            None
        """
        if self.titledb_list:
            return
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        print_debug("Retrieving Title Database")
        self.titledb_list = self.dce_transport._GetTitleDatabase()


    def get_counter_name(self, counter_num):
        """
        Retrieves the name of a performance counter using its number.

        Args:
            counter_num (int): The number of the performance counter.

        Returns:
            str: The name of the performance counter, or None if not found.
        """
        print_debug("Looking up counter: " + str(counter_num))
        try:
            # Ensure the title database is populated
            if not self.titledb_list:
                self.store_title_db()

            # Retrieve the counter name by number
            return self.titledb_list.get(counter_num, None)

        except Exception as e:
            print_bad(f"An error occurred while retrieving the counter name: {e}")
            print_debug("Detailed exception information:", e)
            return None

    def get_counter_num(self, counter_name):
        """
        Retrieves the number of a performance counter using its name.

        Args:
            counter_name (str): The name of the performance counter.

        Returns:
            int: The number of the performance counter, or None if not found.
        """
        print_debug("Looking up counter: " + counter_name)
        try:
            # Ensure the title database is populated
            if not self.titledb_list:
                self.store_title_db()

            # Search for the counter name
            for counter_num, name in self.titledb_list.items():
                if name.lower() == counter_name.lower():  # Case-insensitive match
                    return counter_num

            return None  # Counter name not found

        except Exception as e:
            print_bad(f"An error occurred while retrieving the counter number: {e}")
            print_debug("Detailed exception information:", e)
            return None

    def show_process_list(self, args=None):
        """
        Retrieves and prints the list of running processes.

        Returns:
            None
        """
        #https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters
        
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        print_info("Retrieving Process List...")
        #counter_name = "ID Process"
        arch = self.get_processor_architecture()
        self.dce_transport._connect('winreg')
        # local counters: typeperf -q
        # typeperf -q | findstr /C:Processes
        counter_num = self.get_counter_num("Process")
        print_debug("Counter Num: " + str(counter_num))
        self.dce_transport._connect('winreg')
        result = self.dce_transport._hQueryPerformaceData(str(counter_num), int(arch))
        #print_debug("Result: \n" + str(result))
        try:
            process_list = result[2]["Process"]
        except Exception as e:
            print_bad("Error retrieving process list: " + str(e))
            print_debug("Detailed exception information:", e=sys.exc_info(), force_debug=True)
            # print dict keys
            print_log("Dict Keys: " + str(result[2].keys()))
            return
        names = {}
        names = [key for key in process_list if key != "_Total"]
        names.sort(key=lambda x: process_list[x]["ID Process"])

        psl = {}
        for name in names:
            if name != "_Total":
                psl[process_list[name]["ID Process"]] = {
                    'Name': name,
                    'PID': process_list[name]["ID Process"],
                    'PPID': process_list[name]["Creating Process ID"],
                    'Priority': process_list[name]["Priority Base"],
                    'Threads': process_list[name]["Thread Count"],
                    'Handles': process_list[name]["Handle Count"],
                }
        print(tabulate(psl.values(), headers="keys"))
        print_good("Processes with '(uuid:<random chars>)' have duplicate names but are unique processes")

    def show_network_info_handler(self, args):
        """
        Display network performance stats in a human-readable format.

        Args:
            args: Arguments provided for filtering or display options.
        """
        arch = self.get_processor_architecture()
        self.dce_transport._connect('winreg')

        # Query performance data for network stats
        
        
        if args.tcp:
            # lookup TCPv4 and TCPv6 stats
            counter_name = "TCPv4"
            counter_num = self.get_counter_num(counter_name)
            print_info(f"Found Counter ({counter_name}): {counter_num}")
            self.dce_transport._connect('winreg')
            result = self.dce_transport._hQueryPerformaceData(str(counter_num), int(arch))
            self.show_tcp_info(result)
        elif args.rdp:
            # lookup Terminal Services Session
            counter_name = "Terminal Services Session"
            counter_num = self.get_counter_num(counter_name)
            print_info(f"Found Counter ({counter_name}): {counter_num}")
            self.dce_transport._connect('winreg')
            result = self.dce_transport._hQueryPerformaceData(str(counter_num), int(arch))
            #print_debug("Result: \n" + str(result))
            self.show_rdp_connections(result)
        

    def show_tcp_info(self, result):
        network_iface = result[2]["Network Interface"]
        network_tcpv4 = result[2]["TCPv4"]
        network_tcpv6 = result[2]["TCPv6"]

        # Display network interface names
        iface_names = [key for key in network_iface if key != "_Total"]
        iface_names.sort(key=lambda x: network_iface[x]["Bytes Received/sec"], reverse=True)

        print_info("Network Interfaces:")
        for name in iface_names:
            print_info(f"{name}")

        # Display TCPv4 stats
        print_info("TCPv4 Stats:")
        print_info(f"  Connections Active: {network_tcpv4['Connections Active']}")
        print_info(f"  Connections Established: {network_tcpv4['Connections Established']}")
        print_info(f"  Connections Passive: {network_tcpv4['Connections Passive']}")
        print_info(f"  Connections Reset: {network_tcpv4['Connections Reset']}")
        print_info(f"  Segments Received/sec: {network_tcpv4['Segments Received/sec']}")
        print_info(f"  Segments Sent/sec: {network_tcpv4['Segments Sent/sec']}")
        print("")

        # Display TCPv6 stats
        print_info("TCPv6 Stats:")
        print_info(f"  Connections Active: {network_tcpv6['Connections Active']}")
        print_info(f"  Connections Established: {network_tcpv6['Connections Established']}")
        print_info(f"  Connections Passive: {network_tcpv6['Connections Passive']}")
        print_info(f"  Connections Reset: {network_tcpv6['Connections Reset']}")
        print_info(f"  Segments Received/sec: {network_tcpv6['Segments Received/sec']}")
        print_info(f"  Segments Sent/sec: {network_tcpv6['Segments Sent/sec']}")

    def show_rdp_connections(self, result):
        self.dce_transport._connect('winreg')
        term_serv = result[2]["Terminal Services Session"] # Terminal Services Session
        print_info("RDP Connections:")
        # look for RDP-Tcp and count
        rdp_count = 0
        for key in term_serv:
            if "RDP-Tcp" in key:
                rdp_count += 1
                print_info(f"  {key}")
        print_info(f"Total RDP Connections: {rdp_count}")


    def show_avail_counters(self, args):
        """
        Retrieve and display the Title Database (performance counters) and optionally save it to a local file.

        Args:
            args (Namespace): Arguments for filtering results (optional).
                - args.save: Filepath to save counters (optional).
                - args.filter: Filter string to match counter numbers or descriptions (optional).
                - args.print: Always print counters to the screen.
        """
        try:
            self.setup_dce_transport()
            print_info("Retrieving Title Database")

            # If the titledb_list is already cached, use it
            if self.titledb_list:
                self._display_and_save_counters(args)
            else:
                self.store_title_db()

            # Display results and optionally save
            self._display_and_save_counters(args)

        except Exception as e:
            print_bad(f"An error occurred while retrieving counters: {e}")
            print_debug("Detailed exception information:", e)


    def _display_and_save_counters(self, args):
        """
        Display the Title Database and optionally save filtered or complete results to a file.

        Args:
            titledb_list (list): The list of performance counters.
            args (Namespace): Arguments for filtering and saving results (optional).
                - args.save: Filepath to save counters (optional).
                - args.filter: Filter string to match counter numbers or descriptions (optional).
                - args.print: Always print counters to the screen.
        """
        try:
            # Prepare output based on filter
            output = []
            # {2: 'System', 4: 'Memory', 6: '% Processor Time',
            for elem in self.titledb_list:
                key = elem
                value = self.titledb_list[elem]
                # Apply filter to both counter key and description
                if args.filter and args.filter.lower() not in key.lower() and args.filter.lower() not in value.lower():
                    continue
                output.append(f"{key} - {value}")
            
            # sort the output str ## - str
            output.sort(key=lambda x: int(x.split(" - ")[0]))
            
            # Print results if args.print is provided or save is not specified
            if args.print or not args.save:
                for line in output:
                    print_info(line)

            # Save to file if args.save is provided
            if args.save:
                with open(args.save, "w", encoding="utf-8") as file:
                    file.write("\n".join(output) + "\n")
                print_good(f"Counters saved to {os.path.abspath(args.save)}")

        except Exception as e:
            print_bad(f"Failed to display or save counters: {e}")
            print_debug("Detailed exception information:", e)


    def show_perf_counter(self, args):
        
        # get current debug value
        original_debug_value = get_config_value("debug")
        set_config_value("debug", "True")


        if not args.counter:
            print_warning("Invalid arguments.  Usage: debug-counter -c <counter>")
            return
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        result = self.dce_transport._GetTitleDatabase()
        self.dce_transport._connect('winreg')
        try:
            print_info("Retrieving Performance Counter: " + result[args.counter])
        except KeyError:
            print_warning("Failed to retrieve Performance Counter: " + str(args.counter) + " - Counter not found")
            set_config_value("debug", original_debug_value)
            print_warning("Run in interactive mode to access the Title Database")
            return
        if args.arch == "unk":
            arch = self.get_processor_architecture()
        elif args.arch == "x86":
            arch = "32"
        elif args.arch == "x64":
            arch = "64"
        self.dce_transport._connect('winreg')
        result = self.dce_transport._hQueryPerformaceData(str(args.counter), int(arch))        

        if args.interactive:
            print_info("'result'\tAccess the entire Performance Counter dictionary")
            try:
                perfData = result[2]
                print_info("'perfData'\tAccess the Performance Counter Data only")
            except (KeyError, IndexError, UnboundLocalError):
                print_warning("Failed to retrieve Performance Counter Data")
            try:
                title_db = result[2].pop("title_database")
                print_info("'title_db'\tAccess the Title Database")
            except (KeyError, IndexError, UnboundLocalError):
                print_warning("Failed to retrieve Title Database")
            print_info("Helper functions: 'self.write_to_file(data, filename)'")
            combined_scope = globals().copy()
            combined_scope.update(locals())
            enter_interactive_debug_mode(local=locals())
            set_config_value("debug", original_debug_value)
        else:
            try:
                print_info("Performance Counter Data for:")
                title_db = result[2].pop("title_database")
                counter_name = title_db[args.counter]
                print_info(f"{args.counter} - {counter_name}")
                print_debug("Result: \n" + str(result))
            except (KeyError, IndexError, UnboundLocalError):
                print_warning("Failed to retrieve Performance Counter Data")
                print_debug("Result: \n" + str(result))

            set_config_value("debug", original_debug_value)
        
    def write_to_file(self, data, filename):
        """
        Writes the specified data to a file.

        Args:
            data (dict,str,tuple): The data to write to the file.
            filename (str): The name of the file to write the data to.

        Returns:
            None
        """
        # if dict convert to printable string
        if isinstance(data, dict):
            data = json.dumps(data, indent=4)
        # if tuple convert to printable string
        if isinstance(data, tuple):
            data = str(data)
        with open(filename, "w") as file:
            file.write(data)
        print_good(f"Data written to {filename}")