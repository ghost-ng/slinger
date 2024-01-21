from slingerpkg.utils.printlib import *
from slingerpkg.lib.dcetransport import *
from tabulate import tabulate
from time import sleep
from slingerpkg.utils.common import reduce_slashes

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
        self.active_portfwd_rules = []

    def enum_key_value(self, keyName, hex_dump=True, return_val=False, echo=True):
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

        ans = self.dce_transport._get_key_values(hKey, hex_dump=False)
        #enter_interactive_mode(local=locals())

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

    def ipconfig(self, args):
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

    def hostname(self, args):
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



    def show_fw_rules(self, args):
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

    def show_env_handler(self, args):
        ans = self.show_env()
        print_log(ans)

    def get_processor_architecture(self):
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

    def print_portfwd_rules(self):
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
            
    def show_process_list(self, args):
        """
        Retrieves and prints the list of running processes.

        Returns:
            None
        """
        #https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters
        
        self.setup_dce_transport()
        self.dce_transport._connect('winreg')
        print_info("Retrieving Processes List...")
        #counter_name = "ID Process"
        arch = self.get_processor_architecture()
        self.dce_transport._connect('winreg')
        result = self.dce_transport._hQueryPerformaceData("230", int(arch))
        process_list = result[2]["Process"]
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
        print_good("Proccesses with '(uuid:<random chars>)' have duplicate names but are unique processes")

            