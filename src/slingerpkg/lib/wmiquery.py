import cmd
import json
import csv
import io
from tabulate import tabulate
from slingerpkg.utils.printlib import (
    print_debug,
    print_verbose,
    print_warning,
    print_good,
    print_bad,
    print_info,
)
from slingerpkg.utils.common import tee_output


class WMIQuery:
    """WMI Query Module - Executes WQL queries using existing WMI infrastructure"""

    def __init__(self):
        print_debug("WMIQuery Module Loaded!")
        self.current_namespace = "root/cimv2"
        self.output_format = "table"
        # WMI session reuse
        self._dcom_connection = None
        self._wmi_services = {}  # namespace -> IWbemServices objects

    def wmi_query_handler(self, args):
        """Main handler for wmiexec query command"""
        if not self.check_if_connected():
            print_warning("You must be connected to a share to use WMI queries.")
            return

        # Handle different query modes
        if hasattr(args, "interactive") and args.interactive:
            print_verbose("Starting interactive WQL shell")
            self._start_interactive_shell(args)
        elif hasattr(args, "describe") and args.describe:
            print_verbose(f"Describing WMI class: {args.describe}")
            self._describe_class(args.describe, args)
        elif hasattr(args, "list_classes") and args.list_classes:
            print_verbose("Listing available WMI classes")
            self._list_classes(args)
        elif hasattr(args, "template") and args.template:
            print_verbose(f"Executing query template: {args.template}")
            self._execute_template(args.template, args)
        elif hasattr(args, "list_templates") and args.list_templates:
            print_verbose("Listing available query templates")
            self._list_templates(args)
        elif hasattr(args, "query") and args.query:
            print_verbose(f"Executing WQL query: {args.query}")
            self._execute_single_query(args.query, args)
        else:
            print_bad("No query specified. Use --help for usage information.")

    def setup_wmi(self, namespace="root/cimv2", operation_type="query"):
        """Setup and reuse WMI connection for the session
        
        Args:
            namespace: WMI namespace to connect to
            operation_type: Type of operation ('query', 'dcom', 'event') 
                          - affects what objects are returned
        
        Returns:
            For 'query': IWbemServices object
            For 'dcom': tuple of (dcom_connection, IWbemServices)  
            For 'event': tuple of (dcom_connection, IWbemServices)
        """
        try:
            # Check if we already have a connection to this namespace
            if namespace in self._wmi_services:
                print_debug(f"Reusing existing WMI connection for namespace: {namespace}")
                iWbemServices = self._wmi_services[namespace]
                
                # Return appropriate objects based on operation type
                if operation_type in ['dcom', 'event']:
                    return (self._dcom_connection, iWbemServices)
                else:  # query
                    return iWbemServices

            # Import WMI components
            from impacket.dcerpc.v5.dcomrt import DCOMConnection
            from impacket.dcerpc.v5.dcom import wmi
            from impacket.dcerpc.v5.dtypes import NULL

            # Create DCOM connection if we don't have one
            if self._dcom_connection is None:
                print_debug("Creating new DCOM connection for WMI")
                
                # Use existing connection credentials (following wmiexec patterns)
                host = getattr(self, "host", None)
                username = getattr(self, "username", None)
                password = getattr(self, "password", "")
                domain = getattr(self, "domain", "")

                if not host:
                    raise Exception("No host connection available")

                # Handle NTLM hash parsing (following existing wmiexec patterns)
                lm_hash = ""
                nt_hash = ""
                if hasattr(self, "ntlm_hash") and self.ntlm_hash:
                    if ":" in self.ntlm_hash:
                        lm_hash, nt_hash = self.ntlm_hash.split(":")
                    else:
                        nt_hash = self.ntlm_hash

                # Create DCOM connection with full options (reused for all operations)
                self._dcom_connection = DCOMConnection(
                    host, 
                    username, 
                    password, 
                    domain, 
                    lm_hash, 
                    nt_hash,
                    aesKey="",
                    oxidResolver=True,
                    doKerberos=getattr(self, "use_kerberos", False)
                )
                print_debug("DCOM connection established for WMI session")
            else:
                print_debug("Reusing existing DCOM connection")

            # Create WMI service connection for this namespace
            print_debug(f"Connecting to WMI namespace: {namespace}")
            iInterface = self._dcom_connection.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            # Format namespace correctly for NTLMLogin
            if namespace.startswith("root/"):
                namespace_path = f"//./{namespace}"
            else:
                namespace_path = f"//./root/{namespace}"
            iWbemServices = iWbemLevel1Login.NTLMLogin(namespace_path, NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Note: Do NOT call set_credentials() after NTLMLogin() - it's already authenticated

            # Cache the service connection for this namespace
            self._wmi_services[namespace] = iWbemServices
            print_debug(f"WMI service cached for namespace: {namespace}")

            # Return appropriate objects based on operation type
            if operation_type in ['dcom', 'event']:
                return (self._dcom_connection, iWbemServices)
            else:  # query
                return iWbemServices

        except Exception as e:
            print_debug(f"WMI setup error: {e}")
            raise Exception(f"Failed to setup WMI connection: {e}")

    def cleanup_wmi(self):
        """Cleanup WMI connections when slinger session ends"""
        try:
            # Cleanup WMI service connections
            for namespace, service in self._wmi_services.items():
                try:
                    service.RemRelease()
                    print_debug(f"Released WMI service for namespace: {namespace}")
                except:
                    pass
            self._wmi_services.clear()

            # Cleanup DCOM connection
            if self._dcom_connection:
                try:
                    self._dcom_connection.disconnect()
                    print_debug("DCOM connection closed")
                except:
                    pass
                self._dcom_connection = None

        except Exception as e:
            print_debug(f"WMI cleanup error: {e}")

    def get_wmi_dcom_connection(self, namespace="root/cimv2"):
        """Get shared DCOM connection and WMI service for dcom operations"""
        return self.setup_wmi(namespace, operation_type="dcom")

    def get_wmi_event_connection(self, namespace="root/cimv2"):
        """Get shared DCOM connection and WMI service for event operations"""  
        return self.setup_wmi(namespace, operation_type="event")

    def get_wmi_query_connection(self, namespace="root/cimv2"):
        """Get shared WMI service for query operations"""
        return self.setup_wmi(namespace, operation_type="query")

    def _execute_single_query(self, wql_query, args):
        """Execute a single WQL query"""
        try:
            # Use existing WMI connection infrastructure from wmiexec
            host = getattr(self, "host", "Unknown")
            user = getattr(self, "username", "Unknown")
            print_verbose(f"Executing WQL query on {host} as {user}")

            # Set namespace if specified
            namespace = getattr(args, "namespace", self.current_namespace)
            output_format = getattr(args, "format", self.output_format)
            output_file = getattr(args, "output", None)

            print_debug(f"Query: {wql_query}")
            print_debug(f"Namespace: {namespace}")
            print_debug(f"Format: {output_format}")

            # Execute the query using setup_wmi() for connection reuse
            results = self._run_wql_query(wql_query, namespace)

            if results:
                # Format and display results
                formatted_output = self._format_results(results, output_format)
                
                if output_file:
                    # Use existing tee_output system for file output
                    with tee_output(output_file):
                        print(formatted_output)
                    print_good(f"Query results saved to: {output_file}")
                else:
                    print(formatted_output)
                    
                print_info(f"Query returned {len(results)} result(s)")
            else:
                print_warning("Query returned no results")

        except Exception as e:
            print_bad(f"WQL query failed: {str(e)}")
            print_debug(f"Exception details: {e}")

    def _run_wql_query(self, wql_query, namespace="root/cimv2"):
        """Execute WQL query using setup_wmi() for connection reuse"""
        try:
            # Use setup_wmi() to get/reuse WMI connection
            iWbemServices = self.setup_wmi(namespace)

            # Execute query
            print_debug(f"Executing WQL: {wql_query}")
            iEnumWbemClassObject = iWbemServices.ExecQuery(wql_query)

            # Process results
            results = []
            while True:
                try:
                    pEnum = iEnumWbemClassObject.Next(0xffffffff, 1)[0]
                    record = pEnum.getProperties()
                    results.append(record)
                    pEnum.RemRelease()
                except Exception:
                    break

            # Only cleanup the enumerator, keep the service connection for reuse
            iEnumWbemClassObject.RemRelease()

            print_debug(f"Query completed, {len(results)} results")
            return results

        except Exception as e:
            print_debug(f"WQL query error: {e}")
            raise

    def _describe_class(self, class_name, args):
        """Describe a WMI class schema"""
        try:
            namespace = getattr(args, "namespace", self.current_namespace)
            print_info(f"Describing class '{class_name}' in namespace '{namespace}'")

            # Use setup_wmi() to get/reuse WMI connection
            iWbemServices = self.setup_wmi(namespace)

            # Get class object
            iObject, _ = iWbemServices.GetObject(class_name)
            
            # Display class information
            print_good(f"Class: {class_name}")
            iObject.printInformation()

            # Cleanup only the object, keep service connection for reuse
            iObject.RemRelease()

        except Exception as e:
            print_bad(f"Failed to describe class '{class_name}': {str(e)}")
            print_debug(f"Exception details: {e}")

    def _list_classes(self, args):
        """List available WMI classes in namespace"""
        try:
            namespace = getattr(args, "namespace", self.current_namespace)
            print_info(f"Listing classes in namespace '{namespace}'")

            # Query for available classes
            wql_query = "SELECT * FROM meta_class"
            results = self._run_wql_query(wql_query, namespace)

            if results:
                class_names = []
                for result in results:
                    if '__CLASS' in result:
                        class_names.append(result['__CLASS']['value'])

                class_names.sort()
                
                # Display in columns
                print_good(f"Available classes in {namespace}:")
                for i, class_name in enumerate(class_names):
                    if i % 3 == 0:
                        print()
                    print(f"{class_name:<30}", end="")
                print()
                print_info(f"Total classes: {len(class_names)}")
            else:
                print_warning("No classes found")

        except Exception as e:
            print_bad(f"Failed to list classes: {str(e)}")
            print_debug(f"Exception details: {e}")

    def _execute_template(self, template_name, args):
        """Execute a predefined query template"""
        templates = self._get_query_templates()
        template_name = template_name.lower()
        
        if template_name in templates:
            query = templates[template_name]
            print_info(f"Executing template '{template_name}': {query}")
            self._execute_single_query(query, args)
        else:
            print_bad(f"Template '{template_name}' not found")
            print_info("Available templates:")
            self._list_templates(args)

    def _list_templates(self, args):
        """List available query templates"""
        templates = self._get_query_templates()
        print_good("Available query templates:")
        for name, query in templates.items():
            print(f"  {name:<12} - {query}")
        print_info(f"Total templates: {len(templates)}")
        print_info("Usage: wmiexec query --template <name>")

    def _format_results(self, results, output_format):
        """Format query results in specified format"""
        if not results:
            return "No results"

        if output_format.lower() == "json":
            return self._format_json(results)
        elif output_format.lower() == "csv":
            return self._format_csv(results)
        else:  # Default to table
            return self._format_table(results)

    def _format_table(self, results):
        """Format results as a table"""
        if not results:
            return "No results"

        # Extract headers from first result
        headers = list(results[0].keys())
        
        # Extract data rows
        rows = []
        for result in results:
            row = []
            for header in headers:
                value = result.get(header, {}).get('value', 'N/A')
                if isinstance(value, list):
                    value = ', '.join(str(item) for item in value)
                row.append(str(value) if value is not None else 'NULL')
            rows.append(row)

        return tabulate(rows, headers=headers, tablefmt="grid")

    def _format_json(self, results):
        """Format results as JSON"""
        json_results = []
        for result in results:
            json_result = {}
            for key, value_dict in result.items():
                if isinstance(value_dict, dict) and 'value' in value_dict:
                    json_result[key] = value_dict['value']
                else:
                    json_result[key] = value_dict
            json_results.append(json_result)
        
        return json.dumps(json_results, indent=2, default=str)

    def _format_csv(self, results):
        """Format results as CSV"""
        if not results:
            return "No results"

        output = io.StringIO()
        headers = list(results[0].keys())
        writer = csv.writer(output)
        writer.writerow(headers)

        for result in results:
            row = []
            for header in headers:
                value = result.get(header, {}).get('value', 'N/A')
                if isinstance(value, list):
                    value = ', '.join(str(item) for item in value)
                row.append(str(value) if value is not None else 'NULL')
            writer.writerow(row)

        return output.getvalue()

    def _start_interactive_shell(self, args):
        """Start interactive WQL shell"""
        print_info("Starting interactive WQL shell")
        print_info("Type 'help' for available commands, 'exit' to quit")
        
        shell = WQLShell(self, args)
        shell.cmdloop()

    def _get_query_templates(self):
        """Return predefined query templates"""
        return {
            "processes": "SELECT Name, ProcessId, ParentProcessId, CommandLine FROM Win32_Process",
            "services": "SELECT Name, State, StartMode, PathName FROM Win32_Service",
            "users": "SELECT Name, FullName, LocalAccount, Disabled FROM Win32_UserAccount",
            "network": "SELECT Description, IPAddress, MACAddress FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
            "software": "SELECT Name, Version, Vendor, InstallDate FROM Win32_Product",
            "drives": "SELECT DeviceID, Size, FreeSpace, FileSystem FROM Win32_LogicalDisk",
            "startup": "SELECT Name, Command, Location FROM Win32_StartupCommand",
            "shares": "SELECT Name, Path, Description FROM Win32_Share",
            "hotfixes": "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering",
            "environment": "SELECT Name, VariableValue FROM Win32_Environment WHERE SystemVariable = False"
        }


class WQLShell(cmd.Cmd):
    """Interactive WQL shell for WMI queries"""
    
    def __init__(self, wmi_query_instance, args):
        super().__init__()
        self.wmi_query = wmi_query_instance
        self.args = args
        self.prompt = 'WQL> '
        self.intro = '[!] Interactive WQL Shell - Type help for commands'

    def do_help(self, line):
        """Show help information"""
        if not line:
            print("""
Available Commands:
  help                    - Show this help
  exit                    - Exit interactive shell
  describe <class>        - Describe WMI class schema
  namespace <namespace>   - Change current namespace (default: root/cimv2)
  format <format>         - Set output format (table, json, csv)
  template <name>         - Execute predefined query template
  templates               - List available query templates
  ! <command>             - Execute local shell command

WQL Query Examples:
  SELECT * FROM Win32_Process
  SELECT Name, ProcessId FROM Win32_Process WHERE Name = 'notepad.exe'
  SELECT * FROM Win32_Service WHERE State = 'Running'
  SELECT Name FROM Win32_UserAccount
            """)
        else:
            # Show help for specific command
            super().do_help(line)

    def do_exit(self, line):
        """Exit the WQL shell"""
        print_info("Exiting WQL shell")
        return True

    def do_quit(self, line):
        """Exit the WQL shell"""
        return self.do_exit(line)

    def do_describe(self, class_name):
        """Describe a WMI class: describe Win32_Process"""
        if not class_name:
            print_bad("Usage: describe <class_name>")
            return
        
        # Create temporary args for describe
        temp_args = type('Args', (), {})()
        temp_args.namespace = getattr(self.args, "namespace", "root/cimv2")
        
        self.wmi_query._describe_class(class_name.strip(), temp_args)

    def do_namespace(self, namespace):
        """Change current namespace: namespace root/standardcimv2"""
        if not namespace:
            print_info(f"Current namespace: {self.wmi_query.current_namespace}")
            return
        
        self.wmi_query.current_namespace = namespace.strip()
        print_good(f"Namespace changed to: {namespace.strip()}")

    def do_format(self, format_type):
        """Set output format: format json"""
        if not format_type:
            print_info(f"Current format: {self.wmi_query.output_format}")
            return
        
        format_type = format_type.strip().lower()
        if format_type in ['table', 'json', 'csv']:
            self.wmi_query.output_format = format_type
            print_good(f"Output format set to: {format_type}")
        else:
            print_bad("Invalid format. Use: table, json, or csv")

    def do_template(self, template_name):
        """Execute a predefined query template: template processes"""
        if not template_name:
            print_bad("Usage: template <template_name>")
            print_info("Use 'templates' command to see available templates")
            return
        
        templates = self.wmi_query._get_query_templates()
        template_name = template_name.strip().lower()
        
        if template_name in templates:
            query = templates[template_name]
            print_info(f"Executing template '{template_name}': {query}")
            self._execute_query(query)
        else:
            print_bad(f"Template '{template_name}' not found")
            print_info("Use 'templates' command to see available templates")

    def do_templates(self, line):
        """List available query templates"""
        templates = self.wmi_query._get_query_templates()
        print_good("Available query templates:")
        for name, query in templates.items():
            print(f"  {name:<12} - {query}")

    def do_shell(self, command):
        """Execute local shell command: ! ls -la"""
        import os
        os.system(command)

    def default(self, line):
        """Execute WQL query"""
        if line.strip():
            self._execute_query(line.strip())

    def _execute_query(self, query):
        """Execute a WQL query in the shell context"""
        try:
            # Create temporary args for query execution
            temp_args = type('Args', (), {})()
            temp_args.namespace = getattr(self.args, "namespace", self.wmi_query.current_namespace)
            temp_args.format = self.wmi_query.output_format
            temp_args.output = None  # No file output in interactive mode
            
            self.wmi_query._execute_single_query(query, temp_args)
        except KeyboardInterrupt:
            print_info("\nQuery interrupted")
        except Exception as e:
            print_bad(f"Query execution failed: {str(e)}")