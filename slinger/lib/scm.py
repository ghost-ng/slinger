from slinger.utils.printlib import *
from slinger.lib.dcetransport import *
import traceback
from tabulate import tabulate
import traceback
import sys

class scm():

    def __init__(self):
        print_debug("Service Control Module Loaded!")
        self.services_list = []

    def filter_services(self, filtered):
        # filter format: name=blah, state=blah
        new_list = []
        if "state" in filtered:
            state = filtered.split("=")[1]
            for service in self.services_list:
                if service[3].lower() == state.lower():
                    new_list.append(service)
            return new_list
        elif "name" in filtered:
            name = filtered.split("=")[1]
            for service in self.services_list:
                if name.lower() in service[1].lower():
                    new_list.append(service)
            return new_list
        else:
            return self.services_list
    
    def show_service_handler(self, args):
        if not self.services_list and args.serviceid:
            print_warning("No services have been enumerated. Run enumservices first.")
        else:
            service_arg = args.serviceid if args.serviceid else args.service_name
            self.view_service_details(service_arg)

    def start_service_handler(self, args):
        if not self.services_list and args.serviceid:
            print_warning("No services have been enumerated. Run enumservices first.")
        else:
            service_arg = args.serviceid if args.serviceid else args.service_name
            self.start_service(service_arg)

    def start_service(self, service_arg):
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print_log("Searching through %d services" % len(self.services_list))
            for service in self.services_list:
                #print_info("Checking service %d" % count)
                if count == service_arg:
                    service_name = service[1]
                    break                    
                count += 1
        else:
            print_info("Getting service details for %s" % service_arg)
            service_name = service_arg
            
        if service_name is None:
            print_warning("Service name not found")
            return
        else:
            print_info("Chosen Service: " + service_name)
        try:
            response = self.dce_transport._start_service(service_name)
            if response['ErrorCode'] == 0:
                print_good("Service started successfully")
            else:
                print_log(f"Error starting service '{service_name}': {response['ErrorCode']}")
        except Exception as e:
            if "ERROR_SERVICE_ALREADY_RUNNING" in str(e):
                print_bad("Unable to start service: " + service_name)
                print_warning("Service already running")
                return
            elif "ERROR_SERVICE_DISABLED" in str(e):
                print_bad("Unable to start service: " + service_name)
                print_warning("Service disabled")
                return
            elif "ERROR_SERVICE_LOGON_FAILED" in str(e):
                print_bad("Unable to start service: " + service_name)
                print_warning("Service logon failed")
                return
            elif "ERROR_SERVICE_DOES_NOT_EXIST" in str(e):
                print_bad("Unable to start service: " + service_name)
                print_warning("Service does not exist")
                return
            else:
                print_bad("Unable to start service: " + service_name)
                print_bad("An error occurred:" + str(e))
                print_debug('', sys.exc_info())

    def service_stop_handler(self, args):
        if not self.services_list and args.serviceid:
            print_warning("No services have been enumerated. Run enumservices first.")
        else:
            service_arg = args.serviceid if args.serviceid else args.service_name
            self.stop_service(service_arg)

    def stop_service(self, service_arg):
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print_log("Searching through %d services" % len(self.services_list))
            for service in self.services_list:
                #print_info("Checking service %d" % count)
                if count == service_arg:
                    service_name = service[1]
                    break                    
                count += 1
        else:
            print_info("Getting service details for %s" % service_arg)
            service_name = service_arg
            
        try:
            if service_name is None:
                print_warning("Service name not found")
                return
            else:
                print_info("Chosen Service: " + service_name)
            response = self.dce_transport._stop_service(service_name)
            if response['ErrorCode'] == 0:
                print_good("Service stopped successfully")
            else:
                print_log(f"Error stopping service '{service_name}': {response['ErrorCode']}")
        except Exception as e:
            if "ERROR_SERVICE_NOT_ACTIVE" in str(e):
                print_bad("Unable to stop service: " + service_name)
                print_warning("Service not active")
                return
            elif "ERROR_SERVICE_DOES_NOT_EXIST" in str(e):
                print_bad("Unable to stop service: " + service_name)
                print_warning("Service does not exist")
                return
            else:
                print_bad("Unable to start service: " + service_name)
                print_bad("An error occurred:" + str(e))
                print_debug('', sys.exc_info())

    def enum_services(self, args):
        force = args.new
        filtered = args.filter
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        if force or len(self.services_list) == 0:
            
            print_info("Enumerating services...")
            response = self.dce_transport._enum_services()
        else:
            print_info("Using stored services list...")
            new_list = []
            if filtered:
                print_info("Filtering services...")
                # pass the list through the filter
                new_list = self.filter_services(filtered)
            else:
                new_list = self.services_list
            
            # Print the DataFrame using tabulate
            print_log(tabulate(new_list, headers=['ID','Service Name', 'Display Name', 'State'], tablefmt='psql'))
            print_log("Total Services: %d" % len(self.services_list))
            if new_list:
                print_log("Filtered Services: %d" % len(new_list))
            return
        count = 1
        self.services_list = []
        for i in range(len(response)):
            state = response[i]['ServiceStatus']['dwCurrentState']
            if state == scmr.SERVICE_CONTINUE_PENDING:
                state_str = "CONTINUE PENDING"
            elif state == scmr.SERVICE_PAUSE_PENDING:
                state_str = "PAUSE PENDING"
            elif state == scmr.SERVICE_PAUSED:
                state_str = "PAUSED"
            elif state == scmr.SERVICE_RUNNING:
                state_str = "RUNNING"
            elif state == scmr.SERVICE_START_PENDING:
                state_str = "START PENDING"
            elif state == scmr.SERVICE_STOP_PENDING:
                state_str = "STOP PENDING"
            elif state == scmr.SERVICE_STOPPED:
                state_str = "STOPPED"
            else:
                state_str = "UNKNOWN"

            # Add the data to the list
            self.services_list.append([count, response[i]['lpServiceName'][:-1], response[i]['lpDisplayName'][:-1], state_str])
            count += 1

        new_list = []
        if filtered:
            print_info("Filtering services...")
            # pass the list through the filter
            new_list = self.filter_services(filtered)
        else:
            new_list = self.services_list

        print_log(tabulate(new_list, headers=['ID','Service Name', 'Display Name', 'State'], tablefmt='psql'))
        print_info("Total Services: %d" % len(self.services_list))
        if new_list:
            print_log("Filtered Services: %d" % len(new_list))
        

    def view_service_details(self, service_arg):
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print_log("Searching through %d services" % len(self.services_list))
            for service in self.services_list:
                #print_info("Checking service %d" % count)
                if count == service_arg:
                    service_name = service[1]
                    break                    
                count += 1
        else:
            print_info("Getting service details for %s" % service_arg)
            service_name = service_arg
            
        try:
            if service_name is None:
                print_warning("Service name not found")
                return
            else:
                print_info("Chosen Service: " + service_name)
            resp, resp2 = self.dce_transport._get_service_details(service_name)
            if resp['ErrorCode'] == 0:
                print_log("TYPE              : %2d - " % resp['lpServiceConfig']['dwServiceType'], end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x1:
                    print_log("SERVICE_KERNEL_DRIVER ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x2:
                    print_log("SERVICE_FILE_SYSTEM_DRIVER ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x10:
                    print_log("SERVICE_WIN32_OWN_PROCESS ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x20:
                    print_log("SERVICE_WIN32_SHARE_PROCESS ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x100:
                    print_log("SERVICE_INTERACTIVE_PROCESS ", end=' ')
                print_log("")
                print_log("START_TYPE        : %2d - " % resp['lpServiceConfig']['dwStartType'], end=' ')
                if resp['lpServiceConfig']['dwStartType'] == 0x0:
                    print_log("BOOT START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x1:
                    print_log("SYSTEM START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x2:
                    print_log("AUTO START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x3:
                    print_log("DEMAND START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x4:
                    print_log("DISABLED")
                else:
                    print_log("UNKNOWN")

                print_log("ERROR_CONTROL     : %2d - " % resp['lpServiceConfig']['dwErrorControl'], end=' ')
                if resp['lpServiceConfig']['dwErrorControl'] == 0x0:
                    print_log("IGNORE")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x1:
                    print_log("NORMAL")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x2:
                    print_log("SEVERE")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x3:
                    print_log("CRITICAL")
                else:
                    print_log("UNKNOWN")
                print_log("BINARY_PATH_NAME  : %s" % resp['lpServiceConfig']['lpBinaryPathName'][:-1])
                print_log("LOAD_ORDER_GROUP  : %s" % resp['lpServiceConfig']['lpLoadOrderGroup'][:-1])
                print_log("TAG               : %d" % resp['lpServiceConfig']['dwTagId'])
                print_log("DISPLAY_NAME      : %s" % resp['lpServiceConfig']['lpDisplayName'][:-1])
                print_log("DEPENDENCIES      : %s" % resp['lpServiceConfig']['lpDependencies'][:-1])
                print_log("SERVICE_START_NAME: %s" % resp['lpServiceConfig']['lpServiceStartName'][:-1])
            if resp2['ErrorCode'] == 0:
                print_log("SERVICE_STATUS    : ", end="")
                state = resp2['lpServiceStatus']['dwCurrentState']
                if state == scmr.SERVICE_CONTINUE_PENDING:
                    print_log("CONTINUE PENDING")
                elif state == scmr.SERVICE_PAUSE_PENDING:
                    print_log("PAUSE PENDING")
                elif state == scmr.SERVICE_PAUSED:
                    print_log("PAUSED")
                elif state == scmr.SERVICE_RUNNING:
                    print_log("RUNNING")
                elif state == scmr.SERVICE_START_PENDING:
                    print_log("START PENDING")
                elif state == scmr.SERVICE_STOP_PENDING:
                    print_log("STOP PENDING")
                elif state == scmr.SERVICE_STOPPED:
                    print_log("STOPPED")
                else:
                    print_log("UNKNOWN")
            else:
                print_log(f"Error retrieving service '{service_name}': {resp['ErrorCode']}")
        except Exception as e:
            if "ERROR_SERVICE_DOES_NOT_EXIST" in str(e):
                print_warning("Service does not exist")
                exc_type, exc_value, exc_traceback = sys.exc_info()
                
                # Extracting the line number and other details
                tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
                error_message = ''.join(tb_lines)
                print_debug(error_message)
                return

            print_bad("Unable to view service details: " + service_name)
            print_bad("An error occurred:" + str(e))
            print_debug('', sys.exc_info())
    
    def service_del_handler(self, args):
        if not self.services_list and args.serviceid:
            print_warning("No services have been enumerated. Run enumservices first.")
        else:
            service_arg = args.serviceid if args.serviceid else args.service_name
            self.delete_service(service_arg)

    def delete_service(self, service_arg):
        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print_log("Searching through %d services" % len(self.services_list))
            for service in self.services_list:
                #print_info("Checking service %d" % count)
                if count == service_arg:
                    service_name = service[1]
                    break                    
                count += 1
        else:
            service_name = service_arg
            
        try:
            if service_name is None:
                print_warning("Service name not found")
                return
            else:
                print_info("Chosen Service: " + service_name)
            response = self.dce_transport._delete_service(service_name)
            if response['ErrorCode'] == 0:
                print_good("Service deleted successfully")
            else:
                print_log(f"Error deleting service '{service_name}': {response['ErrorCode']}")
        except Exception as e:
            print_bad("Unable to delete service: " + service_name)
            print_bad("An error occurred:" + str(e))
            print_debug('', sys.exc_info())

    def create_service(self, args):
        service_name = args.servicename
        bin_path = args.binarypath
        display_name = args.displayname
        start_type = args.starttype

        self.setup_dce_transport()
        self.dce_transport._connect('svcctl')
        
        try:
            print_info("Creating service...")
            response = self.dce_transport._create_service(service_name, bin_path, start_type, display_name)
            if response['ErrorCode'] == 0:
                print_good("Service created successfully")
            else:
                print_log(f"Error creating service '{service_name}': {response['ErrorCode']}")
        except Exception as e:
            print_bad("Unable to create service: " + service_name)
            print_bad("An error occurred:" + str(e))
            print_debug('', sys.exc_info())
        
        
        
        
        
