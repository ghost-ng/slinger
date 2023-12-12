from ..utils.printlib import *
from .dcetransport import *
import traceback
from tabulate import tabulate
import traceback

class scm():

    def __init__(self):
        print_good("Service Control Module Loaded!")
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
        
    def start_service(self, service_arg):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print("Searching through %d services" % len(self.services_list))
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
            try:
                response = self.dce_transport._start_service(service_name)
                if response['ErrorCode'] == 0:
                    print_good("Service started successfully")
                else:
                    print(f"Error starting service '{service_name}': {response['ErrorCode']}")
            except Exception as e:
                if "ERROR_SERVICE_ALREADY_RUNNING" in str(e):
                    print_warning("Service already running")
                    self.winreg_already_setup = True
                    return
            
        except Exception as e:
            print_bad("Unable to start service: " + service_name)
            print_bad("An error occurred:")
            traceback.print_exc()

    def stop_service(self, service_arg):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print("Searching through %d services" % len(self.services_list))
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
                print(f"Error stopping service '{service_name}': {response['ErrorCode']}")
        except Exception as e:
            print_bad("Unable to stop service: " + service_name)
            print_bad("An error occurred:")
            traceback.print_exc()

    def enum_services(self, force=False, filtered=None):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
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
            print(tabulate(new_list, headers=['ID','Service Name', 'Display Name', 'State'], tablefmt='psql'))
            print("Total Services: %d" % len(self.services_list))
            if new_list:
                print("Filtered Services: %d" % len(new_list))
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

        print(tabulate(new_list, headers=['ID','Service Name', 'Display Name', 'State'], tablefmt='psql'))
        print_info("Total Services: %d" % len(self.services_list))
        if new_list:
            print("Filtered Services: %d" % len(new_list))
        

    def view_service_details(self, service_arg):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('svcctl')
        
        # lookup taskpath and task name from dict with task_id
        service_name = None
        if type(service_arg) is int:
            print_info("Looking up service ID...")
            count = 1
            #print("Searching through %d services" % len(self.services_list))
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
                print("TYPE              : %2d - " % resp['lpServiceConfig']['dwServiceType'], end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x1:
                    print("SERVICE_KERNEL_DRIVER ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x2:
                    print("SERVICE_FILE_SYSTEM_DRIVER ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x10:
                    print("SERVICE_WIN32_OWN_PROCESS ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x20:
                    print("SERVICE_WIN32_SHARE_PROCESS ", end=' ')
                if resp['lpServiceConfig']['dwServiceType'] & 0x100:
                    print("SERVICE_INTERACTIVE_PROCESS ", end=' ')
                print("")
                print("START_TYPE        : %2d - " % resp['lpServiceConfig']['dwStartType'], end=' ')
                if resp['lpServiceConfig']['dwStartType'] == 0x0:
                    print("BOOT START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x1:
                    print("SYSTEM START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x2:
                    print("AUTO START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x3:
                    print("DEMAND START")
                elif resp['lpServiceConfig']['dwStartType'] == 0x4:
                    print("DISABLED")
                else:
                    print("UNKNOWN")

                print("ERROR_CONTROL     : %2d - " % resp['lpServiceConfig']['dwErrorControl'], end=' ')
                if resp['lpServiceConfig']['dwErrorControl'] == 0x0:
                    print("IGNORE")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x1:
                    print("NORMAL")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x2:
                    print("SEVERE")
                elif resp['lpServiceConfig']['dwErrorControl'] == 0x3:
                    print("CRITICAL")
                else:
                    print("UNKNOWN")
                print("BINARY_PATH_NAME  : %s" % resp['lpServiceConfig']['lpBinaryPathName'][:-1])
                print("LOAD_ORDER_GROUP  : %s" % resp['lpServiceConfig']['lpLoadOrderGroup'][:-1])
                print("TAG               : %d" % resp['lpServiceConfig']['dwTagId'])
                print("DISPLAY_NAME      : %s" % resp['lpServiceConfig']['lpDisplayName'][:-1])
                print("DEPENDENCIES      : %s" % resp['lpServiceConfig']['lpDependencies'][:-1])
                print("SERVICE_START_NAME: %s" % resp['lpServiceConfig']['lpServiceStartName'][:-1])
            if resp2['ErrorCode'] == 0:
                print("SERVICE_STATUS    : ", end="")
                state = resp2['lpServiceStatus']['dwCurrentState']
                if state == scmr.SERVICE_CONTINUE_PENDING:
                    print("CONTINUE PENDING")
                elif state == scmr.SERVICE_PAUSE_PENDING:
                    print("PAUSE PENDING")
                elif state == scmr.SERVICE_PAUSED:
                    print("PAUSED")
                elif state == scmr.SERVICE_RUNNING:
                    print("RUNNING")
                elif state == scmr.SERVICE_START_PENDING:
                    print("START PENDING")
                elif state == scmr.SERVICE_STOP_PENDING:
                    print("STOP PENDING")
                elif state == scmr.SERVICE_STOPPED:
                    print("STOPPED")
                else:
                    print("UNKNOWN")
            else:
                print(f"Error retrieving service '{service_name}': {resp['ErrorCode']}")
        except Exception as e:
            print_bad("Unable to view service details: " + service_name)
            print_bad("An error occurred:")
            traceback.print_exc()
        
        
        
        
        
        
        
