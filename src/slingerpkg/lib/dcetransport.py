import base64
import string
import time
from impacket.dcerpc.v5 import transport, rrp, srvs, wkst, tsch, scmr, rpcrt
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5.tsch import TASK_FLAG_HIDDEN
import os
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from impacket.structure import hexdump
from struct import unpack, pack
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.dcerpc.v5.dtypes import READ_CONTROL
import sys
from slingerpkg.lib.msrpcperformance import *
from impacket.dcerpc.v5.rrp import DCERPCSessionError
from impacket import system_errors, LOG

def parse_lp_data(valueType, valueData, hex_dump=True):
    result = ""
    try:
        if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
            if type(valueData) is int:
                result += 'NULL'
            else:
                #result += "%s" % (valueData.decode('utf-16le')[:-1])
                result += "%s" % (valueData.decode('utf-16le')[::])
        elif valueType == rrp.REG_BINARY:
            result += ''
            if hex_dump:
                result += hexdump(valueData, '\t')
        elif valueType == rrp.REG_DWORD:
            result += "0x%x" % (unpack('<L', valueData)[0])
        elif valueType == rrp.REG_QWORD:
            result += "0x%x" % (unpack('<Q', valueData)[0])
        elif valueType == rrp.REG_NONE:
            try:
                if len(valueData) > 1:
                    result += ''
                    if hex_dump:
                        result += hexdump(valueData, '\t')
                else:
                    result += " NULL"
            except:
                result += " NULL"
        elif valueType == rrp.REG_MULTI_SZ:
            result += "%s" % (valueData.decode('utf-16le')[:-2])
        else:
            result += "Unknown Type 0x%x!" % valueType
            if hex_dump:
                result += hexdump(valueData)
    except Exception as e:
        result += 'Exception thrown when printing reg value %s' % str(e)
        line_num = sys.exc_info()[-1].tb_lineno
        print_debug(f"Error in parsing reg data: {str(e)}", line_num)
        result += 'Invalid data'
        print_debug("LP Data Parsing Error",sys.exc_info())
    return result



class DCETransport:
    def __init__(self, host, username, port, smb_connection):
        self.host = host
        self.port = port
        self.username = username
        self.conn = smb_connection
        self.pipe = None
        self.dce = None
        self.is_connected = False
        self.scManagerHandle = None
        self.regValues = {0: 'REG_NONE', 1: 'REG_SZ', 2: 'REG_EXPAND_SZ', 3: 'REG_BINARY', 4: 'REG_DWORD',
                            5: 'REG_DWORD_BIG_ENDIAN', 6: 'REG_LINK', 7: 'REG_MULTI_SZ', 11: 'REG_QWORD'}
        self.rrp_bind = False
        self.current_bind = None
        self.bind_override = False
        self.winregSetupComplete = False
        self.rrpshouldStop = False
        self.rrpstarted = False
        self.share = None

    def _bind(self, bind_uuid):
        #retrieve plaintext from uuids
        plaintext = uuid_endpoints.get(bind_uuid)
        if plaintext is None:
            raise Exception("Unrecognized endpoint uuid for bind operations")
        
        if bind_uuid == self.current_bind and not self.bind_override:
            print_debug(f"Already bound to {plaintext} rpc endpoint")
            return
        else:
            self.dce.bind(bind_uuid)
            self.bind_override = False
            self.current_bind = bind_uuid
            print_debug(f"Successful bind to {plaintext} rpc endpoint")

    def _connect(self, named_pipe):
        self.pipe = "\\" + named_pipe
        if self.conn is None:
            raise Exception("SMB connection is not initialized")
        rpctransport = transport.SMBTransport(self.conn.getRemoteHost(), filename = self.pipe, smb_connection = self.conn)
        self.dce = rpctransport.get_dce_rpc()
        self.dce.connect()
        
        self.is_connected = True
        # fail safe is case something happened to the RemoteRegistry Service
        if named_pipe == "winreg" and not self.rrpstarted:
            self._enable_remote_registry()

    def _enable_remote_registry(self):
        print_info("Checking the status of the RemoteRegistry service")
        response = self._checkServiceStatus("RemoteRegistry")
        if response:
            self.rrpshouldStop = False
            self.rrpstarted = True
        else:
            print_info("Trying to start RemoteRegistry service")
            self._connect('svcctl')
            response = self._start_service('RemoteRegistry', bind=True)
            if response == "DISABLED":
                self.rrpshouldDisable = True
                print_bad("Remote Registry service is disabled")
                self._connect('svcctl')
                print_info("Trying to enable RemoteRegistry service")
                _ = self._enable_service("RemoteRegistry")
                _ = self._start_service('RemoteRegistry', bind=False)
                print_info("Checking the status of the RemoteRegistry service")
                response = self._checkServiceStatus("RemoteRegistry")
                if response:
                    self.rrpshouldStop = True
                    self.rrpstarted = True
                    print_good("Remote Registry service started")

    def _close_scm_handle(self, serviceHandle):
        try:
            scmr.hRCloseServiceHandle(self.dce, serviceHandle)
        except:
            pass

    def _disconnect(self):
        if self.rrpshouldStop:
            self._connect('svcctl')
            self._stop_service("RemoteRegistry")
            print_info("Remote Registy state restored -> STOPPED")
        if self.rrpshouldDisable:
            self._connect('svcctl')
            self._disable_service("RemoteRegistry")
            print_info("Remote Registy state restored -> DISABLED")
        self.dce.disconnect()
        self.is_connected = False

    def _who(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self._bind(srvs.MSRPC_UUID_SRVS)
        return srvs.hNetrSessionEnum(self.dce, NULL, NULL, 10)

    
    def _enum_server_disk(self):
        # NetrServerDiskEnum
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(srvs.MSRPC_UUID_SRVS)
        response = srvs.hNetrServerDiskEnum(self.dce, 0)
        # The response contains a list of disk drives
        return response
    
    def _enum_info(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(srvs.MSRPC_UUID_SRVS)
        response = srvs.hNetrServerGetInfo(self.dce, 101)
        return response
    

    def _enum_logons(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(wkst.MSRPC_UUID_WKST)
        response = wkst.hNetrWkstaUserEnum(self.dce, 1)
        return response
    
    def _enum_sys(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(wkst.MSRPC_UUID_WKST)
        response = wkst.hNetrWkstaGetInfo(self.dce, 102)
        return response

    def _enum_transport(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self._bind(wkst.MSRPC_UUID_WKST)
        response = wkst.hNetrWkstaTransportEnum(self.dce, 0)
        return response
        
    def _fetch_server_time(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(srvs.MSRPC_UUID_SRVS)
        return srvs.hNetrRemoteTOD(self.dce)
    
    def _enum_folders(self, folder_path='\\', index=0):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
        
        response = tsch.hSchRpcEnumFolders(self.dce, folder_path, index, NULL)
        return response


    def _view_tasks_in_folder(self, folder_path='\\'):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
            
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
        response = tsch.hSchRpcEnumTasks(self.dce, folder_path, flags=tsch.TASK_ENUM_HIDDEN)
        return response

    def _view_tasks(self, task_name, folder_path):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
        abs_path = os.path.normpath(folder_path + "\\" + task_name).replace(r'\\', chr(92)) 
        print_log(f"Retrieving Task: {abs_path}")
        response = tsch.hSchRpcRetrieveTask(self.dce, abs_path)

        return response


    def _create_task(self, task_name, folder_path, task_xml):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
         # Flags and parameters for task creation
        flags = tsch.TASK_CREATE | tsch.TASK_FLAG_SYSTEM_REQUIRED | tsch.TASK_FLAG_HIDDEN
        sddl = ''  # Security descriptor definition language string (empty string for default permissions)
        abs_path = folder_path + "\\" + task_name
        abs_path = abs_path.replace(r'\\', chr(92))

        response = tsch.hSchRpcRegisterTask(self.dce, abs_path, task_xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
        return response

    def _run_task(self, abs_path):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
        #abs_path = folder_path + "\\" + task_name
        #abs_path = abs_path .replace(r'\\', chr(92))
        print_log(f"Running Task: {abs_path}")
        response = tsch.hSchRpcRun(self.dce, abs_path)
        return response

    def _delete_task(self, abs_path):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
        self.bind_override = True
        self._bind(tsch.MSRPC_UUID_TSCHS)
        print_info(f"Deleting Task: {abs_path}")
        response = tsch.hSchRpcDelete(self.dce, abs_path)
        return response

    def _enum_services(self):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        response = scmr.hREnumServicesStatusW(self.dce, self.scManagerHandle)
        self._close_scm_handle(self.scManagerHandle)
        return response

    def _disable_service(self, service_name):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        self.serviceHandle = ans['lpServiceHandle']
        try:
            response = scmr.hRChangeServiceConfigW(self.dce, self.serviceHandle, dwStartType=scmr.SERVICE_DISABLED)
            self._close_scm_handle(self.serviceHandle)
            if response['ErrorCode'] == 0:
                return True
            else:
                return False
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_ACCESS_DENIED" in str(e):
                print_bad("Unable to change service configuration, access denied")
            else:
                print_bad("An error occurred: " + str(e))
            return False

    def _enable_service(self, service_name):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        self.serviceHandle = ans['lpServiceHandle']
        try:
            response = scmr.hRChangeServiceConfigW(self.dce, self.serviceHandle, dwStartType=scmr.SERVICE_AUTO_START)
            self._close_scm_handle(self.serviceHandle)
            if response['ErrorCode'] == 0:
                return True
            else:
                return False
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_ACCESS_DENIED" in str(e):
                print_bad("Unable to change service configuration, access denied")
            else:
                print_bad("An error occurred: " + str(e))
            return False

    def _get_service_details(self, service_name):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        self.serviceHandle = ans['lpServiceHandle']
        resp1 = scmr.hRQueryServiceConfigW(self.dce, self.serviceHandle)
        resp2 = scmr.hRQueryServiceStatus(self.dce, self.serviceHandle)
        self._close_scm_handle(self.serviceHandle)
        return resp1, resp2

    

    def _start_service(self, service_name, bind=True):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        if bind:        # this is needed, do not remove - again........
            self.bind_override = True
            self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        try:
            ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                print_bad("Unable to connect to service, access denied")
            else:
                raise e
            return
        serviceHandle = ans['lpServiceHandle']
        try:
            response = scmr.hRStartServiceW(self.dce, serviceHandle)
            self._close_scm_handle(serviceHandle)
            if service_name == "RemoteRegistry":
                self.rrpstarted = True
            if response['ErrorCode'] == 0:
                
                return True
        except Exception as e:
            if "ERROR_SERVICE_DISABLED" in str(e):
                return "DISABLED"
            elif "ERROR_SERVICE_ALREADY_RUNNING" in str(e):
                return "RUNNING"
            elif "ERROR_ACCESS_DENIED" in str(e):
                print_bad("Unable to start service, access denied")
                return False
            else:
                print_debug(str(e), sys.exc_info())
                return False
            
        

    def _stop_service(self, service_name):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        try:
            ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                print_bad("Unable to connect to service, access denied")
            else:
                print_bad("An error occurred: " + str(e))
                print_debug('', sys.exc_info())
            return
        serviceHandle = ans['lpServiceHandle']
        response = scmr.hRControlService(self.dce, serviceHandle, scmr.SERVICE_CONTROL_STOP)
        self._close_scm_handle(serviceHandle)
        if service_name == "RemoteRegistry":
            self.rrpstarted = False
        return response
    
    def _checkServiceStatus(self, serviceName):
        self._connect('svcctl')
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        # Open SC Manager
        ans = scmr.hROpenSCManagerW(self.dce)
        svcHandle = ans['lpScHandle']
        # Now let's open the service
        try:
            ans = scmr.hROpenServiceW(self.dce, svcHandle, serviceName)
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                print_bad("Unable to connect to service, access denied")
            else:
                print_bad("An error occurred: " + str(e))
                print_debug('', sys.exc_info())
            return
        svcHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.dce, svcHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            print_info('Service %s is in a stopped state' % serviceName)
            return False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            print_info('Service %s is already running' % serviceName)
            return True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

    def _delete_service(self, service_name):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        try:
            ans = scmr.hROpenServiceW(self.dce, self.scManagerHandle, service_name + '\x00')
        except Exception as e:
            if "rpc_s_access_denied" in str(e):
                print_bad("Unable to connect to service, access denied")
            else:
                print_bad("An error occurred: " + str(e))
                print_debug('', sys.exc_info())
            return
        serviceHandle = ans['lpServiceHandle']
        response = scmr.hRDeleteService(self.dce, serviceHandle)
        self._close_scm_handle(serviceHandle)
        return response

    def _create_service(self, service_name, bin_path, start_type, display_name=None):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(scmr.MSRPC_UUID_SCMR)
        ans = scmr.hROpenSCManagerW(self.dce)
        self.scManagerHandle = ans['lpScHandle']
        if display_name is None:
            display_name = service_name     

        try:
            if start_type == 'auto':
                start_type = scmr.SERVICE_AUTO_START
            elif start_type == 'demand':
                start_type = scmr.SERVICE_DEMAND_START
            elif start_type == 'system':
                start_type = scmr.SERVICE_SYSTEM_START
        except AttributeError:
            start_type = scmr.SERVICE_DEMAND_START

        response = scmr.hRCreateServiceW(self.dce, self.scManagerHandle, service_name, display_name, 
                                         dwServiceType=scmr.SERVICE_WIN32_OWN_PROCESS, dwErrorControl=scmr.SERVICE_ERROR_IGNORE, lpBinaryPathName=bin_path, dwStartType=start_type)
        return response

    def _get_boot_key(self):
        bootKey = b''
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        ans = rrp.hOpenLocalMachine(self.dce)
        regHandle = ans['phKey']
        for key in ['JD','Skew1','GBG','Data']:
            print_debug(f"Opening 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\{key}'")
            ans = rrp.hBaseRegOpenKey(self.dce, regHandle, 'SYSTEM\\CurrentControlSet\\Control\\Lsa\\%s' % key)
            keyHandle = ans['phkResult']
            ans = rrp.hBaseRegQueryInfoKey(self.dce,keyHandle)
            # bootKey = bootKey + b(ans['lpClassOut'][:-1])
            bootKey = bootKey + bytes(ans['lpClassOut'][:-1], 'utf-8')
            rrp.hBaseRegCloseKey(self.dce, keyHandle)
        return bootKey

    def _save_hive(self, hiveName):
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        #tmpFileName = ''.join([random.choice(string.ascii_letters) for _ in range(8)]) + '.tmp'
        # TS_57CB.tmp pattern
        tmpFileName = 'TS_' + ''.join([random.choice(string.ascii_uppercase + string.digits) for _ in range(4)]) + '.tmp'
        ans = rrp.hOpenLocalMachine(self.dce)
        regHandle = ans['phKey']
        try:
            ans = rrp.hBaseRegCreateKey(self.dce, regHandle, hiveName)
        except:
            raise Exception("Can't open %s hive" % hiveName)
        keyHandle = ans['phkResult']
        savePath = ""
        absPath = ""
        if self.share.upper() == "ADMIN$":
            absPath = "ADMIN$" + "\\Temp\\" + tmpFileName
            savePath = "..\\Temp\\" + tmpFileName
        elif self.share.upper() == "C$":
            absPath = "C$" + "\\Windows\\Temp\\" + tmpFileName
            savePath = "\\Windows\\Temp\\" + tmpFileName

        try:
            ans = rrp.hBaseRegSaveKey(self.dce, keyHandle, savePath)
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "ERROR_PATH_NOT_FOUND" in str(e):
                print_bad("Unable to save hive, path not found")
            return None
        rrp.hBaseRegCloseKey(self.dce, keyHandle)
        rrp.hBaseRegCloseKey(self.dce, regHandle)

        return tmpFileName

    def _get_root_key(self, keyName):
        # Let's strip the root key
        try:
            rootKey = keyName.split('\\')[0]
            subKey = '\\'.join(keyName.split('\\')[1:])
        except Exception as e:
            print_debug(str(e))
            raise Exception('Error parsing keyName %s' % keyName)
        if rootKey.upper() == 'HKLM':
            ans = rrp.hOpenLocalMachine(self.dce)
        elif rootKey.upper() == 'HKCU':
            ans = rrp.hOpenCurrentUser(self.dce)
        elif rootKey.upper() == 'HKU':
            ans = rrp.hOpenUsers(self.dce)
        elif rootKey.upper() == 'HKCR':
            ans = rrp.hOpenClassesRoot(self.dce)
        else:
            raise Exception('Invalid root key %s ' % rootKey)
        hRootKey = ans['phKey']
        return hRootKey, subKey
    
    def _enum_subkeys(self, keyName, bind=True):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        hRootKey, subKey = self._get_root_key(keyName)
        ans2 = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)
        i = 0
        subkeys = []
        #self.bind_override = True
        #self._bind(rrp.MSRPC_UUID_RRP)
        while True:
            try:
                #self.bind_override = True
                #self._bind(rrp.MSRPC_UUID_RRP)
                key = rrp.hBaseRegEnumKey(self.dce, ans2['phkResult'], i)
                #print_log(keyName + '\\' + key['lpNameOut'][:-1])
                subkeys.append(reduce_slashes(keyName + '\\' + key['lpNameOut'][:-1]))
                i += 1
                
            except Exception as e:
                print_debug(str(e), sys.exc_info())
                break
        return subkeys
    
    def _get_key_handle(self, keyName):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        #self._connect('winreg')
        
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        #print_log(type(keyName))

        hRootKey, subKey = self._get_root_key(keyName)
        ans = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                   samDesired=rrp.MAXIMUM_ALLOWED | rrp.KEY_ENUMERATE_SUB_KEYS | rrp.KEY_QUERY_VALUE)
        hKey = ans['phkResult']
        return hKey
        
    def _get_key_values(self, keyName, hex_dump=True):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        #self.bind_override = True
        #self._bind(rrp.MSRPC_UUID_RRP)
        key_value = ""
        res = ""
        i = 0
        while True:
            try:
                #self._bind(rrp.MSRPC_UUID_RRP)
                ans4 = rrp.hBaseRegEnumValue(self.dce, keyName, i)
                lp_value_name = ans4['lpValueNameOut'][:-1]
                if len(lp_value_name) == 0:
                    lp_value_name = '(Default)'
                lp_type = ans4['lpType']
                lp_data = b''.join(ans4['lpData'])
                #t = lp_data.decode('utf-16le')
                #print(t)
                #lp_data = t
                #lp_data = b''.join(t)

                #print(lp_data.decode('utf-16le'))
                
                #print_log('\t' + lp_value_name + '\t' + self.regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t', end=' ')
                res = '\t' + lp_value_name + '\t' + self.regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t'
                #print_log(res, end='')
                res = res + parse_lp_data(lp_type, lp_data, hex_dump=hex_dump)
                key_value = key_value + res + '\n'
                i += 1
                #self.bind_override = True
                #self._bind(rrp.MSRPC_UUID_RRP)
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    print_debug(str(e))
                    break
            except Exception as e:
                print_debug(str(e), sys.exc_info())
                break
        return key_value

    def _get_binary_data(self, keyName, valueName):
        """
        Retrieves binary data from the specified registry key.

        Args:
            keyName: Registry key name.
            valueName: Value name to retrieve binary data.

        Returns:
            The binary data, or raises an exception if retrieval fails.
        """
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)

        hRootKey, subKey = self._get_root_key(keyName)
        try:
            ans2 = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                    samDesired=READ_CONTROL | rrp.KEY_QUERY_VALUE)
            ans3 = rrp.hBaseRegQueryValue(self.dce, ans2['phkResult'], valueName)

            # Extract binary data (assume it's the second element of the tuple)
            if isinstance(ans3, tuple) and len(ans3) > 1:
                return ans3[1]
            else:
                raise ValueError("Unexpected data structure for ans3: {ans3}")
        except Exception as e:
            print_debug(f"Error in _get_binary_data: {str(e)}", sys.exc_info())
            raise



    def _reg_add(self, keyName, valueName, valueData, valueType, bind=True):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        hRootKey, subKey = self._get_root_key(keyName)
        ans2 = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                       samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)

        dwType = getattr(rrp, valueType, None)

        if dwType is None or not valueType.startswith('REG_'):
            raise Exception('Error parsing value type %s' % valueType)

        #Fix (?) for packValue function
        if dwType in (
            rrp.REG_DWORD, rrp.REG_DWORD_BIG_ENDIAN, rrp.REG_DWORD_LITTLE_ENDIAN,
            rrp.REG_QWORD, rrp.REG_QWORD_LITTLE_ENDIAN
        ):
            valueData = int(valueData)
        else:
            pass
        ans3 = rrp.hBaseRegSetValue(
            self.dce, ans2['phkResult'], valueName, dwType, valueData
        )

        if ans3['ErrorCode'] == 0:
            print_debug('Successfully set key %s\\%s of type %s to value %s' % (
                keyName, valueName, valueType, valueData
            ))
            return True
        else:
            print_debug('Error 0x%08x while setting key %s\\%s of type %s to value %s' % (
                ans3['ErrorCode'], keyName, valueName, valueType, valueData
            ))
            return False

    def _reg_delete_value(self, keyName, valueName):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        hRootKey, subKey = self._get_root_key(keyName)
        ans2 = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                       samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
        ans3 = rrp.hBaseRegDeleteValue(self.dce, ans2['phkResult'], valueName)
        if ans3['ErrorCode'] == 0:
            print_debug('Successfully deleted value %s from key %s' % (valueName, keyName))
            return True
        else:
            print_debug('Error 0x%08x while deleting value %s from key %s' % (ans3['ErrorCode'], valueName, keyName))
            return False
        
    def _reg_delete_key(self, keyName):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        hRootKey, subKey = self._get_root_key(keyName)
        subKey = '\\'.join(subKey.split('\\')[:-1])
        ans2 = rrp.hBaseRegOpenKey(self.dce, hRootKey, subKey,
                                       samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
        try:
            ans3 = rrp.hBaseRegDeleteKey(self.dce, hRootKey, subKey)

        except rpcrt.DCERPCException as e:
            if e.error_code == 5:
                #TODO: Check if DCERPCException appears only because of existing subkeys
                print('Cannot delete key %s. Possibly it contains subkeys or insufficient privileges' % keyName)
                return
            else:
                raise
        except Exception as e:
            print_warning('Unhandled exception while hBaseRegDeleteKey')
            print_debug('Unhandled exception while hBaseRegDeleteKey',sys.exc_info())
            return
        
        if ans3['ErrorCode'] == 0:
            print_debug('Successfully deleted key %s' % keyName)
            return True
        else:
            print_debug('Error 0x%08x while deleting key %s' % (ans3['ErrorCode'], keyName))
            return False
        
    def _reg_create_key(self, keyName):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        self._bind(rrp.MSRPC_UUID_RRP)
        hRootKey, subKey = self._get_root_key(keyName)
        ans2 = rrp.hBaseRegCreateKey(self.dce, hRootKey, subKey,
                                       samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)
        if ans2['ErrorCode'] == 0:
            print_debug('Successfully created key %s' % keyName)
            return True
        else:
            print_debug('Error 0x%08x while creating key %s' % (ans2['ErrorCode'], keyName))
            return False
    
    def _GetTitleDatabase(self, arch=64):
                
        result = {}
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        try:
            self._bind(rrp.MSRPC_UUID_RRP)
        except:
            pass

        # Open Performance Data
        openhkpd_result = rrp.hOpenPerformanceData(self.dce)
                
        queryvalue_result = rrp.hBaseRegQueryValue(self.dce, openhkpd_result['phKey'], lpValueName="Counter 009")

        pos = 0
        result = {}

        status, pos, result['title_database'] = parse_perf_title_database(queryvalue_result[1], pos)
        # print the title database using tabulate
        if status:
            return result['title_database']
        else:
            return None
        

    def _hQueryPerformaceData(self, object_num, arch=64):
        print_warning("Performance Data querying is experimental and is still under development")
        if arch == 64:
            print_debug("Setting 64-bit architecture in hQueryPerformaceData")
            bitwise = True
        else:
            print_debug("Setting 32-bit architecture in hQueryPerformaceData")
            bitwise = False 
        
        result = {}
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self.bind_override = True
        try:
            self._bind(rrp.MSRPC_UUID_RRP)
        except:
            pass

        # Open Performance Data
        openhkpd_result = rrp.hOpenPerformanceData(self.dce)
        
        queryvalue_result = rrp.hBaseRegQueryValue(self.dce, openhkpd_result['phKey'], lpValueName="Counter 009")

        pos = 0
        result = {}

        status, pos, result['title_database'] = parse_perf_title_database(queryvalue_result[1], pos)

        result['title_database'][0] = "<null>"  # correct up to here
        #sort numerically by key
        result['title_database'] = dict(sorted(result['title_database'].items(), key=lambda item: item[0]))
        #print(result['title_database']) 
        perfmon_name = result['title_database'][int(object_num)]
        print_info(f"Querying Performance Data for {perfmon_name} (#{object_num})")
        queryvalue_result =rrp.hBaseRegQueryValue(self.dce, openhkpd_result['phKey'], object_num, 600000)

        pos = 0
        status, pos, data_block = parse_perf_data_block(queryvalue_result[1], pos)
        # store values in a list    
        dbg_perf_block_list = []    
        for key, value in data_block.items():
            dbg_perf_block_list.append(f"{key} : {str(value)}")

        # print list with \n as separator
        s = "\n".join(dbg_perf_block_list)
        print_debug(f"Data Block: \n{s}")

        if not status:
            print("Error parsing data block")
            return False, pos
        
        print_debug(f"Found #{data_block['NumObjectTypes']} object types")
        for i in range(data_block['NumObjectTypes']):
            
            object_start = pos

            counter_definitions = {}
            object_instances = {}

            # Get the type of the object
            
            status, pos, object_type = parse_perf_object_type(queryvalue_result[1], pos, is_64bit=bitwise)    # correct up to here
            print_debug(f"Object #{i} - Object Type: " + str(object_type), sys.exc_info())
            print_debug(f"New Position: {pos}")

            # Validate DefinitionLength
            if object_type['DefinitionLength'] > len(queryvalue_result[1]):
                print_warning(f"DefinitionLength {object_type['DefinitionLength']} exceeds available data size {len(queryvalue_result[1])}")
                print_debug(f"Object Type: {object_type}")
                pos = object_start + object_type['TotalByteLength']
                continue

            # Ensure the position calculation stays within bounds
            if pos + object_type['DefinitionLength'] > len(queryvalue_result[1]):
                print_warning("Position after adding DefinitionLength exceeds available data")
                print_debug(f"Object Start: {object_start}, Current Pos: {pos}, DefinitionLength: {object_type['DefinitionLength']}")
                pos = object_start + object_type['TotalByteLength']
                continue

            object_name = result['title_database'][object_type['ObjectNameTitleIndex']]

            print_debug(f"Object #{i} - Object Name: " + str(object_name), sys.exc_info())
            

            if not status:
                return False, pos

            if object_type['ObjectNameTitleIndex'] == 0:
                print_debug("Skipping object type with index 0")
                pos = object_start + object_type['TotalByteLength']
                continue
            
            result[object_name] = {}    # correct up to here

            # Bring the position to the beginning of the counter definitions
            pos = object_start + object_type['HeaderLength']

            # Parse the counter definitions
            print_debug("Found NumCounters: " + str(object_type['NumCounters']))
            if object_type['NumCounters'] > 0:
                for j in range(object_type['NumCounters']):
                    status, pos, counter_definitions[j] = parse_perf_counter_definition(queryvalue_result[1], pos, is_64bit=bitwise)
                    print_debug("Current Position after Counter Definition: " + str(pos))
                    print_debug("Found Counter Definition: " + str(counter_definitions[j]))
                    if not status:
                        print_debug("Error parsing counter definitions", sys.exc_info())
                        return False, pos

                print_debug("Counter Definitions: \n" + str(counter_definitions))  # correct up to here
            else:
                print_debug("No counter definitions found")            

            # Check if we have any instances
            print_debug("Found NumInstances: " + str(object_type['NumInstances']))
            if object_type['NumInstances'] > 0:

                # Bring the position to the beginning of the instances (or counters)
                pos = object_start + object_type['DefinitionLength']
                # Parse the object instances and counters
                for j in range(object_type['NumInstances']):
                    print_debug(f"Instance #{j}")
                    instance_start = pos

                    # Instance definition
                    print_debug("Current Position for Instance Definition: " + str(pos))
                    status, pos, object_instances[j] = parse_perf_instance_definition(queryvalue_result[1], pos)       # this works
                    print_debug("Instance Definition: " + str(object_instances[j]))
                    if not status:
                        print_debug("Error parsing instance definitions", sys.exc_info())
                        return False, pos

                    # Set up the instance array
                    instance_name = object_instances[j]['InstanceName']
                    print_debug(f"Instance Name: " + str(instance_name))
                    # check if the instance name already exists
                    if instance_name in result[object_name]:
                        instance_name = instance_name + " (uuid:" + generate_random_string(6) + ")"
                    result[object_name][instance_name] = {}
                    #print_info(f"Added: result[{object_name}][{instance_name}]")

                    # Bring the pos to the start of the counter block
                    pos = instance_start + object_instances[j]['ByteLength']

                    # The counter block
                    status, pos, counter_block = parse_perf_counter_block(queryvalue_result[1], pos)
                    
                    if not status:
                        print_debug("Error parsing counter block", sys.exc_info())
                        return False, pos
                    #print_info("NumCounters: " + str(object_type['NumCounters']))
                    print_debug("NumCounters: " + str(object_type['NumCounters']), sys.exc_info())
                    for k in range(object_type['NumCounters']):
                        
                        # Each individual counter
                        status, pos, counter_result = parse_perf_counter_data(queryvalue_result[1], pos, counter_definitions[k])
                        if not status:
                            print_debug("Error parsing counter", sys.exc_info())
                            return False, pos

                        counter_name = result['title_database'][counter_definitions[k]['CounterNameTitleIndex']]
                        print_debug(f"#{k} Counter Name: " + str(counter_name), sys.exc_info())
                        result[object_name][instance_name][counter_name] = counter_result

                    # Bring the pos to the end of the next section
                    
                    pos = instance_start + object_instances[j]['ByteLength'] + counter_block['ByteLength']
            else:  # if NumInstances == 0
                #https://learn.microsoft.com/en-us/windows/win32/perfctrs/performance-data-format
                # start at the end of the PERF_COUNTER_DEFINITIONS and PERF_OBJECT_TYPE
                print_debug(f"Found NumInstances == 0")

                # Calculate the total length of all counter definitions
                total_counter_definitions_length = sum(cd['ByteLength'] for cd in counter_definitions.values())

                # Calculate the start position of the counter block
                counter_block_start = object_start + object_type['HeaderLength'] + total_counter_definitions_length
                initial_counter_block_pos = object_start + object_type['HeaderLength'] + total_counter_definitions_length

                # Calculate padding if needed
                padding_needed = (8 - (initial_counter_block_pos % 8)) % 8

                # Final position of the PERF_COUNTER_BLOCK, considering padding for alignment
                final_counter_block_pos = initial_counter_block_pos + padding_needed


                # these should be the same
                print_debug("Object Start: " + str(object_start))
                print_debug("Initial Counter Block Start: " + str(initial_counter_block_pos))
                print_debug("Final Counter Block Start: " + str(final_counter_block_pos))
                print_debug("Original Position: " + str(pos))

                # Parse the PERF_COUNTER_BLOCK
                #https://learn.microsoft.com/en-us/windows/win32/api/winperf/ns-winperf-perf_counter_block
                
                status, pos, counter_block = parse_perf_counter_block_test(queryvalue_result[1], final_counter_block_pos)
                #status, pos, counter_block = parse_perf_counter_block(queryvalue_result[1], final_counter_block_pos)
                print_debug("Counter Block: " + str(counter_block))
                
                if not status:
                    # Handle error
                    print_debug("Error parsing counter block", sys.exc_info())
                    return False, pos
                print_debug("New Position: " + str(pos))

                # Start parsing the counter data
                print_debug("NumCounters: " + str(object_type['NumCounters']))

                

                for k in range(object_type['NumCounters']):
                    counter_def = counter_definitions[k]
                    counter_name = result['title_database'][counter_definitions[k]['CounterNameTitleIndex']]

                    print_debug(f"#{k} Counter Name: " + str(counter_name))
                    
                    # Bring the pos to the start of the counter

                    #print_debug(f"Counter Block Start: {counter_block_start + counter_def['CounterOffset']} = {counter_block_start} + {counter_def['CounterOffset']}")
                    #counter_block_start = counter_block_start + counter_def['CounterOffset']
                    
                    #status, pos, counter_result = parse_perf_counter_data(queryvalue_result[1], counter_block_start, counter_def)


                    # change position to start of counter block
                    counter_data_start = counter_block_start + counter_def['CounterOffset']

                    # Now set pos to this position
                    pos = counter_data_start

                    status, pos, counter_result = parse_perf_counter_data(queryvalue_result[1], pos, counter_def)

                    if not status:
                        # Handle error
                        print_debug("Error parsing counter", sys.exc_info())
                        result[object_name][counter_name] = "<null>"
                        continue
                        #return False, pos

                    print_debug("Counter Result: " + str(counter_result))

                    # Store counter result
                    result[object_name][counter_name] = counter_result

                
                
                # Update pos after processing all counters
                #pos = counter_block_start + counter_block['ByteLength']


                print_debug("Exiting Counter Definitions Loop")
            

                
        return True, pos, result

    