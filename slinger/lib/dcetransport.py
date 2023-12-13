from impacket.dcerpc.v5 import transport, rrp, srvs, wkst, tsch, scmr
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from impacket.dcerpc.v5.tsch import TASK_FLAG_HIDDEN
import os, traceback
from ..utils.printlib import *
from ..utils.common import *
from impacket.structure import hexdump
from struct import unpack, pack
from impacket.system_errors import ERROR_NO_MORE_ITEMS
from impacket.dcerpc.v5.dtypes import READ_CONTROL


def parse_lp_data(valueType, valueData, hex_dump=True):
    result = ""
    try:
        if valueType == rrp.REG_SZ or valueType == rrp.REG_EXPAND_SZ:
            if type(valueData) is int:
                result += 'NULL'
            else:
                result += "%s" % (valueData.decode('utf-16le')[:-1])
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
        result += 'Invalid data'
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
            response = self._start_service('RemoteRegistry', bind=False)
            self.rrpstarted = True
            self.rrpshouldStop = True
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
        abs_path = abs_path .replace(r'\\', chr(92))
        print_log(f"Creating Task: {abs_path}")
        # Register the task
        # tsch.hSchRpcRegisterTask(dce, '\\%s' % tmpName, xml, tsch.TASK_CREATE, NULL, tsch.TASK_LOGON_NONE)
            
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
                print_bad("An error occurred:")
                traceback.print_exc()
            return
        serviceHandle = ans['lpServiceHandle']
        response = scmr.hRStartServiceW(self.dce, serviceHandle)
        self._close_scm_handle(serviceHandle)
        if service_name == "RemoteRegistry":
            self.rrpstarted = True
        return response

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
                print_bad("An error occurred:")
                traceback.print_exc()
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
        ans = scmr.hROpenServiceW(self.dce, svcHandle, serviceName)
        svcHandle = ans['lpServiceHandle']
        # Let's check its status
        ans = scmr.hRQueryServiceStatus(self.dce, svcHandle)
        if ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_STOPPED:
            print_info('Service %s is in stopped state' % serviceName)
            return False
        elif ans['lpServiceStatus']['dwCurrentState'] == scmr.SERVICE_RUNNING:
            print_info('Service %s is already running' % serviceName)
            return True
        else:
            raise Exception('Unknown service state 0x%x - Aborting' % ans['CurrentState'])

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
        while True:
            try:
                #self.bind_override = True
                #self._bind(rrp.MSRPC_UUID_RRP)
                key = rrp.hBaseRegEnumKey(self.dce, ans2['phkResult'], i)
                #print_log(keyName + '\\' + key['lpNameOut'][:-1])
                subkeys.append(keyName + '\\' + key['lpNameOut'][:-1])
                i += 1
            except Exception as e:
                print_debug(str(e))
                break
        return subkeys
    
    def _get_key_handle(self, keyName, bind=True):
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
        
    def _get_key_values(self, keyName, hex_dump=True, bind=True):
        if not self.is_connected:
            raise Exception("Not connected to remote host")
        self._bind(rrp.MSRPC_UUID_RRP)
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
                #print_log('\t' + lp_value_name + '\t' + self.regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t', end=' ')
                res = '\t' + lp_value_name + '\t' + self.regValues.get(lp_type, 'KEY_NOT_FOUND') + '\t'
                #print_log(res, end='')
                res = res + parse_lp_data(lp_type, lp_data, hex_dump=hex_dump)
                key_value = key_value + res + '\n'
                i += 1
            except rrp.DCERPCSessionError as e:
                if e.get_error_code() == ERROR_NO_MORE_ITEMS:
                    print_debug(str(e))
                    break
        return key_value

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
            print_log('Successfully set key %s\\%s of type %s to value %s' % (
                keyName, valueName, valueType, valueData
            ))
        else:
            print_log('Error 0x%08x while setting key %s\\%s of type %s to value %s' % (
                ans3['ErrorCode'], keyName, valueName, valueType, valueData
            ))
