from slinger.lib.schtasks import schtasks
from slinger.lib.winreg import winreg
from slinger.lib.scm import scm
from slinger.lib.smblib import smblib
from slinger.utils.printlib import *
from slinger.utils.common import *
from slinger.lib.dcetransport import *
import datetime
from impacket import smbconnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
import slinger.var.config as config

dialect_mapping = {
            0x02FF: "SMB 1.0",
            0x031F: "SMB 2.0.2",
            0x0302: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0311: "SMB 3.0.2",
            0x0312: "SMB 3.1.1",
        }


class SlingerClient(winreg, schtasks, scm, smblib):
    def __init__(self, host, username, password, domain, port=445, ntlm_hash=None, use_kerberos=False):
        schtasks.__init__(self)
        winreg.__init__(self)
        scm.__init__(self)
        smblib.__init__(self)
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.ntlm_hash = ntlm_hash
        self.use_kerberos = use_kerberos
        self.conn = None
        self.share = None
        self.current_path = ''
        self.tree_id = None
        self.relative_path = ''
        self.is_connected_to_share = False
        self.is_logged_in = False
        self.port = port
        self.session_start_time = datetime.datetime.now()
        self.dialect = None
        self.smb_version = None
        self.dce_transport = None
        self.srvsvc_pipe = None
        self.wkssvc_pipe = None
    
    


    def login(self):
        self.conn = smbconnection.SMBConnection(self.host, self.host, sess_port=self.port)
        
        if self.conn is None or self.conn == "":
            self.is_logged_in = False
            raise Exception("Failed to create SMB connection.")
        if self.use_kerberos:
            self.conn.kerberosLogin(self.username, self.password, domain=self.domain, lmhash='', nthash='', aesKey='', TGT=None, TGS=None)
        elif self.ntlm_hash:
            self.conn.loginWithHash(self.username, self.ntlm_hash, domain=self.domain)
        else:
            self.conn.login(self.username, self.password, domain=self.domain)
        #set a large timeout
        self.conn.timeout = config.smb_conn_timeout
        self.is_logged_in = True
        self.dialect = self.conn.getDialect()
        self.smb_version = dialect_mapping.get(self.dialect, "Unknown")
        try:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        except Exception as e:
            print_bad(f"Unable to setup DCE transport: {e}")
            raise e
        
        self.dce_transport._enable_remote_registry()
       

    # handle exit
    def exit(self):
        try:
            self.dce_transport._disconnect()
            self.conn.logoff()
            
        except:
            pass
        self.conn = None

    def is_connected_to_remote_share(self):
        return self.conn and self.is_connected_to_share

    
    def info(self):
        dialect_mapping = {
            0x02FF: "SMB 1.0",
            0x031F: "SMB 2.0.2",
            0x0302: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0311: "SMB 3.0.2",
            0x0312: "SMB 3.1.1",
        }
        dialect = self.conn.getDialect()
        smb_version = dialect_mapping.get(dialect, "Unknown")
        print_log(f"Remote Name: {self.conn.getRemoteName()}")
        print_log(f"Remote Host: {self.conn.getRemoteHost()}")
        print_log(f"SMB Version: {smb_version}")
        print_log(f"Connected: {self.is_connected_to_share}")
        if self.is_connected_to_share:
            print_log(f"Share: {self.share}")
            print_log(f"Current Path: {self.current_path}")
        
        print_log(f"Logged in: {self.is_logged_in}")
        print_log(f"Total time of session: {datetime.datetime.now() - self.session_start_time}")

    

    def who(self):

        try:
            if self.dce_transport is None:
                self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
            self.dce_transport._connect('srvsvc')
            resp = self.dce_transport._who()
            for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                    print_log("host: %15s, user: %5s, active: %5d, idle: %5d" % (
                    session['sesi10_cname'][:-1], session['sesi10_username'][:-1], session['sesi10_time'],
                    session['sesi10_idle_time']))
        except DCERPCException as e:
             print_bad(f"Failed to list sessions: {e}")
             raise e

    def enum_server_disk(self):
        try:
            if self.dce_transport is None:
                self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
            self.dce_transport._connect('srvsvc')
            
            response = self.dce_transport._enum_server_disk()
            if response['ErrorCode'] == 0:  # Checking for successful response
                disk_enum = response['DiskInfoStruct']['Buffer']
                print_log("Disk Drives:")
                for disk in disk_enum:
                    print_log(f"  {disk['Disk']}  ", end="")
                print_log()
            else:
                print_log(f"Error: {response['ErrorCode']}")
        except Exception as e:
            print_log(f"An error occurred: {str(e)}")
            raise e

    def enum_logons(self):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('wkssvc')
        response = self.dce_transport._enum_logons()
        print_info("Logged on Users:")
        for user_info in response['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            print_log(f"Username: {user_info['wkui1_username']}")

    def enum_sys(self):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('wkssvc')
        response = self.dce_transport._enum_sys()
        # Assuming you have a response from NetrWkstaGetInfo
        info = response['WkstaInfo']['WkstaInfo102']

        print_log("Workstation Information:")
        print_log(f"Platform ID: {info['wki102_platform_id']}")
        print_log(f"Computer Name: {info['wki102_computername']}")
        print_log(f"Domain Name: {info['wki102_langroup']}")
        print_log(f"Version Major: {info['wki102_ver_major']}")
        print_log(f"Version Minor: {info['wki102_ver_minor']}")
        print_log(f"Logged-on Users: {info['wki102_logged_on_users']}")
 

    def enum_transport(self):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('wkssvc')
        response = self.dce_transport._enum_transport()
        transports = response['TransportInfo']['WkstaTransportInfo']['Level0']['Buffer']


        print_info("Transport Information:")
        for transport in transports:
            print_log(f"Quality Of Service: {transport['wkti0_quality_of_service']}")
            print_log(f"Number of VCs: {transport['wkti0_number_of_vcs']}")

            # Decode the transport name and address from bytes to string
            transport_name = transport['wkti0_transport_name']
            transport_address = transport['wkti0_transport_address']

            print_log(f"Transport Name: {transport_name}")
            readable_mac_address = ':'.join(transport_address[i:i+2] for i in range(0, len(transport_address), 2))
            print_log(f"Readable Transport Address (MAC): {readable_mac_address}")
            print_log(f"WAN ISH: {transport['wkti0_wan_ish']}")
            print_log()

    def enum_info(self):
        if self.dce_transport is None:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
        self.dce_transport._connect('srvsvc')
        response = self.dce_transport._enum_info()
        #print_log(response.dump())
        print_info("Server Info:")
        info = response['InfoStruct']['ServerInfo101']
        print_log(f"Server name: {info['sv101_name']}")
        print_log(f"Server platform id: {info['sv101_platform_id']}")
        print_log(f"Server version: {info['sv101_version_major']}.{info['sv101_version_minor']}")
        print_log(f"Server type: {info['sv101_type']}")
        print_log(f"Server comment: {info['sv101_comment']}")
        print_info("Server Disk Info:")
        self.enum_server_disk()


    def get_server_time(self):
        #print local date and time
        time = datetime.datetime.now()
        date = datetime.date.today()
        print_info(f"Local Time: {time.hour}:{time.minute}:{time.second}")
        print_info(f"Local Date: {date.month}/{date.day}/{date.year}")

        try:
            if self.dce_transport is None:
                    self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
            self.dce_transport._connect('srvsvc')
            response = self.dce_transport._fetch_server_time()
            if response['ErrorCode'] == 0:  # Checking for successful response
                tod_info = response['BufferPtr']
                # Server current time
                hours = tod_info['tod_hours']
                minutes = tod_info['tod_mins']
                seconds = tod_info['tod_secs']
                current_time = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                
                tod_info = response['BufferPtr']
                uptime_seconds = int(tod_info['tod_elapsedt']) // 1000
                uptime_hours = uptime_seconds // 3600
                uptime_minutes = (uptime_seconds % 3600) // 60
                uptime = f"{uptime_hours} hours, {uptime_minutes} minutes"

                 # Server timezone
                tz_minutes = int(tod_info['tod_timezone'])
                tz_hours, tz_mins = divmod(abs(tz_minutes), 60)
                tz_sign = '+' if tz_minutes >= 0 else '-'
                timezone = f"UTC{tz_sign}{tz_hours:02d}:{tz_mins:02d}"

                # Display the extracted information
                print_info(f"Server Time: {current_time}")
                print_info(f"Server Uptime: {uptime}")
                print_info(f"Server Timezone: {timezone}")


            else:
                print_log(f"Error: {response['ErrorCode']}")
        except Exception as e:
            print_log(f"An error occurred: {str(e)}")
            raise e


    def check_if_connected(self):
        if self.conn is None or self.is_connected_to_remote_share() is False:
            print_warning("No share is connected. Use the 'use' command to connect to a share.")
            self.is_connected_to_share = False
            return False
        self.is_connected_to_share = True
        return True
    