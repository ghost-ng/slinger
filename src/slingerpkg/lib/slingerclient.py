from slingerpkg.lib.schtasks import schtasks
from slingerpkg.lib.winreg import winreg
from slingerpkg.lib.scm import scm
from slingerpkg.lib.smblib import smblib
from slingerpkg.lib.secrets import secrets
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from slingerpkg.lib.dcetransport import *
import datetime
from impacket import smbconnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
import slingerpkg.var.config as config

dialect_mapping = {
            0x02FF: "SMB 1.0",
            0x031F: "SMB 2.0.2",
            0x0302: "SMB 2.1",
            0x0300: "SMB 3.0",
            0x0311: "SMB 3.0.2",
            0x0312: "SMB 3.1.1",
        }


class SlingerClient(winreg, schtasks, scm, smblib, secrets):
    def __init__(self, host, username, password, domain, port=445, ntlm_hash=None, use_kerberos=False):
        schtasks.__init__(self)
        winreg.__init__(self)
        scm.__init__(self)
        smblib.__init__(self)
        secrets.__init__(self)
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


    def setup_dce_transport(self):
        """
        Sets up or reuses the DCE transport for RPC communication.
        """
        if not self.dce_transport or not self.dce_transport.is_connected:
            self.dce_transport = DCETransport(self.host, self.username, self.port, self.conn)
            self.dce_transport.set_timeout(config.smb_conn_timeout)
        else:
            print_debug("Reusing existing DCE transport.")

        


    def login(self):
        print_info(f"Connecting to {self.host}:{self.port}...")
        try:
            self.conn = smbconnection.SMBConnection(self.host, self.host, sess_port=self.port, timeout=15)
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "Connection error" in str(e):
                print_bad(f"Failed to connect to {self.host}:{self.port}")
                sys.exit()

        if self.conn is None or self.conn == "":
            self.is_logged_in = False
            raise Exception("Failed to create SMB connection.")
        
        self.conn._timeout = int(config.smb_conn_timeout)

        try:
            if self.use_kerberos:
                self.conn.kerberosLogin(self.username, self.password, domain=self.domain, lmhash='', nthash='', aesKey='', TGT=None, TGS=None)
            elif self.ntlm_hash:
                # get nt and lm hashes from ntlm hash
                try:
                    nt_hash = self.ntlm_hash.split(":")[1]
                    lm_hash = self.ntlm_hash.split(":")[0]
                except IndexError:
                    print_bad("Invalid NTLM hash. Format should be LM:NT or :NT")
                    sys.exit()
                self.conn.login(self.username, self.password, domain=self.domain, lmhash=lm_hash, nthash=nt_hash)
            else:
                self.conn.login(self.username, self.password, domain=self.domain)
            print_good(f"Successfully logged in to {self.host}:{self.port}")
            GRN_BLD = '\033[1;32m'
            RST = '\033[0m'
            print("\nStart Time: " + GRN_BLD + str(self.session_start_time) + RST + "\n")
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "STATUS_LOGON_FAILURE" in str(e):
                print_bad(f"Authentication Failed {self.host}:{self.port}")
                sys.exit()
            elif "STATUS_ACCOUNT_RESTRICTION" in str(e):
                print_good("Login Successful")
                print_bad(f"Account is restricted {self.host}:{self.port}")
                sys.exit()
            else:
                print_bad(f"Login Failed {self.host}:{self.port}")
                print_log(str(e) + "\n" + str(sys.exc_info()))
            sys.exit()
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
            GRN_BLD = '\033[1;32m'
            RST = '\033[0m'
            CURRENT_TIME = datetime.datetime.now()
            print("\nStop Time: " + GRN_BLD + str(CURRENT_TIME) + RST + "\n")
            
        except:
            pass
        self.conn = None

    def is_connected_to_remote_share(self):
        return self.conn and self.is_connected_to_share

    
    def info(self, args=None):
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


    def who(self, args=None):
        """
        Executes the 'who' command to retrieve session information.
        Reuses the transport and resets it if needed.
        """
        try:
            # Setup or reuse transport
            self.setup_dce_transport()
            if "srvsvc" not in self.dce_transport.pipe:
                self.dce_transport._connect('srvsvc')
            # Execute the 'who' command
            resp = self.dce_transport._who()
            for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
                print_log("host: %15s, user: %5s, active: %5d, idle: %5d" % (
                    session['sesi10_cname'][:-1],
                    session['sesi10_username'][:-1],
                    session['sesi10_time'],
                    session['sesi10_idle_time']
                ))
        except DCERPCException as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"Failed to list sessions: {e}")
            raise e
        except Exception as e:
            # Reset the transport on unexpected errors
            print_debug(f"Unexpected error: {str(e)}. Resetting transport.", sys.exc_info())
            self.dce_transport._disconnect()
            self.setup_dce_transport()
            raise e


    def enum_server_disk(self, args=None):
        try:
            self.setup_dce_transport()
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
            print_debug(str(e), sys.exc_info())
            print_log(f"An error occurred: {str(e)}")
            raise e

    def enum_logons(self, args=None):
        self.setup_dce_transport()
        self.dce_transport._connect('wkssvc')
        response = self.dce_transport._enum_logons()
        print_info("Logged on Users:")
        for user_info in response['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
            print_log(f"Username: {user_info['wkui1_username']}")

    def enum_sys(self, args=None):
        self.setup_dce_transport()
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
 

    def enum_transport(self, args=None):
        self.setup_dce_transport()
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

    def enum_info(self, args=None):
        self.setup_dce_transport()
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
        

        # Processor Arch
        response = self.get_processor_architecture()
        print_info(f"Processor Architecture:")
        print_log(f"Architecture: {response}-bit")

        # Enumerate the server disk drives
        print_info("Server Disk Info:")
        self.enum_server_disk()
        
        # Processor Info
        print_info("Processor Info:")
        response = self._sys_proc_info(args, echo=False)
        print_log(f"Processor Name:\t{response['ProcessorNameString']}")
        print_log(f"Processor ID:\t{response['Identifier']}")
        print_log(f"Vendor ID:\t{response['VendorIdentifier']}")

        # System time
        print_info("System Time:")
        response = self._sys_time_info(args, echo=False)
        # convert the time to a readable format
        last_known_good_time_hex = response['LastKnownGoodTime']  # Example: '0x1db6cdf8f0b399a'
        # Convert hex string to an integer
        last_known_good_time_int = int(last_known_good_time_hex, 16)
        # Convert Windows File Time to seconds since UNIX epoch
        # Windows File Time is the number of 100-nanosecond intervals since January 1, 1601 UTC
        unix_time = (last_known_good_time_int - 116444736000000000) // 10000000
        # Convert to a human-readable datetime
        sys_time = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
        print_log(f"Time (UTC):\t{sys_time}")
        last_shutdown_str = self._sys_shutdown_info(args, hex_dump=True, echo=False)
        last_shutdown = datetime.datetime.strptime(last_shutdown_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
        print_log(f"Last Shutdown Time (UTC): {last_shutdown_str}")
        # calc uptime sys_time - last_shutdown
        uptime = sys_time - last_shutdown
        uptime_str = str(uptime).split(".")[0]
        print_log(f"Uptime: {uptime_str}")


    def get_server_time(self, args=None):
        #print local date and time
        time = datetime.datetime.now()
        date = datetime.date.today()
        print_info(f"Local Time: {time.hour}:{time.minute}:{time.second}")
        print_info(f"Local Date: {date.month}/{date.day}/{date.year}")

        try:
            self.setup_dce_transport()
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
            print_debug(str(e), sys.exc_info())
            print_log(f"An error occurred: {str(e)}")
            raise e


    def check_if_connected(self):
        if self.conn is None or self.is_connected_to_remote_share() is False:
            print_warning("No share is connected. Use the 'use' command to connect to a share.")
            self.is_connected_to_share = False
            return False
        self.is_connected_to_share = True
        return True
    