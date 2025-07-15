"""
Named Pipe Enumeration Module for Slinger

This module provides functionality to enumerate named pipes on Windows systems
via SMB connections. It implements multiple enumeration methods and preserves
existing share connections by default.
"""

import logging
from typing import List
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5 import transport, epm

from ..utils.printlib import *


class NamedPipe:
    """Represents a discovered named pipe with metadata"""

    def __init__(self, name: str, pipe_type: str = "unknown", description: str = ""):
        self.name = name
        self.pipe_type = pipe_type
        self.description = description
        self.full_path = f"\\\\pipe\\{name}" if not name.startswith("\\\\pipe\\") else name

    def __repr__(self):
        return f"NamedPipe(name='{self.name}', type='{self.pipe_type}')"


class NamedPipeEnumerator:
    """Enumerates named pipes using multiple methods while preserving connections"""

    # Comprehensive named pipes categorized by function - extensive Windows pipe database
    PIPE_CATEGORIES = {
        "administrative": {
            "lsarpc": "Local Security Authority RPC",
            "lsass": "Local Security Authority Subsystem Service",
            "samr": "Security Account Manager RPC",
            "svcctl": "Service Control Manager RPC",
            "winreg": "Windows Registry RPC",
            "atsvc": "AT Service Scheduler",
            "trkwks": "Distributed Link Tracking Workstation",
            "keysvc": "Cryptographic Key Service",
            "protected_storage": "Protected Storage Service",
            "policyagent": "IPSec Policy Agent",
            "netlogon": "Net Logon Service",
            "scerpc": "Security Configuration Engine RPC",
            "lsarpc_server": "LSA RPC Server",
            "msv1_0": "Microsoft Authentication Package",
            "kerberos": "Kerberos Authentication Service",
            "ntlmssp": "NTLM Security Support Provider",
            "schannel": "Secure Channel Security Package",
            "wdigest": "Digest Authentication Package",
            "credssp": "Credential Security Support Provider",
            "tssdis": "Terminal Services Session Directory",
            "efsrpc": "Encrypting File System RPC",
            "dsrole": "Directory Service Role",
            "drsuapi": "Directory Replication Service",
            "frsrpc": "File Replication Service RPC",
            "dfs": "Distributed File System",
            "dssetup": "Directory Service Setup",
            "cert": "Certificate Services",
            "icardagt": "Information Card Agent",
            "keyiso": "CNG Key Isolation Service",
            "kdc": "Key Distribution Center",
            "kdcsvc": "Kerberos Key Distribution Center Service",
        },
        "file_services": {
            "srvsvc": "Server Service RPC",
            "wkssvc": "Workstation Service RPC",
            "spoolss": "Print Spooler Service",
            "browser": "Computer Browser Service",
            "netdfs": "Distributed File System",
            "ntsvcs": "Plug and Play Service",
            "rpcss": "Remote Procedure Call Service",
            "locator": "RPC Locator Service",
            "ntfrs": "NT File Replication Service",
            "fax": "Fax Service",
            "faxsvc": "Fax Service RPC",
            "messenger": "Messenger Service",
            "alerter": "Alerter Service",
            "netlogon": "Net Logon",
            "netapi": "Net API",
            "rasapi": "Remote Access Service API",
            "rasman": "Remote Access Connection Manager",
            "winprint": "Windows Print Service",
            "printui": "Print User Interface",
            "ssdpsrv": "SSDP Discovery Service",
            "upnphost": "UPnP Device Host",
            "fdphost": "Function Discovery Provider Host",
            "fdsvc": "Function Discovery Resource Publication",
            "p2psvc": "Peer Networking Grouping",
            "pnrpsvc": "Peer Name Resolution Protocol",
        },
        "system_services": {
            "eventlog": "Event Log Service",
            "llsrpc": "License Logging Service",
            "tapsrv": "Telephony Service",
            "dhcpcsvc": "DHCP Client Service",
            "dns": "DNS Client Service",
            "w32time": "Windows Time Service",
            "seclogon": "Secondary Logon Service",
            "schedule": "Task Scheduler Service",
            "wuauserv": "Windows Update Service",
            "bits": "Background Intelligent Transfer Service",
            "cryptsvc": "Cryptographic Services",
            "themes": "Themes Service",
            "audiosrv": "Windows Audio Service",
            "audioendpointbuilder": "Windows Audio Endpoint Builder",
            "dmserver": "Logical Disk Manager",
            "vds": "Virtual Disk Service",
            "vss": "Volume Shadow Copy Service",
            "swprv": "Software Shadow Copy Provider",
            "wmiprvse": "WMI Provider Host",
            "winmgmt": "Windows Management Instrumentation",
            "pcasvc": "Program Compatibility Assistant Service",
            "aelookupsvc": "Application Experience Lookup Service",
            "appinfo": "Application Information Service",
            "appidsvc": "Application Identity Service",
            "bdesvc": "BitLocker Drive Encryption Service",
            "bfe": "Base Filtering Engine",
            "certpropssvc": "Certificate Propagation Service",
            "cscdll": "Offline Files Service",
            "defragsvc": "Disk Defragmenter Service",
            "dps": "Diagnostic Policy Service",
            "ehrecvr": "Windows Media Center Receiver Service",
            "ehsched": "Windows Media Center Scheduler Service",
            "fcsam": "Microsoft Forefront Client Security Antimalware Service",
            "fdresp": "Function Discovery Resource Publication",
            "hidserv": "Human Interface Device Access",
            "hkmsvc": "Health Key and Certificate Management",
            "idsvc": "Windows CardSpace",
            "iphlpsvc": "IP Helper Service",
            "kpssvc": "KtmRm for Distributed Transaction Coordinator",
            "lanmanserver": "Server Service",
            "lanmanworkstation": "Workstation Service",
            "lltdsvc": "Link-Layer Topology Discovery Mapper",
            "lmhosts": "TCP/IP NetBIOS Helper Service",
            "mcsvc": "Media Center Extender Service",
            "mmcss": "Multimedia Class Scheduler Service",
            "msdtc": "Distributed Transaction Coordinator",
            "msiserver": "Windows Installer Service",
            "netprofm": "Network List Service",
            "nla": "Network Location Awareness Service",
            "pla": "Performance Logs and Alerts Service",
            "profsvc": "User Profile Service",
            "qdvd": "QoS RSVP Service",
            "qwave": "Quality Windows Audio Video Experience",
            "rasauto": "Remote Access Auto Connection Manager",
            "rasmans": "Remote Access Connection Manager",
            "remoteaccess": "Routing and Remote Access Service",
            "remoteregistry": "Remote Registry Service",
            "rpclocator": "Remote Procedure Call Locator",
            "sacsvr": "Special Administration Console Helper",
            "sens": "System Event Notification Service",
            "sharedaccess": "Internet Connection Sharing",
            "shellhwdetection": "Shell Hardware Detection Service",
            "slsvc": "Software Licensing Service",
            "snmptrap": "SNMP Trap Service",
            "sppsvc": "Software Protection Platform Service",
            "ssdpsrv": "SSDP Discovery Service",
            "stisvc": "Windows Image Acquisition Service",
            "ms_swprv": "Microsoft Software Shadow Copy Provider",
            "tapisrv": "Telephony Service",
            "termservice": "Remote Desktop Services",
            "trustedinstaller": "Windows Modules Installer",
            "ui0detect": "Interactive Services Detection",
            "upnphost": "UPnP Device Host",
            "vaultsvc": "Credential Manager Service",
            "wcncsvc": "Windows Connect Now - Config Registrar",
            "wcncsvc": "Windows Connect Now - Config Registrar",
            "wcspluginsvc": "Windows Color System",
            "wdiservicehost": "Diagnostic Service Host",
            "wdisystemhost": "Diagnostic System Host",
            "wecsvc": "Windows Event Collector Service",
            "wercplsupport": "Problem Reports and Solutions Control Panel Support",
            "windefend": "Windows Defender Service",
            "winhttpautoproxysvc": "WinHTTP Web Proxy Auto-Discovery Service",
            "winrm": "Windows Remote Management Service",
            "winsock": "Winsock Service",
            "wlansvc": "WLAN AutoConfig Service",
            "wmpnetworksvc": "Windows Media Player Network Sharing Service",
            "wscsvc": "Windows Security Center Service",
            "wuauserv": "Windows Update Service",
            "wudfsvc": "Windows Driver Foundation - User-mode Driver Framework",
        },
        "database_services": {
            "sql\\query": "SQL Server Query Pipe",
            "mssql$": "SQL Server Instance",
            "sqlquery": "SQL Server Query Engine",
            "mssql$sqlexpress": "SQL Server Express Instance",
            "mssql$sharepoint": "SQL Server SharePoint Instance",
            "mysql": "MySQL Database Service",
            "postgresql": "PostgreSQL Database Service",
            "oracle": "Oracle Database Service",
            "db2": "IBM DB2 Database Service",
            "mongodb": "MongoDB Database Service",
            "redis": "Redis Database Service",
            "cassandra": "Apache Cassandra Database Service",
            "elasticsearch": "Elasticsearch Service",
            "memcached": "Memcached Service",
            "couchdb": "CouchDB Database Service",
        },
        "application_services": {
            "tsvcpipe": "Terminal Services",
            "msftewds": "File Transfer Engine",
            "router": "Routing and Remote Access",
            "pipe_eventroot": "WMI Event Subsystem",
            "initshutdown": "System Shutdown Interface",
            "ctx_winstation_api_service": "Citrix WinStation API",
            "ica": "Citrix Independent Computing Architecture",
            "citrix": "Citrix Application Server",
            "vmware": "VMware Tools Service",
            "veeam": "Veeam Backup Service",
            "commvault": "Commvault Backup Service",
            "symantec": "Symantec Endpoint Protection",
            "mcafee": "McAfee Antivirus Service",
            "kaspersky": "Kaspersky Antivirus Service",
            "trendmicro": "Trend Micro Antivirus Service",
            "sophos": "Sophos Antivirus Service",
            "crowdstrike": "CrowdStrike Falcon Service",
            "sentinelone": "SentinelOne Agent Service",
            "carbonblack": "Carbon Black Endpoint Protection",
            "cylance": "Cylance Antivirus Service",
            "webroot": "Webroot SecureAnywhere Service",
            "malwarebytes": "Malwarebytes Anti-Malware Service",
            "avira": "Avira Antivirus Service",
            "avgantivirus": "AVG Antivirus Service",
            "avast": "Avast Antivirus Service",
            "bitdefender": "Bitdefender Antivirus Service",
            "eset": "ESET Antivirus Service",
            "fsecure": "F-Secure Antivirus Service",
            "gdata": "G Data Antivirus Service",
            "norton": "Norton Antivirus Service",
            "panda": "Panda Antivirus Service",
            "quickheal": "Quick Heal Antivirus Service",
            "zonealarm": "ZoneAlarm Firewall Service",
        },
        "terminal_services": {
            "termdd": "Terminal Device Driver",
            "termsrv": "Terminal Services Service",
            "tssdis": "Terminal Services Session Directory",
            "tsgateway": "Terminal Services Gateway",
            "tslsbbroker": "Terminal Services Licensing",
            "umrdpservice": "Remote Desktop Services UserMode Port Redirector",
            "sessionenv": "Remote Desktop Configuration Service",
            "rdpwd": "Remote Desktop Protocol Core Service",
            "rdpdr": "Remote Desktop Device Redirector",
            "rdpclip": "Remote Desktop Clipboard Service",
            "rdpsnd": "Remote Desktop Audio Service",
            "rdpvideominiport": "Remote Desktop Video Miniport",
            "tsusbflt": "Remote Desktop USB Filter",
            "tsusbhub": "Remote Desktop USB Hub",
            "rdpbus": "Remote Desktop Protocol Bus Enumerator",
            "rdpencdd": "RDP Encoder Mirror Driver",
            "rdprefmp": "RDP Reflector Display Driver",
            "rdpdd": "Remote Desktop Protocol Display Driver",
        },
        "web_services": {
            "iisadmin": "IIS Admin Service",
            "w3svc": "World Wide Web Publishing Service",
            "msftpsvc": "Microsoft FTP Service",
            "smtpsvc": "Simple Mail Transfer Protocol Service",
            "nntpsvc": "Network News Transfer Protocol Service",
            "pop3svc": "Post Office Protocol v3 Service",
            "imap4svc": "Internet Message Access Protocol v4 Service",
            "httpsys": "HTTP Service",
            "winhttp": "WinHTTP Web Proxy Auto-Discovery Service",
            "bits": "Background Intelligent Transfer Service",
            "webdav": "WebDAV Client Service",
            "upnpssdp": "UPnP SSDP Service",
            "ssdp": "Simple Service Discovery Protocol",
            "dnscache": "DNS Client Service",
            "dhcp": "DHCP Client Service",
            "tcpip": "TCP/IP Protocol Driver",
            "http": "HTTP Protocol Stack",
            "netbt": "NetBIOS over TCP/IP",
            "rpcss": "Remote Procedure Call Service",
            "rpclocator": "Remote Procedure Call Locator",
            "msdtc": "Distributed Transaction Coordinator",
            "com+": "COM+ Event System",
            "dcom": "DCOM Server Process Launcher",
            "ole": "OLE Service",
            "activeds": "Active Directory Service Interfaces",
        },
        "browser_ipc": {
            "mojo": "Chromium Mojo IPC",
            "chrome": "Chrome Browser IPC",
            "firefox": "Firefox Browser IPC",
            "edge": "Microsoft Edge Browser IPC",
            "opera": "Opera Browser IPC",
            "safari": "Safari Browser IPC",
            "brave": "Brave Browser IPC",
            "vivaldi": "Vivaldi Browser IPC",
            "chromium": "Chromium Browser IPC",
            "ie": "Internet Explorer IPC",
            "iexplore": "Internet Explorer Process IPC",
        },
        "virtualization": {
            "vmware-tools": "VMware Tools Service",
            "vmware-usbarbitrator": "VMware USB Arbitration Service",
            "vmware-converter": "VMware vCenter Converter",
            "vmsvc": "VMware Management Service",
            "vmnat": "VMware NAT Service",
            "vmnetdhcp": "VMware DHCP Service",
            "vmware-hostd": "VMware Host Agent",
            "vmware-vpxd": "VMware VirtualCenter Server",
            "virtualbox": "VirtualBox Service",
            "vboxdrv": "VirtualBox Support Driver",
            "vboxnetflt": "VirtualBox NetFlt Service",
            "vboxnetadp": "VirtualBox NetAdp Service",
            "vboxusb": "VirtualBox USB Service",
            "hyper-v": "Hyper-V Virtual Machine Management",
            "hvhost": "Hyper-V Host Compute Service",
            "vmms": "Hyper-V Virtual Machine Management Service",
            "vmcompute": "Hyper-V Host Compute Service",
            "vmickvpexchange": "Hyper-V Data Exchange Service",
            "vmicheartbeat": "Hyper-V Heartbeat Service",
            "vmicshutdown": "Hyper-V Guest Shutdown Service",
            "vmictimesync": "Hyper-V Time Synchronization Service",
            "vmicvss": "Hyper-V Volume Shadow Copy Requestor",
            "vmicrdv": "Hyper-V Remote Desktop Virtualization Service",
        },
        "development_tools": {
            "msbuild": "Microsoft Build Engine",
            "devenv": "Visual Studio Development Environment",
            "vshost": "Visual Studio Host Process",
            "tfs": "Team Foundation Server",
            "vsts": "Visual Studio Team Services",
            "nuget": "NuGet Package Manager",
            "iisexpress": "IIS Express",
            "sqlservr": "SQL Server Database Engine",
            "nodejs": "Node.js Runtime",
            "python": "Python Interpreter",
            "java": "Java Virtual Machine",
            "dotnet": ".NET Core Runtime",
            "powershell": "PowerShell Core",
            "git": "Git Version Control",
            "svn": "Subversion Version Control",
            "mercurial": "Mercurial Version Control",
            "perforce": "Perforce Version Control",
            "jenkins": "Jenkins Automation Server",
            "teamcity": "TeamCity Build Server",
            "bamboo": "Atlassian Bamboo",
            "octopus": "Octopus Deploy",
            "ansible": "Ansible Automation",
            "puppet": "Puppet Configuration Management",
            "chef": "Chef Configuration Management",
            "saltstack": "SaltStack Configuration Management",
            "docker": "Docker Container Runtime",
            "kubernetes": "Kubernetes Container Orchestration",
            "vagrant": "Vagrant Development Environment",
        },
        "monitoring_tools": {
            "nagios": "Nagios Monitoring Service",
            "zabbix": "Zabbix Monitoring Service",
            "prtg": "PRTG Network Monitor",
            "solarwinds": "SolarWinds Monitoring",
            "datadog": "Datadog Agent",
            "newrelic": "New Relic Agent",
            "splunk": "Splunk Universal Forwarder",
            "elk": "Elastic Stack Agent",
            "prometheus": "Prometheus Monitoring",
            "grafana": "Grafana Visualization",
            "telegraf": "Telegraf Metrics Agent",
            "collectd": "Collectd Statistics Daemon",
            "statsd": "StatsD Metrics Daemon",
            "fluentd": "Fluentd Log Collector",
            "logstash": "Logstash Data Pipeline",
            "filebeat": "Filebeat Log Shipper",
            "metricbeat": "Metricbeat Metrics Shipper",
            "winlogbeat": "Winlogbeat Windows Log Shipper",
            "packetbeat": "Packetbeat Network Analytics",
            "heartbeat": "Heartbeat Uptime Monitor",
            "auditbeat": "Auditbeat Audit Data Shipper",
        },
        "backup_services": {
            "veeam": "Veeam Backup & Replication",
            "commvault": "Commvault Complete Backup",
            "acronis": "Acronis True Image",
            "carbonite": "Carbonite Safe",
            "crashplan": "CrashPlan Backup Service",
            "backblaze": "Backblaze B2 Cloud Storage",
            "duplicati": "Duplicati Backup Service",
            "bacula": "Bacula Backup Service",
            "amanda": "Amanda Network Backup",
            "bareos": "Bareos Backup Service",
            "rsync": "Rsync File Synchronization",
            "robocopy": "Robust File Copy Utility",
            "xcopy": "Extended Copy Utility",
            "ntbackup": "Windows NT Backup Utility",
            "wbadmin": "Windows Server Backup",
            "dpm": "Data Protection Manager",
            "systemcenter": "System Center Data Protection Manager",
        },
        "gaming_services": {
            "steam": "Steam Gaming Platform",
            "origin": "EA Origin Gaming Platform",
            "uplay": "Ubisoft Uplay Gaming Platform",
            "epic": "Epic Games Launcher",
            "battlenet": "Battle.net Gaming Platform",
            "gog": "GOG Galaxy Gaming Platform",
            "discord": "Discord Voice and Chat Service",
            "teamspeak": "TeamSpeak Voice Communication",
            "mumble": "Mumble Voice Communication",
            "ventrilo": "Ventrilo Voice Communication",
            "xbox": "Xbox Gaming Services",
            "nvidia": "NVIDIA GeForce Experience",
            "amd": "AMD Gaming Software",
            "razer": "Razer Synapse Gaming Software",
            "logitech": "Logitech Gaming Software",
            "corsair": "Corsair iCUE Gaming Software",
            "steelseries": "SteelSeries Engine Gaming Software",
            "roccat": "ROCCAT Swarm Gaming Software",
            "hyperx": "HyperX NGenuity Gaming Software",
            "asus": "ASUS ROG Armory Gaming Software",
            "msi": "MSI Dragon Center Gaming Software",
        },
    }

    def __init__(self, smb_connection: SMBConnection, verbose: bool = False):
        """Initialize with existing SMB connection"""
        self.smb_connection = smb_connection
        self.verbose = verbose
        self.logger = logging.getLogger(__name__)
        self.discovered_pipes = []

    def enumerate_pipes(self, method: str = "hybrid") -> List[NamedPipe]:
        """
        Enumerate named pipes using specified method

        Args:
            method: Enumeration method ('smb', 'rpc', 'hybrid')

        Returns:
            List of discovered NamedPipe objects
        """
        self.discovered_pipes = []

        if method in ["smb", "hybrid"]:
            pipes_smb = self._enumerate_via_smb()
            self.discovered_pipes.extend(pipes_smb)

        if method in ["rpc", "hybrid"]:
            pipes_rpc = self._enumerate_via_rpc()
            self.discovered_pipes.extend(pipes_rpc)

        # Remove duplicates while preserving order
        seen = set()
        unique_pipes = []
        for pipe in self.discovered_pipes:
            if pipe.name not in seen:
                seen.add(pipe.name)
                unique_pipes.append(pipe)

        self.discovered_pipes = unique_pipes
        self._categorize_pipes()

        return self.discovered_pipes

    def _enumerate_via_smb(self) -> List[NamedPipe]:
        """Enumerate pipes via direct SMB IPC$ share listing"""
        pipes = []

        try:
            if self.verbose:
                print_debug("[*] Attempting SMB enumeration via IPC$ share")

            # Store current share to preserve connection
            current_share = getattr(self.smb_connection, "_SMBConnection__currentShare", None)

            # Connect to IPC$ share temporarily
            self.smb_connection.connectTree("IPC$")

            try:
                # List contents of IPC$ share root
                files = self.smb_connection.listPath("IPC$", "\\*")

                for file_info in files:
                    filename = file_info.get_longname()
                    if filename not in [".", ".."]:
                        pipe = NamedPipe(filename)
                        pipes.append(pipe)
                        if self.verbose:
                            print_debug(f"[+] Found pipe via SMB: {filename}")

            except Exception as e:
                if self.verbose:
                    print_warning(f"[!] SMB enumeration failed: {str(e)}")

            finally:
                # Restore original share connection if it existed
                if current_share:
                    try:
                        self.smb_connection.connectTree(current_share)
                        if self.verbose:
                            print_debug(f"[*] Restored connection to share: {current_share}")
                    except Exception as e:
                        if self.verbose:
                            print_warning(f"[!] Failed to restore share connection: {str(e)}")

        except Exception as e:
            if self.verbose:
                print_bad(f"[!] SMB enumeration error: {str(e)}")

        return pipes

    def _enumerate_via_rpc(self) -> List[NamedPipe]:
        """Enumerate pipes via RPC endpoint mapper and SMB IPC$ listing"""
        pipes = []

        try:
            if self.verbose:
                print_debug("[*] Attempting RPC endpoint enumeration")

            # Method 1: Try endpoint mapper
            try:
                target = self.smb_connection.getRemoteHost()
                rpctransport = transport.DCERPCTransportFactory(f"ncacn_ip_tcp:{target}[135]")
                rpctransport.set_connect_timeout(5)
                dce = rpctransport.get_dce_rpc()
                dce.connect()

                try:
                    # Use ept_lookup instead of hept_lookup for better compatibility
                    resp = epm.ept_lookup(dce)

                    for entry in resp:
                        # Check for named pipe endpoints in different ways
                        entry_str = str(entry).lower()
                        if "pipe" in entry_str or "ncacn_np" in entry_str:
                            # Extract pipe name from various formats
                            if "\\pipe\\" in entry_str:
                                pipe_name = entry_str.split("\\pipe\\")[1].split()[0].split("\\")[0]
                                pipe = NamedPipe(pipe_name.strip())
                                pipes.append(pipe)
                                if self.verbose:
                                    print_debug(f"[+] Found pipe via RPC endpoint: {pipe_name}")

                except Exception as e:
                    if self.verbose:
                        print_debug(f"[*] ept_lookup failed, trying alternative method: {str(e)}")

                finally:
                    dce.disconnect()

            except Exception as e:
                if self.verbose:
                    print_debug(f"[*] RPC endpoint mapper connection failed: {str(e)}")

            # Method 2: Try well-known RPC services that typically use named pipes
            well_known_rpc_pipes = [
                "lsarpc",
                "samr",
                "netlogon",
                "srvsvc",
                "wkssvc",
                "spoolss",
                "winreg",
                "svcctl",
                "atsvc",
                "eventlog",
                "trkwks",
                "keysvc",
                "protected_storage",
                "ntsvcs",
                "scerpc",
                "llsrpc",
                "browser",
                "netdfs",
                "rpcss",
                "locator",
                "ntfrs",
                "fax",
                "messenger",
                "alerter",
                "dhcpcsvc",
                "dns",
                "w32time",
                "seclogon",
            ]

            if self.verbose:
                print_debug("[*] Testing well-known RPC pipe endpoints")

            for pipe_name in well_known_rpc_pipes:
                try:
                    # Try to connect to the pipe via RPC
                    rpctransport = transport.DCERPCTransportFactory(
                        f"ncacn_np:{target}[\\pipe\\{pipe_name}]"
                    )
                    rpctransport.set_connect_timeout(2)  # Short timeout for testing
                    dce = rpctransport.get_dce_rpc()
                    dce.connect()
                    dce.disconnect()

                    # If connection succeeds, pipe exists
                    pipe = NamedPipe(pipe_name)
                    pipes.append(pipe)
                    if self.verbose:
                        print_debug(f"[+] Confirmed pipe via RPC test: {pipe_name}")

                except Exception:
                    # Connection failed, pipe doesn't exist or not accessible
                    pass

        except Exception as e:
            if self.verbose:
                print_warning(f"[!] RPC enumeration failed: {str(e)}")

        return pipes

    def _categorize_pipes(self):
        """Categorize discovered pipes based on known patterns"""
        for pipe in self.discovered_pipes:
            pipe_name_lower = pipe.name.lower()

            # Check exact matches first
            for category, pipe_dict in self.PIPE_CATEGORIES.items():
                if pipe_name_lower in pipe_dict:
                    pipe.pipe_type = category
                    pipe.description = pipe_dict[pipe_name_lower]
                    break

            # Check pattern matches
            if pipe.pipe_type == "unknown":
                # Database services
                if any(
                    pattern in pipe_name_lower
                    for pattern in [
                        "sql",
                        "mssql",
                        "mysql",
                        "postgresql",
                        "oracle",
                        "db2",
                        "mongodb",
                        "redis",
                    ]
                ):
                    pipe.pipe_type = "database_services"
                    pipe.description = "Database service"
                # Browser IPC
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["mojo", "chrome", "firefox", "edge", "opera", "safari", "brave"]
                ):
                    pipe.pipe_type = "browser_ipc"
                    pipe.description = "Browser IPC mechanism"
                # Virtualization
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["vmware", "virtualbox", "hyper-v", "citrix", "ctx_", "ica"]
                ):
                    pipe.pipe_type = "virtualization"
                    pipe.description = "Virtualization service"
                # Terminal services
                elif any(pattern in pipe_name_lower for pattern in ["rdp", "term", "ts", "remote"]):
                    pipe.pipe_type = "terminal_services"
                    pipe.description = "Terminal/Remote Desktop service"
                # Web services
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["iis", "w3", "http", "web", "ftp", "smtp"]
                ):
                    pipe.pipe_type = "web_services"
                    pipe.description = "Web/HTTP service"
                # Development tools
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["git", "svn", "jenkins", "docker", "nodejs", "python", "java"]
                ):
                    pipe.pipe_type = "development_tools"
                    pipe.description = "Development tool"
                # Monitoring tools
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["nagios", "zabbix", "splunk", "elk", "prometheus", "grafana"]
                ):
                    pipe.pipe_type = "monitoring_tools"
                    pipe.description = "Monitoring service"
                # Backup services
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["backup", "veeam", "commvault", "acronis"]
                ):
                    pipe.pipe_type = "backup_services"
                    pipe.description = "Backup service"
                # Gaming services
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["steam", "origin", "epic", "discord", "nvidia", "amd"]
                ):
                    pipe.pipe_type = "gaming_services"
                    pipe.description = "Gaming service"
                # Application services (antivirus, etc.)
                elif any(
                    pattern in pipe_name_lower
                    for pattern in [
                        "antivirus",
                        "mcafee",
                        "symantec",
                        "kaspersky",
                        "crowdstrike",
                        "av",
                    ]
                ):
                    pipe.pipe_type = "application_services"
                    pipe.description = "Security/Antivirus service"
                # Administrative services
                elif any(
                    pattern in pipe_name_lower
                    for pattern in ["rpc", "lsa", "sam", "admin", "policy", "auth"]
                ):
                    pipe.pipe_type = "administrative"
                    pipe.description = "Windows administrative service"

    def format_output(self, detailed: bool = False) -> str:
        """Format enumeration results for display"""
        if not self.discovered_pipes:
            return "No named pipes discovered."

        output = []

        # Group pipes by category
        categorized = {}
        for pipe in self.discovered_pipes:
            category = pipe.pipe_type
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(pipe)

        # Sort categories for consistent output
        category_order = [
            "administrative",
            "file_services",
            "system_services",
            "database_services",
            "application_services",
            "terminal_services",
            "web_services",
            "browser_ipc",
            "virtualization",
            "development_tools",
            "monitoring_tools",
            "backup_services",
            "gaming_services",
            "unknown",
        ]
        category_icons = {
            "administrative": "🔧",
            "file_services": "📁",
            "system_services": "⚙️",
            "database_services": "🗃️",
            "application_services": "📦",
            "terminal_services": "🖥️",
            "web_services": "🌐",
            "browser_ipc": "🌍",
            "virtualization": "📱",
            "development_tools": "🛠️",
            "monitoring_tools": "📊",
            "backup_services": "💾",
            "gaming_services": "🎮",
            "unknown": "❓",
        }
        category_names = {
            "administrative": "Administrative & Security Pipes",
            "file_services": "File & Network Services",
            "system_services": "System & Core Services",
            "database_services": "Database Services",
            "application_services": "Application & Antivirus Services",
            "terminal_services": "Terminal & Remote Desktop Services",
            "web_services": "Web & Communication Services",
            "browser_ipc": "Browser IPC Mechanisms",
            "virtualization": "Virtualization Services",
            "development_tools": "Development & DevOps Tools",
            "monitoring_tools": "Monitoring & Logging Tools",
            "backup_services": "Backup & Storage Services",
            "gaming_services": "Gaming & Entertainment Services",
            "unknown": "Unknown/Unclassified Pipes",
        }

        output.append(f"Named Pipes Discovered on {self.smb_connection.getRemoteHost()}:")
        output.append("")

        for category in category_order:
            if category in categorized:
                pipes = sorted(categorized[category], key=lambda p: p.name)
                icon = category_icons.get(category, "❓")
                name = category_names.get(category, category.title())

                output.append(f"{icon} {name}:")

                for pipe in pipes:
                    if detailed and pipe.description:
                        output.append(f"  {pipe.full_path:<30} ({pipe.description})")
                    else:
                        output.append(f"  {pipe.full_path}")

                output.append("")

        # Summary
        total_count = len(self.discovered_pipes)
        output.append(f"Total: {total_count} named pipes discovered")

        return "\n".join(output)

    def save_output(self, filename: str, detailed: bool = False) -> bool:
        """Save enumeration results to file"""
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(self.format_output(detailed=detailed))
            return True
        except Exception as e:
            print_bad(f"Failed to save output to {filename}: {str(e)}")
            return False

