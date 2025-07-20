### Task Scheduler
- load task xml

### Registry

- None

### Service Control
- sc modify

### General

### SMB
- add a share #hNetrShareAdd
- remove a share #hNetrShareEnum

## Current Enhancement Tasks

### High Priority
1. **Add verbose flag to show statements like remote path transformations**
   - Default: false
   - Configurable via set config command
   - Show statements like "[*] Remote Path (Before): KeePass-2.58.zip" and "[*] Remote Path (After): IT\KeePass-2.58.zip"

2. **Allow user to specify different filename when downloading**
   - Support syntax: `get KeePass-2.58.zip /tmp/test.zip`
   - Fix error: "[!] Local path /tmp/test.zip does not exist."
   - Should create the file at specified location with custom name

3. ✅ **Fix put relative path uploads issue** (COMPLETED)
   - ✅ Fixed double path joining bug in _resolve_remote_path method
   - ✅ Added proper handling for `../` and `../../` parent directory references
   - ✅ Enhanced path resolution for `.`, empty paths, and simple filenames
   - ✅ Tested with debug scripts and pexpect integration test
   - Location: `src/slingerpkg/lib/smblib.py` lines 1697-1748


### Medium Priority
4. ✅ **Fix navigation above root to default to root location** (COMPLETED)
   - ✅ Added protection in _normalize_path_for_smb method to detect above-root navigation
   - ✅ Automatically redirects users to root when attempting to navigate above share root
   - ✅ Shows user-friendly warning message: "Cannot navigate above share root. Redirecting to root directory."
   - ✅ Tested with pexpect integration test - confirmed working on HTB instance
   - Location: `src/slingerpkg/lib/smblib.py` lines 1679-1685

5. ✅ **Add option to save ls -r output to a file** (COMPLETED)
   - ✅ CLI argument `-o/--output` already implemented for output file specification
   - ✅ `--show` option already implemented to display saved file contents
   - ✅ Integrated with existing tee_output functionality
   - ✅ Tested and confirmed working: `ls -o filename.txt` saves output
   - ✅ Recursive support: `ls -r depth -o filename.txt` saves recursive listing
   - Location: `src/slingerpkg/utils/cli.py` lines 359-366, `src/slingerpkg/lib/smblib.py` lines 763-922

6. ✅ **wmi exec** (COMPLETED - DCE Transport Integration)
   - ✅ Created comprehensive WMI named pipe execution framework
   - ✅ Implemented SMB named pipe transport to bypass DCOM firewall restrictions
   - ✅ **ENHANCED**: Integrated with existing DCE transport infrastructure
   - ✅ **NEW**: Added WMI UUIDs to uuid_endpoints dictionary for proper RPC binding
   - ✅ **NEW**: Added _connect_wmi_service() and _wmi_execute_process() to DCETransport class
   - ✅ **NEW**: Modified WMI implementation to reuse existing DCE connections
   - ✅ Added WMI endpoint discovery and testing capabilities
   - ✅ Full CLI integration with extensive argument parsing
   - ✅ Interactive and non-interactive modes with output capture
   - ✅ Enhanced security through existing SMB authentication reuse
   - ✅ Based on comprehensive research in docs/WMI_NAMED_PIPE_EXECUTION_RESEARCH.md
   - Location: `src/slingerpkg/lib/wmi_namedpipe.py`, `src/slingerpkg/lib/dcetransport.py`, CLI: `src/slingerpkg/utils/cli.py` lines 1523-1571
   - **Status**: Framework integrated with DCE transport - ready for production use with Impacket RPC calls
