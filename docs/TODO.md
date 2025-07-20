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
4. **Fix navigation above root to default to root location**
   - When user tries to navigate above share root, default to root instead of error
   - Provide user-friendly feedback about the limitation

5. **Add option to save ls -r output to a file**
   - Add CLI argument for output file specification
   - Add --show option to display previously saved file contents
   - Integrate with existing tee_output functionality

6. **wmi exec**
   - Implement WMI exec functionality for remote command execution
   - Support for both interactive and non-interactive modes
   - Integrate with existing authentication and session management
   - Ensure proper error handling and output formatting