### Task Scheduler
- ✅ **Load task XML** (COMPLETED v1.13.0) — `taskimport -f task.xml [-n name] [-d folder] [--test] [--force]`

### Registry
- None

### Service Control
- sc modify (partial — `hRChangeServiceConfigW` exists for enable/disable start type, but no general-purpose modify command exposed in CLI)

### General

### SMB
- add a share #hNetrShareAdd
- remove a share #hNetrShareEnum

## Current Enhancement Tasks

### High Priority
1. ✅ **Add verbose flag to show statements like remote path transformations** (COMPLETED)
   - Configurable via `set Verbose true`
   - Config var exists in `src/slingerpkg/var/config.py`

2. ✅ **Allow user to specify different filename when downloading** (COMPLETED)
   - Supports syntax: `get KeePass-2.58.zip /tmp/test.zip`
   - Creates directory if needed, uses custom filename
   - Location: `src/slingerpkg/lib/smblib.py` download_handler lines 348-364

3. ✅ **Fix put relative path uploads issue** (COMPLETED)

### Medium Priority
4. ✅ **Fix navigation above root to default to root location** (COMPLETED)

5. ✅ **Add option to save ls -r output to a file** (COMPLETED)

6. ✅ **wmi exec** (COMPLETED)

7. ✅ **WMI DCOM Interactive Shell with Directory Navigation** (COMPLETED)

### Future Enhancements
8. **System Change Tracking**
   - Add a way to track changes made to the system to show a report for later
   - Track file modifications, service changes, registry edits, scheduled tasks
   - Generate comprehensive audit reports of all system modifications
   - Integration with existing logging infrastructure

9. **Cross-Shell Directory Synchronization**
   - Synchronize cd across WMI shells and native SMB
   - Maintain consistent working directory state across different execution contexts
   - Bidirectional directory synchronization between SMB navigation and WMI shells
   - Unified directory state management
