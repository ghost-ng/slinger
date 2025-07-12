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

3. **Fix put relative path uploads issue**
   - Current issue: `put strap.sh ../` fails with parsing error
   - Need to handle relative paths properly in upload operations
   - Ensure proper path resolution and validation

### Medium Priority
4. **Fix navigation above root to default to root location**
   - When user tries to navigate above share root, default to root instead of error
   - Provide user-friendly feedback about the limitation

5. **Add option to save ls -r output to a file**
   - Add CLI argument for output file specification
   - Add --show option to display previously saved file contents
   - Integrate with existing tee_output functionality

## New Features

### File Search System
6. **Comprehensive file search functionality (find command)**
   - ✅ **Pattern matching**: Wildcard and regex support for file/directory search
   - ✅ **Advanced filtering**: File type (-type f/d), size filters, date filters
   - ✅ **Depth control**: --maxdepth and --mindepth for search boundaries
   - ✅ **Configurable timeout**: -timeout flag with 120-second default
   - ✅ **Progress reporting**: -progress flag shows directory-by-directory traversal
   - ✅ **Multiple output formats**: table, json, list, paths
   - ✅ **HTB integration tested**: Successfully validated against Windows SMB shares

### Completed Enhancements
- ✅ **Verbose flag implementation** - Added -verbose CLI flag that enables verbose output for remote path transformations and other operations
- ✅ **Custom filename downloads** - Fixed download functionality to support custom filenames (e.g., `get KeePass-2.58.zip /tmp/test.zip`)
- ✅ **Relative path uploads** - Fixed put command to properly handle relative paths like `put strap.sh ../`
- ✅ **Root navigation protection** - Navigation above share root automatically defaults to root with warning message
- ✅ **File output for ls -r** - ls command already supports `-o` flag for saving output and `--show` flag for viewing saved files
- ✅ **Find command implementation** - Comprehensive file search with timeout protection, verbose progress, and HTB validation

### Completed Research
- ✅ Codebase structure analysis
- ✅ Current verbose system understanding
- ✅ Path validation mechanisms
- ✅ File transfer implementations
- ✅ CLI argument system architecture
