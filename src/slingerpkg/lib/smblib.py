import base64
from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from tabulate import tabulate
import os, sys, re, ntpath
import datetime, tempfile
from datetime import timedelta


# Share Access
FILE_SHARE_READ         = 0x00000001
FILE_SHARE_WRITE        = 0x00000002

class smblib():

    def __init__(self):
        print_debug("Smb Commands Module Loaded!")

    def cd_handler(self, args=None):
        if self.check_if_connected():
            if args.path:
                self.cd(args.path)
            elif args.command == "cd":
                self.print_current_path()

    def print_current_path(self, args=None):
        if self.check_if_connected():
            print_log(self.current_path)

    # connect to a share
    def connect_share(self, args):      #use this function to connect to a share
        share = args.share
        try:
            self.tree_id = self.conn.connectTree(share)
            self.share = share
            print_good(f"Connected to share {share}")
            self.is_connected_to_share = True
            self.relative_path = ""
            self.update_current_path()
            self.dce_transport.share = share
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            if "STATUS_BAD_NETWORK_NAME" in str(e):
                print_bad(f"Failed to connect to share {share}: Invalid share name.")
            else:
                print_bad(f"Failed to connect to share {share}: {e}")
            raise e

#https://learn.microsoft.com/en-us/windows/win32/api/lmshare/ns-lmshare-share_info_0
#SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
    def list_shares(self, args=None, echo=True, ret=False):
        shares = self.conn.listShares()
        print_debug(f"Shares: {shares}")
        
        share_info_list = []
        for share in shares:
            share_info = {}
            # Retrieve share information
            try:
                resp = self.dce_transport._share_info(share['shi1_netname'])
                
                # Store share information in a dictionary
                share_info = {
                    'Name': remove_null_terminator(resp["InfoStruct"]["ShareInfo502"]["shi502_netname"]),
                    'Path': remove_null_terminator(resp["InfoStruct"]["ShareInfo502"]["shi502_path"]),
                    'Comment': remove_null_terminator(resp["InfoStruct"]["ShareInfo502"]["shi502_remark"])
                }
            except Exception as e:
                print_debug(f"Failed to retrieve share info for {share['shi1_netname']}: {e}", sys.exc_info())
                # If we can't get the share info show only the name
                share_info = {
                    'Name': share['shi1_netname'],
                    'Path': '',
                    'Comment': ''
                }
                share_info_list.append(share_info)
                continue
            #print_info(f"{share_info}")
            share_info_list.append(share_info)

        
        if echo:
            print_info("Available Shares")
            if args and args.list:
                # Print share information in a list format
                for share_info in share_info_list:
                    print(f"Name: {share_info['Name']}")
                    print(f"Path: {share_info['Path']}")
                    print(f"Comment: {share_info['Comment']}")
                    print()
            else:
                # Print share information using tabulate
                headers = ["Name", "Path", "Comment"]
                table = [[share_info['Name'], share_info['Path'], share_info['Comment']] for share_info in share_info_list]
                print(tabulate(table, headers=headers, tablefmt='grid'))
            
        
        if ret:
            # {"Name": "IPC$", "Path": "C:\\Windows\\system32\\IPC$", "Comment": "Remote IPC"}
            share_info_dict = []
            for share_info in share_info_list:
                share_info_dict.append({"name": share_info["Name"], "path": share_info["Path"], "comment": share_info["Comment"]})
            return share_info_dict


    def mkdir(self, args):
        if not self.check_if_connected():
            return
        path = args.path
        try:
            self.conn.createDirectory(self.share, path)
            print_info(f"Directory created {path}")
        except Exception as e:
            if "STATUS_OBJECT_NAME_COLLISION" in str(e):
                print_warning(f"Directory already exists {path}")
            else:
                print_bad(f"Failed to create directory {path}: {e}")
                print_debug(str(e), sys.exc_info())

    def rmdir(self, args):
        if not self.check_if_connected():
            return
        path = ntpath.normpath(ntpath.join(self.relative_path, args.remote_path))
        try:
            print_debug(f"Removing directory {path}")
            self.conn.deleteDirectory(self.share, path)
            print_info(f"Directory removed {path}")
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"Failed to remove directory {path}: {e}")
            raise e

    def rm_handler(self, args):
        if not self.check_if_connected():
            return
        if args.remote_path == "." or args.remote_path == "" or args.remote_path is None:
            print_warning("Please specify a file to remove.")
            return
        if args.remote_path == "*":
            # get file listing
            list_path = self.relative_path + '\\*' if self.relative_path else '*'
            files = self.conn.listPath(self.share, list_path)
            for f in files:
                if f.is_directory() and f.get_longname() in ['.', '..']:
                    continue
                path = ntpath.normpath(ntpath.join(self.relative_path, f.get_longname()))
                print_verbose(f"Removing file {path}")
                self.conn.deleteFile(self.share, path)
                print_info(f"File Removed {path}")
            return
        path = ntpath.normpath(ntpath.join(self.relative_path, args.remote_path))
        
        if self.check_if_connected():
            #if self.file_exists(path):
            #    self.delete(path)
            #else:
            #    print_warning(f"Remote file {path} does not exist.")
            try:
                self.delete(path)
            except Exception as e:
                print_debug(str(e), sys.exc_info())
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    print_warning(f"Remote file {path} does not exist.")

    def delete(self, remote_path):
        
        if not self.check_if_connected():
            return

        #recursively delete files in directory
        if remote_path.endswith('*'):
            
            remote_path = remote_path[:-2]
            if self.is_valid_directory(remote_path):
                print_info(f"Deleting files in directory '{remote_path}'")
                list_path = remote_path + '\\*' if remote_path else '*'
                files = self.conn.listPath(self.share, list_path)
                for f in files:
                    if f.is_directory() and f.get_longname() in ['.', '..']:
                        print_verbose(f"Found directory {os.path.join(remote_path, f.get_longname())}")
                        continue
                    print_verbose(f"Deleting file {os.path.join(remote_path, f.get_longname())}")
                    self.conn.deleteFile(self.share,os.path.join(remote_path, f.get_longname()))
                    print_info(f"File Removed '{os.path.join(remote_path, f.get_longname())}'")
            else:
                print_warning(f"Invalid directory: {remote_path}")
                return
        else:
            print_verbose(f"Deleting file '{remote_path}'")
            try:
                self.conn.deleteFile(self.share, remote_path)
                print_info(f"File Removed '{remote_path}'")
            except Exception as e:
                print_debug(str(e), sys.exc_info())
                if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                    print_warning(f"Remote file '{remote_path}' does not exist.")
                elif "STATUS_FILE_IS_A_DIRECTORY" in str(e):
                    print_warning(f"Remote object '{remote_path}' is a directory, skipping.")
                else:
                    print_bad(f"Failed to delete file '{remote_path}': {e}")
                    raise e

    #update current path as share + relative path
    def update_current_path(self):
        #self.current_path = os.path.normpath(self.share + "\\" + self.relative_path)
        self.current_path = ntpath.normpath(self.share + "\\" + self.relative_path)

    # validate the directory exists
    def is_valid_directory(self, path, print_error=True):
        list_path = path + '\\*' if path else '*'
        try:
            self.conn.listPath(self.share, list_path)
            return True
        except Exception as e:
            if "STATUS_STOPPED_ON_SYMLINK" in str(e):
                if print_error:
                    print_warning(f"Remote directory {path} is a symlink.")
            elif "STATUS_NOT_A_DIRECTORY" in str(e):
                if print_error:
                    print_warning(f"{path} is not a directory.")

            print_debug(f"Failed to list directory {path} on share {self.share}: {e}", sys.exc_info())
            return False

    def cd(self, path):
        if not self.check_if_connected():
            return
            
        print_verbose(f"Changing directory to {path}")
        
        # Handle empty path or current directory
        if not path or path == ".":
            self.print_current_path()
            return
            
        # Handle going to share root
        if path == "/" or path == "\\" or path == self.share:
            self.relative_path = ""
            self.update_current_path()
            self.print_current_path()
            return
        
        # Normalize path for SMB operations
        is_valid, resolved_path, error = self._normalize_path_for_smb(self.relative_path, path)
        
        if not is_valid:
            print_warning(f"Cannot change directory: {error}")
            return
            
        # Try to change to the directory - let SMB server handle access control
        if self.is_valid_directory(resolved_path):
            self.relative_path = resolved_path
            self.update_current_path()
            self.print_current_path()
        else:
            print_warning(f"Directory does not exist or access denied: {resolved_path}")

    # handle file uploads
    def upload_handler(self, args):
        if not self.check_if_connected():
            return
            
        # Check local file exists
        if not os.path.exists(args.local_path):
            print_warning(f"Local path {args.local_path} does not exist.")
            return
            
        # Resolve remote path
        default_filename = ntpath.basename(args.local_path)
        is_valid, remote_path, error = self._resolve_remote_path(args.remote_path, default_filename)
        
        if not is_valid:
            print_warning(f"Cannot upload: {error}")
            return
        
        # Show verbose path information if enabled
        print_verbose(f"Remote Path (Before): {args.remote_path or default_filename}")
        print_verbose(f"Remote Path (After): {remote_path}")
            
        print_info(f"Uploading: {args.local_path} --> {self.share}\\{remote_path}")
        self.upload(args.local_path, remote_path)

    def upload(self, local_path, remote_path):
        if not self.check_if_connected():
            return
        try:
            with open(local_path, 'rb') as file_obj:
                self.conn.putFile(self.share, remote_path, file_obj.read)
        except Exception as e:
            print_debug(str(e), sys.exc_info())
            print_bad(f"Failed to upload file {local_path} to {remote_path}: {e}")
            print_log(sys.exc_info())

    def download_handler(self, args, echo=True):
        if not self.check_if_connected():
            print_warning("You are not connected to a share.")
            return
            
        # Resolve remote path
        is_valid, remote_path, error = self._normalize_path_for_smb(self.relative_path, args.remote_path)
        
        if not is_valid:
            print_warning(f"Cannot download: {error}")
            return
        
        # Show verbose path information if enabled
        print_verbose(f"Remote Path (Before): {args.remote_path}")
        print_verbose(f"Remote Path (After): {remote_path}")
            
        # Determine local path
        if args.local_path in [".", "", None]:
            # Default to current directory with remote filename
            local_path = os.path.join(os.getcwd(), ntpath.basename(args.remote_path))
        else:
            # Check if args.local_path is an existing directory
            if os.path.isdir(args.local_path):
                local_path = os.path.join(args.local_path, ntpath.basename(args.remote_path))
            else:
                # Treat as a specific file path (including new filename)
                local_path = args.local_path
                
        # Ensure local directory exists
        local_dir = os.path.dirname(local_path)
        if local_dir and not os.path.isdir(local_dir):
            try:
                os.makedirs(local_dir, exist_ok=True)
                print_verbose(f"Created local directory: {local_dir}")
            except OSError as e:
                print_warning(f"Failed to create local directory {local_dir}: {e}")
                return
            
        if echo:
            print_info(f"Downloading: {self.share}\\{remote_path} --> {local_path}")
        self.download(remote_path, local_path, echo=echo)

    def download(self, remote_path, local_path, echo=True):
        if remote_path.endswith('.') or remote_path.endswith('..'):
            return
        local_path = os.path.normpath(local_path).replace("\\", "/")
        try:
            if echo:
                full_path = ntpath.join(self.share, remote_path)
                print_verbose(f"Downloading file: {full_path} --> {local_path}")
            with open(local_path, 'wb') as file_obj:
                self.conn.getFile(self.share, remote_path, file_obj.write, shareAccessMode=FILE_SHARE_READ|FILE_SHARE_WRITE)
            if echo:
                print_good(f"Downloaded file '{remote_path}' to '{local_path}'")
        except Exception as e:
            print_debug(f"Failed to download file '{remote_path}' to '{local_path}': {e}", sys.exc_info())
            if "STATUS_OBJECT_NAME_NOT_FOUND" in str(e):
                print_warning(f"Remote file '{remote_path}' does not exist.")
            else:
                print_bad(f"Failed to download file '{remote_path}' to '{local_path}': {e}")

    def mget_handler(self, args):
        if not self.check_if_connected():
            return
        remote_path = args.remote_path if args.remote_path else self.relative_path
        if self.is_valid_directory(remote_path):
            local_path = args.local_path if args.local_path else os.getcwd()
            self.mget(remote_path, local_path, args.r, args.p, args.d)
        else:
            print_log(f"Remote directory {remote_path} does not exist.")

    def mget(self, remote_path=None, local_path=None, go_into_dirs=False, regex=None, current_depth=1, max_depth=1):
        if not self.check_if_connected():
            return
        if local_path is None:
            local_path = os.getcwd()

        if regex is not None:
            try:
                re.compile(regex)
            except re.error:
                print_log(f"Invalid regex: {regex}")
                return

        if remote_path is None:
            remote_path = self.relative_path

        list_path = remote_path + '\\*' if remote_path else '*'
        files = self.conn.listPath(self.share, list_path)

        for elem in files:
            if elem.is_directory() and go_into_dirs and elem.get_longname() not in ['.', '..']:
                if current_depth > max_depth:
                    return
                new_remote_path = os.path.join(remote_path, elem.get_longname())
                new_local_path = os.path.join(local_path, elem.get_longname())
                os.makedirs(new_local_path, exist_ok=True)
                print_verbose(f"Downloading from directory: {new_remote_path} --> {new_local_path}")
                self.mget(new_remote_path, new_local_path, go_into_dirs, regex, current_depth+1, max_depth)
            elif regex is None or re.match(regex, elem.get_longname()):
                self.download(os.path.join(remote_path, elem.get_longname()), os.path.join(local_path, elem.get_longname()))
                

    def file_exists(self, remote_path):
        """
        Check if a file exists at the specified remote path.

        Args:
            remote_path (str): The path of the remote file to check.

        Returns:
            bool: True if the file exists, False otherwise.
        """
        print_debug(f"Checking if file exists: {remote_path}")
        path = ntpath.normpath(ntpath.join(remote_path, ".."))
        print_debug(f"Listing Files in Directory: {path}")
        files = self.conn.listPath(self.share, path)
        print_debug(f"Checking if file exists: {ntpath.basename(remote_path)}")
        for file in files:
            if file.get_longname() == ntpath.basename(remote_path):
                print_debug(f"File exists: {remote_path}")
                return True
        print_debug(f"File does not exist: {remote_path}")
        return False

    def cat(self, args, echo=False):
            """
            Downloads a file from the remote server and prints its contents.

            Args:
                args (str): The remote path of the file to be downloaded.

            Returns:
                None
            """
            if not self.check_if_connected():
                return
            #print_info(f"Reading file: {args.remote_path}")
            path = ntpath.normpath(ntpath.join(self.relative_path, args.remote_path))#.removeprefix("\\")
            print_verbose(f"Target File: {path}")
            temp_path = tempfile.NamedTemporaryFile(dir='/tmp', delete=False).name
            self.download(path, temp_path, echo=echo)
            try:
                with open(temp_path, 'r', encoding=get_config_value("Codec")) as file_obj:
                    print(file_obj.read())
                os.remove(temp_path)
            except UnicodeDecodeError:
                print_warning(f"Failed to decode file '{path}' using codec {get_config_value('Codec')}.  Try changing the codec using the 'set codec <codec>' command.")
                try:
                    os.remove(temp_path)
                except:
                    pass



    def ls(self, args=None):
        """
            List files and directories in the current directory or the specified path.

            Args:
                args (object): Optional arguments for the ls command.

            Returns:
                None
            """
        # Validate --show option requirements
        if hasattr(args, 'show') and args.show:
            if not args.recursive or not args.output:
                print_warning("--show flag requires both -r (recursive) and -o (output) flags")
                return
                
        if not self.check_if_connected():
            return
        path = args.path
        if path is None or path == "." or path == "":
            if self.relative_path == "":
                path = ""
            else:
                path = self.relative_path
        else:
            path = os.path.normpath(os.path.join(self.relative_path,path))


        #if not self.is_valid_directory(path):
        #    print_bad(f"Invalid directory: {path}")
            #return

        dirList = []

        try:
            if not self.is_valid_directory(path, print_error=False) and "\\" not in path:
                list_path = path
            else:
                list_path = path + '\\*' if path else '*'
            files = self.conn.listPath(self.share, list_path)
            for f in files:
                creation_time = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=f.get_ctime()/10)).replace(microsecond=0)
                last_access_time = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=f.get_atime()/10)).replace(microsecond=0)
                last_write_time = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=f.get_mtime()/10)).replace(microsecond=0)
                filesize = sizeof_fmt(f.get_filesize())
                file_type = 'D' if f.is_directory() else 'F'
                attributes = ''
                if f.is_readonly(): attributes += 'R'
                if f.is_hidden(): attributes += 'H'
                if f.is_system(): attributes += 'S'
                if f.is_archive(): attributes += 'A'
                
                long_name = f.get_longname()
                # attributes is file type - attributes (if not empty)
                attribs = file_type if attributes == '' else file_type + "," + attributes
                if args.long:
                    dirList.append([attribs, creation_time, last_access_time, last_write_time, filesize, long_name])
                else:
                    dirList.append([attribs, long_name])
            if path == "\\":
                suffix = ""
            else:
                suffix = path + "\\"
            # Determine output file if specified
            output_file = None
            if hasattr(args, 'output') and args.output:
                output_file = args.output
                
            with tee_output(output_file):
                print_info("Showing file listing for: " + os.path.normpath(self.share + "\\" + suffix))

                # get sort option from arg.sort
                sort_option = args.sort
                reverse_sort_option = args.sort_reverse
                if sort_option == "name":
                    if reverse_sort_option:
                        dirList.sort(key=lambda x: x[5], reverse=True)
                    else:
                        dirList.sort(key=lambda x: x[5])
                elif sort_option == "created":
                    if reverse_sort_option:
                        dirList.sort(key=lambda x: x[1], reverse=True)
                    else:
                        dirList.sort(key=lambda x: x[1])
                elif sort_option == "lastaccess":
                    if reverse_sort_option:
                        dirList.sort(key=lambda x: x[2], reverse=True)
                    else:
                        dirList.sort(key=lambda x: x[2])
                elif sort_option == "lastwrite":
                    if reverse_sort_option:
                        dirList.sort(key=lambda x: x[3], reverse=True)
                    else:
                        dirList.sort(key=lambda x: x[3])
                elif sort_option == "size":
                    if reverse_sort_option:
                        dirList.sort(key=lambda x: x[4], reverse=True)
                    else:
                        dirList.sort(key=lambda x: x[4])
                if args.long:
                    print_log(tabulate(dirList, headers=['Attribs', 'Created', 'LastAccess', 'LastWrite', 'Size', 'Name'], tablefmt='psql'))
                else:
                    print_log(tabulate(dirList, headers=['Attribs', 'Name']))
                
                if args.recursive:
                    print_info(f"Recursively listing files and directories in {path} at depth {args.recursive}")
                    depth = args.recursive
                    self._recursive_ls(path, depth, args)
            
            # Notify user if output was saved
            if output_file:
                print_good(f"Output saved to: {output_file}")
                
            # Show saved file contents if --show flag is used
            if hasattr(args, 'show') and args.show and output_file:
                print_info("Displaying saved recursive listing:")
                print("=" * 50)
                try:
                    with open(output_file, 'r') as f:
                        print(f.read())
                except FileNotFoundError:
                    print_warning(f"Saved file not found: {output_file}")
                except Exception as e:
                    print_warning(f"Error reading saved file: {e}")
                print("=" * 50)

        except Exception as e:
            if "STATUS_NO_SUCH_FILE" in str(e):
                print_warning(f"Invalid directory or file: {path}")
            else:
                print_debug(f"Failed to list file or directory {path} on share {self.share}: {e}", sys.exc_info())
            
    def _recursive_ls(self, path, depth, args):
        """Recursively list directory contents"""
        if depth < 0:  # Changed from <= to < to allow specified depth
            return

        try:
            # 1. List current directory
            norm_path = ntpath.normpath(path)
            list_path = ntpath.join(norm_path, '*')
            files = self.conn.listPath(self.share, list_path)
            
            # 2. Process files and collect directories
            dirList = []
            subdirs = []
            
            for f in files:
                if f.get_longname() in ['.', '..']:
                    continue
                    
                # Add to current listing
                if args.long:
                    try:
                        dirList.append([
                            self._get_file_attributes(f),
                            datetime.fromtimestamp(f.get_create_time()),
                            datetime.fromtimestamp(f.get_last_access_time()),
                            datetime.fromtimestamp(f.get_last_write_time()),
                            f.get_filesize(),
                            f.get_longname()
                        ])
                    except Exception as e:
                        print_debug(f"Error getting file attributes: {e}")
                        continue
                else:
                    dirList.append([self._get_file_attributes(f), f.get_longname()])
                
                # Collect directories for later
                if hasattr(f, 'get_attributes') and f.get_attributes() & 0x10:
                    subdirs.append(f.get_longname())
            
            # 3. Print current directory contents
            if dirList:
                print_info(norm_path)
                if args.long:
                    print_log(tabulate(dirList, headers=['Attribs', 'Created', 'LastAccess', 'LastWrite', 'Size', 'Name']))
                else:
                    print_log(tabulate(dirList, headers=['Attribs', 'Name']))
            
            # 4. Process subdirectories
            for subdir in subdirs:
                new_path = ntpath.join(norm_path, subdir)
                self._recursive_ls(new_path, depth - 1, args)
                    
        except Exception as e:
            print_debug(f"Error listing {norm_path}: {str(e)}")

    def _get_file_attributes(self, f):
        """Convert SMB file attributes to string"""
        attrs = []
        if hasattr(f, 'get_attributes'):
            attr_val = f.get_attributes()
            if attr_val & 0x10:
                attrs.append('D')
            if attr_val & 0x20:
                attrs.append('A')
            if attr_val & 0x1:
                attrs.append('R')
            if attr_val & 0x2:
                attrs.append('H')
            if attr_val & 0x4:
                attrs.append('S')
        return ''.join(attrs) or '-'

    # ============================================================================
    # FILE SEARCH FUNCTIONALITY
    # ============================================================================

    def find_handler(self, args):
        """
        Handle find command with comprehensive search capabilities.
        
        Args:
            args: Parsed command line arguments containing search parameters
        """
        if not self.check_if_connected():
            print_warning("You are not connected to a share.")
            return
            
        try:
            # Validate and normalize search path
            is_valid, search_path, error = self._normalize_path_for_smb(self.relative_path, args.path)
            if not is_valid:
                print_warning(f"Invalid search path: {error}")
                return
                
            # Show verbose information if enabled
            print_verbose(f"Search Path (Before): {args.path}")
            print_verbose(f"Search Path (After): {search_path}")
            print_verbose(f"Search Pattern: {args.pattern}")
            
            # Validate search parameters
            if args.maxdepth <= 0:
                print_warning("Maximum depth must be greater than 0")
                return
                
            if args.mindepth < 0:
                print_warning("Minimum depth cannot be negative")
                return
                
            if args.mindepth >= args.maxdepth:
                print_warning("Minimum depth must be less than maximum depth")
                return
            
            # Perform the search
            results = self._find_files(
                pattern=args.pattern,
                search_path=search_path,
                file_type=args.type,
                size_filter=args.size,
                mtime_filter=args.mtime,
                ctime_filter=args.ctime,
                atime_filter=args.atime,
                use_regex=args.regex,
                case_insensitive=args.iname,
                max_depth=args.maxdepth,
                min_depth=args.mindepth,
                include_hidden=args.hidden,
                find_empty=args.empty,
                limit=args.limit,
                show_progress=args.progress
            )
            
            if not results:
                print_info("No files found matching the search criteria.")
                return
                
            # Sort results
            results = self._sort_find_results(results, args.sort, args.reverse)
            
            # Apply limit if specified
            if args.limit and len(results) > args.limit:
                results = results[:args.limit]
                print_info(f"Results limited to {args.limit} entries")
            
            # Format and display results
            output_file = args.output if hasattr(args, 'output') else None
            with tee_output(output_file):
                self._display_find_results(results, args.format, search_path)
                
            # Notify if output was saved
            if output_file:
                print_good(f"Search results saved to: {output_file}")
                
        except Exception as e:
            print_debug(f"Find operation failed: {str(e)}", sys.exc_info())
            print_bad(f"Search failed: {e}")

    def _find_files(self, pattern, search_path="", file_type="a", size_filter=None,
                   mtime_filter=None, ctime_filter=None, atime_filter=None,
                   use_regex=False, case_insensitive=False, max_depth=10, min_depth=0,
                   include_hidden=False, find_empty=False, limit=None, show_progress=False):
        """
        Core file search implementation with recursive directory traversal.
        
        Returns:
            List of dictionaries containing file information
        """
        import re
        import fnmatch
        from datetime import datetime, timedelta
        
        results = []
        total_dirs_searched = 0
        total_files_examined = 0
        
        try:
            # Compile search pattern
            if use_regex:
                try:
                    if case_insensitive:
                        compiled_pattern = re.compile(pattern, re.IGNORECASE)
                    else:
                        compiled_pattern = re.compile(pattern)
                except re.error as e:
                    raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
            else:
                # For wildcard patterns, we'll use fnmatch
                compiled_pattern = pattern.lower() if case_insensitive else pattern
            
            # Parse size filter if provided
            size_operator, size_bytes = self._parse_size_filter(size_filter) if size_filter else (None, None)
            
            # Calculate date thresholds if provided
            now = datetime.now()
            mtime_threshold = now - timedelta(days=mtime_filter) if mtime_filter else None
            ctime_threshold = now - timedelta(days=ctime_filter) if ctime_filter else None
            atime_threshold = now - timedelta(days=atime_filter) if atime_filter else None
            
            # Perform recursive search
            self._recursive_find(
                search_path, pattern, compiled_pattern, use_regex, case_insensitive,
                file_type, size_operator, size_bytes, mtime_threshold, ctime_threshold, atime_threshold,
                include_hidden, find_empty, max_depth, min_depth, 0, results,
                total_dirs_searched, total_files_examined, show_progress, limit
            )
            
            if show_progress:
                print_info(f"Search completed: {total_dirs_searched} directories searched, {total_files_examined} files examined, {len(results)} matches found")
                
        except Exception as e:
            print_debug(f"Error during file search: {str(e)}", sys.exc_info())
            raise
            
        return results

    def _recursive_find(self, current_path, original_pattern, compiled_pattern, use_regex, case_insensitive,
                       file_type, size_operator, size_bytes, mtime_threshold, ctime_threshold, atime_threshold,
                       include_hidden, find_empty, max_depth, min_depth, current_depth, results,
                       total_dirs_searched, total_files_examined, show_progress, limit):
        """
        Recursive directory traversal for file search.
        """
        import fnmatch
        from datetime import datetime
        
        # Check depth limits
        if current_depth > max_depth:
            return
            
        # Check result limit
        if limit and len(results) >= limit:
            return
        
        try:
            # Construct list path
            if current_path:
                list_path = current_path + '\\*'
            else:
                list_path = '*'
                
            # Get directory listing
            files = self.conn.listPath(self.share, list_path)
            total_dirs_searched += 1
            
            if show_progress and total_dirs_searched % 10 == 0:
                print_info(f"Searched {total_dirs_searched} directories, found {len(results)} matches...")
            
            subdirs = []
            
            for f in files:
                if f.get_longname() in ['.', '..']:
                    continue
                    
                total_files_examined += 1
                
                # Check if hidden and whether to include
                is_hidden = f.is_hidden() if hasattr(f, 'is_hidden') else False
                if is_hidden and not include_hidden:
                    continue
                
                # Get file information
                file_info = self._extract_file_info(f, current_path)
                
                # Apply type filter
                if file_type == 'f' and file_info['is_directory']:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                elif file_type == 'd' and not file_info['is_directory']:
                    continue
                
                # Apply depth filter
                if current_depth < min_depth:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                
                # Apply name pattern matching
                filename = file_info['name']
                name_matches = False
                
                if use_regex:
                    name_matches = bool(compiled_pattern.search(filename))
                else:
                    if case_insensitive:
                        name_matches = fnmatch.fnmatch(filename.lower(), compiled_pattern)
                    else:
                        name_matches = fnmatch.fnmatch(filename, original_pattern)
                
                if not name_matches:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                
                # Apply size filter
                if size_operator and size_bytes is not None:
                    if not self._matches_size_filter(file_info['size'], size_operator, size_bytes):
                        if file_info['is_directory']:
                            subdirs.append(f.get_longname())
                        continue
                
                # Apply time filters
                if mtime_threshold and file_info['mtime'] < mtime_threshold:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                    
                if ctime_threshold and file_info['ctime'] < ctime_threshold:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                    
                if atime_threshold and file_info['atime'] < atime_threshold:
                    if file_info['is_directory']:
                        subdirs.append(f.get_longname())
                    continue
                
                # Apply empty filter
                if find_empty:
                    if file_info['is_directory']:
                        # For directories, check if empty by trying to list contents
                        try:
                            empty_check_path = ntpath.join(current_path, filename) if current_path else filename
                            empty_files = self.conn.listPath(self.share, empty_check_path + '\\*')
                            # Directory is empty if it only contains . and ..
                            is_empty = len([f for f in empty_files if f.get_longname() not in ['.', '..']]) == 0
                            if not is_empty:
                                subdirs.append(f.get_longname())
                                continue
                        except:
                            # If we can't check, assume not empty
                            subdirs.append(f.get_longname())
                            continue
                    else:
                        # For files, check if size is 0
                        if file_info['size'] != 0:
                            continue
                
                # File matches all criteria
                results.append(file_info)
                
                # Add to subdirs if it's a directory for further traversal
                if file_info['is_directory']:
                    subdirs.append(f.get_longname())
                
                # Check limit
                if limit and len(results) >= limit:
                    return
            
            # Recursively search subdirectories
            for subdir in subdirs:
                if limit and len(results) >= limit:
                    break
                    
                new_path = ntpath.join(current_path, subdir) if current_path else subdir
                self._recursive_find(
                    new_path, original_pattern, compiled_pattern, use_regex, case_insensitive,
                    file_type, size_operator, size_bytes, mtime_threshold, ctime_threshold, atime_threshold,
                    include_hidden, find_empty, max_depth, min_depth, current_depth + 1, results,
                    total_dirs_searched, total_files_examined, show_progress, limit
                )
                
        except Exception as e:
            print_debug(f"Error searching directory '{current_path}': {str(e)}")
            # Continue searching other directories

    def _extract_file_info(self, f, current_path):
        """
        Extract file information from SMB file object.
        
        Returns:
            Dictionary with file metadata
        """
        from datetime import datetime
        
        try:
            filename = f.get_longname()
            is_directory = f.is_directory()
            
            # Build full path
            if current_path:
                full_path = ntpath.join(current_path, filename)
            else:
                full_path = filename
            
            # Get timestamps (convert from Windows FILETIME to datetime)
            try:
                mtime = datetime(1601, 1, 1) + timedelta(microseconds=f.get_mtime()/10)
                ctime = datetime(1601, 1, 1) + timedelta(microseconds=f.get_ctime()/10)
                atime = datetime(1601, 1, 1) + timedelta(microseconds=f.get_atime()/10)
            except:
                # Fallback to current time if timestamp conversion fails
                now = datetime.now()
                mtime = ctime = atime = now
            
            return {
                'name': filename,
                'path': full_path,
                'size': f.get_filesize(),
                'is_directory': is_directory,
                'mtime': mtime,
                'ctime': ctime,
                'atime': atime,
                'attributes': self._get_file_attributes(f),
                'is_hidden': f.is_hidden() if hasattr(f, 'is_hidden') else False,
                'is_readonly': f.is_readonly() if hasattr(f, 'is_readonly') else False
            }
            
        except Exception as e:
            print_debug(f"Error extracting file info for {f.get_longname()}: {str(e)}")
            # Return minimal info on error
            return {
                'name': f.get_longname(),
                'path': f.get_longname(),
                'size': 0,
                'is_directory': False,
                'mtime': datetime.now(),
                'ctime': datetime.now(),
                'atime': datetime.now(),
                'attributes': '-',
                'is_hidden': False,
                'is_readonly': False
            }

    def _parse_size_filter(self, size_filter):
        """
        Parse size filter string (e.g., '+1MB', '-100KB', '=5GB').
        
        Returns:
            Tuple of (operator, size_in_bytes)
        """
        import re
        
        if not size_filter:
            return None, None
            
        # Parse size filter format: [+|-|=]<number><unit>
        match = re.match(r'^([+\-=]?)(\d+(?:\.\d+)?)([KMGT]?B?)$', size_filter.upper())
        if not match:
            raise ValueError(f"Invalid size filter format: {size_filter}")
        
        operator = match.group(1) or '='
        number = float(match.group(2))
        unit = match.group(3) or 'B'
        
        # Convert to bytes
        multipliers = {
            'B': 1,
            'KB': 1024,
            'MB': 1024**2,
            'GB': 1024**3,
            'TB': 1024**4
        }
        
        if unit not in multipliers:
            raise ValueError(f"Invalid size unit: {unit}")
        
        size_bytes = int(number * multipliers[unit])
        
        return operator, size_bytes

    def _matches_size_filter(self, file_size, operator, target_size):
        """
        Check if file size matches the filter criteria.
        """
        if operator == '+':
            return file_size > target_size
        elif operator == '-':
            return file_size < target_size
        else:  # operator == '='
            return file_size == target_size

    def _sort_find_results(self, results, sort_field, reverse_order):
        """
        Sort find results by specified field.
        """
        try:
            if sort_field == 'name':
                key_func = lambda x: x['name'].lower()
            elif sort_field == 'size':
                key_func = lambda x: x['size']
            elif sort_field == 'mtime':
                key_func = lambda x: x['mtime']
            elif sort_field == 'ctime':
                key_func = lambda x: x['ctime']
            elif sort_field == 'atime':
                key_func = lambda x: x['atime']
            else:
                key_func = lambda x: x['name'].lower()  # Default to name
            
            return sorted(results, key=key_func, reverse=reverse_order)
            
        except Exception as e:
            print_debug(f"Error sorting results: {str(e)}")
            return results  # Return unsorted on error

    def _display_find_results(self, results, output_format, search_path):
        """
        Display search results in specified format.
        """
        import json
        
        if not results:
            return
        
        print_info(f"Found {len(results)} file(s) in '{search_path}':")
        
        if output_format == 'table':
            self._display_results_table(results)
        elif output_format == 'list':
            self._display_results_list(results)
        elif output_format == 'paths':
            self._display_results_paths(results)
        elif output_format == 'json':
            self._display_results_json(results)
        else:
            # Default to table format
            self._display_results_table(results)

    def _display_results_table(self, results):
        """Display results in table format."""
        table_data = []
        for item in results:
            size_str = sizeof_fmt(item['size']) if not item['is_directory'] else '<DIR>'
            mtime_str = item['mtime'].strftime('%Y-%m-%d %H:%M:%S')
            
            table_data.append([
                item['attributes'],
                size_str,
                mtime_str,
                item['path']
            ])
        
        headers = ['Attrs', 'Size', 'Modified', 'Path']
        print_log(tabulate(table_data, headers=headers, tablefmt='psql'))

    def _display_results_list(self, results):
        """Display results in detailed list format."""
        for item in results:
            type_str = "Directory" if item['is_directory'] else "File"
            size_str = sizeof_fmt(item['size']) if not item['is_directory'] else ""
            
            print_log(f"{type_str}: {item['path']}")
            if not item['is_directory']:
                print_log(f"  Size: {size_str}")
            print_log(f"  Attributes: {item['attributes']}")
            print_log(f"  Modified: {item['mtime'].strftime('%Y-%m-%d %H:%M:%S')}")
            print_log(f"  Created: {item['ctime'].strftime('%Y-%m-%d %H:%M:%S')}")
            print_log("")

    def _display_results_paths(self, results):
        """Display only file paths."""
        for item in results:
            print_log(item['path'])

    def _display_results_json(self, results):
        """Display results in JSON format."""
        import json
        
        # Convert datetime objects to strings for JSON serialization
        json_results = []
        for item in results:
            json_item = item.copy()
            json_item['mtime'] = item['mtime'].isoformat()
            json_item['ctime'] = item['ctime'].isoformat()
            json_item['atime'] = item['atime'].isoformat()
            json_results.append(json_item)
        
        print_log(json.dumps(json_results, indent=2))

    def _normalize_path(self, path):
        """
        Normalize a path using Windows path conventions.
        Always use this for any path operations.
        """
        if not path:
            return ""
        return ntpath.normpath(path)

    def _is_absolute_path(self, path):
        """
        Check if a path is absolute (starts with \\ or contains drive letter).
        """
        if not path:
            return False
        return path.startswith("\\") or (len(path) > 2 and path[1] == ":")

    def _normalize_path_for_smb(self, base_path, target_path):
        """
        Normalize path for SMB operations. SMB server handles all access control.
        Returns (is_valid, normalized_path, error_message)
        """
        try:
            # Normalize the target path
            normalized = self._normalize_path(target_path)
            
            # Handle drive letter paths - not supported in SMB context
            if len(target_path) > 2 and target_path[1] == ":":
                return False, "", f"Drive letter paths not supported. Use share-relative paths instead of '{target_path}'"
            
            # If absolute path (starts with \), don't join with base
            if self._is_absolute_path(target_path):
                # Strip leading backslashes for share-relative absolute paths
                normalized = normalized.lstrip("\\")
                final_path = normalized
            else:
                # Relative path - join with base
                if base_path:
                    combined = ntpath.join(base_path, normalized)
                    final_path = self._normalize_path(combined)
                else:
                    final_path = normalized
            
            return True, final_path, ""
            
        except Exception as e:
            return False, "", f"Path normalization error: {str(e)}"

    def _resolve_remote_path(self, user_path, default_name=None):
        """
        Resolve a user-provided path for remote operations.
        Handles both absolute and relative paths securely.
        
        Args:
            user_path: Path provided by user
            default_name: Default filename if user_path is "." or empty
            
        Returns:
            (success, resolved_path, error_message)
        """
        # Handle default/current directory cases
        if user_path in [".", "", None]:
            if default_name:
                user_path = default_name
            else:
                user_path = ""
        
        # Handle different path types
        if user_path == "../":
            # Parent directory reference - combine with filename
            if default_name:
                # Get parent directory path and add filename
                parent_path = ntpath.dirname(self.relative_path) if self.relative_path else ""
                user_path = ntpath.join(parent_path, default_name) if parent_path else default_name
            else:
                # Just the parent directory
                user_path = ntpath.dirname(self.relative_path) if self.relative_path else ""
        elif "\\" not in user_path and "/" not in user_path and user_path not in [".", "..", ""]:
            # Simple filename, place in current directory
            if self.relative_path:
                user_path = ntpath.join(self.relative_path, user_path)
        
        # Normalize the path
        is_valid, resolved_path, error = self._normalize_path_for_smb(self.relative_path, user_path)
        
        return is_valid, resolved_path, error