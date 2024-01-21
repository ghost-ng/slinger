from slingerpkg.utils.printlib import *
from slingerpkg.utils.common import *
from tabulate import tabulate
import os, sys, re, ntpath
import datetime, tempfile




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
    def connect_share(self, args):
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

    

    def list_shares(self, args=None):
        shares = self.conn.listShares()
        print_info("Available Shares")
        for share in shares:
            print_log(f"{share['shi1_netname']}")

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
                print_debug(f"Removing file {path}")
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
                        print_debug(f"Found directory {os.path.join(remote_path, f.get_longname())}")
                        continue
                    print_debug(f"Deleting file {os.path.join(remote_path, f.get_longname())}")
                    self.conn.deleteFile(self.share,os.path.join(remote_path, f.get_longname()))
                    print_info(f"File Removed '{os.path.join(remote_path, f.get_longname())}'")
            else:
                print_warning(f"Invalid directory: {remote_path}")
                return
        else:
            print_debug(f"Deleting file '{remote_path}'")
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
        # Handle ".." in path
        print_debug(f"Changing directory to {path}")
        if ".." in path:
            path = ntpath.normpath(ntpath.join(self.relative_path, path))
            if path.startswith(".."):
                print_warning("Cannot go above root directory.")
                return
            elif path == ".":
                path = self.share

        # Handle absolute paths
        elif path.startswith("/"):
            path = path.lstrip("/")

        # Handle relative paths
        else:
            #path = os.path.join(self.relative_path, path)
            path = ntpath.normpath(ntpath.join(self.relative_path, path))

        if path == self.share:
            self.relative_path = ""
            self.update_current_path()
            self.print_current_path()
            
        elif self.is_valid_directory(path):
            self.relative_path = path
            self.update_current_path()
            self.print_current_path()
        else:
            print_warning(f"Invalid directory: {path}")

    # handle file uploads
    def upload_handler(self, args):
        remote_path = ""
        if self.check_if_connected():
            if args.remote_path == "." or args.remote_path == "" or args.remote_path is None or "\\" not in args.remote_path:
                remote_path = ntpath.join(self.relative_path,ntpath.basename(args.local_path))
            else:
                remote_path = args.remote_path
            if os.path.exists(args.local_path):
                print_info(f"Uploading: {args.local_path} --> {self.share}\\{remote_path}")
                self.upload(args.local_path, remote_path)
            else:
                print_warning(f"Local path {args.local_path} does not exist.")

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

    def download_handler(self, args):
        remote_path = os.path.normpath(os.path.join(self.relative_path, args.remote_path))
        local_path = ""
        if self.check_if_connected():
            if args.local_path == "." or args.local_path == "" or args.local_path is None or "/" not in args.local_path:
                local_path = os.path.join(os.getcwd(), os.path.basename(args.remote_path))
            else:
                if os.path.isdir(os.path.dirname(args.local_path)):
                    local_path = os.path.join(args.local_path, ntpath.basename(args.remote_path))
                else:
                    local_path = args.local_path
            if os.path.isdir(os.path.dirname(local_path)):
                remote_path = ntpath.normpath(remote_path)
                print_info(f"Downloading: {ntpath.join(self.share,remote_path)} --> {local_path}")
                self.download(remote_path, local_path)
            else:
                print_warning(f"Local path {args.local_path} does not exist.")

    def download(self, remote_path, local_path):
        if remote_path.endswith('.') or remote_path.endswith('..'):
            return

        try:
            with open(local_path, 'wb') as file_obj:
                self.conn.getFile(self.share, remote_path, file_obj.write)
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
                print_info(f"Downloading from directory: {new_remote_path} --> {new_local_path}")
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

    def cat(self, args):
            """
            Downloads a file from the remote server and prints its contents.

            Args:
                args (str): The remote path of the file to be downloaded.

            Returns:
                None
            """
            if not self.check_if_connected():
                return
            path = ntpath.normpath(ntpath.join(self.relative_path, args.remote_path))
            temp_path = tempfile.NamedTemporaryFile(dir='/tmp', delete=False).name
            self.download(path, temp_path)
            try:
                with open(temp_path, 'r', encoding=get_config_value("Codec")) as file_obj:
                    print(file_obj.read())
            except UnicodeDecodeError:
                print_warning(f"Failed to decode file '{path}' using codec {get_config_value('Codec')}.  Try changing the codec using the 'set codec <codec>' command.")
            os.remove(temp_path)



    def ls(self, args=None):
        """
            List files and directories in the current directory or the specified path.

            Args:
                args (object): Optional arguments for the ls command.

            Returns:
                None
            """
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
        except Exception as e:
            if "STATUS_NO_SUCH_FILE" in str(e):
                print_warning(f"Invalid directory or file: {path}")
            else:
                print_debug(f"Failed to list file or directory {path} on share {self.share}: {e}", sys.exc_info())
            
