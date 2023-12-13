from slinger.utils.printlib import *
from slinger.utils.common import *
from tabulate import tabulate
import os, sys, re, ntpath
import datetime, tempfile




class smblib():

    def __init__(self):
        print_debug("Smb Commands Module Loaded!")

    def print_current_path(self):
        print_log(self.current_path)

    # connect to a share
    def connect_share(self, share):
        try:
            self.tree_id = self.conn.connectTree(share)
            self.share = share
            print_good(f"Connected to share {share}")
            self.is_connected_to_share = True
            self.update_current_path()
        except Exception as e:
            if "STATUS_BAD_NETWORK_NAME" in str(e):
                print_bad(f"Failed to connect to share {share}: Invalid share name.")
            else:
                print_bad(f"Failed to connect to share {share}: {e}")
            raise e

    

    def list_shares(self):
        shares = self.conn.listShares()
        print_info("Available Shares")
        for share in shares:
            print_log(f"{share['shi1_netname']}")

    def mkdir(self, path):
        
        try:
            self.conn.createDirectory(self.share, path)
            print_info(f"Directory created {path}")
        except Exception as e:
            print_bad(f"Failed to create directory {path}: {e}")
            raise e

    def rmdir(self, path):
        try:
            self.conn.deleteDirectory(self.share, path)
            print_info(f"Directory removed {path}")
        except Exception as e:
            print_bad(f"Failed to remove directory {path}: {e}")
            raise e

    def delete(self, remote_path):
        self.conn.deleteFile(self.share, remote_path)

    #update current path as share + relative path
    def update_current_path(self):
        #self.current_path = os.path.normpath(self.share + "\\" + self.relative_path)
        self.current_path = ntpath.normpath(self.share + "\\" + self.relative_path)

    # validate the directory exists
    def is_valid_directory(self, path):
        list_path = path + '\\*' if path else '*'
        try:
            self.conn.listPath(self.share, list_path)
            return True
        except Exception as e:
            return False

    def cd(self, path):
        # Handle ".." in path
        if ".." in path:
            path = os.path.normpath(os.path.join(self.relative_path, path))
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
            path = ntpath.normpath(os.path.join(self.relative_path, path))

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
    def upload(self, local_path, remote_path):
        try:
            with open(local_path, 'rb') as file_obj:
                self.conn.putFile(self.share, remote_path, file_obj.read)
        except Exception as e:
            print_bad(f"Failed to upload file {local_path} to {remote_path}: {e}")
            print_log(sys.exc_info())

    def download(self, remote_path, local_path):
        if remote_path.endswith('.') or remote_path.endswith('..'):
            return

        try:
            with open(local_path, 'wb') as file_obj:
                self.conn.getFile(self.share, remote_path, file_obj.write)
        except Exception as e:
            print_bad(f"Failed to download file {remote_path} to {local_path}: {e}")
            print_log(sys.exc_info())

    def mget(self, remote_path=None, local_path=None, go_into_dirs=False, regex=None, current_depth=1, max_depth=1):
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
        files = self.conn.listPath(self.share, remote_path)
        for file in files:
            if file.get_longname() == os.path.basename(remote_path):
                return True
        return False

    def cat(self, path):
        temp_path = tempfile.NamedTemporaryFile(dir='/tmp', delete=False).name
        self.download(path, temp_path)
        with open(temp_path, 'r') as file_obj:
            print_log(file_obj.read())
        os.remove(temp_path)

    # dir list
    def dir_list(self, path=None):
        if path is None or path == "." or path == "":
            if self.relative_path == "":
                path = ""
            else:
                path = self.relative_path
        else:
            path = os.path.normpath(os.path.join(self.relative_path,path))


        if not self.is_valid_directory(path):
            print_bad(f"Invalid directory: {path}")
            return

        dirList = []
        if self.share is None:
            print_warning("No share is connected. Use the 'use' command to connect to a share.")
            return
        try:
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
                dirList.append([file_type, creation_time, last_access_time, last_write_time, filesize, attributes, long_name])
            if path == "\\":
                suffix = ""
            else:
                suffix = path + "\\"
            print_info("Showing directory listing for: " + os.path.normpath(self.share + "\\" + suffix))
            print_log(tabulate(dirList, headers=['Type', 'Created', 'Last Access', 'Last Write', 'Size', 'Attribs', 'Name'], tablefmt='psql'))
        except Exception as e:
            print_bad(f"Failed to list directory {path} on share {self.share}: {e}")
