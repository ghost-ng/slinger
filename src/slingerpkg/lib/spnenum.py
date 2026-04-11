from slingerpkg.utils.printlib import *


class spnenum:
    def __init__(self):
        print_debug("SPNEnum Module Loaded!")

    def spnenum(self, args):
        """Enumerate Service Principal Names (SPNs) from the domain.

        Supports atexec and wmiexec methods.
        Useful for identifying Kerberoasting / silver ticket targets.
        """
        method = getattr(args, "method", "atexec")
        query = getattr(args, "query", "*/*")

        if method in ("atexec", "wmiexec"):
            self._spnenum_exec(method, query, parent_args=args)
        else:
            print_bad(f"Unknown method: {method}")

    def _spnenum_exec(self, method, query, parent_args=None):
        """Enumerate SPNs via setspn command execution."""
        if not self.check_if_connected():
            return

        cmd = f"setspn -Q {query}"
        print_info(f"Enumerating SPNs via {method} (setspn -Q {query})...")

        if method == "atexec":
            from slingerpkg.utils.common import generate_random_string
            import argparse as _argparse

            # Use atexec options from parent args if provided
            tn = getattr(parent_args, "tn", None) if parent_args else None
            if not tn:
                tn = f"SlingerTask_{generate_random_string(6, 8)}"

            atexec_args = _argparse.Namespace(
                command=cmd,
                no_output=False,
                tn=tn,
                ta=getattr(parent_args, "ta", "SYSTEM") if parent_args else "SYSTEM",
                td=(
                    getattr(parent_args, "td", "System Maintenance")
                    if parent_args
                    else "System Maintenance"
                ),
                tf=getattr(parent_args, "tf", "\\Windows") if parent_args else "\\Windows",
                sp=self._resolve_output_path(getattr(parent_args, "sp", None)),
                sn=getattr(parent_args, "sn", None) if parent_args else None,
                wait=getattr(parent_args, "wait", 5) if parent_args else 5,
                shell=False,
            )
            self.atexec(atexec_args)
        elif method == "wmiexec":
            result = self.execute_wmi_command(
                command=cmd,
                capture_output=True,
                timeout=60,
                working_dir=self.wmi_working_dir,
                shell="cmd",
            )
            if result.get("success") and result.get("output"):
                print(result["output"])
            elif not result.get("success"):
                print_bad("WMI execution failed")
