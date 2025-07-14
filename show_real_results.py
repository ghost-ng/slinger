#!/usr/bin/env python3
"""
Show real event log results with debug output - NO MOCK DATA
"""

import pexpect
import sys
import time


def show_real_results():
    """Connect to HTB and show actual event log results"""
    print("=== SHOWING REAL EVENT LOG RESULTS - NO MOCK DATA ===")
    print("Connection: administrator@10.10.11.69")
    print()

    try:
        cmd = "bash -c 'source htb_test_env/bin/activate && python src/slingerpkg/slinger.py -user administrator -host 10.10.11.69 -ntlm :8da83a3fa618b6e3a00e93f676c92a6e'"

        child = pexpect.spawn(cmd, timeout=60, encoding="utf-8")
        child.logfile = sys.stdout

        # Connect
        print("--- Connecting ---")
        child.expect(r"🤠.*>", timeout=60)
        print("\n✓ Connected")

        # Use C$ share
        child.sendline("use C$")
        child.expect(r"🤠.*>", timeout=30)
        print("\n✓ Connected to C$ share")

        # Enable debug to see what's really happening
        print("\n--- Enabling Debug Mode ---")
        child.sendline("set debug true")
        child.expect(r"🤠.*>", timeout=10)
        print("✓ Debug enabled")

        # Try Application log with debug
        print("\n--- Querying Application Log with Debug Output ---")
        child.sendline("eventlog query -log Application -count 2")
        child.expect(r"🤠.*>", timeout=30)

        # Try Security log
        print("\n--- Querying Security Log ---")
        child.sendline("eventlog query -log Security -count 1")
        child.expect(r"🤠.*>", timeout=30)

        # Try event log list
        print("\n--- Listing Event Logs ---")
        child.sendline("eventlog list")
        child.expect(r"🤠.*>", timeout=30)

        print("\n--- Exiting ---")
        child.sendline("exit")
        child.expect(pexpect.EOF, timeout=10)

        return True

    except Exception as e:
        print(f"\nError: {e}")
        return False


if __name__ == "__main__":
    show_real_results()
