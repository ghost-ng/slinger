#!/usr/bin/env python3
import os
import re
import sys
import json
import queue
import shlex
import threading
import subprocess
import time
import pexpect
from openai import OpenAI
from dotenv import load_dotenv
from slingerpkg.automation.vars import ANSI, PROMPT, COMMAND_LIST
from slingerpkg.utils.printlib import print_info

load_dotenv()
OPENAI_MODEL = "gpt-4.1-nano"
API = OpenAI()

#
# Normalize COMMAND_LIST (comma-sep string) into a real list of commands
#
if isinstance(COMMAND_LIST, str):
    WHITELIST = [c.strip() for c in COMMAND_LIST.split(",") if c.strip()]
else:
    WHITELIST = COMMAND_LIST

# 2) Load full help markdown (if you generated cli_menu.md)
HELP_MD = ""
if os.path.exists("cli_menu.md"):
    HELP_MD = open("cli_menu.md").read()

# 3) System prompt for ChatGPT
SYSTEM_PROMPT = f"""
You are an expert penetration tester and slinger user - you need to use your knowledge of the Windows 
platform and understanding of Windows internals.
You are INSIDE the slinger REPL (no external tools).  You have made an initial smd connection with slinger
and are now in the slinger REPL.  

For file system activities, you need to first connect to a share.
Otherwise, you can always run help to view available commands and <command> --help to view
command-specific help.  Also for file system activities, your paths must be UNC paths and 
be relative to the share you are connected to.  Do not include a host name or IP address in your paths.
Example: cd <share>$/Windows/System32
Example: ls <share>$/Windows/System32/
Valid commands: \n{COMMAND_LIST}

DO NOT USE command chaining.  You MUST validate your commands before running them.
If your commands yield error then you need to check the command syntax, possibly run <command> -h, 
and try differnt syntax until is works.

Never use placeholders—always extract real data (paths, user names, share names) 
from prior command outputs.  Do not use wildcards or regex in your commands 
unless the command's help documentation specifically states it is supported.
For example, do not use `*` or `?` in slinger commands unless there is an example in the help documentation.
Do not use placeholders like `<username>` or `<share name>`.  Use real data.

File paths with spaces must be entirely in quotes.

Whenever asked for a plan you MUST respond by calling the function get_step_plan 
with exactly:

{{
  "step": {{
     "narrative": "<what this does>",
     "command":   "<FULL slinger command>"
  }}
}}

Only return valid JSON.  When the work is done reply with:

{{"step":null}}
Do not stop until all objectives are completed or you believe you have exhausted all options.
Help documentation for slinger cli commands.
{HELP_MD}
"""

# 4) Extend your function list with a verification call
FUNCTIONS = [
  {
    "name": "get_step_plan",
    "description": "Return the next narrative+command or null",
    "parameters": {
      "type": "object",
      "properties": {
        "step": {
          "oneOf":[
            {"type":"null"},
            {
              "type":"object",
              "properties":{
                "narrative":{"type":"string"},
                "command":{"type":"string"}
              },
              "required":["narrative","command"]
            }
          ]
        }
      },
      "required":["step"]
    }
  },
  {
    "name": "verify_objective",
    "description": "Check whether the high-level objective is truly complete",
    "parameters": {
      "type":"object",
      "properties":{
        "complete":{"type":"boolean"},
        "checks":{
          "type":"array",
          "items":{
            "type":"object",
            "properties":{
              "narrative":{"type":"string"},
              "command":{"type":"string"}
            },
            "required":["narrative","command"]
          }
        }
      },
      "required":["complete","checks"]
    }
  }
]

def ask_step(messages):
    resp = API.chat.completions.create(
      model=OPENAI_MODEL,
      messages=messages,
      functions=[FUNCTIONS[0]],
      function_call={"name":"get_step_plan"}
    )
    return json.loads(resp.choices[0].message.function_call.arguments)["step"]

def ask_verify(messages):
    resp = API.chat.completions.create(
      model=OPENAI_MODEL,
      messages=messages,
      functions=[FUNCTIONS[1]],
      function_call={"name":"verify_objective"}
    )
    return json.loads(resp.choices[0].message.function_call.arguments)

# 5) Simple ChatGPT wrapper
# 6) Minimal SlingerController
class SlingerController:
    
    def __init__(self, cmdline):
        self.PROMPT = PROMPT
        self.ANSI = re.compile(ANSI)
        
        parts = shlex.split(cmdline)
        env = os.environ.copy(); env.update({'TERM':'dumb','NO_COLOR':'1'})
        self.proc = pexpect.spawn(parts[0], parts[1:], env=env, encoding='utf-8', echo=False, timeout=30)
        self.proc.logfile_read = sys.stderr
        # sync on first prompt
        self.proc.expect(self.PROMPT)

    def send(self, cmd):
        # run and wait for prompt
        self.proc.sendline(cmd)
        self.proc.expect(self.PROMPT)
        # collect between send and prompt
        raw = self.proc.before.splitlines()
        # drop echoed cmd
        if raw and raw[0].strip() == cmd:
            raw = raw[1:]
        # strip ANSI
        return [self.ANSI.sub("", line) for line in raw]

    def close(self):
        try:
            self.proc.sendline("exit")
            self.proc.expect(pexpect.EOF)
        except:
            pass
        self.proc.close()

# 7) Main loop
def main():
    if len(sys.argv) < 2:
        print("Usage: run_agents_linear.py \"<objective>\"", file=sys.stderr)
        sys.exit(1)

    objective = "Objective: " + sys.argv[1]
    epilog = """
            NOTES:
            Never chain commands and always validate your commands before running them.  You must use one at a time.
            Do not use placeholders or wildcards in your commands unless the command's help 
            documentation specifically states it is supported.  
            For example, do not use globbing characters or wildcards like `*` or `?` in slinger commands unless there is an example 
            in the help documentation.  Do not use placeholders like `<username>` or `<share name>`.  
            Use real data.  All file system commands need to have UNC paths awith proper slashes 
            and be relative to the share you are connected to.  Example: cd <share>$/Windows/System32 (be sure
            to use slashes as they are listed in the help documentation).
            Do not repeat commands unless you must to accomplish the objective.  If you do repeat a command,
            you must check the command syntax, possibly run <command> -h, and try different syntax until it works.
            Do not choose to run commands that are not necessary to accomplish the objective.
            Do not choose to run incorrect commands - which means you must check the help documentation for the command you are running.
            
            Troubleshooting:
            When you encounter errors or unexpected output, you must check the command syntax, possibly run <command> -h,
            and try different syntax until it works.  You must also check the help documentation for the command you are running.
            You must also check the help documentation for the command you are running.  Also, check / (slashes) and '"' (quotes).
            Make sure you aren't duplicating the connected share name in the path.
            If you receive error feedback that appears to be missing a slash, add an extra slash then try again - make sure to also use / not \\

            Disallowed commands:
            # shell
            ! <cmd>
            """
    objective += "\n" + epilog
    connect = (
      "python3 src/slinger.py "
      "-user Administrator "
      "-host 10.0.0.100 "
      "-ntlm :REDACTED_HASH "
      "-nojoy"
    )

    print("▶ Launching Slinger…", file=sys.stderr)
    ctrl = SlingerController(connect)
    messages = [
      {"role":"system","content":SYSTEM_PROMPT},
      {"role":"user",  "content":objective}
    ]

    executed = set()
    history = []   # <-- record each action

    while True:
        step = ask_step(messages)

        # if GPT says it's done, run verification
        if step is None:
            print("\n▶ AI says it's done — verifying…", file=sys.stderr)
            # ask it to verify
            verification = ask_verify(messages)

            # keep retrying verify if it returns bad structure
            while True:
                # if complete == true, we're done
                if verification.get("complete") is True:
                    print("\n▶ Objective verified complete!", file=sys.stderr)
                    break

                # ensure 'checks' is a list and each item has non-empty narrative+command
                checks = verification.get("checks")
                if not isinstance(checks, list) or any(
                    not isinstance(chk.get("narrative"), str) or not chk["narrative"].strip() or
                    not isinstance(chk.get("command"),   str) or not chk["command"].strip()
                    for chk in (checks or [])
                ):
                    print("⚠️ Invalid verify_objective response—missing or empty fields.", file=sys.stderr)
                    # ask GPT to resend verification JSON
                    messages.append({"role":"assistant", "content": json.dumps(verification)})
                    messages.append({"role":"user", "content":
                        "The verify_objective response must be JSON with boolean 'complete' and an array 'checks', "
                        "where each check has non-empty 'narrative' and 'command'. Please resend."
                    })
                    verification = ask_verify(messages)
                    continue

                # valid but complete==false: run the checks
                for chk in checks:
                    nar = chk["narrative"]
                    cmd = chk["command"]
                    out = ctrl.send(cmd)
                    history.append({
                        "phase": "verify",
                        "narrative": nar,
                        "command": cmd,
                        "output": out
                    })
                    print(f"\n[VERIFY] {nar}\n[CMD   ] {cmd}")
                    print("⤷", "\n    ".join(out))
                    messages.append({"role":"assistant","content":json.dumps(chk)})
                    messages.append({"role":"user","content":"Verify output:\n"+ "\n".join(out)})
                # after running all checks, re-enter main planning loop
                break
            if verification.get("complete") is True:
                break
            else:
                continue

        nar = step.get("narrative")
        cmd = step.get("command", "")

        # Validate that cmd is a non-empty string
        if not isinstance(cmd, str) or not cmd.strip():
            print(f"⚠️ Invalid or empty command for narrative: {nar}", file=sys.stderr)
            # Ask ChatGPT to resend a valid command for this narrative
            messages.append({"role":"assistant", "content": json.dumps(step)})
            messages.append({"role":"user", "content":
                f"The last response had an invalid or empty `command` for the step: \"{nar}\". "
                "Please reply with a valid JSON “step” object where “command” is a non-empty string."
            })
            continue

        # SKIP duplicates
        if nar in executed:
            # tell GPT “we already did that” so it can give you a new step
            messages.append({"role":"assistant", "content": json.dumps(step)})
            messages.append({"role":"user",      "content": f"Already ran: {nar}"})
            continue

        executed.add(nar)
        # validate first token is a real slinger command
        token = cmd.split()[0]
        if token not in WHITELIST:
            raise RuntimeError(f"Invalid slinger command: {token}")

        print(f"\n[NARRATIVE] {nar}\n[COMMAND  ] {cmd}")
        out = ctrl.send(cmd)
        # record normal action
        history.append({
            "phase": "execute",
            "narrative": nar,
            "command": cmd,
            "output": out
        })

        #print("⤷ Slinger output:\n    " + "\n    ".join(out))

        # feed back and continue planning
        messages.append({"role":"assistant","content":json.dumps(step)})
        messages.append({"role":"user","content":"Output:\n"+ "\n".join(out)})
        time.sleep(0.5)

    ctrl.close()

    # --- Print a summary of all actions and outputs ---
    print("\n=== Summary of Actions Taken ===")
    for i, act in enumerate(history, 1):
        print(f"{i}. [{act['phase']}] {act['narrative']}")
        print(f"     Command: {act['command']}")
        print("     Output:")
        for line in act["output"]:
            print(f"       {line}")

    # --- Ask ChatGPT for a final assessment based on the history ---
    # Build a concise representation of the history for the model
    history_json = json.dumps(history, indent=2)
    assessment_messages = [
        {"role": "system", "content":
            "You are an expert penetration tester reviewing a completed run. "
            "Given the sequence of actions and their outputs, determine whether the high-level objective was met, "
            "note any issues encountered, and provide recommendations or conclusions."
        },
        {"role": "user", "content":
            f"The following is the history of actions taken:\n```\n{history_json}\n```"
        }
    ]
    resp = API.chat.completions.create(
        model=OPENAI_MODEL,
        messages=assessment_messages,
        temperature=0.0
    )
    assessment = resp.choices[0].message.content.strip()
    print("\n=== ChatGPT Assessment ===")
    print(assessment)

if __name__=="__main__":
    main()