from collections import defaultdict
def print_process_tree(processes, verbose=False):
    """
    Given a dictionary of processes keyed by PID (each with 'Name', 'PID', 'PPID', etc.),
    print an ASCII tree where processes are nested under their parent (by PPID).
    
    If a process is orphaned (its PPID chain does not lead to a valid root),
    it will be attached to the root level along with the main tree.
    """
    

    # Build mapping: PPID -> list of child processes.
    children = defaultdict(list)
    for proc in processes.values():
        children[proc["PPID"]].append(proc)
    for ppid in children:
        children[ppid].sort(key=lambda x: x["PID"])

    # Recursive function to print a branch from a given PID.
    def print_branch(pid, prefix="", visited=None):
        if visited is None:
            visited = set()
        if pid in visited:
            #print(prefix + "* [Cycle detected] (PID: {})".format(pid))
            return
        visited.add(pid)
        for i, proc in enumerate(children.get(pid, [])):
            if i == len(children[pid]) - 1:
                connector = "└── "
                new_prefix = prefix + "    "
            else:
                connector = "├── "
                new_prefix = prefix + "│   "
            if verbose:
                print(prefix + connector + f'{proc["Name"]} (PID: {proc["PID"]} | PPID: {proc["PPID"]} | Handles: {proc["Handles"]} | Threads: {proc["Threads"]})')
            else:
                print(prefix + connector + f'{proc["Name"]} (PID: {proc["PID"]} | PPID: {proc["PPID"]})')
            if proc["PID"] != proc["PPID"]:
                print_branch(proc["PID"], new_prefix, visited.copy())

    # Determine reachable processes: those connected (via PPID chain) to a valid root (PPID 0).
    reachable = set()
    def mark_reachable(pid, visited=None):
        if visited is None:
            visited = set()
        if pid in visited:
            return
        visited.add(pid)
        reachable.add(pid)
        for proc in children.get(pid, []):
            if proc["PID"] != proc["PPID"]:
                mark_reachable(proc["PID"], visited.copy())
    mark_reachable(0)

    # Collect orphan roots: processes not reachable from 0.
    orphan_roots = [
        proc for proc in processes.values()
        if proc["PID"] not in reachable and (proc["PPID"] in reachable or proc["PPID"] not in processes)
    ]

    # Print main tree starting from PPID 0.

    if 0 in children:
        print_branch(0, "")
    else:
        print("No root processes with PPID 0 found.")

    # Instead of a separate orphan section, attach orphan roots at the root level.
    if orphan_roots:
        #print("\nAdditional Orphan Branches attached to root:")
        printed_orphans = set()
        for proc in sorted(orphan_roots, key=lambda x: x["PID"]):
            if proc["PID"] in printed_orphans:
                continue
            if verbose:
                print(f'----{proc["Name"]} (PID: {proc["PID"]} | PPID: {proc["PPID"]} | Handles: {proc["Handles"]} | Threads: {proc["Threads"]})')
            else:
                print(f'----{proc["Name"]} (PID: {proc["PID"]} | PPID: {proc["PPID"]})')
            print_branch(proc["PID"], "    ")
            def mark_printed(pid):
                printed_orphans.add(pid)
                for child in children.get(pid, []):
                    if child["PID"] != child["PPID"]:
                        mark_printed(child["PID"])
            mark_printed(proc["PID"])
