# Slinger — TODO / RPC Feature & Enhancement Plan

**Status:** Active plan · last revised 2026-05-05
**Supersedes:** prior `docs/TODO.md` short list and `docs/RPC_FEATURE_PROPOSALS.md` (now removed — content consolidated here)
**Scope:** Fill gaps across the impacket `dcerpc/v5` interface surface, with a
headline focus on **fileless memory injection** primitives and **stealth/legitimacy**
posture for any operation that resembles offensive tradecraft.
**Non-goal:** Reimplementing what already exists upstream (no "psexec-2",
"wmiexec-2", "secretsdump-2"). Every primitive below is either novel composition,
under-served operational tooling, or a stealth-first reframing.

---

## 1. Design Philosophy

These principles are non-negotiable and apply to every primitive proposed below.

| # | Principle | What it means in practice |
|---|-----------|---------------------------|
| 1 | **No disk artifacts on target** for exec/persist primitives | Payloads live in registry, WMI repository, named-pipe transit, or process memory. Anything that has to land on NTFS is rejected unless it's a Microsoft-signed file already present. |
| 2 | **Legitimate-looking metadata** | Service display names, WMI consumer names, registry value names, scheduled-task paths, firewall-rule descriptions all mimic real Windows components by default (configurable opsec profiles). |
| 3 | **Cleanup is part of the operation** | Every offensive primitive ships with a paired `*-cleanup` command and an automatic rollback context manager. Aborted ops back out their state. |
| 4 | **Audit-aware** | Operations that touch monitored surfaces (security log, sysmon channels) check current logging state first and either (a) coordinate (subscribe before acting, snapshot ETW), (b) warn and require `--noisy` opt-in, or (c) refuse if logging anomaly detected. |
| 5 | **Don't recreate what exists** | If impacket's `examples/` has it, slinger doesn't get a thin wrapper. Slinger gets the *next* layer — composition, persistence, eventlog coordination, lifecycle. |
| 6 | **Single-responsibility modules** | One impacket interface → one slinger mixin module → one CLI namespace. Honors the existing inheritance pattern in [slingerclient.py:44](src/slingerpkg/lib/slingerclient.py#L44). |
| 7 | **Track every change** | Every state-mutating primitive calls `self._track(category, action, target, details)` so the existing change tracker can roll back or report. |

---

## 2. Architecture Integration

Slinger's existing pattern is mixin inheritance into `SlingerClient`. New RPC
modules slot in identically:

```
SlingerClient(
    winreg, schtasks, scm, smblib, secrets, spnenum, ticket,
    atexec, wmiexec, EventLog, WMINamedPipeExec, DCETransport,
    # — proposed additions, alphabetized for clarity —
    epmlib,           # endpoint mapper recon + bind helpers
    fasplib,          # firewall RPC
    drsuapilib,       # AD replication (DCSync++ and beyond)
    lsalib,           # lsad + lsat unified
    nrpclib,          # netlogon discovery + (gated) offensive
    samrlib,          # users/groups/SID lookups
    srvslib,          # share/file/session mgmt
    tstslib,          # terminal services
    wkstlib,          # workstation svc
    bkrplib,          # DPAPI BackupKey
    spoolerlib,       # rprn + par unified
    icprlib,          # ADCS cert request
    fileless,         # the memory-injection framework (Section 7)
)
```

Each new mixin lives at `src/slingerpkg/lib/<name>.py`. CLI parsers go in
[src/slingerpkg/utils/cli.py](src/slingerpkg/utils/cli.py) per the existing
convention, with help-categorization entries in `print_all_commands_verbose()`.

**One transport, many ifaces.** Slinger already has `DCETransport`. Extend it
with a `bind_iface(uuid, version, transport='ncacn_np', pipe=None)` helper that
caches DCE bindings per-interface so repeated calls don't pay re-bind cost.
Pipe path defaults driven by an interface→pipe table sourced from EPM (see §3.1).

---

## 3. Phase 1 — Passive Recon & Information Surface

Low-risk, high-value RPC modules currently absent from slinger. Build these
first; they create the substrate that later phases compose against.

### 3.1 `epmlib` — Endpoint Mapper Introspection

**Impacket:** `epm.hept_lookup`, `epm.hept_map`.

**Novel angle:** Most tools use EPM only to *resolve* a known UUID to a port.
Slinger should use it as a **service-surface enumerator**: query `RPC_C_EP_ALL_ELTS`
to dump every registered RPC interface on the target, cross-reference UUIDs
against impacket's known interface table, and emit a triage report:

```
slinger> epmenum
INTERFACE                             VERSION  TRANSPORT     PIPE/PORT          KNOWN AS
12345778-1234-abcd-ef00-0123456789ab  0.0      ncacn_np      \PIPE\lsarpc       LSA RPC
e3514235-4b06-11d1-ab04-00c04fc2dcd2  4.0      ncacn_ip_tcp  49664              DRSUAPI
...
unknown UUIDs flagged with [!] for further research
```

**Why it matters:** drives the "what can I do here?" decision. Also detects
hardened hosts where common interfaces are unbound (e.g., RPC firewall rules
that strip MS-EFSR).

**Commands:** `epmenum`, `epmlookup <uuid>`, `epmmap <uuid> --transport np|tcp`.

### 3.2 `mgmt` — RPC Mgmt Iface (Self-Describing Hosts)

**Impacket:** `mgmt.hinq_if_ids`, `hinq_stats`, `his_server_listening`,
`hinq_princ_name`.

**Novel angle:** Provides a second source of truth alongside EPM. `hinq_if_ids`
returns the interface list as the *server* sees it; comparing against EPM can
reveal interfaces present but unbound to a transport (suggests admin teardown
or RPC filter policy). `hinq_princ_name` recovers the SPN the server uses for
each authn method — useful for kerberoasting target validation without LDAP.

**Commands:** `mgmtifaces`, `mgmtprinc`, `mgmtstats`.

### 3.3 `wkstlib` — Workstation Service

**Impacket helpers:** `hNetrWkstaGetInfo`, `hNetrWkstaUserEnum`,
`hNetrWkstaTransportEnum`, `hNetrGetJoinInformation`, `hNetrUseEnum`, etc.

**Novel angle:** `NetrWkstaUserEnum` returns *currently-logged-on users on the
target*, which is a recon primitive slinger lacks (you only have eventlog +
WMI Win32_LogonSession today). It does not require the user to have a session
on the slinger host. Expose:

```
slinger> wkstusers
USER                LOGON_DOMAIN   LOGON_SERVER   FLAGS
CONTOSO\admin       CONTOSO        DC01           interactive
CONTOSO\svc_sql     CONTOSO        DC01           service
NT AUTHORITY\SYSTEM ...                           system
```

Combine with `tstslib` (§3.6) for full session map.

`NetrUseAdd` / `NetrUseEnum` allow slinger to inspect (and create) outbound SMB
connections from the *target* — useful for pivot reconnaissance ("what shares
is this host already mapping?").

**Stealth-flagged commands:** `wkstjoin/unjoin/rename` operations are noisy —
require explicit `--allow-domain-change` flag and emit a warning that this is
unrecoverable without DA.

**Commands:** `wkstinfo`, `wkstusers`, `wkstuses`, `wksttransports`,
`wkstaltnames`.

### 3.4 `srvslib` — Server Service (NetShareEnum, NetSessionEnum, ...)

**Impacket helpers:** Full `hNetrShare*`, `hNetrSession*`, `hNetrFile*`,
`hNetrConnection*`, `hNetrServer*`.

**Fills existing TODO:** "SMB share management (add/remove shares via
hNetrShareAdd/hNetrShareEnum)".

**Novel angles beyond the TODO:**
- `NetrSessionEnum` — list all SMB sessions *to* the target, not just yours.
  Pairs with `NetrSessionDel` for the ability to surgically drop a session
  (e.g., kick an admin to free a file lock). Stealth note: session-del is
  audited; expose with `--audit-confirm`.
- `NetrFileEnum` + `NetrFileClose` — list/close open files remotely. Lets you
  resolve "file in use" errors during pentests without rebooting.
- `NetrpGetFileSecurity` / `NetrpSetFileSecurity` — read/write file ACLs
  remotely *without* needing a local SMB tree open. This is materially
  different from your existing `smblib` ACL flow — works on shares you can't
  mount.
- `NetrShareAdd` with `STYPE_SPECIAL` flag: create administrative shares
  named `<RANDOM>$` that don't appear in non-admin enumeration.

**Commands:** `shareadd`, `sharedel`, `sharemod`, `sessions`, `sessionkill`,
`openfiles`, `fileclose`, `srvfileacl`.

### 3.5 `lsalib` — LSA (Unified `lsad` + `lsat`)

**Impacket helpers:** SID lookups, policy queries, **secret read/write**, account
rights enumeration, trusted-domain enum.

**Novel angle 1 — secret enumeration as audit:** Most tools dump LSA secrets via
the registry SECURITY hive. The RPC path (`hLsarOpenSecret` / `hLsarQuerySecret`)
needs `LsaOpenPolicy` with `POLICY_GET_PRIVATE_INFORMATION`. Slinger should
expose this as **`lsasecrets-rpc`** — a parallel path that doesn't require
SeBackupPrivilege or hive saves and so leaves a different (often quieter)
audit trail than `secretsdump`.

**Novel angle 2 — privilege deltas:** `LsarEnumeratePrivilegesAccount` against
each account from `LsarEnumerateAccounts` produces a privilege map. Diff
against a baseline snapshot for "who got SeDebugPrivilege overnight?"
detection.

**Novel angle 3 — trust topology:** `LsarEnumerateTrustedDomainsEx` returns
trust direction, attributes (SID-filtering, transitivity). Output as a
mermaid diagram on demand for handoff in pentest reports.

**Commands:** `lsasecrets-rpc`, `lsaprivs`, `lsatrusts`,
`lsalookupsids/names`, `lsapolicy`.

### 3.6 `tstslib` — Terminal Services Session Enum

**Impacket helpers:** `hRpcGetAllSessions`, `hRpcGetSessionInformationEx`,
`hRpcLogoff`, `hRpcDisconnect`, `hRpcShowMessageBox`,
`hRpcIsSessionDesktopLocked`.

**Novel angle:** Pairs with `wkstusers`. TS sessions are richer (idle time,
client IP, console vs. RDP, lock state). Lock state is rare-use intel —
"console session X is unlocked → physical operator present."

`hRpcShowMessageBox` is **not** a payload vector but a **stealth diagnostic** —
useful in red-team exercises where the tester needs to confirm interactive
desktop reach without dropping a popup permanently.

**Stealth posture:** `tstslogoff`/`tstsdisconnect` are session-killing — gate
behind `--confirm-target <session-id>` to avoid fat-finger.

**Commands:** `tssessions`, `tssession <id>`, `tslogoff <id> --confirm-target`,
`tsdesktop-locked? <id>`.

### 3.7 `nrpclib` (recon subset)

**Impacket helpers (passive):** `hDsrGetDcNameEx2`, `hDsrGetSiteName`,
`hNetrLogonGetCapabilities`, `hNetrServerGetTrustInfo`,
`hDsrGetDcSiteCoverageW`.

**Novel angle:** Build a **forest topology snapshot** by walking
`DsrGetDcSiteCoverageW` across discovered DCs. Output a graph (mermaid +
JSON). This is recon you currently get only via `nltest /dsgetdc` or LDAP —
RPC path works against hosts where LDAP is firewalled.

`NetrLogonGetCapabilities` is the canonical Zerologon precursor probe — but
also legitimately tells you if the DC has the secure-channel patch.
Expose as **`nrpc-vuln-probe`**: read-only, returns capability vector with
named flags. Does not exploit. (See §5.3 for the offensive subset.)

**Commands:** `dcdiscover`, `forestmap`, `nrpccaps`, `nrpctrustinfo`.

### 3.8 `iphlp` — IP Helper RPC

**Impacket helpers:** `hIpTransitionCreatev6Inv4Tunnel`,
`hIpTransitionApplyConfigChanges*`.

**Novel angle:** This interface lets you create/delete IPv6-in-IPv4 transition
tunnels remotely — useful for **legitimate network triage** (a customer host
with broken 6to4 needs the tunnel rebuilt) but also represents a
covert-channel surface (creating a tunnel endpoint for traffic blending).
Stealth posture: command requires `--purpose <legit|test>` and the operation
is logged to the slinger session log unconditionally.

**Commands:** `iptunnels`, `iptunnel-add`, `iptunnel-del`.

### 3.9 `dhcpm` — DHCP Server Management

**Impacket helpers:** `hDhcpGetSubnetInfo`, `hDhcpEnumSubnetClientsV5`, etc.

**Novel angle:** Against a target that *is* a DHCP server, enumerate active
leases — this is gold for lateral-movement triage (every IP ↔ MAC ↔ hostname
the server has seen recently). Currently slinger has no path to this without
shelling to `netsh`. Read-only mode by default; write ops (option set) gated
behind `--allow-write`.

**Commands:** `dhcpsubnets`, `dhcpleases <subnet>`, `dhcpoptions <subnet>`.

### 3.10 `even6` — Modern EventLog (XML)

**Impacket helpers:** `hEvtRpcRegisterLogQuery`, `hEvtRpcQueryNext`,
`hEvtRpcGetChannelList`, `hEvtRpcOpenLogHandle`.

**Novel angle:** Slinger has `EventLog` already, but verify it's using `even6`
(modern XML-based query) vs. the legacy `even.py` interface. If legacy:
add `eventlog --xpath '<xpath>'` for arbitrary XPath queries (e.g.,
`*[System/EventID=4624 and EventData/Data[@Name="LogonType"]=10]` for RDP
logons). This is a usability gap, not a primitive gap.

**Commands:** `eventchannels`, `eventquery --xpath`, `eventexport <channel>`.

---

## 4. Phase 2 — Identity, Replication, Cryptographic Material

### 4.1 `samrlib` — SAM Domain/User/Group Management

**Fills existing TODO:** "SAMR user/group management (useradd, usermod,
groupadd, passwd via RPC)".

**Implementation note:** SAMR is broad. Build it as a *unified RPC ORM*
exposing handles cleanly:

```python
with self.samr_connect() as srv:
    with srv.open_domain(domain_sid) as dom:
        with dom.open_user(rid) as usr:
            usr.set_password(new_pw)
            usr.add_to_group("Administrators")
```

CLI surfaces this as one consistent grammar.

**Novel angle beyond TODO — `samr-userdiff`:** Snapshot the user list +
group memberships + last-pw-change timestamps at time T0. On rerun, diff
against snapshot. Detects newly-created accounts, group escalations,
password resets — all from RPC, no eventlog dependency. Output goes to
`change_tracker` so it lands in the project audit trail.

**Stealth-flagged:** `useradd` / `userdel` / `passwd` are universally
audited. Emit warning + require `--allow-noisy`.

**Novel angle — RID cycling for auth probe:** Use SAMR enumeration to
discover SIDs, then probe each via `lsat` `LsarLookupSids` to confirm
account names. This is the SAMR-RID-cycling primitive but framed as
"validate which accounts are reachable via this auth context" rather
than as a standalone enumeration tool.

**Commands:** `useradd`, `userdel`, `usermod`, `passwd`, `groupadd`,
`groupdel`, `groupmod`, `samrenum`, `samrdiff`, `samrridmap`.

### 4.2 `drsuapilib` — Beyond DCSync

**Existing impacket helpers:** `hDRSUnbind`, `hDRSDomainControllerInfo`,
`hDRSCrackNames`. The big calls (`DRSGetNCChanges` for DCSync,
`DRSReplicaAdd`, `DRSVerifyNames`) exist as raw classes — slinger should
wrap them.

**Don't replicate:** secretsdump-style DCSync for all secrets. That's
solved.

**Novel angles:**

1. **`drs-targeted` — single-account DCSync.** Pull *one* user's secrets
   instead of the whole NC. Stealth-relevant: targeted replication
   request looks more like a routine DC operation than a full crawl.
   Pairs with `change_tracker` to log exactly which accounts were
   replicated for the engagement record.

2. **`drs-schema-audit`.** Use `DRSGetNCChanges` against the Schema NC
   to enumerate attribute definitions. Useful for finding non-standard
   attributes (custom schema extensions = potential storage of secrets
   like SSH keys, integration tokens). No tool surfaces this well today.

3. **`drs-replica-topology`.** Use `DRSDomainControllerInfo` +
   `DRSCrackNames` to build the replication graph. Identifies bridgehead
   servers (high-value targets). Output as mermaid.

4. **`drs-canary` (defensive)**. Create a honey object and watch for it
   appearing on a peer DC — verifies whether unexpected replication is
   happening. Edge use, but lives well in the same module.

**Stealth posture:** all `drs-*` ops require `--target-is-dc` flag and
print a one-line warning that DC operations are heavily logged.

**Commands:** `drs-targeted <samaccountname>`, `drs-schema-audit`,
`drs-topology`, `drs-canary install/check`.

### 4.3 `bkrplib` — DPAPI BackupKey

**Impacket helper:** `hBackuprKey`.

**Novel angle:** DPAPI backup-key extraction is well-known, but slinger
should pair it with **opportunistic per-user DPAPI decryption** at the
same shell session — i.e., the moment you obtain the backup key, walk
mounted user profiles for `Credentials/` and `Protect/` blobs and
decrypt in-memory only. No artifacts written.

**Commands:** `dpapi-backupkey`, `dpapi-decrypt --user <name> --in-memory`.

### 4.4 `icprlib` — AD CS Cert Request

**No impacket h-helpers** — build directly on `MS-ICPR` request structure.

**Novel angle:** Request a cert as the current auth context against a
vulnerable template (ESC1 SAN-supply territory). Slinger should ship a
**template-audit** subcommand first — enumerate published templates and
flag misconfig (manager-approval off + supply-SAN-allowed +
client-auth-EKU). The exploit subcommand is gated behind
`--template <name> --san <upn>` and warns about cert-issuance auditing.

Cert is returned as in-memory PFX + parsed metadata. Optional pivot:
hand the PFX to slinger's `ticket` module for PKINIT TGT request.

**Commands:** `adcs-templates`, `adcs-request --template --san`,
`adcs-pivot --template --san --as <upn>` (chains template→cert→TGT).

### 4.5 `sasec` — Scheduled Task Account Secrets

**Impacket helpers:** `hSAGetAccountInformation`,
`hSASetAccountInformation`, `hSAGetNSAccountInformation`,
`hSASetNSAccountInformation`.

**Novel angle:** `SAGetAccountInformation` returns the principal a task
is configured to run as. Combine with slinger's existing schtasks to
find tasks configured to run as *high-value accounts* (DA, service
accounts) — these are kerberoast / coerced-cred candidates. No tool
maps "what tasks are ready to be hijacked because they run as $X?".

`SASetAccountInformation` could *change* a task's run-as account. Off
by default, gated behind `--rewrite-runas` with a noisy confirmation.

**Commands:** `taskprincipals`, `taskhighval` (filtered to interesting
SIDs), `taskrunas-set <task> <user> --rewrite-runas`.

---

## 5. Phase 3 — Stealth-Forward Host Control

### 5.1 `fasplib` — Windows Firewall RPC

**Pure stealth play.** Slinger should never just "disable the firewall"
— that's a giant audit event. Instead, fasplib provides surgical
rule manipulation:

1. **`fw-snapshot`** — capture current rule set into an internal
   handle. Mandatory before any modification.
2. **`fw-allow-callback <port> --as-rule <name-template>`** — open
   one inbound port with a rule whose `Name`, `Description`, and
   `Grouping` mimic a real Windows component (default templates
   shipped: `"@FirewallAPI.dll,-23004"` style identifiers that match
   built-in rules). Rule is **automatically deleted** when the
   slinger session exits or on `fw-rollback`.
3. **`fw-allow-egress <process> <dest>`** — outbound rule scoped to a
   specific binary path, again with masquerade naming.
4. **`fw-rollback`** — restores the snapshot exactly. Idempotent.
5. **`fw-audit-log-state`** — checks if firewall logging is enabled
   (filesize, dropped/allowed). If enabled, warn before any change.

The Python interface to `MS-FASP` isn't a clean h-helper set — implement
via the COM `HNetCfg.FwPolicy2` object surfaced over RPC, **or** via the
underlying `INetFwRules` if direct RPC marshaling is required. (See
impacket source — fasp.py exists but is sparse; will need extension.)

**Internal design:** `fasplib` exposes a `firewall_session()` context
manager. Entering snapshots; exiting rolls back unless `commit()` called.

**Commands:** `fw-snapshot`, `fw-rules`, `fw-add-rule --template`,
`fw-del-rule`, `fw-rollback`, `fw-audit-state`.

### 5.2 `scmr-extensions` — SCM Beyond Service Install

Slinger already has `scm` for service control. Add these *without*
duplicating the service-install pattern (which exists for
psexec-style use):

1. **`scm-enum-vulnerable`** — enumerate services + their binary path
   ACLs + the service ACL itself. Flag services where (a) binary path
   is writable by current user, or (b) service config is mutable
   (`SERVICE_CHANGE_CONFIG`). This is "PrivescCheck" territory but
   slinger lacks it.
2. **`scm-trigger-install`** — install a service with a TRIGGER_START
   trigger (network event, ETW provider, custom event). Avoids
   appearing in `Get-Service | Where StartType -eq Automatic` and
   defers execution. Pairs with §7 fileless framework.
3. **`scm-fail-action-payload`** — set a service's failure action to
   `SC_ACTION_RUN_COMMAND`. The command runs on next service crash.
   Couple with `scm-crash <name>` (issue invalid control code) to
   trigger. Stealth: failure-action runs as SYSTEM.
4. **`scm-share-svchost`** — register a new service sharing an
   existing svchost group. Rarely-monitored config; service appears
   inside an already-running svchost.exe instance.
5. **`scm-acl-snapshot`** — diff service ACLs against baseline (a
   detection primitive for blue-team use of slinger).

**Commands:** `svc-vuln`, `svc-trigger-install`, `svc-failpayload`,
`svc-acldiff`.

### 5.3 `nrpclib` (offensive subset) — Gated

**Helpers:** `hNetrServerPasswordSet2` (Zerologon),
`hNetrServerAuthenticate3`.

**Posture:** Slinger does **not** ship a "zerologon-and-go" command.
It ships:

1. **`nrpc-zerologon-probe`** — read-only check for the auth bypass,
   no state change. Returns "vuln / patched / unknown".
2. **`nrpc-zerologon-restore`** — given a captured machine-account
   hash backup, restore it (defensive use after an exploit).

The actual exploit primitive is intentionally absent from the CLI but
present in the library as `_nrpc_zerologon_set()` for security-research
plugin use, requires explicit `confirm="I understand"` argument.

**Commands:** `nrpc-vuln-probe`, `nrpc-restore-machinepw`.

### 5.4 `spoolerlib` — `rprn` + `par` Unified

**Helpers:** `hRpcEnumPrinterDrivers`, `hRpcAddPrinterDriverEx`,
`hRpcRemoteFindFirstPrinterChangeNotificationEx` (PrinterBug coerce).

**Novel angles:**

1. **`spool-driver-audit`** — enumerate installed printer drivers and
   their on-disk paths. Useful for finding stale/vendor drivers
   (privesc surface).
2. **`spool-coerce <listener>`** — the standard coerce primitive,
   **but** the listener is auto-coordinated with slinger's relay
   subsystem (not yet built — proposed). Slinger should host a built-in
   listener for the resulting auth attempt.
3. **`spool-driver-load`** — `RpcAddPrinterDriverEx` with a UNC path.
   This *does* land a driver file on the spooler driver dir — violates
   principle 1 unless the "driver" is actually `system32\winhttp.dll`
   (LOLbin signed Microsoft path). Flag operation accordingly: **ship
   only with signed-MS-binary path mode**, refuse arbitrary paths
   without `--allow-arbitrary-driver`.

**Commands:** `spool-drivers`, `spool-coerce`, `spool-load-signed`.

---

## 6. Phase 4 — Audit Surface

### 6.1 `even` — EventLog Selective Manipulation

**Off-limits by default, present for blue-team:** Selective record
deletion via direct EVTX manipulation is destructive and forensically
flagged regardless of stealth. Slinger should expose **only**:

1. `eventlog-channel-state <channel>` — read enabled/disabled state.
2. `eventlog-channel-bookmark <channel>` — record the current
   newest-record-id for "did anything new happen since I last
   checked" auditing.
3. `eventlog-snapshot <channel>` — pull current channel to in-memory
   snapshot for offline analysis.

No "clearlog" command. If a customer engagement requires it, that's a
plugin, not core.

---

## 7. Phase 4 — **Fileless Memory Injection Framework**

This is the headline. The goal: a small, composable set of primitives
that let the operator stage and execute a payload in target-process
memory **with no file ever touching the target NTFS volume**.

The framework is named `fileless` and exposes a payload-staging
abstraction backed by multiple delivery channels.

### 7.1 Storage Substrates

A "storage substrate" is anywhere on the target where opaque bytes can
live without being a filesystem file.

| Substrate | Mechanism | Capacity | Persistence | Visibility |
|-----------|-----------|----------|-------------|------------|
| Registry value (`REG_BINARY`) | `rrp` | ~1 MB practical | Survives reboot | Reg auditing if enabled |
| WMI repository (CIM property) | DCOM | ~10 MB practical | Survives reboot | WMI logging rare |
| LSA secret | `lsad` `LsarSetSecret` | ~64 KB | Survives reboot | Audited if SACL set |
| Service description field | `scmr` `RChangeServiceConfig2W` | ~8 KB | Survives reboot | Not audited |
| Schtask description / data | `tsch` | ~64 KB | Survives reboot | Audited only on create |
| AD object attribute (custom schema) | `drsuapi` / LDAP | ~10 MB | Replicates | DC audit |

**Slinger should expose a `payload-stage` command** that takes a local
payload + substrate + opsec profile and writes the bytes:

```
slinger> payload-stage --substrate registry --location "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProxyOverride" --payload ./loader.bin --encrypt
[+] Staged 81920 bytes, AES-256-GCM, key derived from machine SID
[+] Tracked: REGISTRY:write:HKLM\...:81920 bytes
```

**Encryption:** every staged payload is AES-256-GCM encrypted with a
key derived from a deterministic source chosen by the operator
(machine SID + a session salt = key recoverable on next session
without slinger remembering anything). This means a forensic snapshot
of the substrate alone is opaque.

### 7.2 Delivery Channels

A "delivery channel" is the trigger that loads staged bytes into
process memory and executes them. Each channel has a stealth/footprint
profile.

#### 7.2.1 WMI Permanent Event Subscription

**Mechanism:** `__EventFilter` + `ActiveScriptEventConsumer` (JScript)
+ `__FilterToConsumerBinding`. The JScript reads the staged payload
from registry/WMI, decrypts in-process, and executes via reflective
.NET assembly load (`mscoree.dll` `CorBindToRuntimeEx`).

**Stealth notes:**
- Default consumer name template: `"BVTConsumer"` /
  `"SCM Event Filter"` / `"NTEventLogProvider"` (mimics built-in
  WMI providers in `root\subscription`).
- Filter scoped to a low-volume rare event (e.g.,
  `__InstanceModificationEvent` on a specific perf counter that
  changes ~once/hour) to avoid execution flood.
- Operator chooses trigger event class: time-based, logon-based
  (`Win32_LogonSession`), network-based
  (`MSFT_NetIPAddressNotification`), process-based
  (`Win32_ProcessStartTrace`).

**Cleanup:** `wmi-persist-rm <name>` removes filter, consumer, binding
in correct order (binding first, else dangling references).

**Commands:** `wmi-persist install --trigger <wql> --payload-ref <substrate-uri> --consumer-name <name>`,
`wmi-persist list`, `wmi-persist rm`.

#### 7.2.2 Registry-Resident COM Hijack with Scriptlet Trigger

**Mechanism:** Register a fresh CLSID (or hijack a per-user
underused one — the per-machine option is noisier) where
`InProcServer32` points to `scrobj.dll` (Windows Script Component
runtime, signed Microsoft) and the scriptlet moniker is itself a
data-URL with the script inline (so no HTTP fetch). Trigger by
invoking the COM object via a scheduled task with action type
`ComHandler`.

**Stealth notes:**
- All artifacts live in registry keys under `HKLM\SOFTWARE\Classes\CLSID`.
- Scriptlet content fits in a single registry value as base64 SCT XML.
- Schtask uses `ComHandler` action — quieter in some environments
  than `Exec` actions because security tooling often watches `Exec`
  command lines preferentially.

**Commands:** `comhandler-install --clsid <auto|guid> --schtask <name> --payload-ref <uri>`,
`comhandler-rm`.

#### 7.2.3 Service Trigger-Start (Etw / Network / Custom)

**Mechanism:** `scmr` `RCreateServiceW` with `SERVICE_TRIGGER_INFO`
configured to start on a custom-named ETW event. The service binary
is `svchost.exe` pointing at a registry-resident "service DLL" entry
that's actually the address of an existing legitimate service DLL
(loads cleanly). The *real* payload lives in a separate registry value
that an in-process trigger via DLL search-order or AppInit-equivalent
loads.

This one is thorny — the cleanest fileless variant requires either
(a) the existence of an exploitable already-installed service DLL or
(b) accepting a one-time write of an MS-signed binary (LOLbin).
Recommend implementing **only** the trigger-install half; pair with a
*separate* operator-supplied payload-load mechanism. Document
limitation explicitly.

**Commands:** `svc-trigger-install --etw <provider/event> --target-svchost-group <group>`.

#### 7.2.4 DCOM Triggered Loaders (Novel)

**Mechanism:** Avoid the two over-burned objects (`MMC20.Application`,
`ShellWindows.Document`). Instead enumerate available DCOM CLSIDs on
target via registry walk (already in slinger's winreg) and offer a
catalog of *less-monitored* objects with code-execution potential:

- `Excel.Application.RegisterXLL` (loads XLL — disk, skip)
- `Outlook.Application` automation methods
- `Visio.InvisibleApp` macro execution
- `MMC20.Application` (catalog, but flag as well-known)
- `ScriptControl` / `MSScriptControl.ScriptControl` — runs a script
  string in-process, fileless. **Top recommendation.**
- `WSHController.RemoteRun` / `WshNetwork`

Slinger ships a **`dcom-catalog`** subcommand that enumerates which
of these CLSIDs are present + registered + reachable on the target,
flagging recommended-stealth picks first.

**Commands:** `dcom-catalog`, `dcom-exec --clsid <guid> --script <file>`.

#### 7.2.5 Named-Pipe Code Marshal (Pure Memory Transit)

**Mechanism:** A two-step.

1. Slinger uses an existing exec primitive (your `wmiexec` /
   `WMINamedPipeExec` already exists) to launch a tiny first-stage:
   a one-liner that opens a named pipe (`\\.\pipe\<random>`) and
   `ReadFile`s it, then `VirtualAlloc + memcpy + CreateThread`s the
   bytes. The first-stage one-liner is small enough to fit in
   command-line (~600 chars of base64 PowerShell or .NET-via-cmd).
2. Slinger streams the encrypted payload over the named pipe through
   the existing SMB session (no second authentication, no second port).

**Stealth notes:**
- Pipe name uses a Microsoft-mimicking template (`\\.\pipe\PIPE_EVENTROOT_<hex>`).
- Payload encrypted in transit with the same per-session key as
  registry-staged payloads.
- First-stage is the only command-line surface that hits process
  creation events; it's small, doesn't reach to internet, and
  closes the pipe handle immediately after read.

**Commands:** `pipe-load --target-process <name|spawn> --payload <local-file>`.

This is the most "actually-in-memory-only" path: **nothing** lands on
disk or in registry. Cost: requires an already-working exec primitive.

#### 7.2.6 Reflective DLL via Print Spooler Driver Load

Already discussed in §5.4. Flagged for completeness; default-disabled
because it does write a driver file to the spooler driver directory
(violates principle 1 unless the "driver" is a signed MS DLL acting as
a redirector — an uncommon configuration).

### 7.3 Composition & The `payload` Verb

To make the framework usable end-to-end, slinger should ship a single
top-level verb that composes substrate + delivery + cleanup:

```
slinger> payload deploy \
    --substrate wmi-class --substrate-name "Win32_PerfRawData_Custom" \
    --delivery wmi-persist --trigger 'every 1 hour' \
    --payload ./beacon.dll \
    --opsec-profile windows-update \
    --auto-cleanup-on-disconnect
```

Outputs a single **deployment ID**. `payload list`, `payload status <id>`,
`payload rm <id>` operate on that ID and clean up *every* artifact across
substrate and delivery channels in the correct teardown order.

State for deployments lives in a slinger-side JSON file (per-host,
gitignored) so the operator can resume cleanup in a fresh session:

```
~/.slinger/deployments/<host>.json
{
  "deploy-9b2c": {
    "substrate": {"kind": "wmi-class", "namespace": "root\\cimv2", "class": "Win32_PerfRawData_Custom", "instance": "..."},
    "delivery":  {"kind": "wmi-persist", "filter": "...", "consumer": "...", "binding": "..."},
    "opsec_profile": "windows-update",
    "deployed_at": "2026-05-03T17:14:00Z",
    "cleanup_token": "..."
  }
}
```

### 7.4 OPSEC Profiles

A profile is a bundle of naming + scheduling + audit-coordination
defaults. Ship at minimum:

| Profile | Naming pattern | Schedule cadence | Audit posture |
|---------|----------------|------------------|---------------|
| `windows-update` | `WindowsUpdate*`, `wuauserv*` neighbors | hourly +/- jitter | refuses if Windows Update is paused (anomalous) |
| `defender-helper` | `MpScheduled*`, `Microsoft\Windows Defender\*` | matches MS-Defender cadence | refuses if Defender disabled |
| `office-telemetry` | `OfficeClickToRun*`, `OfficeTelemetry*` | matches Office cadence | requires Office installed |
| `generic-low-profile` | random Microsoft-flavored GUIDs | hourly | always allowed |
| `loud` | `slinger-test-*` | immediate | for lab use only — never default |

Operator can author custom profiles in `~/.slinger/opsec_profiles/<name>.toml`.

### 7.5 What Slinger Does NOT Build

Out of scope (use a real C2 / red-team framework — slinger is a
pentest *interactive admin tool*, not an implant):

- Long-haul C2 channels
- Sleep/jitter beaconing
- AMSI/ETW patching code (operator brings their own loader)
- Process hollowing / DLL injection internals (the loader is operator's)

Slinger ships the **delivery and persistence plumbing**; the *payload
itself* is operator-provided.

---

## 8. Cross-Cutting Concerns

### 8.1 Cleanup Orchestration

A new module `lib/lifecycle.py` provides:

```python
class OperationContext:
    """Context manager that records every state change and rolls back on error."""
    def __enter__(self): ...
    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.rollback()
        else:
            self.commit_or_track()

    def record_create(self, resource_kind, locator, deleter): ...
    def record_modify(self, resource_kind, locator, restorer): ...
```

Every new RPC primitive uses this. A `Ctrl-C` mid-operation runs
rollback automatically.

### 8.2 Audit Coordination

A new module `lib/audit_state.py` queries:

- Eventlog channel enabled/disabled state (via §3.10).
- Sysmon presence (registry probe `HKLM\SYSTEM\CurrentControlSet\Services\SysmonDrv`).
- WEF subscriptions (registry probe).
- Defender state (registry + WMI `MSFT_MpPreference`).

Returns a structured "noise budget": which detection layers are live.
Each offensive primitive declares its `noise_signature` and the audit
module decides if the operator should be warned.

### 8.3 Change Tracker Integration

Every primitive in this plan calls `self._track(category, action,
target, details)` per existing CLAUDE.md guidance. New categories:

- `RPC` — generic RPC operation
- `FILELESS` — payload staging / delivery
- `IDENTITY` — SAMR/LSA/DRSUAPI mutations
- `FW` — firewall changes

### 8.4 Naming the Mixins

Use `*lib` suffix to disambiguate from impacket modules and keep
imports clean:

```python
from slingerpkg.lib.epmlib import EPMLib
from slingerpkg.lib.wkstlib import WkstLib
# ...etc
```

### 8.5 Plugin Boundary

For anything in §5.3 (offensive Zerologon), §7.2.6 (spooler driver
load with arbitrary path), and §6 (eventlog clearing) — implement as
**plugins** in `src/slingerpkg/plugins/` rather than core modules.
This makes them opt-in and excludable from packaged releases for
audiences who shouldn't have them.

---

## 9. CLI Grammar

Consistent verb-noun across new commands. Examples:

```
# recon
epmenum                                     # endpoint mapper dump
mgmtifaces                                  # rpc mgmt iface list
wkstusers / wkstinfo / wkstuses             # workstation svc
sessions / openfiles / shareadd             # server svc
tssessions                                  # terminal services
dcdiscover / forestmap                      # netlogon recon
dhcpleases <subnet>                         # dhcp recon

# identity
useradd / passwd / groupmod                 # samr
lsasecrets-rpc / lsaprivs / lsatrusts       # lsa
drs-targeted <user>                         # drsuapi
dpapi-backupkey                             # bkrp
adcs-templates / adcs-request               # icpr

# stealth host control
fw-snapshot / fw-add-rule / fw-rollback     # fasp
svc-vuln / svc-trigger-install              # scmr+
nrpc-vuln-probe                             # nrpc

# fileless framework
payload-stage / payload deploy / payload rm
wmi-persist install/list/rm
comhandler-install / comhandler-rm
pipe-load
dcom-catalog / dcom-exec
```

All commands integrate with the existing help system per CLAUDE.md
(parser added in `cli.py`, category added in
`print_all_commands_verbose()`).

---

## 10. Testing Strategy

Per CLAUDE.md every feature requires tests.

| Layer | Type | What |
|-------|------|------|
| Unit | `tests/unit/test_<module>.py` | Argparse structure, opsec profile parsing, payload encryption round-trip, NDR struct construction |
| Integration | `tests/integration/test_<module>_pexpect.py` | Live target ops against `SLINGER_HOST` |
| Working | `tests/working/test_all_help_pexpect.py` | Help renders for every new command |
| Working | `tests/working/test_all_functional_pexpect.py` | Functional smoke per command |

**Testing the fileless framework specifically requires:**

1. A throwaway lab target (already established at `10.10.0.160`).
2. Per-test cleanup verification — after each test, the substrate +
   delivery artifacts are queried and asserted to be **gone**.
3. A "leakage detection" pass that walks well-known persistence
   surfaces (registry Run keys, WMI `root\subscription`,
   schtasks `\` root, services with auto-start) and confirms slinger
   left zero residue.

A new pytest fixture `cleanup_audit` performs this leakage check
automatically after every fileless test and fails the test if residue
is found.

---

## 11. Risks & Guardrails

| Risk | Mitigation |
|------|------------|
| Operator misuse against unauthorized targets | CLI-level `--engagement-id <ticket>` requirement gating all `payload`, `drs-*`, `nrpc-*`, `samr-*write*` commands; logged to local audit file |
| Botched cleanup leaves persistent backdoor | Mandatory `OperationContext` rollback; `payload audit-leakage <host>` standalone command; deployment state JSON survives sessions |
| Encryption key loss → unrecoverable substrate | Key derivation deterministic from machine SID + session salt; salt printed at deploy time and must be supplied for cleanup |
| Detection by EDR via known-WMI-namespace probing | OPSEC profiles vary namespace + class names; no hardcoded slinger string in any artifact |
| Zerologon / DCSync misuse outside engagement scope | Plugin-only delivery; explicit `confirm="I understand"` Python-level argument |
| Corruption of AD via DRSUAPI write ops | Plan does not propose write-side DRSUAPI; only read (DCSync) and topology recon |

---

## 12. Implementation Phasing

Recommended order — each phase is mergeable independently.

| # | Phase | Modules | Effort | Unblocks |
|---|-------|---------|--------|----------|
| 1 | Recon substrate | `epmlib`, `mgmt`, `wkstlib`, `srvslib`, `tstslib`, `iphlp`, `dhcpm`, `even6` | 2-3 wk | All later phases (driven by recon) |
| 2 | Identity | `samrlib`, `lsalib`, `bkrplib`, `sasec`, `nrpclib` recon | 2 wk | Closes existing TODOs |
| 3 | DCSync++ | `drsuapilib`, `icprlib` | 1.5 wk | Completes AD surface |
| 4 | Stealth host control | `fasplib`, `scmr-extensions`, `spoolerlib`, `audit_state`, `lifecycle` | 2 wk | Substrate for fileless framework |
| 5 | **Fileless framework** | `fileless` core + WMI persist + COM handler + pipe-load + DCOM catalog | 3-4 wk | Core deliverable |
| 6 | Plugin offensives | Zerologon plugin, eventlog-clear plugin, arbitrary-driver-load plugin | 1 wk | Optional shipping |

Each phase ends with: tests added, `cli_menu.md` regenerated,
help-categorization updated, this doc's status row marked complete.

---

## 13. Open Questions for Operator Review

1. **OPSEC profile defaults** — should `windows-update` be the
   shipped default, or `generic-low-profile`? `windows-update` is
   stealthier but encodes assumptions about target patch state.

2. **Engagement-ID gate** — should the `--engagement-id` requirement
   be enforced via config (`~/.slinger/config.toml: require_engagement_id = true`)
   or be an always-on hard requirement for offensive primitives?

3. **Plugin shipping** — should the `slingerpkg` PyPI release include
   the offensive plugins (§5.3, §6, §7.2.6) or ship a separate
   `slingerpkg-redteam` package?

4. **Substrate size enforcement** — refuse staging payloads above
   N bytes per substrate? E.g., service-description field at 8 KB
   is a bad fit for a 200 KB beacon — fail loud or auto-fragment?

5. **Per-host vs per-engagement deployment state** — JSON keyed by
   host today; pivot to engagement-id-keyed for multi-host campaigns?

---

## 14. References to Existing Code Touchpoints

- [src/slingerpkg/lib/slingerclient.py:44](src/slingerpkg/lib/slingerclient.py#L44) — inheritance chain, add new mixins here
- [src/slingerpkg/lib/dcetransport.py](src/slingerpkg/lib/dcetransport.py) — extend with `bind_iface()` cache
- [src/slingerpkg/utils/cli.py](src/slingerpkg/utils/cli.py) — all new parsers
- [src/slingerpkg/lib/change_tracker.py](src/slingerpkg/lib/change_tracker.py) — `_track()` already available via inheritance
- This file (`docs/TODO.md`) — supersedes the prior 2-line TODO list; share-mgmt and SAMR items are absorbed into Phases 1-2

---

*End of plan. Awaiting operator feedback on §13 questions before any
implementation work begins.*
