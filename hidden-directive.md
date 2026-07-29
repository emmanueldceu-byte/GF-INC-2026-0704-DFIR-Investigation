# Threat Hunt Report: HiddenDirective

## Platforms and Languages Leveraged

* Windows endpoints in a Microsoft Azure
* LAW SIlent Corridor Workspace
* LAW cyber range Workspace
* Microsoft Defender for Endpoint
* Microsoft Sentinel / Log Analytics
* Kusto Query Language (KQL)
* PowerShell
* Static malware analysis tools
* Windows and Linux command-line utilities

## Scenario

On 4 July 2026, Greenfield Logistics experienced a suspected security incident involving three systems:

* `GF-WS01`
* `GF-SRV01`
* `GF-DC01`

The managed security service provider escalated activity involving `GF-WS01`, and the incident was declared a Priority 1 investigation.

At the start of the investigation, `GF-WS01` was considered compromised. The status of `GF-SRV01` and `GF-DC01` was unknown.

The primary objectives were to determine:

* How the attacker gained access
* Which systems and accounts were affected
* What commands and tools were used
* Whether credentials were stolen
* Whether persistence was established
* Whether lateral movement occurred
* What data was accessed or copied
* Whether data was successfully exfiltrated

The investigation combined Microsoft Defender telemetry, Microsoft Sentinel logs, alert exports, KQL threat hunting, static malware analysis, and recovered evidence files.

---

# Investigation Steps

## 1. Identifying the Relevant Telemetry

The investigation initially attempted to locate events associated with `GF-WS01` across the available Log Analytics workspaces.

### Query Used

```kusto
search "GF-WS01"
| summarize Events = count() by $table
| order by Events desc
```

### Result

The initial results mainly returned exposure and vulnerability-management tables, including:

* `ExposureGraphEdges`
* `DeviceTvmSoftwareVulnerabilities`
* `DeviceTvmSoftwareInventory`
* `ExposureGraphNodes`
* `NTATopologyDetails`

The expected endpoint process tables were not immediately visible through the broad search.

This demonstrated that the investigation could not rely on one standard telemetry table and that the available environments contained different data sources.

---

## 2. Reviewing Available Devices in Defender

A search was conducted in `DeviceProcessEvents` for devices containing the letters `GF`.

### Query Used

```kusto
DeviceProcessEvents
| where Timestamp between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DeviceName has "GF"
| take 20
```

### Result

The query returned events from:

```text
gf-splunk01
```

The activity included Linux processes such as:

* `grep`
* `dash`
* `sh`

This showed that the filter:

```kusto
DeviceName has "GF"
```

was too broad because it matched the Splunk server rather than only the Greenfield Windows endpoints.

The investigation was subsequently narrowed to exact hostnames such as:

```text
gf-ws01.greenfield.local
```

---

## 3. Locating Process Telemetry for GF-WS01

The investigation identified the custom Sentinel table `WindowsProcess_CL` as a relevant source of Windows process activity.

Before querying the table, its schema was reviewed.

### Query Used

```kusto
WindowsProcess_CL
| getschema
```

### Important Fields Identified

* `TimeGenerated`
* `DvcHostname`
* `ActorUsername`
* `ActingProcessName`
* `TargetProcessName`
* `TargetProcessCommandLine`
* `TargetProcessFilePath`
* `EventType`

A complete process timeline was then generated for `GF-WS01`.

### Query Used

```kusto
WindowsProcess_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-WS01"
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    TargetProcessName,
    TargetProcessCommandLine,
    TargetProcessFilePath,
    EventType
| order by TimeGenerated asc
```

### Result

The process timeline contained both routine activity and suspicious PowerShell-related execution.

This query established the foundation for reconstructing attacker activity on the compromised workstation.

**Screenshot placeholder:** Insert the exported `WindowsProcess_CL` timeline results here.

---

## 4. Identifying Suspicious PowerShell Execution

The process timeline was narrowed to PowerShell activity.

### Query Used

```kusto
WindowsProcess_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-WS01"
| where TargetProcessName =~ "powershell.exe"
    or TargetProcessCommandLine has "powershell"
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    TargetProcessCommandLine,
    TargetProcessFilePath
| order by TimeGenerated asc
```

### Result

The query returned PowerShell executions on `GF-WS01`, including suspicious activity occurring under the `sancadmin` account.

This led to further investigation of the parent-child process relationships surrounding the earliest malicious PowerShell event.

---

## 5. Reconstructing the Initial Process Chain

Microsoft Defender process telemetry was used to identify what launched the suspicious PowerShell process.

### Query Used

```kusto
DeviceProcessEvents
| where Timestamp between (
    datetime(2026-07-04 06:00:00) ..
    datetime(2026-07-04 06:30:00)
)
| where DeviceName =~ "gf-ws01.greenfield.local"
| where FileName =~ "powershell.exe"
| project
    Timestamp,
    DeviceName,
    AccountDomain,
    AccountName,
    FileName,
    ProcessCommandLine,
    ProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessFolderPath,
    InitiatingProcessAccountDomain,
    InitiatingProcessAccountName,
    InitiatingProcessId,
    SHA1
| order by Timestamp asc
```

### Result

A suspicious PowerShell process was identified with:

```text
FileName: powershell.exe
Process ID: 4972
Parent process: explorer.exe
Parent PID: 7756
Account: sancadmin
Timestamp: 2026-07-04 06:16:33
```

### Finding

The PowerShell process was launched directly from `explorer.exe` in the context of the logged-on user.

This is consistent with a user opening or executing a malicious file through Windows Explorer.

The event alone did not identify whether the exact object was an HTML file, shortcut, or another Explorer-associated file. However, the recovered malicious HTML artifact provided supporting evidence for the execution vector.

**Screenshot placeholder:** Insert the `powershell.exe` PID 4972 process event here.

---

## 6. Identifying the Highest-Value Process Chain

The process timeline around the compromise was narrowed to `cmd.exe`, `python.exe`, and `powershell.exe`.

### Query Used

```kusto
DeviceProcessEvents
| where Timestamp between (
    datetime(2026-07-04 06:14:00) ..
    datetime(2026-07-04 06:18:00)
)
| where DeviceName =~ "gf-ws01.greenfield.local"
| where FileName in~ (
    "cmd.exe",
    "python.exe",
    "powershell.exe"
)
| project
    Timestamp,
    AccountName,
    FileName,
    ProcessCommandLine,
    ProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    SHA1
| order by Timestamp asc
```

### Result

The investigation identified the beginning of the process chain:

```text
explorer.exe
  └── cmd.exe
```

The `cmd.exe` process had:

```text
Process ID: 3684
Parent process: explorer.exe
Parent PID: 7756
```

A Python process was then identified as a child of this command shell.

---

## 7. Investigating the Python Payload

A Python process executing a script from a suspicious temporary directory was identified.

### Query Used

```kusto
DeviceProcessEvents
| where Timestamp between (
    datetime(2026-07-04 06:14:00) ..
    datetime(2026-07-04 06:18:00)
)
| where DeviceName =~ "gf-ws01.greenfield.local"
| where FileName =~ "python.exe"
| where ProcessCommandLine has "mshealth.py"
| project
    Timestamp,
    ActionType,
    AccountDomain,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    SHA1
```

### Result

The query identified:

```text
Timestamp: 2026-07-04 06:15:31
Account: gf-ws01\sancadmin
Process: python.exe
Command line:
"python.exe" C:\Windows\Temp\aiagent\mshealth.py

Process ID: 5764
Parent process: cmd.exe
Parent PID: 3684
```

### Confirmed Process Chain

```text
explorer.exe
  └── cmd.exe
       └── python.exe C:\Windows\Temp\aiagent\mshealth.py
```

This activity was suspicious because the Python script was executed from:

```text
C:\Windows\Temp\aiagent\
```

The directory location and process ancestry were inconsistent with normal user activity.

**Screenshot placeholder:** Insert the `mshealth.py` process event here.

---

## 8. Correlating Python and PowerShell Activity

The related processes were placed on a single timeline.

### Query Used

```kusto
DeviceProcessEvents
| where Timestamp between (
    datetime(2026-07-04 06:14:00) ..
    datetime(2026-07-04 06:18:00)
)
| where DeviceName =~ "gf-ws01.greenfield.local"
| where FileName in~ (
    "cmd.exe",
    "python.exe",
    "powershell.exe"
)
| project
    Timestamp,
    AccountName,
    FileName,
    ProcessCommandLine,
    ProcessId,
    ProcessUniqueId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessUniqueId
| order by Timestamp asc
```

### Result

The timeline included:

```text
06:15:25 explorer.exe → cmd.exe PID 3684
06:15:31 cmd.exe → python.exe PID 5764
06:16:33 explorer.exe → powershell.exe PID 4972
```

### Finding

The telemetry confirmed suspicious processes executing within the same short period under the `sancadmin` account.

The available process events established that both the command-shell/Python chain and the PowerShell execution were launched from the interactive Windows Explorer session.

However, the data did not conclusively demonstrate that the Python process directly launched PowerShell.

---

## 9. Analyzing the Malicious HTML Lure

The recovered file:

```text
blog_lure.html
```

was reviewed through static analysis.

### Findings

The artifact contained:

* A fake CloudLens-themed page
* Embedded or hidden malicious instructions
* A PowerShell launcher
* Social-engineering content designed to encourage user interaction
* References to remote payload delivery

### Assessment

The malicious HTML file was assessed as the most likely initial-access and user-execution vector.

The combination of:

* `explorer.exe` launching suspicious processes
* The `sancadmin` interactive user context
* The embedded PowerShell launcher
* The recovered PowerShell loader

supports the conclusion that a user opened the malicious HTML lure, initiating the compromise.

### MITRE ATT&CK

* `T1204.002` – Malicious File
* `T1059.001` – PowerShell

---

## 10. Analyzing loader.ps1

The recovered PowerShell script:

```text
loader.ps1
```

was reviewed through static analysis.

### Confirmed Capabilities

The script included functionality to:

* Bypass AMSI
* Download a second-stage payload
* Decode the downloaded content
* Allocate executable memory
* Copy shellcode into memory
* Execute the shellcode in a new thread

### APIs and Functions Identified

```text
VirtualAlloc
Marshal.Copy
CreateThread
WaitForSingleObject
```

The script also referenced AMSI-related components such as:

```text
AmsiUtils
amsiInitFailed
```

### Finding

The loader was designed to disable or bypass script scanning before downloading and executing shellcode directly in memory.

This reduced the number of malicious artifacts written to disk and increased the likelihood of avoiding signature-based detection.

### MITRE ATT&CK

* `T1059.001` – PowerShell
* `T1562.001` – Impair Defences
* `T1105` – Ingress Tool Transfer
* `T1055` or `T1620` – In-memory or reflective code execution, depending on implementation classification

---

## 11. Investigating Discovery Activity

Process telemetry was searched for common discovery commands and access to the Finance share.

### Query Used

```kusto
WindowsProcess_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-WS01"
| where TargetProcessCommandLine has_any (
    "systeminfo",
    "whoami",
    "quser",
    "ipconfig",
    "arp -a",
    "net view",
    "net localgroup",
    "net user",
    "Get-ADUser",
    @"\\GF-SRV01\Finance",
    "Copy-Item"
)
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    TargetProcessCommandLine
| order by TimeGenerated asc
```

### Commands Identified

```text
systeminfo
whoami
quser
hostname
ipconfig /all
arp -a
net view
net localgroup
net user sancadmin /domain
Get-ADUser svc_backup
```

### Analysis

The commands were used to enumerate:

* Operating system and host details
* Current user identity
* Logged-on sessions
* Network configuration
* Nearby systems
* Local groups
* Domain users
* The `svc_backup` account

### MITRE ATT&CK

* `T1082` – System Information Discovery
* `T1033` – System Owner/User Discovery
* `T1049` or `T1016` – System Network Connections Discovery
* `T1018` – Remote System Discovery
* `T1069` – Permission Groups Discovery
* `T1087.002` – Domain Account Discovery

---

## 12. Confirming Access to the Finance Share

The same discovery query identified a PowerShell command accessing the Finance share on `GF-SRV01`.

### Confirmed Command

```powershell
powershell.exe -WindowStyle Hidden -Command "
Get-ChildItem \\GF-SRV01\Finance -Recurse -ErrorAction SilentlyContinue |
Out-Null;

Copy-Item
\\GF-SRV01\Finance\Invoices\2026\INV-2026-01-001.txt
C:\Users\m.smith\Documents\Invoices\latest_invoice.txt
-Force -ErrorAction SilentlyContinue
"
```

### Findings

The command performed two actions:

1. Recursively enumerated the Finance share:

```text
\\GF-SRV01\Finance
```

2. Copied the invoice:

```text
INV-2026-01-001.txt
```

to:

```text
C:\Users\m.smith\Documents\Invoices\latest_invoice.txt
```

### Assessment

This was confirmed collection activity.

The attacker accessed a remote network share and copied a Finance document to a local directory.

The evidence confirmed access to data hosted on `GF-SRV01`, but it did not prove that malware executed directly on the server.

### MITRE ATT&CK

* `T1039` – Data from Network Shared Drive
* `T1005` – Data from Local System
* `T1074` – Data Staged

**Screenshot placeholder:** Insert the Finance-share PowerShell command here.

---

## 13. Investigating Authentication Activity

The authentication schema was reviewed before investigating activity involving `sancadmin` and `svc_backup`.

### Query Used

```kusto
WindowsAuth_CL
| getschema
```

The available fields included user, host, source IP, logon type, and event result information.

### sancadmin Query

```kusto
WindowsAuth_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where ActorUsername has "sancadmin"
    or TargetUsername has "sancadmin"
| project
    TimeGenerated,
    EventType,
    EventResult,
    ActorUsername,
    TargetUsername,
    SrcIpAddr,
    LogonType
| order by TimeGenerated asc
```

### svc_backup Query

```kusto
WindowsAuth_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-SRV01"
| where TargetUsername =~ "svc_backup"
    or ActorUsername =~ "svc_backup"
| project
    TimeGenerated,
    DvcHostname,
    ActorUsername,
    TargetUsername,
    EventType,
    EventResult,
    SrcIpAddr,
    LogonType
| order by TimeGenerated asc
```

### Result

Authentication events involving `svc_backup` were observed on `GF-SRV01`, including:

```text
2026-07-04 21:00:01
Host: GF-SRV01.greenfield.local
Target account: svc_backup
Logon type: 4
Result: Both failure and success events were recorded
```

### Assessment

The events warranted investigation because the account had already been enumerated with:

```powershell
Get-ADUser svc_backup
```

However, the authentication data did not conclusively prove that the attacker obtained or used the account credentials maliciously.

Credential compromise of `svc_backup` therefore remained unconfirmed.

---

## 14. Investigating Credential Dumping

The `WindowsProcessAccess_CL` table was reviewed for access to `lsass.exe`.

### Query Used

```kusto
WindowsProcessAccess_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-WS01"
| where TargetProcessName =~ "lsass.exe"
    or TargetProcessFilePath endswith @"\lsass.exe"
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    ActingProcessFilePath,
    TargetProcessName,
    TargetProcessFilePath,
    GrantedAccess,
    CallTrace
| order by TimeGenerated asc
```

### Result

The primary processes observed accessing LSASS were:

* `Explorer.exe`
* `MpCmdRun.exe`

No evidence identified known credential-dumping tools or techniques such as:

* Mimikatz
* ProcDump
* `comsvcs.dll` MiniDump
* `MiniDumpWriteDump`
* Suspicious unsigned processes accessing LSASS

### Assessment

Credential dumping was not confirmed.

The LSASS events observed were not sufficient to conclude that credentials had been extracted.

---

## 15. Investigating Lateral Movement Tooling

The recovered binary:

```text
psexec_service.exe
```

was analyzed through static analysis.

### Strings Identified

```text
RemComSvc
RemCom_stdout
RemCom_stderr
RemCom_stdin
\\.\pipe\RemCom_communicaton
OpenSCManagerA
CreateNamedPipeA
CreateProcessA
DeleteService
```

### Analysis

The strings and Windows API references were consistent with the RemCom service used by tools such as Impacket's `psexec.py`.

This indicated that the binary was capable of:

* Creating or interacting with a Windows service
* Executing commands remotely
* Communicating through named pipes
* Removing the service after use

A hash hunt was conducted using the binary's SHA-256 hash:

```text
3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71
```

### Query Used

```kusto
union isfuzzy=true
(
    DeviceFileEvents
    | where SHA256 ==
        "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
    | project
        Timestamp,
        DeviceName,
        EvidenceType = "File",
        ActionType,
        FileName,
        FolderPath,
        AccountName = InitiatingProcessAccountName,
        Details = InitiatingProcessFileName
),
(
    DeviceProcessEvents
    | where SHA256 ==
        "3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71"
    | project
        Timestamp,
        DeviceName,
        EvidenceType = "Process",
        ActionType,
        FileName,
        FolderPath,
        AccountName,
        Details = ProcessCommandLine
)
| order by Timestamp asc
```

### Result

The only confirmed occurrence was:

```text
Device: emmawinvm
Action type: FileCreated
File: psexec_service.exe
Location:
C:\Users\emmanuel\Downloads\hidden-directive-evidence\
hidden-directive-evidence\binaries\psexec_service.exe

Initiating process: Explorer.EXE
```

### Assessment

The binary was present in the extracted evidence archive on an analyst workstation.

There was no confirmed execution of the binary on:

* `GF-WS01`
* `GF-SRV01`
* `GF-DC01`

Therefore:

* Remote-execution tooling was recovered.
* Successful PsExec or RemCom lateral movement was not confirmed.

---

## 16. Analyzing gfupdater.exe

The recovered binary:

```text
gfupdater.exe
```

was analyzed using static techniques including:

* SHA-256 hashing
* String extraction
* PE inspection
* `objdump`
* `.rdata` review

### Findings

The executable contained:

* Native C++ components
* HTTP connector functionality
* Dynamic API resolution
* Named-pipe support
* A named-pipe format similar to:

```text
\\.\pipe\%08lx
```

### Assessment

The executable was suspicious and appeared capable of network or inter-process communication.

However, no telemetry confirmed:

* Execution on a Greenfield host
* Persistence
* Outbound network connections
* Successful command-and-control activity

The binary was classified as recovered suspicious tooling rather than confirmed executed malware.

---

## 17. Reviewing Network Activity

Network telemetry for `GF-WS01` was investigated in both MDE and Sentinel tables.

### MDE Query

```kusto
DeviceNetworkEvents
| where Timestamp between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DeviceName =~ "gf-ws01.greenfield.local"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteUrl,
    RemotePort,
    Protocol,
    ActionType
| order by Timestamp asc
```

### Sentinel Query

```kusto
WindowsNetwork_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-WS01"
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    ActingProcessFilePath,
    NetworkDirection,
    NetworkProtocol,
    SrcIpAddr,
    SrcPortNumber,
    DstIpAddr,
    DstHostname,
    DstPortNumber
| order by TimeGenerated asc
```

### Result

The network exports contained outbound connections, including normal Microsoft-related HTTPS traffic.

The available network events were reviewed for:

* PowerShell connections
* Python connections
* Suspicious remote URLs
* Suspicious remote IP addresses
* Connections to download infrastructure

### Assessment

The loader artifact referenced remote download infrastructure, but the available network telemetry did not independently confirm successful data exfiltration.

---

## 18. Investigating GF-DC01

Process telemetry was reviewed for suspicious activity on the domain controller.

### Query Used

```kusto
WindowsProcess_CL
| where TimeGenerated between (
    datetime(2026-07-04) ..
    datetime(2026-07-05)
)
| where DvcHostname has "GF-DC01"
| project
    TimeGenerated,
    ActorUsername,
    ActingProcessName,
    TargetProcessCommandLine
| order by TimeGenerated asc
```

### Result

The results were reviewed for:

* PowerShell compression
* `Compress-Archive`
* Archive creation
* Suspicious service-account activity
* Malicious child processes
* Persistence mechanisms

### Assessment

Although alerts related to compression and account activity existed, the available process telemetry did not conclusively show malicious execution or persistence on `GF-DC01`.

The domain controller was investigated but not confirmed compromised.

---

## 19. Persistence Investigation

The investigation considered common persistence mechanisms, including:

* Registry Run keys
* Registry RunOnce keys
* Scheduled tasks
* Newly created services
* Startup-folder execution
* WMI event subscriptions
* Remote-management tools
* Secondary local accounts

No confirmed evidence was found showing that the attacker established persistence on the Greenfield systems.

### Assessment

Persistence was not confirmed.

This conclusion was limited by the available telemetry and did not prove that persistence was impossible.

---

# Summary of Findings

## Confirmed Compromised Device

```text
GF-WS01
```

## Confirmed Accessed System

```text
GF-SRV01
```

The Finance share was accessed remotely, and an invoice was copied.

## Investigated but Not Confirmed Compromised

```text
GF-DC01
```

## Initial Access

A user opened the malicious file:

```text
blog_lure.html
```

The artifact contained an embedded PowerShell launcher and was assessed as the initial execution vector.

## Execution Chain

The investigation identified suspicious user-context execution involving:

```text
explorer.exe
  ├── cmd.exe
  │    └── python.exe C:\Windows\Temp\aiagent\mshealth.py
  └── powershell.exe
```

The recovered PowerShell loader:

```text
loader.ps1
```

contained:

* AMSI bypass
* Remote payload download
* Payload decoding
* In-memory shellcode execution

## Discovery Commands

```text
systeminfo
whoami
quser
hostname
ipconfig /all
arp -a
net view
net localgroup
net user sancadmin /domain
Get-ADUser svc_backup
```

## Data Accessed

```text
\\GF-SRV01\Finance
```

## File Copied

```text
\\GF-SRV01\Finance\Invoices\2026\INV-2026-01-001.txt
```

Copied to:

```text
C:\Users\m.smith\Documents\Invoices\latest_invoice.txt
```

## Credential Dumping

Not confirmed.

## Persistence

Not confirmed.

## PsExec or RemCom Execution

Not confirmed.

## Successful Exfiltration

Not confirmed.

## Domain Controller Compromise

Not confirmed.

---

# Indicators of Compromise

## Files and Scripts

```text
blog_lure.html
loader.ps1
mshealth.py
gfupdater.exe
psexec_service.exe
hOQjiirI.exe
```

## SHA-256

```text
3c2fe308c0a563e06263bbacf793bbe9b2259d795fcc36b953793a7e499e7f71
```

This hash was associated with both:

```text
psexec_service.exe
hOQjiirI.exe
```

The identical hash showed that the files were byte-for-byte identical.

## Suspicious Paths

```text
C:\Windows\Temp\aiagent\mshealth.py
C:\Users\m.smith\Documents\Invoices\latest_invoice.txt
```

## Network Share

```text
\\GF-SRV01\Finance
```

## Accounts of Interest

```text
sancadmin
svc_backup
m.smith
```

## RemCom Indicators

```text
RemComSvc
RemCom_stdout
RemCom_stderr
RemCom_stdin
\\.\pipe\RemCom_communicaton
```

---

# MITRE ATT&CK Mapping

| Tactic              | Technique                                      | Evidence                                                            |
| ------------------- | ---------------------------------------------- | ------------------------------------------------------------------- |
| Initial Access      | T1204.002 – Malicious File                     | User execution of `blog_lure.html`                                  |
| Execution           | T1059.001 – PowerShell                         | Embedded PowerShell launcher and `loader.ps1`                       |
| Execution           | T1059.003 – Windows Command Shell              | `cmd.exe` launched from Explorer                                    |
| Execution           | T1059.006 – Python                             | Execution of `mshealth.py`                                          |
| Defence Evasion     | T1562.001 – Impair Defences                    | AMSI bypass                                                         |
| Command and Control | T1105 – Ingress Tool Transfer                  | Remote second-stage payload download                                |
| Discovery           | T1082 – System Information Discovery           | `systeminfo`                                                        |
| Discovery           | T1033 – System Owner/User Discovery            | `whoami`                                                            |
| Discovery           | T1016 – System Network Configuration Discovery | `ipconfig /all`, `arp -a`                                           |
| Discovery           | T1018 – Remote System Discovery                | `net view`                                                          |
| Discovery           | T1069 – Permission Groups Discovery            | `net localgroup`                                                    |
| Discovery           | T1087.002 – Domain Account Discovery           | `net user`, `Get-ADUser`                                            |
| Collection          | T1039 – Data from Network Shared Drive         | Finance-share enumeration                                           |
| Collection          | T1005 – Data from Local System                 | Invoice copied locally                                              |
| Collection          | T1074 – Data Staged                            | Invoice copied to local documents directory                         |
| Lateral Movement    | T1021.002 – SMB/Windows Admin Shares           | Suspected through recovered RemCom tooling; execution not confirmed |
| Persistence         | Not confirmed                                  | No validated persistence mechanism                                  |

---

# Response Taken

The investigation determined that `GF-WS01` should be treated as fully compromised.

Recommended immediate response actions included:

1. Isolate `GF-WS01` from the network.
2. Preserve forensic evidence before rebuilding the system.
3. Reimage or rebuild `GF-WS01` from a trusted baseline.
4. Reset the `sancadmin` password and review all associated authentication activity.
5. Review and rotate credentials used on or from the compromised workstation.
6. Investigate and validate the `svc_backup` account.
7. Audit all access to:

```text
\\GF-SRV01\Finance
```

8. Determine whether additional Finance files were accessed or copied.
9. Remove and block all confirmed malicious artifacts.
10. Search the enterprise for matching hashes, paths, filenames, and RemCom indicators.
11. Review `GF-SRV01` for remote-service creation, scheduled tasks, new binaries, and suspicious logons.
12. Continue monitoring `GF-DC01` even though compromise was not confirmed.

---

# Recommendations

## 1. Improve PowerShell Visibility

Enable:

* PowerShell Script Block Logging
* Module Logging
* Transcription Logging
* Centralized forwarding of PowerShell logs

Monitor for:

* Encoded commands
* Hidden PowerShell windows
* AMSI bypass strings
* Download cradles
* `VirtualAlloc`
* `CreateThread`
* Reflection-based API invocation

---

## 2. Restrict Untrusted Script Execution

Implement:

* Windows Defender Application Control
* AppLocker
* PowerShell Constrained Language Mode where operationally appropriate
* Restrictions on unsigned or untrusted scripts
* Controls preventing script execution from temporary and user-writable directories

High-risk paths include:

```text
C:\Windows\Temp\
C:\Users\<user>\Downloads\
C:\Users\<user>\AppData\
```

---

## 3. Harden File-Share Access

Review permissions on:

```text
\\GF-SRV01\Finance
```

Recommended actions:

* Remove unnecessary user access
* Apply least privilege
* Enable detailed file-share auditing
* Alert on recursive directory enumeration
* Alert on bulk file copying
* Alert on access from unusual workstations or accounts

---

## 4. Improve Service-Account Security

For accounts such as:

```text
svc_backup
```

Implement:

* Strong, unique passwords
* Managed service accounts where possible
* Restrictions on interactive logon
* Restrictions on workstation logon
* Monitoring for unusual authentication sources
* Periodic review of privileges and group membership

---

## 5. Detect Remote Execution Tooling

Create detections for:

```text
RemComSvc
RemCom_stdout
RemCom_stderr
RemCom_stdin
```

Also monitor for:

* Unexpected Windows service creation
* Named pipes associated with RemCom
* `OpenSCManager`
* `CreateService`
* `DeleteService`
* PsExec and Impacket-style execution
* Remote service creation over SMB

---

## 6. Improve Endpoint Telemetry Retention

The investigation encountered differences between:

* Defender Advanced Hunting
* Sentinel custom tables
* Exposure-management tables
* Linux infrastructure telemetry
* Greenfield endpoint telemetry

Recommended improvements:

* Ensure all critical Windows endpoints are onboarded to Microsoft Defender for Endpoint.
* Validate that `DeviceProcessEvents`, `DeviceFileEvents`, and `DeviceNetworkEvents` are consistently available.
* Retain process-creation data long enough to support incident reconstruction.
* Preserve parent process, command-line, hash, account, and unique process-ID fields.
* Maintain consistent hostname normalization across data sources.

---

## 7. User Security Awareness

Because the attack relied on user execution of a malicious lure:

* Train users to identify suspicious HTML files.
* Warn against opening unexpected files from email, chat, or downloads.
* Teach users to report fake login pages and unusual prompts.
* Simulate phishing and malicious-file scenarios periodically.
* Restrict HTML and script attachment types where business requirements permit.

---

# Final Assessment

The investigation confirmed that `GF-WS01` was compromised after a malicious HTML lure initiated suspicious command-shell, Python, and PowerShell activity.

The PowerShell loader bypassed AMSI, downloaded a second-stage payload, and executed shellcode in memory.

The attacker then performed system, network, user, and domain discovery. The attacker accessed the Finance share on `GF-SRV01` and copied an invoice to a local staging path.

The recovered RemCom-compatible service binary indicated that the attacker possessed remote-execution tooling. However, the available telemetry did not confirm that the tool was executed on any Greenfield production host.

No conclusive evidence was found showing:

* Credential dumping
* Persistence
* Successful PsExec lateral movement
* Successful data exfiltration
* Compromise of `GF-DC01`

The strongest evidence-supported scope was:

```text
GF-WS01 — Confirmed compromised
GF-SRV01 — Confirmed network-share access and data collection
GF-DC01 — Investigated; compromise not confirmed
```

The incident demonstrated the importance of retaining complete process telemetry, monitoring PowerShell and script execution, hardening network shares, and distinguishing between suspicious artifacts and confirmed execution.
