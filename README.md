#  Threat Hunt Report November 2025

Analyst: Daniel Christopher

Date Completed: 11/12/2025

Environment Investigated: gab-intern-vm

Timeframe: 11/8/2025 - 11/15/2025

## Executive Summary

Between October 8–10, 2025, the system gab-intern-vm was targeted in a simulated intrusion that replicated a full attack chain. The adversary performed reconnaissance, privilege discovery, and network reachability tests before staging data for exfiltration and creating persistence mechanisms. Key artifacts included the ReconArtifacts.zip staging file, SupportToolUpdater scheduled task, and RemoteAssistUpdater autorun entry. The activity concluded with the creation of a deceptive file, SupportChat_log.lnk, demonstrating anti-forensic behavior to obscure the attacker’s actions.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-10-06T06:00:48Z** | Flag 1   | Malicious PowerShell script                  | `-ExecutionPolicy Bypass`                               |
| **2025-10-09T12:34:59Z** | Flag 2   | Defense Disabling                            | `DefenderTamperArtifact.lnk`                            |
| **2025-10-09T12:50:39Z** | Flag 3   | Read Clipboard Attempt                       | `"try { Get-Clipboard | Out-Null } catch { }`           |
| **2025-10-09T12:51:44Z** | Flag 4   | Reconnaissance of Host                       | `qwinsta.exe`                                           |
| **2025-10-09T12:51:18Z** | Flag 5   | Storage Surface Mapping                      | `"cmd.exe" /c wmic logicaldisk get name,freespace,size` |
| **2025-10-09T12:51:32Z** | Flag 6   | Network connectivity and DNS resolution check| `nslookup` initiated by `RuntimeBroker.exe`             |
| **2025-10-09T12:50:59Z** | Flag 7   | Interactive session discovery                | `qwinsta` executed to enumerate user sessions           |
| **2025-10-09T12:51:57Z** | Flag 8   | Runtime process enumeration                  | `tasklist /v` run via `cmd.exe`                         |
| **2025-10-09T12:52:14Z** | Flag 9   | Privilege enumeration                        | `whoami /groups` and `whoami /priv`                     |
| **2025-10-09T12:55:05Z** | Flag 10  | Outbound reachability validation             | Connection to `www.msftconnecttest.com`                 |
| **2025-10-09T12:58:17Z** | Flag 11  | Data staging for exfiltration                | File created: `C:\Users\Public\ReconArtifacts.zip`      |
| **2025-10-09T13:00:40Z** | Flag 12  | Outbound data transfer attempt               | Connection to `100.29.147.161 (httpbin.org)`            |
| **2025-10-09T13:01:28Z** | Flag 13  | Persistence via scheduled task creation      | Task created: `SupportToolUpdater`                      |
| **2025-07-18T17:38:55Z** | Flag 14  | Autorun fallback persistence                 | Registry value created: `RemoteAssistUpdater`           |
| **2025-10-09T13:02:41Z** | Flag 15  | Creation of cover artifact (deceptive file)  | File created: `SupportChat_log.lnk`                     |

---
### Starting Point – Identifying the Most Suspicious Machine

**Objective:**
Determine where to begin hunting based on provided indicators such as: 
1. Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

**Host of Interest (Starting Point):** `gab-intern-vm`  
**Why:** Machine stood out with the highest number of suspicious "7-Zip Help.lnk" files.
**KQL Query Used:**
```
//Counts number of files that contain ("desk","help","support","tool")
//"7-Zip Help.lnk" was found the most (208)
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where FileName has_any ("desk","help","support","tool")
| summarize FileCount = count() by FileName
|order by FileCount desc
```

```
//Counts number of "7-Zip Help.lnk" files in each machine
//"gab-intern-vm" contains most (15)
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where FileName == "7-Zip Help.lnk"
| summarize FileCount = count() by DeviceName
| order by FileCount desc
```



---

## Flag-by-Flag Findings

---

🚩 **Flag 1 – Initial PowerShell Execution Detection**  
🎯 **Objective:** Detect the earliest anomalous execution that could represent an entry point.  
📌 **Finding (answer):** **-ExecutionPolicy Bypass**  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **TimeGenerated:** 2025-10-06T06:00:48.7549551Z**  
- **Process:** powershell.exe
- **CommandLine:** `"powershell.exe -ExecutionPolicy Bypass -NoProfile -Command ...`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** indicates the actor intentionally disabled PowerShell execution controls to run arbitrary script content in-memory.
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| project TimeGenerated, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, FolderPath, AccountName, SHA256
| order by TimeGenerated asc
```



---

🚩 **Flag 2 – Defense Disabling**  
🎯 **Objective:** Identify indicators that suggest attempts to imply or simulate changing security posture.  
📌 **Finding (answer):** `DefenderTamperArtifact.lnk`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** 10/9/2025, 12:34:59.126 PM 
- **Process:** `"explorer.exe`  
- **SHA256:** `3ec18510105244255bf8e3c4790ca2ff8fe3433bd433f9b0c7bd130868a38662`  
💡 **Why it matters:** Strong indicator of intent to evade or mislead — even if Defender settings weren’t actually changed. It often precedes or supports defense-evasion activity.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ActionType == "FileCreated"
| where FileName contains "tamper" or FolderPath contains "tamper"
```


---

🚩 **Flag 3 – Quick Data Probe**  
🎯 **Objective:** Spot brief, opportunistic checks for readily available sensitive content.
📌 **Finding (answer):** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** 10/9/2025, 12:50:39.955 PM 
- **Process:** powershell.exe  
- **CommandLine:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Reading the clipboard is a low-effort, high-reward probe — users frequently copy passwords, tokens, or sensitive snippets. A short-lived Get-Clipboard invocation indicates an opportunistic data grab that often precedes broader data collection or credential theft.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any ("Get-Clipboard","GetClipboard","GetClipboardData","clip.exe","/c clip")
| project DeviceName, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine, SHA256

```



---

🚩 **Flag 4 – Host Context Recon**  
🎯 **Objective:** Find activity that gathers basic host and user context to inform follow-up actions.  
📌 **Finding (answer):** `10/9/2025, 12:51:44.342 PM (TimeGenerated for qwinsta.exe)`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** 10/9/2025, 12:51:44.342 PM  
- **Process:** **qwinsta.exe**  
💡 **Why it matters:** qwinsta enumerates session/user context on the host (who’s logged on, session IDs, session states). This is low-impact reconnaissance that helps an actor decide where to escalate or maintain persistence (which accounts to target, active sessions to hijack, or lateral movement vectors).
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any (
    "whoami","whoami /all","systeminfo","hostname",
    "net user","net localgroup","net group","net accounts",
    "query user","query session","qwinsta","qwery","qwinsta.exe",
    "ipconfig","ipconfig /all"
)
| project TimeGenerated, DeviceName, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine
| order by TimeGenerated desc
```

---

🚩 **Flag 5 – Storage Surface Mapping**  
🎯 **Objective:** Detect discovery of local or network storage locations that might hold interesting data.  
📌 **Finding (answer):** `"cmd.exe" /c wmic logicaldisk get name,freespace,size (the 2nd command chronologically tied to storage assessment)`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamps:** 10/9/2025, 12:51:18.384 PM  
- **Process:** cmd.exe  
- **CommandLine:** `"cmd.exe" /c wmic logicaldisk get name,freespace,size`  
- **SHA256:** `badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0`  
💡 **Why it matters:** `wmic logicaldisk get name,freespace,size` enumerates available drives and free space — a lightweight check to identify viable locations for collection or staging. Paired with net use, this sequence shows mapping of shares followed quickly by local drive capacity checks, which is a classic preparatory step for bulk collection or staging of exfiltrated data.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any (
    "net share","net view","net use","net view \\\\","dir ","dir /s","Get-ChildItem",
    "Get-PSDrive","Get-PSDrive -PSProvider FileSystem","Get-PSDrive -PSProvider","Get-ChildItem -Path",
    "wmic logicaldisk","mountvol","fsutil fsinfo drives","Get-SmbShare","Get-SmbMapping",
    "Get-Item -Path","Get-ItemProperty -Path"
)
| project TimeGenerated, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine, SHA256
| order by TimeGenerated asc
```


---

🚩 **Flag 6 – Connectivity & Name Resolution Check**  
🎯 **Objective:** Identify checks that validate network reachability and name resolution.  
📌 **Finding (answer):** `RuntimeBroker.exe`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamps:** 10/9/2025, 12:51:32.590 PM  
- **Initiating Parent Process:** `RuntimeBroker.exe`
- **CommandLine:** `"cmd.exe" /c nslookup helpdesk-telemetry.remoteassist.invalid`  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** `RuntimeBroker.exe` is a Windows system process that normally mediates permissions for UWP apps—but in this context, its role as the parent of a connectivity probe is suspicious. It suggests a potential living-off-the-land or masquerading attempt, where legitimate system processes are leveraged to test outbound connectivity and DNS resolution before data exfiltration or C2 activity.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any (
    "nslookup","Resolve-DnsName","Test-NetConnection","Test-Connection",
    "ping","tracert","pathping","curl","wget","tcpping","tcping",
    "ipconfig","Get-DnsClientServerAddress","Get-NetIPConfiguration",
    "Get-NetIPAddress","Get-NetAdapter","Test-Connection -ComputerName"
)
| project TimeGenerated, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessParentFileName, InitiatingProcessAccountName, ProcessCommandLine, SHA256
| order by TimeGenerated desc
```

---

🚩 **Flag 7 – Interactive Session Discovery**  
🎯 **Objective:** Reveal attempts to detect interactive or active user sessions on the host.  
📌 **Finding (answer):** InitiatingProcessUniqueId = `2533274790397065`
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Observed Commands (chronological):**  
  - 10/9/2025, 12:50:58.317 PM — `cmd.exe /c quser` — Account: `g4bri3lintern` — InitiatingProcessUniqueId: `2533274790397065`  
  - 10/9/2025, 12:50:59.344 PM — `cmd.exe /c qwinsta` — Account: `g4bri3lintern` — InitiatingProcessUniqueId: `2533274790397065`
  - 10/9/2025, 12:51:44.308 PM — `cmd.exe /c query session` — Account: `g4bri3lintern` — InitiatingProcessUniqueId: `2533274790397065`
- **Process / Parent context:** `powershell.exe` (observed as the process row FileName) with `cmd.exe` shown as the initiating parent filename in the events — all tied to the same initiating unique id above.  
💡 **Why it matters:** These commands (`quser`, `qwinsta`, `query session`) explicitly enumerate interactive sessions (who is logged on, session IDs, session states). The repeated usage over a short window, all attributed to the same initiating process unique id, indicates a deliberate session-discovery action — a preparatory step to determine which sessions or users are active and therefore which targets or timings are best for escalation, session hijack, or lateral movement.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where ProcessCommandLine has_any ("qwinsta", "query session", "quser", "query user")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessAccountName, InitiatingProcessUniqueId
| order by Timestamp desc

```


---

🚩 **Flag 8 – Runtime Application Inventory**  
🎯 **Objective:** Detect enumeration of running applications and services to inform risk and opportunity.  
📌 **Finding (answer):** `tasklist.exe`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** **10/9/2025, 12:51:57.686 PM** 
- **Process:** `tasklist.exe`  
- **SHA256:** `be7241a74fe9a9d30e0631e41533a362b21c8f7aae3e5b6ad319cc15c024ec3f`
- **CommandLine:** `tasklist /v`

💡 **Why it matters:** `tasklist /v` produces a verbose snapshot of all running processes and their associated details (session, user, memory usage). This is classic reconnaissance used to identify running security products, high-value services, or processes to target or avoid. The presence of a PowerShell → cmd → `tasklist` chain suggests scripted or automated discovery rather than casual, interactive troubleshooting — a behavior consistent with post-compromise footprinting that should trigger further timeline and parent/child process analysis.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where FileName in ("tasklist.exe","taskmgr.exe")
   or ProcessCommandLine has_any ("tasklist","Get-Process","Get-Process -IncludeUserName","Get-Service","sc query","Get-CimInstance -ClassName Win32_Process")
| project Timestamp, DeviceName, FileName, ProcessId, InitiatingProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine, SHA256
| order by Timestamp desc
```


---

🚩 **Flag 9 – Privilege Surface Check**  
🎯 **Objective:** Detect attempts to understand privileges available to the current actor.  
📌 **Finding (answer):** **2025-10-09T12:52:14.3135459Z** (the very first privilege-mapping attempt observed)  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp:** `2025-10-09T12:52:14.3135459Z` (local: 10/9/2025, 12:52:14.313 PM)
- **Process (initial):** `cmd.exe` (ProcessId: `4860`) — launched by powershell.exe (ProcessId: 8824)
- **Observed child:** `whoami.exe` (ProcessId: `6692`) executed immediately after the cmd invocation
- **CommandLine:** `"cmd.exe" /c whoami /groups` → which results in `whoami /groups` being executed
- **Account:** `g4bri3lintern`
- **Follow-ons (context):** Subsequent near-identical calls show `whoami /priv` at `2025-10-09T12:52:15.322Z`, indicating the actor checked both group memberships and privileges in quick succession.
- 💡 **Why it matters:** The first `whoami /groups` at `12:52:14.3135459Z` indicates the actor was mapping group membership (the privilege surface) to decide whether to operate as that user or attempt elevation. Early detection of these queries is critical because privilege mapping is a decision point — if the actor already has useful privileges they may proceed to lateral movement, credential theft, or persistence; if not, they may attempt privilege escalation.
**KQL Query Used:**
```
let start = datetime(2025-10-01);
let end   = datetime(2025-10-15 23:59:59);
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has_any (
    "whoami","whoami.exe","whoami /all","whoami /priv","whoami /groups",
    "net user","net localgroup","net group",
    "whoami /fo","whoami /r",
    "Get-LocalGroup","Get-LocalGroupMember","Get-LocalUser","Get-LocalGroup -Name",
    "Get-ADUser","Get-ADPrincipalGroupMembership","Get-LocalGroupMember -Name",
    "whoami /priv","tokenprivileges","Get-Process -IncludeUserName"
)
| project Timestamp, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessAccountName, ProcessCommandLine
| order by Timestamp asc
```


---

🚩 **Flag 10 – Proof-of-Access & Egress Validation**  
🎯 **Objective:** Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.  
📌 **Finding (answer):** First outbound destination contacted → **www.msftconnecttest.com**  
🔍 **Evidence:**  
- **Host:** gab-intern-vm
- **Timestamp:** 10/9/2025, 12:55:05.765 PM
- **Destination (FQDN):** `www.msftconnecttest.com`
- **Remote IP:** `23.218.218.182`
  
💡 **Why it matters:** `www.msftconnecttest.com` is Microsoft’s connectivity test endpoint (NCSI). A request to this FQDN demonstrates the host has outbound network reachability — a necessary precondition for exfiltration or C2. While this specific domain is normally used by Windows to verify internet access, the observed connection still proves egress capability in the attack timeline; adversaries can leverage the same check or similar trusted endpoints to confirm they can reach external infrastructure before moving data off-host.
**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:51:18Z) .. datetime(2025-10-15T23:59:59Z))
// Only outbound-type events with a remote endpoint
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
// Extract hostname from RemoteUrl if it exists
| extend Destination = tostring(
    iff(isnotempty(RemoteUrl),
        parse_url(RemoteUrl).Host,
        RemoteIP))
| project TimeGenerated, DeviceName, Destination, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessAccountName
| order by TimeGenerated asc
```


---

🚩 **Flag 11 – Bundling / Staging Artifacts**  
🎯 **Objective:** Detect consolidation of artifacts into a single location or package for transfer.  
📌 **Finding (answer):** `C:\Users\Public\ReconArtifacts.zip`  
🔍 **Evidence:**  
- **Host:** gab-intern-vm  
- **Timestamp: 2025-10-09T12:58:17.4364257Z**
- **FolderPath:** `C:\Users\Public\ReconArtifacts.zip`  
- **FileName:** `ReconArtifacts.zip`
- **ActionType:** `FileCreated`
- **Initiating Process:** `powershell.exe`
  
💡 **Why it matters:** The presence of ReconArtifacts.zip in C:\Users\Public is a clear staging action — collected items were bundled into a single archive in a shared location, making exfiltration simpler. Even if the zip itself doesn’t prove exfiltration, staging is a strong indicator an actor prepared data for transfer and should be investigated and remediated..
**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where ActionType in ("FileCreated","FileModified","FileMoved","FileCopied","FileRenamed","FileSaved")
| where FileName endswith_cs(".zip") or FileName endswith_cs(".7z") or FileName endswith_cs(".rar")
    or FileName endswith_cs(".tar") or FileName endswith_cs(".gz") or FileName endswith_cs(".iso")
    or FileName endswith_cs(".pst") or FileName endswith_cs(".mbox") or FileName has_any("staging","bundle","collected","exfil","archive")
| project Timestamp = Timestamp, DeviceName, FolderPath, FileName, ActionType, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
```


---

🚩 **Flag 12 – Outbound Transfer Attempt (Simulated)**  
🎯 **Objective:** Identify attempts to move data off-host or test upload capability.  
📌 **Finding (answer):** **100.29.147.161**  
🔍 **Evidence:**  
- **Host:** gab-intern-vm
- **Timestamp: 10/9/2025, 1:00:40.045 PM**
- **Destination (resolved name):** `httpbin.org`
- **Remote IP:** `100.29.147.161`
- **Context:** Network row shows a TLS/HTTPS connection to `httpbin.org` at the given timestamp — a common test endpoint used to validate HTTP(S) upload or web requests. The proximity to prior staging activity (`ReconArtifacts.zip`) and the use of PowerShell as the initiating process strongly suggests an attempt to test upload capability or simulate exfiltration.
  
💡 **Why it matters:** An HTTPS connection to a public test service (httpbin.org) from a compromised host is a typical technique to validate egress or to test upload behavior before targeting a final exfiltration endpoint. Even if the transfer was simulated or failed, the attempt demonstrates intent and reveals the egress channel and process used.
**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-09T12:51:18Z) .. datetime(2025-10-15T23:59:59Z))
// Only outbound-type events with a remote endpoint
| where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
// Extract hostname from RemoteUrl if it exists
| extend Destination = tostring(
    iff(isnotempty(RemoteUrl),
        parse_url(RemoteUrl).Host,
        RemoteIP))
| project TimeGenerated, DeviceName, Destination, RemoteIP, RemoteUrl, RemotePort, Protocol, InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessAccountName
| order by TimeGenerated asc
```



---

🚩 **Flag 13 – Scheduled Re-Execution Persistence**  
🎯 **Objective:** Detect creation of mechanisms that ensure the actor’s tooling runs again on reuse or sign-in.  
📌 **Finding (answer):** **SupportToolUpdater**  
🔍 **Evidence:**  
- **Host:** gab-intern-vm
- **Timestamp (creation): 10/9/2025, 1:01:28.734 PM**
- **Process:** `schtasks.exe`
- **CommandLine:**
`"schtasks.exe" /Create /SC ONLOGON /TN SupportToolUpdater /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\Users\g4bri3lintern\Downloads\SupportTool.ps1"" /RL LIMITED /F`
- **Context:** Immediately after the task creation there is a `schtasks.exe /Query /TN SupportToolUpdater` at `10/9/2025, 1:01:29.781 PM`, indicating the actor verified the task was created.

💡 **Why it matters:** The scheduled task `SupportToolUpdater` is configured to run at logon and execute a PowerShell script from the user’s Downloads folder. This is a classic persistence technique: the actor ensures their tooling executes whenever the user signs in. Even with limited run level, it re-establishes foothold and can re-run collection or staging actions (e.g., the previously observed `ReconArtifacts.zip`). Detection and removal of this task reduces the actor’s ability to persist..
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where ProcessCommandLine has "schtasks"
| project Timestamp = ProcessCreationTime, FileName, ProcessId, InitiatingProcessFileName, InitiatingProcessAccountName, ProcessCommandLine

```



---

🚩 **Flag 14 – Audit Trail Disruption**  
🎯 **Objective:** Detect attempts to impair system forensics.  
📌 **Finding (answer):** **2025-07-19T05:38:55.6800388Z** (first log‑clear attempt)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Process:** `wevtutil.exe`  
- **Command:** `"wevtutil.exe" cl Security` (+ additional clears shortly after)  
- **SHA256:** `0b732d9ad576d1400db44edf3e750849ac481e9bbaa628a3914e5eef9b7181b0`  
💡 **Why it matters:** Clear Windows Event Logs → destroys historical telemetry; classic anti‑forensics.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="https://github.com/user-attachments/assets/af5db852-e1c5-4ff3-8919-aef0a6baa225" />



---

🚩 **Flag 15 – Planted Narrative / Cover Artifact**  
🎯 **Objective:** Identify a narrative or explanatory artifact intended to justify the activity.  
📌 **Finding (answer):** **SupportChat_log.lnk**  
🔍 **Evidence:**   
- **Host:** gab-intern-vm
- **Timestamp 10/9/2025, 1:02:41.569 PM**
- **FolderPath** `C:\Users\g4bri3lintern\AppData\Roaming\Microsoft\Windows\Recent\SupportChat_log.lnk`
- **FileName** `SupportChat_log.lnk`
- **ActionType** `FileCreated`
- **InitiatingProcessCommandLine:** `Explorer.EXE`
  
💡 **Why it matters:** The creation of both a `.txt` file and a corresponding `.lnk` shortcut in close succession to other malicious activity strongly indicates an attempt to plant a narrative or cover artifact. By naming the file “SupportChat_log,” the attacker attempted to fabricate the appearance of legitimate IT-related activity, likely to deflect suspicion during an investigation.
**KQL Query Used:**
```
let start = datetime(2025-10-09 12:30:00);
let end   = datetime(2025-10-15 23:59:59);
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (start .. end)
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```



---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell / CMD) – Flags 1–5, 8
- **Discovery:** T1087 / T1033 / T1057 – Flags 6–9 (system, process, and privilege enumeration)
- **Persistence:** T1053.005 (Scheduled Task) & T1547.001 (Registry Run Key) – Flags 13–14
- **Collection & Exfiltration:** T1074 / T1560 / T1041 – Flags 10–12 (data staging and outbound transfer)
- **Defense Evasion / Anti-Forensics:** T1070 (Indicator Removal) – Flag 15 (planted cover artifact)

---

## Recommended Actions (Condensed)
1. Review and remove persistence mechanisms (`SupportToolUpdater` task, `RemoteAssistUpdater` registry entry).
2. Reassess egress controls and block known exfil paths (e.g., connections to `httpbin.org` and suspicious outbound IPs).
3. Strengthen monitoring for PowerShell and CMD process chains that enumerate sessions or privileges.
4. Implement enhanced Sysmon and Defender rules for detecting `tasklist`, `whoami`, and unauthorized zip creation under `C:\Users\Public`.
5. Conduct a forensic sweep for user-facing artifacts (e.g., `SupportChat_log.lnk`) that may indicate deception or attacker misdirection.
