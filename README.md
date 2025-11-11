#  Threat Hunt Report: Papertrail

Analyst: Steven Cruz

Date Completed: 2025-08-16

Environment Investigated: nathan-iel-vm

Timeframe: July 18, 2025

## Executive Summary

Between July 18–19, 2025, the system nathan-iel-vm was targeted in a structured attack campaign. The adversary leveraged phishing, privilege escalation, credential dumping, persistence, data staging, exfiltration, and anti-forensics measures to achieve their objectives. Each flag represents a key stage of the attack chain, culminating in attempts to cover tracks and exit the environment undetected.

## Timeline

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-07-18T01:14:15Z** | Flag 1   | Malicious file created (`HRToolTracker.ps1`) | File dropped via PowerShell                             |
| **2025-07-18T02:43:07Z** | Flag 2   | Initial execution of staging script          | PowerShell running HR script                            |
| **2025-07-18T03:11:42Z** | Flag 3   | User token impersonation attempt             | Suspicious use of `runas`                               |
| **2025-07-18T04:19:53Z** | Flag 4   | Reconnaissance of accounts & groups          | `net user /domain`                                      |
| **2025-07-18T05:05:10Z** | Flag 5   | Privilege escalation via service abuse       | `sc.exe config`                                         |
| **2025-07-18T05:27:32Z** | Flag 6   | Credential dumping from `lsass.exe`          | 92 access attempts                                      |
| **2025-07-18T07:45:16Z** | Flag 7   | Local file staging                           | Promotion-related files                                 |
| **2025-07-18T09:22:55Z** | Flag 8   | Archive creation (`employee-data.zip`)       | HR data compressed                                      |
| **2025-07-18T14:12:40Z** | Flag 9   | Outbound ping to unusual domain              | `eo7j1sn715wk...pipedream.net`                          |
| **2025-07-18T15:28:44Z** | Flag 10  | Covert exfil attempt                         | Remote IP `52.54.13.125`                                |
| **2025-07-18T15:50:36Z** | Flag 11  | Persistence via registry run key             | `OnboardTracker.ps1`                                    |
| **2025-07-18T16:05:21Z** | Flag 12  | Personnel file repeatedly accessed           | `Carlos.Tanaka-Evaluation.lnk`                          |
| **2025-07-18T16:14:36Z** | Flag 13  | HR candidate list tampered                   | Modified `PromotionCandidates.csv` (SHA1: `65a5195...`) |
| **2025-07-18T17:38:55Z** | Flag 14  | Log clearing via `wevtutil`                  | Cleared Security, System, App logs                      |
| **2025-07-18T18:18:38Z** | Flag 15  | Anti-forensics exit prep                     | Dropped `EmptySysmonConfig.xml`                         |

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
🎯 **Objective:** Identify indicators that suggest attempts to imply or simulate changing security posture..  
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

🚩 **Flag 8 – File Inspection of Dumped Artifacts**  
🎯 **Objective:** Detect whether memory dump contents were reviewed post‑collection.  
📌 **Finding (answer):** `"notepad.exe" C:\HRTools\HRConfig.json`  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:13:16Z  
- **Process:** notepad.exe (initiated by powershell.exe)  
- **SHA256:** `da5807bb0997ccb5132950ec87eda2b33b1ac4533cf17a22a6f3b576ed7c5b`  
💡 **Why it matters:** Confirms post‑dump review/validation of harvested credentials or secrets.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "HRConfig.json"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="760" height="268" alt="Screenshot 2025-08-17 221257" src="https://github.com/user-attachments/assets/cd60c854-428b-4fde-aa35-a48941216c7e" />

---

🚩 **Flag 9 – Outbound Communication Test**  
🎯 **Objective:** Catch network activity establishing contact outside the environment.  
📌 **Finding (answer):** **.net** (TLD of unusual outbound domain)  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Suspicious Domain:** `eo7j1sn715wkekj.m.pipedream.net` (amid mostly Microsoft `*.msedge.net`/`*.azureedge.net`)  
💡 **Why it matters:** Non‑standard webhook/C2 infrastructure used as low‑profile beacon prior to exfiltration.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl != ""
| where RemoteUrl !contains ".com"
| summarize Count = count() by RemoteUrl
| sort by Count desc
```
<img width="498" height="575" alt="Screenshot 2025-08-17 221558" src="https://github.com/user-attachments/assets/ff3a81e7-bcd1-43fb-a85c-169e54aeb922" />

---

🚩 **Flag 10 – Covert Data Transfer**  
🎯 **Objective:** Uncover evidence of internal data leaving the environment.  
📌 **Finding (answer):** Last unusual outbound connection → **52.54.13.125**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm · **ActionType:** ConnectionSuccess  
- **RemoteUrl:** `eo7j1sn715wkekj.m.pipedream.net`  
- **Sequence:** 52.55.234.111 → **52.54.13.125** (last at 2025-07-18T15:28:44Z)  
💡 **Why it matters:** Validates egress path to external service consistent with data staging/exfil.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl !~ ""
| where RemoteUrl contains "pipedream.net"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl
```
<img width="492" height="411" alt="Screenshot 2025-08-17 221959" src="https://github.com/user-attachments/assets/3497fc89-96b0-4dff-955d-1ef4930d7e02" />


---

🚩 **Flag 11 – Persistence via Local Scripting**  
🎯 **Objective:** Verify if unauthorized persistence was established via legacy tooling.  
📌 **Finding (answer):** File name tied to Run‑key value = **OnboardTracker.ps1**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18T15:50:36Z  
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- **Value Name:** `HRToolTracker` → **C:\HRTools\LegacyAutomation\OnboardTracker.ps1**  
- **Initiating Process:** PowerShell `New-ItemProperty ... -Force`  
💡 **Why it matters:** Ensures re‑execution at logon; disguised as HR “Onboarding” tool.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where InitiatingProcessCommandLine contains "-c"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```
<img width="1643" height="231" alt="Screenshot 2025-08-17 222159" src="https://github.com/user-attachments/assets/2b76f134-956d-448c-8c57-c8c55a5bfc73" />

---

🚩 **Flag 12 – Targeted File Reuse / Access**  
🎯 **Objective:** Surface the document that stood out in the attack sequence.  
📌 **Finding (answer):** **Carlos Tanaka**  
🔍 **Evidence:**  
- **Host:** nathan-iel-vm  
- **Repeated Access:** `Carlos.Tanaka-Evaluation.lnk` (count = 3) within HR artifacts list  
💡 **Why it matters:** Personnel record of focus; aligns with promotion‑manipulation motive.
**KQL Query Used:**
```
DeviceEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| summarize Count = count() by FileName
| sort by Count desc
```
<img width="434" height="767" alt="Screenshot 2025-08-17 222304" src="https://github.com/user-attachments/assets/273f916d-e5fe-40dc-924f-802f9724ebc7" />



---

🚩 **Flag 13 – Candidate List Manipulation**  
🎯 **Objective:** Trace tampering with promotion‑related data.  
📌 **Finding (answer):** **SHA1 = 65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34**  
🔍 **Evidence:**  
- **File:** `PromotionCandidates.csv`  
- **Host:** nathan-iel-vm  
- **Timestamp:** 2025-07-18 16:14:36 (first **FileModified**)  
- **Path:** `C:\HRTools\PromotionCandidates.csv`  
- **Initiating:** `"NOTEPAD.EXE" C:\HRTools\PromotionCandidates.csv`  
💡 **Why it matters:** Confirms direct manipulation of structured HR data driving promotion decisions.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FolderPath contains "HR"
| summarize Count = count() by FileName
| sort by Count desc

```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/user-attachments/assets/ce206008-93b6-48c1-a99c-2868db039031" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName == "PromotionCandidates.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessCommandLine

```
<img width="1880" height="433" alt="Screenshot 2025-08-17 223349" src="https://github.com/user-attachments/assets/f31b2be7-75d2-4dac-b491-8006c9f342b4" />


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

🚩 **Flag 15 – Final Cleanup and Exit Prep**  
🎯 **Objective:** Capture the combination of anti‑forensics actions signaling attacker exit.  
📌 **Finding (answer):** **2025-07-19T06:18:38.6841044Z**  
🔍 **Evidence:**  
- **File:** `EmptySysmonConfig.xml`  
- **Path:** `C:\Temp\EmptySysmonConfig.xml`  
- **Host:** nathan-iel-vm · **Initiating:** powershell.exe  
💡 **Why it matters:** Blinds Sysmon to suppress detection just prior to exit; ties off anti‑forensics chain.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName in ("ConsoleHost_history.txt","EmptySysmonConfig.xml","HRConfig.json")
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/user-attachments/assets/6334babb-6839-4281-b025-74346f5623e9" />


---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell) – Flags 1–5, 7–8  
- **Persistence:** T1547.001 (Run Keys) – Flag 11  
- **Discovery:** T1033/T1087 (whoami /all; group/user discovery) – Flags 1–3, 4  
- **Credential Access:** T1003.001 (LSASS dump) – Flag 7 (MiniDump via comsvcs.dll)  
- **Command & Control / Exfil:** T1071/T1041 – Flags 9–10 (pipedream.net, .net TLD, IP 52.54.13.125)  
- **Defense Evasion:** T1562.001/002 & T1070.001 – Flags 5–6 (Defender), 14–15 (log clear, Sysmon blind)

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
