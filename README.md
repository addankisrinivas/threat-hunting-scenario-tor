<img width="405" alt="image" src="https://github.com/user-attachments/assets/5f02beb8-4a78-463c-80c6-1ab8af33fe2d" />



# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/addankisrinivas/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` or `tor-browser(.exe)` or `torbrowser(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “firstuser” downloaded a Tor installer, and did something that resulted in many Tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-02-16T23:39:25.7705396Z`. These events began at  `2025-02-16T23:23:54.7864951Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "dimi-win10-au"
| where InitiatingProcessAccountName == "firstuser"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-16T23:23:54.7864951Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="747" alt="image" src="https://github.com/user-attachments/assets/f9c12afa-9b3a-4e11-9b1d-1579630f634b" />



---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that contained the string “tor-browser-windows-x86_64-portable-14.0.6.exe”. Based on the logs returned, on `2025-02-16T23:27:07.0628924Z`, the Tor Browser portable installer (version 14.0.6, 64-bit) was silently executed (/S flag) on the device "dimi-win10-au" by the user "firstuser" from the Downloads folder, without any user interaction.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "dimi-win10-au"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.6.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, AccountName, ProcessCommandLine
```
<img width="746" alt="image" src="https://github.com/user-attachments/assets/c1a03d55-aeb2-453a-a65f-002ff040f9ce" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “firstuser” actually opened the Tor browser. There was evidence that they did open it at `2025-02-16T23:27:40.3533338Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "dimi-win10-au"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "torbrowser.exe")  
| order by Timestamp desc 
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="731" alt="image" src="https://github.com/user-attachments/assets/89690c3b-dd0e-4718-b09c-5e4d83f0af24" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. At `2025-02-16T23:28:16.2709247Z`, the user "firstuser" on the device "dimi-win10-au" successfully established a connection to `127.0.0.1` (localhost) using port `9150`, which is commonly used for Tor’s SOCKS proxy. The connection was initiated by `firefox.exe`, located in `C:\Users\firstuser\Desktop\Tor Browser\Browser\firefox.exe`, indicating that the Tor Browser was actively running and routing traffic through the Tor network. There were a few other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "dimi-win10-au"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ( "tor.exe", "firefox.exe", "tor-browser.exe", "torbrowser.exe")
| where RemotePort in ( "9001", "9030", "9050", "9051", "9150", "9151" , "80", "443")
| project Timestamp, DeviceName, Account = InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc 
```
<img width="757" alt="image" src="https://github.com/user-attachments/assets/84ee0cb0-2e0c-4a24-9251-95e8003a1e34" />


---

## Chronological Event Timeline 

### 1. Initial Download and File Creation

- **Timestamp:** `2025-02-16T23:23:54.7864951Z`
- **Event:** FileRenamed
- **Details:** The file tor-browser-windows-x86_64-portable-14.0.6.exe was renamed in the Downloads folder. This indicates the user "firstuser" downloaded the Tor Browser installer.
- **File Path:** `C:\Users\firstuser\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`
- **SHA256:** `8396d2cd3859189ac38629ac7d71128f6596b5cc71e089ce490f86f14b4ffb94`

### 2. Silent Execution of Tor Browser Installer

- **Timestamp:** `2025-02-16T23:27:07.0628924Z`
- **Event:** ProcessCreated
- **Details:** The Tor Browser portable installer `(tor-browser-windows-x86_64-portable-14.0.6.exe)` was silently executed with the /S flag, indicating an unattended installation
- **Command Line:** `tor-browser-windows-x86_64-portable-14.0.6.exe /S`
- **File Path:** `C:\Users\firstuser\Downloads\tor-browser-windows-x86_64-portable-14.0.6.exe`
- **SHA256:** `8396d2cd3859189ac38629ac7d71128f6596b5cc71e089ce490f86f14b4ffb94`

### 3. Tor Browser Files Created on Desktop

- **Timestamp:** `2025-02-16T23:27:25.7716741Z`
- **Event:** FileCreated
- **Details:** Multiple Tor-related files were created on the desktop, including tor.exe, Tor.txt, Torbutton.txt, and Tor-Launcher.txt.
- **File Path:**
  - `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`.
  - `C:\Users\firstuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor.txt`
  - `C:\Users\firstuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Torbutton.txt`
  - `C:\Users\firstuser\Desktop\Tor Browser\Browser\TorBrowser\Docs\Licenses\Tor-Launcher.txt`


### 4. Tor Browser Launched

- **Timestamp:** `2025-02-16T23:27:40.4930654Z`
- **Event:** ProcessCreated
- **Details:** The Tor Browser (firefox.exe) was launched by the user "firstuser".
- **File Path:** `C:\Users\firstuser\Desktop\Tor Browser\Browser\firefox.exe`
- **SHA256:** `85d8fb8fcfdaaa51b8db3aabe69b52beb091e337bab31e397b803eea71f48266'

### 5. Tor Process Started

- **Timestamps:** `2025-02-16T23:27:48.6046858Z`
- **Event:** ProcessCreated
- **Details:** The Tor process (tor.exe) was started, configuring the Tor network settings.
- **File Path:** `C:\Users\firstuser\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`
- **SHA256:** `02282ab31d10e230f545e67f3b4c1a9a67362bedbf7fe5ed7de7d1fcd1e45d12`

### 6. Tor Network Connections Established

- **Timestamp:** 
  - `2025-02-16T23:28:00.887326Z ` - Connected to `135.181.41.38`, `5.181.158.232`, `172.234.250.96` on port `443`.
  - `2025-02-16T23:28:16.2709247Z` - Local connection to `127.0.0.1` on port `9150`.
  - `2025-02-16T23:27:50.485429Z`  - Local connection to `127.0.0.1` on port `9151`.
- **Event:** ConnectionSuccess
- **Details:** Multiple successful connections were established over the Tor network, including connections to remote IPs (5.181.158.232, 135.181.41.38, 172.234.250.96) on port 443, and a local connection to 127.0.0.1 on port 9150 (Tor’s SOCKS proxy).
- **File Path:** `C:\Users\firstuser\Desktop\Tor Browser\Browser\firefox.exe`
- **Initiating Process:** firefox.exe and tor.exe

### 7. Creation of "tor-shopping-list.txt"

- **Timestamps:** `2025-02-16T23:39:25.7705396Z`
- **Event:** FileCreated
- **Details:** A file named tor-shopping-list.txt was created on the desktop, suggesting the user may have been using the Tor Browser for browsing or note-taking.
- **File Path:** `C:\Users\firstuser\Desktop\tor-shopping-list.txt`
- **SHA256:** `9806177b83936e1e1383dbc0a51f26e3b107158e47d262926e929a8823176dee`

### 8. Shortcut File Created

- **Timestamps:** `2025-02-16T23:39:26.0444819Z`
- **Event:** FileCreated
- **Details:** A shortcut file (tor-shopping-list.lnk) was created in the Recent folder, likely referencing the tor-shopping-list.txt file.
- **File Path:** `C:\Users\firstuser\AppData\Roaming\Microsoft\Windows\Recent\tor-shopping-list.lnk`
- **SHA256:** `05dfc3b65116649d3b6ec23dbdbaabc2540365a1c6f44a0389c03fc38f3ee59e`

---

## Summary

The user "firstuser" downloaded and silently installed the Tor Browser on their device "dimi-win10-au" without any user prompts. Shortly after installation, they launched the browser, which started the Tor process and established multiple encrypted connections, including a local proxy (127.0.0.1:9150) and external IPs, confirming active browsing through the Tor network. Additionally, the user created a file named `tor-shopping-list.txt` on their desktop, along with a shortcut in the Recent Files folder, suggesting they may have taken notes related to their browsing activity. The timeline of events indicates deliberate and active use of the Tor Browser for anonymous internet access, with possible documentation in the form of the “shopping list” file.

---

## Response Taken

TOR usage was confirmed on endpoint `dimi-win10-au` by the user `firstuser`. The device was isolated and the user's direct manager was notified.

---
