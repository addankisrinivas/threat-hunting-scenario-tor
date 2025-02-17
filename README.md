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

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
