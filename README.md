# 🛠️ REGTeches Technician's Toolkit V24.02 Pro

![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-blue)
![Language](https://img.shields.io/badge/Language-PowerShell%20%7C%20WinForms-5391FE)
![Version](https://img.shields.io/badge/Version-V24.02%20Pro-green)
![License](https://img.shields.io/badge/License-MIT-orange)

**The ultimate "Swiss Army Knife" for Systems Administrators, IT Technicians, and Power Users.**

The **REGTeches Technician's Toolkit** is a lightweight, portable, all-in-one executable built entirely on native PowerShell and Windows Forms. It consolidates hundreds of scattered Windows utilities, repair commands, and diagnostic tools into a single, high-DPI-aware professional interface.

Designed to replace the clutter of USB drives, this tool allows you to diagnose, repair, secure, and optimize any Windows machine in seconds—without installing third-party bloatware.

---

## 🚀 Key Features

### 🖥️ Live System Monitor (Staggered-Update Engine)
* **Real-Time Metrics:** Visualizes CPU Load, RAM Usage, System Drive (C:) Space, and Network Bandwidth.
* **Network Operations Center (NOC):** Instant display of Hostname, Model, Serial Number, and active IP addresses.
* **Smart Performance:** Uses a new **"Staggered Update" logic** to monitor heavy metrics (Ping/Bandwidth) less frequently than light metrics (CPU/RAM), ensuring zero UI lag even on older hardware.

### 🤖 Local AI Troubleshooter (New in V24.02)
* **Offline "Expert Mode":** A built-in logic engine that analyzes plain-English problem descriptions (e.g., *"printer stuck,"* *"wifi slow,"* *"forgot password"*).
* **Auto-Remediation:** Instantly suggests and **launches** the specific tool required to fix the issue.
* **Privacy First:** Runs entirely locally—no data is sent to the cloud.

### 🛠️ Repair & Maintenance
* **One-Click System Repair:** Automates a full maintenance sequence: Temp Clean > Bin Empty > SFC Scan > DISM Health Check > Defrag/Trim.
* **Nuclear Update Reset:** Stops Windows Update services (`wuauserv`, `bits`, `cryptsvc`), clears the `SoftwareDistribution` and `catroot2` folders, re-registers DLLs, and resets Winsock to fix stubborn update errors.
* **Deep Cleaning:** Access to advanced Disk Cleanup (`SAGERUN`), WinSxS Component Store cleanup, and removal of "Windows.old" directories.

### 🌐 Network Operations
* **Visual Drive Mapper:** A dedicated GUI for mapping network drives with persistent credentials.
* **Connectivity Tools:** One-button controls for `Flush DNS`, `Release/Renew IP`, `Netstat`, and Route Tables.
* **Wi-Fi Rescue:** Instantly reveal saved Wi-Fi passwords and export all profiles to XML for migration.

### 🛡️ Security & Deployment
* **Winget Integration:** Silently install essential software (Chrome, Firefox, Zoom, VS Code, etc.) using Microsoft's native package manager.
* **Rescue Scanners:** Quick-download links for malware hunters like **Malwarebytes**, **HitmanPro**, and **Kaspersky VRT**.
* **Sysinternals Suite:** Built-in downloader for the full suite or specific tools like **Process Explorer**, **AutoRuns**, and **BlueScreenView**.
* **User Management:** Add/Remove users, reset passwords, and enable the Hidden Administrator account via GUI.

### 💾 Disaster Recovery
* **Smart Profile Backup:** Uses `Robocopy` to mirror User Documents, Desktop, and Wi-Fi profiles to external storage.
* **Imaging Solutions:** Capture and Apply **WIM** (File-based) and **FFU** (Sector-based) system images using native DISM commands.
* **Bare Metal Backup:** Triggers `wbadmin` to create a full system image backup including EFI/Recovery partitions.

---

## 📥 Installation & Usage

### Option 1: The "Bootstrapper" (Recommended)
You can launch the tool directly from PowerShell without manually downloading files. Run this command as **Administrator**:

```powershell
