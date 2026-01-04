# ==========================================
# REGTeches Technician's Toolkit V24.02 Pro
# Distribution Mode: Ready
# Company: REGTeches | Developer: Ronald Goodchild
# To Compile: Install-Module ps2exe; Invoke-PS2EXE -InputFile "Toolkit.ps1" -OutputFile "TechniciansToolkit.exe" -NoConsole -RequireAdmin -sta
# ==========================================

# --- 1. LOAD WINDOWS LIBRARIES FIRST (CRITICAL FIX) ---
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
Add-Type -AssemblyName System.Drawing
# ------------------------------------------------------

# --- HIGH DPI AWARENESS FIX (Crisp Text on 4K/1080p) ---
try {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        [void][System.Windows.Forms.Application]::SetHighDpiMode("SystemAware")
    } else {
        $code = @"
        [DllImport("user32.dll")]
        public static extern bool SetProcessDPIAware();
"@
        $Win32 = Add-Type -MemberDefinition $code -Name "Win32" -Namespace Win32 -PassThru
        [void]$Win32::SetProcessDPIAware()
    }
} catch {
    # Fail silently on very old systems
}
# -------------------------------------------------------

# --- AUTO-ELEVATION BLOCK ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Check if file is saved
    if ([string]::IsNullOrEmpty($PSCommandPath)) {
        [System.Windows.Forms.MessageBox]::Show("Please SAVE this script to a file (e.g., 'Toolkit.ps1') before running it.`n`nIt needs a file path to restart as Administrator.", "Save File Required", 'OK', 'Warning')
        Exit
    }
    
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName = "powershell.exe"
    $processInfo.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $processInfo.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($processInfo) | Out-Null
    } catch {
        # User clicked No on UAC
    }
    Exit
}
# ----------------------------

# Region: Helper Functions

function Update-Status($message) {
    $timestamp = Get-Date -Format "HH:mm:ss"
    if ($statusTextBox.InvokeRequired) {
        $statusTextBox.Invoke([Action[string]]{ param($msg) $statusTextBox.AppendText("[$timestamp] $msg`r`n"); $statusTextBox.ScrollToCaret() }, $message)
    } else {
        $statusTextBox.AppendText("[$timestamp] $message`r`n")
        $statusTextBox.ScrollToCaret() 
    }
}

# --- WINGET AUTO-INSTALL CHECK (Now Safe to Run) ---
if (-not (Get-Command "winget" -ErrorAction SilentlyContinue)) {
    $params = @{
        Text = "Winget (App Installer) is missing.`n`nDo you want to download and install it now?`n(Required for Software Center & Security Suite)"
        Caption = "Winget Missing"
        Buttons = [System.Windows.Forms.MessageBoxButtons]::YesNo
        Icon = [System.Windows.Forms.MessageBoxIcon]::Question
    }
    if ([System.Windows.Forms.MessageBox]::Show($params.Text, $params.Caption, $params.Buttons, $params.Icon) -eq 'Yes') {
        try {
            $wingetUrl = "https://aka.ms/getwinget"
            $tempBundle = "$env:TEMP\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            
            # Create a temporary splash to show activity since the main GUI isn't loaded yet
            $splash = New-Object System.Windows.Forms.Form
            $splash.Size = New-Object System.Drawing.Size(300, 100)
            $splash.StartPosition = "CenterScreen"
            $splash.Text = "Installing Winget..."
            $splash.ControlBox = $false
            $lbl = New-Object System.Windows.Forms.Label
            $lbl.Text = "Downloading Winget from Microsoft...`nPlease Wait."
            $lbl.AutoSize = $true
            $lbl.Location = New-Object System.Drawing.Point(20, 30)
            $splash.Controls.Add($lbl)
            $splash.Show()
            [System.Windows.Forms.Application]::DoEvents()

            # Download (Added TimeoutSec 30 for safety)
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $wingetUrl -OutFile $tempBundle -UseBasicParsing -TimeoutSec 30

            # Install
            $lbl.Text = "Installing Package..."
            [System.Windows.Forms.Application]::DoEvents()
            Add-AppxPackage -Path $tempBundle -ErrorAction Stop
            
            $splash.Close()
            [System.Windows.Forms.MessageBox]::Show("Winget Installed Successfully!", "Success")
        } catch {
            if ($splash) { $splash.Close() }
            [System.Windows.Forms.MessageBox]::Show("Failed to install Winget automatically.`nError: $_", "Error", 'OK', 'Error')
        }
    }
}
# ----------------------------------------------

function Select-Folder($desc = "Select Folder") {
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $FolderBrowser.Description = $desc
    $FolderBrowser.ShowNewFolderButton = $true
    if ($FolderBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $FolderBrowser.SelectedPath }
    return $null
}

function Select-File($filter = "All files (*.*)|*.*", $checkExists = $true) {
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
    $FileBrowser.Filter = $filter
    $FileBrowser.CheckFileExists = $checkExists
    if ($FileBrowser.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { return $FileBrowser.FileName }
    return $null
}

function Run-Command($command, $arguments) {
    $progressBar.Visible = $true
    $cancelButton.Enabled = $true
    $script:CancellationToken = $false

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $command
    $startInfo.Arguments = $arguments
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    try {
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        $process.Start() | Out-Null

        while (-not $process.HasExited) {
            [System.Windows.Forms.Application]::DoEvents()
            if ($script:CancellationToken) {
                try { $process.Kill(); Update-Status "Stopped." } catch {}
                break
            }
            while (-not $process.StandardOutput.EndOfStream) { Update-Status $process.StandardOutput.ReadLine() }
            while (-not $process.StandardError.EndOfStream) { Update-Status "ERR: $($process.StandardError.ReadLine())" }
            Start-Sleep -Milliseconds 50
        }
        if ($process.StandardOutput) { Update-Status $process.StandardOutput.ReadToEnd() }
    }
    catch { Update-Status "Error: $_" }
    finally { $progressBar.Visible = $false; $cancelButton.Enabled = $false }
}

# --- AI TROUBLESHOOTER (Local Expert) ---
function Show-AITroubleshooter {
    $aiForm = New-Object System.Windows.Forms.Form
    $aiForm.Text = "Technician's Toolkit AI (Local Expert)"
    $aiForm.Size = New-Object System.Drawing.Size(550, 400)
    $aiForm.StartPosition = "CenterScreen"
    $aiForm.BackColor = "#1e1e1e"
    $aiForm.ForeColor = "White"
    $aiForm.FormBorderStyle = "FixedToolWindow"

    $lblPrompt = New-Object System.Windows.Forms.Label
    $lblPrompt.Text = "Describe the problem below (e.g., 'printer stuck', 'forgot password', 'slow pc'):"
    $lblPrompt.Location = New-Object System.Drawing.Point(20, 20)
    $lblPrompt.Size = New-Object System.Drawing.Size(500, 30)
    $lblPrompt.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    [void]$aiForm.Controls.Add($lblPrompt)

    $txtInput = New-Object System.Windows.Forms.TextBox
    $txtInput.Location = New-Object System.Drawing.Point(20, 55)
    $txtInput.Size = New-Object System.Drawing.Size(380, 30)
    $txtInput.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    [void]$aiForm.Controls.Add($txtInput)

    $btnAsk = New-Object System.Windows.Forms.Button
    $btnAsk.Text = "ANALYZE"
    $btnAsk.Location = New-Object System.Drawing.Point(410, 53)
    $btnAsk.Size = New-Object System.Drawing.Size(100, 32)
    $btnAsk.BackColor = "Teal"
    $btnAsk.ForeColor = "White"
    $btnAsk.FlatStyle = "Flat"
    [void]$aiForm.Controls.Add($btnAsk)

    $lblResult = New-Object System.Windows.Forms.Label
    $lblResult.Text = "Waiting for input..."
    $lblResult.Location = New-Object System.Drawing.Point(20, 100)
    $lblResult.Size = New-Object System.Drawing.Size(490, 150)
    $lblResult.Font = New-Object System.Drawing.Font("Consolas", 10)
    $lblResult.ForeColor = "Lime"
    $lblResult.BorderStyle = "FixedSingle"
    [void]$aiForm.Controls.Add($lblResult)

    $btnAction = New-Object System.Windows.Forms.Button
    $btnAction.Text = "Run Suggested Tool"
    $btnAction.Location = New-Object System.Drawing.Point(20, 270)
    $btnAction.Size = New-Object System.Drawing.Size(490, 50)
    $btnAction.BackColor = "#333"
    $btnAction.ForeColor = "Gray"
    $btnAction.FlatStyle = "Flat"
    $btnAction.Enabled = $false
    $btnAction.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    [void]$aiForm.Controls.Add($btnAction)

    $script:suggestedAction = $null

    $btnAsk.Add_Click({
        $q = $txtInput.Text.ToLower()
        $found = $false
        
        if ($q -match "print|jam|spool|queue|stuck") {
            $lblResult.Text = "ANALYSIS: Printer Service Issue.`n`nRECOMMENDATION: Use 'Printer Commander' to clear the print spooler and reset the queue."
            $script:suggestedAction = { Show-PrinterMenu }
            $found = $true
        }
        elseif ($q -match "slow|lag|fast|junk|clean|space|full") {
            $lblResult.Text = "ANALYSIS: Performance Degradation.`n`nRECOMMENDATION: Run 'One-Click System Repair' or 'Disk Cleanup' to free space and optimize."
            $script:suggestedAction = { Start-Process "cleanmgr.exe" "/sagerun:1" }
            $found = $true
        }
        elseif ($q -match "wifi|internet|connect|offline|dns|ping|ip") {
            $lblResult.Text = "ANALYSIS: Network Connectivity Error.`n`nRECOMMENDATION: Use 'Network Ops' to flush DNS and reset the network stack."
            $script:suggestedAction = { Run-Command "ipconfig" "/flushdns"; Run-Command "netsh" "winsock reset"; [Windows.Forms.MessageBox]::Show("DNS Flushed & Winsock Reset.") }
            $found = $true
        }
        elseif ($q -match "password|lock|user|login|admin") {
            $lblResult.Text = "ANALYSIS: Account Access Issue.`n`nRECOMMENDATION: Open 'User Management' to reset passwords or unlock accounts."
            $script:suggestedAction = { Start-Process "lusrmgr.msc" }
            $found = $true
        }
        elseif ($q -match "virus|malware|hack|scan|defender") {
            $lblResult.Text = "ANALYSIS: Security Threat.`n`nRECOMMENDATION: Launch 'Windows Defender Quick Scan' immediately."
            $script:suggestedAction = { Start-Process powershell -ArgumentList "Start-MpScan -ScanType QuickScan" }
            $found = $true
        }
        elseif ($q -match "update|corrupt|error|blue|bsod|fix") {
            $lblResult.Text = "ANALYSIS: System Corruption.`n`nRECOMMENDATION: Run 'SFC /Scannow' or 'Reset Windows Updates'."
            $script:suggestedAction = { Run-Command "sfc" "/scannow" }
            $found = $true
        }

        if ($found) {
            $btnAction.Text = "LAUNCH TOOL NOW"
            $btnAction.ForeColor = "White"
            $btnAction.BackColor = "Green"
            $btnAction.Enabled = $true
        } else {
            $lblResult.Text = "I couldn't find a specific tool in this kit for that.`n`nWould you like to search the web for '$($txtInput.Text)'?"
            $btnAction.Text = "Search Google for Solution"
            $btnAction.ForeColor = "White"
            $btnAction.BackColor = "CornflowerBlue"
            $btnAction.Enabled = $true
            $script:suggestedAction = { Start-Process "https://www.google.com/search?q=$($txtInput.Text)" }
        }
    })

    $btnAction.Add_Click({
        if ($script:suggestedAction) { & $script:suggestedAction; $aiForm.Close() }
    })
    $aiForm.AcceptButton = $btnAsk
    $aiForm.ShowDialog()
}
# -----------------------------

# --- Persistent Tool Logic ---
function Get-ToolDownload($toolName, $url) {
    $toolDir = "$env:SystemDrive\REGTeches_Tools"
    if (!(Test-Path $toolDir)) { New-Item -ItemType Directory -Path $toolDir -Force | Out-Null }
    
    $path = Join-Path $toolDir $toolName
    
    try {
        if (-not (Test-Path $path)) { 
            Update-Status "Downloading $toolName to $toolDir..."
            [System.Windows.Forms.Application]::DoEvents()
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $url -OutFile $path 
        } else {
            Update-Status "Using cached $toolName from $toolDir."
        }

        if ($path -match ".zip$") {
            $extractPath = "$toolDir\Extracted_$($toolName.Replace('.zip',''))"
            if (!(Test-Path $extractPath)) {
                Expand-Archive -Path $path -DestinationPath $extractPath -Force
            }
            Start-Process $extractPath
        } else {
            Start-Process $path
        }
        Update-Status "Launched $toolName."
    } catch {
        Update-Status "Error downloading $($toolName): $_"
    }
}

function Backup-UserProfileData {
    $backupRoot = Select-Folder
    if (-not $backupRoot) { return }
    $user = $env:USERNAME
    $targetDir = Join-Path $backupRoot "$user`_Backup_$(Get-Date -Format 'yyyyMMdd')"
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    Update-Status "=== Starting Smart Profile Backup for $user ==="
    Update-Status "Exporting WiFi Profiles..."
    $wifiDir = Join-Path $targetDir "WiFi_Profiles"
    New-Item -ItemType Directory -Path $wifiDir -Force | Out-Null
    Run-Command "netsh" "wlan export profile folder=`"$wifiDir`" key=clear"
    $folders = @("Desktop", "Documents", "Pictures", "Music", "Videos", "Downloads", "Favorites")
    foreach ($f in $folders) {
        $src = "$env:USERPROFILE\$f"
        $dst = "$targetDir\$f"
        Update-Status "Backing up $f..."
        Run-Command "robocopy" "`"$src`" `"$dst`" /E /R:1 /W:1 /NFL /NDL"
    }
    Update-Status "=== Backup Complete at $targetDir ==="
    [System.Windows.Forms.MessageBox]::Show("Backup saved to:`n$targetDir", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

function Reset-WindowsUpdate {
    if ([System.Windows.Forms.MessageBox]::Show("This will stop services, clear Update caches, reset Winsock, and re-register DLLs.`n`nContinue?", "Confirm Nuclear Reset", [System.Windows.Forms.MessageBoxButtons]::YesNo) -eq 'Yes') {
        Update-Status "Attempting to create System Restore Point..."
        try {
            Checkpoint-Computer -Description "Pre-UpdateReset" -RestorePointType "MODIFY_SETTINGS" -ErrorAction Stop
            Update-Status "Restore Point Created."
        } catch {
            Update-Status "Restore Point Failed (Protection might be off). Continuing..."
        }
        Update-Status "=== STARTING UPDATE RESET ==="
        $services = "bits", "wuauserv", "appidsvc", "cryptsvc"
        foreach ($svc in $services) { Update-Status "Stopping $svc..."; Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue }
        
        $bitsPath = "$env:ALLUSERSPROFILE\Application Data\Microsoft\Network\Downloader\*"
        Update-Status "Clearing BITS Queue..."; Remove-Item -Path $bitsPath -Recurse -Force -ErrorAction SilentlyContinue

        $softDist = "$env:SystemRoot\SoftwareDistribution"; $catRoot = "$env:SystemRoot\system32\catroot2"
        Update-Status "Removing SoftwareDistribution..."; Remove-Item -Path $softDist -Recurse -Force -ErrorAction SilentlyContinue
        Update-Status "Removing Catroot2..."; Remove-Item -Path $catRoot -Recurse -Force -ErrorAction SilentlyContinue

        $dlls = "atl.dll", "urlmon.dll", "mshtml.dll"
        foreach ($dll in $dlls) { Update-Status "Registering $dll..."; Start-Process "regsvr32.exe" -ArgumentList "/s $dll" }

        Update-Status "Resetting Winsock..."; Run-Command "netsh" "winsock reset"; Run-Command "netsh" "winsock reset proxy"
        foreach ($svc in $services) { Update-Status "Starting $svc..."; Start-Service -Name $svc -ErrorAction SilentlyContinue }

        Update-Status "=== RESET COMPLETE. PLEASE REBOOT. ==="
        [System.Windows.Forms.MessageBox]::Show("Windows Update Reset Complete.`n`nPlease reboot the computer.", "Done", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
    }
}

function Show-ChkdskMenu {
    $chkForm = New-Object System.Windows.Forms.Form
    $chkForm.Text = "Advanced Disk Utility"
    $chkForm.Size = New-Object System.Drawing.Size(400,280)
    $chkForm.StartPosition = "CenterScreen"
    $chkForm.BackColor = "#1e1e1e"
    $chkForm.ForeColor = "White"
    $btnStyle = @{ Size = New-Object System.Drawing.Size(340,40); BackColor = '#333333'; ForeColor = 'White'; FlatStyle = 'Flat' }
    
    $btnCheck = New-Object System.Windows.Forms.Button; $btnCheck.Text = "Run CHKDSK (Scan Only)"; $btnCheck.Location = New-Object System.Drawing.Point(20,20); $btnCheck.Size=$btnStyle.Size; $btnCheck.BackColor=$btnStyle.BackColor; $btnCheck.ForeColor=$btnStyle.ForeColor; $btnCheck.FlatStyle=$btnStyle.FlatStyle
    $btnCheck.Add_Click({ Start-Process "cmd.exe" "/k chkdsk $env:SystemDrive" })
    [void]$chkForm.Controls.Add($btnCheck)

    $btnFix = New-Object System.Windows.Forms.Button; $btnFix.Text = "Run CHKDSK /F (Fix Errors)"; $btnFix.Location = New-Object System.Drawing.Point(20,70); $btnFix.Size=$btnStyle.Size; $btnFix.BackColor=$btnStyle.BackColor; $btnFix.ForeColor=$btnStyle.ForeColor; $btnFix.FlatStyle=$btnStyle.FlatStyle
    $btnFix.Add_Click({ Start-Process "cmd.exe" "/k chkdsk $env:SystemDrive /F" })
    [void]$chkForm.Controls.Add($btnFix)

    $btnFixScan = New-Object System.Windows.Forms.Button; $btnFixScan.Text = "Run CHKDSK /R (Full Repair)"; $btnFixScan.Location = New-Object System.Drawing.Point(20,120); $btnFixScan.Size=$btnStyle.Size; $btnFixScan.BackColor=$btnStyle.BackColor; $btnFixScan.ForeColor=$btnStyle.ForeColor; $btnFixScan.FlatStyle=$btnStyle.FlatStyle
    $btnFixScan.Add_Click({ Start-Process "cmd.exe" "/k chkdsk $env:SystemDrive /R" })
    [void]$chkForm.Controls.Add($btnFixScan)

    $btnExit = New-Object System.Windows.Forms.Button; $btnExit.Text = "Close"; $btnExit.Location = New-Object System.Drawing.Point(20,180); $btnExit.Size=$btnStyle.Size; $btnExit.BackColor="DarkRed"; $btnExit.ForeColor="White"; $btnExit.FlatStyle="Flat"
    $btnExit.Add_Click({ $chkForm.Close() })
    [void]$chkForm.Controls.Add($btnExit)
    $chkForm.ShowDialog()
}

function Show-DriveMapper {
    $credentialFile = Join-Path $env:APPDATA "network_drive_credentials.xml"
    $mapForm = New-Object System.Windows.Forms.Form
    $mapForm.Text = "Technician's Toolkit - Network Drive Control"
    $mapForm.Size = New-Object System.Drawing.Size(550, 680)
    $mapForm.StartPosition = "CenterScreen"
    $mapForm.FormBorderStyle = "FixedSingle"
    $mapForm.MaximizeBox = $false
    
    # --- FONT FIX FOR DRIVE MAPPER (Enforce small compact size) ---
    $mapForm.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 8)
    # -------------------------------------------------------

    $grpConnection = New-Object System.Windows.Forms.GroupBox; $grpConnection.Text = "1. Target Paths"; $grpConnection.Location = New-Object System.Drawing.Point(12, 12); $grpConnection.Size = New-Object System.Drawing.Size(510, 180); [void]$mapForm.Controls.Add($grpConnection)
    $grpCreds = New-Object System.Windows.Forms.GroupBox; $grpCreds.Text = "2. Authentication"; $grpCreds.Location = New-Object System.Drawing.Point(12, 200); $grpCreds.Size = New-Object System.Drawing.Size(510, 130); [void]$mapForm.Controls.Add($grpCreds)
    $grpList = New-Object System.Windows.Forms.GroupBox; $grpList.Text = "3. Mapped Drives"; $grpList.Location = New-Object System.Drawing.Point(12, 400); $grpList.Size = New-Object System.Drawing.Size(510, 200); [void]$mapForm.Controls.Add($grpList)

    $lblDrive = New-Object System.Windows.Forms.Label; $lblDrive.Text = "Start Drive:"; $lblDrive.Location = New-Object System.Drawing.Point(15, 30); $lblDrive.AutoSize = $true; [void]$grpConnection.Controls.Add($lblDrive)
    $cbDrive = New-Object System.Windows.Forms.ComboBox; $cbDrive.Location = New-Object System.Drawing.Point(100, 27); $cbDrive.Width = 60; $cbDrive.DropDownStyle = "DropDownList"; [void]$grpConnection.Controls.Add($cbDrive)
    $lblPath = New-Object System.Windows.Forms.Label; $lblPath.Text = "Network Paths:`n(One per line)"; $lblPath.Location = New-Object System.Drawing.Point(15, 65); $lblPath.AutoSize = $true; [void]$grpConnection.Controls.Add($lblPath)
    $txtPaths = New-Object System.Windows.Forms.TextBox; $txtPaths.Location = New-Object System.Drawing.Point(100, 65); $txtPaths.Size = New-Object System.Drawing.Size(300, 100); $txtPaths.Multiline = $true; $txtPaths.ScrollBars = "Vertical"; [void]$grpConnection.Controls.Add($txtPaths)
    $btnBrowse = New-Object System.Windows.Forms.Button; $btnBrowse.Text = "Browse..."; $btnBrowse.Location = New-Object System.Drawing.Point(410, 65); $btnBrowse.Width = 80; [void]$grpConnection.Controls.Add($btnBrowse)

    $lblUser = New-Object System.Windows.Forms.Label; $lblUser.Text = "Username:"; $lblUser.Location = New-Object System.Drawing.Point(15, 30); $lblUser.AutoSize = $true; [void]$grpCreds.Controls.Add($lblUser)
    $txtUser = New-Object System.Windows.Forms.TextBox; $txtUser.Location = New-Object System.Drawing.Point(100, 27); $txtUser.Width = 180; [void]$grpCreds.Controls.Add($txtUser)
    $lblPass = New-Object System.Windows.Forms.Label; $lblPass.Text = "Password:"; $lblPass.Location = New-Object System.Drawing.Point(15, 60); $lblPass.AutoSize = $true; [void]$grpCreds.Controls.Add($lblPass)
    $txtPass = New-Object System.Windows.Forms.TextBox; $txtPass.Location = New-Object System.Drawing.Point(100, 57); $txtPass.Width = 180; $txtPass.UseSystemPasswordChar = $true; [void]$grpCreds.Controls.Add($txtPass)
    $chkPersist = New-Object System.Windows.Forms.CheckBox; $chkPersist.Text = "Reconnect at Sign-in"; $chkPersist.Location = New-Object System.Drawing.Point(300, 27); $chkPersist.AutoSize = $true; $chkPersist.Checked = $true; [void]$grpCreds.Controls.Add($chkPersist)
    $chkPrompt = New-Object System.Windows.Forms.CheckBox; $chkPrompt.Text = "Prompt for credentials for EACH path"; $chkPrompt.Location = New-Object System.Drawing.Point(300, 57); $chkPrompt.AutoSize = $true; $chkPrompt.ForeColor = "DarkBlue"; [void]$grpCreds.Controls.Add($chkPrompt)

    $chkPrompt.Add_CheckedChanged({ if ($chkPrompt.Checked) { $txtUser.Enabled=$false; $txtPass.Enabled=$false } else { $txtUser.Enabled=$true; $txtPass.Enabled=$true } })

    $btnMap = New-Object System.Windows.Forms.Button; $btnMap.Text = "MAP DRIVES"; $btnMap.Location = New-Object System.Drawing.Point(12, 345); $btnMap.Size = New-Object System.Drawing.Size(120, 40); $btnMap.BackColor = "CornflowerBlue"; $btnMap.ForeColor = "White"; $btnMap.FlatStyle = "Flat"; $btnMap.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold); [void]$mapForm.Controls.Add($btnMap)
    $btnRemove = New-Object System.Windows.Forms.Button; $btnRemove.Text = "Disconnect"; $btnRemove.Location = New-Object System.Drawing.Point(140, 345); $btnRemove.Size = New-Object System.Drawing.Size(100, 40); [void]$mapForm.Controls.Add($btnRemove)
    $btnRemoveAll = New-Object System.Windows.Forms.Button; $btnRemoveAll.Text = "Disconnect All"; $btnRemoveAll.Location = New-Object System.Drawing.Point(250, 345); $btnRemoveAll.Size = New-Object System.Drawing.Size(100, 40); [void]$mapForm.Controls.Add($btnRemoveAll)
    $btnRefresh = New-Object System.Windows.Forms.Button; $btnRefresh.Text = "Refresh List"; $btnRefresh.Location = New-Object System.Drawing.Point(422, 345); $btnRefresh.Size = New-Object System.Drawing.Size(100, 40); [void]$mapForm.Controls.Add($btnRefresh)

    $lstDrives = New-Object System.Windows.Forms.ListBox; $lstDrives.Location = New-Object System.Drawing.Point(15, 25); $lstDrives.Size = New-Object System.Drawing.Size(480, 160); $lstDrives.Font = New-Object System.Drawing.Font("Consolas", 9); [void]$grpList.Controls.Add($lstDrives)
    
    # --- FIX: Replaced obsolete 'StatusBar' with a docked Label ---
    $statusBar = New-Object System.Windows.Forms.Label
    $statusBar.Dock = "Bottom"
    $statusBar.Height = 25
    $statusBar.BorderStyle = "FixedSingle"
    $statusBar.TextAlign = "MiddleLeft"
    $statusBar.Text = "Ready"
    [void]$mapForm.Controls.Add($statusBar)
    # -------------------------------------------------------------

    $mapForm.Add_Load({ 
        $avail = [int][char]'C'..[int][char]'Z' | ForEach { [char]$_ } | Where { $_ -notin (Get-PSDrive -PSProvider FileSystem).Name }
        [void]$cbDrive.Items.AddRange($avail); if($avail){$cbDrive.SelectedItem=$avail[-1]}
        if (Test-Path $credentialFile) { try { $c=Import-Clixml $credentialFile; $txtUser.Text=$c.Username; $txtPass.Text=(ConvertTo-SecureString $c.Password -SecureKey (1..16)|ConvertFrom-SecureString -AsPlainText) } catch {} }
        $lstDrives.Items.Clear(); Get-PSDrive -PSProvider FileSystem | Where {$_.DisplayRoot} | ForEach { [void]$lstDrives.Items.Add(("{0,-5} --> {1}" -f ($_.Name+":"), $_.DisplayRoot)) }
    })

    $btnMap.Add_Click({
        $paths = $txtPaths.Lines | Where { $_.Trim() -ne "" }; if(!$paths){ [Windows.Forms.MessageBox]::Show("Enter path"); return }
        $statusBar.Text="Mapping..."; $curAsc=[int][char]$cbDrive.SelectedItem; $gCred=$null
        if(!$chkPrompt.Checked -and $txtUser.Text){ $gCred=New-Object System.Management.Automation.PSCredential($txtUser.Text, (ConvertTo-SecureString $txtPass.Text -AsPlainText -Force)) }
        foreach($p in $paths){
            $clean=$p.Trim(); if($clean -notmatch "^\\\\"){$clean="\\$clean"}; $dL=[char]$curAsc
            if(Get-PSDrive -Name $dL -EA SilentlyContinue){ Remove-PSDrive -Name $dL -Force -EA SilentlyContinue }
            try { 
                $par=@{Name=$dL;PSProvider="FileSystem";Root=$clean;Persist=$chkPersist.Checked}; if($chkPrompt.Checked){try{$par.Credential=Get-Credential -UserName $env:USERNAME -Message "Creds for $clean"}catch{continue}}elseif($gCred){$par.Credential=$gCred}
                New-PSDrive @par -EA Stop | Out-Null; $statusBar.Text="Mapped $dL"
            } catch { [Windows.Forms.MessageBox]::Show("Error mapping $dL to $clean`n$($_.Exception.Message)") }
            $curAsc--
        }
        if(!$chkPrompt.Checked){ @{Username=$txtUser.Text;Password=(ConvertFrom-SecureString (ConvertTo-SecureString $txtPass.Text -AsPlainText -Force) -SecureKey (1..16))} | Export-Clixml $credentialFile -Force }
        $lstDrives.Items.Clear(); Get-PSDrive -PSProvider FileSystem | Where {$_.DisplayRoot} | ForEach { [void]$lstDrives.Items.Add(("{0,-5} --> {1}" -f ($_.Name+":"), $_.DisplayRoot)) }
    })

    $btnRemove.Add_Click({ if($lstDrives.SelectedItem){ Remove-PSDrive -Name $lstDrives.SelectedItem.ToString().Substring(0,1) -Force -EA SilentlyContinue; $btnRefresh.PerformClick() } })
    $btnRemoveAll.Add_Click({ if([Windows.Forms.MessageBox]::Show("Disconnect ALL?","Confirm",'YesNo')-eq'Yes'){ Get-PSDrive -PSProvider FileSystem | Where {$_.DisplayRoot} | ForEach { Remove-PSDrive -Name $_.Name -Force }; $btnRefresh.PerformClick() } })
    $btnRefresh.Add_Click({ $lstDrives.Items.Clear(); Get-PSDrive -PSProvider FileSystem | Where {$_.DisplayRoot} | ForEach { [void]$lstDrives.Items.Add(("{0,-5} --> {1}" -f ($_.Name+":"), $_.DisplayRoot)) }; $statusBar.Text="Refreshed" })
    $btnBrowse.Add_Click({ $d=New-Object System.Windows.Forms.FolderBrowserDialog; if($d.ShowDialog()-eq'OK'){$txtPaths.Text+=$d.SelectedPath+"`r`n"} })
    $mapForm.ShowDialog()
}

function Show-PrinterMenu {
    $pForm = New-Object System.Windows.Forms.Form
    $pForm.Text = "Printer Commander"; $pForm.Size = New-Object System.Drawing.Size(600,450); $pForm.StartPosition = "CenterScreen"; $pForm.BackColor = "#222222"; $pForm.ForeColor = "White"
    
    $lstPrinters = New-Object System.Windows.Forms.ListBox
    $lstPrinters.Location = New-Object System.Drawing.Point(20, 40)
    $lstPrinters.Size = New-Object System.Drawing.Size(350, 300)
    $lstPrinters.Font = New-Object System.Drawing.Font("Consolas", 10)
    [void]$pForm.Controls.Add($lstPrinters)

    $lblTitle = New-Object System.Windows.Forms.Label; $lblTitle.Text="Select Printer:"; $lblTitle.Location=New-Object System.Drawing.Point(20, 15); $lblTitle.AutoSize=$true
    [void]$pForm.Controls.Add($lblTitle)

    # Actions Panel
    $btnStyle = @{ Size = New-Object System.Drawing.Size(180,35); BackColor = '#444444'; ForeColor = 'White'; FlatStyle = 'Flat' }
    
    $btnRefresh = New-Object System.Windows.Forms.Button; $btnRefresh.Text = "Refresh List"; $btnRefresh.Location = New-Object System.Drawing.Point(390, 40); $btnRefresh.Size=$btnStyle.Size; $btnRefresh.BackColor="Teal"; $btnRefresh.ForeColor="White"; $btnRefresh.FlatStyle=$btnStyle.FlatStyle
    [void]$pForm.Controls.Add($btnRefresh)

    $btnTest = New-Object System.Windows.Forms.Button; $btnTest.Text = "Print Test Page"; $btnTest.Location = New-Object System.Drawing.Point(390, 85); $btnTest.Size=$btnStyle.Size; $btnTest.BackColor=$btnStyle.BackColor; $btnTest.ForeColor=$btnStyle.ForeColor; $btnTest.FlatStyle=$btnStyle.FlatStyle
    [void]$pForm.Controls.Add($btnTest)

    $btnQueue = New-Object System.Windows.Forms.Button; $btnQueue.Text = "Open Queue Window"; $btnQueue.Location = New-Object System.Drawing.Point(390, 130); $btnQueue.Size=$btnStyle.Size; $btnQueue.BackColor=$btnStyle.BackColor; $btnQueue.ForeColor=$btnQueue.ForeColor; $btnQueue.FlatStyle=$btnQueue.FlatStyle
    [void]$pForm.Controls.Add($btnQueue)

    $btnDefault = New-Object System.Windows.Forms.Button; $btnDefault.Text = "Set as Default"; $btnDefault.Location = New-Object System.Drawing.Point(390, 175); $btnDefault.Size=$btnStyle.Size; $btnDefault.BackColor=$btnStyle.BackColor; $btnDefault.ForeColor=$btnDefault.ForeColor; $btnDefault.FlatStyle=$btnDefault.FlatStyle
    [void]$pForm.Controls.Add($btnDefault)

    $btnClearSel = New-Object System.Windows.Forms.Button; $btnClearSel.Text = "Clear THIS Queue"; $btnClearSel.Location = New-Object System.Drawing.Point(390, 220); $btnClearSel.Size=$btnStyle.Size; $btnClearSel.BackColor="DarkGoldenrod"; $btnClearSel.ForeColor="White"; $btnClearSel.FlatStyle=$btnStyle.FlatStyle
    [void]$pForm.Controls.Add($btnClearSel)

    # Global Actions
    $grpGlobal = New-Object System.Windows.Forms.GroupBox; $grpGlobal.Text="Global Actions"; $grpGlobal.Location=New-Object System.Drawing.Point(20, 350); $grpGlobal.Size=New-Object System.Drawing.Size(550, 50); $grpGlobal.ForeColor="White"
    [void]$pForm.Controls.Add($grpGlobal)

    $btnSpool = New-Object System.Windows.Forms.Button; $btnSpool.Text = "Restart Spooler"; $btnSpool.Location = New-Object System.Drawing.Point(10, 15); $btnSpool.Size=New-Object System.Drawing.Size(120, 25); $btnSpool.BackColor="DarkRed"; $btnSpool.ForeColor="White"; $btnSpool.FlatStyle="Flat"
    [void]$grpGlobal.Controls.Add($btnSpool)

    $btnPurgeAll = New-Object System.Windows.Forms.Button; $btnPurgeAll.Text = "Nuke ALL Queues"; $btnPurgeAll.Location = New-Object System.Drawing.Point(140, 15); $btnPurgeAll.Size=New-Object System.Drawing.Size(120, 25); $btnPurgeAll.BackColor="DarkRed"; $btnPurgeAll.ForeColor="White"; $btnPurgeAll.FlatStyle="Flat"
    [void]$grpGlobal.Controls.Add($btnPurgeAll)

    # Logic
    $RefreshList = {
        $lstPrinters.Items.Clear()
        $printers = Get-CimInstance Win32_Printer | Sort-Object Name
        foreach ($p in $printers) {
            $defMark = if($p.Default){" (DEF)"}else{""}
            [void]$lstPrinters.Items.Add("$($p.Name)$defMark")
        }
    }

    $pForm.Add_Load({ & $RefreshList })
    $btnRefresh.Add_Click({ & $RefreshList })
    
    $btnSpool.Add_Click({ Restart-Service Spooler -Force; [Windows.Forms.MessageBox]::Show("Spooler Restarted") })
    
    $btnPurgeAll.Add_Click({ 
        if([Windows.Forms.MessageBox]::Show("Delete ALL jobs from ALL printers?","Confirm","YesNo")-eq'Yes'){
            Stop-Service Spooler -Force
            Remove-Item "$env:SystemRoot\System32\spool\PRINTERS\*" -Force -Recurse -ErrorAction SilentlyContinue
            Start-Service Spooler
            [Windows.Forms.MessageBox]::Show("All Queues Cleared.")
        }
    })

    $btnTest.Add_Click({
        if($lstPrinters.SelectedItem){
            $name = $lstPrinters.SelectedItem.ToString().Replace(" (DEF)","")
            Start-Process powershell -ArgumentList "-NoProfile -Command `"Get-CimInstance Win32_Printer -Filter 'Name=''$name''' | Invoke-CimMethod -MethodName PrintTestPage`"" -WindowStyle Hidden
            [Windows.Forms.MessageBox]::Show("Test Page Sent to: $name`n`n(If PDF, check taskbar for 'Save As' icon)")
        }
    })

    $btnQueue.Add_Click({
        if($lstPrinters.SelectedItem){
            $name = $lstPrinters.SelectedItem.ToString().Replace(" (DEF)","")
            Start-Process "rundll32.exe" "printui.dll,PrintUIEntry /o /n `"$name`""
        }
    })

    $btnDefault.Add_Click({
        if($lstPrinters.SelectedItem){
            $name = $lstPrinters.SelectedItem.ToString().Replace(" (DEF)","")
            try {
                $p = Get-CimInstance Win32_Printer -Filter "Name='$name'"
                Invoke-CimMethod -InputObject $p -MethodName SetDefaultPrinter | Out-Null
                & $RefreshList
            } catch { [Windows.Forms.MessageBox]::Show("Error: $_") }
        }
    })

    $btnClearSel.Add_Click({
        if($lstPrinters.SelectedItem){
            $name = $lstPrinters.SelectedItem.ToString().Replace(" (DEF)","")
            if([Windows.Forms.MessageBox]::Show("Clear queue for: $name?","Confirm","YesNo")-eq'Yes'){
                try {
                    $p = Get-CimInstance Win32_Printer -Filter "Name='$name'"
                    Invoke-CimMethod -InputObject $p -MethodName CancelAllJobs | Out-Null
                    [Windows.Forms.MessageBox]::Show("Jobs Cancelled.")
                } catch { [Windows.Forms.MessageBox]::Show("Error: $_") }
            }
        }
    })

    $pForm.ShowDialog()
}

# Global Variables for Monitor
$script:prevBytesRec = 0
$script:prevBytesSent = 0
$script:lastTick = Get-Date
$script:monitorBusy = $false 
$script:tickCounter = 0 

# SAFE INITIALIZATION FIX
try {
    $script:perfCPU = New-Object System.Diagnostics.PerformanceCounter("Processor", "% Processor Time", "_Total")
} catch {
    $script:perfCPU = $null
    # Optional: Log that fast counters failed
}

# End Region

# --- GUI SETUP ---
$form = New-Object System.Windows.Forms.Form
$form.Text = 'REGTeches Technician''s Toolkit V24.02 Pro' 
$form.Size = New-Object System.Drawing.Size(1600, 1000)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'Fixed3D'
$form.BackColor = '#121212' 

# --- TABS SETUP ---
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(12, 160)
$tabControl.Size = New-Object System.Drawing.Size(1560, 720)
$tabControl.Appearance = 'FlatButtons'

# TAB 1: CONSOLE
$tabConsole = New-Object System.Windows.Forms.TabPage
$tabConsole.Text = "Console / Log"
$tabConsole.BackColor = "Black"
$statusTextBox = New-Object System.Windows.Forms.TextBox
$statusTextBox.Dock = "Fill"
$statusTextBox.Multiline = $true
$statusTextBox.ScrollBars = "Vertical"
$statusTextBox.ReadOnly = $true
$statusTextBox.BackColor = 'Black'
$statusTextBox.ForeColor = '#00FF00' 
$statusTextBox.Font = New-Object System.Drawing.Font("Consolas", 11)
[void]$tabConsole.Controls.Add($statusTextBox)
[void]$tabControl.Controls.Add($tabConsole)

# TAB 2: SYSTEM MONITOR
$tabMonitor = New-Object System.Windows.Forms.TabPage
$tabMonitor.Text = "Live Monitor"
$tabMonitor.BackColor = "#1E1E1E"
[void]$tabControl.Controls.Add($tabMonitor)

# Monitor Controls
# === FONT REDUCTION FIX ===
$lblFont = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold) # WAS 24pt
$mediumFont = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold) # WAS 14pt
$detailFont = New-Object System.Drawing.Font("Segoe UI", 10) # WAS 12pt
# ==========================

# CPU
$lblCpuTitle = New-Object System.Windows.Forms.Label; $lblCpuTitle.Text="CPU Usage"; $lblCpuTitle.Location=New-Object System.Drawing.Point(50,30); $lblCpuTitle.ForeColor="White"; $lblCpuTitle.AutoSize=$true; $lblCpuTitle.Font=$detailFont
[void]$tabMonitor.Controls.Add($lblCpuTitle)
$lblCpu = New-Object System.Windows.Forms.Label; $lblCpu.Text="0%"; $lblCpu.Location=New-Object System.Drawing.Point(50,55); $lblCpu.ForeColor="Cyan"; $lblCpu.AutoSize=$true; $lblCpu.Font=$lblFont
[void]$tabMonitor.Controls.Add($lblCpu)
$progCpu = New-Object System.Windows.Forms.ProgressBar; $progCpu.Location=New-Object System.Drawing.Point(50,105); $progCpu.Size=New-Object System.Drawing.Size(600,20)
[void]$tabMonitor.Controls.Add($progCpu)

# RAM
$lblRamTitle = New-Object System.Windows.Forms.Label; $lblRamTitle.Text="RAM Usage"; $lblRamTitle.Location=New-Object System.Drawing.Point(50,150); $lblRamTitle.ForeColor="White"; $lblRamTitle.AutoSize=$true; $lblRamTitle.Font=$detailFont
[void]$tabMonitor.Controls.Add($lblRamTitle)
$lblRam = New-Object System.Windows.Forms.Label; $lblRam.Text="0 / 0 GB"; $lblRam.Location=New-Object System.Drawing.Point(50,175); $lblRam.ForeColor="Lime"; $lblRam.AutoSize=$true; $lblRam.Font=$lblFont
[void]$tabMonitor.Controls.Add($lblRam)
$progRam = New-Object System.Windows.Forms.ProgressBar; $progRam.Location=New-Object System.Drawing.Point(50,225); $progRam.Size=New-Object System.Drawing.Size(600,20)
[void]$tabMonitor.Controls.Add($progRam)

# Disk C:
$lblDiskTitle = New-Object System.Windows.Forms.Label; $lblDiskTitle.Text="System Drive Space"; $lblDiskTitle.Location=New-Object System.Drawing.Point(50,270); $lblDiskTitle.ForeColor="White"; $lblDiskTitle.AutoSize=$true; $lblDiskTitle.Font=$detailFont
[void]$tabMonitor.Controls.Add($lblDiskTitle)
$lblDisk = New-Object System.Windows.Forms.Label; $lblDisk.Text="0 GB Free"; $lblDisk.Location=New-Object System.Drawing.Point(50,295); $lblDisk.ForeColor="Yellow"; $lblDisk.AutoSize=$true; $lblDisk.Font=$lblFont
[void]$tabMonitor.Controls.Add($lblDisk)
$progDisk = New-Object System.Windows.Forms.ProgressBar; $progDisk.Location=New-Object System.Drawing.Point(50,345); $progDisk.Size=New-Object System.Drawing.Size(600,20)
[void]$tabMonitor.Controls.Add($progDisk)

# --- NEW: SYSTEM IDENTITY VISUAL (PC IMAGE REPLACEMENT) ---
$grpIdent = New-Object System.Windows.Forms.GroupBox; $grpIdent.Text="System Identity"; $grpIdent.Location=New-Object System.Drawing.Point(700, 30); $grpIdent.Size=New-Object System.Drawing.Size(800, 120); $grpIdent.ForeColor="LightBlue"; $grpIdent.Font=$detailFont
[void]$tabMonitor.Controls.Add($grpIdent)

$identFont = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$lblHost = New-Object System.Windows.Forms.Label; $lblHost.Text="Host: $env:COMPUTERNAME"; $lblHost.Location=New-Object System.Drawing.Point(20, 30); $lblHost.AutoSize=$true; $lblHost.Font=$identFont; $lblHost.ForeColor="White"
[void]$grpIdent.Controls.Add($lblHost)

$csInfo = Get-CimInstance Win32_ComputerSystem
$lblModel = New-Object System.Windows.Forms.Label; $lblModel.Text="$($csInfo.Manufacturer) - $($csInfo.Model)"; $lblModel.Location=New-Object System.Drawing.Point(20, 70); $lblModel.AutoSize=$true; $lblModel.Font=$detailFont; $lblModel.ForeColor="Gray"
[void]$grpIdent.Controls.Add($lblModel)

# --- NETWORK SECTION (Moved Down & Split) ---
$grpNet = New-Object System.Windows.Forms.GroupBox; $grpNet.Text="Network Operations Center"; $grpNet.Location=New-Object System.Drawing.Point(700, 170); $grpNet.Size=New-Object System.Drawing.Size(800, 420); $grpNet.ForeColor="White"; $grpNet.Font=$detailFont
[void]$tabMonitor.Controls.Add($grpNet)

# Left Side: IP List (Room to grow down)
$lblIp = New-Object System.Windows.Forms.Label; $lblIp.Text="Scanning IPs..."; $lblIp.Location=New-Object System.Drawing.Point(20, 40); $lblIp.AutoSize=$true
[void]$grpNet.Controls.Add($lblIp)

# Right Side: Metrics & Tools (Prevent overlap)
$lblPing = New-Object System.Windows.Forms.Label; $lblPing.Text="Latency (Google): ..."; $lblPing.Location=New-Object System.Drawing.Point(400, 40); $lblPing.AutoSize=$true
[void]$grpNet.Controls.Add($lblPing)

$lblNetSpeed = New-Object System.Windows.Forms.Label; $lblNetSpeed.Text="Live Traffic: Calculating..."; $lblNetSpeed.Location=New-Object System.Drawing.Point(400, 100); $lblNetSpeed.AutoSize=$true; $lblNetSpeed.Font=$mediumFont; $lblNetSpeed.ForeColor="Orange"
[void]$grpNet.Controls.Add($lblNetSpeed)

$btnSpeedTest = New-Object System.Windows.Forms.Button; $btnSpeedTest.Text="RUN SPEED TEST (Download)"; $btnSpeedTest.Location=New-Object System.Drawing.Point(400, 180); $btnSpeedTest.Size=New-Object System.Drawing.Size(300, 50); $btnSpeedTest.BackColor="Teal"; $btnSpeedTest.ForeColor="White"; $btnSpeedTest.FlatStyle="Flat"
$btnSpeedTest.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold) # REDUCED SIZE HERE
[void]$grpNet.Controls.Add($btnSpeedTest)

$btnSpeedTest.Add_Click({
    $btnSpeedTest.Text = "Running Test..."
    $btnSpeedTest.Enabled = $false
    [System.Windows.Forms.Application]::DoEvents()
    
    $url = "http://speedtest.tele2.net/10MB.zip" 
    $tempFile = "$env:TEMP\speedtest_regtech.tmp"
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    
    try {
        $wc = New-Object System.Net.WebClient
        $wc.DownloadFile($url, $tempFile)
        
        $sw.Stop()
        $sizeBytes = (Get-Item $tempFile).Length
        $seconds = $sw.Elapsed.TotalSeconds
        $mbps = [math]::Round(($sizeBytes / 1MB) / $seconds, 2)
        
        [System.Windows.Forms.MessageBox]::Show("Download Speed: $mbps MB/s`nTime: $([math]::Round($seconds,2))s", "Test Result", 'OK', 'Information')
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    } catch {
        [System.Windows.Forms.MessageBox]::Show("Speed test failed. Check internet.", "Error", 'OK', 'Error')
    }
    $btnSpeedTest.Text = "RUN SPEED TEST (Download)"
    $btnSpeedTest.Enabled = $true
})

# --- TAB 3: SOFTWARE DEPLOY ---
$tabDeploy = New-Object System.Windows.Forms.TabPage; $tabDeploy.Text = "Software Deploy"; $tabDeploy.BackColor = "#222222"
[void]$tabControl.Controls.Add($tabDeploy)

$lblDrop = New-Object System.Windows.Forms.Label; $lblDrop.Text = "SOFTWARE INSTALLER`n(Select EXE or MSI)"; $lblDrop.Location = New-Object System.Drawing.Point(50, 30); $lblDrop.AutoSize=$true; $lblDrop.Font=$lblFont; $lblDrop.ForeColor="LightBlue"
[void]$tabDeploy.Controls.Add($lblDrop)

$txtInstallPath = New-Object System.Windows.Forms.TextBox; $txtInstallPath.Location=New-Object System.Drawing.Point(50, 150); $txtInstallPath.Size=New-Object System.Drawing.Size(800, 30); $txtInstallPath.Font=$detailFont; $txtInstallPath.ReadOnly=$true
[void]$tabDeploy.Controls.Add($txtInstallPath)

$btnBrowseInst = New-Object System.Windows.Forms.Button; $btnBrowseInst.Text="Browse..."; $btnBrowseInst.Location=New-Object System.Drawing.Point(860, 150); $btnBrowseInst.Size=New-Object System.Drawing.Size(100, 30); $btnBrowseInst.BackColor="Gray"; $btnBrowseInst.ForeColor="White"
$btnBrowseInst.Add_Click({ $f=Select-File "Installers (*.exe;*.msi)|*.exe;*.msi"; if($f){$txtInstallPath.Text=$f} })
[void]$tabDeploy.Controls.Add($btnBrowseInst)

$lblArgs = New-Object System.Windows.Forms.Label; $lblArgs.Text = "Silent Arguments (Optional):"; $lblArgs.Location = New-Object System.Drawing.Point(50, 210); $lblArgs.AutoSize=$true; $lblArgs.ForeColor="White"; $lblArgs.Font=$detailFont
[void]$tabDeploy.Controls.Add($lblArgs)

$txtArgs = New-Object System.Windows.Forms.TextBox; $txtArgs.Location=New-Object System.Drawing.Point(50, 240); $txtArgs.Size=New-Object System.Drawing.Size(800, 30); $txtArgs.Font=$detailFont
[void]$tabDeploy.Controls.Add($txtArgs)

# Quick Argument Buttons
$btnS = New-Object System.Windows.Forms.Button; $btnS.Text="Add /S"; $btnS.Location=New-Object System.Drawing.Point(860, 240); $btnS.Size=New-Object System.Drawing.Size(80,30); $btnS.Add_Click({$txtArgs.Text += " /S"})
[void]$tabDeploy.Controls.Add($btnS)
$btnQ = New-Object System.Windows.Forms.Button; $btnQ.Text="Add /qn"; $btnQ.Location=New-Object System.Drawing.Point(950, 240); $btnQ.Size=New-Object System.Drawing.Size(80,30); $btnQ.Add_Click({$txtArgs.Text += " /qn"})
[void]$tabDeploy.Controls.Add($btnQ)

$btnRunInstall = New-Object System.Windows.Forms.Button; $btnRunInstall.Text="RUN INSTALLER (ADMIN)"; $btnRunInstall.Location=New-Object System.Drawing.Point(50, 300); $btnRunInstall.Size=New-Object System.Drawing.Size(300, 60); $btnRunInstall.BackColor="Green"; $btnRunInstall.ForeColor="White"; $btnRunInstall.Font=$lblFont; $btnRunInstall.FlatStyle='Flat'
$btnRunInstall.Add_Click({
    if ($txtInstallPath.Text) {
        $tabControl.SelectedTab = $tabConsole
        Update-Status "Installing: $($txtInstallPath.Text)..."
        Run-Command $txtInstallPath.Text $txtArgs.Text
        Update-Status "Installation process finished."
    } else { [Windows.Forms.MessageBox]::Show("Please select a file.") }
})
[void]$tabDeploy.Controls.Add($btnRunInstall)


# Timer Logic Update (STAGGERED UPDATES)
$sysTimer = New-Object System.Windows.Forms.Timer
$sysTimer.Interval = 2000 # 2 seconds
$sysTimer.Add_Tick({
    if ($script:monitorBusy) { return }
    $script:monitorBusy = $true
    $script:tickCounter++

    try {
        # --- PHASE 1: FAST CHECKS (Run Every 2s) ---
        
        # === CPU FIX: FALLBACK LOGIC ===
        $cpu = 0
        try {
            # Try fast method first
            $cpu = $script:perfCPU.NextValue()
        } catch {
            $cpu = 0
        }

        # If fast method fails (returns 0 or error), use WMI fallback
        if ($cpu -eq 0) {
            try {
                $cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
            } catch {
                $cpu = 0
            }
        }
        # ===============================

        $lblCpu.Text = "$([math]::Round($cpu))%"
        $progCpu.Value = [math]::Min([int]$cpu, 100)
        
        # RAM (CIM)
        $os = Get-CimInstance Win32_OperatingSystem
        $totalBytes = $os.TotalVisibleMemorySize * 1024
        $freeBytes = $os.FreePhysicalMemory * 1024
        $usedBytes = $totalBytes - $freeBytes
        $percRam = ($usedBytes / $totalBytes) * 100
        $lblRam.Text = "$([math]::Round($usedBytes/1GB,1)) GB / $([math]::Round($totalBytes/1GB,1)) GB"
        $progRam.Value = [math]::Min([int]$percRam, 100)

        # --- PHASE 2: SLOW CHECKS (Run Every 4th tick / 8s) ---
        if ($script:tickCounter % 4 -eq 0) {
            
            # Disk (CIM)
            $driveLetter = $env:SystemDrive.Substring(0,2)
            $disk = Get-CimInstance Win32_LogicalDisk | Where-Object DeviceID -eq $driveLetter
            $totalDisk = $disk.Size
            $freeDisk = $disk.FreeSpace
            $usedDisk = $totalDisk - $freeDisk
            $percDisk = ($usedDisk / $totalDisk) * 100
            $lblDisk.Text = "$([math]::Round($freeDisk/1GB,1)) GB Free (of $([math]::Round($totalDisk/1GB,0)) GB)"
            $progDisk.Value = [math]::Min([int]$percDisk, 100)
            
            # Ping (Ultra-Fast 50ms Timeout to prevent locking)
            try {
                $pingSender = New-Object System.Net.NetworkInformation.Ping
                $reply = $pingSender.Send("8.8.8.8", 50) 
                if ($reply.Status -eq 'Success') { 
                    $lblPing.Text = "Latency: $($reply.RoundtripTime) ms" 
                    $lblPing.ForeColor = "White"
                } else {
                    $lblPing.Text = "Latency: ..."
                }
            } catch {}

            # Bandwidth (SUM OF ALL ACTIVE ADAPTERS FIX)
            $adapters = Get-NetAdapterStatistics | Where-Object { $_.ReceivedBytes -gt 0 }
            if ($adapters) {
                $currRec = ($adapters | Measure-Object ReceivedBytes -Sum).Sum
                $currSent = ($adapters | Measure-Object SentBytes -Sum).Sum
                $timeDiff = ((Get-Date) - $script:lastTick).TotalSeconds
                
                if ($timeDiff -gt 0 -and $script:prevBytesRec -gt 0) {
                    $downSpeed = ($currRec - $script:prevBytesRec) / $timeDiff
                    $upSpeed = ($currSent - $script:prevBytesSent) / $timeDiff
                    
                    if ($downSpeed -lt 0) { $downSpeed = 0 }
                    if ($upSpeed -lt 0) { $upSpeed = 0 }
                    
                    $dStr = if($downSpeed -gt 1MB) { "$([math]::Round($downSpeed/1MB, 2)) MB/s" } else { "$([math]::Round($downSpeed/1KB, 0)) KB/s" }
                    $uStr = if($upSpeed -gt 1MB) { "$([math]::Round($upSpeed/1MB, 2)) MB/s" } else { "$([math]::Round($upSpeed/1KB, 0)) KB/s" }
                    
                    $lblNetSpeed.Text = "▼ $dStr    ▲ $uStr"
                }
                $script:prevBytesRec = $currRec
                $script:prevBytesSent = $currSent
                $script:lastTick = Get-Date
            }
            
            # --- NO MORE BACKGROUND IP CHECKS ---
            # This prevents the loop/flash issue entirely.
        }
    } catch {
        # Fail silently to keep UI alive
    }

    $script:monitorBusy = $false
})

# --- IP SCAN ON LOAD (Run Once - No Freeze) ---
# We define a function to refresh IPs, and call it once when the tab is selected.
$RefreshIPs = {
    try {
        # Using Legacy WMI (Works on older/stuck systems)
        $configs = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        $ipList = @()
        foreach ($c in $configs) {
            foreach ($addr in $c.IPAddress) {
                # Filter valid IPv4 (looks like x.x.x.x)
                if ($addr -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$') {
                    $ipList += $addr
                }
            }
        }
        if ($ipList.Count -gt 0) {
            $lblIp.Text = "IP Addresses:`n" + ($ipList -join "`n")
        } else {
            $lblIp.Text = "IP: Not Connected"
        }
    } catch {
        $lblIp.Text = "IP Scan Error"
    }
}

# --- SMART MONITOR: PAUSE WHEN HIDDEN ---
$tabControl.Add_SelectedIndexChanged({
    if ($tabControl.SelectedTab.Text -eq "Live Monitor") {
        $script:prevBytesRec = 0 
        $sysTimer.Start()
        # RUN IP SCAN ONCE HERE (Safe from freezing loop)
        & $RefreshIPs 
        Update-Status "Live Monitor Started."
    } else {
        $sysTimer.Stop()
        Update-Status "Live Monitor Paused."
    }
})

[void]$form.Controls.Add($tabControl)

# Initial Status
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$bios = Get-CimInstance Win32_BIOS
$uptime = (Get-Date) - $os.LastBootUpTime
$statusTextBox.Text = @"
SYSTEM READY - REGTeches Technician's Toolkit V24.02 Pro
----------------------------------------
User:       $env:USERNAME
Model:      $($cs.Manufacturer) $($cs.Model)
Serial:     $($bios.SerialNumber)
OS Build:   $($os.Caption) ($($os.Version))
Uptime:     $($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m
----------------------------------------
"@ + "`r`n"

# Progress Bar (Bottom)
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Dock = 'Bottom'
$progressBar.Height = 15
$progressBar.Style = 'Marquee'
$progressBar.Visible = $false
[void]$form.Controls.Add($progressBar)

# Buttons
$btnStyle = @{ Size = New-Object System.Drawing.Size(100, 30); BackColor = '#333'; ForeColor = 'White'; FlatStyle = 'Flat' }

$cancelButton = New-Object System.Windows.Forms.Button; $cancelButton.Text="STOP"; $cancelButton.Location=New-Object System.Drawing.Point(1450, 120); $cancelButton.Size=New-Object System.Drawing.Size(120, 30); $cancelButton.BackColor='DarkRed'; $cancelButton.ForeColor='White'; $cancelButton.FlatStyle='Flat'; $cancelButton.Enabled=$false
[void]$form.Controls.Add($cancelButton); $cancelButton.Add_Click({ $script:CancellationToken = $true; $cancelButton.Enabled = $false; Update-Status 'Stopping...' })

$saveLogButton = New-Object System.Windows.Forms.Button; $saveLogButton.Text="Save Log"; $saveLogButton.Location=New-Object System.Drawing.Point(12, 120); $saveLogButton.Size=$btnStyle.Size; $saveLogButton.BackColor=$btnStyle.BackColor; $saveLogButton.ForeColor=$btnStyle.ForeColor; $saveLogButton.FlatStyle=$btnStyle.FlatStyle
[void]$form.Controls.Add($saveLogButton); $saveLogButton.Add_Click({ $sfd = New-Object System.Windows.Forms.SaveFileDialog; $sfd.Filter="Txt|*.txt"; $sfd.FileName="TechniciansToolkit_Log.txt"; if($sfd.ShowDialog()-eq'OK'){$statusTextBox.Text|Out-File $sfd.FileName; Update-Status "Log Saved."}})

$clearLogButton = New-Object System.Windows.Forms.Button; $clearLogButton.Text="Clear Log"; $clearLogButton.Location=New-Object System.Drawing.Point(120, 120); $clearLogButton.Size=$btnStyle.Size; $clearLogButton.BackColor=$btnStyle.BackColor; $clearLogButton.ForeColor=$btnStyle.ForeColor; $clearLogButton.FlatStyle=$btnStyle.FlatStyle
[void]$form.Controls.Add($clearLogButton); $clearLogButton.Add_Click({ $statusTextBox.Text=""; Update-Status "Ready." })

$rebootButton = New-Object System.Windows.Forms.Button; $rebootButton.Text="Reboot PC"; $rebootButton.Location=New-Object System.Drawing.Point(240, 120); $rebootButton.Size=$btnStyle.Size; $rebootButton.BackColor='DarkOrange'; $rebootButton.ForeColor='Black'; $rebootButton.FlatStyle='Flat'
[void]$form.Controls.Add($rebootButton); $rebootButton.Add_Click({ if([System.Windows.Forms.MessageBox]::Show("Reboot now?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo)-eq'Yes'){Restart-Computer -Force} })

$shutdownButton = New-Object System.Windows.Forms.Button; $shutdownButton.Text="Shutdown"; $shutdownButton.Location=New-Object System.Drawing.Point(350, 120); $shutdownButton.Size=$btnStyle.Size; $shutdownButton.BackColor='DarkRed'; $shutdownButton.ForeColor='White'; $shutdownButton.FlatStyle='Flat'
[void]$form.Controls.Add($shutdownButton); $shutdownButton.Add_Click({ if([System.Windows.Forms.MessageBox]::Show("Shutdown now?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo)-eq'Yes'){Stop-Computer -Force} })


# ================= MAIN MENU CONSTRUCTION =================

# --- 1. File Menu ---
$fileMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&File")
$exitItem = New-Object System.Windows.Forms.ToolStripMenuItem("Exit")
$exitItem.Add_Click({ $form.Close() })
[void]$fileMenu.DropDownItems.Add($exitItem)

# --- 2. AUTOMATION ---
$autoMenu = New-Object System.Windows.Forms.ToolStripMenuItem("★ &Automation")
$oneClickItem = New-Object System.Windows.Forms.ToolStripMenuItem("Run One-Click System Repair")
$oneClickItem.Add_Click({
    if ([System.Windows.Forms.MessageBox]::Show("Start Automatic Maintenance?`n`nActions:`n1. Clean Temp Files`n2. Empty Recycle Bin`n3. SFC Scan (System Files)`n4. DISM Scan (Image Health)`n5. Defrag/Trim C:", "Confirm Auto-Repair", [System.Windows.Forms.MessageBoxButtons]::YesNo) -eq 'Yes') {
        # Switch to Console Tab so user sees output
        $tabControl.SelectedTab = $tabConsole
        Update-Status "=== STARTING ONE-CLICK REPAIR ==="
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue; Update-Status "Temp Cleaned."
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue; Update-Status "Bin Emptied."
        Update-Status "Running SFC Scan..."
        Run-Command "sfc.exe" "/scannow"
        Update-Status "Running DISM Scan..."
        Run-Command "dism" "/Online /Cleanup-Image /ScanHealth"
        Update-Status "Optimizing Drive..."
        Run-Command "defrag.exe" "$env:SystemDrive /O"
        Update-Status "=== ONE-CLICK REPAIR COMPLETE ==="
    }
})
[void]$autoMenu.DropDownItems.Add($oneClickItem)

# --- 3. System Manager ---
$sysMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&System Manager")

$hwSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Hardware")
$specsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Basic System Specs"); $specsItem.Add_Click({ $cs=Get-CimInstance Win32_ComputerSystem; $os=Get-CimInstance Win32_OperatingSystem; $cpu=Get-CimInstance Win32_Processor; Update-Status "OS: $($os.Caption) | CPU: $($cpu.Name) | RAM: $([math]::Round($cs.TotalPhysicalMemory/1GB,2)) GB" })
$uptimeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Show System Uptime"); $uptimeItem.Add_Click({ $os=Get-CimInstance Win32_OperatingSystem; $u=(Get-Date)-$os.LastBootUpTime; [System.Windows.Forms.MessageBox]::Show("Uptime: $($u.Days)d $($u.Hours)h $($u.Minutes)m", "Uptime") })
$ramDetailItem = New-Object System.Windows.Forms.ToolStripMenuItem("RAM Details"); $ramDetailItem.Add_Click({ Get-CimInstance Win32_PhysicalMemory | ForEach-Object { Update-Status "Slot: $($_.BankLabel) | $([math]::Round($_.Capacity/1GB,0))GB | $($_.Speed)MHz | $($_.Manufacturer)" } })
$battReportItem = New-Object System.Windows.Forms.ToolStripMenuItem("Battery Report"); $battReportItem.Add_Click({ $p="$env:USERPROFILE\Desktop\battery.html"; Run-Command "powercfg" "/batteryreport /output `"$p`""; Start-Process $p })
$driverInfoItem = New-Object System.Windows.Forms.ToolStripMenuItem("PnP Driver Info"); $driverInfoItem.Add_Click({ Run-Command "powershell" "Get-PnpDevice | Select-Object FriendlyName, Status, Class | Format-Table -AutoSize" })
$dxDiagItem = New-Object System.Windows.Forms.ToolStripMenuItem("DirectX Diagnostics (dxdiag)"); $dxDiagItem.Add_Click({ Start-Process "dxdiag" })
[void]$hwSubMenu.DropDownItems.AddRange(@($specsItem, $uptimeItem, $ramDetailItem, $battReportItem, $driverInfoItem, $dxDiagItem))

$drvMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Drivers (Backup/Install)")
$installDrvItem = New-Object System.Windows.Forms.ToolStripMenuItem("Install Drivers (From Folder)"); $installDrvItem.Add_Click({ $p = Select-Folder; if($p){ Update-Status "Installing Drivers..."; Run-Command "pnputil" "/add-driver `"$p\*.inf`" /subdirs /install" } })
$exportDrvItem = New-Object System.Windows.Forms.ToolStripMenuItem("Export Drivers (Backup)"); $exportDrvItem.Add_Click({ $p = Select-Folder; if($p){ Update-Status "Exporting Drivers..."; Export-WindowsDriver -Online -Destination $p -ErrorAction SilentlyContinue } })
[void]$drvMenu.DropDownItems.AddRange(@($installDrvItem, $exportDrvItem))

# NEW: WINDOWS POLICY & SECURITY
$polMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Windows Policy & Security")
$gpEdit = New-Object System.Windows.Forms.ToolStripMenuItem("Group Policy Editor (gpedit)"); $gpEdit.Add_Click({ Start-Process "gpedit.msc" })
$secPol = New-Object System.Windows.Forms.ToolStripMenuItem("Local Security Policy (secpol)"); $secPol.Add_Click({ Start-Process "secpol.msc" })
$azMan = New-Object System.Windows.Forms.ToolStripMenuItem("Authorization Manager (azman)"); $azMan.Add_Click({ Start-Process "azman.msc" })
$certMgr = New-Object System.Windows.Forms.ToolStripMenuItem("Certificate Manager (certmgr)"); $certMgr.Add_Click({ Start-Process "certmgr.msc" })
$rsopItem = New-Object System.Windows.Forms.ToolStripMenuItem("Resultant Set of Policy (RSoP)"); $rsopItem.Add_Click({ Start-Process "rsop.msc" })
$gpUpdateItem = New-Object System.Windows.Forms.ToolStripMenuItem("Force Group Policy Update"); $gpUpdateItem.Add_Click({ Update-Status "Updating Group Policy..."; Run-Command "gpupdate" "/force" })
[void]$polMenu.DropDownItems.AddRange(@($gpEdit, $secPol, $azMan, $certMgr, $rsopItem, $gpUpdateItem))

# NEW: ADVANCED ADMIN TOOLS
$admToolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Advanced Admin Tools")
$compSvcs = New-Object System.Windows.Forms.ToolStripMenuItem("Component Services (dcomcnfg)"); $compSvcs.Add_Click({ Start-Process "dcomcnfg" })
$shareFolder = New-Object System.Windows.Forms.ToolStripMenuItem("Shared Folders (fsmgmt)"); $shareFolder.Add_Click({ Start-Process "fsmgmt.msc" })
$admFolder = New-Object System.Windows.Forms.ToolStripMenuItem("Open Admin Tools Folder"); $admFolder.Add_Click({ Start-Process "control" "admintools" })
[void]$admToolsMenu.DropDownItems.AddRange(@($compSvcs, $shareFolder, $admFolder))

$troubleSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Troubleshooting Consoles")
$tTools = @{ 
    "Task Manager"="taskmgr"; 
    "Resource Monitor"="resmon"; 
    "Performance Monitor"="perfmon.msc";
    "Event Viewer"="eventvwr.msc";
    "Services"="services.msc";
    "Computer Management"="compmgmt.msc";
    "Disk Management"="diskmgmt.msc";
    "Device Manager"="devmgmt.msc";
    "System Configuration (msconfig)"="msconfig"; 
    "System Restore"="rstrui"; 
    "Advanced Firewall"="wf.msc";
    "Print Management"="printmanagement.msc"
}
foreach($n in $tTools.Keys){ $i=New-Object System.Windows.Forms.ToolStripMenuItem($n); $i.Tag=$tTools[$n]; $i.Add_Click({Start-Process $this.Tag}); [void]$troubleSubMenu.DropDownItems.Add($i) }
$relItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reliability Monitor"); $relItem.Add_Click({ Start-Process "perfmon" "/rel" }); [void]$troubleSubMenu.DropDownItems.Add($relItem)
$sep = New-Object System.Windows.Forms.ToolStripSeparator; [void]$troubleSubMenu.DropDownItems.Add($sep)
$tsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Task Scheduler"); $tsItem.Add_Click({ Start-Process "taskschd.msc" }); [void]$troubleSubMenu.DropDownItems.Add($tsItem)
$godModeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Create 'God Mode'"); $godModeItem.Add_Click({ $p = "$env:USERPROFILE\Desktop\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"; if(!(Test-Path $p)){ New-Item -Path $p -ItemType Directory -Force; Update-Status "God Mode Created." }})
$timeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Force Time Sync (Repair & Sync)"); 
$timeItem.Add_Click({ 
    Update-Status "Stopping Time Service..."
    Stop-Service w32time -Force
    Update-Status "Configuring Peers to time.windows.com..."
    Run-Command "w32tm" "/config /manualpeerlist:`"time.windows.com,0x9`" /syncfromflags:manual /update"
    Update-Status "Restarting Service..."
    Start-Service w32time
    Update-Status "Forcing Resync..."
    Run-Command "w32tm" "/resync"
})
[void]$troubleSubMenu.DropDownItems.AddRange(@($godModeItem, $timeItem))

$userSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("User Management")
$listUserItem = New-Object System.Windows.Forms.ToolStripMenuItem("List Users"); $listUserItem.Add_Click({ Run-Command "net" "user" })
$usrGroupsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Local Users and Groups (GUI)"); $usrGroupsItem.Add_Click({ Start-Process "lusrmgr.msc" })
$adminItem = New-Object System.Windows.Forms.ToolStripMenuItem("Enable Hidden Admin"); $adminItem.Add_Click({ Run-Command "net" "user administrator /active:yes" })
$unlockItem = New-Object System.Windows.Forms.ToolStripMenuItem("Unlock User"); $unlockItem.Add_Click({ $u=[Microsoft.VisualBasic.Interaction]::InputBox("Username to Unlock:"); if($u){ Run-Command "net" "user $u /active:yes" } })
$addUserItem = New-Object System.Windows.Forms.ToolStripMenuItem("Add User"); $addUserItem.Add_Click({ $u=[Microsoft.VisualBasic.Interaction]::InputBox("Username:"); $p=[Microsoft.VisualBasic.Interaction]::InputBox("Password:"); if($u){ Run-Command "net" "user $u $p /add" } })
$delUserItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete User"); $delUserItem.Add_Click({ $u=[Microsoft.VisualBasic.Interaction]::InputBox("Username to Delete:"); if($u){ Run-Command "net" "user $u /delete" } })
$addAdmItem = New-Object System.Windows.Forms.ToolStripMenuItem("Add User to Admins"); $addAdmItem.Add_Click({ $u=[Microsoft.VisualBasic.Interaction]::InputBox("Username:"); if($u){ Run-Command "net" "localgroup administrators $u /add" } })
$passItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Password"); $passItem.Add_Click({ $u=[Microsoft.VisualBasic.Interaction]::InputBox("Username:"); $p=[Microsoft.VisualBasic.Interaction]::InputBox("New Password:"); if($u){ Run-Command "net" "user $u $p" } })
[void]$userSubMenu.DropDownItems.AddRange(@($listUserItem, $usrGroupsItem, $adminItem, $unlockItem, $addUserItem, $delUserItem, $addAdmItem, $passItem))

$confSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Configuration")
$verboseItem = New-Object System.Windows.Forms.ToolStripMenuItem("Enable Verbose Boot"); $verboseItem.Add_Click({ New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value 1 -PropertyType DWord -Force })
$extItem = New-Object System.Windows.Forms.ToolStripMenuItem("Show File Extensions"); $extItem.Add_Click({ Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 })
$hibItem = New-Object System.Windows.Forms.ToolStripMenuItem("Disable Hibernation"); $hibItem.Add_Click({ Run-Command "powercfg" "-h off" })
$telemetryItem = New-Object System.Windows.Forms.ToolStripMenuItem("Disable Telemetry"); $telemetryItem.Add_Click({ $p = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"; if(!(Test-Path $p)){New-Item $p -Force}; New-ItemProperty $p -Name "AllowTelemetry" -Value 0 -PropertyType DWord -Force; Update-Status "Telemetry Disabled." })
[void]$confSubMenu.DropDownItems.AddRange(@($verboseItem, $extItem, $hibItem, $telemetryItem))

# NEW: CONTROL PANEL MENU
$cplSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Control Panel Tools")
$cplItems = @{ 
    "Add/Remove Programs"="appwiz.cpl"; 
    "Network Connections"="ncpa.cpl"; 
    "Power Options"="powercfg.cpl"; 
    "System Properties"="sysdm.cpl"; 
    "Date & Time"="timedate.cpl"; 
    "Sound Settings"="mmsys.cpl"; 
    "Internet Properties"="inetcpl.cpl"; 
    "Firewall (Basic)"="firewall.cpl"
}
foreach($n in $cplItems.Keys){ $i=New-Object System.Windows.Forms.ToolStripMenuItem($n); $i.Tag=$cplItems[$n]; $i.Add_Click({Start-Process $this.Tag}); [void]$cplSubMenu.DropDownItems.Add($i) }

[void]$sysMenu.DropDownItems.AddRange(@($hwSubMenu, $drvMenu, $cplSubMenu, $polMenu, $admToolsMenu, $troubleSubMenu, $userSubMenu, $confSubMenu))


# --- 4. Maintenance & Repair ---
$maintMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Maintenance")

$fileCleanMenu = New-Object System.Windows.Forms.ToolStripMenuItem("File Cleanup (Specific)")
$prefetchItem = New-Object System.Windows.Forms.ToolStripMenuItem("Clean Prefetch"); $prefetchItem.Add_Click({ Get-ChildItem -Path "$env:SystemRoot\Prefetch" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; Update-Status "Prefetch Cleaned." })
$tempItem = New-Object System.Windows.Forms.ToolStripMenuItem("Clean System Temp"); $tempItem.Add_Click({ Get-ChildItem -Path "$env:SystemRoot\Temp" -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; Update-Status "System Temp Cleaned." })
$userTempItem = New-Object System.Windows.Forms.ToolStripMenuItem("Clean User Temp"); $userTempItem.Add_Click({ Get-ChildItem -Path $env:TEMP -Force -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue; Update-Status "User Temp Cleaned." })
[void]$fileCleanMenu.DropDownItems.AddRange(@($prefetchItem, $tempItem, $userTempItem))

$diskSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Disk & Space")
$advCleanMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Advanced Disk Cleanup")
$sageSet = New-Object System.Windows.Forms.ToolStripMenuItem("Configure Options (SAGESET:1)"); $sageSet.Add_Click({ Start-Process "cleanmgr.exe" "/SAGESET:1" })
$sageRun = New-Object System.Windows.Forms.ToolStripMenuItem("Run Saved Config (SAGERUN:1)"); $sageRun.Add_Click({ Start-Process "cleanmgr.exe" "/SAGERUN:1" })
$lowDisk = New-Object System.Windows.Forms.ToolStripMenuItem("Low Disk Mode (Prompted)"); $lowDisk.Add_Click({ Start-Process "cleanmgr.exe" "/LOWDISK" })
$vLowDisk = New-Object System.Windows.Forms.ToolStripMenuItem("Very Low Disk (Silent)"); $vLowDisk.Add_Click({ Start-Process "cleanmgr.exe" "/VERYLOWDISK" })
$setupClean = New-Object System.Windows.Forms.ToolStripMenuItem("Clean Setup Files"); $setupClean.Add_Click({ Start-Process "cleanmgr.exe" "/SETUP" })
$autoClean = New-Object System.Windows.Forms.ToolStripMenuItem("Auto Clean (Silent)"); $autoClean.Add_Click({ Start-Process "cleanmgr.exe" "/AUTOCLEAN" })
[void]$advCleanMenu.DropDownItems.AddRange(@($sageSet, $sageRun, $lowDisk, $vLowDisk, $setupClean, $autoClean))

$compStoreItem = New-Object System.Windows.Forms.ToolStripMenuItem("Deep Clean WinSxS"); $compStoreItem.Add_Click({ Update-Status "Deep Cleaning WinSxS..."; Run-Command "dism" "/online /cleanup-image /startcomponentcleanup" })
$winOldItem = New-Object System.Windows.Forms.ToolStripMenuItem("Delete 'Windows.old'"); $winOldItem.Add_Click({ if([System.Windows.Forms.MessageBox]::Show("Delete Windows.old?", "Warning", [System.Windows.Forms.MessageBoxButtons]::YesNo)-eq'Yes'){ Update-Status "Deleting Windows.old..."; Remove-Item -Path "$env:SystemDrive\Windows.old" -Recurse -Force -ErrorAction SilentlyContinue; Update-Status "Done." } })
$smartItem = New-Object System.Windows.Forms.ToolStripMenuItem("Check SMART Health"); $smartItem.Add_Click({ Get-CimInstance -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus | Select InstanceName, PredictFailure | Format-Table | Out-String | Update-Status })
[void]$diskSubMenu.DropDownItems.AddRange(@($advCleanMenu, $compStoreItem, $winOldItem, $smartItem))

$repairSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("System Repairs")
$sfcItem = New-Object System.Windows.Forms.ToolStripMenuItem("SFC /scannow"); $sfcItem.Add_Click({ Run-Command "sfc" "/scannow" })
$dismItem = New-Object System.Windows.Forms.ToolStripMenuItem("DISM Restore Health"); $dismItem.Add_Click({ Run-Command "dism" "/online /cleanup-image /restorehealth" })
$chkdskItem = New-Object System.Windows.Forms.ToolStripMenuItem("Advanced Check Disk (Menu)"); $chkdskItem.Add_Click({ Show-ChkdskMenu })
$resetUpdateItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Windows Update (Full Repair)"); $resetUpdateItem.Add_Click({ Reset-WindowsUpdate })
[void]$repairSubMenu.DropDownItems.AddRange(@($sfcItem, $dismItem, $chkdskItem, $resetUpdateItem))

# NEW: PRINTER COMMANDER MENU
$printSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Printer Commander")
$printRunItem = New-Object System.Windows.Forms.ToolStripMenuItem("Open Printer Menu"); $printRunItem.Add_Click({ Show-PrinterMenu })
[void]$printSubMenu.DropDownItems.Add($printRunItem)

$fixSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Quick Fixes")
$iconItem = New-Object System.Windows.Forms.ToolStripMenuItem("Rebuild Icon Cache"); $iconItem.Add_Click({ Stop-Process -Name explorer -Force; Remove-Item "$env:LOCALAPPDATA\IconCache.db" -Force -ErrorAction SilentlyContinue; Start-Process explorer })
$wsResetItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Windows Store"); $wsResetItem.Add_Click({ Run-Command "wsreset.exe" "" })
[void]$fixSubMenu.DropDownItems.AddRange(@($iconItem, $wsResetItem))

[void]$maintMenu.DropDownItems.AddRange(@($fileCleanMenu, $diskSubMenu, $repairSubMenu, $printSubMenu, $fixSubMenu))


# --- 5. Network Ops ---
$netMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Network Ops")

# --- Map Drive Menu Item ---
$mapDriveItem = New-Object System.Windows.Forms.ToolStripMenuItem("Network Drive Mapper (GUI)")
$mapDriveItem.Add_Click({ Show-DriveMapper })
[void]$netMenu.DropDownItems.Add($mapDriveItem)
$sepNet = New-Object System.Windows.Forms.ToolStripSeparator
[void]$netMenu.DropDownItems.Add($sepNet)
# --------------------------------

$ipConfigMenu = New-Object System.Windows.Forms.ToolStripMenuItem("IP Configuration")
$ipAllItem = New-Object System.Windows.Forms.ToolStripMenuItem("IPConfig /all"); $ipAllItem.Add_Click({ Run-Command "ipconfig" "/all" })
$ipRelItem = New-Object System.Windows.Forms.ToolStripMenuItem("Release IP"); $ipRelItem.Add_Click({ Run-Command "ipconfig" "/release" })
$ipRenItem = New-Object System.Windows.Forms.ToolStripMenuItem("Renew IP"); $ipRenItem.Add_Click({ Run-Command "ipconfig" "/renew" })
$flushItem = New-Object System.Windows.Forms.ToolStripMenuItem("Flush DNS"); $flushItem.Add_Click({ Run-Command "ipconfig" "/flushdns" })
$statItem = New-Object System.Windows.Forms.ToolStripMenuItem("Netstat (Port Check)"); $statItem.Add_Click({ Run-Command "netstat" "-ano" })
$routeItem = New-Object System.Windows.Forms.ToolStripMenuItem("Print Route Table"); $routeItem.Add_Click({ Run-Command "route" "print" })
[void]$ipConfigMenu.DropDownItems.AddRange(@($ipAllItem, $ipRelItem, $ipRenItem, $flushItem, $statItem, $routeItem))

# =========================================================
# FIXED CONNECTIVITY TOOLS SECTION
# =========================================================
$toolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Connectivity Tools")

$pingItem = New-Object System.Windows.Forms.ToolStripMenuItem("Ping Continuous"); 
$pingItem.Add_Click({ $t=[Microsoft.VisualBasic.Interaction]::InputBox("Host:"); if($t){ Run-Command "ping" "-t $t" } })

# Typo fixed here (Removed extra quote)
$traceItem = New-Object System.Windows.Forms.ToolStripMenuItem("Tracert"); 
$traceItem.Add_Click({ $t=[Microsoft.VisualBasic.Interaction]::InputBox("Host:"); if($t){ Run-Command "tracert" $t } })

# Typo fixed here (Removed extra quote)
$nslookupItem = New-Object System.Windows.Forms.ToolStripMenuItem("NSLookup"); 
$nslookupItem.Add_Click({ $t=[Microsoft.VisualBasic.Interaction]::InputBox("Host:"); if($t){ Run-Command "nslookup" $t } })

$pubIpItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get Public IP"); 
$pubIpItem.Add_Click({ try { $ip = (Invoke-WebRequest -Uri "https://api.ipify.org").Content; Update-Status "Public IP: $ip" } catch { Update-Status "Failed." } })

$rdpItem = New-Object System.Windows.Forms.ToolStripMenuItem("Remote Desktop (MSTSC)"); 
$rdpItem.Add_Click({ Start-Process "mstsc" })

$hostsItem = New-Object System.Windows.Forms.ToolStripMenuItem("Edit Hosts File"); 
$hostsItem.Add_Click({ Start-Process "notepad.exe" "C:\Windows\System32\drivers\etc\hosts" -Verb RunAs })

$testNetItem = New-Object System.Windows.Forms.ToolStripMenuItem("Test-NetConnection (Port)"); 
$testNetItem.Add_Click({ $t=[Microsoft.VisualBasic.Interaction]::InputBox("Host:"); $p=[Microsoft.VisualBasic.Interaction]::InputBox("Port (e.g. 3389):"); if($t -and $p){ Run-Command "powershell" "Test-NetConnection -ComputerName $t -Port $p" } })

[void]$toolsMenu.DropDownItems.AddRange(@($pingItem, $traceItem, $nslookupItem, $pubIpItem, $rdpItem, $hostsItem, $testNetItem))
# =========================================================

# NEW: POWERSHELL EXTRAS MENU
$psExtraMenu = New-Object System.Windows.Forms.ToolStripMenuItem("PowerShell Extras")
$enableRemItem = New-Object System.Windows.Forms.ToolStripMenuItem("Enable PowerShell Remoting"); $enableRemItem.Add_Click({ Run-Command "powershell" "Enable-PSRemoting -Force" })
$checkRdpItem = New-Object System.Windows.Forms.ToolStripMenuItem("Check RDP Firewall Rules"); $checkRdpItem.Add_Click({ Run-Command "powershell" "Get-NetFirewallRule -DisplayGroup 'Remote Desktop' | Select Name, Enabled, Direction | Format-Table -AutoSize" })
[void]$psExtraMenu.DropDownItems.AddRange(@($enableRemItem, $checkRdpItem))

$netshMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Netsh & Reset")
$resetTcpItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset TCP/IP"); $resetTcpItem.Add_Click({ Run-Command "netsh" "int ip reset" })
$resetSockItem = New-Object System.Windows.Forms.ToolStripMenuItem("Reset Winsock"); $resetSockItem.Add_Click({ Run-Command "netsh" "winsock reset" })
$fwOffItem = New-Object System.Windows.Forms.ToolStripMenuItem("Turn Firewall OFF"); $fwOffItem.Add_Click({ Run-Command "netsh" "advfirewall set allprofiles state off" })
[void]$netshMenu.DropDownItems.AddRange(@($resetTcpItem, $resetSockItem, $fwOffItem))

[void]$netMenu.DropDownItems.AddRange(@($ipConfigMenu, $toolsMenu, $psExtraMenu, $netshMenu))


# --- 6. Security Suite ---
$secMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Security Suite")

$defMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Windows Defender")
$defQuick = New-Object System.Windows.Forms.ToolStripMenuItem("Quick Scan"); $defQuick.Add_Click({ Start-Process powershell -ArgumentList "Start-MpScan -ScanType QuickScan" })
$defOffline = New-Object System.Windows.Forms.ToolStripMenuItem("Offline Scan (Reboot)"); $defOffline.Add_Click({ if([System.Windows.Forms.MessageBox]::Show("PC will reboot to scan. Continue?", "Confirm", [System.Windows.Forms.MessageBoxButtons]::YesNo)-eq'Yes'){ Start-Process powershell -ArgumentList "Start-MpScan -ScanType OfflineScan" } })
$defUpdate = New-Object System.Windows.Forms.ToolStripMenuItem("Update Signatures"); $defUpdate.Add_Click({ Update-Status "Updating Defender..."; Update-MpSignature; Update-Status "Done." })
[void]$defMenu.DropDownItems.AddRange(@($defQuick, $defOffline, $defUpdate))

$tpMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Rescue Scanners (Winget)")
# UPDATED: Winget with --no-progress
$avApps = @{ 'Malwarebytes'='Malwarebytes.Malwarebytes'; 'AdwCleaner'='Malwarebytes.AdwCleaner'; 'HitmanPro'='Sophos.HitmanPro'; 'ESET Online'='ESET.OnlineScanner'; 'Kaspersky Tool'='Kaspersky.VirusRemovalTool' }
foreach ($name in $avApps.Keys) { $i = New-Object System.Windows.Forms.ToolStripMenuItem("Install/Run $name"); $i.Tag = $avApps[$name]; $i.Add_Click({ Run-Command "winget" "install $($this.Tag) -e --accept-source-agreements --accept-package-agreements --no-progress --disable-interactivity" }); [void]$tpMenu.DropDownItems.Add($i) }

$keySubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Keys & Encryption")
$keyItem = New-Object System.Windows.Forms.ToolStripMenuItem("Show Product Key"); $keyItem.Add_Click({ $k = (Get-CimInstance -Query 'select * from SoftwareLicensingService').OA3xOriginalProductKey; if($k){ [System.Windows.Forms.MessageBox]::Show("Product Key:`n$k", "Key Found", 'OK', 'Information') } else { Update-Status "No OEM Key found." }})
$actItem = New-Object System.Windows.Forms.ToolStripMenuItem("Check Activation Expiry"); $actItem.Add_Click({ Run-Command "cscript" "//nologo $env:SystemRoot\System32\slmgr.vbs /xpr" })
$bitStat = New-Object System.Windows.Forms.ToolStripMenuItem("BitLocker Status"); $bitStat.Add_Click({ Run-Command "manage-bde" "-status" })
$bitKey = New-Object System.Windows.Forms.ToolStripMenuItem("BitLocker Recovery Key"); $bitKey.Add_Click({ Run-Command "manage-bde" "-protectors -get C:" })
$wifiKeyItem = New-Object System.Windows.Forms.ToolStripMenuItem("Show Wi-Fi Password"); $wifiKeyItem.Add_Click({ $ssid = (netsh wlan show interfaces) -match '^\s+SSID' -replace '^\s+SSID\s+:\s+',''; if($ssid){ $out = netsh wlan show profile name="$ssid" key=clear; $pass = ($out -match 'Key Content') -replace '^\s+Key Content\s+:\s+',''; [System.Windows.Forms.MessageBox]::Show("SSID: $ssid`nPassword: $pass", "Wi-Fi Key", 'OK', 'Information') } })
[void]$keySubMenu.DropDownItems.AddRange(@($keyItem, $actItem, $bitStat, $bitKey, $wifiKeyItem))

[void]$secMenu.DropDownItems.AddRange(@($defMenu, $tpMenu, $keySubMenu))


# --- 7. Software Center ---
$softMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Software Center")

$instSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Install Essentials")
$apps = @{ 
    'Chrome'='Google.Chrome'; 'Firefox'='Mozilla.Firefox'; 'VLC'='VideoLAN.VLC'; '7-Zip'='7zip.7zip'; 
    'Adobe Reader'='Adobe.Acrobat.Reader.64-bit'; 'RustDesk'='RustDesk.RustDesk'; 'Adv IP Scanner'='Famatech.AdvancedIPScanner'; 
    'Zoom'='Zoom.Zoom'; 'PowerToys'='Microsoft.PowerToys'; 'VS Code'='Microsoft.VisualStudioCode';
    'Tailscale'='Tailscale.Tailscale'; 'WinSCP'='WinSCP.WinSCP'; 'PuTTY'='PuTTY.PuTTY'; 'Notepad++'='Notepad++.Notepad++'
}
# UPDATED: Winget with --no-progress
foreach ($name in $apps.Keys) { $i = New-Object System.Windows.Forms.ToolStripMenuItem($name); $i.Tag = $apps[$name]; $i.Add_Click({ Run-Command "winget" "install $($this.Tag) -e --accept-source-agreements --accept-package-agreements --no-progress --disable-interactivity" }); [void]$instSubMenu.DropDownItems.Add($i) }

$commSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Community Utilities")
$cttItem = New-Object System.Windows.Forms.ToolStripMenuItem("Chris Titus WinUtil"); $cttItem.Add_Click({ Start-Process powershell -ArgumentList "-Command `"irm 'https://christitus.com/win' | iex`"" })
$masItem = New-Object System.Windows.Forms.ToolStripMenuItem("MAS Activation"); $masItem.Add_Click({ Start-Process powershell -ArgumentList "-Command `"irm 'https://get.activated.win' | iex`"" })
$winFeat = New-Object System.Windows.Forms.ToolStripMenuItem("Turn Windows Features On/Off"); $winFeat.Add_Click({ Start-Process "optionalfeatures.exe" })
[void]$commSubMenu.DropDownItems.AddRange(@($cttItem, $masItem, $winFeat))

$wingetSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Winget Management")
$upAllItem = New-Object System.Windows.Forms.ToolStripMenuItem("Upgrade All Apps"); $upAllItem.Add_Click({ Run-Command "winget" "upgrade --all --accept-source-agreements --accept-package-agreements --no-progress" })
$wgListItem = New-Object System.Windows.Forms.ToolStripMenuItem("List Installed"); $wgListItem.Add_Click({ Run-Command "winget" "list" })
[void]$wingetSubMenu.DropDownItems.AddRange(@($upAllItem, $wgListItem))

# FULL SYSINTERNALS
$proSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Sysinternals Suite")
$sysTools = @{
    'Process Explorer'='procexp.exe'; 'AutoRuns'='autoruns.exe'; 'TCP View'='Tcpview.exe'; 
    'Process Monitor'='Procmon.exe'; 'RAMMap'='RAMMap.exe'; 'Disk2VHD'='disk2vhd.exe';
    'BgInfo'='Bginfo.exe'; 'ZoomIt'='ZoomIt.exe'; 'Desktops'='Desktops.exe';
    'DiskView'='DiskView.exe'; 'AccessEnum'='AccessEnum.exe'; 'AdExplorer'='AdExplorer.exe';
    'Autologon'='Autologon.exe'; 'DebugView'='Dbgview.exe'; 'Hex2Dec'='Hex2dec.exe';
    'Whois'='Whois.exe'; 'BlueScreenView'='BlueScreenView.zip'
}
foreach($t in $sysTools.Keys){ 
    $i=New-Object System.Windows.Forms.ToolStripMenuItem($t); $i.Tag=$sysTools[$t]; 
    if ($t -eq 'BlueScreenView') { $i.Add_Click({ Get-ToolDownload "BlueScreenView.zip" "https://www.nirsoft.net/utils/bluescreenview.zip" }) }
    else { $i.Add_Click({ Get-ToolDownload $this.Tag "https://live.sysinternals.com/$($this.Tag)" }) }
    [void]$proSubMenu.DropDownItems.Add($i) 
}
# Suite Downloader
$suiteItem = New-Object System.Windows.Forms.ToolStripMenuItem("Download Full Suite (ZIP)"); 
$suiteItem.Add_Click({ 
    $p="$env:USERPROFILE\Desktop\SysinternalsSuite.zip"; Update-Status "Downloading Suite..."
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $p
    Update-Status "Saved to Desktop." 
})
$sep = New-Object System.Windows.Forms.ToolStripSeparator
[void]$proSubMenu.DropDownItems.Add($sep)
[void]$proSubMenu.DropDownItems.Add($suiteItem)

[void]$softMenu.DropDownItems.AddRange(@($instSubMenu, $commSubMenu, $wingetSubMenu, $proSubMenu))


# --- 8. Data Rescue ---
$dataMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Data Rescue")

$imgSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Imaging & System Backups (Enhanced)")
$disk2vhdItem = New-Object System.Windows.Forms.ToolStripMenuItem("Live Image (Disk2vhd)"); $disk2vhdItem.Add_Click({ Get-ToolDownload "disk2vhd.exe" "https://live.sysinternals.com/disk2vhd.exe" })

# UPDATED: Specific Bare Metal wbadmin command
$wbBackupItem = New-Object System.Windows.Forms.ToolStripMenuItem("Native System Image (Bare Metal Recovery)")
$wbBackupItem.Add_Click({
     [System.Windows.Forms.MessageBox]::Show("This creates a standard Windows System Image containing C:, EFI, and Recovery partitions, useful for bare metal restoration.`n`nYou need an EXTERNAL USB drive connected as the target.", "Info")
    $target = Select-Folder -Description "Select EXTERNAL Target Drive Root (e.g. E:\)"
    if(!$target -or $target.Length -gt 3){ [System.Windows.Forms.MessageBox]::Show("Please select the ROOT of a drive (like E:\)."); return}
    $targetDrive = $target.Substring(0,2)
    if([System.Windows.Forms.MessageBox]::Show("Start backup to drive $targetDrive ?`nThis will take significant time.", "Confirm", 'YesNo') -eq 'Yes'){
        Update-Status "Starting Native System Image Backup..."
        Run-Command "wbadmin" "start backup -backupTarget:$targetDrive -allCritical -quiet"
    }
})

$dismFfuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Capture FFU Image (Sector Clone - DISM)"); $dismFfuItem.Add_Click({ $drv = [Microsoft.VisualBasic.Interaction]::InputBox("Physical Drive Path (e.g. \\.\PhysicalDrive0):"); if($drv){ $file = Select-Folder -desc "Select Save Location"; if($file){ $name = [Microsoft.VisualBasic.Interaction]::InputBox("Image Name (no extension):"); Run-Command "dism" "/capture-ffu /imagefile:`"$file\$name.ffu`" /capturedrive=$drv /name:`"$name`"" }}})

# NEW: WIM Capture
$captureWimItem = New-Object System.Windows.Forms.ToolStripMenuItem("Capture WIM Image (File-Based - DISM)")
$captureWimItem.Add_Click({
    $srcPath = Select-Folder -Description "Select Source Drive Root (e.g. C:\)"
    if($srcPath){
        $destFile = Select-File -Filter "Windows Image File (*.wim)|*.wim" -CheckFileExists $false
        if($destFile){
            $name = [Microsoft.VisualBasic.Interaction]::InputBox("Image Name:")
            if($name){
                 [System.Windows.Forms.MessageBox]::Show("Capturing WIM takes a long time. Check console for progress.", "Info")
                 Run-Command "dism" "/Capture-Image /ImageFile:`"$destFile`" /CaptureDir:`"$srcPath`" /Name:`"$name`" /Compress:fast /Verify"
            }
        }
    }
})

$sepImg = New-Object System.Windows.Forms.ToolStripSeparator
$clonezillaItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get Clonezilla (ISO Download)"); $clonezillaItem.Add_Click({ Start-Process "https://clonezilla.org/downloads.php" })
$rescuezillaItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get Rescuezilla (GUI Clonezilla Download)"); $rescuezillaItem.Add_Click({ Start-Process "https://rescuezilla.com/download" })
$macriumItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get AOMEI Backupper (Download)"); $macriumItem.Add_Click({ Start-Process "https://www.ubackup.com/download.html" })

[void]$imgSubMenu.DropDownItems.AddRange(@($disk2vhdItem, $wbBackupItem, $dismFfuItem, $captureWimItem, $sepImg, $clonezillaItem, $rescuezillaItem, $macriumItem))

$profSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("User Profile Backup")
$smartBackupItem = New-Object System.Windows.Forms.ToolStripMenuItem("Smart Backup (Docs/Desktop/WiFi)"); $smartBackupItem.Add_Click({ Backup-UserProfileData })
$browserBackupItem = New-Object System.Windows.Forms.ToolStripMenuItem("Backup Browser Profiles (Raw Data)"); 
$browserBackupItem.Add_Click({ 
    $dest = Select-Folder -desc "Select Destination for Browser Data"; if(!$dest){return}
    Update-Status "Backing up Chrome/Edge/Firefox Profiles..."
    $browsers = @{
        "Chrome"="$env:LOCALAPPDATA\Google\Chrome\User Data"; 
        "Edge"="$env:LOCALAPPDATA\Microsoft\Edge\User Data"; 
        "Firefox"="$env:APPDATA\Mozilla\Firefox\Profiles"
    }
    foreach($b in $browsers.Keys){
        if(Test-Path $browsers[$b]){ 
            Run-Command "robocopy" "`"$($browsers[$b])`" `"$dest\$b`" /E /XB *Cache* /R:1 /W:1 /NFL /NDL" 
        }
    }
    [Windows.Forms.MessageBox]::Show("Browser data saved to $dest")
})
$transwizItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get Transwiz (Domain Migration)"); $transwizItem.Add_Click({ Start-Process "https://www.forensit.com/downloads.html" })
[void]$profSubMenu.DropDownItems.AddRange(@($smartBackupItem, $browserBackupItem, $transwizItem))

$sysStateMenu = New-Object System.Windows.Forms.ToolStripMenuItem("System State")
$regBackupItem = New-Object System.Windows.Forms.ToolStripMenuItem("Backup Registry Hives"); 
$regBackupItem.Add_Click({
    $dest = Select-Folder -desc "Select Destination for Registry Files"; if(!$dest){return}
    Update-Status "Exporting Registry Hives..."
    Run-Command "reg" "export HKLM\SYSTEM `"$dest\System.reg`" /y"
    Run-Command "reg" "export HKLM\SOFTWARE `"$dest\Software.reg`" /y"
    Run-Command "reg" "export HKCU `"$dest\CurrentUser.reg`" /y"
    [Windows.Forms.MessageBox]::Show("Registry exported to $dest")
})
$createRpItem = New-Object System.Windows.Forms.ToolStripMenuItem("Create System Restore Point"); 
$createRpItem.Add_Click({ 
    Update-Status "Creating Restore Point..."
    try { Checkpoint-Computer -Description "REGTeches_Manual_Point" -RestorePointType "MODIFY_SETTINGS"; [Windows.Forms.MessageBox]::Show("Restore Point Created.") } 
    catch { [Windows.Forms.MessageBox]::Show("Failed. Ensure System Protection is ON.") }
})
[void]$sysStateMenu.DropDownItems.AddRange(@($regBackupItem, $createRpItem))

$recToolsMenu = New-Object System.Windows.Forms.ToolStripMenuItem("File Recovery Tools (Download)")
$recuvaItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get Recuva (Portable)"); $recuvaItem.Add_Click({ Start-Process "https://www.ccleaner.com/recuva/builds" })
$testDiskItem = New-Object System.Windows.Forms.ToolStripMenuItem("Get TestDisk/PhotoRec"); $testDiskItem.Add_Click({ Start-Process "https://www.cgsecurity.org/wiki/TestDisk_Download" })
[void]$recToolsMenu.DropDownItems.AddRange(@($recuvaItem, $testDiskItem))

$bootMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Advanced Boot")
$rebootWinRE = New-Object System.Windows.Forms.ToolStripMenuItem("Reboot to Recovery (WinRE)"); $rebootWinRE.Add_Click({ if([Windows.Forms.MessageBox]::Show("Reboot into Advanced Repair Mode?","Confirm","YesNo")-eq'Yes'){ Run-Command "reagentc" "/boottore"; Restart-Computer -Force } })
[void]$bootMenu.DropDownItems.Add($rebootWinRE)

$robocopyItem = New-Object System.Windows.Forms.ToolStripMenuItem("Full Drive Mirror (Robocopy)"); $robocopyItem.Add_Click({ $src=Select-Folder -desc "Source Drive Root"; if($src){ $dst=Select-Folder -desc "Destination Drive Root"; if($dst){ Run-Command "robocopy" "`"$src`" `"$dst`" /MIR /R:2 /W:2" }}})

[void]$dataMenu.DropDownItems.AddRange(@($imgSubMenu, $profSubMenu, $sysStateMenu, $recToolsMenu, $bootMenu, $robocopyItem))


# --- 9. ♻ RESTORE & RECOVERY (NEW v23) ---
$restoreMenu = New-Object System.Windows.Forms.ToolStripMenuItem("♻ Restore && Recovery")

$imgRestoreMenu = New-Object System.Windows.Forms.ToolStripMenuItem("System Image Restoration")
$launchSdclt = New-Object System.Windows.Forms.ToolStripMenuItem("Launch Windows Backup Restore"); $launchSdclt.Add_Click({ Start-Process "sdclt.exe" })
$applyWimItem = New-Object System.Windows.Forms.ToolStripMenuItem("Apply WIM Image (Secondary Drive)"); 
$applyWimItem.Add_Click({
    [Windows.Forms.MessageBox]::Show("WARNING: This overwrites files. Use only on secondary/mounted drives, NOT C:\ while running Windows.", "Warning")
    $wimFile = Select-File "WIM Images|*.wim"
    if($wimFile){
        $targetDir = Select-Folder "Target Drive Root (e.g. E:\)"
        if($targetDir){
            if([Windows.Forms.MessageBox]::Show("Apply image to $targetDir ? This is destructive.", "Confirm", 'YesNo') -eq 'Yes'){
                Run-Command "dism" "/Apply-Image /ImageFile:`"$wimFile`" /ApplyDir:`"$targetDir`" /Index:1" 
            }
        }
    }
})
# FFU Apply Command - informational primarily as it works best in WinPE
$applyFfuItem = New-Object System.Windows.Forms.ToolStripMenuItem("Apply FFU Image (Physical Disk - DANGEROUS)"); 
$applyFfuItem.Add_Click({
    $ffuFile = Select-File "FFU Images|*.ffu"
    if($ffuFile){
        $disk = [Microsoft.VisualBasic.Interaction]::InputBox("Target Physical Drive Path (e.g. \\.\PhysicalDrive1):`n`nWARNING: DATA WILL BE WIPED.")
        if($disk -and [Windows.Forms.MessageBox]::Show("WIPE $disk and apply image?", "CRITICAL WARNING", 'YesNo') -eq 'Yes'){
             Run-Command "dism" "/apply-ffu /ImageFile:`"$ffuFile`" /ApplyDrive:$disk"
        }
    }
})
[void]$imgRestoreMenu.DropDownItems.AddRange(@($launchSdclt, $applyWimItem, $applyFfuItem))

$profRestoreMenu = New-Object System.Windows.Forms.ToolStripMenuItem("User Data Restore")
$wifiRestoreItem = New-Object System.Windows.Forms.ToolStripMenuItem("Restore WiFi Profiles (From Folder)"); 
$wifiRestoreItem.Add_Click({
    $src = Select-Folder "Select Folder containing XML profiles"
    if($src){
        $files = Get-ChildItem -Path $src -Filter "*.xml"
        foreach($xml in $files){
            Update-Status "Importing WiFi: $($xml.Name)..."
            Run-Command "netsh" "wlan add profile filename=`"$($xml.FullName)`" user=all"
        }
        [Windows.Forms.MessageBox]::Show("WiFi Import Complete.")
    }
})
$browserRestoreItem = New-Object System.Windows.Forms.ToolStripMenuItem("Restore Browser Profiles"); 
$browserRestoreItem.Add_Click({
    [Windows.Forms.MessageBox]::Show("CLOSE ALL BROWSERS before continuing!", "Warning")
    $src = Select-Folder "Select Backup Source Folder"
    if($src){
        $browsers = @{ "Chrome"="$env:LOCALAPPDATA\Google\Chrome\User Data"; "Edge"="$env:LOCALAPPDATA\Microsoft\Edge\User Data"; "Firefox"="$env:APPDATA\Mozilla\Firefox\Profiles" }
        foreach($b in $browsers.Keys){
            $bSrc = Join-Path $src $b
            if(Test-Path $bSrc){
                Update-Status "Restoring $b..."
                Run-Command "robocopy" "`"$bSrc`" `"$($browsers[$b])`" /E /XO /R:1 /W:1 /NFL /NDL"
            }
        }
        [Windows.Forms.MessageBox]::Show("Restore Complete.")
    }
})
$regImportItem = New-Object System.Windows.Forms.ToolStripMenuItem("Import Registry Hive (.reg)"); 
$regImportItem.Add_Click({
    $regFile = Select-File "Registry Files|*.reg"
    if($regFile){
        Update-Status "Importing Registry..."
        Run-Command "reg" "import `"$regFile`""
        [Windows.Forms.MessageBox]::Show("Registry Imported.")
    }
})
[void]$profRestoreMenu.DropDownItems.AddRange(@($wifiRestoreItem, $browserRestoreItem, $regImportItem))

$drvRestoreMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Driver Restore")
$drvRestItem = New-Object System.Windows.Forms.ToolStripMenuItem("Bulk Install Drivers (From Folder)"); 
$drvRestItem.Add_Click({ $p = Select-Folder; if($p){ Update-Status "Installing Drivers..."; Run-Command "pnputil" "/add-driver `"$p\*.inf`" /subdirs /install" } })
[void]$drvRestoreMenu.DropDownItems.Add($drvRestItem)

[void]$restoreMenu.DropDownItems.AddRange(@($imgRestoreMenu, $profRestoreMenu, $drvRestoreMenu))


# --- 10. Help ---
$helpMenu = New-Object System.Windows.Forms.ToolStripMenuItem("&Help")

# --- AI HELPER ITEM ---
$aiItem = New-Object System.Windows.Forms.ToolStripMenuItem("🤖 AI Troubleshooter (Ask Me)"); 
$aiItem.Add_Click({ Show-AITroubleshooter })
[void]$helpMenu.DropDownItems.Add($aiItem)
# ----------------------

$webSubMenu = New-Object System.Windows.Forms.ToolStripMenuItem("Useful Websites")
$urls = @{ 
    'Ankh Tech'='https://ankhtech.weebly.com/'; 
    'MAS Activation'='https://massgrave.dev/genuine-installation-media';
    'Windows Insider ISO'='https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewiso';
    'MS Software Download'='https://msdl.gravesoft.dev/';
    'Chris Titus WinUtil'='https://github.com/ChrisTitusTech/winutil';
    'Get Into PC'='https://getintopc.com/';
    'Autounattend Gen'='https://schneegans.de/windows/unattend-generator/';
    'Sordum Tools'='https://www.sordum.org/';
    'Win Config Designer'='https://github.com/letsdoautomation/windows-configuration-designer';
    'Snappy Driver'='https://sdi-tool.org/download/'; 
    'NirSoft'='https://www.nirsoft.net/' 
}
foreach ($k in $urls.Keys) { $i=New-Object System.Windows.Forms.ToolStripMenuItem($k); $i.Tag=$urls[$k]; $i.Add_Click({Start-Process $this.Tag}); [void]$webSubMenu.DropDownItems.Add($i) }

# --- PROFESSIONAL ABOUT DIALOG (600x400 Design - FIXED LINK) ---
$aboutItem = New-Object System.Windows.Forms.ToolStripMenuItem("About"); 
$aboutItem.Add_Click({ 
    $abForm = New-Object System.Windows.Forms.Form
    $abForm.Text = "About"
    $abForm.Size = New-Object System.Drawing.Size(600, 420)
    $abForm.StartPosition = "CenterScreen"
    $abForm.BackColor = "#1e1e1e"
    $abForm.ForeColor = "White"
    $abForm.FormBorderStyle = "FixedDialog"
    $abForm.MaximizeBox = $false
    $abForm.MinimizeBox = $false

    # Title Label
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Technician's Toolkit"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 22, [System.Drawing.FontStyle]::Bold)
    $lblTitle.Location = New-Object System.Drawing.Point(30, 20)
    $lblTitle.AutoSize = $true
    $lblTitle.ForeColor = "Cyan"
    $abForm.Controls.Add($lblTitle)

    # Version Label (Moved Down)
    $lblVer = New-Object System.Windows.Forms.Label
    $lblVer.Text = "Version 24.02 Pro"
    $lblVer.Font = New-Object System.Drawing.Font("Segoe UI", 12)
    $lblVer.Location = New-Object System.Drawing.Point(35, 75)
    $lblVer.AutoSize = $true
    $lblVer.ForeColor = "LightGray"
    $abForm.Controls.Add($lblVer)

    # Horizontal Divider Line
    $line = New-Object System.Windows.Forms.Panel
    $line.Location = New-Object System.Drawing.Point(30, 110)
    $line.Size = New-Object System.Drawing.Size(520, 1)
    $line.BackColor = "Gray"
    $abForm.Controls.Add($line)

    # Details Labels (Static Text)
    $lblDetails = New-Object System.Windows.Forms.Label
    $lblDetails.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblDetails.Location = New-Object System.Drawing.Point(30, 130)
    $lblDetails.Text = "Developed by: Ronald Goodchild`nCompany: REGTeches"
    $lblDetails.AutoSize = $true
    $abForm.Controls.Add($lblDetails)

    # CLICKABLE Link Label
    $lnkWeb = New-Object System.Windows.Forms.LinkLabel
    $lnkWeb.Text = "www.regteches.com"
    $lnkWeb.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lnkWeb.Location = New-Object System.Drawing.Point(30, 180)
    $lnkWeb.AutoSize = $true
    $lnkWeb.LinkColor = "Cyan"
    $lnkWeb.ActiveLinkColor = "Yellow"
    $lnkWeb.LinkBehavior = "HoverUnderline"
    $lnkWeb.Add_Click({ Start-Process "http://www.regteches.com" })
    $abForm.Controls.Add($lnkWeb)

    # Copyright Label (Below Link)
    $lblCopy = New-Object System.Windows.Forms.Label
    $lblCopy.Text = "© 2026 REGTeches - All Rights Reserved"
    $lblCopy.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblCopy.Location = New-Object System.Drawing.Point(30, 210)
    $lblCopy.AutoSize = $true
    $lblCopy.ForeColor = "LightGray"
    $abForm.Controls.Add($lblCopy)

    # System Info Section (Bottom Left)
    $lblSys = New-Object System.Windows.Forms.Label
    $lblSys.Font = New-Object System.Drawing.Font("Consolas", 9)
    $lblSys.ForeColor = "DarkGray"
    $lblSys.Location = New-Object System.Drawing.Point(30, 280)
    $lblSys.Size = New-Object System.Drawing.Size(400, 60)
    $lblSys.Text = "Registered User: $env:USERNAME`nSystem: $([System.Environment]::OSVersion.VersionString)"
    $abForm.Controls.Add($lblSys)

    # OK Button
    $btnOk = New-Object System.Windows.Forms.Button
    $btnOk.Text = "Close"
    $btnOk.Location = New-Object System.Drawing.Point(450, 310)
    $btnOk.Size = New-Object System.Drawing.Size(100, 35)
    $btnOk.BackColor = "#333"
    $btnOk.ForeColor = "White"
    $btnOk.FlatStyle = "Flat"
    $btnOk.Add_Click({ $abForm.Close() })
    $abForm.Controls.Add($btnOk)

    $abForm.ShowDialog()
})
[void]$helpMenu.DropDownItems.AddRange(@($webSubMenu, $aboutItem))


# --- STRIP (WITH FONT FIX) ---
$menuStrip = New-Object System.Windows.Forms.MenuStrip
# FONT FIX: Set main menu font to 9pt (Standard Windows Default)
$menuStrip.Font = New-Object System.Drawing.Font("Segoe UI", 9)
[void]$menuStrip.Items.AddRange(@($fileMenu, $autoMenu, $sysMenu, $maintMenu, $netMenu, $secMenu, $softMenu, $dataMenu, $restoreMenu, $helpMenu))
$form.MainMenuStrip = $menuStrip
[void]$form.Controls.Add($menuStrip)

[void]$form.ShowDialog()