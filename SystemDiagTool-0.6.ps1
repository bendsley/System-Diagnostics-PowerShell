#Requires -Version 7.0
<#
.SYNOPSIS
    WBE Consulting LLC — System & Network Diagnostic Tool

.DESCRIPTION
    Menu-driven diagnostic tool covering system characteristics, hardware details,
    users, event log analysis, services & processes, and network diagnostics.
    All sections are always collected; display is optional. Everything is written
    to a timestamped log file if the user chooses to save.

.NOTES
    Author:     WBE Consulting LLC
    Written by: Brad Endsley
    Requires:   PowerShell 7.x or later
    Run as:     Administrator (required for event logs, traceroute, full service data)
#>

# ═══════════════════════════════════════════════════════════════
#  HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

function Write-Header {
    param([string]$Title)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line              -ForegroundColor Cyan
    Write-Host "  $Title"        -ForegroundColor Cyan
    Write-Host $line              -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---"  -ForegroundColor Yellow
}

function Write-Log {
    # Appends a line to the in-memory log buffer (always) and optionally prints to screen.
    param([string]$Line, [switch]$NoScreen)
    $script:LogBuffer.Add($Line)
    if (-not $NoScreen) { Write-Host $Line }
}

function Write-LogHeader {
    param([string]$Title, [switch]$NoScreen)
    $line = "=" * 60
    Write-Log ""           -NoScreen:$NoScreen
    Write-Log $line        -NoScreen:$NoScreen
    Write-Log "  $Title"   -NoScreen:$NoScreen
    Write-Log $line        -NoScreen:$NoScreen
}

function Write-LogSection {
    param([string]$Title, [switch]$NoScreen)
    Write-Log ""                   -NoScreen:$NoScreen
    Write-Log "--- $Title ---"     -NoScreen:$NoScreen
}

function Test-ValidIP {
    param([string]$IP)
    return ($IP -match '^\d{1,3}(\.\d{1,3}){3}$') -and (
        ($IP -split '\.') | ForEach-Object { [int]$_ -le 255 -and [int]$_ -ge 0 }
    ) -notcontains $false
}

function Test-ValidPort {
    param([string]$Port)
    if ([string]::IsNullOrWhiteSpace($Port)) { return $true }
    return ($Port -match '^\d+$') -and ([int]$Port -ge 1) -and ([int]$Port -le 65535)
}

function Test-ValidHostname {
    param([string]$Name)
    return $Name -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
}

function Test-ValidIPorHost {
    param([string]$Value)
    return (Test-ValidIP -IP $Value) -or (Test-ValidHostname -Name $Value)
}

function Resolve-ToIP {
    param([string]$Value)
    if (Test-ValidIP -IP $Value) { return $Value }
    try {
        return [System.Net.Dns]::GetHostAddresses($Value) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1 -ExpandProperty IPAddressToString
    } catch { return $null }
}

# ═══════════════════════════════════════════════════════════════
#  SECTION FUNCTIONS  (each writes to $script:LogBuffer always;
#  screen output controlled by -NoScreen switch)
# ═══════════════════════════════════════════════════════════════

# ── 1. System Characteristics ───────────────────────────────────
function Invoke-SystemCharacteristics {
    param([switch]$NoScreen)

    Write-LogHeader "1. System Characteristics" -NoScreen:$NoScreen

    Write-LogSection "Identity" -NoScreen:$NoScreen
    $cs  = Get-CimInstance Win32_ComputerSystem  -ErrorAction SilentlyContinue
    $os  = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $fqdn = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { 'N/A' }

    Write-Log "  Hostname         : $($env:COMPUTERNAME)"                                           -NoScreen:$NoScreen
    Write-Log "  FQDN             : $fqdn"                                                          -NoScreen:$NoScreen
    Write-Log "  Domain/Workgroup : $(if ($cs) { $cs.Domain } else { 'N/A' })"                     -NoScreen:$NoScreen
    Write-Log "  Current User     : $($env:USERDOMAIN)\$($env:USERNAME)"                            -NoScreen:$NoScreen
    Write-Log "  OS               : $(if ($os) { "$($os.Caption) (Build $($os.BuildNumber))" } else { 'N/A' })" -NoScreen:$NoScreen
    Write-Log "  OS Architecture  : $(if ($os) { $os.OSArchitecture } else { 'N/A' })"             -NoScreen:$NoScreen
    Write-Log "  PS Version       : $($PSVersionTable.PSVersion)"                                   -NoScreen:$NoScreen
    Write-Log "  Last Boot        : $(if ($os) { $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss') } else { 'N/A' })" -NoScreen:$NoScreen

    Write-LogSection "Network Adapters" -NoScreen:$NoScreen
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } | Sort-Object Name
    foreach ($nic in $adapters) {
        $nicIPs = Get-NetIPAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty IPAddress
        $nicDNS = Get-DnsClientServerAddress -InterfaceIndex $nic.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty ServerAddresses
        $gw     = Get-NetRoute -InterfaceIndex $nic.InterfaceIndex -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                  Select-Object -First 1 -ExpandProperty NextHop
        Write-Log "  Adapter          : $($nic.Name)  [$($nic.InterfaceDescription)]"              -NoScreen:$NoScreen
        Write-Log "  MAC Address      : $($nic.MacAddress)"                                         -NoScreen:$NoScreen
        Write-Log "  Link Speed       : $($nic.LinkSpeed)"                                          -NoScreen:$NoScreen
        Write-Log "  IPv4 Address(es) : $($nicIPs -join ', ')"                                      -NoScreen:$NoScreen
        Write-Log "  Default Gateway  : $(if ($gw) { $gw } else { 'N/A' })"                        -NoScreen:$NoScreen
        Write-Log "  DNS Servers      : $(if ($nicDNS) { $nicDNS -join ', ' } else { 'N/A' })"     -NoScreen:$NoScreen
        Write-Log ""                                                                                 -NoScreen:$NoScreen
    }
}

# ── 2. Hardware Details ─────────────────────────────────────────
function Invoke-HardwareDetails {
    param([switch]$NoScreen)

    Write-LogHeader "2. Hardware Details" -NoScreen:$NoScreen

    # CPU
    Write-LogSection "CPU" -NoScreen:$NoScreen
    $cpus = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
    foreach ($cpu in $cpus) {
        Write-Log "  Model            : $($cpu.Name.Trim())"                    -NoScreen:$NoScreen
        Write-Log "  Cores (Physical) : $($cpu.NumberOfCores)"                  -NoScreen:$NoScreen
        Write-Log "  Logical Procs    : $($cpu.NumberOfLogicalProcessors)"      -NoScreen:$NoScreen
        Write-Log "  Base Speed       : $($cpu.MaxClockSpeed) MHz"              -NoScreen:$NoScreen
        Write-Log "  Socket           : $($cpu.SocketDesignation)"              -NoScreen:$NoScreen
        Write-Log "  Manufacturer     : $($cpu.Manufacturer)"                   -NoScreen:$NoScreen
    }

    # Memory
    Write-LogSection "Memory" -NoScreen:$NoScreen
    $os      = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
    $freeGB  = [math]::Round($os.FreePhysicalMemory    / 1MB, 2)
    $usedGB  = [math]::Round($totalGB - $freeGB, 2)
    Write-Log "  Total RAM        : $totalGB GB"   -NoScreen:$NoScreen
    Write-Log "  Used RAM         : $usedGB GB"    -NoScreen:$NoScreen
    Write-Log "  Free RAM         : $freeGB GB"    -NoScreen:$NoScreen

    $dimms = Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue
    if ($dimms) {
        Write-Log "  DIMMs Installed  : $($dimms.Count)"  -NoScreen:$NoScreen
        foreach ($dimm in $dimms) {
            $dimmGB = [math]::Round($dimm.Capacity / 1GB, 0)
            Write-Log "    Slot $($dimm.DeviceLocator): $dimmGB GB  Speed: $($dimm.Speed) MHz  Mfr: $($dimm.Manufacturer.Trim())" -NoScreen:$NoScreen
        }
    }

    # Storage
    Write-LogSection "Storage — Physical Disks" -NoScreen:$NoScreen
    $disks = Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue | Sort-Object Index
    foreach ($disk in $disks) {
        $diskSizeGB = [math]::Round($disk.Size / 1GB, 1)
        Write-Log "  Disk $($disk.Index): $($disk.Model.Trim())  —  $diskSizeGB GB  ($($disk.MediaType))" -NoScreen:$NoScreen
    }

    Write-LogSection "Storage — Volumes" -NoScreen:$NoScreen
    $vols = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue |
            Where-Object { $_.Root -match '^[A-Z]:\\$' }
    foreach ($vol in $vols) {
        try {
            $usedBytes  = $vol.Used
            $freeBytes  = $vol.Free
            if ($null -ne $usedBytes -and $null -ne $freeBytes) {
                $totalBytes = $usedBytes + $freeBytes
                $usedPct    = if ($totalBytes -gt 0) { [math]::Round(($usedBytes / $totalBytes) * 100, 1) } else { 0 }
                $totalGBv   = [math]::Round($totalBytes / 1GB, 1)
                $freeGBv    = [math]::Round($freeBytes  / 1GB, 1)
                $usedGBv    = [math]::Round($usedBytes  / 1GB, 1)
                $flag       = if ($usedPct -ge 90) { "  [!] CRITICAL — disk nearly full" }
                              elseif ($usedPct -ge 75) { "  [~] WARNING — disk usage high" }
                              else { "" }
                Write-Log "  $($vol.Name): Total $totalGBv GB  |  Used $usedGBv GB ($usedPct%)  |  Free $freeGBv GB$flag" -NoScreen:$NoScreen
            }
        } catch { }
    }
    Write-LogSection "Storage — Drive Encryption" -NoScreen:$NoScreen
    try {
        # BitLocker — available via Get-BitLockerVolume on Windows 10/11/Server with RSAT or built-in
        $blVolumes = Get-BitLockerVolume -ErrorAction Stop
        if ($blVolumes) {
            foreach ($blv in $blVolumes) {
                $pct        = $blv.EncryptionPercentage
                $method     = if ($blv.EncryptionMethod) { $blv.EncryptionMethod } else { "N/A" }
                $protectors = ($blv.KeyProtector | ForEach-Object { $_.KeyProtectorType }) -join ", "
                switch ($blv.VolumeStatus) {
                    "FullyEncrypted"      { $statusLabel = "[+] Fully Encrypted" }
                    "FullyDecrypted"      { $statusLabel = "[-] Not Encrypted"   }
                    "EncryptionInProgress"{ $statusLabel = "[~] Encrypting ($pct%)" }
                    "DecryptionInProgress"{ $statusLabel = "[~] Decrypting ($pct%)" }
                    default               { $statusLabel = "[?] $($blv.VolumeStatus)" }
                }
                $lockStatus = if ($blv.LockStatus -eq "Locked") { "  [LOCKED]" } else { "" }
                Write-Log "  Drive $($blv.MountPoint)  BitLocker: $statusLabel$lockStatus" -NoScreen:$NoScreen
                Write-Log "    Encryption Method : $method"      -NoScreen:$NoScreen
                Write-Log "    Key Protectors    : $(if ($protectors) { $protectors } else { 'None' })" -NoScreen:$NoScreen
                Write-Log "" -NoScreen:$NoScreen
            }
        } else {
            Write-Log "  No BitLocker volumes found." -NoScreen:$NoScreen
        }
    } catch {
        # BitLocker cmdlet not available — try WMI fallback
        try {
            $wmiEnc = Get-CimInstance -Namespace "ROOT\CIMV2\Security\MicrosoftVolumeEncryption" `
                                      -ClassName Win32_EncryptableVolume -ErrorAction Stop
            foreach ($vol in $wmiEnc) {
                $statusMap = @{ 0="Fully Decrypted"; 1="Fully Encrypted"; 2="Encryption In Progress";
                                3="Decryption In Progress"; 4="Encryption Paused"; 5="Decryption Paused" }
                $statusLabel = $statusMap[[int]$vol.ProtectionStatus] ?? "Unknown ($($vol.ProtectionStatus))"
                Write-Log "  Drive $($vol.DriveLetter)  BitLocker: $statusLabel" -NoScreen:$NoScreen
            }
        } catch {
            Write-Log "  [!] BitLocker status unavailable (requires admin or BitLocker feature): $_" -NoScreen:$NoScreen
        }
    }

    # Check for third-party encryption via filesystem flags as a supplemental hint
    try {
        $encFolders = Get-ChildItem -Path "$env:SystemDrive\" -Depth 0 -ErrorAction SilentlyContinue |
                      Where-Object { $_.Attributes -band [System.IO.FileAttributes]::Encrypted }
        if ($encFolders) {
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  [~] EFS (Encrypting File System) encrypted items detected at root." -NoScreen:$NoScreen
        }
    } catch { }
}
function Invoke-Users {
    param([switch]$NoScreen)

    Write-LogHeader "3. Users" -NoScreen:$NoScreen

    # ── A. Active Directory ──────────────────────────────────────
    $adAvailable = $false
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $adAvailable = $true
    } catch { }

    if ($adAvailable) {
        Write-LogSection "Active Directory Users" -NoScreen:$NoScreen
        Write-Log "  (Source: Active Directory)" -NoScreen:$NoScreen
        Write-Log "" -NoScreen:$NoScreen
        try {
            $adUsers = Get-ADUser -Filter * -Properties DisplayName, SamAccountName, Enabled,
                                  LockedOut, LastLogonDate, PasswordExpired, PasswordLastSet,
                                  Department, Title, EmailAddress |
                       Sort-Object SamAccountName

            foreach ($u in $adUsers) {
                $marker    = if ($u.SamAccountName -eq $env:USERNAME) { "  ◄ CURRENT USER" } else { "" }
                $status    = if ($u.Enabled) { "Enabled" } else { "Disabled" }
                $locked    = if ($u.LockedOut) { "  [LOCKED]" } else { "" }
                $pwExp     = if ($u.PasswordExpired) { "  [PW EXPIRED]" } else { "" }
                $lastLogon = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
                $pwSet     = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }

                Write-Log "  [$status$locked$pwExp] $($u.SamAccountName)$marker" -NoScreen:$NoScreen
                if ($u.DisplayName)  { Write-Log "    Display Name  : $($u.DisplayName)"  -NoScreen:$NoScreen }
                if ($u.Title)        { Write-Log "    Title         : $($u.Title)"         -NoScreen:$NoScreen }
                if ($u.Department)   { Write-Log "    Department    : $($u.Department)"    -NoScreen:$NoScreen }
                if ($u.EmailAddress) { Write-Log "    Email         : $($u.EmailAddress)"  -NoScreen:$NoScreen }
                Write-Log "    Last Logon    : $lastLogon" -NoScreen:$NoScreen
                Write-Log "    PW Last Set   : $pwSet"     -NoScreen:$NoScreen
                Write-Log "" -NoScreen:$NoScreen
            }
            Write-Log "  Total AD users: $($adUsers.Count)" -NoScreen:$NoScreen
        } catch {
            Write-Log "  [!] Failed to query AD: $_" -NoScreen:$NoScreen
            $adAvailable = $false
        }
    }

    # ── B. Local Users (always shown regardless of AD) ───────────
    Write-LogSection "Local Users" -NoScreen:$NoScreen
    Write-Log "  (Source: Local machine)" -NoScreen:$NoScreen
    Write-Log "" -NoScreen:$NoScreen
    try {
        $localUsers = Get-LocalUser | Sort-Object Name
        foreach ($u in $localUsers) {
            $marker    = if ($u.Name -eq $env:USERNAME) { "  ◄ CURRENT USER" } else { "" }
            $status    = if ($u.Enabled) { "Enabled" } else { "Disabled" }
            $lastLogon = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
            $pwChange  = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }

            Write-Log "  [$status] $($u.Name)$marker"     -NoScreen:$NoScreen
            Write-Log "    Full Name     : $($u.FullName)" -NoScreen:$NoScreen
            Write-Log "    Last Logon    : $lastLogon"     -NoScreen:$NoScreen
            Write-Log "    PW Last Set   : $pwChange"      -NoScreen:$NoScreen
            Write-Log "    Description   : $($u.Description)" -NoScreen:$NoScreen
            Write-Log "" -NoScreen:$NoScreen
        }
        Write-Log "  Total local users: $($localUsers.Count)" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Failed to query local users: $_" -NoScreen:$NoScreen
    }
}

# ── 4. Event Log Analysis ───────────────────────────────────────
function Invoke-EventLogAnalysis {
    param([switch]$NoScreen)

    Write-LogHeader "4. Event Log Analysis" -NoScreen:$NoScreen

    $cutoff = (Get-Date).AddHours(-24)

    # Critical & Error events — System + Application
    Write-LogSection "Critical / Error Events (last 24 hours — System & Application)" -NoScreen:$NoScreen
    foreach ($logName in @('System', 'Application')) {
        Write-Log "" -NoScreen:$NoScreen
        Write-Log "  [ $logName Log ]" -NoScreen:$NoScreen
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                Level     = 1, 2        # 1 = Critical, 2 = Error
                StartTime = $cutoff
            } -ErrorAction Stop | Select-Object -First 50

            if ($events.Count -eq 0) {
                Write-Log "  No critical or error events found." -NoScreen:$NoScreen
            } else {
                foreach ($ev in $events) {
                    $lvl = if ($ev.Level -eq 1) { "CRITICAL" } else { "ERROR" }
                    Write-Log "  [$lvl] $($ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))  ID:$($ev.Id)  Source: $($ev.ProviderName)" -NoScreen:$NoScreen
                    $msg = ($ev.Message -split "`n")[0].Trim()
                    if ($msg.Length -gt 120) { $msg = $msg.Substring(0, 120) + "..." }
                    Write-Log "         $msg" -NoScreen:$NoScreen
                }
                Write-Log "" -NoScreen:$NoScreen
                Write-Log "  Showing up to 50 most recent. Total found: $($events.Count)" -NoScreen:$NoScreen
            }
        } catch {
            Write-Log "  [!] Could not read $logName log: $_" -NoScreen:$NoScreen
        }
    }

    # Failed logon attempts — Security log
    Write-LogSection "Failed Logon Attempts (last 24 hours — Security Log)" -NoScreen:$NoScreen
    try {
        $failedLogons = Get-WinEvent -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4625          # Failed logon event ID
            StartTime = $cutoff
        } -ErrorAction Stop | Select-Object -First 100

        if ($failedLogons.Count -eq 0) {
            Write-Log "  No failed logon attempts found." -NoScreen:$NoScreen
        } else {
            # Group by account name for a summary
            $grouped = $failedLogons | ForEach-Object {
                $xml  = [xml]$_.ToXml()
                $data = $xml.Event.EventData.Data
                [PSCustomObject]@{
                    Time        = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    AccountName = ($data | Where-Object { $_.Name -eq 'TargetUserName'  }).'#text'
                    WorkStation = ($data | Where-Object { $_.Name -eq 'WorkstationName' }).'#text'
                    SourceIP    = ($data | Where-Object { $_.Name -eq 'IpAddress'       }).'#text'
                    LogonType   = ($data | Where-Object { $_.Name -eq 'LogonType'       }).'#text'
                }
            }

            Write-Log "  Summary by account:" -NoScreen:$NoScreen
            $grouped | Group-Object AccountName | Sort-Object Count -Descending | ForEach-Object {
                Write-Log "    $($_.Count)x  $($_.Name)" -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Detail (most recent 25):" -NoScreen:$NoScreen
            $grouped | Select-Object -First 25 | ForEach-Object {
                Write-Log "  $($_.Time)  Account: $($_.AccountName)  From: $($_.SourceIP)  WS: $($_.WorkStation)  Type: $($_.LogonType)" -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total failed logons in period: $($failedLogons.Count)" -NoScreen:$NoScreen
        }
    } catch {
        if ($_ -match 'No events') {
            Write-Log "  No failed logon attempts found." -NoScreen:$NoScreen
        } else {
            Write-Log "  [!] Could not read Security log (requires Administrator): $_" -NoScreen:$NoScreen
        }
    }
}

# ── 5. Services & Processes ─────────────────────────────────────
function Invoke-ServicesAndProcesses {
    param([switch]$NoScreen)

    Write-LogHeader "5. Services & Processes" -NoScreen:$NoScreen

    # All running services
    Write-LogSection "Running Services" -NoScreen:$NoScreen
    try {
        $running = Get-Service -ErrorAction Stop |
                   Where-Object { $_.Status -eq 'Running' } |
                   Sort-Object DisplayName

        Write-Log "  Total running: $($running.Count)" -NoScreen:$NoScreen
        Write-Log "" -NoScreen:$NoScreen
        foreach ($svc in $running) {
            Write-Log "  [Running]  $($svc.DisplayName)  ($($svc.Name))" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Failed to enumerate services: $_" -NoScreen:$NoScreen
    }

    # Stopped services that have Automatic startup type
    Write-LogSection "Stopped Services with Automatic Startup (should be running)" -NoScreen:$NoScreen
    try {
        $stoppedAuto = Get-CimInstance Win32_Service -ErrorAction Stop |
                       Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } |
                       Sort-Object DisplayName

        if ($stoppedAuto.Count -eq 0) {
            Write-Log "  [+] No stopped auto-start services found." -NoScreen:$NoScreen
        } else {
            Write-Log "  [!] $($stoppedAuto.Count) auto-start service(s) are NOT running:" -NoScreen:$NoScreen
            Write-Log "" -NoScreen:$NoScreen
            foreach ($svc in $stoppedAuto) {
                Write-Log "  [!] $($svc.DisplayName)  ($($svc.Name))  State: $($svc.State)" -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [!] Failed to check auto-start services: $_" -NoScreen:$NoScreen
    }

    # Top CPU/memory consuming processes
    Write-LogSection "Top 20 Processes by CPU Time" -NoScreen:$NoScreen
    try {
        $topCPU = Get-Process -ErrorAction Stop |
                  Sort-Object CPU -Descending |
                  Select-Object -First 20

        Write-Log ("  {0,-30} {1,10} {2,12} {3,8}" -f "Name", "CPU (s)", "Mem (MB)", "PID") -NoScreen:$NoScreen
        Write-Log ("  {0,-30} {1,10} {2,12} {3,8}" -f ("-"*30), ("-"*10), ("-"*12), ("-"*8)) -NoScreen:$NoScreen
        foreach ($p in $topCPU) {
            $memMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
            $cpu   = if ($p.CPU) { [math]::Round($p.CPU, 1) } else { 0 }
            Write-Log ("  {0,-30} {1,10} {2,12} {3,8}" -f $p.Name, $cpu, $memMB, $p.Id) -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Failed to enumerate processes: $_" -NoScreen:$NoScreen
    }

    Write-LogSection "Top 20 Processes by Memory Usage" -NoScreen:$NoScreen
    try {
        $topMem = Get-Process -ErrorAction Stop |
                  Sort-Object WorkingSet64 -Descending |
                  Select-Object -First 20

        Write-Log ("  {0,-30} {1,12} {2,10} {3,8}" -f "Name", "Mem (MB)", "CPU (s)", "PID") -NoScreen:$NoScreen
        Write-Log ("  {0,-30} {1,12} {2,10} {3,8}" -f ("-"*30), ("-"*12), ("-"*10), ("-"*8)) -NoScreen:$NoScreen
        foreach ($p in $topMem) {
            $memMB = [math]::Round($p.WorkingSet64 / 1MB, 1)
            $cpu   = if ($p.CPU) { [math]::Round($p.CPU, 1) } else { 0 }
            Write-Log ("  {0,-30} {1,12} {2,10} {3,8}" -f $p.Name, $memMB, $cpu, $p.Id) -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Failed to enumerate processes: $_" -NoScreen:$NoScreen
    }
}

# ── 6. Network Diagnostics ──────────────────────────────────────
function Invoke-NetworkDiagnostics {
    param([switch]$NoScreen)

    Write-LogHeader "7. Network Diagnostics" -NoScreen:$NoScreen

    # ── Input ───────────────────────────────────────────────────
    if (-not $NoScreen) {

        # Source
        Write-Host ""
        Write-Host "  Detecting local addresses..." -ForegroundColor DarkGray
        $LocalHostname = $env:COMPUTERNAME
        $LocalIPs = @(
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object {
                $_.IPAddress -notmatch '^127\.' -and
                $_.IPAddress -notmatch '^169\.254\.' -and
                $_.PrefixOrigin -ne 'WellKnown'
            } | Select-Object -ExpandProperty IPAddress
        )

        $SourceMenuItems = @()
        if ($LocalHostname) { $SourceMenuItems += @{ Label = "$LocalHostname (this machine's hostname)"; Value = $LocalHostname } }
        foreach ($ip in $LocalIPs) { $SourceMenuItems += @{ Label = $ip; Value = $ip } }

        Write-Host ""
        Write-Host "  Local source options:" -ForegroundColor White
        for ($i = 0; $i -lt $SourceMenuItems.Count; $i++) {
            Write-Host "    [$($i+1)] $($SourceMenuItems[$i].Label)" -ForegroundColor Green
        }
        Write-Host "    [M] Enter manually" -ForegroundColor Yellow
        Write-Host ""
        $sc = Read-Host "  Select source (1-$($SourceMenuItems.Count) or M)"

        if ($sc -match '^[Mm]$') {
            do {
                $SourceInput = Read-Host "  Source IP or hostname"
                if (-not (Test-ValidIPorHost -Value $SourceInput)) { Write-Host "  [!] Invalid. Try again." -ForegroundColor Red }
            } while (-not (Test-ValidIPorHost -Value $SourceInput))
        } elseif ($sc -match '^\d+$' -and [int]$sc -ge 1 -and [int]$sc -le $SourceMenuItems.Count) {
            $SourceInput = $SourceMenuItems[[int]$sc - 1].Value
        } else {
            Write-Host "  [!] Invalid selection, falling back to manual." -ForegroundColor Yellow
            do {
                $SourceInput = Read-Host "  Source IP or hostname"
                if (-not (Test-ValidIPorHost -Value $SourceInput)) { Write-Host "  [!] Invalid. Try again." -ForegroundColor Red }
            } while (-not (Test-ValidIPorHost -Value $SourceInput))
        }

        $SourceIP = Resolve-ToIP -Value $SourceInput
        if ($null -eq $SourceIP) {
            Write-Host "  [!] Could not resolve '$SourceInput' — will use as-is." -ForegroundColor Yellow
            $SourceIP = $SourceInput
        }
        $SourceDisplay = if ($SourceInput -eq $SourceIP) { $SourceIP } else { "$SourceInput ($SourceIP)" }

        # Destination
        do {
            $DestInput = Read-Host "  Destination IP or FQDN"
            if (-not (Test-ValidIPorHost -Value $DestInput)) { Write-Host "  [!] Invalid. Try again." -ForegroundColor Red }
        } while (-not (Test-ValidIPorHost -Value $DestInput))

        $DestIP = Resolve-ToIP -Value $DestInput
        if ($null -eq $DestIP) {
            Write-Host "  [!] Could not resolve '$DestInput' — will use as-is." -ForegroundColor Yellow
            $DestIP = $DestInput
        }
        $DestDisplay  = if ($DestInput -eq $DestIP) { $DestIP } else { "$DestInput ($DestIP)" }
        $DestIsFQDN   = (-not (Test-ValidIP -IP $DestInput)) -and ($DestInput -match '\.')

        # Port
        do {
            $DestPort = Read-Host "  Destination port (Enter to skip)"
            if (-not (Test-ValidPort -Port $DestPort)) { Write-Host "  [!] Invalid port. Try again." -ForegroundColor Red }
        } while (-not (Test-ValidPort -Port $DestPort))
        $PortDisplay = if ([string]::IsNullOrWhiteSpace($DestPort)) { "Not specified" } else { $DestPort }

        # DNS Server
        Write-Host ""
        Write-Host "  Detecting local DNS servers..." -ForegroundColor DarkGray
        $LocalDNSServers = @(
            Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            Select-Object -ExpandProperty ServerAddresses |
            Where-Object { $_ -notmatch '^127\.' } |
            Select-Object -Unique
        )
        $DnsMenuItems = @()
        foreach ($dns in $LocalDNSServers) { $DnsMenuItems += @{ Label = "$dns (local)"; Value = $dns } }
        $DnsMenuItems += @{ Label = "8.8.8.8   — Google Primary";       Value = "8.8.8.8"  }
        $DnsMenuItems += @{ Label = "8.8.4.4   — Google Secondary";     Value = "8.8.4.4"  }
        $DnsMenuItems += @{ Label = "1.1.1.1   — Cloudflare Primary";   Value = "1.1.1.1"  }
        $DnsMenuItems += @{ Label = "1.0.0.1   — Cloudflare Secondary"; Value = "1.0.0.1"  }
        $DnsMenuItems += @{ Label = "9.9.9.9   — Quad9";                Value = "9.9.9.9"  }

        Write-Host ""
        Write-Host "  Select DNS server for NSLookup:" -ForegroundColor White
        for ($i = 0; $i -lt $DnsMenuItems.Count; $i++) {
            $c = if ($DnsMenuItems[$i].Label -match 'local') { "Green" } else { "Yellow" }
            Write-Host "    [$($i+1)] $($DnsMenuItems[$i].Label)" -ForegroundColor $c
        }
        Write-Host "    [M] Enter manually" -ForegroundColor Cyan
        Write-Host ""
        $dc = Read-Host "  Select DNS (1-$($DnsMenuItems.Count) or M)"

        if ($dc -match '^[Mm]$') {
            do {
                $DnsServer = Read-Host "  DNS server IP"
                if (-not (Test-ValidIP -IP $DnsServer)) { Write-Host "  [!] Invalid IP. Try again." -ForegroundColor Red }
            } while (-not (Test-ValidIP -IP $DnsServer))
            $DnsDisplay = "$DnsServer (manual)"
        } elseif ($dc -match '^\d+$' -and [int]$dc -ge 1 -and [int]$dc -le $DnsMenuItems.Count) {
            $DnsServer  = $DnsMenuItems[[int]$dc - 1].Value
            $DnsDisplay = $DnsMenuItems[[int]$dc - 1].Label
        } else {
            Write-Host "  [!] Invalid, defaulting to system DNS." -ForegroundColor Yellow
            $DnsServer  = $null
            $DnsDisplay = "System default"
        }

        # Store inputs into log buffer header
        $script:LogBuffer.Add("")
        $script:LogBuffer.Add("  Source      : $SourceDisplay")
        $script:LogBuffer.Add("  Destination : $DestDisplay")
        $script:LogBuffer.Add("  Port        : $PortDisplay")
        $script:LogBuffer.Add("  DNS Server  : $DnsDisplay")

        # ── Internet Connectivity ──────────────────────────────
        Write-LogSection "Internet Connectivity" -NoScreen:$NoScreen
        $targets = @(
            @{ Label = "Google DNS (8.8.8.8)";     Host = "8.8.8.8"    },
            @{ Label = "Cloudflare DNS (1.1.1.1)"; Host = "1.1.1.1"    },
            @{ Label = "Google (google.com)";       Host = "google.com" }
        )
        $passCount = 0
        foreach ($t in $targets) {
            try {
                $r = Test-Connection -ComputerName $t.Host -Count 1 -Quiet -ErrorAction Stop
                if ($r) { Write-Log "  [+] PASS  $($t.Label)" -NoScreen:$NoScreen; $passCount++ }
                else    { Write-Log "  [-] FAIL  $($t.Label)" -NoScreen:$NoScreen }
            } catch    { Write-Log "  [!] ERROR $($t.Label) — $_" -NoScreen:$NoScreen }
        }
        Write-Log "" -NoScreen:$NoScreen
        if    ($passCount -eq $targets.Count) { Write-Log "  [+] Internet: FULL ($passCount/$($targets.Count))"    -NoScreen:$NoScreen }
        elseif ($passCount -gt 0)             { Write-Log "  [~] Internet: PARTIAL ($passCount/$($targets.Count))" -NoScreen:$NoScreen }
        else                                  { Write-Log "  [x] Internet: NONE (0/$($targets.Count))"             -NoScreen:$NoScreen }

        Write-LogSection "DNS Resolution Test" -NoScreen:$NoScreen
        foreach ($dh in @("google.com","cloudflare.com")) {
            try {
                $ips = [System.Net.Dns]::GetHostAddresses($dh) | ForEach-Object { $_.IPAddressToString }
                Write-Log "  [+] $dh resolved to: $($ips -join ', ')" -NoScreen:$NoScreen
            } catch { Write-Log "  [-] $dh failed to resolve" -NoScreen:$NoScreen }
        }

        Write-LogSection "HTTP/HTTPS Reachability" -NoScreen:$NoScreen
        foreach ($uri in @("http://detectportal.firefox.com/success.txt","https://clients3.google.com/generate_204","https://www.cloudflare.com/cdn-cgi/trace")) {
            try {
                $resp = Invoke-WebRequest -Uri $uri -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                if ($resp.StatusCode -in 200,204) { Write-Log "  [+] PASS  $uri (HTTP $($resp.StatusCode))" -NoScreen:$NoScreen }
                else                              { Write-Log "  [-] WARN  $uri (HTTP $($resp.StatusCode))" -NoScreen:$NoScreen }
            } catch { Write-Log "  [-] FAIL  $uri — $_" -NoScreen:$NoScreen }
        }

        # ── NSLookup ───────────────────────────────────────────
        Write-LogSection "NSLookup — Source ($SourceDisplay)  DNS: $DnsDisplay" -NoScreen:$NoScreen
        $nsArgs = if ($DnsServer) { @($SourceInput, $DnsServer) } else { @($SourceInput) }
        try { nslookup @nsArgs 2>&1 | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen } }
        catch { Write-Log "  [!] NSLookup failed: $_" -NoScreen:$NoScreen }

        Write-LogSection "NSLookup — Destination ($DestDisplay)  DNS: $DnsDisplay" -NoScreen:$NoScreen
        $nsArgs = if ($DnsServer) { @($DestInput, $DnsServer) } else { @($DestInput) }
        try { nslookup @nsArgs 2>&1 | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen } }
        catch { Write-Log "  [!] NSLookup failed: $_" -NoScreen:$NoScreen }

        # ── Ping ───────────────────────────────────────────────
        Write-LogSection "Ping: $DestDisplay (4 packets)" -NoScreen:$NoScreen
        try { ping $DestIP -n 4 2>&1 | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen } }
        catch { Write-Log "  [!] Ping failed: $_" -NoScreen:$NoScreen }

        # ── TCP Port Test ──────────────────────────────────────
        if (-not [string]::IsNullOrWhiteSpace($DestPort)) {
            Write-LogSection "TCP Port Test: $DestDisplay : $DestPort" -NoScreen:$NoScreen
            try {
                $tcp  = New-Object System.Net.Sockets.TcpClient
                $ar   = $tcp.BeginConnect($DestIP, [int]$DestPort, $null, $null)
                $wait = $ar.AsyncWaitHandle.WaitOne(3000, $false)
                if ($wait -and $tcp.Connected) { Write-Log "  [+] Port $DestPort on $DestIP is OPEN / REACHABLE" -NoScreen:$NoScreen }
                else                           { Write-Log "  [-] Port $DestPort on $DestIP is CLOSED or FILTERED" -NoScreen:$NoScreen }
                $tcp.Close()
            } catch { Write-Log "  [!] Port test error: $_" -NoScreen:$NoScreen }
        }

        # ── SSL Certificate ────────────────────────────────────
        if ($DestIsFQDN) {
            $sslPort = if (-not [string]::IsNullOrWhiteSpace($DestPort)) { [int]$DestPort } else { 443 }
            Write-LogSection "SSL Certificate: $DestInput (port $sslPort)" -NoScreen:$NoScreen
            try {
                $tc  = New-Object System.Net.Sockets.TcpClient
                $ca  = $tc.BeginConnect($DestInput, $sslPort, $null, $null)
                $con = $ca.AsyncWaitHandle.WaitOne(5000, $false)
                if (-not $con -or -not $tc.Connected) {
                    Write-Log "  [!] Could not connect on port $sslPort — SSL check skipped." -NoScreen:$NoScreen
                    $tc.Close()
                } else {
                    $tc.EndConnect($ca)
                    $ss = New-Object System.Net.Security.SslStream(
                        $tc.GetStream(), $false, { param($s,$c,$ch,$e) $true })
                    $ss.AuthenticateAsClient($DestInput)
                    $cert = $ss.RemoteCertificate
                    if ($null -eq $cert) {
                        Write-Log "  [!] No certificate returned." -NoScreen:$NoScreen
                    } else {
                        $c2       = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert
                        $nb       = [datetime]::Parse($c2.GetEffectiveDateString())
                        $na       = [datetime]::Parse($c2.GetExpirationDateString())
                        $days     = ($na - (Get-Date)).Days
                        $sanExt   = $c2.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                        $sanText  = if ($sanExt) { $sanExt.Format($false) } else { "Not present" }
                        $expFlag  = if ($days -lt 0) { "  [!] EXPIRED" } elseif ($days -le 14) { "  [!] EXPIRES VERY SOON" } elseif ($days -le 30) { "  [~] Expiring within 30 days" } else { "  [+] Valid" }

                        Write-Log "  Subject          : $($c2.Subject)"                              -NoScreen:$NoScreen
                        Write-Log "  Issuer           : $($c2.Issuer)"                               -NoScreen:$NoScreen
                        Write-Log "  Serial Number    : $($c2.SerialNumber)"                         -NoScreen:$NoScreen
                        Write-Log "  Thumbprint       : $($c2.Thumbprint)"                           -NoScreen:$NoScreen
                        Write-Log "  Valid From       : $($nb.ToString('yyyy-MM-dd HH:mm:ss'))"      -NoScreen:$NoScreen
                        Write-Log "  Valid To         : $($na.ToString('yyyy-MM-dd HH:mm:ss'))$expFlag" -NoScreen:$NoScreen
                        Write-Log "  Days Until Expiry: $days"                                        -NoScreen:$NoScreen
                        Write-Log "  TLS Protocol     : $($ss.SslProtocol)"                          -NoScreen:$NoScreen
                        Write-Log "  Cipher Algorithm : $($ss.CipherAlgorithm)"                      -NoScreen:$NoScreen
                        Write-Log "  Key Exchange     : $($ss.KeyExchangeAlgorithm)"                 -NoScreen:$NoScreen
                        Write-Log "  Key Size (bits)  : $($c2.PublicKey.Key.KeySize)"                -NoScreen:$NoScreen
                        Write-Log "  Signature Alg    : $($c2.SignatureAlgorithm.FriendlyName)"      -NoScreen:$NoScreen
                        Write-Log "  SAN Entries      : $sanText"                                    -NoScreen:$NoScreen
                    }
                    $ss.Close(); $tc.Close()
                }
            } catch { Write-Log "  [!] SSL check failed: $_" -NoScreen:$NoScreen }
        }

        # ── Traceroute ─────────────────────────────────────────
        Write-LogSection "Traceroute: $DestDisplay" -NoScreen:$NoScreen
        Write-Log "  (This may take a moment...)" -NoScreen:$NoScreen
        try { tracert $DestIP 2>&1 | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen } }
        catch { Write-Log "  [!] Traceroute failed: $_" -NoScreen:$NoScreen }

    } else {
        Write-Log "  [Network Diagnostics requires interactive input — skipped in silent mode]" -NoScreen:$true
    }
}

# ── 6. Software ─────────────────────────────────────────────────
function Invoke-Software {
    param([switch]$NoScreen)

    Write-LogHeader "6. Software" -NoScreen:$NoScreen

    # ── A. System Software (Microsoft / Windows components) ──────
    Write-LogSection "System Software (Microsoft / Windows Components)" -NoScreen:$NoScreen
    try {
        # Pull from both 32-bit and 64-bit registry hives
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        $systemSoftware = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -and
                (
                    $_.Publisher -match 'Microsoft' -or
                    $_.DisplayName -match '^Microsoft' -or
                    $_.DisplayName -match '^Windows '  -or
                    $_.DisplayName -match 'Visual C\+\+' -or
                    $_.DisplayName -match '\.NET'
                )
            } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Sort-Object DisplayName |
            Select-Object -Unique

        if ($systemSoftware.Count -eq 0) {
            Write-Log "  No Microsoft/system software entries found." -NoScreen:$NoScreen
        } else {
            Write-Log ("  {0,-55} {1,-20} {2,-12}" -f "Name", "Version", "Install Date") -NoScreen:$NoScreen
            Write-Log ("  {0,-55} {1,-20} {2,-12}" -f ("-"*55), ("-"*20), ("-"*12))      -NoScreen:$NoScreen
            foreach ($sw in $systemSoftware) {
                $name    = if ($sw.DisplayName.Length -gt 54)  { $sw.DisplayName.Substring(0,51) + "..." } else { $sw.DisplayName }
                $ver     = if ($sw.DisplayVersion)  { $sw.DisplayVersion }  else { "N/A" }
                $instDate = if ($sw.InstallDate -and $sw.InstallDate -match '^\d{8}$') {
                                "$($sw.InstallDate.Substring(0,4))-$($sw.InstallDate.Substring(4,2))-$($sw.InstallDate.Substring(6,2))"
                            } else { "N/A" }
                Write-Log ("  {0,-55} {1,-20} {2,-12}" -f $name, $ver, $instDate) -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total system software entries: $($systemSoftware.Count)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Failed to enumerate system software: $_" -NoScreen:$NoScreen
    }

    # ── B. Third-Party Software ───────────────────────────────────
    Write-LogSection "Third-Party Software (All Non-Microsoft Applications)" -NoScreen:$NoScreen
    try {
        $regPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )

        # Collect all entries that have a display name
        $allEntries = Get-ItemProperty -Path $regPaths -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName }

        # Define what counts as a Microsoft/system entry to EXCLUDE
        $isMicrosoftEntry = {
            param($sw)
            $pub  = $sw.Publisher  ?? ""
            $name = $sw.DisplayName ?? ""
            (
                $pub  -match 'Microsoft'          -or
                $name -match '^Microsoft '        -or
                $name -match '^Windows '          -or
                $name -match '^Windows SDK'       -or
                $name -match 'Visual C\+\+'       -or
                $name -match '\.NET (Framework|Runtime|SDK|Desktop|Core)' -or
                $name -match '^Microsoft\.NET'    -or
                $name -match '^KB\d+'             -or   # standalone KB hotfix entries
                $sw.SystemComponent -eq 1               # hidden system components
            )
        }

        $thirdPartySoftware = $allEntries |
            Where-Object { -not (& $isMicrosoftEntry $_) } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
            Group-Object DisplayName |          # deduplicate by name
            ForEach-Object { $_.Group | Select-Object -First 1 } |
            Sort-Object DisplayName

        if ($thirdPartySoftware.Count -eq 0) {
            Write-Log "  No third-party software entries found." -NoScreen:$NoScreen
        } else {
            Write-Log ("  {0,-50} {1,-20} {2,-30} {3,-12}" -f "Name", "Version", "Publisher", "Install Date") -NoScreen:$NoScreen
            Write-Log ("  {0,-50} {1,-20} {2,-30} {3,-12}" -f ("-"*50), ("-"*20), ("-"*30), ("-"*12))         -NoScreen:$NoScreen
            foreach ($sw in $thirdPartySoftware) {
                $name     = if ($sw.DisplayName.Length -gt 49)  { $sw.DisplayName.Substring(0,46)  + "..." } else { $sw.DisplayName }
                $ver      = if ($sw.DisplayVersion)             { $sw.DisplayVersion }                       else { "N/A" }
                $pub      = $sw.Publisher ?? ""
                $pubTrunc = if ($pub.Length -gt 29) { $pub.Substring(0,26) + "..." } else { $pub }
                $instDate = if ($sw.InstallDate -and $sw.InstallDate -match '^\d{8}$') {
                                "$($sw.InstallDate.Substring(0,4))-$($sw.InstallDate.Substring(4,2))-$($sw.InstallDate.Substring(6,2))"
                            } elseif ($sw.InstallDate) { $sw.InstallDate }
                              else { "N/A" }
                Write-Log ("  {0,-50} {1,-20} {2,-30} {3,-12}" -f $name, $ver, $pubTrunc, $instDate) -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total third-party software entries: $($thirdPartySoftware.Count)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Failed to enumerate third-party software: $_" -NoScreen:$NoScreen
    }

    # ── C. KB / Windows Updates ───────────────────────────────────
    Write-LogSection "KB Updates (Windows & Security Updates)" -NoScreen:$NoScreen
    try {
        # Get-HotFix covers QFE patches, security updates, and cumulative updates
        $hotfixes = Get-HotFix -ErrorAction Stop |
                    Sort-Object InstalledOn -Descending

        if ($hotfixes.Count -eq 0) {
            Write-Log "  No KB updates found via Get-HotFix." -NoScreen:$NoScreen
        } else {
            # Most recent update date
            $latestPatch = $hotfixes | Where-Object { $_.InstalledOn } |
                           Select-Object -First 1
            if ($latestPatch) {
                Write-Log "  Last patched    : $($latestPatch.InstalledOn.ToString('yyyy-MM-dd'))  ($($latestPatch.HotFixID))" -NoScreen:$NoScreen
            }
            $daysSincePatch = if ($latestPatch.InstalledOn) {
                ([datetime]::Today - $latestPatch.InstalledOn.Date).Days
            } else { $null }

            if ($null -ne $daysSincePatch) {
                $patchFlag = if    ($daysSincePatch -gt 90) { "  [!] CRITICAL — over 90 days since last patch" }
                             elseif ($daysSincePatch -gt 30) { "  [~] WARNING  — over 30 days since last patch" }
                             else                            { "  [+] Patch currency OK" }
                Write-Log "  Days since last : $daysSincePatch$patchFlag" -NoScreen:$NoScreen
            }

            Write-Log "  Total KB entries: $($hotfixes.Count)" -NoScreen:$NoScreen
            Write-Log "" -NoScreen:$NoScreen
            Write-Log ("  {0,-15} {1,-12} {2,-20} {3}" -f "HotFix ID", "Type", "Installed On", "Description") -NoScreen:$NoScreen
            Write-Log ("  {0,-15} {1,-12} {2,-20} {3}" -f ("-"*15), ("-"*12), ("-"*20), ("-"*40))             -NoScreen:$NoScreen

            foreach ($kb in $hotfixes) {
                $instOn = if ($kb.InstalledOn) { $kb.InstalledOn.ToString('yyyy-MM-dd') } else { "N/A" }
                $desc   = if ($kb.Description.Length -gt 60) { $kb.Description.Substring(0,57) + "..." } else { $kb.Description }
                Write-Log ("  {0,-15} {1,-12} {2,-20} {3}" -f $kb.HotFixID, $kb.HotFixID.Substring(0, [math]::Min(2,$kb.HotFixID.Length)), $instOn, $desc) -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [!] Get-HotFix failed: $_" -NoScreen:$NoScreen
    }

    # Also check Windows Update history via COM object for richer detail
    Write-Log "" -NoScreen:$NoScreen
    Write-LogSection "Windows Update History (via COM — last 25 entries)" -NoScreen:$NoScreen
    try {
        $updateSession    = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher   = $updateSession.CreateUpdateSearcher()
        $totalHistoryCount = $updateSearcher.GetTotalHistoryCount()

        if ($totalHistoryCount -eq 0) {
            Write-Log "  No Windows Update history found." -NoScreen:$NoScreen
        } else {
            $history = $updateSearcher.QueryHistory(0, [math]::Min(25, $totalHistoryCount))
            Write-Log ("  {0,-12} {1,-20} {2,-15} {3}" -f "Result", "Date", "KB", "Title") -NoScreen:$NoScreen
            Write-Log ("  {0,-12} {1,-20} {2,-15} {3}" -f ("-"*12), ("-"*20), ("-"*15), ("-"*45)) -NoScreen:$NoScreen

            for ($i = 0; $i -lt $history.Count; $i++) {
                $h      = $history.Item($i)
                $result = switch ($h.ResultCode) {
                    1 { "In Progress" }; 2 { "Succeeded" }; 3 { "Succeeded+Reboot" }
                    4 { "Failed" };      5 { "Aborted" };   default { "Unknown" }
                }
                $date   = if ($h.Date) { $h.Date.ToString('yyyy-MM-dd HH:mm') } else { "N/A" }
                # Extract KB number from title if present
                $kb     = if ($h.Title -match 'KB(\d+)') { "KB$($Matches[1])" } else { "N/A" }
                $title  = if ($h.Title.Length -gt 60) { $h.Title.Substring(0,57) + "..." } else { $h.Title }
                $resultFlag = if ($result -eq "Failed" -or $result -eq "Aborted") { "  [!]" } else { "" }
                Write-Log ("  {0,-12} {1,-20} {2,-15} {3}{4}" -f $result, $date, $kb, $title, $resultFlag) -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total update history entries: $totalHistoryCount  (showing last 25)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Windows Update COM query failed (may require interactive session): $_" -NoScreen:$NoScreen
    }
}

# ═══════════════════════════════════════════════════════════════
#  BANNER
# ═══════════════════════════════════════════════════════════════

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║         WBE Consulting LLC                       ║" -ForegroundColor Cyan
Write-Host "  ║         System & Network Diagnostic Tool         ║" -ForegroundColor Cyan
Write-Host "  ║         Written by Brad Endsley                  ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "  [!] WARNING: Not running as Administrator." -ForegroundColor Red
    Write-Host "      Event logs, traceroute, and some services may be limited." -ForegroundColor Red
    Write-Host ""
}

# ═══════════════════════════════════════════════════════════════
#  MAIN MENU LOOP
# ═══════════════════════════════════════════════════════════════

$MenuItems = @(
    @{ Number = "1"; Label = "System Characteristics";   Fn = "Invoke-SystemCharacteristics"  },
    @{ Number = "2"; Label = "Hardware Details";          Fn = "Invoke-HardwareDetails"        },
    @{ Number = "3"; Label = "Users";                     Fn = "Invoke-Users"                  },
    @{ Number = "4"; Label = "Event Log Analysis";        Fn = "Invoke-EventLogAnalysis"       },
    @{ Number = "5"; Label = "Services & Processes";      Fn = "Invoke-ServicesAndProcesses"   },
    @{ Number = "6"; Label = "Software";                  Fn = "Invoke-Software"               },
    @{ Number = "7"; Label = "Network Diagnostics";       Fn = "Invoke-NetworkDiagnostics"     }
)

# Initialise the global log buffer once for the entire session
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()
$logTimestamp     = Get-Date -Format "yyyyMMdd-HHmmss"
$logHostname      = $env:COMPUTERNAME
$runTimestamp     = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

$script:LogBuffer.Add("WBE Consulting LLC — System & Network Diagnostic Tool")
$script:LogBuffer.Add("Written by Brad Endsley")
$script:LogBuffer.Add("Run at   : $runTimestamp")
$script:LogBuffer.Add("Hostname : $logHostname")
$script:LogBuffer.Add("User     : $($env:USERDOMAIN)\$($env:USERNAME)")
$script:LogBuffer.Add("")

$mainMenuActive = $true

while ($mainMenuActive) {

    Write-Host ""
    Write-Host "  Available diagnostics:" -ForegroundColor White
    Write-Host ""
    foreach ($item in $MenuItems) {
        Write-Host "    [$($item.Number)]  $($item.Label)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "    [A]  Run all sections"   -ForegroundColor Gray
    Write-Host "    [Q]  Quit"               -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Enter section numbers separated by commas, or A for all, or Q to quit." -ForegroundColor DarkGray
    Write-Host "  Example: 1,3,6  or  A" -ForegroundColor DarkGray
    Write-Host ""

    $selection = Read-Host "  Your selection"

    if ($selection -match '^[Qq]$') {
        Write-Host ""
        Write-Host "  Exiting." -ForegroundColor DarkGray
        $mainMenuActive = $false
        break
    }

    if ($selection -match '^[Aa]$') {
        $selectedNumbers = $MenuItems | ForEach-Object { $_.Number }
    } else {
        $selectedNumbers = $selection -split ',' |
                           ForEach-Object { $_.Trim() } |
                           Where-Object   { $_ -match '^\d+$' }
    }

    $selectedItems = $MenuItems | Where-Object { $_.Number -in $selectedNumbers }

    if ($selectedItems.Count -eq 0) {
        Write-Host "  [!] No valid selections. Please try again." -ForegroundColor Red
        continue
    }

    Write-Host ""
    Write-Host "  Selected sections:" -ForegroundColor White
    foreach ($item in $selectedItems) {
        Write-Host "    [+] $($item.Number). $($item.Label)" -ForegroundColor Green
    }
    Write-Host ""
    $confirm = Read-Host "  Proceed? (Y/N/M to return to menu)"
    if ($confirm -match '^[Mm]$') { continue }
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "  Cancelled." -ForegroundColor DarkGray
        continue
    }

    # ── Run selected sections ───────────────────────────────────
    Write-Host ""
    Write-Host "  Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray

    foreach ($item in $selectedItems) {
        Write-Host ""
        Write-Host "  Running: $($item.Number). $($item.Label)..." -ForegroundColor DarkGray
        & $item.Fn
    }

    # Run unselected sections silently into the log buffer
    $unselectedItems = $MenuItems | Where-Object { $_.Number -notin $selectedNumbers }
    foreach ($item in $unselectedItems) {
        if ($item.Fn -eq "Invoke-NetworkDiagnostics") { continue }
        & $item.Fn -NoScreen
    }

    # ── Section complete — offer menu or quit ───────────────────
    Write-Header "SECTIONS COMPLETE"
    Write-Host "  Ran             : $($selectedItems.Label -join ', ')" -ForegroundColor White
    Write-Host "  Finished        : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host ""

    $script:LogBuffer.Add("")
    $script:LogBuffer.Add("=" * 60)
    $script:LogBuffer.Add("  SECTIONS COMPLETE: $($selectedItems.Label -join ', ')")
    $script:LogBuffer.Add("  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    $script:LogBuffer.Add("=" * 60)

    Write-Host "    [M]  Return to main menu" -ForegroundColor Gray
    Write-Host "    [Q]  Quit"                -ForegroundColor Gray
    Write-Host ""
    $postRun = Read-Host "  What would you like to do?"

    if ($postRun -notmatch '^[Mm]$') {
        $mainMenuActive = $false
    }
}

# ═══════════════════════════════════════════════════════════════
#  SAVE LOG
# ═══════════════════════════════════════════════════════════════

$saveLog = Read-Host "  Save output to a log file? (Y/N)"
if ($saveLog -match '^[Yy]') {
    $logFileName = "$logHostname-wbediag-$logTimestamp.log"
    $logPath     = Join-Path -Path $PSScriptRoot -ChildPath $logFileName
    try {
        $script:LogBuffer | Set-Content -Path $logPath -Encoding UTF8
        Write-Host ""
        Write-Host "  [+] Log saved to:" -ForegroundColor Green
        Write-Host "      $logPath"      -ForegroundColor White
    } catch {
        Write-Host ""
        Write-Host "  [!] Failed to save log: $_" -ForegroundColor Red
    }
} else {
    Write-Host ""
    Write-Host "  Log not saved." -ForegroundColor DarkGray
}

Write-Host ""
