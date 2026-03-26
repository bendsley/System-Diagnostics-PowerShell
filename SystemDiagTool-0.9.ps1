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

# ── 8. Security ─────────────────────────────────────────────────
function Invoke-Security {
    param([switch]$NoScreen)

    Write-LogHeader "8. Security" -NoScreen:$NoScreen

    # Firewall
    Write-LogSection "Windows Firewall Status" -NoScreen:$NoScreen
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $status    = if ($p.Enabled) { "[+] ENABLED" } else { "[-] DISABLED  [!]" }
            $inbound   = $p.DefaultInboundAction
            $outbound  = $p.DefaultOutboundAction
            Write-Log "  $($p.Name.PadRight(10)) : $status  |  Inbound: $inbound  |  Outbound: $outbound" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not query firewall profiles: $_" -NoScreen:$NoScreen
    }

    Write-LogSection "Firewall — Inbound Rules (Enabled, Allow)" -NoScreen:$NoScreen
    try {
        $rules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
                 Sort-Object DisplayName | Select-Object -First 40
        Write-Log "  (Showing up to 40 enabled inbound allow rules)" -NoScreen:$NoScreen
        Write-Log "" -NoScreen:$NoScreen
        foreach ($r in $rules) {
            $ports = (Get-NetFirewallPortFilter -AssociatedNetFirewallRule $r -ErrorAction SilentlyContinue).LocalPort -join ","
            $ports = if ($ports) { "  Port: $ports" } else { "" }
            Write-Log "  $($r.DisplayName)$ports" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not enumerate firewall rules: $_" -NoScreen:$NoScreen
    }

    # Defender / AV
    Write-LogSection "Windows Defender / Antivirus Status" -NoScreen:$NoScreen
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defStatus  = if ($mp.AntivirusEnabled)       { "[+] Enabled"  } else { "[-] DISABLED  [!]" }
        $rtStatus   = if ($mp.RealTimeProtectionEnabled) { "[+] Enabled" } else { "[-] DISABLED  [!]" }
        $defAge     = ([datetime]::Today - $mp.AntivirusSignatureLastUpdated.Date).Days
        $defAgeFlag = if ($defAge -gt 7) { "  [!] STALE" } elseif ($defAge -gt 3) { "  [~] Check update" } else { "" }
        $lastScan   = if ($mp.QuickScanStartTime) { $mp.QuickScanStartTime.ToString('yyyy-MM-dd HH:mm') } else { "Never" }

        Write-Log "  Antivirus             : $defStatus"                                           -NoScreen:$NoScreen
        Write-Log "  Real-Time Protection  : $rtStatus"                                            -NoScreen:$NoScreen
        Write-Log "  Signature Version     : $($mp.AntivirusSignatureVersion)"                     -NoScreen:$NoScreen
        Write-Log "  Signatures Updated    : $($mp.AntivirusSignatureLastUpdated.ToString('yyyy-MM-dd'))  ($defAge days ago)$defAgeFlag" -NoScreen:$NoScreen
        Write-Log "  Last Quick Scan       : $lastScan"                                            -NoScreen:$NoScreen
        Write-Log "  AM Engine Version     : $($mp.AMEngineVersion)"                               -NoScreen:$NoScreen
        Write-Log "  AM Product Version    : $($mp.AMProductVersion)"                              -NoScreen:$NoScreen
        Write-Log "  Tamper Protection     : $(if ($mp.IsTamperProtected) { '[+] Enabled' } else { '[-] Disabled' })" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not query Defender status (may not be active AV): $_" -NoScreen:$NoScreen
    }

    # Open listening ports with process names
    Write-LogSection "Open Listening Ports (TCP/UDP)" -NoScreen:$NoScreen
    try {
        $tcpConns = Get-NetTCPConnection -State Listen -ErrorAction Stop |
                    Sort-Object LocalPort
        $udpConns = Get-NetUDPEndpoint -ErrorAction Stop |
                    Sort-Object LocalPort

        $procMap  = @{}
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_.Name }

        Write-Log ("  {0,-8} {1,-8} {1,-30} {2,-25}" -f "Proto", "Port", "Address", "Process") -NoScreen:$NoScreen
        Write-Log ("  {0,-8} {1,-8} {2,-30} {3,-25}" -f "-----", "----", "-------", "-------")  -NoScreen:$NoScreen

        foreach ($c in $tcpConns) {
            $proc = $procMap[$c.OwningProcess] ?? "PID:$($c.OwningProcess)"
            Write-Log ("  {0,-8} {1,-8} {2,-30} {3,-25}" -f "TCP", $c.LocalPort, $c.LocalAddress, $proc) -NoScreen:$NoScreen
        }
        foreach ($u in $udpConns) {
            $proc = $procMap[$u.OwningProcess] ?? "PID:$($u.OwningProcess)"
            Write-Log ("  {0,-8} {1,-8} {2,-30} {3,-25}" -f "UDP", $u.LocalPort, $u.LocalAddress, $proc) -NoScreen:$NoScreen
        }
        Write-Log "" -NoScreen:$NoScreen
        Write-Log "  TCP listening: $($tcpConns.Count)  |  UDP endpoints: $($udpConns.Count)" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not enumerate open ports: $_" -NoScreen:$NoScreen
    }
}

# ── 9. Group Policy & Time Sync ──────────────────────────────────
function Invoke-GroupPolicyAndTimeSync {
    param([switch]$NoScreen)

    Write-LogHeader "9. Group Policy & Time Sync" -NoScreen:$NoScreen

    # Group Policy
    Write-LogSection "Group Policy — Last Refresh" -NoScreen:$NoScreen
    try {
        $gpResult = gpresult /r /scope computer 2>&1
        $gpResult | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen }
    } catch {
        Write-Log "  [!] gpresult failed: $_" -NoScreen:$NoScreen
    }

    Write-LogSection "Applied GPOs" -NoScreen:$NoScreen
    try {
        $rsop = Get-GPResultantSetOfPolicy -ReportType Html -Path "$env:TEMP\rsop_temp.html" -ErrorAction Stop 2>&1
        # Parse from registry instead if RSAT not available
        $compGPOs = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" -ErrorAction SilentlyContinue)
        Write-Log "  (Use gpresult /h report.html for full HTML GPO report)" -NoScreen:$NoScreen
    } catch { }

    # Parse applied GPO names from registry
    try {
        $gpoKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" -ErrorAction SilentlyContinue
        if ($gpoKeys) {
            foreach ($key in $gpoKeys) {
                $gpoProps = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                if ($gpoProps.DisplayName) {
                    Write-Log "  GPO: $($gpoProps.DisplayName)" -NoScreen:$NoScreen
                }
            }
        } else {
            Write-Log "  No GPO history found in registry." -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not read GPO registry: $_" -NoScreen:$NoScreen
    }

    # Time Sync
    Write-LogSection "Time Synchronization" -NoScreen:$NoScreen
    try {
        $w32Status = w32tm /query /status 2>&1
        $w32Status | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen }
    } catch {
        Write-Log "  [!] w32tm query failed: $_" -NoScreen:$NoScreen
    }

    Write-LogSection "NTP Source" -NoScreen:$NoScreen
    try {
        $w32Source = w32tm /query /source 2>&1
        Write-Log "  NTP Source : $($w32Source -join ' ')" -NoScreen:$NoScreen

        $timePeers = w32tm /query /peers 2>&1
        $timePeers | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen }
    } catch {
        Write-Log "  [!] Could not query NTP peers: $_" -NoScreen:$NoScreen
    }

    # Clock skew check
    try {
        $localTime  = [datetime]::Now
        $utcTime    = [datetime]::UtcNow
        $tzInfo     = [TimeZoneInfo]::Local
        Write-Log "" -NoScreen:$NoScreen
        Write-Log "  Local Time   : $($localTime.ToString('yyyy-MM-dd HH:mm:ss'))" -NoScreen:$NoScreen
        Write-Log "  UTC Time     : $($utcTime.ToString('yyyy-MM-dd HH:mm:ss'))"   -NoScreen:$NoScreen
        Write-Log "  Time Zone    : $($tzInfo.DisplayName)"                         -NoScreen:$NoScreen
    } catch { }
}

# ── 10. Startup & Scheduled Tasks ───────────────────────────────
function Invoke-StartupAndTasks {
    param([switch]$NoScreen)

    Write-LogHeader "10. Startup Programs & Scheduled Tasks" -NoScreen:$NoScreen

    # Startup Programs — registry
    Write-LogSection "Startup Programs (Registry)" -NoScreen:$NoScreen
    $startupPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";                Label = "HKLM Run (All Users)" },
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";            Label = "HKLM RunOnce" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";                Label = "HKCU Run (Current User)" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";            Label = "HKCU RunOnce" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";    Label = "HKLM Run (32-bit)" }
    )

    $totalStartup = 0
    foreach ($sp in $startupPaths) {
        try {
            if (Test-Path $sp.Path) {
                $entries = Get-ItemProperty -Path $sp.Path -ErrorAction SilentlyContinue
                $props   = $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                if ($props) {
                    Write-Log "" -NoScreen:$NoScreen
                    Write-Log "  [ $($sp.Label) ]" -NoScreen:$NoScreen
                    foreach ($p in $props) {
                        Write-Log "    $($p.Name.PadRight(30)) : $($p.Value)" -NoScreen:$NoScreen
                        $totalStartup++
                    }
                }
            }
        } catch { }
    }

    # Startup folder
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $items = Get-ChildItem $folder -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
            if ($items) {
                Write-Log "" -NoScreen:$NoScreen
                Write-Log "  [ Startup Folder: $folder ]" -NoScreen:$NoScreen
                foreach ($item in $items) {
                    Write-Log "    $($item.Name)" -NoScreen:$NoScreen
                    $totalStartup++
                }
            }
        }
    }

    Write-Log "" -NoScreen:$NoScreen
    Write-Log "  Total startup entries: $totalStartup" -NoScreen:$NoScreen

    # Scheduled Tasks — non-Microsoft only
    Write-LogSection "Scheduled Tasks (Non-Microsoft)" -NoScreen:$NoScreen
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop |
                 Where-Object {
                     $_.TaskPath -notmatch '\\Microsoft\\' -and
                     $_.State    -ne 'Disabled'
                 } | Sort-Object TaskName

        if ($tasks.Count -eq 0) {
            Write-Log "  No non-Microsoft scheduled tasks found." -NoScreen:$NoScreen
        } else {
            Write-Log ("  {0,-40} {1,-12} {2,-20} {3}" -f "Task Name", "State", "Last Run", "Author") -NoScreen:$NoScreen
            Write-Log ("  {0,-40} {1,-12} {2,-20} {3}" -f ("-"*40), ("-"*12), ("-"*20), ("-"*30))     -NoScreen:$NoScreen
            foreach ($t in $tasks) {
                $info     = $t | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
                $lastRun  = if ($info.LastRunTime -and $info.LastRunTime.Year -gt 1999) {
                                $info.LastRunTime.ToString('yyyy-MM-dd HH:mm')
                            } else { "Never" }
                $name     = if ($t.TaskName.Length -gt 39) { $t.TaskName.Substring(0,36) + "..." } else { $t.TaskName }
                $author   = $t.Author ?? "N/A"
                $author   = if ($author.Length -gt 29) { $author.Substring(0,26) + "..." } else { $author }
                Write-Log ("  {0,-40} {1,-12} {2,-20} {3}" -f $name, $t.State, $lastRun, $author) -NoScreen:$NoScreen
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total non-Microsoft scheduled tasks: $($tasks.Count)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not enumerate scheduled tasks: $_" -NoScreen:$NoScreen
    }
}

# ── 11. Proxy, Wi-Fi & VPN ──────────────────────────────────────
function Invoke-ProxyWifiVPN {
    param([switch]$NoScreen)

    Write-LogHeader "11. Proxy, Wi-Fi Profiles & VPN" -NoScreen:$NoScreen

    # Proxy
    Write-LogSection "Proxy Settings" -NoScreen:$NoScreen
    try {
        $proxyReg = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction Stop
        $enabled  = $proxyReg.ProxyEnable
        Write-Log "  Proxy Enabled     : $(if ($enabled -eq 1) { '[+] Yes' } else { 'No' })"  -NoScreen:$NoScreen
        if ($enabled -eq 1) {
            Write-Log "  Proxy Server      : $($proxyReg.ProxyServer)"   -NoScreen:$NoScreen
            Write-Log "  Proxy Override    : $($proxyReg.ProxyOverride)" -NoScreen:$NoScreen
        }
        $autoConfig = $proxyReg.AutoConfigURL
        if ($autoConfig) {
            Write-Log "  Auto-Config URL   : $autoConfig" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not read proxy settings: $_" -NoScreen:$NoScreen
    }

    # System-wide proxy (WinHTTP)
    Write-LogSection "WinHTTP Proxy (System-Wide)" -NoScreen:$NoScreen
    try {
        $winhttp = netsh winhttp show proxy 2>&1
        $winhttp | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen }
    } catch {
        Write-Log "  [!] netsh winhttp failed: $_" -NoScreen:$NoScreen
    }

    # Wi-Fi Profiles
    Write-LogSection "Wi-Fi Profiles" -NoScreen:$NoScreen
    try {
        $wlanOutput = netsh wlan show profiles 2>&1
        if ($wlanOutput -match 'WLAN AutoConfig') {
            Write-Log "  [!] WLAN service not running — no Wi-Fi profiles available." -NoScreen:$NoScreen
        } else {
            $profileNames = $wlanOutput | Where-Object { $_ -match 'All User Profile' } |
                            ForEach-Object { ($_ -split ':',2)[1].Trim() }

            if ($profileNames.Count -eq 0) {
                Write-Log "  No Wi-Fi profiles found." -NoScreen:$NoScreen
            } else {
                Write-Log ("  {0,-35} {1,-15} {2}" -f "SSID", "Auth", "Encryption") -NoScreen:$NoScreen
                Write-Log ("  {0,-35} {1,-15} {2}" -f ("-"*35), ("-"*15), ("-"*15))  -NoScreen:$NoScreen
                foreach ($profile in $profileNames) {
                    try {
                        $detail = netsh wlan show profile name="$profile" 2>&1
                        $auth   = ($detail | Where-Object { $_ -match 'Authentication' } | Select-Object -First 1) -replace '.*:\s*',''
                        $enc    = ($detail | Where-Object { $_ -match 'Cipher'         } | Select-Object -First 1) -replace '.*:\s*',''
                        $ssid   = if ($profile.Length -gt 34) { $profile.Substring(0,31) + "..." } else { $profile }
                        Write-Log ("  {0,-35} {1,-15} {2}" -f $ssid, $auth.Trim(), $enc.Trim()) -NoScreen:$NoScreen
                    } catch { Write-Log "  $profile" -NoScreen:$NoScreen }
                }
                Write-Log "" -NoScreen:$NoScreen
                Write-Log "  Total Wi-Fi profiles: $($profileNames.Count)" -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [!] Could not enumerate Wi-Fi profiles: $_" -NoScreen:$NoScreen
    }

    # VPN
    Write-LogSection "VPN Adapters & Status" -NoScreen:$NoScreen
    try {
        $vpnAdapters = Get-NetAdapter -ErrorAction Stop |
                       Where-Object { $_.InterfaceDescription -match 'VPN|Tunnel|WireGuard|OpenVPN|Cisco|GlobalProtect|FortiClient|Pulse|SonicWall|Check Point|Juniper|AnyConnect' }

        if ($vpnAdapters.Count -eq 0) {
            Write-Log "  No VPN adapters detected by name." -NoScreen:$NoScreen
        } else {
            foreach ($vpn in $vpnAdapters) {
                $status = $vpn.Status
                $flag   = if ($status -eq 'Up') { "[+] Connected" } else { "[-] Disconnected" }
                Write-Log "  $flag  $($vpn.Name)  [$($vpn.InterfaceDescription)]" -NoScreen:$NoScreen
                Write-Log "    Link Speed : $($vpn.LinkSpeed)" -NoScreen:$NoScreen
            }
        }

        # Also check VPN connections defined in Windows (rasphone / VPN connections)
        $vpnConns = Get-VpnConnection -ErrorAction SilentlyContinue
        if ($vpnConns) {
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Windows VPN Connections:" -NoScreen:$NoScreen
            foreach ($v in $vpnConns) {
                $connStatus = if ($v.ConnectionStatus -eq 'Connected') { "[+] Connected" } else { "[-] $($v.ConnectionStatus)" }
                Write-Log "  $connStatus  $($v.Name)  ($($v.TunnelType))  Server: $($v.ServerAddress)" -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [!] Could not enumerate VPN adapters: $_" -NoScreen:$NoScreen
    }
}

# ── 12. Remote Management Readiness ─────────────────────────────
function Invoke-RemoteManagement {
    param([switch]$NoScreen)

    Write-LogHeader "12. Remote Management Readiness" -NoScreen:$NoScreen

    # WinRM
    Write-LogSection "WinRM (PowerShell Remoting)" -NoScreen:$NoScreen
    try {
        $winrm = Get-Service WinRM -ErrorAction Stop
        $status = $winrm.Status
        $flag   = if ($status -eq 'Running') { "[+] Running" } else { "[-] $status" }
        Write-Log "  WinRM Service     : $flag" -NoScreen:$NoScreen

        $winrmConfig = winrm get winrm/config/client 2>&1 | Select-Object -First 10
        $winrmConfig | ForEach-Object { Write-Log "  $_" -NoScreen:$NoScreen }
    } catch {
        Write-Log "  [!] Could not query WinRM: $_" -NoScreen:$NoScreen
    }

    # RDP
    Write-LogSection "Remote Desktop (RDP)" -NoScreen:$NoScreen
    try {
        $rdpEnabled = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -ErrorAction Stop).fDenyTSConnections
        $rdpStatus  = if ($rdpEnabled -eq 0) { "[+] Enabled" } else { "[-] Disabled" }
        Write-Log "  RDP               : $rdpStatus" -NoScreen:$NoScreen

        $rdpPort = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).PortNumber
        Write-Log "  RDP Port          : $(if ($rdpPort) { $rdpPort } else { '3389 (default)' })" -NoScreen:$NoScreen

        $nla = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ErrorAction SilentlyContinue).UserAuthentication
        Write-Log "  NLA Required      : $(if ($nla -eq 1) { '[+] Yes (secure)' } else { '[~] No (less secure)' })" -NoScreen:$NoScreen

        # RDP-allowed users
        $rdpGroup = net localgroup "Remote Desktop Users" 2>&1 | Where-Object { $_ -match '\S' -and $_ -notmatch 'command|Members|---' }
        Write-Log "" -NoScreen:$NoScreen
        Write-Log "  Remote Desktop Users group:" -NoScreen:$NoScreen
        if ($rdpGroup) {
            $rdpGroup | ForEach-Object { Write-Log "    $_" -NoScreen:$NoScreen }
        } else {
            Write-Log "    (empty — Administrators have access by default)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not query RDP settings: $_" -NoScreen:$NoScreen
    }

    # Remote Registry
    Write-LogSection "Remote Registry Service" -NoScreen:$NoScreen
    try {
        $remReg = Get-Service RemoteRegistry -ErrorAction Stop
        $flag   = if ($remReg.Status -eq 'Running') { "[~] Running (potential security risk)" } else { "[+] Stopped" }
        Write-Log "  Remote Registry   : $flag  (StartType: $($remReg.StartType))" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not query Remote Registry service: $_" -NoScreen:$NoScreen
    }

    # SMB
    Write-LogSection "SMB Configuration" -NoScreen:$NoScreen
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1      = if ($smbConfig.EnableSMB1Protocol) { "[-] ENABLED  [!] SECURITY RISK" } else { "[+] Disabled" }
        $smb2      = if ($smbConfig.EnableSMB2Protocol) { "[+] Enabled"  } else { "[-] Disabled" }
        Write-Log "  SMBv1             : $smb1" -NoScreen:$NoScreen
        Write-Log "  SMBv2/3           : $smb2" -NoScreen:$NoScreen
        Write-Log "  Signing Required  : $($smbConfig.RequireSecuritySignature)" -NoScreen:$NoScreen
        Write-Log "  Encrypt Data      : $($smbConfig.EncryptData)" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not query SMB configuration: $_" -NoScreen:$NoScreen
    }

    # PSRemoting test
    Write-LogSection "PowerShell Remoting" -NoScreen:$NoScreen
    try {
        $psRemoting = Get-PSSessionConfiguration -ErrorAction Stop | Select-Object -First 3
        foreach ($s in $psRemoting) {
            Write-Log "  Session Config    : $($s.Name)  Permission: $($s.Permission)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] PS Remoting not configured or access denied: $_" -NoScreen:$NoScreen
    }
}

# ── 13. Performance Snapshot ─────────────────────────────────────
function Invoke-PerformanceSnapshot {
    param([switch]$NoScreen)

    Write-LogHeader "13. Performance Snapshot" -NoScreen:$NoScreen

    # CPU utilization
    Write-LogSection "CPU Utilization" -NoScreen:$NoScreen
    try {
        # Sample over 2 seconds for a more accurate reading
        $cpuLoad = (Get-CimInstance Win32_Processor -ErrorAction Stop |
                    Measure-Object -Property LoadPercentage -Average).Average
        $cpuFlag = if ($cpuLoad -ge 90) { "  [!] CRITICAL" } elseif ($cpuLoad -ge 75) { "  [~] HIGH" } else { "" }
        Write-Log "  CPU Load          : $cpuLoad%$cpuFlag" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not get CPU load: $_" -NoScreen:$NoScreen
    }

    # Memory utilization
    Write-LogSection "Memory Utilization" -NoScreen:$NoScreen
    try {
        $os       = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $totalGB  = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)
        $freeGB   = [math]::Round($os.FreePhysicalMemory    / 1MB, 2)
        $usedGB   = [math]::Round($totalGB - $freeGB, 2)
        $usedPct  = [math]::Round(($usedGB / $totalGB) * 100, 1)
        $memFlag  = if ($usedPct -ge 90) { "  [!] CRITICAL" } elseif ($usedPct -ge 75) { "  [~] HIGH" } else { "" }
        Write-Log "  Total RAM         : $totalGB GB"              -NoScreen:$NoScreen
        Write-Log "  Used              : $usedGB GB ($usedPct%)$memFlag" -NoScreen:$NoScreen
        Write-Log "  Free              : $freeGB GB"               -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not get memory stats: $_" -NoScreen:$NoScreen
    }

    # Page file
    Write-LogSection "Page File" -NoScreen:$NoScreen
    try {
        $pageFiles = Get-CimInstance Win32_PageFileUsage -ErrorAction Stop
        foreach ($pf in $pageFiles) {
            $allocGB  = [math]::Round($pf.AllocatedBaseSize / 1KB, 2)
            $usageGB  = [math]::Round($pf.CurrentUsage      / 1KB, 2)
            $peakGB   = [math]::Round($pf.PeakUsage         / 1KB, 2)
            $usedPct  = if ($allocGB -gt 0) { [math]::Round(($usageGB / $allocGB) * 100, 1) } else { 0 }
            Write-Log "  Path              : $($pf.Name)"                   -NoScreen:$NoScreen
            Write-Log "  Allocated         : $allocGB GB"                   -NoScreen:$NoScreen
            Write-Log "  Current Usage     : $usageGB GB ($usedPct%)"       -NoScreen:$NoScreen
            Write-Log "  Peak Usage        : $peakGB GB"                    -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not query page file: $_" -NoScreen:$NoScreen
    }

    # System uptime
    Write-LogSection "System Uptime" -NoScreen:$NoScreen
    try {
        $os       = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $uptime   = (Get-Date) - $os.LastBootUpTime
        $days     = [math]::Floor($uptime.TotalDays)
        $hours    = $uptime.Hours
        $mins     = $uptime.Minutes
        $uptimeFlag = if ($days -gt 90) { "  [!] Over 90 days — reboot recommended" }
                      elseif ($days -gt 30) { "  [~] Over 30 days — consider scheduling reboot" }
                      else { "" }
        Write-Log "  Last Boot         : $($os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))"  -NoScreen:$NoScreen
        Write-Log "  Uptime            : $days days, $hours hrs, $mins min$uptimeFlag"            -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not calculate uptime: $_" -NoScreen:$NoScreen
    }

    # Battery (laptops)
    Write-LogSection "Battery Status" -NoScreen:$NoScreen
    try {
        $batteries = Get-CimInstance Win32_Battery -ErrorAction Stop
        if (-not $batteries) {
            Write-Log "  No battery detected (desktop or AC-only system)." -NoScreen:$NoScreen
        } else {
            foreach ($bat in $batteries) {
                $chargeMap = @{1="Discharging";2="AC Connected";3="Fully Charged";4="Low";5="Critical";6="Charging";7="Charging+High";8="Charging+Low";9="Charging+Critical";10="Undefined";11="Partially Charged"}
                $charge    = $chargeMap[[int]$bat.BatteryStatus] ?? "Unknown"
                $pct       = $bat.EstimatedChargeRemaining
                $batFlag   = if ($pct -lt 20 -and $bat.BatteryStatus -eq 1) { "  [!] LOW BATTERY" } else { "" }
                $wear      = if ($bat.DesignCapacity -and $bat.FullChargeCapacity) {
                                 $wearPct = [math]::Round((1 - ($bat.FullChargeCapacity / $bat.DesignCapacity)) * 100, 1)
                                 "$wearPct% wear"
                             } else { "N/A" }

                Write-Log "  Battery           : $($bat.Name)"          -NoScreen:$NoScreen
                Write-Log "  Status            : $charge"               -NoScreen:$NoScreen
                Write-Log "  Charge            : $pct%$batFlag"         -NoScreen:$NoScreen
                Write-Log "  Wear Level        : $wear"                 -NoScreen:$NoScreen
                Write-Log "  Est. Runtime      : $($bat.EstimatedRunTime) min" -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [!] Could not query battery: $_" -NoScreen:$NoScreen
    }
}

# ── 14. Printers & Print Queues ──────────────────────────────────
function Invoke-Printers {
    param([switch]$NoScreen)

    Write-LogHeader "14. Printers & Print Queues" -NoScreen:$NoScreen

    # Installed printers
    Write-LogSection "Installed Printers" -NoScreen:$NoScreen
    try {
        $printers = Get-Printer -ErrorAction Stop | Sort-Object Name
        if ($printers.Count -eq 0) {
            Write-Log "  No printers installed." -NoScreen:$NoScreen
        } else {
            Write-Log ("  {0,-40} {1,-12} {2,-10} {3}" -f "Name", "Type", "Status", "Driver") -NoScreen:$NoScreen
            Write-Log ("  {0,-40} {1,-12} {2,-10} {3}" -f ("-"*40), ("-"*12), ("-"*10), ("-"*30)) -NoScreen:$NoScreen
            foreach ($p in $printers) {
                $name     = if ($p.Name.Length -gt 39) { $p.Name.Substring(0,36) + "..." } else { $p.Name }
                $type     = if ($p.Type -eq 'Local') { "Local" } else { "Network" }
                $default  = if ($p.Default) { " [DEFAULT]" } else { "" }
                $driver   = if ($p.DriverName.Length -gt 29) { $p.DriverName.Substring(0,26) + "..." } else { $p.DriverName }
                Write-Log ("  {0,-40} {1,-12} {2,-10} {3}{4}" -f $name, $type, $p.PrinterStatus, $driver, $default) -NoScreen:$NoScreen
                if ($p.PortName) {
                    Write-Log ("  {0,-40}   Port: {1}" -f "", $p.PortName) -NoScreen:$NoScreen
                }
            }
            Write-Log "" -NoScreen:$NoScreen
            Write-Log "  Total printers: $($printers.Count)" -NoScreen:$NoScreen
        }
    } catch {
        Write-Log "  [!] Could not enumerate printers: $_" -NoScreen:$NoScreen
    }

    # Print queues / pending jobs
    Write-LogSection "Print Queue (Pending Jobs)" -NoScreen:$NoScreen
    try {
        $jobs = Get-PrintJob -ErrorAction Stop 2>&1
        if (-not $jobs -or $jobs.Count -eq 0) {
            Write-Log "  [+] No pending print jobs." -NoScreen:$NoScreen
        } else {
            Write-Log "  Pending print jobs:" -NoScreen:$NoScreen
            foreach ($job in $jobs) {
                Write-Log "  Printer: $($job.PrinterName)  Job: $($job.Id)  User: $($job.UserName)  Status: $($job.JobStatus)  Size: $($job.Size) bytes" -NoScreen:$NoScreen
            }
        }
    } catch {
        Write-Log "  [+] No pending print jobs (or access denied)." -NoScreen:$NoScreen
    }

    # Print spooler status
    Write-LogSection "Print Spooler Service" -NoScreen:$NoScreen
    try {
        $spooler = Get-Service Spooler -ErrorAction Stop
        $flag    = if ($spooler.Status -eq 'Running') { "[+] Running" } else { "[!] $($spooler.Status)" }
        Write-Log "  Spooler           : $flag  (StartType: $($spooler.StartType))" -NoScreen:$NoScreen
    } catch {
        Write-Log "  [!] Could not query spooler service: $_" -NoScreen:$NoScreen
    }
}

# ── TOOLS ────────────────────────────────────────────────────────
function Invoke-Tools {

    $ToolItems = @(
        @{ Number =  "1"; Label = "Disk Cleanup";                  Desc = "Launch cleanmgr disk cleanup utility"              },
        @{ Number =  "2"; Label = "IP Release & Renew";            Desc = "ipconfig /release then /renew on all adapters"     },
        @{ Number =  "3"; Label = "Flush DNS Cache";               Desc = "ipconfig /flushdns"                                },
        @{ Number =  "4"; Label = "GPUpdate /force";               Desc = "Force Group Policy refresh"                        },
        @{ Number =  "5"; Label = "RSOP Report";                   Desc = "Generate Resultant Set of Policy HTML report"      },
        @{ Number =  "6"; Label = "Reset Winsock & TCP/IP Stack";  Desc = "netsh winsock reset + netsh int ip reset"          },
        @{ Number =  "7"; Label = "SFC /scannow";                  Desc = "System File Checker — scan and repair system files"},
        @{ Number =  "8"; Label = "DISM Health Check & Repair";    Desc = "Check and restore Windows image health"            },
        @{ Number =  "9"; Label = "Clear Print Queue";             Desc = "Stop spooler, delete jobs, restart spooler"        },
        @{ Number = "10"; Label = "Restart a Service";             Desc = "Prompt for a service name and restart it"          },
        @{ Number = "11"; Label = "Clear Windows Update Cache";    Desc = "Stop WU service, clear cache, restart"             },
        @{ Number = "12"; Label = "Test DNS Resolution";           Desc = "Resolve a hostname to IP using current DNS"        }
    )

    $toolsActive = $true

    while ($toolsActive) {

        Write-Host ""
        Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
        Write-Host "  │                      TOOLS MENU                         │" -ForegroundColor Magenta
        Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
        Write-Host ""
        Write-Host "  ── MAINTENANCE ─────────────────────────────────────────────" -ForegroundColor Yellow
        Write-Host "    [ 1]  Disk Cleanup                  Launch cleanmgr"           -ForegroundColor Gray
        Write-Host "    [ 2]  IP Release & Renew            All adapters"              -ForegroundColor Gray
        Write-Host "    [ 3]  Flush DNS Cache               ipconfig /flushdns"        -ForegroundColor Gray
        Write-Host "    [ 9]  Clear Print Queue             Stop/clear/start spooler"  -ForegroundColor Gray
        Write-Host "    [11]  Clear Windows Update Cache    Stop WU, clear, restart"   -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ── POLICY & SYSTEM ─────────────────────────────────────────" -ForegroundColor Green
        Write-Host "    [ 4]  GPUpdate /force               Force GP refresh"          -ForegroundColor Gray
        Write-Host "    [ 5]  RSOP Report                   HTML policy report"        -ForegroundColor Gray
        Write-Host "    [ 6]  Reset Winsock & TCP/IP        Network stack reset"       -ForegroundColor Gray
        Write-Host "    [10]  Restart a Service             Prompt for service name"   -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ── REPAIR & DIAGNOSTICS ────────────────────────────────────" -ForegroundColor Cyan
        Write-Host "    [ 7]  SFC /scannow                  System File Checker"       -ForegroundColor Gray
        Write-Host "    [ 8]  DISM Health Check & Repair    Windows image repair"      -ForegroundColor Gray
        Write-Host "    [12]  Test DNS Resolution           Resolve a hostname"        -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ── NETWORK TOOLS ───────────────────────────────────────────" -ForegroundColor Blue
        Write-Host "    [13]  Continuous Ping               Ping until Ctrl+C"         -ForegroundColor Gray
        Write-Host "    [14]  Test-NetConnection            ICMP + TCP port test"      -ForegroundColor Gray
        Write-Host "    [15]  Check Default Gateway        Auto-detect & ping GW"      -ForegroundColor Gray
        Write-Host "    [16]  Wi-Fi Signal & Channel        Signal strength + details" -ForegroundColor Gray
        Write-Host "    [17]  Show Routing Table            route print"               -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ── APPLICATION TOOLS ───────────────────────────────────────" -ForegroundColor Magenta
        Write-Host "    [18]  Clear Teams Cache             Stop Teams, clear cache"   -ForegroundColor Gray
        Write-Host "    [19]  Reset Edge/IE Proxy           Clear proxy + WinHTTP"     -ForegroundColor Gray
        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "    [ M]  Return to Main Menu"                                     -ForegroundColor White
        Write-Host "    [ Q]  Quit"                                                    -ForegroundColor White
        Write-Host ""

        $toolChoice = Read-Host "  Select a tool"

        if ($toolChoice -match '^[Qq]$') {
            Write-Host ""
            Write-Host "  Exiting." -ForegroundColor DarkGray
            exit
        }
        if ($toolChoice -match '^[Mm]$') {
            $toolsActive = $false
            break
        }

        Write-Host ""

        switch ($toolChoice) {

            # ── 1. Disk Cleanup ──────────────────────────────────
            "1" {
                Write-Host "  Launching Disk Cleanup..." -ForegroundColor Cyan
                try {
                    Start-Process cleanmgr -Wait
                    Write-Host "  [+] Disk Cleanup completed." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] Disk Cleanup launched at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } catch {
                    Write-Host "  [!] Failed to launch Disk Cleanup: $_" -ForegroundColor Red
                }
            }

            # ── 2. IP Release & Renew ────────────────────────────
            "2" {
                Write-Host "  Running ipconfig /release..." -ForegroundColor Cyan
                $rel = ipconfig /release 2>&1
                $rel | ForEach-Object { Write-Host "  $_" }
                Write-Host ""
                Write-Host "  Running ipconfig /renew..." -ForegroundColor Cyan
                $ren = ipconfig /renew 2>&1
                $ren | ForEach-Object { Write-Host "  $_" }
                Write-Host ""
                Write-Host "  [+] IP Release & Renew complete." -ForegroundColor Green
                $script:LogBuffer.Add("[TOOL] IP Release/Renew at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                $script:LogBuffer.Add(($rel + $ren) -join "`n")
            }

            # ── 3. Flush DNS ─────────────────────────────────────
            "3" {
                Write-Host "  Flushing DNS cache..." -ForegroundColor Cyan
                $flush = ipconfig /flushdns 2>&1
                $flush | ForEach-Object { Write-Host "  $_" }
                Write-Host "  [+] DNS cache flushed." -ForegroundColor Green
                $script:LogBuffer.Add("[TOOL] Flush DNS at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
            }

            # ── 4. GPUpdate /force ───────────────────────────────
            "4" {
                Write-Host "  Running GPUpdate /force (this may take a moment)..." -ForegroundColor Cyan
                $gp = gpupdate /force 2>&1
                $gp | ForEach-Object { Write-Host "  $_" }
                Write-Host ""
                Write-Host "  [+] Group Policy update complete." -ForegroundColor Green
                $script:LogBuffer.Add("[TOOL] GPUpdate /force at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                $script:LogBuffer.Add($gp -join "`n")
            }

            # ── 5. RSOP Report ───────────────────────────────────
            "5" {
                $rsopPath = "$PSScriptRoot\$($env:COMPUTERNAME)-RSOP-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
                Write-Host "  Generating RSOP report..." -ForegroundColor Cyan
                Write-Host "  Output: $rsopPath" -ForegroundColor DarkGray
                try {
                    $rsop = gpresult /h "$rsopPath" /f 2>&1
                    $rsop | ForEach-Object { Write-Host "  $_" }
                    if (Test-Path $rsopPath) {
                        Write-Host "  [+] RSOP report saved to: $rsopPath" -ForegroundColor Green
                        $open = Read-Host "  Open report in browser? (Y/N)"
                        if ($open -match '^[Yy]$') { Start-Process $rsopPath }
                    } else {
                        Write-Host "  [!] Report file not found — gpresult may require elevation." -ForegroundColor Red
                    }
                    $script:LogBuffer.Add("[TOOL] RSOP report generated: $rsopPath at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } catch {
                    Write-Host "  [!] RSOP failed: $_" -ForegroundColor Red
                }
            }

            # ── 6. Reset Winsock & TCP/IP ────────────────────────
            "6" {
                Write-Host "  [!] WARNING: This will require a reboot to take effect." -ForegroundColor Yellow
                $confirm = Read-Host "  Continue? (Y/N)"
                if ($confirm -match '^[Yy]$') {
                    Write-Host "  Resetting Winsock..." -ForegroundColor Cyan
                    $ws = netsh winsock reset 2>&1
                    $ws | ForEach-Object { Write-Host "  $_" }
                    Write-Host ""
                    Write-Host "  Resetting TCP/IP stack..." -ForegroundColor Cyan
                    $ip = netsh int ip reset 2>&1
                    $ip | ForEach-Object { Write-Host "  $_" }
                    Write-Host ""
                    Write-Host "  [+] Reset complete. A reboot is required." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] Winsock + TCP/IP reset at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    $reboot = Read-Host "  Reboot now? (Y/N)"
                    if ($reboot -match '^[Yy]$') { Restart-Computer -Force }
                } else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
            }

            # ── 7. SFC /scannow ──────────────────────────────────
            "7" {
                Write-Host "  Running SFC /scannow (this may take several minutes)..." -ForegroundColor Cyan
                Write-Host "  Results will also be in CBS.log at %windir%\Logs\CBS\CBS.log" -ForegroundColor DarkGray
                Write-Host ""
                $sfc = sfc /scannow 2>&1
                $sfc | ForEach-Object { Write-Host "  $_" }
                Write-Host ""
                Write-Host "  [+] SFC scan complete." -ForegroundColor Green
                $script:LogBuffer.Add("[TOOL] SFC /scannow at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                $script:LogBuffer.Add($sfc -join "`n")
            }

            # ── 8. DISM Health Check & Repair ────────────────────
            "8" {
                Write-Host "  ── DISM Options ────────────────────────────" -ForegroundColor Cyan
                Write-Host "    [1]  CheckHealth    (fast, no network)"    -ForegroundColor Gray
                Write-Host "    [2]  ScanHealth     (thorough, no network)" -ForegroundColor Gray
                Write-Host "    [3]  RestoreHealth  (repair, needs internet or source)" -ForegroundColor Gray
                Write-Host ""
                $dismChoice = Read-Host "  Select DISM option (1/2/3)"
                $dismCmd = switch ($dismChoice) {
                    "1" { "/Online /Cleanup-Image /CheckHealth"   }
                    "2" { "/Online /Cleanup-Image /ScanHealth"    }
                    "3" { "/Online /Cleanup-Image /RestoreHealth" }
                    default { $null }
                }
                if ($dismCmd) {
                    Write-Host ""
                    Write-Host "  Running DISM $dismCmd" -ForegroundColor Cyan
                    Write-Host "  (This may take several minutes...)" -ForegroundColor DarkGray
                    Write-Host ""
                    $dism = & dism $dismCmd.Split(' ') 2>&1
                    $dism | ForEach-Object { Write-Host "  $_" }
                    Write-Host ""
                    Write-Host "  [+] DISM complete." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] DISM $dismCmd at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    $script:LogBuffer.Add($dism -join "`n")
                } else {
                    Write-Host "  Invalid selection." -ForegroundColor Red
                }
            }

            # ── 9. Clear Print Queue ─────────────────────────────
            "9" {
                Write-Host "  Stopping Print Spooler..." -ForegroundColor Cyan
                try {
                    Stop-Service Spooler -Force -ErrorAction Stop
                    Write-Host "  Deleting print jobs..." -ForegroundColor Cyan
                    $spoolPath = "$env:SystemRoot\System32\spool\PRINTERS"
                    $deleted = 0
                    Get-ChildItem -Path $spoolPath -ErrorAction SilentlyContinue |
                        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; $deleted++ }
                    Write-Host "  Starting Print Spooler..." -ForegroundColor Cyan
                    Start-Service Spooler -ErrorAction Stop
                    Write-Host "  [+] Print queue cleared ($deleted job file(s) removed)." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] Print queue cleared ($deleted files) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } catch {
                    Write-Host "  [!] Failed to clear print queue: $_" -ForegroundColor Red
                    try { Start-Service Spooler -ErrorAction SilentlyContinue } catch { }
                }
            }

            # ── 10. Restart a Service ────────────────────────────
            "10" {
                $svcName = Read-Host "  Enter the service name or display name"
                if ([string]::IsNullOrWhiteSpace($svcName)) {
                    Write-Host "  No service name entered." -ForegroundColor Red
                } else {
                    try {
                        $svc = Get-Service -Name $svcName -ErrorAction Stop
                        Write-Host "  Found: $($svc.DisplayName) — Status: $($svc.Status)" -ForegroundColor Cyan
                        $confirm = Read-Host "  Restart this service? (Y/N)"
                        if ($confirm -match '^[Yy]$') {
                            Restart-Service -Name $svc.Name -Force -ErrorAction Stop
                            Start-Sleep -Seconds 2
                            $newStatus = (Get-Service -Name $svc.Name).Status
                            Write-Host "  [+] Service restarted. Current status: $newStatus" -ForegroundColor Green
                            $script:LogBuffer.Add("[TOOL] Restarted service '$($svc.Name)' at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') — Status: $newStatus")
                        } else {
                            Write-Host "  Cancelled." -ForegroundColor DarkGray
                        }
                    } catch {
                        Write-Host "  [!] Service '$svcName' not found or could not be restarted: $_" -ForegroundColor Red
                    }
                }
            }

            # ── 11. Clear Windows Update Cache ───────────────────
            "11" {
                Write-Host "  [!] This will stop Windows Update services temporarily." -ForegroundColor Yellow
                $confirm = Read-Host "  Continue? (Y/N)"
                if ($confirm -match '^[Yy]$') {
                    $wuServices = @('wuauserv','bits','cryptsvc','msiserver')
                    Write-Host "  Stopping Windows Update services..." -ForegroundColor Cyan
                    $wuServices | ForEach-Object {
                        Stop-Service $_ -Force -ErrorAction SilentlyContinue
                        Write-Host "    Stopped: $_"
                    }
                    Write-Host "  Clearing SoftwareDistribution cache..." -ForegroundColor Cyan
                    $wuCache  = "$env:SystemRoot\SoftwareDistribution"
                    $catroot2 = "$env:SystemRoot\System32\catroot2"
                    $cleared  = 0
                    @($wuCache, $catroot2) | ForEach-Object {
                        if (Test-Path $_) {
                            Get-ChildItem $_ -Recurse -ErrorAction SilentlyContinue |
                                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                            $cleared++
                            Write-Host "    Cleared: $_"
                        }
                    }
                    Write-Host "  Restarting Windows Update services..." -ForegroundColor Cyan
                    $wuServices | ForEach-Object {
                        Start-Service $_ -ErrorAction SilentlyContinue
                        Write-Host "    Started: $_"
                    }
                    Write-Host ""
                    Write-Host "  [+] Windows Update cache cleared." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] Windows Update cache cleared at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
            }

            # ── 12. Test DNS Resolution ──────────────────────────
            "12" {
                $hostname = Read-Host "  Enter hostname or FQDN to resolve"
                if ([string]::IsNullOrWhiteSpace($hostname)) {
                    Write-Host "  No hostname entered." -ForegroundColor Red
                } else {
                    Write-Host ""
                    Write-Host "  Resolving '$hostname'..." -ForegroundColor Cyan
                    try {
                        $result = [System.Net.Dns]::GetHostEntry($hostname)
                        Write-Host "  [+] Hostname    : $($result.HostName)" -ForegroundColor Green
                        Write-Host "  [+] IP Address(es):" -ForegroundColor Green
                        $result.AddressList | ForEach-Object {
                            Write-Host "        $($_.IPAddressToString)  ($($_.AddressFamily))" -ForegroundColor White
                        }
                        Write-Host ""
                        # Also run nslookup for additional detail
                        Write-Host "  nslookup output:" -ForegroundColor DarkGray
                        nslookup $hostname 2>&1 | ForEach-Object { Write-Host "  $_" }
                        $script:LogBuffer.Add("[TOOL] DNS resolution of '$hostname' at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') → $($result.AddressList.IPAddressToString -join ', ')")
                    } catch {
                        Write-Host "  [-] Could not resolve '$hostname': $_" -ForegroundColor Red
                        $script:LogBuffer.Add("[TOOL] DNS resolution FAILED for '$hostname' at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                    }
                }
            }

            # ── 13. Continuous Ping ──────────────────────────────
            "13" {
                $pingTarget = Read-Host "  Enter hostname or IP to ping"
                if ([string]::IsNullOrWhiteSpace($pingTarget)) {
                    Write-Host "  No target entered." -ForegroundColor Red
                } else {
                    Write-Host ""
                    Write-Host "  Pinging $pingTarget continuously — press Ctrl+C to stop." -ForegroundColor Cyan
                    Write-Host ""
                    $sent = 0; $received = 0; $failed = 0
                    try {
                        while ($true) {
                            $ping   = New-Object System.Net.NetworkInformation.Ping
                            $reply  = $ping.Send($pingTarget, 2000)
                            $sent++
                            $ts     = Get-Date -Format "HH:mm:ss"
                            if ($reply.Status -eq 'Success') {
                                $received++
                                Write-Host "  [$ts]  Reply from $($reply.Address)  time=$($reply.RoundtripTime)ms  TTL=$($reply.Options.Ttl)" -ForegroundColor Green
                            } else {
                                $failed++
                                Write-Host "  [$ts]  Request timed out / $($reply.Status)" -ForegroundColor Red
                            }
                            Start-Sleep -Milliseconds 1000
                        }
                    } catch [System.Management.Automation.PipelineStoppedException] {
                        # Ctrl+C caught cleanly
                    } catch { }
                    finally {
                        $lossPct = if ($sent -gt 0) { [math]::Round(($failed / $sent) * 100, 1) } else { 0 }
                        Write-Host ""
                        Write-Host "  ── Ping Summary ─────────────────────────────" -ForegroundColor Cyan
                        Write-Host "  Sent: $sent  |  Received: $received  |  Lost: $failed ($lossPct%)" -ForegroundColor White
                        $script:LogBuffer.Add("[TOOL] Continuous ping to '$pingTarget' — Sent: $sent  Received: $received  Lost: $failed ($lossPct%)")
                    }
                }
            }

            # ── 14. Test-NetConnection (port reachability) ───────
            "14" {
                $tncTarget = Read-Host "  Enter hostname or IP"
                $tncPort   = Read-Host "  Enter TCP port (leave blank to test ICMP only)"
                Write-Host ""
                try {
                    if ([string]::IsNullOrWhiteSpace($tncPort)) {
                        Write-Host "  Testing ICMP connectivity to $tncTarget..." -ForegroundColor Cyan
                        $tnc = Test-NetConnection -ComputerName $tncTarget -ErrorAction Stop
                        Write-Host "  PingSucceeded   : $($tnc.PingSucceeded)"                              -ForegroundColor $(if ($tnc.PingSucceeded) { "Green" } else { "Red" })
                        Write-Host "  RemoteAddress   : $($tnc.RemoteAddress)"                              -ForegroundColor White
                        Write-Host "  PingReplyDetails: RTT=$($tnc.PingReplyDetails.RoundtripTime)ms"       -ForegroundColor White
                        Write-Host "  NameResolution  : $($tnc.NameResolutionSucceeded)"                    -ForegroundColor White
                        $script:LogBuffer.Add("[TOOL] Test-NetConnection $tncTarget — Ping: $($tnc.PingSucceeded)  RTT: $($tnc.PingReplyDetails.RoundtripTime)ms")
                    } else {
                        Write-Host "  Testing TCP port $tncPort on $tncTarget..." -ForegroundColor Cyan
                        $tnc = Test-NetConnection -ComputerName $tncTarget -Port ([int]$tncPort) -ErrorAction Stop
                        $portColor = if ($tnc.TcpTestSucceeded) { "Green" } else { "Red" }
                        Write-Host "  TcpTestSucceeded: $($tnc.TcpTestSucceeded)"                           -ForegroundColor $portColor
                        Write-Host "  RemoteAddress   : $($tnc.RemoteAddress)"                              -ForegroundColor White
                        Write-Host "  RemotePort      : $($tnc.RemotePort)"                                 -ForegroundColor White
                        Write-Host "  PingSucceeded   : $($tnc.PingSucceeded)"                              -ForegroundColor $(if ($tnc.PingSucceeded) { "Green" } else { "Red" })
                        Write-Host "  RTT             : $($tnc.PingReplyDetails.RoundtripTime)ms"           -ForegroundColor White
                        $script:LogBuffer.Add("[TOOL] Test-NetConnection $tncTarget`:$tncPort — TCP: $($tnc.TcpTestSucceeded)  Ping: $($tnc.PingSucceeded)")
                    }
                } catch {
                    Write-Host "  [!] Test-NetConnection failed: $_" -ForegroundColor Red
                }
            }

            # ── 15. Check Default Gateway ────────────────────────
            "15" {
                Write-Host "  Detecting default gateway(s)..." -ForegroundColor Cyan
                Write-Host ""
                try {
                    $gateways = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
                                Where-Object { $_.NextHop -ne '0.0.0.0' } |
                                Sort-Object RouteMetric

                    if ($gateways.Count -eq 0) {
                        Write-Host "  [!] No default gateway found." -ForegroundColor Red
                    } else {
                        foreach ($gw in $gateways) {
                            $nic     = Get-NetAdapter -InterfaceIndex $gw.InterfaceIndex -ErrorAction SilentlyContinue
                            $nicName = if ($nic) { $nic.Name } else { "Interface $($gw.InterfaceIndex)" }
                            Write-Host "  Gateway   : $($gw.NextHop)  via $nicName  (Metric: $($gw.RouteMetric))" -ForegroundColor White
                            Write-Host "  Testing reachability..." -ForegroundColor DarkGray
                            $ping  = New-Object System.Net.NetworkInformation.Ping
                            $reply = $ping.Send($gw.NextHop, 2000)
                            if ($reply.Status -eq 'Success') {
                                Write-Host "  [+] Gateway $($gw.NextHop) is REACHABLE  (RTT: $($reply.RoundtripTime)ms)" -ForegroundColor Green
                            } else {
                                Write-Host "  [-] Gateway $($gw.NextHop) is UNREACHABLE ($($reply.Status))" -ForegroundColor Red
                            }
                            Write-Host ""
                            $script:LogBuffer.Add("[TOOL] Gateway check: $($gw.NextHop) via $nicName — $($reply.Status)  RTT: $($reply.RoundtripTime)ms")
                        }
                    }
                } catch {
                    Write-Host "  [!] Gateway check failed: $_" -ForegroundColor Red
                }
            }

            # ── 16. Wi-Fi Signal & Channel ───────────────────────
            "16" {
                Write-Host "  Querying Wi-Fi interface status..." -ForegroundColor Cyan
                Write-Host ""
                try {
                    $wlanInfo = netsh wlan show interfaces 2>&1
                    if ($wlanInfo -match 'There is no wireless interface') {
                        Write-Host "  [!] No wireless adapter found on this machine." -ForegroundColor Red
                    } else {
                        $wlanInfo | ForEach-Object { Write-Host "  $_" }

                        # Parse key fields and highlight them
                        $ssid    = ($wlanInfo | Where-Object { $_ -match '^\s+SSID\s+:' }           | Select-Object -First 1) -replace '.*:\s*',''
                        $bssid   = ($wlanInfo | Where-Object { $_ -match 'BSSID' }                  | Select-Object -First 1) -replace '.*:\s*',''
                        $signal  = ($wlanInfo | Where-Object { $_ -match 'Signal' }                 | Select-Object -First 1) -replace '.*:\s*',''
                        $channel = ($wlanInfo | Where-Object { $_ -match 'Channel' }                | Select-Object -First 1) -replace '.*:\s*',''
                        $band    = ($wlanInfo | Where-Object { $_ -match 'Radio type|Band' }        | Select-Object -First 1) -replace '.*:\s*',''
                        $rxRate  = ($wlanInfo | Where-Object { $_ -match 'Receive rate' }           | Select-Object -First 1) -replace '.*:\s*',''
                        $txRate  = ($wlanInfo | Where-Object { $_ -match 'Transmit rate' }          | Select-Object -First 1) -replace '.*:\s*',''
                        $auth    = ($wlanInfo | Where-Object { $_ -match 'Authentication' }         | Select-Object -First 1) -replace '.*:\s*',''

                        $sigNum  = [int]($signal -replace '[^0-9]','') 2>$null
                        $sigColor = if ($sigNum -ge 70) { "Green" } elseif ($sigNum -ge 40) { "Yellow" } else { "Red" }
                        $sigFlag  = if ($sigNum -lt 40) { "  [!] POOR SIGNAL" } elseif ($sigNum -lt 70) { "  [~] FAIR SIGNAL" } else { "  [+] GOOD SIGNAL" }

                        Write-Host ""
                        Write-Host "  ── Summary ──────────────────────────────────" -ForegroundColor Cyan
                        Write-Host "  SSID            : $($ssid.Trim())"             -ForegroundColor White
                        Write-Host "  BSSID           : $($bssid.Trim())"            -ForegroundColor White
                        Write-Host "  Signal Strength : $($signal.Trim())$sigFlag"   -ForegroundColor $sigColor
                        Write-Host "  Channel         : $($channel.Trim())"          -ForegroundColor White
                        Write-Host "  Band/Radio      : $($band.Trim())"             -ForegroundColor White
                        Write-Host "  Receive Rate    : $($rxRate.Trim()) Mbps"      -ForegroundColor White
                        Write-Host "  Transmit Rate   : $($txRate.Trim()) Mbps"      -ForegroundColor White
                        Write-Host "  Authentication  : $($auth.Trim())"             -ForegroundColor White
                        $script:LogBuffer.Add("[TOOL] Wi-Fi — SSID: $($ssid.Trim())  Signal: $($signal.Trim())  Channel: $($channel.Trim())  Band: $($band.Trim())")
                    }
                } catch {
                    Write-Host "  [!] Wi-Fi query failed: $_" -ForegroundColor Red
                }
            }

            # ── 17. Show Routing Table ───────────────────────────
            "17" {
                Write-Host "  Routing Table:" -ForegroundColor Cyan
                Write-Host ""
                try {
                    route print 2>&1 | ForEach-Object { Write-Host "  $_" }
                    $script:LogBuffer.Add("[TOOL] Routing table retrieved at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } catch {
                    Write-Host "  [!] route print failed: $_" -ForegroundColor Red
                }
            }

            # ── 18. Clear Teams Cache ────────────────────────────
            "18" {
                Write-Host "  [!] This will close Microsoft Teams if it is running." -ForegroundColor Yellow
                $confirm = Read-Host "  Continue? (Y/N)"
                if ($confirm -match '^[Yy]$') {
                    Write-Host ""
                    Write-Host "  Stopping Teams processes..." -ForegroundColor Cyan
                    $teamsProcs = @('Teams','ms-teams','msedgewebview2')
                    foreach ($proc in $teamsProcs) {
                        $running = Get-Process -Name $proc -ErrorAction SilentlyContinue
                        if ($running) {
                            $running | Stop-Process -Force -ErrorAction SilentlyContinue
                            Write-Host "    Stopped: $proc" -ForegroundColor Gray
                        }
                    }
                    Start-Sleep -Seconds 2

                    # Teams classic cache paths
                    $teamsCachePaths = @(
                        "$env:APPDATA\Microsoft\Teams\Cache",
                        "$env:APPDATA\Microsoft\Teams\blob_storage",
                        "$env:APPDATA\Microsoft\Teams\databases",
                        "$env:APPDATA\Microsoft\Teams\GPUCache",
                        "$env:APPDATA\Microsoft\Teams\IndexedDB",
                        "$env:APPDATA\Microsoft\Teams\Local Storage",
                        "$env:APPDATA\Microsoft\Teams\tmp"
                    )
                    # Teams new (work or school) cache path
                    $teamsNewPath = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"

                    $cleared = 0
                    Write-Host "  Clearing Teams cache folders..." -ForegroundColor Cyan

                    foreach ($path in $teamsCachePaths) {
                        if (Test-Path $path) {
                            Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue |
                                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                            Write-Host "    Cleared: $path" -ForegroundColor Gray
                            $cleared++
                        }
                    }

                    if (Test-Path $teamsNewPath) {
                        Get-ChildItem -Path $teamsNewPath -Recurse -ErrorAction SilentlyContinue |
                            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                        Write-Host "    Cleared: $teamsNewPath (Teams new)" -ForegroundColor Gray
                        $cleared++
                    }

                    if ($cleared -eq 0) {
                        Write-Host "  [~] No Teams cache folders found — Teams may not be installed." -ForegroundColor Yellow
                    } else {
                        Write-Host ""
                        Write-Host "  [+] Teams cache cleared ($cleared folder(s))." -ForegroundColor Green
                        Write-Host "  Teams will rebuild its cache on next launch." -ForegroundColor DarkGray
                    }
                    $script:LogBuffer.Add("[TOOL] Teams cache cleared ($cleared folders) at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } else {
                    Write-Host "  Cancelled." -ForegroundColor DarkGray
                }
            }

            # ── 19. Reset Edge / IE Proxy Settings ───────────────
            "19" {
                Write-Host "  Resetting Edge / Internet Explorer proxy settings..." -ForegroundColor Cyan
                Write-Host ""
                try {
                    # Clear registry proxy settings
                    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                    Set-ItemProperty -Path $regPath -Name ProxyEnable    -Value 0          -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $regPath -Name ProxyServer     -Value ""         -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $regPath -Name ProxyOverride   -Value ""         -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $regPath -Name AutoConfigURL   -Value ""         -ErrorAction SilentlyContinue
                    Write-Host "  [+] Registry proxy settings cleared." -ForegroundColor Green

                    # Reset WinHTTP proxy
                    Write-Host "  Resetting WinHTTP proxy..." -ForegroundColor Cyan
                    $winhttp = netsh winhttp reset proxy 2>&1
                    $winhttp | ForEach-Object { Write-Host "  $_" }

                    # Flush DNS for good measure
                    ipconfig /flushdns | Out-Null
                    Write-Host "  [+] DNS cache flushed." -ForegroundColor Green

                    # Notify any running processes to pick up the change
                    $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
                    $type = Add-Type -MemberDefinition $signature -Name WinInet -Namespace PInvoke -PassThru -ErrorAction SilentlyContinue
                    if ($type) {
                        $type::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null  # INTERNET_OPTION_SETTINGS_CHANGED
                        $type::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null  # INTERNET_OPTION_REFRESH
                        Write-Host "  [+] Notified WinINet of proxy change." -ForegroundColor Green
                    }

                    Write-Host ""
                    Write-Host "  [+] Proxy reset complete. Browser restart may be required." -ForegroundColor Green
                    $script:LogBuffer.Add("[TOOL] Edge/IE proxy reset at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
                } catch {
                    Write-Host "  [!] Proxy reset failed: $_" -ForegroundColor Red
                }
            }

            default {
                Write-Host "  [!] Invalid selection. Please choose a number from the menu." -ForegroundColor Red
            }
        }

        Write-Host ""
        Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
        Write-Host "    [M]  Back to Tools menu    [Q]  Quit    [Enter]  Main menu" -ForegroundColor DarkGray
        Write-Host ""
        $toolNav = Read-Host "  "
        if ($toolNav -match '^[Qq]$') {
            Write-Host "  Exiting." -ForegroundColor DarkGray
            exit
        }
        if ($toolNav -notmatch '^[Mm]$') {
            # Anything other than M (including just pressing Enter) goes back to main menu
            $toolsActive = $false
        }
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
    @{ Number =  "1"; Label = "System Characteristics";        Fn = "Invoke-SystemCharacteristics"   ; Category = "SYSTEM"      },
    @{ Number =  "2"; Label = "Hardware Details";               Fn = "Invoke-HardwareDetails"         ; Category = "SYSTEM"      },
    @{ Number =  "3"; Label = "Users";                          Fn = "Invoke-Users"                   ; Category = "SYSTEM"      },
    @{ Number =  "4"; Label = "Performance Snapshot";           Fn = "Invoke-PerformanceSnapshot"     ; Category = "SYSTEM"      },
    @{ Number =  "5"; Label = "Event Log Analysis";             Fn = "Invoke-EventLogAnalysis"        ; Category = "DIAGNOSTICS" },
    @{ Number =  "6"; Label = "Services & Processes";           Fn = "Invoke-ServicesAndProcesses"    ; Category = "DIAGNOSTICS" },
    @{ Number =  "7"; Label = "Software";                       Fn = "Invoke-Software"                ; Category = "DIAGNOSTICS" },
    @{ Number =  "8"; Label = "Startup Programs & Tasks";       Fn = "Invoke-StartupAndTasks"         ; Category = "DIAGNOSTICS" },
    @{ Number =  "9"; Label = "Printers & Print Queues";        Fn = "Invoke-Printers"                ; Category = "DIAGNOSTICS" },
    @{ Number = "10"; Label = "Security";                       Fn = "Invoke-Security"                ; Category = "SECURITY"    },
    @{ Number = "11"; Label = "Remote Management Readiness";    Fn = "Invoke-RemoteManagement"        ; Category = "SECURITY"    },
    @{ Number = "12"; Label = "Group Policy & Time Sync";       Fn = "Invoke-GroupPolicyAndTimeSync"  ; Category = "SECURITY"    },
    @{ Number = "13"; Label = "Proxy, Wi-Fi & VPN";             Fn = "Invoke-ProxyWifiVPN"            ; Category = "NETWORK"     },
    @{ Number = "14"; Label = "Network Diagnostics";            Fn = "Invoke-NetworkDiagnostics"      ; Category = "NETWORK"     }
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
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │                   DIAGNOSTIC MENU                       │" -ForegroundColor Cyan
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Cyan

    $currentCategory = ""
    foreach ($item in $MenuItems) {
        if ($item.Category -ne $currentCategory) {
            $currentCategory = $item.Category
            $catColor = switch ($currentCategory) {
                "SYSTEM"      { "Yellow"  }
                "DIAGNOSTICS" { "Green"   }
                "SECURITY"    { "Red"     }
                "NETWORK"     { "Cyan"    }
                default       { "White"   }
            }
            Write-Host ""
            Write-Host "  ── $currentCategory " -ForegroundColor $catColor -NoNewline
            Write-Host ("─" * (45 - $currentCategory.Length)) -ForegroundColor DarkGray
        }
        Write-Host ("    [{0,2}]  {1}" -f $item.Number, $item.Label) -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  ── TOOLS ───────────────────────────────────────────────────" -ForegroundColor Magenta
    Write-Host "    [ T]  Tools Menu                  Utilities & repair tools" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  ─────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "    [ A]  Run all diagnostic sections" -ForegroundColor White
    Write-Host "    [ Q]  Quit"                        -ForegroundColor White
    Write-Host ""
    Write-Host "  Enter numbers separated by commas, A for all, T for tools, Q to quit." -ForegroundColor DarkGray
    Write-Host "  Examples:  1,2,3   or   10,11,12   or   A   or   T" -ForegroundColor DarkGray
    Write-Host ""

    $selection = Read-Host "  Your selection"

    if ($selection -match '^[Qq]$') {
        Write-Host ""
        Write-Host "  Exiting." -ForegroundColor DarkGray
        $mainMenuActive = $false
        break
    }

    if ($selection -match '^[Tt]$') {
        Invoke-Tools
        continue
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
