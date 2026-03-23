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
}

# ── 3. Users ────────────────────────────────────────────────────
function Invoke-Users {
    param([switch]$NoScreen)

    Write-LogHeader "3. Users" -NoScreen:$NoScreen

    $currentUser = "$($env:USERDOMAIN)\$($env:USERNAME)"
    $adAvailable = $false

    # Try Active Directory first
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
                $isCurrentMarker = if ($u.SamAccountName -eq $env:USERNAME) { "  ◄ CURRENT USER" } else { "" }
                $status          = if ($u.Enabled) { "Enabled" } else { "Disabled" }
                $locked          = if ($u.LockedOut) { "  [LOCKED]" } else { "" }
                $pwExp           = if ($u.PasswordExpired) { "  [PW EXPIRED]" } else { "" }
                $lastLogon       = if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
                $pwSet           = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }

                Write-Log "  [$status$locked$pwExp] $($u.SamAccountName)$isCurrentMarker" -NoScreen:$NoScreen
                if ($u.DisplayName)   { Write-Log "    Display Name  : $($u.DisplayName)"   -NoScreen:$NoScreen }
                if ($u.Title)         { Write-Log "    Title         : $($u.Title)"          -NoScreen:$NoScreen }
                if ($u.Department)    { Write-Log "    Department    : $($u.Department)"     -NoScreen:$NoScreen }
                if ($u.EmailAddress)  { Write-Log "    Email         : $($u.EmailAddress)"   -NoScreen:$NoScreen }
                Write-Log "    Last Logon    : $lastLogon"   -NoScreen:$NoScreen
                Write-Log "    PW Last Set   : $pwSet"       -NoScreen:$NoScreen
                Write-Log "" -NoScreen:$NoScreen
            }

            Write-Log "  Total AD users: $($adUsers.Count)" -NoScreen:$NoScreen

        } catch {
            Write-Log "  [!] Failed to query AD users: $_" -NoScreen:$NoScreen
            $adAvailable = $false
        }
    }

    if (-not $adAvailable) {
        Write-LogSection "Local Users (AD unavailable or not joined)" -NoScreen:$NoScreen
        Write-Log "  (Source: Local machine)" -NoScreen:$NoScreen
        Write-Log "" -NoScreen:$NoScreen

        try {
            $localUsers = Get-LocalUser | Sort-Object Name
            foreach ($u in $localUsers) {
                $isCurrentMarker = if ($u.Name -eq $env:USERNAME) { "  ◄ CURRENT USER" } else { "" }
                $status          = if ($u.Enabled) { "Enabled" } else { "Disabled" }
                $lastLogon       = if ($u.LastLogon) { $u.LastLogon.ToString('yyyy-MM-dd HH:mm') } else { "Never" }
                $pwChange        = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { "N/A" }

                Write-Log "  [$status] $($u.Name)$isCurrentMarker"   -NoScreen:$NoScreen
                Write-Log "    Full Name     : $($u.FullName)"        -NoScreen:$NoScreen
                Write-Log "    Last Logon    : $lastLogon"            -NoScreen:$NoScreen
                Write-Log "    PW Last Set   : $pwChange"             -NoScreen:$NoScreen
                Write-Log "    Description   : $($u.Description)"     -NoScreen:$NoScreen
                Write-Log "" -NoScreen:$NoScreen
            }
            Write-Log "  Total local users: $($localUsers.Count)" -NoScreen:$NoScreen
        } catch {
            Write-Log "  [!] Failed to query local users: $_" -NoScreen:$NoScreen
        }
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

    Write-LogHeader "6. Network Diagnostics" -NoScreen:$NoScreen

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
            @{ Label = "Google DNS (8.8.8.8)";     Host = "8.8.8.8"      },
            @{ Label = "Cloudflare DNS (1.1.1.1)"; Host = "1.1.1.1"      },
            @{ Label = "Google (google.com)";       Host = "google.com"   },
            @{ Label = "Microsoft (microsoft.com)"; Host = "microsoft.com"}
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
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════

$MenuItems = @(
    @{ Number = "1"; Label = "System Characteristics";   Fn = "Invoke-SystemCharacteristics"  },
    @{ Number = "2"; Label = "Hardware Details";          Fn = "Invoke-HardwareDetails"        },
    @{ Number = "3"; Label = "Users";                     Fn = "Invoke-Users"                  },
    @{ Number = "4"; Label = "Event Log Analysis";        Fn = "Invoke-EventLogAnalysis"       },
    @{ Number = "5"; Label = "Services & Processes";      Fn = "Invoke-ServicesAndProcesses"   },
    @{ Number = "6"; Label = "Network Diagnostics";       Fn = "Invoke-NetworkDiagnostics"     }
)

Write-Host "  Available diagnostics:" -ForegroundColor White
Write-Host ""
foreach ($item in $MenuItems) {
    Write-Host "    [$($item.Number)]  $($item.Label)" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Enter section numbers separated by commas, or A for all." -ForegroundColor DarkGray
Write-Host "  Example: 1,3,6  or  A" -ForegroundColor DarkGray
Write-Host ""

$selection = Read-Host "  Your selection"

if ($selection -match '^[Aa]$') {
    $selectedNumbers = $MenuItems | ForEach-Object { $_.Number }
} else {
    $selectedNumbers = $selection -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
}

$selectedItems = $MenuItems | Where-Object { $_.Number -in $selectedNumbers }

if ($selectedItems.Count -eq 0) {
    Write-Host "  [!] No valid selections made. Exiting." -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "  Selected sections:" -ForegroundColor White
foreach ($item in $selectedItems) {
    Write-Host "    [+] $($item.Number). $($item.Label)" -ForegroundColor Green
}
Write-Host ""
$confirm = Read-Host "  Proceed? (Y/N)"
if ($confirm -notmatch '^[Yy]') {
    Write-Host "  Aborted." -ForegroundColor Red
    exit
}

# ═══════════════════════════════════════════════════════════════
#  EXECUTION
# ═══════════════════════════════════════════════════════════════

# Initialise the global log buffer — every section writes here regardless of display choice
$script:LogBuffer = [System.Collections.Generic.List[string]]::new()

$runTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logHostname  = $env:COMPUTERNAME

# Write log file header (always)
$script:LogBuffer.Add("WBE Consulting LLC — System & Network Diagnostic Tool")
$script:LogBuffer.Add("Written by Brad Endsley")
$script:LogBuffer.Add("Run at   : $runTimestamp")
$script:LogBuffer.Add("Hostname : $logHostname")
$script:LogBuffer.Add("User     : $($env:USERDOMAIN)\$($env:USERNAME)")
$script:LogBuffer.Add("")

Write-Host ""
Write-Host "  Started: $runTimestamp" -ForegroundColor DarkGray

foreach ($item in $selectedItems) {
    Write-Host ""
    Write-Host "  Running: $($item.Number). $($item.Label)..." -ForegroundColor DarkGray

    # All sections run with screen output (NoScreen:$false)
    # Sections NOT selected are also run silently for the log
    & $item.Fn
}

# Run unselected sections silently for the log
$unselectedItems = $MenuItems | Where-Object { $_.Number -notin $selectedNumbers }
foreach ($item in $unselectedItems) {
    # Network diagnostics requires interactive input — cannot run silently
    if ($item.Fn -eq "Invoke-NetworkDiagnostics") { continue }
    & $item.Fn -NoScreen
}

# ═══════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════

Write-Header "COMPLETE"
Write-Host "  Sections run    : $($selectedItems.Label -join ', ')" -ForegroundColor White
Write-Host "  Completed       : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"  -ForegroundColor DarkGray
Write-Host ""

$script:LogBuffer.Add("")
$script:LogBuffer.Add("=" * 60)
$script:LogBuffer.Add("  RUN COMPLETE")
$script:LogBuffer.Add("  Sections : $($selectedItems.Label -join ', ')")
$script:LogBuffer.Add("  Finished : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
$script:LogBuffer.Add("=" * 60)

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
