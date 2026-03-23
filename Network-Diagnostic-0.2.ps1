#Requires -Version 7.0
<#
.SYNOPSIS
    Network Diagnostic Tool - Performs NSLookup, Ping, and Traceroute diagnostics.

.DESCRIPTION
    Prompts the user for source IP, destination IP, and optional destination port,
    then validates internet connectivity, runs NSLookup on both IPs, pings the
    destination 4 times, and performs a traceroute to the destination.

.NOTES
    Author:           WBE Consulting LLC
    Written by:       Brad Endsley
    Requires:         PowerShell 7.x or later
    Run as Administrator for best results with traceroute.
#>

# ─────────────────────────────────────────────
#  Helper Functions
# ─────────────────────────────────────────────

function Write-Header {
    param([string]$Title)
    $line = "=" * 60
    Write-Host ""
    Write-Host $line -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host $line -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "--- $Title ---" -ForegroundColor Yellow
}

function Test-ValidIP {
    param([string]$IP)
    return ($IP -match '^\d{1,3}(\.\d{1,3}){3}$') -and (
        ($IP -split '\.') | ForEach-Object { [int]$_ -le 255 -and [int]$_ -ge 0 }
    ) -notcontains $false
}

function Test-ValidPort {
    param([string]$Port)
    if ([string]::IsNullOrWhiteSpace($Port)) { return $true }  # Optional field
    return ($Port -match '^\d+$') -and ([int]$Port -ge 1) -and ([int]$Port -le 65535)
}

function Test-ValidHostname {
    # Accepts a plain hostname (e.g. SERVER01) or FQDN (e.g. server.contoso.com)
    param([string]$Name)
    return $Name -match '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
}

function Test-ValidIPorHost {
    param([string]$Value)
    return (Test-ValidIP -IP $Value) -or (Test-ValidHostname -Name $Value)
}

function Resolve-ToIP {
    # Returns the first IPv4 address resolved from a hostname/FQDN, or the IP itself if already an IP.
    param([string]$Value)
    if (Test-ValidIP -IP $Value) { return $Value }
    try {
        $Resolved = [System.Net.Dns]::GetHostAddresses($Value) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1 -ExpandProperty IPAddressToString
        return $Resolved
    } catch {
        return $null
    }
}

# ─────────────────────────────────────────────
#  Banner
# ─────────────────────────────────────────────

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║       WBE Consulting LLC                 ║" -ForegroundColor Cyan
Write-Host "  ║       Network Diagnostic Tool            ║" -ForegroundColor Cyan
Write-Host "  ║       Written by Brad Endsley            ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  This tool will perform:" -ForegroundColor White
Write-Host "    [1] Internet connectivity validation" -ForegroundColor Gray
Write-Host "    [2] NSLookup on source and destination" -ForegroundColor Gray
Write-Host "    [3] Ping destination (4 attempts)" -ForegroundColor Gray
Write-Host "    [4] TCP port test (if port provided)" -ForegroundColor Gray
Write-Host "    [5] SSL certificate info (if destination is an FQDN)" -ForegroundColor Gray
Write-Host "    [6] Traceroute to destination" -ForegroundColor Gray
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  [!] WARNING: Not running as Administrator." -ForegroundColor Red
    Write-Host "      Traceroute results may be limited." -ForegroundColor Red
}

# ─────────────────────────────────────────────
#  User Input
# ─────────────────────────────────────────────

Write-Header "INPUT"

# Source — detect local IPs/hostname and let user choose
Write-Host ""
Write-Host "  Detecting local addresses..." -ForegroundColor DarkGray

$LocalHostname = $env:COMPUTERNAME
$LocalIPs = @(
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {
        $_.IPAddress -notmatch '^127\.' -and
        $_.IPAddress -notmatch '^169\.254\.' -and
        $_.PrefixOrigin -ne 'WellKnown'
    } |
    Select-Object -ExpandProperty IPAddress
)

# Build a menu combining hostname + IPs
$SourceMenuItems = @()
if ($LocalHostname) {
    $SourceMenuItems += @{ Label = "$LocalHostname (this machine's hostname)"; Value = $LocalHostname }
}
foreach ($ip in $LocalIPs) {
    $SourceMenuItems += @{ Label = $ip; Value = $ip }
}

if ($SourceMenuItems.Count -gt 0) {
    Write-Host ""
    Write-Host "  Local source options detected:" -ForegroundColor White
    for ($i = 0; $i -lt $SourceMenuItems.Count; $i++) {
        Write-Host "    [$($i + 1)] $($SourceMenuItems[$i].Label)" -ForegroundColor Green
    }
    Write-Host "    [M] Enter a different IP address or hostname manually" -ForegroundColor Yellow
    Write-Host ""

    $SourceChoice = Read-Host "  Select a source (1-$($SourceMenuItems.Count) or M)"

    if ($SourceChoice -match '^[Mm]$') {
        do {
            $SourceInput = Read-Host "  Enter the Source IP address or hostname"
            if (-not (Test-ValidIPorHost -Value $SourceInput)) {
                Write-Host "  [!] Invalid IP address or hostname. Please try again." -ForegroundColor Red
            }
        } while (-not (Test-ValidIPorHost -Value $SourceInput))
    } elseif ($SourceChoice -match '^\d+$' -and [int]$SourceChoice -ge 1 -and [int]$SourceChoice -le $SourceMenuItems.Count) {
        $SourceInput = $SourceMenuItems[[int]$SourceChoice - 1].Value
        Write-Host "  Using: $SourceInput" -ForegroundColor Green
    } else {
        Write-Host "  [!] Invalid selection. Falling back to manual entry." -ForegroundColor Yellow
        do {
            $SourceInput = Read-Host "  Enter the Source IP address or hostname"
            if (-not (Test-ValidIPorHost -Value $SourceInput)) {
                Write-Host "  [!] Invalid IP address or hostname. Please try again." -ForegroundColor Red
            }
        } while (-not (Test-ValidIPorHost -Value $SourceInput))
    }
} else {
    Write-Host "  [!] Could not detect local addresses. Please enter manually." -ForegroundColor Yellow
    do {
        $SourceInput = Read-Host "  Enter the Source IP address or hostname"
        if (-not (Test-ValidIPorHost -Value $SourceInput)) {
            Write-Host "  [!] Invalid IP address or hostname. Please try again." -ForegroundColor Red
        }
    } while (-not (Test-ValidIPorHost -Value $SourceInput))
}

# Resolve source to IP if a hostname was entered
$SourceIP = Resolve-ToIP -Value $SourceInput
if ($null -eq $SourceIP) {
    Write-Host "  [!] WARNING: Could not resolve '$SourceInput' to an IP address." -ForegroundColor Yellow
    Write-Host "      NSLookup will still be attempted using the entered value." -ForegroundColor Yellow
    $SourceIP = $SourceInput   # Use as-is; nslookup can still attempt it
}
$SourceDisplay = if ($SourceInput -eq $SourceIP) { $SourceIP } else { "$SourceInput ($SourceIP)" }

# Destination — IP address or FQDN
do {
    $DestInput = Read-Host "  Enter the Destination IP address or FQDN"
    if (-not (Test-ValidIPorHost -Value $DestInput)) {
        Write-Host "  [!] Invalid IP address or FQDN. Please try again." -ForegroundColor Red
    }
} while (-not (Test-ValidIPorHost -Value $DestInput))

# Resolve destination to IP
$DestIP = Resolve-ToIP -Value $DestInput
if ($null -eq $DestIP) {
    Write-Host "  [!] WARNING: Could not resolve '$DestInput' to an IP address." -ForegroundColor Yellow
    Write-Host "      Ping and traceroute will use the entered value directly." -ForegroundColor Yellow
    $DestIP = $DestInput
}
$DestDisplay = if ($DestInput -eq $DestIP) { $DestIP } else { "$DestInput ($DestIP)" }

# Determine if destination is an FQDN (contains a dot and is not a plain IP)
$DestIsFQDN = (-not (Test-ValidIP -IP $DestInput)) -and ($DestInput -match '\.')

# Destination Port (optional)
do {
    $DestPort = Read-Host "  Enter the Destination Port (press Enter to skip)"
    if (-not (Test-ValidPort -Port $DestPort)) {
        Write-Host "  [!] Invalid port. Must be between 1-65535. Please try again." -ForegroundColor Red
    }
} while (-not (Test-ValidPort -Port $DestPort))

$PortDisplay = if ([string]::IsNullOrWhiteSpace($DestPort)) { "Not specified" } else { $DestPort }

# DNS Server Selection
Write-Host ""
Write-Host "  Detecting locally configured DNS servers..." -ForegroundColor DarkGray

$LocalDNSServers = @(
    Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses.Count -gt 0 } |
    Select-Object -ExpandProperty ServerAddresses |
    Where-Object { $_ -notmatch '^127\.' } |
    Select-Object -Unique
)

$DnsMenuItems = @()

# Add local DNS servers to menu
foreach ($dns in $LocalDNSServers) {
    $DnsMenuItems += @{ Label = "$dns (local)"; Value = $dns }
}

# Add well-known external DNS options
$DnsMenuItems += @{ Label = "8.8.8.8   — Google Primary";     Value = "8.8.8.8"   }
$DnsMenuItems += @{ Label = "8.8.4.4   — Google Secondary";   Value = "8.8.4.4"   }
$DnsMenuItems += @{ Label = "1.1.1.1   — Cloudflare Primary"; Value = "1.1.1.1"   }
$DnsMenuItems += @{ Label = "1.0.0.1   — Cloudflare Secondary"; Value = "1.0.0.1" }
$DnsMenuItems += @{ Label = "9.9.9.9   — Quad9";              Value = "9.9.9.9"   }

Write-Host ""
Write-Host "  Select DNS server for NSLookup queries:" -ForegroundColor White
for ($i = 0; $i -lt $DnsMenuItems.Count; $i++) {
    $Color = if ($DnsMenuItems[$i].Label -match 'local') { "Green" } else { "Yellow" }
    Write-Host "    [$($i + 1)] $($DnsMenuItems[$i].Label)" -ForegroundColor $Color
}
Write-Host "    [M] Enter a DNS server IP manually" -ForegroundColor Cyan
Write-Host ""

$DnsChoice = Read-Host "  Select DNS server (1-$($DnsMenuItems.Count) or M)"

if ($DnsChoice -match '^[Mm]$') {
    do {
        $DnsServer = Read-Host "  Enter DNS server IP address"
        if (-not (Test-ValidIP -IP $DnsServer)) {
            Write-Host "  [!] Invalid IP address. Please try again." -ForegroundColor Red
        }
    } while (-not (Test-ValidIP -IP $DnsServer))
    $DnsDisplay = "$DnsServer (manual)"
} elseif ($DnsChoice -match '^\d+$' -and [int]$DnsChoice -ge 1 -and [int]$DnsChoice -le $DnsMenuItems.Count) {
    $DnsServer  = $DnsMenuItems[[int]$DnsChoice - 1].Value
    $DnsDisplay = $DnsMenuItems[[int]$DnsChoice - 1].Label
    Write-Host "  Using DNS: $DnsDisplay" -ForegroundColor Green
} else {
    Write-Host "  [!] Invalid selection. Defaulting to system DNS." -ForegroundColor Yellow
    $DnsServer  = $null
    $DnsDisplay = "System default"
}

# Confirm
Write-Host ""
Write-Host "  ┌──────────────────────────────────────────────┐" -ForegroundColor White
Write-Host "  │  Source      : $SourceDisplay" -ForegroundColor White
Write-Host "  │  Destination : $DestDisplay" -ForegroundColor White
Write-Host "  │  Dest Port   : $PortDisplay" -ForegroundColor White
Write-Host "  │  DNS Server  : $DnsDisplay" -ForegroundColor White
Write-Host "  └──────────────────────────────────────────────┘" -ForegroundColor White
Write-Host ""
$Confirm = Read-Host "  Proceed with diagnostics? (Y/N)"
if ($Confirm -notmatch '^[Yy]') {
    Write-Host "  Aborted." -ForegroundColor Red
    exit
}

# ─────────────────────────────────────────────
#  Timestamp
# ─────────────────────────────────────────────

$Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$LogTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogHostname  = $env:COMPUTERNAME
$TempLog      = [System.IO.Path]::GetTempFileName()

# Begin capturing all output to a temp file
Start-Transcript -Path $TempLog -Force | Out-Null

Write-Host ""
Write-Host "  Started: $Timestamp" -ForegroundColor DarkGray

# ─────────────────────────────────────────────
#  1. Internet Connectivity Validation
# ─────────────────────────────────────────────

Write-Header "Internet Connectivity Validation"

# Define test targets: well-known public IPs and DNS names
$InternetTargets = @(
    @{ Label = "Google DNS (8.8.8.8)";      Host = "8.8.8.8" },
    @{ Label = "Cloudflare DNS (1.1.1.1)";  Host = "1.1.1.1" },
    @{ Label = "Google (google.com)";        Host = "google.com" },
    @{ Label = "Microsoft (microsoft.com)";  Host = "microsoft.com" }
)

$InternetPassCount = 0

foreach ($Target in $InternetTargets) {
    try {
        $Result = Test-Connection -ComputerName $Target.Host -Count 1 -Quiet -ErrorAction Stop
        if ($Result) {
            Write-Host "  [+] PASS  $($Target.Label)" -ForegroundColor Green
            $InternetPassCount++
        } else {
            Write-Host "  [-] FAIL  $($Target.Label)" -ForegroundColor Red
        }
    } catch {
        Write-Host "  [!] ERROR $($Target.Label) — $_" -ForegroundColor Red
    }
}

Write-Host ""
if ($InternetPassCount -eq $InternetTargets.Count) {
    Write-Host "  [✓] Internet connectivity: FULL ($InternetPassCount/$($InternetTargets.Count) targets reachable)" -ForegroundColor Green
} elseif ($InternetPassCount -gt 0) {
    Write-Host "  [~] Internet connectivity: PARTIAL ($InternetPassCount/$($InternetTargets.Count) targets reachable)" -ForegroundColor Yellow
    Write-Host "      Some traffic may be blocked by firewall or DNS filtering." -ForegroundColor Yellow
} else {
    Write-Host "  [✗] Internet connectivity: NONE (0/$($InternetTargets.Count) targets reachable)" -ForegroundColor Red
    Write-Host "      No internet access detected. Remaining tests will still run." -ForegroundColor Red
}

# DNS Resolution check
Write-Section "Public DNS Resolution Test"
$DnsTestHosts = @("google.com", "cloudflare.com")
foreach ($DnsHost in $DnsTestHosts) {
    try {
        $DnsResult = [System.Net.Dns]::GetHostAddresses($DnsHost)
        $ResolvedIPs = $DnsResult | ForEach-Object { $_.IPAddressToString }
        Write-Host "  [+] $DnsHost resolved to: $($ResolvedIPs -join ', ')" -ForegroundColor Green
    } catch {
        Write-Host "  [-] $DnsHost failed to resolve — DNS may be broken or blocked" -ForegroundColor Red
    }
}

# HTTP/HTTPS reachability check
Write-Section "HTTP/HTTPS Reachability Test"
$HttpTargets = @(
    @{ Label = "http://detectportal.firefox.com/success.txt" },
    @{ Label = "https://clients3.google.com/generate_204" },
    @{ Label = "https://www.cloudflare.com/cdn-cgi/trace" }
)
foreach ($Http in $HttpTargets) {
    try {
        $Response = Invoke-WebRequest -Uri $Http.Label -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($Response.StatusCode -in 200, 204) {
            Write-Host "  [+] PASS  $($Http.Label) (HTTP $($Response.StatusCode))" -ForegroundColor Green
        } else {
            Write-Host "  [-] WARN  $($Http.Label) (HTTP $($Response.StatusCode))" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [-] FAIL  $($Http.Label) — $_" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
#  2. NSLookup
# ─────────────────────────────────────────────

Write-Header "NSLookup  (DNS: $DnsDisplay)"

# Build nslookup argument — append DNS server if one was selected
$NsArgs = if ($DnsServer) { @($SourceInput, $DnsServer) } else { @($SourceInput) }

Write-Section "NSLookup: Source ($SourceDisplay)"
try {
    $NsSource = nslookup @NsArgs 2>&1
    $NsSource | ForEach-Object { Write-Host "  $_" }
} catch {
    Write-Host "  [!] NSLookup failed for $SourceInput : $_" -ForegroundColor Red
}

$NsArgs = if ($DnsServer) { @($DestInput, $DnsServer) } else { @($DestInput) }

Write-Section "NSLookup: Destination ($DestDisplay)"
try {
    $NsDest = nslookup @NsArgs 2>&1
    $NsDest | ForEach-Object { Write-Host "  $_" }
} catch {
    Write-Host "  [!] NSLookup failed for $DestInput : $_" -ForegroundColor Red
}

# ─────────────────────────────────────────────
#  3. Ping (4 attempts)
# ─────────────────────────────────────────────

Write-Header "Ping: $DestDisplay (4 packets)"

try {
    $PingResults = ping $DestIP -n 4 2>&1
    $PingResults | ForEach-Object { Write-Host "  $_" }
} catch {
    Write-Host "  [!] Ping failed: $_" -ForegroundColor Red
}

# ─────────────────────────────────────────────
#  4. Port Connectivity Test (if port provided)
# ─────────────────────────────────────────────

if (-not [string]::IsNullOrWhiteSpace($DestPort)) {
    Write-Header "TCP Port Test: $DestIP : $DestPort"

    try {
        $TcpClient = New-Object System.Net.Sockets.TcpClient
        $AsyncResult = $TcpClient.BeginConnect($DestIP, [int]$DestPort, $null, $null)
        $Wait = $AsyncResult.AsyncWaitHandle.WaitOne(3000, $false)

        if ($Wait -and $TcpClient.Connected) {
            Write-Host "  [+] TCP Port $DestPort on $DestIP is OPEN / REACHABLE" -ForegroundColor Green
        } else {
            Write-Host "  [-] TCP Port $DestPort on $DestIP is CLOSED or FILTERED (timeout)" -ForegroundColor Red
        }
        $TcpClient.Close()
    } catch {
        Write-Host "  [!] Port test error: $_" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
#  5. SSL Certificate Info (FQDN destinations only)
# ─────────────────────────────────────────────

if ($DestIsFQDN) {
    # Use port 443 by default; if user specified a port use that instead
    $SslPort = if (-not [string]::IsNullOrWhiteSpace($DestPort)) { [int]$DestPort } else { 443 }

    Write-Header "SSL Certificate: $DestInput (port $SslPort)"

    try {
        $TcpConn   = New-Object System.Net.Sockets.TcpClient
        $ConnAsync = $TcpConn.BeginConnect($DestInput, $SslPort, $null, $null)
        $Connected = $ConnAsync.AsyncWaitHandle.WaitOne(5000, $false)

        if (-not $Connected -or -not $TcpConn.Connected) {
            Write-Host "  [!] Could not connect to $DestInput on port $SslPort — SSL check skipped." -ForegroundColor Red
            $TcpConn.Close()
        } else {
            $TcpConn.EndConnect($ConnAsync)
            $SslStream = New-Object System.Net.Security.SslStream(
                $TcpConn.GetStream(), $false,
                { param($s, $cert, $chain, $errors) $true }   # Accept all certs so we can still inspect expired/self-signed
            )
            $SslStream.AuthenticateAsClient($DestInput)
            $Cert = $SslStream.RemoteCertificate

            if ($null -eq $Cert) {
                Write-Host "  [!] No certificate returned by the server." -ForegroundColor Red
            } else {
                # Cast to X509Certificate2 for richer properties
                $Cert2        = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $Cert
                $NotBefore    = [datetime]::Parse($Cert2.GetEffectiveDateString())
                $NotAfter     = [datetime]::Parse($Cert2.GetExpirationDateString())
                $DaysLeft     = ($NotAfter - (Get-Date)).Days
                $Protocol     = $SslStream.SslProtocol
                $CipherAlg    = $SslStream.CipherAlgorithm
                $KeyExch      = $SslStream.KeyExchangeAlgorithm

                # Parse Subject Alternative Names
                $SANExtension = $Cert2.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                $SANText      = if ($SANExtension) { $SANExtension.Format($false) } else { "Not present" }

                # Expiry color coding
                $ExpiryColor = if ($DaysLeft -lt 0) { "Red" }
                               elseif ($DaysLeft -le 14) { "Red" }
                               elseif ($DaysLeft -le 30) { "Yellow" }
                               else { "Green" }

                Write-Host "  Subject          : $($Cert2.Subject)" -ForegroundColor White
                Write-Host "  Issuer           : $($Cert2.Issuer)" -ForegroundColor White
                Write-Host "  Serial Number    : $($Cert2.SerialNumber)" -ForegroundColor White
                Write-Host "  Thumbprint       : $($Cert2.Thumbprint)" -ForegroundColor White
                Write-Host "  Valid From       : $($NotBefore.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
                Write-Host "  Valid To         : $($NotAfter.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor $ExpiryColor
                Write-Host "  Days Until Expiry: $DaysLeft" -ForegroundColor $ExpiryColor

                if ($DaysLeft -lt 0) {
                    Write-Host "  [!] CERTIFICATE IS EXPIRED" -ForegroundColor Red
                } elseif ($DaysLeft -le 14) {
                    Write-Host "  [!] WARNING: Certificate expires very soon!" -ForegroundColor Red
                } elseif ($DaysLeft -le 30) {
                    Write-Host "  [~] NOTICE: Certificate expires within 30 days." -ForegroundColor Yellow
                } else {
                    Write-Host "  [+] Certificate is valid." -ForegroundColor Green
                }

                Write-Host "  TLS Protocol     : $Protocol" -ForegroundColor White
                Write-Host "  Cipher Algorithm : $CipherAlg" -ForegroundColor White
                Write-Host "  Key Exchange     : $KeyExch" -ForegroundColor White
                Write-Host "  SAN Entries      : $SANText" -ForegroundColor White
                Write-Host "  Key Size (bits)  : $($Cert2.PublicKey.Key.KeySize)" -ForegroundColor White
                Write-Host "  Signature Alg    : $($Cert2.SignatureAlgorithm.FriendlyName)" -ForegroundColor White
            }

            $SslStream.Close()
            $TcpConn.Close()
        }
    } catch {
        Write-Host "  [!] SSL certificate check failed: $_" -ForegroundColor Red
    }
}

# ─────────────────────────────────────────────
#  6. Traceroute
# ─────────────────────────────────────────────

Write-Header "Traceroute: $DestDisplay"
Write-Host "  (This may take a moment...)" -ForegroundColor DarkGray

try {
    $TraceResults = tracert $DestIP 2>&1
    $TraceResults | ForEach-Object { Write-Host "  $_" }
} catch {
    Write-Host "  [!] Traceroute failed: $_" -ForegroundColor Red
}

# ─────────────────────────────────────────────
#  Done
# ─────────────────────────────────────────────

Write-Header "DIAGNOSTICS COMPLETE"
Write-Host "  Source       : $SourceDisplay" -ForegroundColor White
Write-Host "  Destination  : $DestDisplay" -ForegroundColor White
Write-Host "  Port         : $PortDisplay" -ForegroundColor White
Write-Host "  DNS Server   : $DnsDisplay" -ForegroundColor White
Write-Host "  Completed    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ""

# Stop transcript before prompting (keeps the prompt itself out of the log)
Stop-Transcript | Out-Null

# ─────────────────────────────────────────────
#  Save Log?
# ─────────────────────────────────────────────

$SaveLog = Read-Host "  Save output to a log file? (Y/N)"
if ($SaveLog -match '^[Yy]') {
    $LogFileName = "$LogHostname-netdiag-$LogTimestamp.log"
    $LogPath     = Join-Path -Path $PSScriptRoot -ChildPath $LogFileName

    try {
        Copy-Item -Path $TempLog -Destination $LogPath -Force
        Write-Host ""
        Write-Host "  [+] Log saved to:" -ForegroundColor Green
        Write-Host "      $LogPath" -ForegroundColor White
    } catch {
        Write-Host ""
        Write-Host "  [!] Failed to save log: $_" -ForegroundColor Red
        Write-Host "      Temp copy available at: $TempLog" -ForegroundColor Yellow
    }
} else {
    Write-Host ""
    Write-Host "  Log not saved." -ForegroundColor DarkGray
}

# Clean up temp file
if (Test-Path $TempLog) {
    Remove-Item $TempLog -Force -ErrorAction SilentlyContinue
}

Write-Host ""
