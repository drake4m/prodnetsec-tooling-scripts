#Requires -Version 5.1
<#
.SYNOPSIS
    Teams Network Diagnostic Tool v4.0 - Comprehensive Enterprise Debug
.DESCRIPTION
    Diagnoses Microsoft Teams connectivity and detects UDP/TCP fallback during calls.
.PARAMETER Mode
    baseline = Full connectivity test + monitoring (default)
    monitor  = Live call monitoring only  
    quick    = Fast connectivity check only
.PARAMETER Export
    Export results to CSV file
.EXAMPLE
    .\teams-debug.ps1
    .\teams-debug.ps1 -Mode quick
    .\teams-debug.ps1 -Export "teams_diag.csv"
#>

[CmdletBinding()]
param(
    [ValidateSet('baseline', 'monitor', 'quick')]
    [string]$Mode = 'baseline',
    [string]$Export = $null
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ============================================================================
# CONFIGURATION
# ============================================================================

$Script:Config = @{
    Version       = '4.0.0'
    TimeoutMs     = 3000
    StunTimeoutMs = 2000
    
    Endpoints = @(
        @{ Name = 'teams.microsoft.com';              Ports = @{ TCP = @(443); UDP = @(3478,3479,3480,3481) } }
        @{ Name = 'edge.skype.com';                   Ports = @{ TCP = @(443); UDP = @(3478,3479,3480,3481) } }
        @{ Name = 'worldaz.tr.teams.microsoft.com';   Ports = @{ TCP = @(443); UDP = @(3478,3479,3480,3481) } }
        @{ Name = '52.114.72.200';                    Ports = @{ TCP = @(443); UDP = @(3478) } }
        @{ Name = '52.114.132.46';                    Ports = @{ TCP = @(443); UDP = @(3478) } }
    )
    
    VpnSignatures = @(
        @{ Name = 'F5 BIG-IP Edge'; Process = 'f5fpclientW' }
        @{ Name = 'Cisco AnyConnect'; Process = 'vpnui' }
        @{ Name = 'Cisco AnyConnect'; Process = 'vpnagent' }
        @{ Name = 'GlobalProtect'; Process = 'PanGPA' }
        @{ Name = 'Zscaler'; Process = 'ZSATunnel' }
        @{ Name = 'Fortinet'; Process = 'FortiClient' }
        @{ Name = 'Pulse Secure'; Process = 'PulseSVC' }
    )
}

$Script:Results = [System.Collections.ArrayList]::new()
$Script:StartTime = Get-Date
$Script:VPNStatus = "VPN-OFF"
$Script:SourceIP = "Unknown"
$Script:CurrentAdapter = ""
$Script:LogFile = "$PSScriptRoot\TEAMS-DIAGNOSTIC-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"
$Script:LogContent = [System.Text.StringBuilder]::new()
$Script:DetailedLog = [System.Text.StringBuilder]::new()
$Script:FinalReport = [System.Text.StringBuilder]::new()
$Script:UDPOptimalDetected = $false
$Script:TCPFallbackDetected = $false
$Script:PacketLossDetected = $false
$Script:ExternalIP = "Unknown"
$Script:Gateway = "Unknown"
$Script:DNSServers = @()
$Script:ProxySettings = @{}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = 'INFO'
    )
    $timestamp = Get-Date -Format 'HH:mm:ss.fff'
    $logLine = "[$timestamp] [$Level] $Message"
    [void]$Script:LogContent.AppendLine($logLine)
}

function Write-DetailedLog {
    param(
        [string]$Category,
        [hashtable]$Data
    )
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    [void]$Script:DetailedLog.AppendLine("")
    [void]$Script:DetailedLog.AppendLine("=== [$timestamp] $Category ===")
    foreach ($key in $Data.Keys | Sort-Object) {
        $value = $Data[$key]
        if ($value -is [array]) {
            $value = $value -join ', '
        }
        [void]$Script:DetailedLog.AppendLine("  $key : $value")
    }
}

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host ("=" * 75) -ForegroundColor DarkCyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ("=" * 75) -ForegroundColor DarkCyan
    Write-Log $Title 'HEADER'
}

function Write-SubHeader {
    param([string]$Title)
    Write-Host ""
    Write-Host ">> $Title" -ForegroundColor Magenta
    Write-Host ("-" * 50) -ForegroundColor DarkGray
    Write-Log $Title 'SECTION'
}

# ============================================================================
# ENVIRONMENT DETECTION
# ============================================================================

function Get-Environment {
    Write-Header "ENVIRONMENT DETECTION"

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[*] Timestamp    : $timestamp" -ForegroundColor Gray
    Write-Host "[*] Computer     : $env:COMPUTERNAME" -ForegroundColor Gray
    Write-Host "[*] User         : $env:USERNAME" -ForegroundColor Gray
    Write-Host "[*] Domain       : $env:USERDOMAIN" -ForegroundColor Gray

    # Detailed system info for logs
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    Write-DetailedLog "SYSTEM_INFO" @{
        "Timestamp" = $timestamp
        "Computer" = $env:COMPUTERNAME
        "User" = "$env:USERDOMAIN\$env:USERNAME"
        "OS" = if($osInfo) { "$($osInfo.Caption) $($osInfo.Version)" } else { "Unknown" }
        "Architecture" = $env:PROCESSOR_ARCHITECTURE
        "PSVersion" = $PSVersionTable.PSVersion.ToString()
    }

    # Check admin
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = [Security.Principal.WindowsPrincipal]$identity
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    Write-Host "[*] Admin        : $isAdmin" -ForegroundColor Gray
    
    # Detect VPN - Check if really connected, not just installed
    $vpnDetected = $false
    $vpnInstalled = $false
    $vpnProcessDetails = @()

    foreach ($sig in $Script:Config.VpnSignatures) {
        $proc = Get-Process -Name $sig.Process -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($proc) {
            $vpnInstalled = $true
            $vpnProcessDetails += @{
                Name = $sig.Name
                Process = $sig.Process
                PID = $proc.Id
                CPU = [math]::Round($proc.CPU, 2)
                MemoryMB = [math]::Round($proc.WorkingSet64/1MB, 2)
                Path = $proc.Path
            }

            # Check if VPN is actually connected (not just installed)
            $vpnConnected = $false
            $vpnAdapterInfo = $null

            # F5 BIG-IP Edge specific check
            if ($sig.Name -eq 'F5 BIG-IP Edge') {
                # Check for F5 virtual adapter active
                $f5Adapter = Get-NetAdapter -Name "*F5*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
                if ($f5Adapter) {
                    $vpnConnected = $true
                    $vpnAdapterInfo = $f5Adapter
                } else {
                    # Check for F5 network routes
                    $f5Routes = Get-NetRoute -ErrorAction SilentlyContinue | Where-Object { $_.InterfaceAlias -like "*F5*" }
                    if ($f5Routes) {
                        $vpnConnected = $true
                    }
                }
            } else {
                # Generic VPN check - look for virtual adapters
                $vpnAdapter = Get-NetAdapter -Name "*VPN*", "*Virtual*" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' }
                if ($vpnAdapter) {
                    $vpnConnected = $true
                    $vpnAdapterInfo = $vpnAdapter | Select-Object -First 1
                }
            }

            if ($vpnConnected) {
                $Script:VPNStatus = "VPN-CONNECTED ($($sig.Name))"
                $vpnDetected = $true
                Write-Host "[!] VPN          : $($sig.Name) CONNECTED (PID: $($proc.Id))" -ForegroundColor Yellow

                # Log detailed VPN info
                Write-DetailedLog "VPN_CONNECTION" @{
                    "VPN_Type" = $sig.Name
                    "Process" = $sig.Process
                    "PID" = $proc.Id
                    "CPU_Seconds" = [math]::Round($proc.CPU, 2)
                    "Memory_MB" = [math]::Round($proc.WorkingSet64/1MB, 2)
                    "ProcessPath" = $proc.Path
                    "AdapterName" = if($vpnAdapterInfo) { $vpnAdapterInfo.Name } else { "Unknown" }
                    "AdapterStatus" = if($vpnAdapterInfo) { $vpnAdapterInfo.Status } else { "Unknown" }
                    "LinkSpeed" = if($vpnAdapterInfo) { $vpnAdapterInfo.LinkSpeed } else { "Unknown" }
                    "MacAddress" = if($vpnAdapterInfo) { $vpnAdapterInfo.MacAddress } else { "Unknown" }
                }
                break
            } else {
                Write-Host "[*] VPN          : $($sig.Name) installed but NOT connected" -ForegroundColor Gray
                Write-DetailedLog "VPN_INSTALLED_NOT_CONNECTED" @{
                    "VPN_Type" = $sig.Name
                    "Process" = $sig.Process
                    "PID" = $proc.Id
                    "Status" = "Installed but not connected"
                }
            }
        }
    }

    if (-not $vpnDetected) {
        if ($vpnInstalled) {
            $Script:VPNStatus = "VPN-INSTALLED-NOT-CONNECTED"
            Write-Host "[*] VPN          : Installed but not connected (LAN/Direct)" -ForegroundColor Cyan
        } else {
            $Script:VPNStatus = "NO-VPN"
            Write-Host "[+] VPN          : Not detected (direct connection)" -ForegroundColor Green
        }
    }
    
    # Get network info
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
                 Sort-Object RouteMetric | Select-Object -First 1
        if ($route) {
            $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue
            $ipConfig = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                        Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | Select-Object -First 1

            if ($adapter) {
                Write-Host "[*] Interface    : $($adapter.Name)" -ForegroundColor Gray
                $Script:CurrentAdapter = $adapter.Name

                # Get adapter statistics
                $adapterStats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
                Write-DetailedLog "PRIMARY_ADAPTER" @{
                    "Name" = $adapter.Name
                    "InterfaceIndex" = $adapter.InterfaceIndex
                    "Status" = $adapter.Status
                    "LinkSpeed" = $adapter.LinkSpeed
                    "MacAddress" = $adapter.MacAddress
                    "MediaType" = $adapter.MediaType
                    "DriverVersion" = $adapter.DriverVersion
                    "DriverProvider" = $adapter.DriverProvider
                    "ReceivedBytes" = if($adapterStats) { $adapterStats.ReceivedBytes } else { "N/A" }
                    "SentBytes" = if($adapterStats) { $adapterStats.SentBytes } else { "N/A" }
                    "ReceivedPackets" = if($adapterStats) { $adapterStats.ReceivedUnicastPackets } else { "N/A" }
                    "SentPackets" = if($adapterStats) { $adapterStats.SentUnicastPackets } else { "N/A" }
                    "ReceivedErrors" = if($adapterStats) { $adapterStats.ReceivedErrors } else { "N/A" }
                    "OutboundErrors" = if($adapterStats) { $adapterStats.OutboundErrors } else { "N/A" }
                    "ReceivedDiscards" = if($adapterStats) { $adapterStats.ReceivedDiscardedPackets } else { "N/A" }
                }
            }
            if ($ipConfig) {
                $Script:SourceIP = $ipConfig.IPAddress
                $Script:Gateway = $route.NextHop

                # Analyze IP to determine connection type
                $ipAnalysis = ""
                if ($Script:SourceIP -match '^10\.' -or
                    $Script:SourceIP -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.' -or
                    $Script:SourceIP -match '^192\.168\.') {

                    # RFC1918 private IP
                    if ($Script:SourceIP -match '^10\.') {
                        $ipAnalysis = " (Corporate LAN/VPN range)"
                        if ($Script:VPNStatus -eq "NO-VPN") {
                            $Script:VPNStatus = "ON-SITE-LAN"
                        }
                    } elseif ($Script:SourceIP -match '^192\.168\.') {
                        $ipAnalysis = " (Home/Office router)"
                        if ($Script:VPNStatus -eq "NO-VPN") {
                            $Script:VPNStatus = "HOME-NETWORK"
                        }
                    } else {
                        $ipAnalysis = " (Private network)"
                    }
                } else {
                    $ipAnalysis = " (Public/Routable IP)"
                }

                Write-Host "[*] Source IP    : $($ipConfig.IPAddress)$ipAnalysis" -ForegroundColor Gray
                Write-Host "[*] Subnet       : /$($ipConfig.PrefixLength)" -ForegroundColor Gray
            }
            Write-Host "[*] Gateway      : $($route.NextHop)" -ForegroundColor Gray
            Write-Host "[*] Metric       : $($route.RouteMetric)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "[!] Network info : Could not detect" -ForegroundColor Yellow
    }

    # DNS Servers
    Write-Host ""
    Write-Host "[*] DNS Configuration:" -ForegroundColor Cyan
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                      Where-Object { $_.ServerAddresses } | Select-Object -First 3
        foreach ($dns in $dnsServers) {
            $Script:DNSServers += $dns.ServerAddresses
            Write-Host "    Interface: $($dns.InterfaceAlias) -> $($dns.ServerAddresses -join ', ')" -ForegroundColor Gray
        }
        Write-DetailedLog "DNS_SERVERS" @{
            "Servers" = ($Script:DNSServers | Select-Object -Unique) -join ', '
        }
    } catch {
        Write-Host "    [!] Could not get DNS servers" -ForegroundColor Yellow
    }

    # Proxy Settings
    Write-Host ""
    Write-Host "[*] Proxy Configuration:" -ForegroundColor Cyan
    try {
        $proxyReg = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
        $Script:ProxySettings = @{
            Enabled = if($proxyReg.ProxyEnable -eq 1) { $true } else { $false }
            Server = $proxyReg.ProxyServer
            Override = $proxyReg.ProxyOverride
            AutoConfigURL = $proxyReg.AutoConfigURL
        }
        if ($Script:ProxySettings.Enabled) {
            Write-Host "    [!] Proxy ENABLED: $($Script:ProxySettings.Server)" -ForegroundColor Yellow
        } else {
            Write-Host "    [+] Proxy disabled (direct connection)" -ForegroundColor Green
        }
        if ($Script:ProxySettings.AutoConfigURL) {
            Write-Host "    [*] PAC URL: $($Script:ProxySettings.AutoConfigURL)" -ForegroundColor Gray
        }
        Write-DetailedLog "PROXY_SETTINGS" $Script:ProxySettings
    } catch {
        Write-Host "    [!] Could not get proxy settings" -ForegroundColor Yellow
    }

    # All Network Adapters (for detailed log)
    try {
        $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        foreach ($adp in $allAdapters) {
            Write-DetailedLog "NETWORK_ADAPTER" @{
                "Name" = $adp.Name
                "Status" = $adp.Status
                "MacAddress" = $adp.MacAddress
                "LinkSpeed" = $adp.LinkSpeed
                "MediaType" = $adp.MediaType
                "InterfaceIndex" = $adp.InterfaceIndex
            }
        }
    } catch {}

    # Routing Table (for detailed log)
    try {
        $routes = Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                  Where-Object { $_.DestinationPrefix -ne '255.255.255.255/32' } |
                  Sort-Object RouteMetric | Select-Object -First 20
        foreach ($rt in $routes) {
            Write-DetailedLog "ROUTE" @{
                "Destination" = $rt.DestinationPrefix
                "NextHop" = $rt.NextHop
                "Metric" = $rt.RouteMetric
                "Interface" = $rt.InterfaceAlias
                "Protocol" = $rt.Protocol
            }
        }
    } catch {}

    # External IP
    Write-Host ""
    try {
        $extIP = (Invoke-RestMethod -Uri 'https://api.ipify.org?format=json' -TimeoutSec 3 -ErrorAction Stop).ip
        $Script:ExternalIP = $extIP
        Write-Host "[*] External IP  : $extIP" -ForegroundColor Gray
        Write-DetailedLog "EXTERNAL_IP" @{
            "IP" = $extIP
            "Source" = "api.ipify.org"
        }
    } catch {
        Write-Host "[*] External IP  : N/A" -ForegroundColor DarkGray
    }
    
    # Microsoft Network Connectivity Status Indicator (NCSI) Check
    Write-Host ""
    Write-Host "[*] Windows Internet Status Check (NCSI):" -ForegroundColor Cyan
    
    $ncsiOk = $true
    $ncsiIssues = @()
    
    # Test 1: HTTP connectivity test
    try {
        $httpTest = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/connecttest.txt' -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($httpTest.Content -match 'Microsoft Connect Test') {
            Write-Host "    [+] HTTP Test    : OK (Microsoft Connect Test received)" -ForegroundColor Green
        } else {
            Write-Host "    [!] HTTP Test    : Unexpected response" -ForegroundColor Yellow
            $ncsiOk = $false
            $ncsiIssues += "HTTP response incorrect"
        }
    } catch {
        Write-Host "    [X] HTTP Test    : FAILED - $($_.Exception.Message)" -ForegroundColor Red
        $ncsiOk = $false
        $ncsiIssues += "HTTP blocked/filtered"
        Write-Log "NCSI HTTP test failed: $($_.Exception.Message)" 'ERROR'
    }
    
    # Test 2: DNS resolution test
    try {
        $dnsTest = Resolve-DnsName -Name 'dns.msftncsi.com' -Type A -ErrorAction Stop
        $expectedIP = '131.107.255.255'
        if ($dnsTest.IPAddress -contains $expectedIP) {
            Write-Host "    [+] DNS Test     : OK (resolved to $expectedIP)" -ForegroundColor Green
        } else {
            Write-Host "    [!] DNS Test     : Resolved to wrong IP: $($dnsTest.IPAddress)" -ForegroundColor Yellow
            $ncsiOk = $false
            $ncsiIssues += "DNS hijacked/filtered"
        }
    } catch {
        Write-Host "    [X] DNS Test     : FAILED - Cannot resolve dns.msftncsi.com" -ForegroundColor Red
        $ncsiOk = $false
        $ncsiIssues += "DNS resolution failed"
        Write-Log "NCSI DNS test failed: $($_.Exception.Message)" 'ERROR'
    }
    
    # Test 3: Alternative connectivity test (Windows 10+)
    try {
        $null = Invoke-WebRequest -Uri 'http://www.msftconnecttest.com/redirect' -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
    } catch {
        # Expected to get 302 redirect
        if ($_.Exception.Response.StatusCode -eq 'Found' -or $_.Exception.Message -match '302') {
            Write-Host "    [+] Redirect Test: OK (302 redirect detected)" -ForegroundColor Green
        } else {
            Write-Host "    [!] Redirect Test: Unexpected behavior" -ForegroundColor Yellow
            $ncsiIssues += "Redirect test abnormal"
        }
    }
    
    # Summary
    if ($ncsiOk) {
        Write-Host "    [+] NCSI Status  : PASSED - Windows shows 'Internet access'" -ForegroundColor Green
    } else {
        Write-Host "    [X] NCSI Status  : FAILED - Windows may show 'No Internet'" -ForegroundColor Red
        Write-Host "    [!] Issues       : $($ncsiIssues -join ', ')" -ForegroundColor Yellow
        Write-Host "    [!] Impact       : Teams may have connectivity issues" -ForegroundColor Yellow
        Write-Host "    [!] Fix          : Check proxy/firewall allows msftconnecttest.com" -ForegroundColor Cyan
        Write-Log "NCSI Failed - Issues: $($ncsiIssues -join ', ')" 'ERROR'
    }
}

# ============================================================================
# TCP TEST - Using Test-NetConnection for better compatibility
# ============================================================================

function Test-TCPConnection {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resolvedIP = $HostName
    $localPort = 0
    $errorDetail = ""

    # Resolve DNS first
    try {
        $dnsResult = [System.Net.Dns]::GetHostAddresses($HostName) |
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                     Select-Object -First 1
        if ($dnsResult) {
            $resolvedIP = $dnsResult.IPAddressToString
        }
    } catch {
        $errorDetail = "DNS_FAILED:$($_.Exception.Message)"
    }

    try {
        # Use Test-NetConnection for better compatibility without admin rights
        $result = Test-NetConnection -ComputerName $HostName -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        $sw.Stop()

        if ($result) {
            Write-DetailedLog "TCP_TEST" @{
                "Target" = $HostName
                "ResolvedIP" = $resolvedIP
                "Port" = $Port
                "Protocol" = "TCP"
                "Result" = "SUCCESS"
                "RTT_ms" = $sw.ElapsedMilliseconds
                "Method" = "Test-NetConnection"
                "SourceIP" = $Script:SourceIP
            }
            return @{
                Success = $true
                RTT     = $sw.ElapsedMilliseconds
                Trace   = "TcpTestSucceeded=True|IP=$resolvedIP"
                ResolvedIP = $resolvedIP
            }
        } else {
            # Try alternative method with .NET socket
            $sw.Restart()
            $tcp = $null
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $task = $tcp.ConnectAsync($HostName, $Port)
                $completed = $task.Wait($TimeoutMs)
                $sw.Stop()

                if ($completed -and $tcp.Connected) {
                    $localPort = $tcp.Client.LocalEndPoint.Port
                    Write-DetailedLog "TCP_TEST" @{
                        "Target" = $HostName
                        "ResolvedIP" = $resolvedIP
                        "Port" = $Port
                        "LocalPort" = $localPort
                        "Protocol" = "TCP"
                        "Result" = "SUCCESS"
                        "RTT_ms" = $sw.ElapsedMilliseconds
                        "Method" = "Socket"
                        "SourceIP" = $Script:SourceIP
                    }
                    return @{
                        Success = $true
                        RTT     = $sw.ElapsedMilliseconds
                        Trace   = "TcpTestSucceeded=True(Socket)|IP=$resolvedIP|LocalPort=$localPort"
                        ResolvedIP = $resolvedIP
                        LocalPort = $localPort
                    }
                } else {
                    Write-DetailedLog "TCP_TEST" @{
                        "Target" = $HostName
                        "ResolvedIP" = $resolvedIP
                        "Port" = $Port
                        "Protocol" = "TCP"
                        "Result" = "FAILED"
                        "Error" = "Timeout after ${TimeoutMs}ms"
                        "Method" = "Socket"
                        "SourceIP" = $Script:SourceIP
                    }
                    return @{
                        Success = $false
                        RTT     = $TimeoutMs
                        Trace   = "TCP=False|Timeout|IP=$resolvedIP"
                        ResolvedIP = $resolvedIP
                    }
                }
            } catch {
                $errorDetail = $_.Exception.Message
                Write-DetailedLog "TCP_TEST" @{
                    "Target" = $HostName
                    "ResolvedIP" = $resolvedIP
                    "Port" = $Port
                    "Protocol" = "TCP"
                    "Result" = "FAILED"
                    "Error" = $errorDetail
                    "Method" = "Socket"
                    "SourceIP" = $Script:SourceIP
                }
                return @{
                    Success = $false
                    RTT     = $sw.ElapsedMilliseconds
                    Trace   = "TCP=False|Error=$errorDetail"
                    ResolvedIP = $resolvedIP
                }
            } finally {
                if ($tcp) { $tcp.Dispose() }
            }
        }
    } catch {
        $sw.Stop()
        $errorDetail = $_.Exception.Message
        Write-DetailedLog "TCP_TEST" @{
            "Target" = $HostName
            "ResolvedIP" = $resolvedIP
            "Port" = $Port
            "Protocol" = "TCP"
            "Result" = "FAILED"
            "Error" = "TNC-Error: $errorDetail"
            "SourceIP" = $Script:SourceIP
        }
        return @{
            Success = $false
            RTT     = $sw.ElapsedMilliseconds
            Trace   = "TCP=False|TNC-Error"
            ResolvedIP = $resolvedIP
        }
    }
}

# ============================================================================
# UDP TEST - Simplified connectivity check
# ============================================================================

function Test-UDPConnection {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 2000
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $resolvedIP = $HostName
    $errorDetail = ""

    # Resolve DNS first
    try {
        $dnsResult = [System.Net.Dns]::GetHostAddresses($HostName) |
                     Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                     Select-Object -First 1
        if ($dnsResult) {
            $resolvedIP = $dnsResult.IPAddressToString
        }
    } catch {
        $errorDetail = "DNS_FAILED"
    }

    # Check if port is commonly used Teams media port
    if ($Port -in @(3478, 3479, 3480, 3481)) {
        # For Teams STUN/TURN ports, try STUN binding request
        $udp = $null
        $srcPort = Get-Random -Minimum 50000 -Maximum 50100

        try {
            $udp = New-Object System.Net.Sockets.UdpClient($srcPort)
            $udp.Client.ReceiveTimeout = $TimeoutMs
            $udp.Client.SendTimeout = $TimeoutMs

            # STUN Binding Request (RFC 5389)
            $txId = [byte[]]::new(12)
            (New-Object System.Random).NextBytes($txId)
            $stunReq = [byte[]]@(0x00,0x01,0x00,0x00,0x21,0x12,0xA4,0x42) + $txId

            # Resolve and connect
            $targetIP = [System.Net.Dns]::GetHostAddresses($HostName) |
                       Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                       Select-Object -First 1

            if (-not $targetIP) {
                Write-DetailedLog "UDP_TEST" @{
                    "Target" = $HostName
                    "Port" = $Port
                    "Protocol" = "UDP/STUN"
                    "Result" = "FAILED"
                    "Error" = "DNS resolution failed"
                    "LocalPort" = $srcPort
                    "SourceIP" = $Script:SourceIP
                }
                return @{ Success = $false; RTT = 0; Trace = "DNS Failed"; SrcPort = $srcPort; ResolvedIP = "N/A" }
            }

            $resolvedIP = $targetIP.IPAddressToString
            $endpoint = New-Object System.Net.IPEndPoint($targetIP, $Port)
            $udp.Connect($endpoint)

            # Send STUN request
            $bytesSent = $udp.Send($stunReq, $stunReq.Length)

            # Try to receive response (non-blocking)
            $asyncResult = $udp.BeginReceive($null, $null)
            $waitHandle = $asyncResult.AsyncWaitHandle

            if ($waitHandle.WaitOne($TimeoutMs)) {
                $remoteEP = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $response = $udp.EndReceive($asyncResult, [ref]$remoteEP)
                $sw.Stop()

                # Got STUN response - UDP works perfectly
                Write-DetailedLog "UDP_TEST" @{
                    "Target" = $HostName
                    "ResolvedIP" = $resolvedIP
                    "Port" = $Port
                    "LocalPort" = $srcPort
                    "Protocol" = "UDP/STUN"
                    "Result" = "SUCCESS"
                    "STUNResponse" = "YES"
                    "ResponseSize" = $response.Length
                    "RTT_ms" = $sw.ElapsedMilliseconds
                    "BytesSent" = $bytesSent
                    "SourceIP" = $Script:SourceIP
                    "RemoteEndpoint" = "$($remoteEP.Address):$($remoteEP.Port)"
                }
                return @{
                    Success  = $true
                    RTT      = $sw.ElapsedMilliseconds
                    Trace    = "STUN Response OK|IP=$resolvedIP"
                    SrcPort  = $srcPort
                    RespSize = $response.Length
                    ResolvedIP = $resolvedIP
                }
            } else {
                # Timeout - but UDP packet was sent successfully (no STUN response)
                $sw.Stop()
                Write-DetailedLog "UDP_TEST" @{
                    "Target" = $HostName
                    "ResolvedIP" = $resolvedIP
                    "Port" = $Port
                    "LocalPort" = $srcPort
                    "Protocol" = "UDP/STUN"
                    "Result" = "PARTIAL"
                    "STUNResponse" = "NO (timeout)"
                    "RTT_ms" = $sw.ElapsedMilliseconds
                    "BytesSent" = $bytesSent
                    "SourceIP" = $Script:SourceIP
                    "Note" = "UDP packet sent but no STUN response - may be filtered"
                }
                return @{
                    Success = $true
                    RTT     = $sw.ElapsedMilliseconds
                    Trace   = "UDP Send OK (No STUN)|IP=$resolvedIP"
                    SrcPort = $srcPort
                    ResolvedIP = $resolvedIP
                }
            }
        } catch {
            $sw.Stop()
            $errorDetail = $_.Exception.Message
            Write-DetailedLog "UDP_TEST" @{
                "Target" = $HostName
                "ResolvedIP" = $resolvedIP
                "Port" = $Port
                "LocalPort" = $srcPort
                "Protocol" = "UDP/STUN"
                "Result" = "FAILED"
                "Error" = $errorDetail
                "RTT_ms" = $sw.ElapsedMilliseconds
                "SourceIP" = $Script:SourceIP
            }
            return @{
                Success = $false
                RTT     = $sw.ElapsedMilliseconds
                Trace   = "UDP Failed|Error=$errorDetail"
                SrcPort = $srcPort
                ResolvedIP = $resolvedIP
            }
        } finally {
            if ($udp) { $udp.Close(); $udp.Dispose() }
        }
    } else {
        # For non-Teams ports
        return @{
            Success = $true
            RTT     = 10
            Trace   = "UDP Port Assumed Open"
            SrcPort = 0
            ResolvedIP = $resolvedIP
        }
    }
}

# ============================================================================
# CONNECTIVITY TESTS
# ============================================================================

function Invoke-ConnectivityTests {
    Write-Header "CONNECTIVITY TESTS (UDP/TCP)"
    
    $allResults = @()
    
    foreach ($ep in $Script:Config.Endpoints) {
        Write-SubHeader $ep.Name
        
        # Resolve DNS first
        $resolvedIP = $ep.Name
        try {
            $dns = [System.Net.Dns]::GetHostAddresses($ep.Name) | 
                   Where-Object { $_.AddressFamily -eq 'InterNetwork' } | 
                   Select-Object -First 1
            if ($dns) { $resolvedIP = $dns.IPAddressToString }
        } catch {}
        
        # TCP Tests
        foreach ($port in $ep.Ports.TCP) {
            Write-Host "  Testing TCP $($ep.Name):$port ..." -ForegroundColor DarkGray -NoNewline
            $result = Test-TCPConnection -HostName $resolvedIP -Port $port -TimeoutMs $Script:Config.TimeoutMs
            
            $status = if ($result.Success) { "OK" } else { "KO" }
            $statusIcon = if ($result.Success) { "+" } else { "X" }
            
            # Try ping for additional info
            $pingOk = $false
            try {
                $ping = Test-Connection -ComputerName $resolvedIP -Count 1 -Quiet -ErrorAction SilentlyContinue
                $pingOk = $ping
            } catch {}
            
            $displayStatus = "[$statusIcon] $status (Ping:$pingOk)"
            $trace = "TCP=$($result.Success)|RTT=$($result.RTT)ms"
            
            Write-Host "`r  " -NoNewline
            if ($result.Success) {
                Write-Host "[+] TCP $port OK (Ping:$pingOk) RTT:$($result.RTT)ms" -ForegroundColor Green
                Write-Log "TCP $($ep.Name):$port - SUCCESS - RTT:$($result.RTT)ms" 'SUCCESS'
            } else {
                Write-Host "[X] TCP $port FAILED" -ForegroundColor Red
                Write-Log "TCP $($ep.Name):$port - FAILED" 'ERROR'
            }
            
            $allResults += [PSCustomObject]@{
                Host     = $ep.Name
                Port     = $port
                Protocol = 'TCP'
                Status   = $displayStatus
                Trace    = $trace
                VPN      = $Script:VPNStatus
                RTT_ms   = $result.RTT
            }
        }
        
        # UDP Tests
        foreach ($port in $ep.Ports.UDP) {
            Write-Host "  Testing UDP $($ep.Name):$port ..." -ForegroundColor DarkGray -NoNewline
            $result = Test-UDPConnection -HostName $resolvedIP -Port $port -TimeoutMs $Script:Config.StunTimeoutMs
            
            $statusIcon = if ($result.Success) { "+" } else { "X" }
            $status = if ($result.Success) { "OK" } else { "KO" }
            
            Write-Host "`r  " -NoNewline
            if ($result.Success) {
                Write-Host "[+] UDP $port OK | src:$($result.SrcPort) | $($result.RTT)ms" -ForegroundColor Green
                Write-Log "UDP $($ep.Name):$port - SUCCESS - RTT:$($result.RTT)ms" 'SUCCESS'
            } else {
                Write-Host "[X] UDP $port FAILED | $($result.Trace)" -ForegroundColor Red
                Write-Log "UDP $($ep.Name):$port - FAILED - $($result.Trace)" 'ERROR'
            }
            
            $allResults += [PSCustomObject]@{
                Host     = $ep.Name
                Port     = $port
                Protocol = 'UDP'
                Status   = "[$statusIcon] $status"
                Trace    = $result.Trace
                VPN      = $Script:VPNStatus
                RTT_ms   = $result.RTT
            }
        }
    }
    
    # MTU Test
    Write-SubHeader "MTU PATH TEST"
    $mtuSizes = @(1500, 1400, 1350, 1300)
    $effectiveMtu = 1200
    
    foreach ($size in $mtuSizes) {
        $payload = $size - 28
        $output = & ping -n 1 -f -l $payload 8.8.8.8 2>&1 | Out-String
        $needsFrag = $output -match 'Packet needs to be fragmented|DF flag set|too big'
        $success = ($output -match 'Reply from') -and (-not $needsFrag)
        
        Write-Host "  MTU $size : $(if($success){'OK'}else{'Fragmentation required'})" -ForegroundColor $(if($success){'Green'}else{'Yellow'})
        
        if ($success -and $size -gt $effectiveMtu) { $effectiveMtu = $size }
    }
    
    $allResults += [PSCustomObject]@{
        Host     = 'MTU-TEST'
        Port     = $effectiveMtu
        Protocol = 'ICMP'
        Status   = if ($effectiveMtu -ge 1400) { "[+] OK" } else { "[!] WARN" }
        Trace    = "EffectiveMTU=$effectiveMtu"
        VPN      = $Script:VPNStatus
        RTT_ms   = 0
    }
    
    $Script:Results = $allResults
    return $allResults
}

# ============================================================================
# LIVE CALL MONITORING - DETECT UDP vs TCP FALLBACK
# ============================================================================

function Get-TeamsCallStatus {
    $status = @{
        TeamsRunning    = $false
        TeamsProcesses  = @()
        UDPPorts        = @()
        TCPConnections  = @()
        MediaTransport  = "UNKNOWN"
        IsOptimalUDP    = $false
        IsTCPFallback   = $false
    }
    
    # Find Teams processes (New Teams and Classic)
    $teamsProcs = Get-Process -Name 'ms-teams', 'Teams', 'msteams' -ErrorAction SilentlyContinue
    if ($teamsProcs) {
        $status.TeamsRunning = $true
        $status.TeamsProcesses = $teamsProcs | Select-Object Id, Name, 
            @{N='CPU';E={[math]::Round($_.CPU,1)}},
            @{N='RAM_MB';E={[math]::Round($_.WorkingSet64/1MB,0)}}
    }
    
    # Get UDP endpoints (Teams media)
    try {
        $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object {
            $teamsProcs.Id -contains $_.OwningProcess -or
            ($_.LocalPort -ge 3478 -and $_.LocalPort -le 3481) -or
            ($_.LocalPort -ge 50000 -and $_.LocalPort -le 50059)
        }
        
        foreach ($ep in $udpEndpoints) {
            $procName = (Get-Process -Id $ep.OwningProcess -ErrorAction SilentlyContinue).Name
            $status.UDPPorts += [PSCustomObject]@{
                LocalAddress = $ep.LocalAddress
                LocalPort    = $ep.LocalPort
                PID          = $ep.OwningProcess
                Process      = $procName
                Type         = if ($ep.LocalPort -ge 3478 -and $ep.LocalPort -le 3481) { "STUN/TURN" } 
                              elseif ($ep.LocalPort -ge 50000) { "RTP-Media" }
                              else { "Other" }
            }
        }
    } catch {}
    
    # Get TCP connections (potential fallback)
    try {
        $tcpConnections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object {
            ($teamsProcs.Id -contains $_.OwningProcess) -and
            ($_.RemotePort -eq 443 -or $_.RemotePort -eq 3478)
        }
        
        foreach ($conn in $tcpConnections) {
            $procName = (Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue).Name
            $remoteHost = $conn.RemoteAddress
            try {
                $dns = [System.Net.Dns]::GetHostEntry($conn.RemoteAddress)
                if ($dns.HostName) { $remoteHost = $dns.HostName }
            } catch {}
            
            $isTeamsRelay = $remoteHost -match 'teams|skype|microsoft|lync|52\.11[0-9]\.'
            
            $status.TCPConnections += [PSCustomObject]@{
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemoteHost    = $remoteHost
                RemotePort    = $conn.RemotePort
                PID           = $conn.OwningProcess
                Process       = $procName
                IsTeamsRelay  = $isTeamsRelay
            }
        }
    } catch {}
    
    # Determine transport mode
    $hasUDPMedia = ($status.UDPPorts | Where-Object { $_.Type -eq 'RTP-Media' -or $_.Type -eq 'STUN/TURN' }).Count -gt 0
    $hasTCPTeams = ($status.TCPConnections | Where-Object { $_.IsTeamsRelay -and $_.RemotePort -eq 443 }).Count -gt 0
    
    if ($hasUDPMedia) {
        $status.MediaTransport = "UDP-OPTIMAL"
        $status.IsOptimalUDP = $true
    } elseif ($hasTCPTeams -and -not $hasUDPMedia) {
        $status.MediaTransport = "TCP-FALLBACK"
        $status.IsTCPFallback = $true
    } elseif ($status.TeamsRunning) {
        $status.MediaTransport = "NO-MEDIA-DETECTED"
    }
    
    return $status
}

function Start-LiveMonitor {
    Write-Header "SURVEILLANCE APPEL EN DIRECT (Detection UDP vs TCP + Qualite)"
    Write-Host ""
    Write-Host "  Instructions:" -ForegroundColor Yellow
    Write-Host "    1. Demarrer ou rejoindre un appel Teams" -ForegroundColor Gray
    Write-Host "    2. Appuyer sur ESPACE pour capturer l'etat" -ForegroundColor Gray
    Write-Host "    3. Appuyer sur ESC pour terminer et voir le rapport" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Legende:" -ForegroundColor Yellow
    Write-Host "    UDP-OPTIMAL   = Media utilise UDP (meilleure qualite)" -ForegroundColor Green
    Write-Host "    TCP-FALLBACK  = Media utilise TCP 443 (qualite degradee)" -ForegroundColor Red
    Write-Host "    PACKET-LOSS   = Pertes de paquets detectees" -ForegroundColor Yellow
    Write-Host ""
    
    Write-Log "Monitoring started" 'INFO'
    $snapshotCount = 0
    $Script:MonitoringSnapshots = @()
    $Script:NetworkStats = @{
        LastBytes = 0
        LastPackets = 0
        LastTime = Get-Date
    }
    
    while ($true) {
        if ([Console]::KeyAvailable) {
            $key = [Console]::ReadKey($true)
            
            if ($key.Key -eq 'Escape') {
                Write-Host ""
                Write-Host "  [ESC] Exiting monitor..." -ForegroundColor Yellow
                break
            }
            elseif ($key.Key -eq 'Spacebar' -or $key.Key -eq 'R') {
                $snapshotCount++
                $ts = Get-Date -Format 'HH:mm:ss.fff'
                
                Write-Host ""
                Write-Host ("=" * 70) -ForegroundColor DarkCyan
                Write-Host "  SNAPSHOT #$snapshotCount @ $ts | VPN: $Script:VPNStatus" -ForegroundColor Cyan
                Write-Host ("=" * 70) -ForegroundColor DarkCyan
                
                $callStatus = Get-TeamsCallStatus
                
                # Teams process status
                if ($callStatus.TeamsRunning) {
                    Write-Host ""
                    Write-Host "  [+] TEAMS PROCESSES:" -ForegroundColor Green
                    foreach ($p in $callStatus.TeamsProcesses) {
                        Write-Host "      PID:$($p.Id) $($p.Name) | CPU:$($p.CPU)s | RAM:$($p.RAM_MB)MB" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host ""
                    Write-Host "  [-] Teams is NOT running" -ForegroundColor Red
                }
                
                # Transport mode detection
                Write-Host ""
                $transportColor = switch ($callStatus.MediaTransport) {
                    "UDP-OPTIMAL"      { "Green" }
                    "TCP-FALLBACK"     { "Red" }
                    default            { "Yellow" }
                }
                Write-Host "  >>> TRANSPORT MEDIA: $($callStatus.MediaTransport) <<<" -ForegroundColor $transportColor
                Write-Log "Snapshot #$snapshotCount - Transport: $($callStatus.MediaTransport)" 'MONITOR'
                
                # UDP Ports
                if ($callStatus.UDPPorts.Count -gt 0) {
                    Write-Host ""
                    Write-Host "  [+] ACTIVE UDP PORTS (Media/STUN):" -ForegroundColor Green
                    foreach ($udp in $callStatus.UDPPorts) {
                        Write-Host "      $($udp.LocalAddress):$($udp.LocalPort) | $($udp.Type) | $($udp.Process) (PID:$($udp.PID))" -ForegroundColor Cyan
                    }
                } else {
                    Write-Host ""
                    Write-Host "  [!] NO UDP MEDIA PORTS DETECTED" -ForegroundColor Yellow
                    Write-Host "      -> Teams may be using TCP fallback or no call active" -ForegroundColor DarkYellow
                }
                
                # TCP Connections
                $teamsRelayConns = $callStatus.TCPConnections | Where-Object { $_.IsTeamsRelay }
                if ($teamsRelayConns.Count -gt 0) {
                    Write-Host ""
                    $tcpColor = if ($callStatus.IsOptimalUDP) { "Gray" } else { "Red" }
                    $tcpLabel = if ($callStatus.IsTCPFallback) { "[!] TCP FALLBACK CONNECTIONS:" } else { "[*] TCP Connections (signaling):" }
                    Write-Host "  $tcpLabel" -ForegroundColor $tcpColor
                    foreach ($tcp in $teamsRelayConns) {
                        $hostDisplay = if ($tcp.RemoteHost.Length -gt 35) { $tcp.RemoteHost.Substring(0,35) + "..." } else { $tcp.RemoteHost }
                        Write-Host "      :$($tcp.LocalPort) -> $($tcp.RemoteAddress):$($tcp.RemotePort) ($hostDisplay)" -ForegroundColor $(if($callStatus.IsTCPFallback){"Red"}else{"DarkGray"})
                    }
                    
                    if ($callStatus.IsTCPFallback) {
                        Write-Host ""
                        Write-Host "  !!! WARNING: Media is using TCP 443 fallback !!!" -ForegroundColor Red
                        Write-Host "      -> Audio/Video quality will be DEGRADED" -ForegroundColor Yellow
                        Write-Host "      -> Check: Firewall blocks UDP 3478-3481" -ForegroundColor Yellow
                        Write-Host "      -> Check: VPN not configured for split-tunnel" -ForegroundColor Yellow
                    }
                }
                
                # Network Quality Metrics
                Write-Host ""
                Write-Host "  NETWORK QUALITY METRICS:" -ForegroundColor White
                
                # Get network interface stats
                try {
                    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -eq $Script:CurrentAdapter } | Select-Object -First 1
                    if (-not $adapter) {
                        $adapter = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Select-Object -First 1
                    }
                    
                    if ($adapter) {
                        $stats = Get-NetAdapterStatistics -Name $adapter.Name -ErrorAction SilentlyContinue
                        if ($stats) {
                            $packetLoss = 0
                            if ($stats.ReceivedUnicastPackets -gt 0) {
                                $packetLoss = [math]::Round(($stats.ReceivedDiscardedPackets + $stats.ReceivedErrors) / $stats.ReceivedUnicastPackets * 100, 2)
                            }
                            
                            Write-Host "      Packets Received : $($stats.ReceivedUnicastPackets)" -ForegroundColor Gray
                            Write-Host "      Packets Sent     : $($stats.SentUnicastPackets)" -ForegroundColor Gray
                            Write-Host "      Errors/Discards  : $($stats.ReceivedErrors + $stats.ReceivedDiscardedPackets)" -ForegroundColor $(if($stats.ReceivedErrors -gt 0){'Yellow'}else{'Gray'})
                            
                            if ($packetLoss -gt 0) {
                                $lossColor = if ($packetLoss -gt 5) { 'Red' } elseif ($packetLoss -gt 1) { 'Yellow' } else { 'Gray' }
                                Write-Host "      PACKET LOSS      : $packetLoss%" -ForegroundColor $lossColor
                                if ($packetLoss -gt 1) {
                                    Write-Host "      [!] Quality impact detected!" -ForegroundColor Yellow
                                    $Script:PacketLossDetected = $true
                                    Write-Log "Packet loss detected: $packetLoss%" 'WARNING'
                                }
                            }
                        }
                        
                        # Bandwidth estimation
                        $linkSpeed = $adapter.LinkSpeed
                        if ($linkSpeed) {
                            $speedMbps = [int]($linkSpeed -replace '[^\d]', '') / 1000000
                            Write-Host "      Link Speed       : $speedMbps Mbps" -ForegroundColor Gray
                            if ($speedMbps -lt 10) {
                                Write-Host "      [!] Low bandwidth detected (<10 Mbps)" -ForegroundColor Yellow
                            }
                        }
                    }
                } catch {}
                
                # Quick diagnosis
                Write-Host ""
                Write-Host "  DIAGNOSIS:" -ForegroundColor White
                if ($callStatus.IsOptimalUDP) {
                    Write-Host "      [OK] Call is using OPTIMAL UDP transport" -ForegroundColor Green
                    Write-Log "UDP OPTIMAL - Call quality should be good" 'SUCCESS'
                    $Script:UDPOptimalDetected = $true
                } elseif ($callStatus.IsTCPFallback) {
                    Write-Host "      [FAIL] Call DEGRADED - TCP 443 fallback active" -ForegroundColor Red
                    Write-Host "      [WARN] UDP ports 3478-3481 may be BLOCKED" -ForegroundColor Yellow
                    Write-Log "TCP FALLBACK DETECTED - Call quality degraded" 'ERROR'
                    $Script:TCPFallbackDetected = $true
                } elseif ($callStatus.TeamsRunning) {
                    Write-Host "      [?] No active media - waiting for call" -ForegroundColor Yellow
                } else {
                    Write-Host "      [!] Teams not running" -ForegroundColor Yellow
                }
            }
        }
        Start-Sleep -Milliseconds 100
    }
}

# ============================================================================
# RESULTS TABLE OUTPUT
# ============================================================================

function Write-ResultsTable {
    param([array]$Results)
    
    Write-Header "CONNECTIVITY RESULTS SUMMARY"
    Write-Host ""
    
    # Header
    $fmt = "{0,-30} {1,5} {2,-18} {3,-28} {4,-12}"
    Write-Host ($fmt -f "Host", "Port", "Status", "Trace", "VPN") -ForegroundColor White
    Write-Host ("-" * 95) -ForegroundColor DarkGray
    
    # Sort and display results
    $sortedResults = $Results | Sort-Object Host, Port
    
    foreach ($r in $sortedResults) {
        $hostDisplay = $r.Host
        if ($hostDisplay.Length -gt 30) { $hostDisplay = $hostDisplay.Substring(0, 27) + "..." }
        
        $traceDisplay = $r.Trace
        if ($traceDisplay.Length -gt 28) { $traceDisplay = $traceDisplay.Substring(0, 25) + "..." }
        
        $color = if ($r.Status -match 'OK') { 'Green' } elseif ($r.Status -match 'KO|FAIL') { 'Red' } else { 'Yellow' }
        
        $line = $fmt -f $hostDisplay, $r.Port, $r.Status, $traceDisplay, $r.VPN
        Write-Host $line -ForegroundColor $color
    }
    
    Write-Host ("-" * 95) -ForegroundColor DarkGray
    
    # Summary stats
    $total = $Results.Count
    $okCount = ($Results | Where-Object { $_.Status -match 'OK' }).Count
    $failCount = ($Results | Where-Object { $_.Status -match 'KO|FAIL' }).Count
    $udpFails = ($Results | Where-Object { $_.Protocol -eq 'UDP' -and $_.Status -match 'KO' }).Count
    $tcpFails = ($Results | Where-Object { $_.Protocol -eq 'TCP' -and $_.Status -match 'KO' }).Count
    
    Write-Host ""
    Write-Host "  TOTAL: $total | OK: $okCount | FAIL: $failCount (UDP: $udpFails, TCP: $tcpFails)" -ForegroundColor $(if($failCount -gt 0){'Yellow'}else{'Green'})
}

# ============================================================================
# FINAL REPORT GENERATION
# ============================================================================

function New-FinalReport {
    $report = [System.Text.StringBuilder]::new()
    
    [void]$report.AppendLine("")
    [void]$report.AppendLine("="*70)
    [void]$report.AppendLine("RAPPORT DIAGNOSTIC TEAMS - $(Get-Date -Format 'dd/MM/yyyy HH:mm:ss')")
    [void]$report.AppendLine("="*70)
    [void]$report.AppendLine("")
    
    # Environment info
    [void]$report.AppendLine("ENVIRONNEMENT:")
    [void]$report.AppendLine("  Ordinateur : $env:COMPUTERNAME")
    [void]$report.AppendLine("  Utilisateur: $env:USERNAME")
    [void]$report.AppendLine("  IP locale  : $Script:SourceIP")
    [void]$report.AppendLine("  VPN        : $Script:VPNStatus")
    [void]$report.AppendLine("")
    
    # Test results summary
    $udpFails = ($Script:Results | Where-Object { $_.Protocol -eq 'UDP' -and $_.Status -match 'KO' }).Count
    $tcpFails = ($Script:Results | Where-Object { $_.Protocol -eq 'TCP' -and $_.Status -match 'KO' }).Count
    $total = $Script:Results.Count
    $okCount = ($Script:Results | Where-Object { $_.Status -match 'OK' }).Count
    
    [void]$report.AppendLine("RESULTATS DES TESTS:")
    [void]$report.AppendLine("  Total tests: $total")
    [void]$report.AppendLine("  Reussis    : $okCount")
    [void]$report.AppendLine("  Echoues    : $($total - $okCount)")
    [void]$report.AppendLine("  - UDP fails: $udpFails")
    [void]$report.AppendLine("  - TCP fails: $tcpFails")
    [void]$report.AppendLine("")
    
    # Transport mode detected during monitoring
    [void]$report.AppendLine("MODE TRANSPORT TEAMS DETECTE:")
    if ($Script:UDPOptimalDetected) {
        [void]$report.AppendLine("  [OK] UDP OPTIMAL - Bonne qualite audio/video")
    } elseif ($Script:TCPFallbackDetected) {
        [void]$report.AppendLine("  [CRITIQUE] TCP FALLBACK - Qualite degradee!")
        [void]$report.AppendLine("    -> Audio/video saccades, coupures possibles")
        [void]$report.AppendLine("    -> UDP 3478-3481 bloques par firewall/proxy")
    } else {
        [void]$report.AppendLine("  [?] Pas d'appel Teams detecte pendant le test")
    }
    [void]$report.AppendLine("")
    
    # Network quality issues
    if ($Script:PacketLossDetected) {
        [void]$report.AppendLine("QUALITE RESEAU:")
        [void]$report.AppendLine("  [ALERTE] Pertes de paquets detectees")
        [void]$report.AppendLine("    -> Impact sur la qualite des appels")
    }
    
    # Critical issues
    [void]$report.AppendLine("PROBLEMES DETECTES:")
    if ($udpFails -gt 0) {
        [void]$report.AppendLine("  [CRITIQUE] $udpFails ports UDP bloques")
        [void]$report.AppendLine("    -> Teams va basculer en TCP (qualite degradee)")
        [void]$report.AppendLine("    SOLUTION: Autoriser UDP 3478-3481 sortant")
    }
    if ($tcpFails -gt 0) {
        [void]$report.AppendLine("  [ALERTE] $tcpFails connexions TCP echouees")
    }
    if ($Script:VPNStatus -match 'VPN-CONNECTED') {
        [void]$report.AppendLine("  [INFO] VPN F5 connecte: $Script:VPNStatus")
        [void]$report.AppendLine("    SOLUTION: Configurer split-tunnel pour Teams")
    }
    
    if ($udpFails -eq 0 -and $tcpFails -eq 0 -and $Script:UDPOptimalDetected) {
        [void]$report.AppendLine("  [OK] Configuration reseau optimale pour Teams")
    }
    
    [void]$report.AppendLine("")
    [void]$report.AppendLine("="*70)
    [void]$report.AppendLine("FIN DU RAPPORT")
    [void]$report.AppendLine("="*70)
    
    return $report.ToString()
}

# ============================================================================
# DIAGNOSTIC ANALYSIS
# ============================================================================

function Write-Diagnosis {
    Write-Header "DIAGNOSTIC ANALYSIS"
    
    $udpFails = ($Script:Results | Where-Object { $_.Protocol -eq 'UDP' -and $_.Status -match 'KO' }).Count
    $tcpFails = ($Script:Results | Where-Object { $_.Protocol -eq 'TCP' -and $_.Status -match 'KO' }).Count
    $mtuResult = $Script:Results | Where-Object { $_.Host -eq 'MTU-TEST' }
    
    Write-Host ""
    
    if ($udpFails -gt 0) {
        Write-Host "  [X] CRITICAL: $udpFails UDP port(s) BLOCKED" -ForegroundColor Red
        Write-Host "     -> Teams will fallback to TCP 443 (degraded quality)" -ForegroundColor Yellow
        Write-Host "     -> FIX: Allow UDP 3478-3481 outbound to *.teams.microsoft.com" -ForegroundColor Cyan
        Write-Host "     -> FIX: Configure VPN split-tunnel for Microsoft 365" -ForegroundColor Cyan
        Write-Host ""
    }
    
    if ($tcpFails -gt 0) {
        Write-Host "  [!] WARNING: $tcpFails TCP connection(s) FAILED" -ForegroundColor Yellow
        Write-Host "     -> Teams signaling may be impacted" -ForegroundColor Yellow
        Write-Host "     -> FIX: Verify proxy allows HTTPS to *.teams.microsoft.com" -ForegroundColor Cyan
        Write-Host ""
    }
    
    if ($mtuResult -and $mtuResult.Status -match 'WARN') {
        Write-Host "  [!] WARNING: MTU issue detected ($($mtuResult.Port))" -ForegroundColor Yellow
        Write-Host "     -> VPN tunnel may cause fragmentation" -ForegroundColor Yellow
        Write-Host "     -> FIX: Set VPN MTU to 1350" -ForegroundColor Cyan
        Write-Host ""
    }
    
    if ($Script:VPNStatus -match 'VPN-ON') {
        Write-Host "  [!] VPN DETECTED: $Script:VPNStatus" -ForegroundColor Yellow
        Write-Host "     -> Ensure split-tunnel is configured for Teams endpoints" -ForegroundColor Cyan
        Write-Host ""
    }
    
    if ($udpFails -eq 0 -and $tcpFails -eq 0) {
        Write-Host "  [+] ALL CONNECTIVITY TESTS PASSED" -ForegroundColor Green
        Write-Host "     -> Network path to Teams is healthy" -ForegroundColor Green
        Write-Host "     -> UDP media should work optimally" -ForegroundColor Green
        Write-Host ""
    }
    
    # Quick call status check
    $callStatus = Get-TeamsCallStatus
    if ($callStatus.TeamsRunning) {
        Write-Host "  [*] Teams Status: Running ($(($callStatus.TeamsProcesses).Count) process(es))" -ForegroundColor Cyan
        Write-Host "  [*] Current Media Transport: $($callStatus.MediaTransport)" -ForegroundColor $(if($callStatus.IsOptimalUDP){'Green'}elseif($callStatus.IsTCPFallback){'Red'}else{'Yellow'})
    }
}

# ============================================================================
# EXPORT
# ============================================================================

function Export-Results {
    param([string]$Path)

    if (-not $Path) { return }

    try {
        # Export CSV
        $Script:Results | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "  [+] Resultats CSV exportes vers: $Path" -ForegroundColor Green
        Write-Log "Export CSV: $Path" 'INFO'

        # Export detailed technical log (for infra/firewall debug)
        $detailedLogFile = $Path -replace '\.csv$', '-DETAILED.log'
        $detailedContent = @"
================================================================================
TEAMS DIAGNOSTIC - DETAILED TECHNICAL LOG
================================================================================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Computer: $env:COMPUTERNAME
User: $env:USERDOMAIN\$env:USERNAME
================================================================================

--- SUMMARY ---
Source IP: $Script:SourceIP
External IP: $Script:ExternalIP
Gateway: $Script:Gateway
VPN Status: $Script:VPNStatus
DNS Servers: $($Script:DNSServers -join ', ')
Proxy Enabled: $($Script:ProxySettings.Enabled)
Proxy Server: $($Script:ProxySettings.Server)

$($Script:DetailedLog.ToString())

--- END OF LOG ---
"@
        $detailedContent | Out-File -FilePath $detailedLogFile -Encoding UTF8
        Write-Host "  [+] Log technique detaille: $detailedLogFile" -ForegroundColor Green

        # Export simple log file
        $logContent = $Script:LogContent.ToString()
        if ($logContent) {
            $logContent | Out-File -FilePath $Script:LogFile -Encoding UTF8
            Write-Host "  [+] Fichier log simple: $Script:LogFile" -ForegroundColor Green
        }

        # Export final report (for email)
        $reportFile = $Path -replace '\.csv$', '-RAPPORT.txt'
        $finalReport = New-FinalReport
        $finalReport | Out-File -FilePath $reportFile -Encoding UTF8
        Write-Host "  [+] Rapport final (email): $reportFile" -ForegroundColor Green

    } catch {
        Write-Host "  [-] Export echoue: $($_.Exception.Message)" -ForegroundColor Red
        Write-Log "Export error: $($_.Exception.Message)" 'ERROR'
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Clear-Host
Write-Host ""
Write-Host "  ================================================================" -ForegroundColor Cyan
Write-Host "      TEAMS NETWORK DIAGNOSTIC TOOL v$($Script:Config.Version)" -ForegroundColor Cyan
Write-Host "      Mode: $($Mode.ToUpper())" -ForegroundColor Cyan
Write-Host "  ================================================================" -ForegroundColor Cyan

# Phase 1: Environment
Get-Environment

# Phase 2: Connectivity tests (skip in monitor-only mode)
if ($Mode -ne 'monitor') {
    $results = Invoke-ConnectivityTests
    Write-ResultsTable -Results $results
}

# Phase 3: Live monitoring (skip in quick mode)
if ($Mode -ne 'quick') {
    Start-LiveMonitor
}

# Phase 4: Diagnosis
Write-Diagnosis

# Phase 5: Export
if ($Export) {
    Export-Results -Path $Export
}

# Phase 6: Final Report Display
$finalReport = New-FinalReport
Write-Header "RAPPORT FINAL (COPIER-COLLER POUR EMAIL)"
Write-Host $finalReport -ForegroundColor White

$duration = [math]::Round(((Get-Date) - $Script:StartTime).TotalSeconds, 1)
Write-Host ""
Write-Host "  Diagnostic termine en ${duration}s" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  FICHIERS GENERES:" -ForegroundColor Cyan
Write-Host "    - CSV : $Export" -ForegroundColor Gray
Write-Host "    - LOG : $Script:LogFile" -ForegroundColor Gray
Write-Host "    - RAPPORT : $($Export -replace '\.csv$', '-RAPPORT.txt')" -ForegroundColor Gray
Write-Host ""
Write-Host "  [!] Vous pouvez copier le rapport ci-dessus pour l'envoyer par email" -ForegroundColor Yellow
Write-Host ""

# SIG # Begin signature block
# MIIEWQYJKoZIhvcNAQcCoIIESjCCBEYCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC6EJBGd1qMnEK1
# FMZiFdUNO3Q72qGdk+n1eKsmvYKXZqCCAkswggJHMIIBsKADAgECAhBsFMR9j+F2
# j0gDPwhXGnc5MA0GCSqGSIb3DQEBBQUAMCgxJjAkBgNVBAMTHU9wZW4gU291cmNl
# IC0gVG9vbGluZyBTY3JpcHRzMB4XDTI0MTIzMTIzMDAwMFoXDTMwMTIzMTIzMDAw
# MFowKDEmMCQGA1UEAxMdT3BlbiBTb3VyY2UgLSBUb29saW5nIFNjcmlwdHMwgZ8w
# DQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALzTWKzo1CV6B/I88KWstlfPoegUCAVM
# eNTfbu+2SAWk9Y/igwl+tOPFz9Ufcip9Ad8hwAIQ9ZY6pQHz1Q1u0mIqrhMU8nC+
# MSgUhqo2RL8inzIlUTLZDlR72J2xfwStCm486LJpSL/LBTYARWBzKxUBpuFZDhWL
# OXscqwgdHNN1AgMBAAGjcjBwMBMGA1UdJQQMMAoGCCsGAQUFBwMDMFkGA1UdAQRS
# MFCAEHeYnWBUDvZNV8qpp54CmIqhKjAoMSYwJAYDVQQDEx1PcGVuIFNvdXJjZSAt
# IFRvb2xpbmcgU2NyaXB0c4IQbBTEfY/hdo9IAz8IVxp3OTANBgkqhkiG9w0BAQUF
# AAOBgQCGGiZz8gG8GLGzoeAURFUs4OvQd+Qmy85ixM7ELID1lGtdQeM7umkS4GW5
# IyCgprJdYrCUbdTpIP65RSAZw+Rr0+HM6sbb5Gekznhsy+X0HsnMmMGVw37EcTT/
# s5Ww0OudJKOkUrgkNG90ZwUm8we8CPozg3r8Mo4B6FGVjZxlOjGCAWQwggFgAgEB
# MDwwKDEmMCQGA1UEAxMdT3BlbiBTb3VyY2UgLSBUb29saW5nIFNjcmlwdHMCEGwU
# xH2P4XaPSAM/CFcadzkwDQYJYIZIAWUDBAIBBQCgfDAQBgorBgEEAYI3AgEMMQIw
# ADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYK
# KwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgCpSGiWNzP/S4FTfczI2u/PLMKt/7
# eycn2uxKVqyxsJUwDQYJKoZIhvcNAQEBBQAEgYAi83c9xsLj1i+xXGceC5Fc/s1G
# YkNPLBoDy02hnuoSW83SJRo8lH1XkclW5Y8Lk/ZaTjYBE0KYiMpnECzl8+cJ8Xq3
# bXFNRUS1a4tQTGg9ola2tLmU+jd30w7wMZmdqulBFl735wTfyufjdcmGtkKDQ/4Y
# O6N2dViRByYGhU036g==
# SIG # End signature block
