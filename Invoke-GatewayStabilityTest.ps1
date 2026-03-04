[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$InterfaceAlias = "Integrated NIC 1 Port 1-1",

  # Host offsets inside detected subnet (Network + offsets). Default: 26..31
  [Parameter(Mandatory=$false)]
  [int[]]$HostOffsets = (26..31),

  # Require N consecutive replies before declaring stable and removing that IP
  [Parameter(Mandatory=$false)]
  [int]$RequiredConsecutiveSuccess = 3,

  [Parameter(Mandatory=$false)]
  [int]$PingTimeoutMs = 500,

  [Parameter(Mandatory=$false)]
  [int]$PollDelayMs = 500,

  [Parameter(Mandatory=$false)]
  [string]$LogDirectory = "C:\Temp",

  [Parameter(Mandatory=$false)]
  [switch]$NoBeep
)

# ---------------- Effective settings (from params) ----------------
$ifAlias                    = $InterfaceAlias
$hostOffsets                = $HostOffsets | ForEach-Object { [int]$_ }
$requiredConsecutiveSuccess = [int]$RequiredConsecutiveSuccess
$pingTimeoutMs              = [int]$PingTimeoutMs
$pollDelayMs                = [int]$PollDelayMs
$beepOnStableSuccess        = -not $NoBeep

# -------- Logging --------
$logDir = $LogDirectory
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logPath = Join-Path $logDir ("GatewayPing_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
    )
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line  = "{0} [{1}] {2}" -f $stamp, $Level, $Message

    switch ($Level) {
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line -ForegroundColor Gray }
    }

    Add-Content -Path $logPath -Value $line
}

Write-Log "Starting gateway stability ping script. Log file: $logPath" "INFO"

# ---------------- Self-check ----------------

function Invoke-SelfCheck {
    param([Parameter(Mandatory)][string]$InterfaceAlias)

    $psv = $PSVersionTable.PSVersion.ToString()
    $pse = $PSVersionTable.PSEdition
    $os  = $PSVersionTable.OS

    Write-Log "Self-check: PowerShell $pse $psv" "INFO"
    if ($os) { Write-Log "Self-check: OS = $os" "INFO" }

    # Determine Windows reliably across PS 5.1 and PS 7+
    $isWindows = $false
    if (Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue) {
        $isWindows = [bool]$IsWindows
    } else {
        $isWindows = ($env:OS -eq "Windows_NT")
    }

    if (-not $isWindows) {
        Write-Log "Self-check FAILED: This script requires Windows (NetTCPIP/NetAdapter cmdlets are Windows-only)." "ERROR"
        throw "Unsupported OS"
    }

    # Must be elevated
    $isAdmin = $false
    try {
        $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        Write-Log "Self-check FAILED: Could not determine elevation status: $($_.Exception.Message)" "ERROR"
        throw
    }

    if (-not $isAdmin) {
        Write-Log "Self-check FAILED: Not running as Administrator. Start PowerShell with 'Run as administrator'." "ERROR"
        throw "Not elevated"
    }
    Write-Log "Self-check: Running elevated (Administrator) = True" "INFO"

    # Required cmdlets
    $requiredCmdlets = @(
        "Get-NetIPAddress",
        "Get-NetIPConfiguration",
        "New-NetIPAddress",
        "Remove-NetIPAddress",
        "Get-NetAdapter"
    )

    # In PS 7+, attempt to load modules via compatibility if commands missing
    $missing = @()
    foreach ($c in $requiredCmdlets) {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { $missing += $c }
    }

    if ($missing.Count -gt 0 -and $pse -eq "Core") {
        Write-Log "Self-check: Missing cmdlets detected in PowerShell Core. Attempting module import via Windows PowerShell compatibility..." "WARN"
        try {
            Import-Module NetTCPIP  -UseWindowsPowerShell -ErrorAction SilentlyContinue | Out-Null
            Import-Module NetAdapter -UseWindowsPowerShell -ErrorAction SilentlyContinue | Out-Null
        } catch { }

        $missing = @()
        foreach ($c in $requiredCmdlets) {
            if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { $missing += $c }
        }
    }

    if ($missing.Count -gt 0) {
        Write-Log ("Self-check FAILED: Required commands not found: {0}" -f ($missing -join ", ")) "ERROR"
        Write-Log "Tip: If using PowerShell 7, try: Import-Module NetTCPIP -UseWindowsPowerShell" "WARN"
        throw "Missing required cmdlets"
    }

    Write-Log "Self-check: Required networking commands found." "INFO"

    # Validate interface exists
    $adapter = Get-NetAdapter -Name $InterfaceAlias -ErrorAction SilentlyContinue
    if (-not $adapter) {
        Write-Log "Self-check FAILED: InterfaceAlias '$InterfaceAlias' not found on this system." "ERROR"
        Write-Log "Available adapters:" "INFO"
        Get-NetAdapter | ForEach-Object { Write-Log (" - " + $_.Name) "INFO" }
        throw "Bad InterfaceAlias"
    }
    Write-Log "Self-check: Found adapter '$InterfaceAlias' (Status=$($adapter.Status), LinkSpeed=$($adapter.LinkSpeed))." "INFO"

    # Validate IP + prefix + gateway
    $ipObj = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.AddressState -eq "Preferred" -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -notlike "127.*"
        } |
        Select-Object -First 1

    if (-not $ipObj) {
        Write-Log "Self-check FAILED: No Preferred IPv4 address found on '$InterfaceAlias'." "ERROR"
        throw "No Preferred IPv4"
    }

    Write-Log ("Self-check: IPv4 = {0}/{1} (State={2})" -f $ipObj.IPAddress, $ipObj.PrefixLength, $ipObj.AddressState) "INFO"

    if ($ipObj.PrefixLength -eq 32) {
        Write-Log "Self-check FAILED: PrefixLength is /32 on '$InterfaceAlias'. This will break routing/ARP. Fix NIC prefix (e.g. /24)." "ERROR"
        throw "Bad PrefixLength /32"
    }

    $cfg = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue
    $gw  = $cfg.IPv4DefaultGateway.NextHop

    if (-not $gw) {
        Write-Log "Self-check FAILED: No IPv4 default gateway detected on '$InterfaceAlias'." "ERROR"
        throw "No Default Gateway"
    }

    Write-Log "Self-check: Default Gateway = $gw" "INFO"
    Write-Log "Self-check PASSED." "SUCCESS"
}

# ---------------- Helpers ----------------

function Convert-IPv4ToInt {
    param([Parameter(Mandatory)][string]$IPv4)
    $bytes = [System.Net.IPAddress]::Parse($IPv4).GetAddressBytes()
    [Array]::Reverse($bytes)
    return [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-IntToIPv4 {
    param([Parameter(Mandatory)][uint32]$Int)
    $bytes = [BitConverter]::GetBytes($Int)
    [Array]::Reverse($bytes)
    return ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-SubnetMaskIntFromPrefix {
    param([Parameter(Mandatory)][int]$PrefixLength)

    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        throw "Invalid PrefixLength: $PrefixLength"
    }
    if ($PrefixLength -eq 0) { return [uint32]0 }

    # Safe across Windows PowerShell 5.1: keep math in UInt64 and clamp to 32-bit.
    [uint64]$allOnes = 4294967295  # 0xFFFFFFFF as an unsigned decimal
    [uint64]$mask64  = (($allOnes -shl (32 - $PrefixLength)) -band $allOnes)

    return [uint32]$mask64
}

function Get-NicContext {
    param([Parameter(Mandatory)][string]$InterfaceAlias)

    $ipObj = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object {
            $_.AddressState -eq "Preferred" -and
            $_.PrefixLength -ne 32 -and
            $_.IPAddress -notlike "169.254.*" -and
            $_.IPAddress -notlike "127.*"
        } |
        Select-Object -First 1

    if (-not $ipObj) {
        throw "No usable IPv4 found on '$InterfaceAlias' (need Preferred IPv4 with PrefixLength != 32)."
    }

    $ipCfg = Get-NetIPConfiguration -InterfaceAlias $InterfaceAlias -ErrorAction Stop
    $gw = $ipCfg.IPv4DefaultGateway.NextHop
    if (-not $gw) { throw "No IPv4 default gateway found on '$InterfaceAlias'." }

    # --- PS 5.1-safe unsigned subnet math ---
    [uint64]$allOnes = 4294967295

    [uint32]$maskInt = Get-SubnetMaskIntFromPrefix $ipObj.PrefixLength
    [uint32]$ipInt   = Convert-IPv4ToInt $ipObj.IPAddress

    [uint64]$net64   = (([uint64]$ipInt -band [uint64]$maskInt) -band $allOnes)
    [uint64]$inv64   = (($allOnes -bxor [uint64]$maskInt) -band $allOnes)
    [uint64]$bcast64 = (([uint64]$net64 -bor [uint64]$inv64) -band $allOnes)

    [uint32]$netInt   = [uint32]$net64
    [uint32]$bcastInt = [uint32]$bcast64

    [pscustomobject]@{
        IPAddress    = $ipObj.IPAddress
        PrefixLength = $ipObj.PrefixLength
        NetworkInt   = $netInt
        BroadcastInt = $bcastInt
        Network      = Convert-IntToIPv4 $netInt
        Broadcast    = Convert-IntToIPv4 $bcastInt
        Gateway      = $gw
    }
}

function Ensure-SourceIPsOnAdapter {
    param(
        [Parameter(Mandatory)][string]$InterfaceAlias,
        [Parameter(Mandatory)][string[]]$IPAddresses,
        [Parameter(Mandatory)][int]$PrefixLength
    )

    $null = Get-NetAdapter -Name $InterfaceAlias -ErrorAction Stop

    foreach ($ip in $IPAddresses) {
        $existing = Get-NetIPAddress -AddressFamily IPv4 -IPAddress $ip -ErrorAction SilentlyContinue
        if ($existing) {
            if ($existing.InterfaceAlias -ne $InterfaceAlias) {
                Write-Log "$ip already exists on '$($existing.InterfaceAlias)' locally. Skipping add on '$InterfaceAlias'." "WARN"
            } else {
                Write-Log "$ip already present on '$InterfaceAlias'. (PrefixLength=$($existing.PrefixLength))" "INFO"
            }
            continue
        }

        New-NetIPAddress -InterfaceAlias $InterfaceAlias `
                         -IPAddress $ip `
                         -PrefixLength $PrefixLength `
                         -AddressFamily IPv4 `
                         -Type Unicast `
                         -ErrorAction Stop | Out-Null

        Write-Log "Added $ip/$PrefixLength to '$InterfaceAlias'." "INFO"
    }
}

function Remove-SourceIPFromAdapter {
    param(
        [Parameter(Mandatory)][string]$InterfaceAlias,
        [Parameter(Mandatory)][string]$IPAddress
    )
    $entry = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -IPAddress $IPAddress -ErrorAction SilentlyContinue
    if ($entry) {
        Remove-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $IPAddress -Confirm:$false -ErrorAction Stop
        return $true
    }
    return $false
}

function Get-PingTimeMs {
    param([string[]]$PingOutput)
    $m = ($PingOutput | Select-String -Pattern "time[=<]\s*(\d+)ms").Matches
    if ($m.Count -gt 0) { return $m[0].Groups[1].Value }
    if ($PingOutput -match "time<\s*1ms") { return "1" }
    return $null
}

# ---------------- Main ----------------

try {
    Invoke-SelfCheck -InterfaceAlias $ifAlias

    $ctx = Get-NicContext -InterfaceAlias $ifAlias
    $gateway = $ctx.Gateway

    Write-Log "NIC: $ifAlias" "INFO"
    Write-Log ("Anchor IP: {0}/{1}" -f $ctx.IPAddress, $ctx.PrefixLength) "INFO"
    Write-Log ("Subnet: {0}/{1} (broadcast {2})" -f $ctx.Network, $ctx.PrefixLength, $ctx.Broadcast) "INFO"
    Write-Log ("Gateway: {0}" -f $gateway) "INFO"
    Write-Log ("Stability: {0} consecutive replies required before removal." -f $requiredConsecutiveSuccess) "INFO"

    # Validate offsets fit the subnet size
    [uint32]$usableHosts = $ctx.BroadcastInt - $ctx.NetworkInt - 1
    $maxOffset = ($hostOffsets | Measure-Object -Maximum).Maximum
    if ([uint32]$maxOffset -gt $usableHosts) {
        throw "Host offset $maxOffset doesn't fit in subnet /$($ctx.PrefixLength). Usable host offsets are 1..$usableHosts."
    }

    # Build sources as Network + offsets
    $sources = $hostOffsets | ForEach-Object {
        Convert-IntToIPv4 ([uint32]($ctx.NetworkInt + [uint32]$_))
    }
    Write-Log ("Sources: {0}" -f ($sources -join ", ")) "INFO"

    # Add source IPs to adapter with correct PrefixLength
    Ensure-SourceIPsOnAdapter -InterfaceAlias $ifAlias -IPAddresses $sources -PrefixLength $ctx.PrefixLength

    # Track pending and streaks
    $pending = [System.Collections.Generic.List[string]]::new()
    $successStreak = @{}
    foreach ($src in $sources) {
        [void]$pending.Add($src)
        $successStreak[$src] = 0
    }

    Write-Log "Beginning ping loop: only STABLE successes will be printed/logged; stable IPs are removed." "INFO"
    Write-Log "Press Ctrl+C to stop." "INFO"

    while ($true) {
        foreach ($src in @($pending)) {

            $out = & ping.exe -n 1 -w $pingTimeoutMs -S $src $gateway 2>&1
            $rc  = $LASTEXITCODE
            $isReply = ($rc -eq 0 -and ($out -match "Reply from $([regex]::Escape($gateway))"))

            if ($isReply) { $successStreak[$src]++ } else { $successStreak[$src] = 0 }

            if ($successStreak[$src] -ge $requiredConsecutiveSuccess) {
                $timeMs = Get-PingTimeMs -PingOutput $out
                $msg = if ($timeMs) {
                    "STABLE SUCCESS ($requiredConsecutiveSuccess x): $src -> $gateway time=${timeMs}ms. Removing $src from NIC."
                } else {
                    "STABLE SUCCESS ($requiredConsecutiveSuccess x): $src -> $gateway. Removing $src from NIC."
                }

                Write-Log $msg "SUCCESS"
                if ($beepOnStableSuccess) { [console]::Beep(1000, 150) }

                if (Remove-SourceIPFromAdapter -InterfaceAlias $ifAlias -IPAddress $src) {
                    Write-Log "Removed $src from '$ifAlias'." "INFO"
                    [void]$pending.Remove($src)
                } else {
                    Write-Log "Could not remove $src (not found on '$ifAlias'). Removing from pending anyway." "WARN"
                    [void]$pending.Remove($src)
                }
            }
        }

        if ($pending.Count -eq 0) {
            Write-Log "Done: all source IPs achieved stability and were removed." "INFO"
            break
        }

        Start-Sleep -Milliseconds $pollDelayMs
    }
}
catch {
    Write-Log ("Unhandled error: {0}" -f $_.Exception.Message) "ERROR"
    Write-Log $_.Exception.ToString() "ERROR"
    throw
}
finally {
    Write-Log "Script exiting." "INFO"
}
