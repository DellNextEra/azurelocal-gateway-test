[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$InterfaceAlias = "Integrated NIC 1 Port 1-1",

  [Parameter(Mandatory=$false)]
  [string[]]$HostOffsets = (26..31),

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
# Run PowerShell as Administrator

$ifAlias = "Integrated NIC 1 Port 1-1"

# If HostOffsets is passed as strings, normalize to ints
$hostOffsets = $HostOffsets | ForEach-Object { [int]$_ }
``
# Require this many consecutive replies before declaring "stable"
$requiredConsecutiveSuccess = 3

# Timing
$pollDelayMs   = 500
$pingTimeoutMs = 500

# Notification
$beepOnStableSuccess = -not $NoBeep

# -------- Logging --------
$logDir  = "C:\Temp"
if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
$logPath = Join-Path $logDir ("GatewayPing_{0}.log" -f (Get-Date -Format "yyyyMMdd_HHmmss"))

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","SUCCESS")][string]$Level = "INFO"
    )
    $stamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line  = "{0} [{1}] {2}" -f $stamp, $Level, $Message

    # Write to console (colored) + log file
    switch ($Level) {
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        default   { Write-Host $line -ForegroundColor Gray }
    }

    Add-Content -Path $logPath -Value $line
}

Write-Log "Starting gateway stability ping script. Log file: $logPath" "INFO"

# ---------------- Helpers ----------------

function Convert-IPv4ToInt {
    param([Parameter(Mandatory)][string]$IPv4)
    $bytes = [System.Net.IPAddress]::Parse($IPv4).GetAddressBytes()
    [Array]::Reverse($bytes)
    [BitConverter]::ToUInt32($bytes, 0)
}

function Convert-IntToIPv4 {
    param([Parameter(Mandatory)][uint32]$Int)
    $bytes = [BitConverter]::GetBytes($Int)
    [Array]::Reverse($bytes)
    ([System.Net.IPAddress]::new($bytes)).ToString()
}

function Get-SubnetMaskIntFromPrefix {
    param([Parameter(Mandatory)][int]$PrefixLength)
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { throw "Invalid PrefixLength: $PrefixLength" }
    if ($PrefixLength -eq 0) { return [uint32]0 }
    return [uint64]0xFFFFFFFF -shl (32 - $PrefixLength)
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

    $maskInt  = [uint32](Get-SubnetMaskIntFromPrefix $ipObj.PrefixLength)
    $ipInt    = Convert-IPv4ToInt $ipObj.IPAddress
    $netInt   = $ipInt -band $maskInt
    $bcastInt = $netInt -bor ([uint32]0xFFFFFFFF -bxor $maskInt)

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
    $ctx = Get-NicContext -InterfaceAlias $ifAlias
    $gateway = $ctx.Gateway

    Write-Log "NIC: $ifAlias" "INFO"
    Write-Log ("Anchor IP: {0}/{1}" -f $ctx.IPAddress, $ctx.PrefixLength) "INFO"
    Write-Log ("Subnet: {0}/{1} (broadcast {2})" -f $ctx.Network, $ctx.PrefixLength, $ctx.Broadcast) "INFO"
    Write-Log ("Gateway: {0}" -f $gateway) "INFO"
    Write-Log ("Stability: {0} consecutive replies required before removal." -f $requiredConsecutiveSuccess) "INFO"

    # Validate offsets fit the subnet size
    $usableHosts = $ctx.BroadcastInt - $ctx.NetworkInt - 1
    $maxOffset = ($hostOffsets | Measure-Object -Maximum).Maximum
    if ($maxOffset -gt $usableHosts) {
        throw "Host offset $maxOffset doesn't fit in subnet /$($ctx.PrefixLength). Usable host offsets are 1..$usableHosts."
    }

    # Build sources as Network + offsets
    $sources = $hostOffsets | ForEach-Object { Convert-IntToIPv4 ($ctx.NetworkInt + $_) }
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
