# Azure Local Gateway Stability Test

Runs gateway ping tests from temporary source IPs (network+26..31) on a chosen NIC.
Requires 3 consecutive successful replies before reporting stability and removing each temporary IP.

## Quick Run (from URL) - Admin PowerShell
> Review the script before running in production environments.

```powershell
irm "https://raw.githubusercontent.com/DellNextEra/azurelocal-gateway-test/main/Invoke-GatewayStabilityTest.ps1" | iex
