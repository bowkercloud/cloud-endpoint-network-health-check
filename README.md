# Windows 365 Network Health Check

A PowerShell script that tests connectivity to every endpoint required for Windows 365 and Azure Virtual Desktop - covering the Cloud PC host network, the end user client device, Intune, and Windows Autopilot.

Built and maintained by [Daniel Bowker](https://bowker.cloud) - Microsoft MVP for Windows 365.

## Credit

Inspired by [Shannon Fritz's original gist](https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3).

---

## Overview

Network connectivity issues are one of the most common causes of Windows 365 provisioning failures and poor Cloud PC experiences. Microsoft's requirements are spread across four separate documentation pages. This script brings them all together and tests them in one run.

**Over 200 endpoints** across:

- Windows 365 service (provisioning, IoT hubs, registration)
- AVD session host endpoints - required and optional
- End user device / client endpoints
- Intune core service, Win32 apps, WNS push, Delivery Optimization
- Windows Autopilot (Windows Update, NTP, TPM, diagnostics)
- Azure Certificate Authority (CRL/OCSP - for closed/restricted networks)

---

## Modes

| Mode | Description | Run from |
|------|-------------|----------|
| 1 | Cloud PC / Host Network | The Cloud PC or a VM in the same Azure VNet |
| 2 | Client Device Network | The physical device used to connect to the Cloud PC |
| 3 | Both | Runs all tests in sequence |

---

## Result Types

| Status | Meaning |
|--------|---------|
| `[ OK ]` | TCP connection succeeded |
| `[FAIL]` | TCP connection blocked or timed out |
| `[SKIP]` | Wildcard endpoint - cannot TCP test; verify DNS resolution manually |
| `[INFO]` | UDP or IP range entry - verify firewall/NSG allows outbound UDP |

---

## Running the Script

**From a PowerShell 7 prompt (recommended):**

```powershell
irm https://bowker.cloud/w365check | iex
```

**From a CMD prompt or Run dialog:**

```powershell
pwsh -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/w365check | iex"
```

**From Windows PowerShell 5.1:**

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/w365check | iex"
```

**Run locally with parameters:**

```powershell
.\Test-W365NetworkHealth.ps1
.\Test-W365NetworkHealth.ps1 -Mode 1
.\Test-W365NetworkHealth.ps1 -Mode 2 -OutputPath C:\Temp\results.csv
.\Test-W365NetworkHealth.ps1 -Mode 3 -EndpointsCSV .\Endpoints.csv
```

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Mode` | 1 = Cloud PC, 2 = Client, 3 = Both. Prompted if not supplied. | 0 (prompt) |
| `-EndpointsCSV` | Path to local Endpoints.csv. Downloads from GitHub if not supplied. | Auto |
| `-OutputPath` | Export results to CSV. | None |

---

## How It Works

The script loads endpoints from `Endpoints.csv` (downloaded automatically from this repo). Each entry includes the endpoint, port, protocol, test mode, and a direct reference link to the relevant Microsoft documentation.

For each testable endpoint, a TCP connection attempt is made with a 5 second timeout. Wildcards and UDP/IP range entries are flagged rather than tested, with guidance on what to verify manually.

At the end, a summary lists every failure, wildcard, and UDP/IP range entry that needs attention.

### Intune endpoints

Microsoft's documentation includes a caution that the Office 365 Endpoint API (`endpoints.office.com`) **no longer returns accurate data for Intune**. This script uses the static consolidated list from the Intune documentation directly - not the deprecated API.

---

## Files

| File | Description |
|------|-------------|
| `Test-W365NetworkHealth.ps1` | The script |
| `Endpoints.csv` | Over 200 endpoints with category, port, protocol, test mode, and documentation reference |

---

## Endpoint Sources

All endpoints are sourced directly from Microsoft documentation:

- [Network requirements for Windows 365](https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network)
- [Required FQDNs and endpoints for AVD – Session Hosts](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#session-host-virtual-machines)
- [Required FQDNs and endpoints for AVD – End User Devices](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices)
- [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints)
- [Azure Certificate Authority details](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details)

---

## Requirements

- PowerShell 5.1 or later (PowerShell 7 recommended)
- Outbound internet access to test against (or run from the network you want to validate)
- No modules or dependencies required

---

## Contributing

If Microsoft update their network requirements and something needs adding or changing, raise an issue or submit a PR against `Endpoints.csv`.

---

## Legal

This script is provided under the [MIT License](LICENSE) - free to use, modify, and distribute.

It is provided as-is, without warranty of any kind. Always review scripts before running them in your environment. This tool is not affiliated with or endorsed by Microsoft.

---

*[bowker.cloud](https://bowker.cloud) - Cutting Through the Endpoint Chaos*
