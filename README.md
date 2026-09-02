# Microsoft Cloud Endpoint Network Health Check

> [!IMPORTANT]
> **This repository is archived and retained for backwards compatibility.**
> Active development has moved to [Microsoft Cloud Endpoint Network Health Check](https://github.com/bowkercloud/Microsoft-Cloud-Endpoint-Network-Health-Check).
> Existing `https://bowker.cloud/w365check` commands and legacy file links remain available, but new users should use `https://bowker.cloud/endpointcheck` and the new repository.

**Microsoft Intune, Windows 365 & Azure Virtual Desktop**

PowerShell network validation for Microsoft Intune, Windows 365 and Azure Virtual Desktop.

Built and maintained by [Daniel Bowker](https://bowker.cloud) - Microsoft MVP for Windows 365.

## Credit

Inspired by [Shannon Fritz's original gist](https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3).

---

## Overview

Network connectivity is behind a surprising number of endpoint problems. Failed device enrolment, Cloud PC provisioning failures, Win32 app deployment issues, Windows Update problems and poor remote session quality can all come back to something being blocked, intercepted or routed differently than expected.

The problem is that Microsoft publishes the requirements for Intune, Windows 365 and Azure Virtual Desktop across several different documentation pages.

This script brings them together and tests them in one run.

The current endpoint dataset contains **442 entries** across Microsoft Intune, Windows 365 and Azure Virtual Desktop in the commercial Microsoft cloud.

## What's new in v4.0

The script started life as a Windows 365 network checker, but it has grown quite a bit beyond that.

The biggest change in v4.0 is that **Microsoft Intune now has dedicated validation**, alongside Windows 365 and Azure Virtual Desktop.

You can now choose exactly what you want to validate:

```text
[1] All Cloud Endpoint requirements
[2] Microsoft Intune
[3] Windows 365
[4] Azure Virtual Desktop
```

The test then asks where you are running it from.

```text
[1] Host / Cloud Network
    (Cloud PC, AVD session host, or Azure VNet VM)

[2] Physical Client Device
    (Intune-managed Windows device, or device connecting to a Cloud PC or
     AVD session host using Windows App)

[3] Both
```

This keeps two different questions separate:

```text
Workload = WHAT you are validating
Mode     = WHERE you are testing from
```

Windows 365 also includes the Intune, AVD and Azure platform dependencies it actually relies on. It is deliberately not just a test of the `W365-CloudPC` endpoints.

Other changes across the recent overhaul include:

- Real TLS handshakes with SNI, not just TCP 443
- Likely SSL inspection detection
- DNS failures reported separately from port failures
- Wildcard endpoints actually tested where possible
- Real UDP testing for RDP Shortpath
- SNTP/NTP testing including clock skew
- Azure IMDS and WireServer checks
- IPv6 connectivity checks
- Connection latency reporting
- ZTNA/Secure Web Gateway interception checks
- Port 80 validation where Microsoft require both 80 and 443
- Parallel endpoint testing and host/port deduplication
- Optional Intune IP range filtering
- Improved `Get-Help` documentation and parameter examples

---

## Workload and Mode

### Workloads

| Workload | Validates |
|----------|-----------|
| `All` | Everything below. The default. |
| `Intune` | Published Microsoft Intune network requirements for Windows devices |
| `Windows365` | Windows 365 service endpoints plus the AVD, Intune and Azure platform dependencies it relies on |
| `AVD` | Azure Virtual Desktop session host and client requirements |

### Modes

| Mode | Description | Run from |
|------|-------------|----------|
| 1 | Host / Cloud Network | Cloud PC, AVD session host, or VM in the Azure network you want to validate |
| 2 | Physical Client Device | Intune-managed Windows device, or the device connecting to a Cloud PC or AVD session host using Windows App |
| 3 | Both | Runs both in sequence |

### Examples

```powershell
.\Test-W365NetworkHealth.ps1 -Workload Intune -Mode 2
.\Test-W365NetworkHealth.ps1 -Workload Windows365 -Mode 1
.\Test-W365NetworkHealth.ps1 -Workload AVD -Mode 3
.\Test-W365NetworkHealth.ps1 -Workload All -Mode 3
```

Commands written before workload selection existed still work unchanged. `-Workload` is optional and defaults to `All`.

---

## Microsoft Intune

Intune now has dedicated validation rather than being tested only as part of Windows 365.

`-Workload Intune` validates the published Microsoft Intune network requirements for Windows devices in the commercial Microsoft cloud, including:

- Core Intune service connectivity
- Intune Management Extension and Win32 apps
- Windows Push Notification Services
- Delivery Optimization and Windows Update dependencies
- Windows Autopilot, including diagnostics upload
- Microsoft Azure Attestation
- Microsoft Store
- Remote Help
- Endpoint Privilege Management dependencies present in Microsoft's Intune endpoint list
- PowerShell Gallery and OneGet
- Published Intune IP ranges, including the Azure Front Door ranges used by Intune

Remote Help and Microsoft Store remain in their own categories so it is obvious which results relate to optional features your environment may not use.

Intune requirements are device requirements. That means the same Intune set can be tested from a Cloud PC or from a normal physical Intune-managed Windows device.

**Scope:** this validates Microsoft's published Intune network requirements for Windows devices in the commercial cloud. It does not claim to test every endpoint for every Microsoft product that integrates with Intune. Products with their own network documentation, such as Microsoft Defender for Endpoint and Security Copilot, may have additional requirements.

---

## Windows 365

Selecting `Windows365` does more than test the Windows 365 service endpoints.

Microsoft's Windows 365 network requirements include four separate areas: the physical device, Microsoft Intune, the AVD session host virtual machine and the Windows 365 service.

A Cloud PC is a Windows 365-managed desktop that relies on Intune, Azure Virtual Desktop connectivity components and Azure platform services, so testing only the Windows 365 service FQDNs could give you an all-green result while a genuine dependency is still blocked.

The Windows 365 workload therefore includes:

- Windows 365 service endpoints, including provisioning and IoT hub registration
- Required and optional AVD session host requirements
- Client-side AVD connectivity and certificate authority endpoints
- Intune requirements needed to provision and manage a Cloud PC
- Entra ID and authentication dependencies
- Azure fabric endpoints including IMDS and WireServer
- RDP connectivity and RDP Shortpath

It excludes optional Intune features that a Cloud PC does not need to provision, manage or connect, such as Remote Help and Microsoft Store.

---

## Azure Virtual Desktop

`-Workload AVD` covers:

- Required AVD session host endpoints
- Optional AVD session host endpoints
- Client-side connectivity
- Azure Certificate Authority endpoints
- Azure fabric IPs
- RDP Shortpath on both the host and client side

Mode still applies:

- `AVD -Mode 1` focuses on the host/session-host side
- `AVD -Mode 2` focuses on the physical client device, including the client side of RDP Shortpath
- `AVD -Mode 3` runs both

---

## Result Types

| Status | Meaning |
|--------|---------|
| `[ OK ]` | Connected. On port 443 this means a full TLS handshake with SNI where supported |
| `[FAIL]` | DNS resolved, but the connection failed |
| `[DNS!]` | The hostname did not resolve |
| `[TLS!]` | TCP connected but the TLS handshake failed |
| `[INSP]` | TLS completed but the certificate chain suggests likely SSL inspection |
| `[ZONE]` | Wildcard has no stable public hostname, so the parent DNS zone was validated instead |
| `[INFO]` | Published IP range, Azure-only check, reference entry or other informational result |

A DNS problem, firewall block and SSL inspection issue can all break the service, but they need completely different fixes. Keeping them separate is much more useful than a single generic failure.

---

## Running the Script

**PowerShell 7 is recommended:**

```powershell
irm https://bowker.cloud/endpointcheck | iex
```

**From CMD or the Windows Run dialog:**

```powershell
pwsh -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/endpointcheck | iex"
```

**Windows PowerShell 5.1:**

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/endpointcheck | iex"
```

The original `https://bowker.cloud/w365check` alias remains available for backwards compatibility.

**Review before running:**

```powershell
Invoke-WebRequest https://bowker.cloud/endpointcheck -OutFile .\Test-W365NetworkHealth.ps1
notepad .\Test-W365NetworkHealth.ps1
.\Test-W365NetworkHealth.ps1
```

> **Run it elevated.** Some Azure fabric checks behave differently from a non-elevated session and can otherwise appear unreachable when they are fine. Administrator is enough for the normal test.

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Workload` | `All`, `Intune`, `Windows365`, `AVD`. Prompted if not supplied. | Prompt, then `All` |
| `-Mode` | 1 = Host / Cloud Network, 2 = Physical Client Device, 3 = Both. | Prompt, then 1 |
| `-EndpointsCSV` | Path to a local Endpoints.csv. Downloads from GitHub if not supplied. | Auto |
| `-OutputPath` | Export results to CSV. | None |
| `-NoTlsCheck` | Skip TLS handshake and certificate validation; TCP only. | Off |
| `-NoIntuneIPFilter` | Never offer optional Intune IP range filtering. Alias: `-NoRegionFilter`. | Off |
| `-SkipRegionPicker` | Original parameter name, retained for backwards compatibility. | Off |
| `-MaxParallel` | Concurrent probes. | 12 |

---

## How It Works

The script loads endpoints from `Endpoints.csv`, normally downloaded automatically from the repository. Each entry includes its category, port, protocol, mode, workload membership, notes and a direct Microsoft documentation reference.

Probes run concurrently and identical host/port combinations are deduplicated, so a shared endpoint is tested once rather than repeatedly for every category.

### TLS, not just TCP

A successful TCP connection to port 443 does not always mean the service is usable.

A proxy, Secure Web Gateway or local security agent can accept the socket and then block the actual hostname when TLS starts.

Where appropriate, the script therefore performs a real TLS handshake with SNI and checks the certificate chain.

This helps distinguish between a blocked port, DNS problem, TLS failure and likely SSL inspection.

Some Windows Update and Delivery Optimization CDN endpoints are deliberately excluded from TLS validation because the certificates returned by the CDN do not reliably cover the Microsoft hostname. Those entries are TCP-tested instead rather than generating a false TLS failure.

### Wildcards are tested

Wildcard requirements are no longer automatically skipped.

Where a reliable hostname exists inside the wildcard, the script connects to a verified service within that namespace.

Where there is no stable public hostname, the parent DNS zone is checked instead.

That does not prove every possible FQDN inside the wildcard is allowed through the firewall, but it catches common DNS filtering problems and is much more useful than simply returning `[SKIP]`.

### UDP is genuinely tested

RDP Shortpath sends a real STUN binding request over UDP 3478 on both the host and client side where Microsoft require it.

NTP sends a real SNTP request and reports stratum and clock skew. A badly skewed clock can cause Entra authentication issues that initially look unrelated to networking.

### Port 80 matters

A number of Microsoft endpoint groups are documented as requiring both TCP 80 and 443.

That is particularly important for Windows Update and Delivery Optimization. Testing only 443 can give you a healthy result while the actual content path on port 80 is blocked.

The endpoint dataset includes port 80 where Microsoft require it and the destination genuinely responds on that port.

### Azure fabric checks

The script also understands Azure-specific services.

IMDS gets a real HTTP request using the required metadata header, while WireServer is checked on its documented ports.

If IMDS responds, the script knows it is running inside Azure and can interpret the remaining results accordingly.

### ZTNA and Secure Web Gateways

Modern ZTNA and Secure Web Gateway clients do not always configure a traditional Windows proxy.

The script performs behavioural checks that can help identify when traffic appears to be accepted locally rather than reaching the intended destination.

This is deliberately vendor-neutral.

It also understands that very low latency to Microsoft endpoints can be completely normal from a Cloud PC or Azure VM already sitting on Microsoft's backbone, so fast connectivity by itself is not treated as proof of interception.

---

## Optional Intune IP Range Filtering

Microsoft publishes Intune service IP ranges across a subset of Azure regions.

If useful, the script can filter the CIDR guidance shown at the end of the test.

This is **optional** and does not change any of the connectivity tests.

By default, the script shows all applicable Intune ranges.

If you choose regional filtering, your own Azure region may not appear in Microsoft's published mapping. A UK customer, for example, will not find UK South in that list. That is expected and does not mean anything is missing from the test.

If the Microsoft service-tag data cannot be downloaded or mapped, the script simply shows all applicable ranges and carries on. It is not treated as a health failure.

---

## Published IP Ranges

Published CIDR ranges are deliberately not probed one address at a time.

Picking a random IP from a global Microsoft range and seeing whether it responds does not prove whether your firewall configuration is correct, and can easily create false failures.

The ranges are therefore grouped as firewall/NSG guidance rather than presented as hundreds of individual probes.

The full detail is still available in the CSV export.

---

## CSV Export

Use `-OutputPath` if you want to retain the complete result set:

```powershell
.\Test-W365NetworkHealth.ps1 -Workload Intune -Mode 2 -OutputPath C:\Temp\CloudEndpointNetworkHealth.csv
```

The export includes:

```text
Category
Subcategory
Hostname
Port
Status
TestedAs
Detail
Rtt
Issuer
Notes
KnownDead
Workloads
SelectedWorkload
Timestamp
```

Useful for attaching evidence to a ticket, comparing tests from different networks or keeping a record of exactly what was checked.

---

## Files

| File | Description |
|------|-------------|
| `Test-W365NetworkHealth.ps1` | Main PowerShell script. The filename predates dedicated Intune and AVD validation and is retained so existing links, commands and automation keep working. |
| `Endpoints.csv` | All 442 endpoint entries with category, port, protocol, mode, workload membership, notes and Microsoft documentation reference |

`Endpoints.csv` remains the source of truth. Workload membership lives in the `Workloads` column, so shared dependencies can belong to more than one workload without duplicating rows.

---

## Scope

The project currently targets the **commercial Microsoft cloud**.

Coverage has been audited against Microsoft's published lists for:

| Source | Covered |
|---|---:|
| Windows 365 service (Enterprise) | 16/16 |
| AVD session hosts - required | 23/23 |
| AVD session hosts - optional | 9/9 |
| AVD end user devices | 18/18 |
| Intune Consolidated Endpoint List | 59/59 |
| Intune MAA attestation | 16/16 |
| Autopilot diagnostics upload | 34/34 |

**Government clouds are not currently covered.** If you use Windows 365 Government, GCC/GCC High or Azure Government-specific AVD/Intune endpoint sets, use the relevant Microsoft Government documentation rather than relying on this test alone.

---

## Endpoint Sources

All requirements are sourced from Microsoft documentation:

- [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints)
- [Network requirements for Windows 365](https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network)
- [Required FQDNs and endpoints for AVD - Session Hosts](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#session-host-virtual-machines)
- [Required FQDNs and endpoints for AVD - End User Devices](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices)
- [Azure Certificate Authority details](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details)
- [Azure communication IPs (WireServer / IMDS)](https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips)

### A note on Intune

Microsoft warns that the Office 365 Endpoint API (`endpoints.office.com`) no longer provides an accurate endpoint list for Intune.

The script therefore uses the static Consolidated Endpoint List from Microsoft's Intune documentation instead of relying on that API.

### Reference-only and known-dead entries

A small number of endpoints still appear in Microsoft's documentation but are not currently live.

Rather than silently deleting them, the CSV can mark them as reference-only or known-dead so the source data stays faithful to what Microsoft publish without generating the same misleading failure on every run.

If Microsoft bring one of the known-dead endpoints back, it will show up automatically.

---

## Requirements

- PowerShell 5.1 or later
- PowerShell 7 recommended
- Outbound internet access
- No additional PowerShell modules or dependencies

> **If you edit the script:** keep it **ASCII-only with no BOM**. This preserves both `irm | iex` and local Windows PowerShell 5.1 compatibility.

---

## Limitations and Caveats

**Proxy servers are not traversed.** TCP and TLS sockets bypass WinHTTP and WinInet proxy settings. The script reports when a proxy is configured, but the results describe the direct socket path.

**VPN split tunnelling affects results.** The test follows whatever network path is active when you run it.

**User context vs SYSTEM context.** Autopilot OOBE, Windows Update and TPM attestation can run as SYSTEM. A successful user-context test does not guarantee SYSTEM has the same path.

To test from SYSTEM:

```powershell
psexec.exe -accepteula -i -s powershell.exe
```

**Some wildcards are confirmed at DNS-zone level only.** Where there is no stable hostname to test, DNS can be validated but the individual port cannot be proven open.

**Some endpoints deliberately skip TLS validation.** Certain Windows Update and Delivery Optimization hostnames are delivered through third-party CDNs where certificate validation against the documented hostname is not meaningful. Those entries are TCP-tested only.

**Run it from the right place.** Mode 1 is for the Cloud PC, AVD session host or Azure VM/network you want to validate. Mode 2 is for the physical client device, either a normal Intune-managed Windows endpoint or the device used to connect through Windows App.

---

## Contributing

Microsoft regularly change their endpoint requirements.

If something needs adding or Microsoft update one of the published lists, raise an issue or submit a PR against `Endpoints.csv`.

---

## Legal

This script is available to use, modify and distribute under the [MIT License](LICENSE).

It is provided as-is, without warranty of any kind. Always review scripts before running them in your environment.

This project is not affiliated with or endorsed by Microsoft.

---

*[bowker.cloud](https://bowker.cloud) - Cutting Through the Endpoint Chaos*
