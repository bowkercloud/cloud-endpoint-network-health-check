# Windows 365 Network Health Check

A PowerShell script for testing the network connectivity required by Windows 365 and Azure Virtual Desktop, covering the Cloud PC or session host network, the end user device, Microsoft Intune and Windows Autopilot.

Built and maintained by [Daniel Bowker](https://bowker.cloud) - Microsoft MVP for Windows 365.

## Credit

Inspired by [Shannon Fritz's original gist](https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3).

---

## Overview

Network connectivity is one of the most common causes of Windows 365 provisioning failures and poor Cloud PC experiences.

The challenge is that the network requirements sit across multiple Microsoft documentation pages covering Windows 365, Azure Virtual Desktop, Intune, Windows Autopilot and supporting Azure services.

This script brings those requirements together and tests them in one run.

The latest version covers **442 endpoint entries** across:

| Category | Entries | Covers |
|----------|---------|--------|
| `Intune` | 254 | Core service, Win32 apps, WNS, Delivery Optimization, MAA attestation and published IP ranges |
| `Intune-Autopilot` | 59 | Windows Update, NTP, TPM attestation and diagnostics |
| `W365-CloudPC` | 28 | Windows 365 provisioning, IoT hubs and registration |
| `AVD-SessionHost` | 24 | Required AVD session host endpoints and Azure fabric IPs |
| `Intune-RemoteHelp` | 23 | Remote Help |
| `Client-AVD` | 20 | End user device endpoints |
| `Client-AVD-CertCA` | 11 | Azure Certificate Authority CRL/OCSP endpoints |
| `AVD-SessionHost-Optional` | 10 | Optional AVD session host endpoints |
| `Intune-Store` | 9 | Microsoft Store and app installation |
| `Intune-RemoteHelp-GCC` | 4 | Remote Help endpoints for US Government tenants |

Conditional services such as Remote Help and Microsoft Store are kept in separate categories, making it easier to see which requirements apply to your environment.

---

## What It Tests

This has moved quite a long way beyond a basic port checker.

The script now validates:

- TCP connectivity
- TLS handshakes with SNI
- Certificate chains and likely SSL inspection
- DNS resolution failures separately from port failures
- Wildcard endpoints
- RDP Shortpath using a real STUN request over UDP 3478
- NTP using SNTP, including clock skew
- Azure IMDS and WireServer
- IPv6 connectivity
- Endpoint connection latency
- Configured system proxies
- Behaviour that may indicate local ZTNA/SWG interception
- Required port 80 connectivity where Microsoft document both 80 and 443

Tests run concurrently and duplicate host/port combinations are only tested once.

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
| `[ OK ]` | Connection succeeded. On port 443 this includes a TLS handshake where applicable |
| `[FAIL]` | DNS resolved but the connection failed |
| `[DNS!]` | The hostname could not be resolved |
| `[TLS!]` | TCP connected but the TLS handshake failed |
| `[INSP]` | Certificate chain indicates likely SSL inspection |
| `[ZONE]` | Wildcard has no stable hostname to test, so the parent DNS zone was validated |
| `[INFO]` | Informational result such as an IP range, Azure-specific check or reference entry |

Separating these results matters. A DNS problem, firewall block and SSL inspection issue can all break connectivity, but they need completely different fixes.

---

## Running the Script

**PowerShell 7 is recommended:**

```powershell
irm https://bowker.cloud/w365check | iex
```

**From CMD or the Windows Run dialog:**

```powershell
pwsh -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/w365check | iex"
```

**Windows PowerShell 5.1:**

```powershell
powershell -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/w365check | iex"
```

**Run locally:**

```powershell
.\Test-W365NetworkHealth.ps1
.\Test-W365NetworkHealth.ps1 -Mode 1
.\Test-W365NetworkHealth.ps1 -Mode 2 -OutputPath C:\Temp\results.csv
.\Test-W365NetworkHealth.ps1 -Mode 3 -EndpointsCSV .\Endpoints.csv
```

> **I'd recommend running it elevated.** Some Azure fabric checks behave differently from a non-elevated PowerShell session. Administrator is enough.

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Mode` | 1 = Cloud PC, 2 = Client, 3 = Both. Prompted if not supplied | Prompt |
| `-EndpointsCSV` | Use a local Endpoints.csv rather than downloading it | Auto |
| `-OutputPath` | Export all results to CSV | None |
| `-NoTlsCheck` | Skip TLS and certificate validation and use TCP only | Off |
| `-SkipRegionPicker` | Skip Intune IP range region mapping | Off |
| `-MaxParallel` | Number of concurrent probes | 12 |

---

## Wildcard Endpoints

One of the biggest changes from the original script is that **wildcards are no longer simply skipped**.

Where possible, the script uses a verified hostname within the wildcard to test connectivity.

For example:

```text
*.wvd.microsoft.com
```

can be tested using a known live service within that namespace.

Where there isn't a reliable public hostname to use, the script checks the parent DNS zone instead. This doesn't prove that every destination inside the wildcard is reachable, but it does catch common DNS filtering problems and is much more useful than simply returning `[SKIP]`.

---

## TLS and SSL Inspection

A successful TCP connection to port 443 doesn't necessarily mean the service is usable.

A proxy or security product can accept the TCP connection locally and then block the actual hostname further into the connection.

For endpoints where TLS validation is appropriate, the script performs a full TLS handshake with SNI and checks the certificate chain.

This can identify:

- TCP connectivity working but TLS failing
- Certificate chains that indicate likely SSL inspection
- Situations where a security agent or proxy is accepting traffic locally

Some Windows Update and Delivery Optimization endpoints are deliberately excluded from TLS validation because of the way Microsoft content is delivered through third-party CDNs. These are TCP-tested instead.

---

## UDP Testing

UDP is no longer reported as something you need to check manually.

### RDP Shortpath

The script sends a real STUN binding request over UDP 3478.

This is tested from both the session host and client side where required by Microsoft.

### NTP

The script sends a real SNTP request and reports the response, including clock skew.

Large time differences are worth knowing about because they can cause Entra authentication problems that don't immediately look network related.

---

## Azure Fabric Checks

When running Mode 1, the script also checks Azure-specific services including:

- Azure Instance Metadata Service (IMDS)
- WireServer on the documented ports

IMDS is used to confirm whether the machine is actually running inside Azure, allowing the script to give more useful guidance for the remaining Azure checks.

---

## Intune IP Range Region Picker

Modes 1 and 3 can optionally map Microsoft's published Intune IP ranges against the Azure regions where those ranges are located.

This is important:

**The region picker does not test connectivity.**

It simply reduces the IP-range guidance shown at the end of the run so you're not presented with ranges that aren't relevant to the Azure region you're testing from.

Use:

```powershell
-SkipRegionPicker
```

if you don't need it.

---

## Published IP Ranges

Published CIDR ranges are deliberately not tested one IP at a time.

Choosing a random address inside a Microsoft global range and checking whether it responds doesn't prove whether the firewall rule is correct and can easily create false failures.

Instead, the ranges are grouped in the results and should be validated against your firewall or NSG rules.

The full list is still included when exporting results to CSV.

---

## Endpoint CSV

`Endpoints.csv` remains the source of truth for the endpoint list.

Each entry includes the endpoint, port, protocol, mode, notes and the relevant Microsoft documentation reference.

This means Microsoft network requirement changes can normally be handled by updating the CSV rather than changing the PowerShell code.

The CSV also keeps track of a small number of endpoints that Microsoft still publish but which are no longer live, without turning them into misleading failures on every run.

---

## CSV Export

Use `-OutputPath` if you want a complete record of the test:

```powershell
.\Test-W365NetworkHealth.ps1 -Mode 1 -OutputPath C:\Temp\W365NetworkHealth.csv
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
Timestamp
```

This is useful for troubleshooting, attaching results to tickets or comparing runs from different network locations.

---

## Scope

The endpoint list has been audited against Microsoft's published requirements for the **commercial Azure cloud**.

Coverage includes:

| Source | Coverage |
|---|---:|
| Windows 365 service | 16/16 |
| AVD session host required | 23/23 |
| AVD session host optional | 9/9 |
| AVD end user devices | 18/18 |
| Intune Consolidated Endpoint List | 59/59 |
| Intune MAA attestation | 16/16 |
| Autopilot diagnostics | 34/34 |

### Government clouds

Windows 365 Government and the Azure Government-specific AVD and Intune endpoint sets are currently outside the scope of the script.

If you're using GCC or GCC High, check the relevant Microsoft Government cloud documentation rather than relying on these results alone.

---

## Microsoft Sources

All endpoint requirements come directly from Microsoft documentation:

- [Network requirements for Windows 365](https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network)
- [Required FQDNs and endpoints for AVD - Session Hosts](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#session-host-virtual-machines)
- [Required FQDNs and endpoints for AVD - End User Devices](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices)
- [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints)
- [Azure Certificate Authority details](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details)
- [Azure communication IPs](https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips)

### A note on Intune

Microsoft specifically warns that the Office 365 Endpoint API (`endpoints.office.com`) no longer provides an accurate endpoint list for Intune.

For that reason, this script uses Microsoft's published Intune Consolidated Endpoint List rather than trying to dynamically pull the information from the deprecated API.

---

## Limitations and Caveats

There are a few things worth understanding before acting on a result.

### Proxies

The socket tests do not traverse WinHTTP or WinInet proxy settings.

If your environment relies on a traditional proxy, the script reports the direct network path. It will tell you when a proxy is configured, but it cannot guarantee that traffic travelling through that proxy will behave the same way.

### ZTNA and Secure Web Gateway clients

Products such as ZTNA and Secure Web Gateway agents can intercept traffic without configuring a traditional Windows proxy.

The script performs additional behavioural checks to help identify this, but these should still be treated as diagnostic indicators rather than proof of a specific vendor or product.

### User vs SYSTEM context

Windows Autopilot, Windows Update and TPM attestation can operate as SYSTEM.

A successful user-context test doesn't necessarily guarantee that SYSTEM has the same network access.

For deeper troubleshooting you can run PowerShell as SYSTEM and repeat the test.

### VPN and split tunnelling

The script tests whichever network path is active when you run it.

If Microsoft traffic is split-tunnelled away from your corporate VPN, the result represents that direct path rather than the VPN egress route.

### Run it from the right place

Mode 1 should be run from the Cloud PC or a VM on the same Azure network.

Mode 2 should be run from the physical endpoint and network the user will actually use.

That sounds obvious, but it makes a big difference to what the results tell you.

---

## Requirements

- PowerShell 5.1 or later
- PowerShell 7 recommended
- Outbound internet access
- No additional PowerShell modules or dependencies

---

## Files

| File | Description |
|------|-------------|
| `Test-W365NetworkHealth.ps1` | Main PowerShell script |
| `Endpoints.csv` | Microsoft endpoint and network requirement data |

---

## Contributing

Microsoft change these requirements regularly.

If you spot something missing or Microsoft update one of the endpoint lists, raise an issue or submit a PR against `Endpoints.csv`.

---

## Legal

This script is provided under the [MIT License](LICENSE) and is free to use, modify and distribute.

It is provided as-is, without warranty of any kind. Always review scripts before running them in your environment.

This project is not affiliated with or endorsed by Microsoft.

---

*[bowker.cloud](https://bowker.cloud) - Cutting Through the Endpoint Chaos*