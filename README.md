# Windows 365 Network Health Check

A PowerShell script that tests connectivity to every endpoint required for Windows 365 and Azure Virtual Desktop - covering the Cloud PC host network, the end user client device, Intune, and Windows Autopilot.

Built and maintained by [Daniel Bowker](https://bowker.cloud) - Microsoft MVP for Windows 365.

## Credit

Inspired by [Shannon Fritz's original gist](https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3).

---

## Overview

Network connectivity issues are one of the most common causes of Windows 365 provisioning failures and poor Cloud PC experiences. Microsoft's requirements are spread across four separate documentation pages. This script brings them all together and tests them in one run.

**442 endpoint entries** across:

| Category | Entries | Covers |
|----------|---------|--------|
| `Intune` | 254 | Core service, Win32 apps, WNS push, Delivery Optimization, MAA attestation, published IP ranges |
| `Intune-Autopilot` | 59 | Windows Update, NTP, TPM attestation, diagnostics upload |
| `W365-CloudPC` | 28 | Provisioning, IoT hubs, registration |
| `AVD-SessionHost` | 24 | Session host required endpoints, Azure fabric IPs |
| `Intune-RemoteHelp` | 23 | Remote Help (only if you use the feature) |
| `Client-AVD` | 20 | End user device endpoints |
| `Client-AVD-CertCA` | 11 | Azure Certificate Authority CRL/OCSP, for closed networks |
| `AVD-SessionHost-Optional` | 10 | Session host optional endpoints |
| `Intune-Store` | 9 | Microsoft Store / app install |
| `Intune-RemoteHelp-GCC` | 4 | Remote Help for US Government tenants |

Conditional feature sets live in their own categories, so it is obvious which apply to your tenant and which you can ignore.

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
| `[ OK ]` | Connected. On port 443 this means a full TLS handshake with SNI, not just a TCP connect |
| `[FAIL]` | Resolved in DNS, but the connection failed - a firewall or policy block |
| `[DNS!]` | The name never resolved. A DNS problem, not a port problem - different fix entirely |
| `[TLS!]` | TCP port open but the TLS handshake failed - usually a proxy accepting the connection and refusing the hostname |
| `[INSP]` | TLS completed but the certificate chain roots outside the public CA programme - likely SSL inspection |
| `[ZONE]` | Wildcard with no stable public hostname; the parent DNS zone was confirmed authoritative instead |
| `[INFO]` | Published IP range, Azure-only check, or a reference-only entry |

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

> **Run it elevated.** The Azure fabric IPs do not answer a non-elevated connect, so an unelevated run can report them as unreachable when they are fine. Administrator is enough.

---

## Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `-Mode` | 1 = Cloud PC, 2 = Client, 3 = Both. Prompted if not supplied. | 0 (prompt) |
| `-EndpointsCSV` | Path to local Endpoints.csv. Downloads from GitHub if not supplied. | Auto |
| `-OutputPath` | Export results to CSV. | None |
| `-NoTlsCheck` | Skip TLS handshake and certificate validation; TCP connect only. | Off |
| `-SkipRegionPicker` | Skip the Intune IP-range region mapping (Modes 1 and 3). | Off |
| `-MaxParallel` | Concurrent probes. | 12 |

---

## How It Works

The script loads endpoints from `Endpoints.csv` (downloaded automatically from this repo). Each entry includes the endpoint, port, protocol, test mode, and a direct reference link to the relevant Microsoft documentation. Probes run concurrently, and identical host:port pairs are deduplicated so shared endpoints are tested once.

**Wildcards are tested, not skipped.** Of the 52 wildcard entries, most are validated by connecting to a real, verified host inside the zone - `*.wvd.microsoft.com` via `rdbroker.wvd.microsoft.com`, `*.manage.microsoft.com` via `m.manage.microsoft.com`, and so on. Where no stable public label exists, the parent zone is queried for an authoritative SOA record instead, which still catches DNS-layer filtering.

**TLS, not just TCP.** A plain TCP connect to port 443 cannot tell an allowed endpoint from a proxy that accepts the connection and blocks the hostname. Every 443 endpoint gets a real TLS handshake with SNI, and the certificate chain is walked to its root and compared against the public root CA programme.

**UDP is genuinely tested.** RDP Shortpath sends a real STUN binding request on UDP 3478 - on both the session host and the client side, since Microsoft require it for both. NTP sends a real SNTP packet and reports stratum plus clock skew; skew over five minutes is called out, because it breaks Entra authentication in ways that look unrelated.

**Azure fabric IPs are probed, not assumed.** IMDS gets a real HTTP request with the `Metadata` header; WireServer is checked on ports 80, 32526 and 53. If IMDS answers, the script knows it is in Azure and stops offering "not an Azure VM" as an explanation for a silent WireServer - the usual cause there is security context, not the network.

**Both ports are tested where Microsoft list both.** Many endpoint sets are documented as "TCP: 80, 443", and testing only 443 misses the port that carries the payload for Windows Update and Delivery Optimization. Every port-80 entry was verified to actually listen there before being added; three hosts documented as 80,443 only ever answer on 443, so they are not tested on 80 rather than reporting a permanent false failure.

**Published IP ranges are deliberately not probed.** The CIDR entries collapse into grouped summary lines. Testing individual IPs inside a global range produces misleading results, because not every published address serves traffic from every region at any given time. Allow them at the firewall and verify by rule. The full list still exports via `-OutputPath`.

### Pre-flight environment report

Before testing, the script reports the things that change what the results mean: the security context it is running in, whether a system proxy is configured, whether a local ZTNA/SWG agent is intercepting traffic (detected behaviourally, using a control probe to an unroutable address), whether IPv6 egress works, and whether TLS validation is on.

### The Intune region picker (Modes 1 and 3)

Modes 1 and 3 offer to narrow the Intune IP-range guidance to your Azure region. **This tests no connectivity** - it only decides which published CIDR ranges get printed in the summary. Use `-SkipRegionPicker` to skip it.

Only 21 regions are listed because Microsoft publish Intune service IPs in 21 of Azure's 77 regions; nothing is missing. The abbreviated names (`switzerlandn`, `germanywc`) are Microsoft's own service-tag spellings.

### Intune endpoints

Microsoft's documentation includes a caution that the Office 365 Endpoint API (`endpoints.office.com`) **no longer returns accurate data for Intune**. This script uses the static consolidated list from the Intune documentation directly - not the deprecated API.

### Reference-only and known-dead entries

Some endpoints appear in Microsoft's documentation but are not live. Rather than delete them, which would make the list a less faithful record of what Microsoft publish, they are handled in the CSV:

- **Reference only** (6 entries) - listed but never probed. `sinwns1011421.wns.windows.com` and five legacy `lgmsape*` Autopilot diagnostics endpoints superseded by the `amsu*lmsas` set.
- **Known dead** (3 entries) - `amsua0902lmsas`, `amsub0801lmsas` and `gcc.relay.remotehelp.microsoft.com`. These are still probed every run, but reported separately rather than as DNS failures, because there are no DNS forwarders to go and check. If Microsoft ever bring them up, that shows immediately.

---

## Files

| File | Description |
|------|-------------|
| `Test-W365NetworkHealth.ps1` | The script |
| `Endpoints.csv` | All 442 entries with category, port, protocol, test mode, notes, and a documentation reference |

`-OutputPath` exports every row with: `Category, Subcategory, Hostname, Port, Status, TestedAs, Detail, Rtt, Issuer, Notes, Timestamp`. `TestedAs` records which host was probed for each wildcard and `Issuer` the certificate chain root, so results are auditable rather than something you take on trust.

---

## Scope: commercial Azure cloud

Every endpoint is audited against the four Microsoft pages below. Coverage for commercial Azure is complete:

| Source | Covered |
|---|---|
| Windows 365 service (Enterprise) | 16/16 |
| AVD session hosts - required | 23/23 |
| AVD session hosts - optional | 9/9 |
| AVD end user devices | 18/18 |
| Intune Consolidated Endpoint List | 59/59 |
| Intune MAA attestation | 16/16 |
| Autopilot diagnostics upload | 34/34 |

**Government clouds are not covered.** If you run Windows 365 Government (GCC / GCC High), this script will not test the endpoints you need - the Windows 365 Government tab (`*.infra.windows365.microsoft.us`, the `.us` IoT hubs, `login.microsoftonline.us`, `rdweb`/`rdbroker.wvd.azure.us`, the GCCH Intune URLs) and the AVD "Azure for US Government" tables are all out of scope. Use Microsoft's Government endpoint documentation directly for those.

---

## Endpoint Sources

All endpoints are sourced directly from Microsoft documentation:

- [Network requirements for Windows 365](https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network)
- [Required FQDNs and endpoints for AVD – Session Hosts](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#session-host-virtual-machines)
- [Required FQDNs and endpoints for AVD – End User Devices](https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint?tabs=azure#end-user-devices)
- [Network endpoints for Microsoft Intune](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints)
- [Azure Certificate Authority details](https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details)
- [Azure communication IPs (WireServer / IMDS)](https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips)

### Known discrepancies in Microsoft's documentation

Validated against live DNS. Reported rather than hidden:

- `sinwns1011421.wns.windows.com` - listed in endpoints table 171, absent from the Consolidated Endpoint List on the same page, and returns an authoritative NXDOMAIN globally. Confirmed via EDNS Client Subnet from Singapore, Sydney and London, so it is not region-scoped.
- `amsua0902lmsas.blob.core.windows.net` and `amsub0801lmsas.blob.core.windows.net` - listed in table 182, neither resolves.
- `gcc.relay.remotehelp.microsoft.com` - listed in table 188, does not resolve.

---

## Requirements

- PowerShell 5.1 or later (PowerShell 7 recommended)
- Outbound internet access to test against (or run from the network you want to validate)
- No modules or dependencies required

> **If you edit the script:** keep it **ASCII-only, with no BOM**. Both matter and they pull against each other. A BOM breaks `irm | iex` - `Invoke-RestMethod` keeps it at the start of the string, so `[CmdletBinding()]` is no longer the first statement and you get `Unexpected attribute 'CmdletBinding'`. Non-ASCII characters without a BOM break Windows PowerShell 5.1 reading the file from disk, because 5.1 falls back to Windows-1252. Staying ASCII-only satisfies both.

---

## Limitations and Caveats

**Proxy servers are not traversed.** TCP and TLS sockets bypass WinHTTP and WinInet proxy settings. The script detects a configured proxy and warns you, but results still describe the direct path, not the path real client traffic takes. Microsoft do not support SSL inspection for `*.manage.microsoft.com`, `*.dm.microsoft.com`, the Device Health Attestation endpoints, Defender for Endpoint, Endpoint Privilege Management, or the Microsoft Store API - the `[INSP]` result exists to help you find those.

**VPN split tunnelling affects results.** The script tests from whatever network path is active. With split tunnelling, Microsoft 365 and Azure traffic may bypass the VPN entirely, so results will not reflect the enforced routing policy.

**User context vs system context.** Autopilot OOBE, Windows Update and TPM attestation run as SYSTEM. User-context connectivity does not guarantee system context can reach the same endpoints. To test that path: `psexec.exe -accepteula -i -s powershell.exe`.

**Wildcards confirmed at zone level only.** Some wildcard entries have no stable public hostname to connect to. DNS resolution is confirmed but the port is not proven open - verify your firewall rule covers the whole wildcard.

**Some endpoints are excluded from TLS validation, deliberately.** Windows Update and Delivery Optimization content is served by third-party CDNs (Akamai, Fastly) that present a certificate not covering the hostname - `fallback.tls.fastly.net` or `a248.e.akamai.net`. Every candidate host in those zones was tested and none has a matching certificate, so a TLS check there proves nothing and fails unpredictably. Those rows are marked `NoTls` in the CSV and TCP-tested only. What matters for them is **port 80**: the content is signed and fetched over HTTP.

**Run it from the right place.** Mode 1 on the Cloud PC or a VM in the same Azure VNet. Mode 2 on the physical client device on the end user's network.

---

## Contributing

If Microsoft update their network requirements and something needs adding or changing, raise an issue or submit a PR against `Endpoints.csv`.

---

## Legal

This script is provided under the [MIT License](LICENSE) - free to use, modify, and distribute.

It is provided as-is, without warranty of any kind. Always review scripts before running them in your environment. This tool is not affiliated with or endorsed by Microsoft.

---

*[bowker.cloud](https://bowker.cloud) - Cutting Through the Endpoint Chaos*
