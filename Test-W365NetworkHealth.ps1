#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 365 & AVD Network Health Check

.DESCRIPTION
    Tests network connectivity to all endpoints required for Windows 365 Cloud PCs and Azure Virtual Desktop.
    Can be run from the Cloud PC (Host Network) or from the physical client device (Client Network).

    Endpoints are loaded from a companion Endpoints.csv file (recommended) or from built-in defaults.

    Run directly from GitHub:
    powershell -ExecutionPolicy Bypass -Command "irm https://bowker.cloud/w365check | iex"

.PARAMETER Mode
    1 = Cloud PC / Host Network
    2 = Client Device / Client Network
    3 = Both

.PARAMETER EndpointsCSV
    Path to the companion Endpoints.csv file. If not provided, the script will attempt to download it
    from the same GitHub location, then fall back to built-in defaults.

.PARAMETER OutputPath
    Optional path to export results to a CSV file.

.EXAMPLE
    .\Test-W365NetworkHealth.ps1
    .\Test-W365NetworkHealth.ps1 -Mode 1 -OutputPath C:\Temp\results.csv
    .\Test-W365NetworkHealth.ps1 -Mode 3 -EndpointsCSV .\Endpoints.csv

.NOTES
    Version:    2.5
    Blog:       https://bowker.cloud
    References:
        https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network
        https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint
        https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints
    Inspired by: https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3

    CHANGELOG:
    v2.5 - Region picker rebuilt using a working approach: since no dedicated
           MicrosoftIntune service tag exists, each published Intune IP range (ID
           163) is cross-referenced against the AzureCloud.<Region> tags (which do
           have full regional breakdown covering the entire Azure public IP space)
           using CIDR containment logic, to determine which region it physically
           belongs to. Verified against the real Azure IP Ranges JSON: all 81
           published ranges resolve cleanly to one of 21 regions. Front Door and
           IPv6 ranges are always shown regardless of region selection.
    v2.4 - Removed the Azure region picker for Intune IP ranges entirely. Diagnostic
           output in v2.3 confirmed there is no "MicrosoftIntune.<Region>" Azure
           service tag - Microsoft's own docs state Intune-related entries in the
           service tags JSON are filed under AzureFrontDoor.MicrosoftSecurity, not
           a dedicated per-region Intune tag. The ID 163 Intune client/host service
           IP list is a flat published list, not a formal regionally-broken-out
           service tag, so no live region filtering is possible. All IP ranges
           remain [INFO] entries with corrected guidance reflecting this.
    v2.3 - Region picker rewritten with mandatory [region-picker] prefixed checkpoint
           messages at every stage (page fetch, JSON download, parse, region count),
           printed unconditionally in DarkGray so the exact failure point is always
           visible, never silent. Simplified filename regex. Array-wrapped Where-Object
           results to avoid PS5.1 single-item unwrapping issues seen elsewhere in this
           script.
    v2.2 - FAILED endpoint output now shows the Notes field for context (e.g. regional
           WNS nodes). Region picker fetch failures now show explicit diagnostic
           messages instead of failing silently. More resilient regex-based parsing
           of the Microsoft service tags download link.
    v2.1 - Added Azure region picker for Intune IP range guidance (fetches live from
           Microsoft service tags JSON). IP ranges always shown as [INFO], never TCP
           tested. Added FABRIC status for 168.63.129.16 and 169.254.169.254 (Azure
           WireServer/IMDS) per https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips.
           Removed deprecated *.cmdagent.trafficmanager.net (consolidated into
           *.infra.windows365.microsoft.com per Microsoft).

    NOTE on Intune endpoints:
    Microsoft have deprecated the Office 365 Endpoint API (endpoints.office.com) for retrieving
    Intune FQDNs. Per Microsoft's own caution on the Intune endpoints page:
    "The previously available PowerShell scripts for retrieving Microsoft Intune endpoint IP addresses
    and FQDNs no longer return accurate data from the Office 365 Endpoint service."
    This script uses the static consolidated list from the Microsoft documentation instead.
#>

[CmdletBinding()]
param(
    [int]$Mode = 0,
    [string]$EndpointsCSV = '',
    [string]$OutputPath = ''
)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
$ScriptName     = 'Test-W365NetworkHealth'
$ScriptVersion  = 'v2.5'
$CSVGitHubURL   = 'https://raw.githubusercontent.com/bowkercloud/windows365/main/Endpoints.csv'
$TimeoutSeconds = 5

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Banner
# ─────────────────────────────────────────────────────────────────────────────
function Write-Banner {
    $banner = @"

   ___   ___  __    __  _  __ _____  ____       ____  _     ___  _   _ ____
  | __ )/ _ \| |  / / | |/ /| ____|  _ \     / ___|| |   / _ \| | | |  _ \
  |  _ \ | | | | /  / | ' / |  _|  | |_) |   | |    | |  | | | | | | | | | |
  | |_) | |_| | |/ /  | . \ | |___ |  _ <    | |___ | |__| |_| | |_| | |_| |
  |____/ \___/|_/_/   |_|\_\|_____||_| \_\    \____||_____\___/ \___/|____/
                                                           https://bowker.cloud

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  $ScriptName  $ScriptVersion" -ForegroundColor Blue
    Write-Host "  Windows 365 & AVD Network Health Check" -ForegroundColor Blue
    Write-Host ""
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Test a single host:port
# ─────────────────────────────────────────────────────────────────────────────
function Test-Endpoint {
    param(
        [string]$Hostname,
        [int]$Port,
        [string]$Protocol = 'TCP',
        [string]$Notes = '',
        [string]$Category = ''
    )

    $result = [PSCustomObject]@{
        Category  = $Category
        Hostname  = $Hostname
        Port      = $Port
        Status    = 'UNKNOWN'
        Notes     = $Notes
        Timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    }

    # Wildcard endpoints cannot be TCP-tested
    if ($Hostname -match '^\*') {
        $result.Status = 'WILDCARD'
        $pad = [string]::new(' ', [Math]::Max(0, 55 - ($Hostname.Length + $Port.ToString().Length)))
        Write-Host "  [" -NoNewline
        Write-Host "SKIP" -ForegroundColor DarkYellow -NoNewline
        Write-Host "] $Hostname`:$Port$pad (wildcard - verify DNS resolution manually)" -ForegroundColor DarkYellow
        return $result
    }

    # Azure platform fabric IPs (WireServer / IMDS) - cannot be reliably TCP tested
    # Per https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips
    # these addresses operate at the Azure fabric level, must not be intercepted,
    # proxied, or redirected, and can behave differently to normal endpoints.
    if ($Hostname -eq '168.63.129.16' -or $Hostname -eq '169.254.169.254') {
        $result.Status = 'FABRIC'
        $pad = [string]::new(' ', [Math]::Max(0, 55 - ($Hostname.Length + $Port.ToString().Length)))
        Write-Host "  [" -NoNewline
        Write-Host "INFO" -ForegroundColor DarkCyan -NoNewline
        Write-Host "] $Hostname`:$Port$pad (Azure fabric IP - not reliably TCP testable, must not be proxied/intercepted)" -ForegroundColor DarkCyan
        return $result
    }

    # IP ranges (CIDR) - always flag as INFO, recommend service tag at firewall.
    # Raw TCP tests against individual IPs in a global range produce misleading
    # results, since not every published IP is actively serving traffic from
    # every Azure region at any given time.
    if ($Hostname -match '/\d+$') {
        $result.Status = 'IPRANGE'
        $pad = [string]::new(' ', [Math]::Max(0, 55 - ($Hostname.Length + $Port.ToString().Length)))
        Write-Host "  [" -NoNewline
        Write-Host "INFO" -ForegroundColor DarkCyan -NoNewline
        if ($Hostname -match ':') {
            Write-Host "] $Hostname  TCP:$Port$pad (IPv6 range - verify firewall allows IPv6 outbound)" -ForegroundColor DarkCyan
        } elseif ($Protocol -eq 'UDP' -or $Port -eq 3478) {
            Write-Host "] $Hostname  UDP:$Port$pad (IP range - verify firewall/NSG allows UDP $Port outbound)" -ForegroundColor DarkCyan
        } else {
            Write-Host "] $Hostname  TCP:$Port$pad (IP range - published Intune range, allow at firewall)" -ForegroundColor DarkCyan
        }
        return $result
    }

    # time.windows.com is UDP/123 - flag rather than TCP test
    if ($Port -eq 123) {
        $result.Status = 'UDPONLY'
        $pad = [string]::new(' ', [Math]::Max(0, 55 - ($Hostname.Length + $Port.ToString().Length)))
        Write-Host "  [" -NoNewline
        Write-Host "INFO" -ForegroundColor DarkCyan -NoNewline
        Write-Host "] $Hostname  UDP:$Port$pad (UDP only - NTP; verify firewall allows UDP 123 outbound)" -ForegroundColor DarkCyan
        return $result
    }

    $pad = [string]::new(' ', [Math]::Max(0, 55 - ($Hostname.Length + $Port.ToString().Length)))
    Write-Host "  [    ] $Hostname`:$Port$pad" -NoNewline

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connect   = $tcpClient.BeginConnect($Hostname, $Port, $null, $null)
        $wait      = $connect.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds), $false)

        if ($wait -and -not $tcpClient.Client.Poll(0, [System.Net.Sockets.SelectMode]::SelectError)) {
            $tcpClient.EndConnect($connect) 2>$null
            $result.Status = 'OK'
            Write-Host "`r  [" -NoNewline
            Write-Host " OK " -ForegroundColor Green -NoNewline
            Write-Host "] $Hostname`:$Port$pad"
        } else {
            $result.Status = 'FAIL'
            Write-Host "`r  [" -NoNewline
            Write-Host "FAIL" -ForegroundColor Red -NoNewline
            Write-Host "] $Hostname`:$Port$pad"
        }
        $tcpClient.Close()
    } catch {
        $result.Status = 'FAIL'
        Write-Host "`r  [" -NoNewline
        Write-Host "FAIL" -ForegroundColor Red -NoNewline
        Write-Host "] $Hostname`:$Port  ($_)"
    }

    return $result
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Test a list of endpoints from CSV data
# ─────────────────────────────────────────────────────────────────────────────
function Test-EndpointList {
    param(
        [array]$Endpoints,
        [string]$FilterMode   # 'CloudPC', 'Client', or 'Both'
    )

    $allResults = @()
    $categories = $Endpoints | Select-Object -ExpandProperty Category -Unique

    foreach ($cat in $categories) {
        $catEndpoints = $Endpoints | Where-Object { $_.Category -eq $cat }
        Write-Host ""
        Write-Host "  ── $cat ──" -ForegroundColor Cyan

        foreach ($ep in $catEndpoints) {
            $testMode = $ep.TestMode.Trim()
            if ($FilterMode -eq 'CloudPC' -and $testMode -eq 'Client')  { continue }
            if ($FilterMode -eq 'Client'  -and $testMode -eq 'CloudPC') { continue }

            $ports = $ep.Port -split ','
            foreach ($port in $ports) {
                $portNum = [int]$port.Trim()
                $r = Test-Endpoint -Hostname $ep.Endpoint.Trim() -Port $portNum -Protocol $ep.Protocol -Notes $ep.Notes -Category $ep.Category
                $allResults += $r
            }
        }
    }

    return $allResults
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPER: Print summary
# ─────────────────────────────────────────────────────────────────────────────
function Write-Summary {
    param([array]$Results)

    $ok       = [int]($Results | Where-Object { $_.Status -eq 'OK'       } | Measure-Object).Count
    $fail     = [int]($Results | Where-Object { $_.Status -eq 'FAIL'     } | Measure-Object).Count
    $wildcard = [int]($Results | Where-Object { $_.Status -eq 'WILDCARD' } | Measure-Object).Count
    $udponly  = [int]($Results | Where-Object { $_.Status -in 'IPRANGE','UDPONLY' } | Measure-Object).Count
    $fabric   = [int]($Results | Where-Object { $_.Status -eq 'FABRIC'   } | Measure-Object).Count
    $total    = [int]($Results | Measure-Object).Count

    Write-Host ""
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  RESULTS SUMMARY" -ForegroundColor White
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  Total entries  : $total"
    Write-Host "  OK             : $ok" -ForegroundColor Green
    if ($fail -gt 0) {
        Write-Host "  FAILED         : $fail" -ForegroundColor Red
    } else {
        Write-Host "  FAILED         : $fail" -ForegroundColor Green
    }
    Write-Host "  Wildcards      : $wildcard  (verify DNS resolution manually)"         -ForegroundColor DarkYellow
    Write-Host "  UDP/IP Ranges  : $udponly   (verify firewall/NSG allows UDP outbound)" -ForegroundColor DarkCyan
    if ($fabric -gt 0) {
        Write-Host "  Azure Fabric   : $fabric   (see notes - cannot be reliably TCP tested)" -ForegroundColor DarkCyan
    }
    Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray

    if ($fail -gt 0) {
        Write-Host ""
        Write-Host "  FAILED ENDPOINTS:" -ForegroundColor Red
        $Results | Where-Object { $_.Status -eq 'FAIL' } | ForEach-Object {
            if ($_.Notes) {
                Write-Host "    $($_.Hostname):$($_.Port)  [$($_.Category)]  - $($_.Notes)" -ForegroundColor Red
            } else {
                Write-Host "    $($_.Hostname):$($_.Port)  [$($_.Category)]" -ForegroundColor Red
            }
        }
    }

    $wildcardItems = $Results | Where-Object { $_.Status -eq 'WILDCARD' }
    if ($wildcardItems) {
        Write-Host ""
        Write-Host "  WILDCARD ENDPOINTS (verify DNS resolution manually):" -ForegroundColor DarkYellow
        $wildcardItems | ForEach-Object {
            Write-Host "    $($_.Hostname)  [$($_.Category)]" -ForegroundColor DarkYellow
        }
    }

    $udpItems = $Results | Where-Object { $_.Status -in 'IPRANGE','UDPONLY' }
    if ($udpItems) {
        Write-Host ""
        Write-Host "  UDP / IP RANGE ENTRIES (verify firewall/NSG allows outbound UDP):" -ForegroundColor DarkCyan
        $udpItems | ForEach-Object {
            Write-Host "    $($_.Hostname)  UDP:$($_.Port)  [$($_.Category)]  - $($_.Notes)" -ForegroundColor DarkCyan
        }
        Write-Host ""
        Write-Host "  Note: the Intune client/host service IP ranges (ID 163) are a published list," -ForegroundColor DarkGray
        Write-Host "        not a dedicated Azure service tag, so they can't be filtered directly by" -ForegroundColor DarkGray
        Write-Host "        region. If you selected a region above, this list has already been" -ForegroundColor DarkGray
        Write-Host "        narrowed by cross-referencing each range against AzureCloud regional tags." -ForegroundColor DarkGray
        Write-Host "        The separate Azure Front Door ranges are covered by the" -ForegroundColor DarkGray
        Write-Host "        AzureFrontDoor.MicrosoftSecurity service tag if you prefer to use one." -ForegroundColor DarkGray
    }

    $fabricItems = $Results | Where-Object { $_.Status -eq 'FABRIC' }
    if ($fabricItems) {
        Write-Host ""
        Write-Host "  AZURE FABRIC IPs (WireServer / IMDS - do not proxy or intercept):" -ForegroundColor DarkCyan
        $fabricItems | ForEach-Object {
            Write-Host "    $($_.Hostname):$($_.Port)  [$($_.Category)]  - $($_.Notes)" -ForegroundColor DarkCyan
        }
        Write-Host "    See: https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips" -ForegroundColor DarkGray
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# BUILT-IN FALLBACK ENDPOINT LIST
# Source: Microsoft documentation (hardcoded - do NOT use endpoints.office.com
# API for Intune as Microsoft have deprecated it for this purpose)
# ─────────────────────────────────────────────────────────────────────────────
function Get-BuiltInEndpoints {
    return @(
        # ── Windows 365 Service ──────────────────────────────────────────────
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='Registration';      Endpoint='login.microsoftonline.com';               Port=443;        TestMode='Both';    Notes='Entra ID authentication' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='Registration';      Endpoint='login.live.com';                         Port=443;        TestMode='Both';    Notes='Microsoft account authentication' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='Registration';      Endpoint='enterpriseregistration.windows.net';      Port=443;        TestMode='Both';    Notes='Device registration' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Provisioning';  Endpoint='global.azure-devices-provisioning.net';   Port='443,5671'; TestMode='CloudPC'; Notes='IoT Hub device provisioning' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-prod-prap01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='Asia Pacific' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-prod-prau01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='Australia' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-prod-preu01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='Europe' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-prod-prna01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='North America' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-prod-prna02.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='North America 2' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-2-prod-preu01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='Europe 2' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-2-prod-prna01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='North America 2b' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-3-prod-preu01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='Europe 3' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-3-prod-prna01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='North America 3' }
        [PSCustomObject]@{ Category='W365-CloudPC'; Subcategory='IoT Hubs';          Endpoint='hm-iot-in-4-prod-prna01.azure-devices.net'; Port='443,5671'; TestMode='CloudPC'; Notes='North America 4' }

        # ── AVD Session Host (required) ──────────────────────────────────────
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Core';             Endpoint='login.microsoftonline.com';               Port=443;  TestMode='CloudPC'; Notes='Authentication to Microsoft Online Services' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Core';             Endpoint='51.5.0.0/16';                             Port=3478; TestMode='CloudPC'; Notes='RDP Shortpath relayed connectivity (TURN/STUN). Service tag: WindowsVirtualDesktop' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Core';             Endpoint='catalogartifact.azureedge.net';            Port=443;  TestMode='CloudPC'; Notes='Azure Marketplace. Service tag: AzureFrontDoor.Frontend' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Core';             Endpoint='aka.ms';                                  Port=443;  TestMode='CloudPC'; Notes='Microsoft URL shortener' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Monitoring';       Endpoint='gcs.prod.monitoring.core.windows.net';     Port=443;  TestMode='CloudPC'; Notes='AVD agent traffic. Service tag: AzureMonitor' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Activation';       Endpoint='azkms.core.windows.net';                  Port=1688; TestMode='CloudPC'; Notes='Windows KMS activation' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Updates';          Endpoint='mrsglobalsteus2prod.blob.core.windows.net'; Port=443; TestMode='CloudPC'; Notes='AVD agent and SXS stack updates' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Portal';           Endpoint='wvdportalstorageblob.blob.core.windows.net'; Port=443; TestMode='CloudPC'; Notes='Azure portal support' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Azure';            Endpoint='169.254.169.254';                         Port=80;   TestMode='CloudPC'; Notes='Azure Instance Metadata Service (IMDS) - Azure fabric IP; must not be proxied or intercepted' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Azure';            Endpoint='168.63.129.16';                           Port=80;   TestMode='CloudPC'; Notes='WireServer - session host health monitoring; Azure fabric IP; must not be proxied or intercepted' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Certificates';     Endpoint='oneocsp.microsoft.com';                   Port=80;   TestMode='CloudPC'; Notes='OCSP certificate validation' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Certificates';     Endpoint='www.microsoft.com';                       Port=80;   TestMode='CloudPC'; Notes='Certificate chain' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Certificates';     Endpoint='azcsprodeusaikpublish.blob.core.windows.net'; Port=80; TestMode='CloudPC'; Notes='AIK certificate publishing' }
        [PSCustomObject]@{ Category='AVD-SessionHost'; Subcategory='Certificates';     Endpoint='ctldl.windowsupdate.com';                 Port=80;   TestMode='CloudPC'; Notes='Certificate Trust List download' }

        # ── AVD Session Host (optional) ──────────────────────────────────────
        [PSCustomObject]@{ Category='AVD-SessionHost-Optional'; Subcategory='Auth';    Endpoint='login.windows.net';                       Port=443;  TestMode='CloudPC'; Notes='Sign in to Microsoft Online Services and Microsoft 365' }
        [PSCustomObject]@{ Category='AVD-SessionHost-Optional'; Subcategory='Connectivity'; Endpoint='www.msftconnecttest.com';            Port=80;   TestMode='CloudPC'; Notes='Internet connectivity detection' }

        # ── Client / End User Device ─────────────────────────────────────────
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Auth';               Endpoint='login.microsoftonline.com';               Port=443;  TestMode='Client'; Notes='Authentication to Microsoft Online Services' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Navigation';         Endpoint='go.microsoft.com';                        Port=443;  TestMode='Client'; Notes='Microsoft FWLinks' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Navigation';         Endpoint='aka.ms';                                  Port=443;  TestMode='Client'; Notes='Microsoft URL shortener' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Docs';               Endpoint='learn.microsoft.com';                     Port=443;  TestMode='Client'; Notes='Microsoft documentation' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Legal';              Endpoint='privacy.microsoft.com';                   Port=443;  TestMode='Client'; Notes='Microsoft privacy statement' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Service';            Endpoint='graph.microsoft.com';                     Port=443;  TestMode='Client'; Notes='Microsoft Graph API' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Portal';             Endpoint='windows.cloud.microsoft';                 Port=443;  TestMode='Client'; Notes='Connection center' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Portal';             Endpoint='windows365.microsoft.com';                Port=443;  TestMode='Client'; Notes='Windows 365 service traffic' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Portal';             Endpoint='ecs.office.com';                          Port=443;  TestMode='Client'; Notes='Connection center configuration' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Certificates';       Endpoint='www.microsoft.com';                       Port=80;   TestMode='Client'; Notes='Certificate chain' }
        [PSCustomObject]@{ Category='Client-AVD'; Subcategory='Certificates';       Endpoint='azcsprodeusaikpublish.blob.core.windows.net'; Port=80; TestMode='Client'; Notes='AIK certificate publishing' }

        # ── Client - Azure CA Certificate checks (closed network) ───────────
        # Source: https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details
        # Note: oneocsp.microsoft.com and www.microsoft.com already covered above in Client-AVD certs
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='cacerts.digicert.com';   Port=80; TestMode='Client'; Notes='AIA - DigiCert CA certificate downloads' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='cacerts.digicert.cn';    Port=80; TestMode='Client'; Notes='AIA - DigiCert CA certificate downloads (CN)' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='cacerts.geotrust.com';   Port=80; TestMode='Client'; Notes='AIA - GeoTrust CA certificate downloads' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='caissuers.microsoft.com'; Port=80; TestMode='Client'; Notes='AIA - Microsoft CA certificate downloads' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='www.microsoft.com';      Port=80; TestMode='Client'; Notes='AIA and CRL - Microsoft certificate downloads' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='crl3.digicert.com';      Port=80; TestMode='Client'; Notes='CRL - DigiCert CRL distribution point' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='crl4.digicert.com';      Port=80; TestMode='Client'; Notes='CRL - DigiCert CRL distribution point' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='crl.digicert.cn';        Port=80; TestMode='Client'; Notes='CRL - DigiCert CRL distribution point (CN)' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='ocsp.digicert.com';      Port=80; TestMode='Client'; Notes='OCSP - DigiCert OCSP responder' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='ocsp.digicert.cn';       Port=80; TestMode='Client'; Notes='OCSP - DigiCert OCSP responder (CN)' }
        [PSCustomObject]@{ Category='Client-AVD-CertCA'; Subcategory='Certificate Authority'; Endpoint='oneocsp.microsoft.com';  Port=80; TestMode='Client'; Notes='OCSP - Microsoft OCSP responder' }

        # ── Intune Core Service ──────────────────────────────────────────────
        # NOTE: Static list per Microsoft documentation. The endpoints.office.com API
        # no longer returns accurate Intune data and should NOT be used.
        # Source: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints
        [PSCustomObject]@{ Category='Intune'; Subcategory='Core Service';           Endpoint='manage.microsoft.com';                    Port=443;  TestMode='CloudPC'; Notes='Intune client and host service' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Core Service';           Endpoint='EnterpriseEnrollment.manage.microsoft.com'; Port=443; TestMode='CloudPC'; Notes='Intune enterprise enrollment' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swda01-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swda02-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdb01-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdb02-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdc01-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdc02-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdd01-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdd02-mscdn.manage.microsoft.com';        Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdin01-mscdn.manage.microsoft.com';       Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN (India)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Win32 Apps';             Endpoint='swdin02-mscdn.manage.microsoft.com';       Port=443;  TestMode='CloudPC'; Notes='Win32 app CDN (India)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='login.microsoftonline.com';               Port=443;  TestMode='CloudPC'; Notes='Authentication and Identity (Entra ID)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='graph.windows.net';                       Port=443;  TestMode='CloudPC'; Notes='Authentication and Identity' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='login.live.com';                          Port=443;  TestMode='CloudPC'; Notes='Consumer device auth and Microsoft account' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='account.live.com';                        Port=443;  TestMode='CloudPC'; Notes='Consumer Outlook.com and OneDrive device auth' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='enterpriseregistration.windows.net';      Port=443;  TestMode='CloudPC'; Notes='Device registration' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Auth';                   Endpoint='certauth.enterpriseregistration.windows.net'; Port=443; TestMode='CloudPC'; Notes='Certificate-based device registration' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Navigation';             Endpoint='go.microsoft.com';                        Port=443;  TestMode='CloudPC'; Notes='Endpoint discovery' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Config';                 Endpoint='config.edge.skype.com';                   Port=443;  TestMode='CloudPC'; Notes='Feature deployment dependency' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Config';                 Endpoint='ecs.office.com';                          Port=443;  TestMode='CloudPC'; Notes='Feature deployment dependency' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Config';                 Endpoint='fd.api.orgmsg.microsoft.com';             Port=443;  TestMode='CloudPC'; Notes='Organizational messages' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Config';                 Endpoint='config.office.com';                       Port=443;  TestMode='CloudPC'; Notes='Office Customization Service' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Org Messages';            Endpoint='ris.prod.api.personalization.ideas.microsoft.com'; Port=443; TestMode='CloudPC'; Notes='Organizational messages personalization service' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='WNS Push';               Endpoint='sinwns1011421.wns.windows.com';            Port=443;  TestMode='CloudPC'; Notes='Windows Push Notification - Singapore-specific node; may not resolve outside APAC tenants' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='WNS Push';               Endpoint='sin.notify.windows.com';                  Port=443;  TestMode='CloudPC'; Notes='Windows Push Notification - Singapore notify node' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Android AOSP';           Endpoint='intunecdnpeasd.azureedge.net';             Port=443;  TestMode='CloudPC'; Notes='Android AOSP - legacy domain (migrating to manage.microsoft.com)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='Android AOSP';           Endpoint='intunecdnpeasd.manage.microsoft.com';     Port=443;  TestMode='CloudPC'; Notes='Android AOSP device management' }

        # ── Intune IP Ranges (ID 163 - Allow Required) ───────────────────────
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.145.74.224/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.150.254.64/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.154.145.224/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.200.254.32/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.207.244.0/27';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.213.25.64/27';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.213.86.128/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.216.205.32/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.237.143.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.67.13.176/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.67.15.128/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.69.67.224/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.69.231.128/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.70.78.128/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.70.79.128/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.74.111.192/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.77.53.176/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.86.221.176/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.89.174.240/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.89.175.192/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.37.153.0/24';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.37.192.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.38.81.0/24';      Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.41.1.0/24';       Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.1.0/24';       Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.130.0/24';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.224.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.43.129.0/24';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.44.19.224/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.91.147.72/29';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.168.189.128/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.189.172.160/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.189.229.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.191.167.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.192.159.40/29';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.192.174.216/29';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.199.207.192/28';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.193.10/31';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.193.12/30';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.194.128/31';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.208.149.192/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.208.157.128/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.214.131.176/29';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.67.121.224/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.70.151.32/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.71.14.96/28';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.74.25.0/24';      Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.78.245.240/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.78.247.128/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.79.197.64/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.79.197.96/28';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.180.208/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.180.224/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.184.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.82.248.224/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.82.249.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.84.70.128/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.119.8.128/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='48.218.252.128/25';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.150.137.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.162.111.96/28';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.168.116.128/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.182.141.192/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.236.189.96/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.240.244.160/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.151.0.192/27';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.153.235.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.154.140.128/25';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.154.195.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.155.45.128/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='68.218.134.96/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='74.224.214.64/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='74.242.35.0/25';     Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='104.46.162.96/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='104.208.197.64/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.160.217.160/27'; Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.201.237.160/27'; Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.202.86.192/27';  Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.205.63.0/25';    Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.212.214.0/25';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.215.131.0/27';   Port=443; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.219.0/24'; Port=443; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.227.0/24'; Port=443; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.228.0/23'; Port=443; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='150.171.97.0/24'; Port=443; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - IPv6'; Endpoint='2620:1ec:40::/48'; Port=443; TestMode='CloudPC'; Notes='Intune IPv6 range' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - IPv6'; Endpoint='2620:1ec:49::/48'; Port=443; TestMode='CloudPC'; Notes='Intune IPv6 range' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - IPv6'; Endpoint='2620:1ec:4a::/47'; Port=443; TestMode='CloudPC'; Notes='Intune IPv6 range' }

[PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.145.74.224/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.150.254.64/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.154.145.224/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.200.254.32/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.207.244.0/27';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.213.25.64/27';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.213.86.128/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.216.205.32/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='4.237.143.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.67.13.176/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.67.15.128/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.69.67.224/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.69.231.128/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.70.78.128/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.70.79.128/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.74.111.192/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.77.53.176/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.86.221.176/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.89.174.240/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='13.89.175.192/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.37.153.0/24';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.37.192.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.38.81.0/24';      Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.41.1.0/24';       Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.1.0/24';       Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.130.0/24';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.42.224.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.43.129.0/24';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.44.19.224/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.91.147.72/29';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.168.189.128/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.189.172.160/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.189.229.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.191.167.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.192.159.40/29';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.192.174.216/29';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.199.207.192/28';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.193.10/31';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.193.12/30';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.204.194.128/31';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.208.149.192/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.208.157.128/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='20.214.131.176/29';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.67.121.224/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.70.151.32/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.71.14.96/28';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.74.25.0/24';      Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.78.245.240/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.78.247.128/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.79.197.64/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.79.197.96/28';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.180.208/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.180.224/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.80.184.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.82.248.224/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.82.249.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.84.70.128/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='40.119.8.128/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='48.218.252.128/25';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.150.137.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.162.111.96/28';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.168.116.128/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.182.141.192/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.236.189.96/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='52.240.244.160/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.151.0.192/27';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.153.235.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.154.140.128/25';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.154.195.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='57.155.45.128/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='68.218.134.96/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='74.224.214.64/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='74.242.35.0/25';     Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='104.46.162.96/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='104.208.197.64/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.160.217.160/27'; Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.201.237.160/27'; Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.202.86.192/27';  Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.205.63.0/25';    Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.212.214.0/25';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges'; Endpoint='172.215.131.0/27';   Port=80; TestMode='CloudPC'; Notes='Intune client and host service (ID 163)' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.219.0/24'; Port=80; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.227.0/24'; Port=80; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='13.107.228.0/23'; Port=80; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='IP Ranges - Azure Front Door'; Endpoint='150.171.97.0/24'; Port=80; TestMode='CloudPC'; Notes='Intune Azure Front Door endpoint' }

        # ── Intune Autopilot ─────────────────────────────────────────────────
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Windows Update'; Endpoint='tsfe.trafficshaping.dsp.mp.microsoft.com'; Port=443; TestMode='CloudPC'; Notes='Autopilot traffic shaping' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Windows Update'; Endpoint='adl.windows.com';                        Port=443; TestMode='CloudPC'; Notes='Autopilot Windows Update' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='NTP';            Endpoint='time.windows.com';                      Port=123;  TestMode='CloudPC'; Notes='NTP time sync (UDP only)' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='WNS';            Endpoint='clientconfig.passport.net';             Port=443;  TestMode='CloudPC'; Notes='Autopilot WNS dependency' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='WNS';            Endpoint='windowsphone.com';                      Port=443;  TestMode='CloudPC'; Notes='Autopilot WNS dependency' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='WNS';            Endpoint='c.s-microsoft.com';                     Port=443;  TestMode='CloudPC'; Notes='Autopilot WNS dependency (specific node alongside *.s-microsoft.com)' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='TPM';            Endpoint='ekop.intel.com';                        Port=443;  TestMode='CloudPC'; Notes='Intel TPM Endorsement Key certificate' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='TPM';            Endpoint='ekcert.spserv.microsoft.com';           Port=443;  TestMode='CloudPC'; Notes='Microsoft TPM EK certificate service' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='TPM';            Endpoint='ftpm.amd.com';                          Port=443;  TestMode='CloudPC'; Notes='AMD fTPM certificate' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Diagnostics';    Endpoint='lgmsapeweu.blob.core.windows.net';      Port=443;  TestMode='CloudPC'; Notes='Autopilot diagnostics - West Europe' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Diagnostics';    Endpoint='lgmsapewus2.blob.core.windows.net';     Port=443;  TestMode='CloudPC'; Notes='Autopilot diagnostics - West US2' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Diagnostics';    Endpoint='lgmsapesea.blob.core.windows.net';      Port=443;  TestMode='CloudPC'; Notes='Autopilot diagnostics - SE Asia' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Diagnostics';    Endpoint='lgmsapeaus.blob.core.windows.net';      Port=443;  TestMode='CloudPC'; Notes='Autopilot diagnostics - Australia' }
        [PSCustomObject]@{ Category='Intune-Autopilot'; Subcategory='Diagnostics';    Endpoint='lgmsapeind.blob.core.windows.net';      Port=443;  TestMode='CloudPC'; Notes='Autopilot diagnostics - India' }
    )
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

Write-Banner

# ── Step 1: Resolve endpoint list ────────────────────────────────────────────
$endpointData = $null

if ($EndpointsCSV -and (Test-Path $EndpointsCSV)) {
    Write-Host "  Loading endpoints from: $EndpointsCSV" -ForegroundColor DarkGray
    $endpointData = Import-Csv -Path $EndpointsCSV
} else {
    Write-Host "  Attempting to download Endpoints.csv from GitHub..." -ForegroundColor DarkGray
    try {
        $tempCSV = Join-Path $env:TEMP 'W365Endpoints.csv'
        Invoke-WebRequest -Uri $CSVGitHubURL -OutFile $tempCSV -TimeoutSec 15 -ErrorAction Stop
        $endpointData = Import-Csv -Path $tempCSV
        Write-Host "  Downloaded successfully." -ForegroundColor Green
    } catch {
        Write-Host "  Could not download CSV. Using built-in endpoint defaults." -ForegroundColor Yellow
        $endpointData = Get-BuiltInEndpoints
    }
}

Write-Host ""
Write-Host "  NOTE: Intune endpoints use a static hardcoded list per Microsoft guidance." -ForegroundColor DarkGray
Write-Host "        The endpoints.office.com API is deprecated for Intune and returns inaccurate data." -ForegroundColor DarkGray

# ── Step 2: Prompt for mode if not supplied ───────────────────────────────────
if ($Mode -notin 0, 1, 2, 3) {
    Write-Host "  Invalid mode '$Mode'. Please choose 1, 2, or 3." -ForegroundColor Red
    $Mode = 0
}

if ($Mode -eq 0) {
    Write-Host ""
    Write-Host "  Which network do you want to test from?" -ForegroundColor Yellow
    Write-Host "    [1]  Cloud PC / Host Network  (run ON the Cloud PC or Azure VNet VM)" -ForegroundColor White
    Write-Host "    [2]  Client Device Network    (run on the physical device used to ACCESS the Cloud PC)" -ForegroundColor White
    Write-Host "    [3]  Both" -ForegroundColor White
    Write-Host ""
    $inputMode = Read-Host "  Enter choice [1]"
    if ([string]::IsNullOrWhiteSpace($inputMode)) { $inputMode = '1' }
    $Mode = [int]$inputMode
    if ($Mode -notin 1, 2, 3) { $Mode = 1 }
}

$modeLabel = switch ($Mode) {
    1 { 'Cloud PC / Host Network' }
    2 { 'Client Device Network' }
    3 { 'Both' }
}

# ── Step 2b: Region picker for Intune IP ranges ───────────────────────────────
# There is no dedicated "MicrosoftIntune.<Region>" Azure service tag - confirmed
# by direct inspection of the Azure IP Ranges JSON. Instead, we cross-reference
# each published Intune IP range (ID 163) against the AzureCloud.<Region> tags,
# which DO have full regional breakdown covering the entire Azure public IP
# space, to work out which region each published range actually belongs to.
$selectedRegion = $null

function ConvertTo-UInt32IP {
    param([string]$IP)
    try {
        $bytes = ([System.Net.IPAddress]$IP).GetAddressBytes()
        if ($bytes.Length -ne 4) { return $null }
        return ([uint32]$bytes[0] -shl 24) -bor ([uint32]$bytes[1] -shl 16) -bor ([uint32]$bytes[2] -shl 8) -bor [uint32]$bytes[3]
    } catch { return $null }
}

function Get-CidrRange {
    param([string]$Cidr)
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $null }
    $base = ConvertTo-UInt32IP $parts[0]
    if ($null -eq $base) { return $null }
    $prefix   = [int]$parts[1]
    $hostBits = 32 - $prefix
    $mask     = if ($hostBits -ge 32) { [uint32]0 } elseif ($hostBits -eq 0) { [uint32]::MaxValue } else { [uint32]::MaxValue -shl $hostBits }
    $hostMask = [uint32]::MaxValue - $mask
    $netStart = $base -band $mask
    $netEnd   = $netStart -bor $hostMask
    return [PSCustomObject]@{ Start = $netStart; End = $netEnd }
}

function Test-CidrContains {
    param([string]$OuterCidr, [string]$InnerCidr)
    $outer = Get-CidrRange $OuterCidr
    $inner = Get-CidrRange $InnerCidr
    if (-not $outer -or -not $inner) { return $false }
    return ($inner.Start -ge $outer.Start -and $inner.End -le $outer.End)
}

if ($Mode -eq 1 -or $Mode -eq 3) {
    Write-Host ""
    Write-Host "  [region-picker] Mapping published Intune IP ranges to Azure regions..." -ForegroundColor DarkGray

    $ipRangeEndpoints = @($endpointData | Where-Object { $_.Subcategory -eq 'IP Ranges' } | Select-Object -ExpandProperty Endpoint -Unique)
    Write-Host "  [region-picker] $($ipRangeEndpoints.Count) unique IPv4 ranges to map" -ForegroundColor DarkGray

    $regionMap   = @{}
    $downloadLink = $null

    try {
        $page  = Invoke-WebRequest -Uri 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519' -UseBasicParsing -TimeoutSec 15
        $match = [regex]::Match($page.Content, 'ServiceTags_Public_[0-9]+')
        if ($match.Success) {
            $downloadLink = 'https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/' + $match.Value + '.json'
        }
    } catch {
        Write-Host "  [region-picker] Could not reach Microsoft download page: $($_.Exception.Message)" -ForegroundColor DarkYellow
    }

    if ($downloadLink) {
        try {
            $tagData = Invoke-RestMethod -Uri $downloadLink -TimeoutSec 30
            $azureCloudRegions = $tagData.values | Where-Object { $_.name -like 'AzureCloud.*' }
            Write-Host "  [region-picker] Loaded $(@($azureCloudRegions).Count) AzureCloud regional tags" -ForegroundColor DarkGray

            foreach ($ipRange in $ipRangeEndpoints) {
                $foundRegion = $null
                foreach ($tag in $azureCloudRegions) {
                    foreach ($prefix in $tag.properties.addressPrefixes) {
                        if ($prefix -notmatch ':' -and (Test-CidrContains -OuterCidr $prefix -InnerCidr $ipRange)) {
                            $foundRegion = $tag.properties.region
                            break
                        }
                    }
                    if ($foundRegion) { break }
                }
                if ($foundRegion) {
                    if (-not $regionMap.ContainsKey($foundRegion)) { $regionMap[$foundRegion] = @() }
                    $regionMap[$foundRegion] += $ipRange
                }
            }
            Write-Host "  [region-picker] Mapped $(($regionMap.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum) of $($ipRangeEndpoints.Count) ranges across $($regionMap.Keys.Count) regions" -ForegroundColor DarkGray
        } catch {
            Write-Host "  [region-picker] Failed to download or process service tags JSON: $($_.Exception.Message)" -ForegroundColor DarkYellow
        }
    }

    if ($regionMap.Keys.Count -gt 0) {
        Write-Host ""
        Write-Host "  Select your Azure region to narrow the Intune IP range guidance:" -ForegroundColor Yellow
        Write-Host "    [0]  Skip region filtering - show full list" -ForegroundColor White
        $sortedRegions = $regionMap.Keys | Sort-Object
        $i = 1
        foreach ($region in $sortedRegions) {
            Write-Host ("    [{0}]  {1}  ({2} ranges)" -f $i, $region, $regionMap[$region].Count) -ForegroundColor White
            $i++
        }
        Write-Host ""
        Write-Host "  Note: mapped by cross-referencing against AzureCloud regional tags," -ForegroundColor DarkGray
        Write-Host "        since Intune itself has no dedicated regional service tag." -ForegroundColor DarkGray
        Write-Host "        Front Door and IPv6 ranges are always shown regardless of choice." -ForegroundColor DarkGray
        Write-Host ""
        $inputRegion = Read-Host "  Enter choice [0]"
        if ([string]::IsNullOrWhiteSpace($inputRegion)) { $inputRegion = '0' }

        $regionIndex = 0
        [void][int]::TryParse($inputRegion, [ref]$regionIndex)

        if ($regionIndex -gt 0 -and $regionIndex -le $sortedRegions.Count) {
            $selectedRegion = $sortedRegions[$regionIndex - 1]
            $keepRanges = $regionMap[$selectedRegion]
            Write-Host "  Region: $selectedRegion  ($($keepRanges.Count) ranges)" -ForegroundColor Blue
            $endpointData = $endpointData | Where-Object {
                $_.Subcategory -ne 'IP Ranges' -or $_.Endpoint -in $keepRanges
            }
        } else {
            Write-Host "  Showing full list (no region filter applied)." -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  [region-picker] Could not map any ranges to regions - showing full static list." -ForegroundColor DarkYellow
    }
}

Write-Host ""
Write-Host "  Mode      : $modeLabel" -ForegroundColor Blue
if ($selectedRegion) {
    Write-Host "  Region    : $selectedRegion  (mapped via AzureCloud tags)" -ForegroundColor Blue
}
Write-Host "  Computer  : $env:COMPUTERNAME  |  User: $env:USERNAME" -ForegroundColor DarkGray
Write-Host "  Date/Time : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
Write-Host ""
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "  Legend:  [ OK ] Connected   [FAIL] Blocked   [SKIP] Wildcard   [INFO] UDP/IP Range/Fabric" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────" -ForegroundColor DarkGray

$allResults = @()

# ── Step 3: Run tests ─────────────────────────────────────────────────────────
if ($Mode -eq 1 -or $Mode -eq 3) {
    Write-Host ""
    Write-Host "┌─ CLOUD PC / HOST NETWORK TESTS ─────────────────────────┐" -ForegroundColor Magenta
    $allResults += Test-EndpointList -Endpoints $endpointData -FilterMode 'CloudPC'
    Write-Host ""
    Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
}

if ($Mode -eq 2 -or $Mode -eq 3) {
    Write-Host ""
    Write-Host "┌─ CLIENT DEVICE NETWORK TESTS ───────────────────────────┐" -ForegroundColor Blue
    $allResults += Test-EndpointList -Endpoints $endpointData -FilterMode 'Client'
    Write-Host ""
    Write-Host "└─────────────────────────────────────────────────────────┘" -ForegroundColor Blue
}

# ── Step 4: Summary ───────────────────────────────────────────────────────────
Write-Summary -Results $allResults

# ── Step 5: Export results (optional) ────────────────────────────────────────
if ($OutputPath) {
    try {
        $allResults | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
        Write-Host ""
        Write-Host "  Results exported to: $OutputPath" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] Could not export results: $_" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "  Done." -ForegroundColor Blue
Write-Host ""
