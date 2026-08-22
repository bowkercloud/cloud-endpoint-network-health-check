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
    Version:    3.9
    Blog:       https://bowker.cloud
    References:
        https://learn.microsoft.com/en-us/windows-365/enterprise/requirements-network
        https://learn.microsoft.com/en-us/azure/virtual-desktop/required-fqdn-endpoint
        https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints
    Inspired by: https://gist.github.com/shannonfritz/4c9f1cf800f3406729a58417639736f3

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
    [string]$OutputPath = '',
    [switch]$NoTlsCheck,
    [switch]$SkipRegionPicker,
    # 12 rather than something higher: beyond about a dozen, wall-clock barely
    # improves (the slowest individual probes dominate, not the queue) while
    # CDN-hosted Microsoft endpoints start rate-limiting concurrent TLS
    # handshakes and returning InternalError alerts that read as false failures.
    [int]$MaxParallel = 12
)

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
$ScriptName     = 'Test-W365NetworkHealth'
$ScriptVersion  = 'v3.9'
$CSVGitHubURL   = 'https://raw.githubusercontent.com/bowkercloud/windows365/main/Endpoints.csv'
$TimeoutSeconds = 5
$script:InterceptDetected = $false   # set by the Step 2c control probe; read by Write-Summary
# $MaxParallel comes from the parameter block - raise for speed, lower if a proxy rate-limits you

# -----------------------------------------------------------------------------
# HELPER: Banner
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# WILDCARD PROBE TABLE
#
# Microsoft publish many requirements as wildcards (*.wvd.microsoft.com). Older
# versions of this script printed those as [SKIP] and told you to check DNS by
# hand - which meant a third of the FQDN list was never actually validated,
# including the two most important entries in the whole file.
#
# Two-tier approach instead:
#   Tier 1 - probe a real, known host inside the zone and TCP test it properly.
#            Every probe host below was verified to resolve before being added.
#   Tier 2 - where no stable public label exists, query the parent zone for SOA.
#            That won't prove the port is open, but it does prove DNS for the
#            zone isn't being blackholed, which is the usual way these break on
#            a filtered network.
#
# Value = probe host to TCP test. $null = no known label, use the SOA fallback.
# -----------------------------------------------------------------------------
$WildcardProbes = @{
    '*.wvd.microsoft.com'                         = 'rdbroker.wvd.microsoft.com'
    '*.prod.warm.ingest.monitor.core.windows.net' = 'gcs.prod.warm.ingest.monitor.core.windows.net'
    '*.microsoftaik.azure.net'                    = 'ftpm.microsoftaik.azure.net'
    '*.events.data.microsoft.com'                 = 'v10.events.data.microsoft.com'
    '*.prod.do.dsp.mp.microsoft.com'              = 'kv801.prod.do.dsp.mp.microsoft.com'
    '*.do.dsp.mp.microsoft.com'                   = 'kv801.prod.do.dsp.mp.microsoft.com'
    # 2.tlu is Akamai-served. Plain tlu.* sits behind Fastly on a shared fallback
    # certificate and rejects handshakes with a TLS InternalError under the
    # concurrency this script generates, which reads as a false TLS failure.
    '*.dl.delivery.mp.microsoft.com'              = '2.tlu.dl.delivery.mp.microsoft.com'
    '*.delivery.mp.microsoft.com'                 = 'fe3.delivery.mp.microsoft.com'
    '*.digicert.com'                              = 'ocsp.digicert.com'
    '*.cdn.office.net'                            = 'res.cdn.office.net'
    # a.manage rather than m.manage: m.manage sits on Azure CDN and serves a
    # *.azureedge.net certificate, so a TLS check there proves nothing about the
    # hostname. a.manage returns a certificate that actually covers the name -
    # which matters, because Microsoft explicitly do not support SSL inspection
    # on *.manage.microsoft.com and this is where we would detect it.
    '*.manage.microsoft.com'                      = 'a.manage.microsoft.com'
    '*.notify.windows.com'                        = 'db5.notify.windows.com'
    '*.wns.windows.com'                           = 'client.wns.windows.com'
    '*.windowsupdate.com'                         = 'download.windowsupdate.com'
    '*.update.microsoft.com'                      = 'fe2.update.microsoft.com'
    '*.s-microsoft.com'                           = 'c.s-microsoft.com'
    '*.windows.cloud.microsoft'                   = 'windows.cloud.microsoft'
    # No stable public label - SOA zone check only.
    # azure-dns entries are nameservers: they answer DNS on 53, never 443, so a
    # port probe against them is meaningless. Zone check is the honest test.
    '*.azure-dns.com'                             = $null
    '*.azure-dns.net'                             = $null
    '*.infra.windows365.microsoft.com'            = $null
    '*.service.windows.cloud.microsoft'           = $null
    '*.windows.static.microsoft'                  = $null
    '*.aikcertaia.microsoft.com'                  = $null
    '*.sfx.ms'                                    = $null
    '*.officeconfig.msocdn.com'                   = $null
    '*.dm.microsoft.com'                          = $null
    '*.servicebus.windows.net'                    = $null
    '*eh.servicebus.windows.net'                  = $null
}

# -----------------------------------------------------------------------------
# HELPER: Strip a wildcard pattern down to its parent zone for SOA lookups
# -----------------------------------------------------------------------------
function Get-WildcardZone {
    param([string]$Pattern)
    # '*.wvd.microsoft.com' -> 'wvd.microsoft.com'
    # '*eh.servicebus.windows.net' -> 'servicebus.windows.net'  (no dot after *)
    $z = $Pattern -replace '^\*\.', ''
    if ($z -eq $Pattern) { $z = $Pattern -replace '^\*[^.]*\.', '' }
    return $z
}

# -----------------------------------------------------------------------------
# HELPER: Classify a CSV row into how it should be handled
#   Tcp      - normal FQDN/IP, connect and test
#   Wildcard - probe a real host inside the zone, or SOA the zone
#   IpRange  - published CIDR, collapse into a grouped summary line
#   Fabric   - Azure WireServer / IMDS, must not be proxied or intercepted
#   UdpOnly  - NTP and friends, can't be TCP tested
# -----------------------------------------------------------------------------
function Get-EndpointKind {
    param([string]$Hostname, [int]$Port, [string]$WildcardNote = '')

    # Reference-only rows: endpoints Microsoft still list somewhere in their docs
    # but which are known not to be live. Kept in the CSV so the list stays a
    # faithful record of what's published, but never probed - testing them just
    # generates a failure every user has to learn to ignore. Driven by the CSV's
    # WildcardNote column, so marking a future stale entry needs no code change.
    if ($WildcardNote -match '^\s*Reference')                       { return 'Reference' }

    if ($Hostname -match '^\*')                                     { return 'Wildcard' }
    if ($Hostname -eq '169.254.169.254')                            { return 'Imds' }
    if ($Hostname -eq '168.63.129.16')                              { return 'WireServer' }

    # UDP entries that CAN actually be tested, rather than just flagged.
    # RDP Shortpath is the single biggest factor in how responsive a Cloud PC
    # feels, so "verify this yourself" was the least useful thing to say about it.
    if ($Port -eq 3478)                                             { return 'Stun' }
    if ($Port -eq 123)                                              { return 'Ntp' }

    if ($Hostname -match '/\d+$')                                   { return 'IpRange' }
    return 'Tcp'
}

# -----------------------------------------------------------------------------
# HELPER: SOA zone check for wildcards with no probe host.
#
# Runs on the main thread, deliberately. Resolve-DnsName lives in the DnsClient
# module, and having 32 runspaces auto-load it simultaneously makes some of them
# throw - which showed up as zones being reported as DNS failures when they
# resolve perfectly well single-threaded. There are only a handful of these
# lookups and each takes a few milliseconds, so there's nothing to gain from
# parallelising them anyway.
# -----------------------------------------------------------------------------
function Test-DnsZone {
    param([string]$Zone)

    try {
        $soa = @(Resolve-DnsName -Name $Zone -Type SOA -ErrorAction Stop |
                 Where-Object { $_.QueryType -eq 'SOA' })
        if ($soa.Count -gt 0) {
            return [PSCustomObject]@{ Status = 'ZONE'; Detail = "zone is authoritative ($($soa[0].PrimaryServer))"; IP = '' }
        }
    } catch { }

    # Resolve-DnsName unavailable, or the SOA query failed - try the apex directly
    try {
        $null = [System.Net.Dns]::GetHostAddresses($Zone)
        return [PSCustomObject]@{ Status = 'ZONE'; Detail = 'zone apex resolves'; IP = '' }
    } catch { }

    return [PSCustomObject]@{ Status = 'DNSFAIL'; Detail = 'zone did not resolve - DNS filtering?'; IP = '' }
}

# -----------------------------------------------------------------------------
# PROBE: runs inside a runspace. TCP connects only.
# Resolves DNS first so a name that doesn't resolve is reported as DNSFAIL
# rather than being lumped in with genuine firewall blocks - different problem,
# completely different fix.
# -----------------------------------------------------------------------------
$ProbeScript = {
    param([string]$Kind, [string]$Target, [int]$Port, [int]$TimeoutSeconds, [bool]$DoTls)

    function New-Result { param($S,$D,$I='',$R=$null,$Issuer='')
        [PSCustomObject]@{ Status=$S; Detail=$D; IP=$I; Rtt=$R; Issuer=$Issuer }
    }

    # -- UDP: STUN binding request (RDP Shortpath / TURN relay) ---------------
    # A real binding request, not a TCP connect standing in for one. If UDP 3478
    # is blocked the socket simply never gets a reply, which is exactly the
    # failure that silently degrades Cloud PCs to the TCP transport.
    # UDP is unreliable by design - a single lost datagram is not evidence of a
    # blocked port, so both UDP probes get three attempts before reporting failure.
    if ($Kind -eq 'STUN') {
      for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Client.ReceiveTimeout = $TimeoutSeconds * 1000
            $udp.Connect($Target, $Port)
            $req = [byte[]]::new(20)
            $req[0] = 0x00; $req[1] = 0x01          # Binding Request
            $req[2] = 0x00; $req[3] = 0x00          # length 0
            $req[4] = 0x21; $req[5] = 0x12; $req[6] = 0xA4; $req[7] = 0x42   # magic cookie
            $txn = [byte[]]::new(12); (New-Object Random).NextBytes($txn)
            [Array]::Copy($txn, 0, $req, 8, 12)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            [void]$udp.Send($req, 20)
            $ep   = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $resp = $udp.Receive([ref]$ep)
            $sw.Stop(); $udp.Close()
            if ($resp.Length -ge 20 -and $resp[0] -eq 0x01 -and $resp[1] -eq 0x01) {
                return New-Result 'OK' 'STUN binding success - UDP 3478 open' '' ([int]$sw.ElapsedMilliseconds)
            }
            if ($attempt -eq 3) { return New-Result 'FAIL' 'replied but not a STUN binding success' }
        } catch {
            if ($attempt -eq 3) { return New-Result 'FAIL' "no STUN reply after 3 attempts - UDP $Port likely blocked" }
        }
        Start-Sleep -Milliseconds 300
      }
    }

    # -- UDP: SNTP time request -----------------------------------------------
    # Also reports clock skew, since a skewed clock breaks Entra authentication
    # in ways that look nothing like a time problem.
    if ($Kind -eq 'NTP') {
      for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $udp = New-Object System.Net.Sockets.UdpClient
            $udp.Client.ReceiveTimeout = $TimeoutSeconds * 1000
            $udp.Connect($Target, $Port)
            $req = [byte[]]::new(48); $req[0] = 0x1B      # LI=0, VN=3, Mode=3 (client)
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            [void]$udp.Send($req, 48)
            $ep   = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
            $resp = $udp.Receive([ref]$ep)
            $sw.Stop(); $udp.Close()
            if ($resp.Length -ge 48) {
                $secs = [BitConverter]::ToUInt32(($resp[43..40]), 0)
                $srv  = [datetime]::new(1900,1,1,0,0,0,[DateTimeKind]::Utc).AddSeconds($secs)
                $skew = [math]::Round(((Get-Date).ToUniversalTime() - $srv).TotalSeconds, 1)
                $msg  = "NTP reply - stratum $($resp[1]), clock skew ${skew}s"
                if ([math]::Abs($skew) -gt 300) {
                    return New-Result 'WARN' "$msg (skew over 5 min - will break Entra auth)" '' ([int]$sw.ElapsedMilliseconds)
                }
                return New-Result 'OK' $msg '' ([int]$sw.ElapsedMilliseconds)
            }
            if ($attempt -eq 3) { return New-Result 'FAIL' 'short NTP reply' }
        } catch {
            if ($attempt -eq 3) { return New-Result 'FAIL' "no NTP reply after 3 attempts - UDP $Port likely blocked" }
        }
        Start-Sleep -Milliseconds 300
      }
    }

    # -- Azure Instance Metadata Service --------------------------------------
    # Only meaningful from inside Azure. Outside it there is nothing to reach,
    # so a non-answer is reported as "not in Azure", never as a failure.
    if ($Kind -eq 'IMDS') {
        try {
            $req = [System.Net.HttpWebRequest]::Create('http://169.254.169.254/metadata/instance?api-version=2021-02-01')
            $req.Headers.Add('Metadata', 'true')
            $req.Timeout = $TimeoutSeconds * 1000
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resp = $req.GetResponse()
            $sw.Stop()
            $code = [int]$resp.StatusCode
            $resp.Close()
            if ($code -eq 200) { return New-Result 'OK' 'IMDS responded - running in Azure, metadata reachable' '169.254.169.254' ([int]$sw.ElapsedMilliseconds) }
            return New-Result 'INFO' "IMDS returned HTTP $code"
        } catch {
            return New-Result 'NOTAZURE' 'no IMDS response - not an Azure VM, or IMDS is being intercepted'
        }
    }

    # -- TCP (optionally with a TLS handshake) --------------------------------
    $ip = ''
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses($Target)
        $v4    = $addrs | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
        if (-not $v4) { $v4 = $addrs | Select-Object -First 1 }
        $ip = $v4.IPAddressToString
    } catch {
        return New-Result 'DNSFAIL' 'name did not resolve'
    }

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $sw  = [System.Diagnostics.Stopwatch]::StartNew()
        $ar  = $tcp.BeginConnect($ip, $Port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds), $false)) {
            $tcp.Close()
            return New-Result 'FAIL' "no response within ${TimeoutSeconds}s" $ip
        }
        try { $tcp.EndConnect($ar) } catch { $tcp.Close(); return New-Result 'FAIL' 'connection refused' $ip }
        $sw.Stop()
        $rtt = [int]$sw.ElapsedMilliseconds

        # TCP is open. On 443, complete a TLS handshake with SNI so we learn
        # whether the *hostname* is actually permitted and who issued the
        # certificate - a plain TCP connect to a proxy or SSL-inspection box
        # looks identical to a genuinely allowed endpoint.
        if ($DoTls -and $Port -eq 443) {
            try {
                $cb  = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sn,$c,$ch,$e) $true }
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
                $ssl.AuthenticateAsClient($Target)
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl.RemoteCertificate
                $ssl.Close(); $tcp.Close()

                # Walk to the ROOT of the chain rather than judging the intermediate.
                # Intermediates are numerous and change often (Microsoft content is
                # served via several CDNs, each with its own issuing CA), so matching
                # on them produces false positives. Roots are few and stable.
                $rootSubject = $cert.Issuer
                try {
                    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $null = $chain.Build($cert)
                    if ($chain.ChainElements.Count -gt 0) {
                        $rootSubject = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate.Subject
                    }
                } catch { }

                # Organisations behind the public root CA programme. An intercepting
                # proxy signs with its own root, which will not appear here.
                $publicRoots = @(
                    'DigiCert','Baltimore','Microsoft','GlobalSign','Entrust','ISRG','Let''s Encrypt',
                    'USERTrust','Sectigo','Comodo','AAA Certificate Services','Amazon','Starfield',
                    'Go Daddy','Certainly','Google Trust Services','GTS Root','VeriSign','Thawte',
                    'GeoTrust','RapidSSL','QuoVadis','IdenTrust','SSL.com','Buypass','Actalis',
                    'Certum','Asseco','T-Systems','Deutsche Telekom','Telia','Sonera','SwissSign',
                    'D-TRUST','Atos','WISeKey','OISTE','HARICA','emSign','SecureTrust','Trustwave',
                    'XRamp','Network Solutions','Cybertrust','Security Communication','SECOM',
                    'Izenpe','Firmaprofesional','ANF','Hongkong Post','TWCA','Chunghwa','GDCA',
                    'CFCA','Certigna','Dhimyotis','E-Tugra','TrustCor','AddTrust','Unizeto','Camerfirma'
                )
                $match = $false
                foreach ($k in $publicRoots) { if ($rootSubject -like "*$k*") { $match = $true; break } }

                if (-not $match) {
                    return New-Result 'INSPECT' 'TLS completed but the chain roots to a non-public CA' $ip $rtt $rootSubject
                }
                return New-Result 'OK' 'TCP + TLS handshake succeeded' $ip $rtt $rootSubject
            } catch {
                $m = $_.Exception.Message -replace '\s+', ' '
                try { $tcp.Close() } catch { }

                # CDN front-ends rate-limit concurrent handshakes and answer with a
                # TLS InternalError alert - observed against Fastly-served Microsoft
                # content under a 32-way parallel run, where the same host completes
                # fine on its own. Back off long enough to clear that window and
                # retry once: a genuine policy block still fails consistently.
                try {
                    Start-Sleep -Milliseconds 750
                    $tcp2 = New-Object System.Net.Sockets.TcpClient
                    $ar2  = $tcp2.BeginConnect($ip, $Port, $null, $null)
                    if ($ar2.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSeconds), $false)) {
                        $tcp2.EndConnect($ar2)
                        $cb2  = [System.Net.Security.RemoteCertificateValidationCallback]{ param($sn,$c,$ch,$e) $true }
                        $ssl2 = New-Object System.Net.Security.SslStream($tcp2.GetStream(), $false, $cb2)
                        $ssl2.AuthenticateAsClient($Target)
                        $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]$ssl2.RemoteCertificate
                        $ssl2.Close(); $tcp2.Close()
                        return New-Result 'OK' 'TCP + TLS handshake succeeded (second attempt)' $ip $rtt $cert2.Issuer
                    }
                    $tcp2.Close()
                } catch { }

                return New-Result 'TLSFAIL' "TCP open but TLS handshake failed - $m" $ip $rtt
            }
        }

        $tcp.Close()
        return New-Result 'OK' '' $ip $rtt
    } catch {
        return New-Result 'FAIL' ($_.Exception.Message -replace '\s+', ' ') $ip
    }
}

# -----------------------------------------------------------------------------
# HELPER: Run every probe across a runspace pool.
#
# The old engine tested serially with a 5s timeout. Fine on a healthy network,
# but on a network that's actually blocking things - the entire reason you'd run
# this script - every blocked endpoint costs the full timeout, one after
# another. Running them concurrently makes the worst case roughly the timeout
# itself rather than the timeout multiplied by the number of failures.
#
# Runspaces rather than ForEach-Object -Parallel because this script supports
# Windows PowerShell 5.1, where that parameter doesn't exist.
# -----------------------------------------------------------------------------
function Invoke-ProbeBatch {
    param(
        [array]$WorkItems,          # Key, Kind, Target, Port
        [int]$MaxParallel = 32,
        [int]$TimeoutSec  = 5
    )

    $results = @{}
    if (-not $WorkItems -or $WorkItems.Count -eq 0) { return $results }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $MaxParallel)
    $pool.ApartmentState = 'MTA'
    $pool.Open()

    $jobs = New-Object System.Collections.ArrayList
    foreach ($w in $WorkItems) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($ProbeScript).
                  AddArgument($w.Kind).
                  AddArgument($w.Target).
                  AddArgument($w.Port).
                  AddArgument($TimeoutSec).
                  AddArgument((-not $NoTlsCheck) -and (-not $w.NoTls))
        [void]$jobs.Add([PSCustomObject]@{
            Key    = $w.Key
            PS     = $ps
            Handle = $ps.BeginInvoke()
        })
    }

    # Progress while the pool drains
    $total = $jobs.Count
    while ($true) {
        $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
        Write-Host ("`r  Testing... {0}/{1} probes complete   " -f $done, $total) -NoNewline -ForegroundColor DarkGray
        if ($done -ge $total) { break }
        Start-Sleep -Milliseconds 200
    }
    Write-Host ("`r{0}`r" -f (' ' * 50)) -NoNewline

    foreach ($j in $jobs) {
        try {
            $r = $j.PS.EndInvoke($j.Handle)
            if ($r -and $r.Count -gt 0) { $results[$j.Key] = $r[0] }
            else { $results[$j.Key] = [PSCustomObject]@{ Status = 'FAIL'; Detail = 'no result returned'; IP = '' } }
        } catch {
            $results[$j.Key] = [PSCustomObject]@{ Status = 'FAIL'; Detail = $_.Exception.Message; IP = '' }
        } finally {
            $j.PS.Dispose()
        }
    }

    $pool.Close()
    $pool.Dispose()
    return $results
}

# -----------------------------------------------------------------------------
# HELPER: Print one result line in the established house style
# -----------------------------------------------------------------------------
function Write-ResultLine {
    param([string]$Tag, [ConsoleColor]$Colour, [string]$Label, [string]$Trailer = '')

    $pad = [string]::new(' ', [Math]::Max(1, 56 - $Label.Length))
    Write-Host "  [" -NoNewline
    Write-Host $Tag -ForegroundColor $Colour -NoNewline
    if ($Trailer) {
        Write-Host "] $Label$pad" -NoNewline
        Write-Host $Trailer -ForegroundColor DarkGray
    } else {
        Write-Host "] $Label"
    }
}

# -----------------------------------------------------------------------------
# HELPER: Test a list of endpoints from CSV data
#
# Three phases now: plan the work, run it concurrently, then print in the
# original grouped-by-category order. Deduplicating identical host:port pairs
# before the run means shared endpoints like login.microsoftonline.com are
# tested once and the verdict reused, instead of being retested per category.
# -----------------------------------------------------------------------------
function Test-EndpointList {
    param(
        [array]$Endpoints,
        [string]$FilterMode   # 'CloudPC', 'Client', or 'Both'
    )

    # -- Phase 1: plan --------------------------------------------------------
    $plan     = New-Object System.Collections.ArrayList
    $work     = @{}   # Key -> work item (dedupes automatically)

    foreach ($ep in $Endpoints) {
        $testMode = $ep.TestMode.Trim()
        if ($FilterMode -eq 'CloudPC' -and $testMode -eq 'Client')  { continue }
        if ($FilterMode -eq 'Client'  -and $testMode -eq 'CloudPC') { continue }

        $epHost = $ep.Endpoint.Trim()

        foreach ($port in ($ep.Port -split ',')) {
            $portNum = [int]$port.Trim()
            $kind    = Get-EndpointKind -Hostname $epHost -Port $portNum -WildcardNote $ep.WildcardNote

            $item = [PSCustomObject]@{
                Category    = $ep.Category
                Subcategory = $ep.Subcategory
                Hostname    = $epHost
                Port        = $portNum
                Protocol     = $ep.Protocol
                Notes        = $ep.Notes
                WildcardNote = $ep.WildcardNote
                KnownDead    = ($ep.WildcardNote -match '^\s*KnownDead')
                NoTls        = ($ep.WildcardNote -match '^\s*NoTls')
                Kind         = $kind
                Key          = $null
                ProbeTarget  = $null
            }

            switch ($kind) {
                'Tcp' {
                    $item.ProbeTarget = $epHost
                    $item.Key = "TCP|$epHost|$portNum"
                    if (-not $work.ContainsKey($item.Key)) {
                        $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'TCP'; Target = $epHost; Port = $portNum; NoTls = $item.NoTls }
                    }
                }

                'Stun' {
                    # CIDR entries (e.g. 51.5.0.0/16) have no single host to talk to,
                    # so probe Microsoft's published AVD STUN/TURN endpoints instead.
                    # What matters is whether UDP 3478 egress works at all.
                    $probe = if ($epHost -match '/\d+$') { 'stun.azure.com' } else { $epHost }
                    $item.ProbeTarget = $probe
                    $item.Key = "STUN|$probe|$portNum"
                    if (-not $work.ContainsKey($item.Key)) {
                        $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'STUN'; Target = $probe; Port = $portNum }
                    }
                }

                'Ntp' {
                    $item.ProbeTarget = $epHost
                    $item.Key = "NTP|$epHost|$portNum"
                    if (-not $work.ContainsKey($item.Key)) {
                        $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'NTP'; Target = $epHost; Port = $portNum }
                    }
                }

                'Imds' {
                    $item.ProbeTarget = $epHost
                    $item.Key = "IMDS|$epHost"
                    if (-not $work.ContainsKey($item.Key)) {
                        $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'IMDS'; Target = $epHost; Port = $portNum }
                    }
                }

                'WireServer' {
                    $item.ProbeTarget = $epHost
                    $item.Key = "TCP|$epHost|$portNum"
                    if (-not $work.ContainsKey($item.Key)) {
                        $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'TCP'; Target = $epHost; Port = $portNum; NoTls = $item.NoTls }
                    }
                }
                'Wildcard' {
                    $probe = $null
                    if ($WildcardProbes.ContainsKey($epHost)) { $probe = $WildcardProbes[$epHost] }

                    if ($probe) {
                        $item.ProbeTarget = $probe
                        $item.Key = "TCP|$probe|$portNum"
                        if (-not $work.ContainsKey($item.Key)) {
                            $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'TCP'; Target = $probe; Port = $portNum; NoTls = $item.NoTls }
                        }
                    } else {
                        $zone = Get-WildcardZone -Pattern $epHost
                        $item.ProbeTarget = $zone
                        $item.Key = "ZONE|$zone"
                        if (-not $work.ContainsKey($item.Key)) {
                            $work[$item.Key] = [PSCustomObject]@{ Key = $item.Key; Kind = 'ZONE'; Target = $zone; Port = 0 }
                        }
                    }
                }
            }

            [void]$plan.Add($item)
        }
    }

    # -- Phase 2: run ---------------------------------------------------------
    $probeResults = @{}
    # Everything except zone checks runs in the pool. Zone checks stay on the
    # main thread - see Test-DnsZone for why.
    $tcpWork  = @($work.Values | Where-Object { $_.Kind -ne 'ZONE' })
    $zoneWork = @($work.Values | Where-Object { $_.Kind -eq 'ZONE' })

    if ($tcpWork.Count -gt 0 -or $zoneWork.Count -gt 0) {
        Write-Host ""
        Write-Host "  Running $($tcpWork.Count) connection probes across $MaxParallel parallel workers, plus $($zoneWork.Count) DNS zone checks..." -ForegroundColor DarkGray
        $sw = [System.Diagnostics.Stopwatch]::StartNew()

        if ($tcpWork.Count -gt 0) {
            $probeResults = Invoke-ProbeBatch -WorkItems $tcpWork -MaxParallel $MaxParallel -TimeoutSec $TimeoutSeconds
        }
        foreach ($z in $zoneWork) {
            $probeResults[$z.Key] = Test-DnsZone -Zone $z.Target
        }

        $sw.Stop()
        Write-Host ("  Completed in {0:n1}s" -f $sw.Elapsed.TotalSeconds) -ForegroundColor DarkGray
    }

    # -- Phase 3: report ------------------------------------------------------
    $allResults = New-Object System.Collections.ArrayList
    $stamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    foreach ($cat in ($plan | Select-Object -ExpandProperty Category -Unique)) {
        Write-Host ""
        Write-Host "  -- $cat --" -ForegroundColor Cyan

        $catItems  = @($plan | Where-Object { $_.Category -eq $cat })
        $rangeRows = New-Object System.Collections.ArrayList

        foreach ($item in $catItems) {

            $result = [PSCustomObject]@{
                Category    = $item.Category
                Subcategory = $item.Subcategory
                Hostname    = $item.Hostname
                Port        = $item.Port
                Status      = 'UNKNOWN'
                TestedAs    = $item.ProbeTarget
                Detail      = ''
                Rtt         = $null
                Issuer      = ''
                Notes       = $item.Notes
                KnownDead   = $item.KnownDead
                Timestamp   = $stamp
            }

            switch ($item.Kind) {

                'Tcp' {
                    $p = $probeResults[$item.Key]
                    $result.Status = $p.Status
                    $result.Detail = $p.Detail
                    $result.Rtt    = $p.Rtt
                    $result.Issuer = $p.Issuer
                    $label = "$($item.Hostname):$($item.Port)"
                    switch ($p.Status) {
                        'OK'      { Write-ResultLine -Tag ' OK ' -Colour Green    -Label $label -Trailer $(if ($p.Rtt -ne $null) { "($($p.Rtt) ms)" } else { '' }) }
                        'INSPECT' { Write-ResultLine -Tag 'INSP' -Colour Yellow   -Label $label -Trailer "(SSL inspection? cert issuer: $($p.Issuer))" }
                        'TLSFAIL' { Write-ResultLine -Tag 'TLS!' -Colour Yellow   -Label $label -Trailer "($($p.Detail))" }
                        'DNSFAIL' { Write-ResultLine -Tag 'DNS!' -Colour Magenta  -Label $label -Trailer "(name did not resolve - DNS block, not a firewall block)" }
                        default   { Write-ResultLine -Tag 'FAIL' -Colour Red      -Label $label -Trailer "($($p.Detail))" }
                    }
                }

                { $_ -in 'Stun','Ntp' } {
                    $p = $probeResults[$item.Key]
                    $result.Status = $p.Status
                    $result.Detail = $p.Detail
                    $result.Rtt    = $p.Rtt
                    $proto = if ($item.Kind -eq 'Stun') { 'UDP' } else { 'UDP' }
                    $label = "$($item.Hostname)  $proto`:$($item.Port)"
                    $via   = if ($item.ProbeTarget -ne $item.Hostname) { " via $($item.ProbeTarget)" } else { '' }
                    switch ($p.Status) {
                        'OK'   { Write-ResultLine -Tag ' OK ' -Colour Green  -Label $label -Trailer "($($p.Detail)$via)" }
                        'WARN' { Write-ResultLine -Tag 'WARN' -Colour Yellow -Label $label -Trailer "($($p.Detail))" }
                        default{ Write-ResultLine -Tag 'FAIL' -Colour Red    -Label $label -Trailer "($($p.Detail)$via)" }
                    }
                }

                'Imds' {
                    $p = $probeResults[$item.Key]
                    $result.Status = $p.Status
                    $result.Detail = $p.Detail
                    $label = "$($item.Hostname):$($item.Port)"
                    switch ($p.Status) {
                        'OK'       { Write-ResultLine -Tag ' OK ' -Colour Green    -Label $label -Trailer "(IMDS responded - running in Azure)" }
                        'NOTAZURE' { Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "(no IMDS response - not an Azure VM, or being intercepted)" }
                        default    { Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "($($p.Detail))" }
                    }
                }

                'WireServer' {
                    $p = $probeResults[$item.Key]
                    $result.Rtt = $p.Rtt
                    $label = "$($item.Hostname):$($item.Port)"
                    if ($p.Status -eq 'OK') {
                        $result.Status = 'OK'
                        $result.Detail = 'WireServer reachable - running in Azure'
                        Write-ResultLine -Tag ' OK ' -Colour Green -Label $label -Trailer "(WireServer reachable - running in Azure)"
                    } else {
                        # Cross-reference IMDS. If IMDS answered we are provably in Azure,
                        # so "not an Azure VM" is already ruled out and offering it only sends
                        # the reader down the wrong path. On Windows 365 the usual cause is
                        # security context: WireServer does not answer a raw user-context
                        # connect, but does answer once elevated.
                        $imdsOk = $false
                        if ($probeResults.ContainsKey('IMDS|169.254.169.254')) {
                            $imdsOk = ($probeResults['IMDS|169.254.169.254'].Status -eq 'OK')
                        }
                        $result.Status = 'NOTAZURE'

                        # Port 53 is a special case and must not inherit the elevation
                        # advice. Microsoft only require it when the VNet uses
                        # Azure-provided DNS; with custom DNS servers there is nothing
                        # listening and silence is the correct, expected answer. Telling
                        # someone to re-run elevated for that is the same wrong-cause
                        # problem v3.4 set out to remove.
                        if ($item.Port -eq 53) {
                            $result.Detail = 'no response on 53 - expected when the VNet uses custom DNS rather than Azure-provided DNS'
                            Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "(only required with Azure-provided DNS - expected silence on custom DNS)"
                        } elseif ($imdsOk) {
                            $result.Detail = 'IMDS answered so this IS Azure - WireServer did not respond in this security context; re-run elevated'
                            Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "(IMDS answered - you ARE in Azure; WireServer needs an elevated context)"
                        } else {
                            $result.Detail = 'no WireServer response - not an Azure VM, or being intercepted'
                            Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "(no response - not an Azure VM, or being intercepted)"
                        }
                    }
                }

                'Wildcard' {
                    $p     = $probeResults[$item.Key]
                    $label = "$($item.Hostname):$($item.Port)"
                    $result.Rtt    = $p.Rtt
                    $result.Issuer = $p.Issuer
                    switch ($p.Status) {
                        'OK' {
                            $result.Status = 'OK-PROBE'
                            $result.Detail = "probed via $($item.ProbeTarget)"
                            Write-ResultLine -Tag ' OK ' -Colour Green -Label $label -Trailer "(probed $($item.ProbeTarget)$(if ($p.Rtt -ne $null) { ", $($p.Rtt) ms" }))"
                        }
                        'INSPECT' {
                            $result.Status = 'INSPECT'
                            $result.Detail = "probed via $($item.ProbeTarget) - unrecognised CA"
                            Write-ResultLine -Tag 'INSP' -Colour Yellow -Label $label -Trailer "(SSL inspection? via $($item.ProbeTarget), issuer: $($p.Issuer))"
                        }
                        'TLSFAIL' {
                            $result.Status = 'TLSFAIL'
                            $result.Detail = "probed via $($item.ProbeTarget) - $($p.Detail)"
                            Write-ResultLine -Tag 'TLS!' -Colour Yellow -Label $label -Trailer "(via $($item.ProbeTarget): $($p.Detail))"
                        }
                        'ZONE' {
                            $result.Status = 'ZONE'
                            $result.Detail = $p.Detail
                            Write-ResultLine -Tag 'ZONE' -Colour Cyan -Label $label -Trailer "(DNS zone resolves; port not directly testable)"
                        }
                        'DNSFAIL' {
                            $result.Status = 'DNSFAIL'
                            $result.Detail = $p.Detail
                            Write-ResultLine -Tag 'DNS!' -Colour Magenta -Label $label -Trailer "($($p.Detail))"
                        }
                        default {
                            $result.Status = 'FAIL'
                            $result.Detail = "probe $($item.ProbeTarget) - $($p.Detail)"
                            Write-ResultLine -Tag 'FAIL' -Colour Red -Label $label -Trailer "(probe $($item.ProbeTarget): $($p.Detail))"
                        }
                    }
                }

                'IpRange' {
                    # Collected and printed as one grouped line per category below,
                    # rather than one line per range. Full detail still goes to CSV.
                    $result.Status = 'IPRANGE'
                    $result.Detail = 'published IP range - allow at firewall'
                    [void]$rangeRows.Add($item)
                }

                'Reference' {
                    # Listed for completeness, deliberately not probed.
                    $result.Status = 'REFERENCE'
                    $result.Detail = $item.WildcardNote
                    $result.TestedAs = ''
                    Write-ResultLine -Tag 'INFO' -Colour DarkGray -Label "$($item.Hostname):$($item.Port)" -Trailer "(reference only - not tested)"
                }
            }

            [void]$allResults.Add($result)
        }

        # -- Collapsed IP range summary for this category ---------------------
        if ($rangeRows.Count -gt 0) {
            $groups = $rangeRows | Group-Object { "{0}|{1}|{2}" -f $_.Subcategory, $_.Protocol, $_.Port }
            foreach ($g in $groups) {
                $parts = $g.Name -split '\|'
                $sub   = $parts[0]; $proto = $parts[1]; $prt = $parts[2]
                $v6    = @($g.Group | Where-Object { $_.Hostname -match ':' }).Count
                $v4    = $g.Count - $v6

                $bits = @()
                if ($v4 -gt 0) { $bits += "$v4 IPv4" }
                if ($v6 -gt 0) { $bits += "$v6 IPv6" }
                $label = "{0} ranges  {1}:{2}" -f ($bits -join ' + '), $proto, $prt

                Write-ResultLine -Tag 'INFO' -Colour DarkCyan -Label $label -Trailer "($sub - allow at firewall; see summary)"
            }
        }
    }

    return $allResults.ToArray()
}

# -----------------------------------------------------------------------------
# HELPER: Print summary
# -----------------------------------------------------------------------------
function Write-Summary {
    param([array]$Results)

    # Set when the latency heuristic sees locally-terminated connections.
    $localTermination = $false

    $ok       = @($Results | Where-Object { $_.Status -eq 'OK'       }).Count
    $okProbe  = @($Results | Where-Object { $_.Status -eq 'OK-PROBE' }).Count
    $zone     = @($Results | Where-Object { $_.Status -eq 'ZONE'     }).Count
    $fail     = @($Results | Where-Object { $_.Status -eq 'FAIL'     }).Count
    $dnsfail  = @($Results | Where-Object { $_.Status -eq 'DNSFAIL'  }).Count
    $ranges   = @($Results | Where-Object { $_.Status -eq 'IPRANGE'  }).Count
    $udponly  = @($Results | Where-Object { $_.Status -eq 'UDPONLY'  }).Count
    $fabric   = @($Results | Where-Object { $_.Status -eq 'FABRIC'   }).Count
    $refonly  = @($Results | Where-Object { $_.Status -eq 'REFERENCE'}).Count
    $inspect  = @($Results | Where-Object { $_.Status -eq 'INSPECT'  }).Count
    $tlsfail  = @($Results | Where-Object { $_.Status -eq 'TLSFAIL'  }).Count
    $warn     = @($Results | Where-Object { $_.Status -eq 'WARN'     }).Count
    $notazure = @($Results | Where-Object { $_.Status -eq 'NOTAZURE' }).Count
    $total    = @($Results).Count

    # DNS failures split two ways. Three names Microsoft publish have never
    # resolved anywhere (see README); telling the reader to go and check their
    # DNS forwarders for those is a wild goose chase. They are still probed, so
    # if Microsoft ever fix them this reports the change rather than hiding it.
    $dnsKnown = @($Results | Where-Object { $_.Status -eq 'DNSFAIL' -and $_.KnownDead }).Count
    $dnsNew   = $dnsfail - $dnsKnown

    # Any status not counted above would silently vanish from this summary while
    # still being included in Total, so the numbers would stop adding up with no
    # indication why. Catch that here rather than letting it drift.
    $known    = @('OK','OK-PROBE','ZONE','FAIL','DNSFAIL','IPRANGE','UDPONLY','FABRIC','REFERENCE','INSPECT','TLSFAIL','WARN','NOTAZURE')
    $other    = @($Results | Where-Object { $known -notcontains $_.Status }).Count

    $problems = $fail + $dnsNew + $tlsfail

    Write-Host ""
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  RESULTS SUMMARY" -ForegroundColor White
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
    Write-Host "  Total entries    : $total"
    Write-Host "  OK               : $ok" -ForegroundColor Green
    if ($okProbe -gt 0) {
        Write-Host "  OK (wildcard)    : $okProbe  (verified via a real host inside the zone)" -ForegroundColor Green
    }
    if ($zone -gt 0) {
        Write-Host "  Zone resolves    : $zone  (wildcard, DNS confirmed; port not directly testable)" -ForegroundColor Cyan
    }
    if ($problems -gt 0) {
        Write-Host "  FAILED           : $fail" -ForegroundColor Red
        if ($dnsNew -gt 0) {
            Write-Host "  DNS FAILURES     : $dnsNew  (name/zone did not resolve - fix DNS, not the firewall)" -ForegroundColor Magenta
        }
    } else {
        Write-Host "  FAILED           : 0" -ForegroundColor Green
    }
    if ($dnsKnown -gt 0) {
        Write-Host "  Known-dead names : $dnsKnown  (published by Microsoft, have never resolved - not your DNS)" -ForegroundColor DarkGray
    }
    if ($ranges -gt 0) {
        Write-Host "  IP ranges        : $ranges  (published CIDR list - allow at firewall, see below)" -ForegroundColor DarkCyan
    }
    if ($udponly -gt 0) {
        Write-Host "  UDP only         : $udponly  (verify firewall/NSG allows UDP outbound)" -ForegroundColor DarkCyan
    }
    if ($fabric -gt 0) {
        Write-Host "  Azure Fabric     : $fabric  (cannot be reliably TCP tested)" -ForegroundColor DarkCyan
    }
    if ($refonly -gt 0) {
        Write-Host "  Reference only   : $refonly  (documented but not live - listed, not tested)" -ForegroundColor DarkGray
    }
    if ($inspect -gt 0) {
        Write-Host "  SSL INSPECTION   : $inspect  (cert issued by an unrecognised CA - see below)" -ForegroundColor Yellow
    }
    if ($tlsfail -gt 0) {
        Write-Host "  TLS FAILURES     : $tlsfail  (port open but TLS handshake failed)" -ForegroundColor Yellow
    }
    if ($warn -gt 0) {
        Write-Host "  Warnings         : $warn" -ForegroundColor Yellow
    }
    if ($notazure -gt 0) {
        # Mode 1 and 3 mean the user has told us they are ON a Cloud PC, so
        # "expected unless run on the Cloud PC" is exactly the wrong thing to say.
        if ($Mode -eq 1 -or $Mode -eq 3) {
            Write-Host "  Azure fabric     : $notazure  (did not respond - see the note above; usually security context, not the network)" -ForegroundColor DarkCyan
        } else {
            Write-Host "  Azure-only checks: $notazure  (no response - expected unless run on the Cloud PC)" -ForegroundColor DarkCyan
        }
    }
    if ($other -gt 0) {
        Write-Host "  Unclassified     : $other  (status not counted above - please report this)" -ForegroundColor Yellow
    }

    # Latency picture - reachability is only half of what makes a Cloud PC usable
    $rtts = @($Results | Where-Object { $_.Rtt -ne $null -and $_.Rtt -ge 0 } | ForEach-Object { [int]$_.Rtt })
    if ($rtts.Count -gt 0) {
        $sorted = $rtts | Sort-Object
        $median = $sorted[[int][math]::Floor($sorted.Count / 2)]
        Write-Host "  Connect latency  : median ${median} ms, min $($sorted[0]) ms, max $($sorted[-1]) ms  (over $($rtts.Count) probes)" -ForegroundColor DarkGray

        # Sub-millisecond connects mean a handshake completed without time for a
        # round trip. ACROSS THE INTERNET that means something local answered.
        # INSIDE AZURE it does not: a Cloud PC on the Microsoft Hosted Network
        # sits on Microsoft's own backbone, frequently in the same region or
        # metro as the service it is calling, and sub-millisecond connects to
        # Microsoft endpoints are simply normal there.
        #
        # So this cannot be read without knowing where we are, and the script
        # already knows - IMDS told us. Treating Azure proximity as interception
        # tells the reader their results are untrustworthy when they are fine.
        #
        # The remaining physics check works in both places: from anywhere on
        # earth, some endpoint in a list spanning Japan, Australia, Europe and
        # the US must be far away. If even the SLOWEST probe came back quickly,
        # nothing is reaching a distant endpoint and something local is
        # answering everything.
        $subMs   = @($sorted | Where-Object { $_ -lt 2 }).Count
        $slowest = $sorted[-1]
        $inAzure = @($Results | Where-Object { $_.Hostname -eq '169.254.169.254' -and $_.Status -eq 'OK' }).Count -gt 0

        # Endpoints that are physically far from most of the world. Nowhere on
        # earth is within 2ms of all of these, Azure backbone or not, so any of
        # them answering that fast means something local answered - a threshold
        # on the slowest probe overall cannot say that, because a run whose
        # endpoint list happens to be regional would trip it.
        $farHosts = @('intunemaape13.jpe.attest.azure.net','intunemaape17.jpe.attest.azure.net',
                      'intunemaape18.jpe.attest.azure.net','intunemaape19.jpe.attest.azure.net',
                      'hm-iot-in-prod-prau01.azure-devices.net','hm-iot-in-prod-prap01.azure-devices.net')
        $farImpossible = @($Results | Where-Object {
                            $_.Hostname -in $farHosts -and $_.Rtt -ne $null -and $_.Rtt -lt 2 }).Count -gt 0

        # The control probe is authoritative: an unroutable address was accepted,
        # so something local is answering on behalf of every destination. That
        # outranks anything the timings suggest, in Azure or not.
        if ($subMs -ge 3 -and ($script:InterceptDetected -or $farImpossible -or -not $inAzure)) {
            $localTermination = $true
            Write-Host ""
            Write-Host "  NOTE: $subMs of $($rtts.Count) probes completed in under 2 ms. A TCP handshake to a" -ForegroundColor DarkYellow
            Write-Host "        remote endpoint cannot complete that fast, so those connections are being" -ForegroundColor DarkYellow
            Write-Host "        terminated locally - typically a ZTNA/SWG client or transparent proxy." -ForegroundColor DarkYellow
            Write-Host "        The latency figures above do not describe the path to Microsoft, and on" -ForegroundColor DarkYellow
            Write-Host "        non-443 ports an [ OK ] only proves the local agent accepted the socket." -ForegroundColor DarkYellow
            Write-Host "        Port 443 results are unaffected: the TLS handshake still runs end to end." -ForegroundColor DarkYellow
        }
        elseif ($subMs -ge 3 -and $inAzure) {
            Write-Host ""
            Write-Host "  NOTE: $subMs of $($rtts.Count) probes completed in under 2 ms. IMDS confirms this is" -ForegroundColor DarkGray
            Write-Host "        an Azure VM, so that is expected rather than suspicious - you are on" -ForegroundColor DarkGray
            Write-Host "        Microsoft's backbone, often in the same region as the service being" -ForegroundColor DarkGray
            Write-Host "        called. Distant endpoints still took real time (slowest ${slowest} ms), which" -ForegroundColor DarkGray
            Write-Host "        confirms traffic is genuinely leaving this machine. No interception implied." -ForegroundColor DarkGray
        }
    }
    Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

    # -- Things that are actually broken --------------------------------------
    $failItems = @($Results | Where-Object { $_.Status -eq 'FAIL' })
    if ($failItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  BLOCKED ENDPOINTS (resolved in DNS, but the connection failed):" -ForegroundColor Red
        foreach ($f in $failItems) {
            $line = "    $($f.Hostname):$($f.Port)  [$($f.Category)]"
            if ($f.TestedAs -and $f.TestedAs -ne $f.Hostname) { $line += "  via $($f.TestedAs)" }
            if ($f.Notes) { $line += "  - $($f.Notes)" }
            Write-Host $line -ForegroundColor Red
        }
    }

    # -- SSL inspection -------------------------------------------------------
    # The single most misleading result the old TCP-only engine could produce:
    # a proxy terminating TLS answers the connect, so the endpoint looks fine
    # while the traffic is actually being intercepted.
    $inspectItems = @($Results | Where-Object { $_.Status -eq 'INSPECT' })
    if ($inspectItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  LIKELY SSL INSPECTION:" -ForegroundColor Yellow
        Write-Host "  These endpoints completed a TLS handshake, but the certificate chain roots to" -ForegroundColor DarkGray
        Write-Host "  a CA outside the public root programme - the signature of an intercepting" -ForegroundColor DarkGray
        Write-Host "  proxy. Check the root name below; if it is your own corporate CA, that" -ForegroundColor DarkGray
        Write-Host "  confirms inspection is active on these endpoints." -ForegroundColor DarkGray
        foreach ($i in $inspectItems) {
            Write-Host "    $($i.Hostname):$($i.Port)  [$($i.Category)]" -ForegroundColor Yellow
            Write-Host "      chain root: $($i.Issuer)" -ForegroundColor DarkGray
        }
        Write-Host "    Microsoft do NOT support SSL inspection for *.manage.microsoft.com," -ForegroundColor DarkGray
        Write-Host "    *.dm.microsoft.com, the Device Health Attestation endpoints, Defender for" -ForegroundColor DarkGray
        Write-Host "    Endpoint, Endpoint Privilege Management, or the Microsoft Store API." -ForegroundColor DarkGray
        Write-Host "    Exclude those from inspection or they will fail in ways that look unrelated." -ForegroundColor DarkGray
    }

    $tlsItems = @($Results | Where-Object { $_.Status -eq 'TLSFAIL' })
    if ($tlsItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  TLS HANDSHAKE FAILURES (TCP port open, but TLS did not complete):" -ForegroundColor Yellow
        foreach ($t in $tlsItems) {
            Write-Host "    $($t.Hostname):$($t.Port)  [$($t.Category)]  - $($t.Detail)" -ForegroundColor Yellow
        }
        # Two very different causes produce an identical TLS alert here, and this
        # script already has TWO independent signals for which environment we are
        # in. Both must be consulted, because they detect different things:
        #
        #   - The 203.0.113.1 control probe catches agents that intercept
        #     everything (transparent proxies).
        #   - The sub-2ms latency heuristic catches SELECTIVE agents. A ZTNA
        #     client such as Global Secure Access only tunnels its configured
        #     destinations, so an unroutable test address is correctly left
        #     alone and the control probe stays silent, while Microsoft traffic
        #     is still terminated locally.
        #
        # Selective interception is the common case, so keying only off the
        # control probe misses most real deployments.
        if ($script:InterceptDetected -or $localTermination) {
            # Name the signal that actually fired. Pointing at the control probe
            # when the control probe stayed silent is its own wrong detail.
            $why = if ($script:InterceptDetected) { 'the control probe above was accepted' }
                   else { 'the sub-2ms probe timings above' }
            Write-Host "    A local agent is intercepting traffic on this device ($why)," -ForegroundColor DarkGray
            Write-Host "    so it - not Microsoft - terminated this handshake." -ForegroundColor DarkGray
            Write-Host "    An 'InternalError' alert from a ZTNA/SWG client usually means the agent" -ForegroundColor DarkGray
            Write-Host "    could not broker that specific hostname: no matching policy, an upstream" -ForegroundColor DarkGray
            Write-Host "    failure, or the destination excluded from its tunnel. Treat this as a" -ForegroundColor DarkGray
            Write-Host "    real finding until proven otherwise - if it is Windows Update or" -ForegroundColor DarkGray
            Write-Host "    Delivery Optimization content, patching may genuinely be broken." -ForegroundColor DarkGray
            Write-Host "    To confirm: re-run and see whether the SAME hostname fails each time" -ForegroundColor DarkGray
            Write-Host "    (agent policy) or a different one each run (CDN rate limiting), and" -ForegroundColor DarkGray
            Write-Host "    compare against a device outside the agent." -ForegroundColor DarkGray
        } else {
            Write-Host "    A reachable port with a failing handshake usually means a proxy is" -ForegroundColor DarkGray
            Write-Host "    accepting the connection but refusing the hostname. Check whether the" -ForegroundColor DarkGray
            Write-Host "    same host fails on every run - a policy block is consistent." -ForegroundColor DarkGray
        }
        # Only mention the CDN-shared-certificate situation when a failure is
        # actually in one of those zones, otherwise it is a stray fact about a
        # hostname that is not on screen.
        $cdnZones = @('windowsupdate.com','delivery.mp.microsoft.com','adl.windows.com')
        $hitCdn = @($tlsItems | Where-Object { $h = $_.Hostname; @($cdnZones | Where-Object { $h -like "*$_" }).Count -gt 0 })
        if ($hitCdn.Count -gt 0) {
            Write-Host "    Note: these are CDN-fronted content endpoints. Every host in those zones" -ForegroundColor DarkGray
            Write-Host "    serves a CDN certificate (Akamai or Fastly) that does not cover the" -ForegroundColor DarkGray
            Write-Host "    hostname, so a handshake there can fail for reasons that have nothing to" -ForegroundColor DarkGray
            Write-Host "    do with your network. They are normally excluded from TLS validation for" -ForegroundColor DarkGray
            Write-Host "    that reason - if you are seeing them here, TLS was forced on somehow." -ForegroundColor DarkGray
            Write-Host "    What matters for these is port 80: the content is signed and fetched" -ForegroundColor DarkGray
            Write-Host "    over HTTP, so check the port 80 result above instead." -ForegroundColor DarkGray
        }
    }

    $warnItems = @($Results | Where-Object { $_.Status -eq 'WARN' })
    if ($warnItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  WARNINGS:" -ForegroundColor Yellow
        foreach ($w in $warnItems) {
            Write-Host "    $($w.Hostname):$($w.Port)  [$($w.Category)]  - $($w.Detail)" -ForegroundColor Yellow
        }
    }

    $dnsItems  = @($Results | Where-Object { $_.Status -eq 'DNSFAIL' -and -not $_.KnownDead })
    $deadItems = @($Results | Where-Object { $_.Status -eq 'DNSFAIL' -and $_.KnownDead })
    if ($dnsItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  DNS FAILURES (the name never resolved - this is a DNS problem, not a port problem):" -ForegroundColor Magenta
        foreach ($d in $dnsItems) {
            $line = "    $($d.Hostname)  [$($d.Category)]"
            if ($d.TestedAs -and $d.TestedAs -ne $d.Hostname) { $line += "  via $($d.TestedAs)" }
            Write-Host $line -ForegroundColor Magenta
        }
        Write-Host "    Check DNS forwarders, split-horizon DNS, and any DNS-layer filtering product." -ForegroundColor DarkGray
    }
    if ($deadItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  KNOWN-DEAD NAMES (nothing to fix - these are documentation errors at Microsoft):" -ForegroundColor DarkGray
        foreach ($d in $deadItems) {
            $why = if ($d.Notes) { " - $($d.Notes)" } else { '' }
            Write-Host "    $($d.Hostname)  [$($d.Category)]$why" -ForegroundColor DarkGray
        }
        Write-Host "    Microsoft publish these but they have never resolved, from any network," -ForegroundColor DarkGray
        Write-Host "    so seeing them here says nothing about your DNS. They are still probed" -ForegroundColor DarkGray
        Write-Host "    on every run, so if Microsoft ever bring them up you will see it here." -ForegroundColor DarkGray
    }

    # -- Wildcards confirmed only at the zone level ---------------------------
    $zoneItems = @($Results | Where-Object { $_.Status -eq 'ZONE' })
    if ($zoneItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  WILDCARDS CONFIRMED AT DNS ZONE LEVEL:" -ForegroundColor Cyan
        Write-Host "  These have no stable public hostname to connect to, so the zone was checked" -ForegroundColor DarkGray
        Write-Host "  for an authoritative SOA instead. DNS is reaching them; confirm the firewall" -ForegroundColor DarkGray
        Write-Host "  rule covers the whole wildcard." -ForegroundColor DarkGray
        foreach ($z in ($zoneItems | Sort-Object Hostname -Unique)) {
            Write-Host "    $($z.Hostname)  [$($z.Category)]" -ForegroundColor Cyan
        }
    }

    # -- IP ranges, collapsed -------------------------------------------------
    # Previously this printed all ~177 CIDR entries individually, which buried
    # the results that actually needed attention. Grouped counts here; the full
    # list still goes to the CSV via -OutputPath.
    $rangeItems = @($Results | Where-Object { $_.Status -eq 'IPRANGE' })
    if ($rangeItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  PUBLISHED IP RANGES (allow at the firewall - not individually testable):" -ForegroundColor DarkCyan
        $byCat = $rangeItems | Group-Object Category, Subcategory
        foreach ($g in $byCat) {
            $v6 = @($g.Group | Where-Object { $_.Hostname -match ':' }).Count
            $v4 = $g.Count - $v6
            $bits = @()
            if ($v4 -gt 0) { $bits += "$v4 IPv4" }
            if ($v6 -gt 0) { $bits += "$v6 IPv6" }
            $ports = ($g.Group | Select-Object -ExpandProperty Port -Unique | Sort-Object) -join ','
            Write-Host ("    {0,-46} {1}  (ports {2})" -f $g.Name, ($bits -join ' + '), $ports) -ForegroundColor DarkCyan
        }
        Write-Host ""
        Write-Host "    Testing individual IPs inside these ranges produces misleading results -" -ForegroundColor DarkGray
        Write-Host "    not every published address serves traffic from every region at a given" -ForegroundColor DarkGray
        Write-Host "    time. Allow the ranges at the firewall and verify by rule, not by probe." -ForegroundColor DarkGray
        Write-Host "    Run with -OutputPath to get the full CIDR list in CSV form." -ForegroundColor DarkGray
        Write-Host "    Azure Front Door ranges are covered by the AzureFrontDoor.MicrosoftSecurity" -ForegroundColor DarkGray
        Write-Host "    service tag if you prefer to use one." -ForegroundColor DarkGray
    }

    # -- UDP ------------------------------------------------------------------
    $udpItems = @($Results | Where-Object { $_.Status -eq 'UDPONLY' })
    if ($udpItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  UDP ENTRIES (verify firewall/NSG allows outbound UDP):" -ForegroundColor DarkCyan
        foreach ($u in $udpItems) {
            Write-Host "    $($u.Hostname)  UDP:$($u.Port)  [$($u.Category)]  - $($u.Notes)" -ForegroundColor DarkCyan
        }
    }

    # -- Azure fabric ---------------------------------------------------------
    $fabricItems = @($Results | Where-Object { $_.Status -eq 'FABRIC' })
    if ($fabricItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  AZURE FABRIC IPs (WireServer / IMDS - do not proxy or intercept):" -ForegroundColor DarkCyan
        foreach ($f in $fabricItems) {
            Write-Host "    $($f.Hostname):$($f.Port)  [$($f.Category)]  - $($f.Notes)" -ForegroundColor DarkCyan
        }
        Write-Host "    See: https://learn.microsoft.com/en-us/azure/virtual-desktop/azurecommunicationips" -ForegroundColor DarkGray
    }

    # -- Reference-only entries -----------------------------------------------
    $refItems = @($Results | Where-Object { $_.Status -eq 'REFERENCE' })
    if ($refItems.Count -gt 0) {
        Write-Host ""
        Write-Host "  REFERENCE ONLY (listed by Microsoft, deliberately not tested):" -ForegroundColor DarkGray
        foreach ($r in ($refItems | Sort-Object Hostname -Unique)) {
            Write-Host "    $($r.Hostname)  [$($r.Category)]" -ForegroundColor DarkGray
            if ($r.Notes) { Write-Host "      $($r.Notes)" -ForegroundColor DarkGray }
        }
        Write-Host "    These are kept in Endpoints.csv so the list stays a faithful record of" -ForegroundColor DarkGray
        Write-Host "    what Microsoft publish, but probing them only produces noise." -ForegroundColor DarkGray
    }

    if ($problems -eq 0) {
        Write-Host ""
        Write-Host "  No blocked endpoints or DNS failures found." -ForegroundColor Green
    }
}
function Get-BuiltInEndpoints {
    return @(
        # -- Windows 365 Service ----------------------------------------------
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

        # -- AVD Session Host (required) --------------------------------------
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

        # -- AVD Session Host (optional) --------------------------------------
        [PSCustomObject]@{ Category='AVD-SessionHost-Optional'; Subcategory='Auth';    Endpoint='login.windows.net';                       Port=443;  TestMode='CloudPC'; Notes='Sign in to Microsoft Online Services and Microsoft 365' }
        [PSCustomObject]@{ Category='AVD-SessionHost-Optional'; Subcategory='Connectivity'; Endpoint='www.msftconnecttest.com';            Port=80;   TestMode='CloudPC'; Notes='Internet connectivity detection' }

        # -- Client / End User Device -----------------------------------------
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

        # -- Client - Azure CA Certificate checks (closed network) -----------
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

        # -- Intune Core Service ----------------------------------------------
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
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape1.eus.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - East US' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape2.eus2.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - East US 2' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape3.cus.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - Central US' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape4.wus.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - West US' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape5.scus.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - South Central US' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape6.ncus.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - North Central US' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape7.neu.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - North Europe' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape8.neu.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - North Europe 2' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape9.neu.attest.azure.net';        Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - North Europe 3' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape10.weu.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - West Europe' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape11.weu.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - West Europe 2' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape12.weu.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - West Europe 3' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape13.jpe.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - Japan East' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape17.jpe.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - Japan East 2' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape18.jpe.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - Japan East 3' }
        [PSCustomObject]@{ Category='Intune'; Subcategory='MAA Attestation';        Endpoint='intunemaape19.jpe.attest.azure.net';       Port=443;  TestMode='CloudPC'; Notes='Microsoft Azure Attestation - Japan East 4' }

        # -- Intune IP Ranges (ID 163 - Allow Required) -----------------------
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

        # -- Intune Autopilot -------------------------------------------------
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

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------

Write-Banner

# -- Step 1: Resolve endpoint list --------------------------------------------
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

# -- Step 2: Prompt for mode if not supplied -----------------------------------
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

# -- Step 2b: Region picker for Intune IP ranges -------------------------------
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

# Build a flat [start, end, region] table from the service tag prefixes, parsing
# each CIDR exactly once.
#
# The previous approach compared every Intune range against every prefix string
# directly, which re-parsed BOTH CIDRs on every comparison: 461,739 comparisons
# and roughly 923,000 IPAddress parses, taking around 80 seconds. Parsing once
# up front and then comparing plain integers gives identical results in about
# 1.3 seconds - the download and JSON parse were never the slow part.
function Build-PrefixTable {
    param([array]$AzureCloudTags)

    $table = New-Object System.Collections.ArrayList
    foreach ($tag in $AzureCloudTags) {
        $region = $tag.properties.region
        if (-not $region) { continue }
        foreach ($prefix in $tag.properties.addressPrefixes) {
            if ($prefix.IndexOf(':') -ge 0) { continue }   # skip IPv6
            $r = Get-CidrRange $prefix
            if ($r) {
                [void]$table.Add([PSCustomObject]@{ Start = $r.Start; End = $r.End; Region = $region })
            }
        }
    }
    return $table
}

if (($Mode -eq 1 -or $Mode -eq 3) -and -not $SkipRegionPicker) {
    Write-Host ""
    Write-Host "  [region-picker] Mapping published Intune IP ranges to Azure regions..." -ForegroundColor DarkGray
    Write-Host "  [region-picker] This only narrows the IP-range guidance shown at the end." -ForegroundColor DarkGray
    Write-Host "  [region-picker] No connectivity is tested here - use -SkipRegionPicker to skip." -ForegroundColor DarkGray

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

            $prefixTable = Build-PrefixTable -AzureCloudTags $azureCloudRegions
            Write-Host "  [region-picker] Indexed $($prefixTable.Count) IPv4 prefixes" -ForegroundColor DarkGray

            foreach ($ipRange in $ipRangeEndpoints) {
                $r = Get-CidrRange $ipRange
                if (-not $r) { continue }
                $foundRegion = $null
                foreach ($row in $prefixTable) {
                    if ($r.Start -ge $row.Start -and $r.End -le $row.End) { $foundRegion = $row.Region; break }
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
        Write-Host "        Only $($regionMap.Keys.Count) regions are listed because Microsoft publish Intune service" -ForegroundColor DarkGray
        Write-Host "        IPs in those regions only - the other Azure regions have none. Region" -ForegroundColor DarkGray
        Write-Host "        names are Microsoft's own service-tag spellings (e.g. 'switzerlandn')." -ForegroundColor DarkGray
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
# -- Step 2c: Environment checks -----------------------------------------------
# Context and proxy configuration change what the results actually mean, so
# state them up front rather than leaving the reader to guess.
Write-Host ""
Write-Host "  -- Environment --" -ForegroundColor Cyan

$isSystem = $false
try {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $isSystem = $id.IsSystem
    $isAdmin  = (New-Object System.Security.Principal.WindowsPrincipal($id)).IsInRole(
                    [System.Security.Principal.WindowsBuiltInRole]::Administrator)
    $ctx = if ($isSystem) { 'SYSTEM' } elseif ($isAdmin) { "$($id.Name) (elevated)" } else { $id.Name }
    Write-Host "  Running as       : $ctx" -ForegroundColor DarkGray
} catch { }

if (-not $isSystem) {
    Write-Host "  NOTE: running in user context. Autopilot OOBE, Windows Update and TPM" -ForegroundColor DarkYellow
    Write-Host "        attestation run as SYSTEM, which can have a different proxy and" -ForegroundColor DarkYellow
    Write-Host "        firewall path. To test that path, re-run under SYSTEM:" -ForegroundColor DarkYellow
    Write-Host "        psexec.exe -accepteula -i -s powershell.exe" -ForegroundColor DarkGray
    if (-not $isAdmin) {
        # Elevation alone changes results, well short of SYSTEM: the WireServer
        # fabric IP does not answer a raw connect from a non-elevated process on
        # a Cloud PC, and does as soon as the console is elevated.
        Write-Host "        Elevation alone also matters - the Azure fabric IPs do not answer a" -ForegroundColor DarkYellow
        Write-Host "        non-elevated connect. Try an elevated console before reading too much" -ForegroundColor DarkYellow
        Write-Host "        into any fabric result below." -ForegroundColor DarkYellow
    }
}

# Proxy configuration. TCP sockets bypass WinHTTP/WinINET entirely, so if a
# proxy is configured the results below describe the direct path, not the path
# real traffic takes.
try {
    $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy()
    $testUri  = [Uri]'https://login.microsoftonline.com'
    $proxyUri = $sysProxy.GetProxy($testUri)
    if ($proxyUri -and $proxyUri.AbsoluteUri -ne $testUri.AbsoluteUri) {
        Write-Host "  Proxy detected   : $($proxyUri.Host):$($proxyUri.Port)" -ForegroundColor DarkYellow
        Write-Host "  WARNING: this script uses raw TCP/TLS sockets, which bypass WinINET and" -ForegroundColor DarkYellow
        Write-Host "           WinHTTP proxy settings. Results reflect the DIRECT path. Traffic" -ForegroundColor DarkYellow
        Write-Host "           from real clients will go via the proxy and may behave differently." -ForegroundColor DarkYellow
    } else {
        Write-Host "  Proxy            : none configured for HTTPS" -ForegroundColor DarkGray
    }
} catch { }

# Control probe. 203.0.113.1 is RFC 5737 TEST-NET-3: reserved for documentation
# and never routed on the public internet, so nothing anywhere should ever accept
# a connection on it. If something does, a local agent is accepting on behalf of
# every destination and an [ OK ] no longer proves traffic reached Microsoft.
# WinINET proxy detection above cannot see this - ZTNA and SWG clients intercept
# below that layer, at the WFP/driver level, and set no proxy at all.
try {
    $ctl   = New-Object System.Net.Sockets.TcpClient
    $ctlAr = $ctl.BeginConnect('203.0.113.1', 443, $null, $null)
    if ($ctlAr.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(3), $false)) {
        try {
            $ctl.EndConnect($ctlAr)
            $script:InterceptDetected = $true
            Write-Host "  Traffic intercept: YES - a local agent is terminating connections" -ForegroundColor DarkYellow
            Write-Host "  WARNING: a control probe to 203.0.113.1 (RFC 5737, unroutable by design)" -ForegroundColor DarkYellow
            Write-Host "           was ACCEPTED. Something on this device - a ZTNA/SWG client such as" -ForegroundColor DarkYellow
            Write-Host "           Global Secure Access, Zscaler or Netskope, or a transparent proxy -" -ForegroundColor DarkYellow
            Write-Host "           answers on behalf of every destination. TCP-only results below show" -ForegroundColor DarkYellow
            Write-Host "           that agent accepting, not the endpoint being reachable. Port 443" -ForegroundColor DarkYellow
            Write-Host "           results still hold: the TLS handshake runs end to end." -ForegroundColor DarkYellow
        } catch {
            Write-Host "  Traffic intercept: none detected (control probe correctly refused)" -ForegroundColor DarkGray
        }
    } else {
        Write-Host "  Traffic intercept: none detected (control probe correctly timed out)" -ForegroundColor DarkGray
    }
    $ctl.Close()
} catch { }

# IPv6 egress - six IPv6 ranges are in the endpoint list but nothing tested
# whether IPv6 leaves the network at all.
try {
    $v6 = [System.Net.Dns]::GetHostAddresses('ipv6.msftconnecttest.com') |
          Where-Object { $_.AddressFamily -eq 'InterNetworkV6' } | Select-Object -First 1
    if ($v6) {
        $t6 = New-Object System.Net.Sockets.TcpClient([System.Net.Sockets.AddressFamily]::InterNetworkV6)
        $a6 = $t6.BeginConnect($v6, 80, $null, $null)
        if ($a6.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds(5), $false)) {
            try { $t6.EndConnect($a6); Write-Host "  IPv6 egress      : working" -ForegroundColor DarkGray }
            catch { Write-Host "  IPv6 egress      : not available (IPv6 endpoints in the list will be unreachable)" -ForegroundColor DarkCyan }
        } else {
            Write-Host "  IPv6 egress      : not available (IPv6 endpoints in the list will be unreachable)" -ForegroundColor DarkCyan
        }
        $t6.Close()
    } else {
        Write-Host "  IPv6 egress      : no IPv6 address resolved - IPv6 likely not in use" -ForegroundColor DarkCyan
    }
} catch {
    Write-Host "  IPv6 egress      : not available" -ForegroundColor DarkCyan
}

if ($NoTlsCheck) {
    Write-Host "  TLS validation   : disabled (-NoTlsCheck)" -ForegroundColor DarkGray
} else {
    Write-Host "  TLS validation   : enabled - certificates checked on port 443" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray
Write-Host "  Legend:  [ OK ] Connected   [FAIL] Blocked   [DNS!] Name did not resolve" -ForegroundColor DarkGray
Write-Host "           [INSP] SSL inspection detected  [TLS!] TLS handshake failed" -ForegroundColor DarkGray
Write-Host "           [ZONE] Wildcard zone resolves   [INFO] IP range / Azure-only / reference" -ForegroundColor DarkGray
Write-Host "-----------------------------------------------------" -ForegroundColor DarkGray

$allResults = @()

# -- Step 3: Run tests ---------------------------------------------------------
if ($Mode -eq 1 -or $Mode -eq 3) {
    Write-Host ""
    Write-Host "+- CLOUD PC / HOST NETWORK TESTS -------------------------+" -ForegroundColor Magenta
    $allResults += Test-EndpointList -Endpoints $endpointData -FilterMode 'CloudPC'
    Write-Host ""
    Write-Host "+---------------------------------------------------------+" -ForegroundColor Magenta
}

if ($Mode -eq 2 -or $Mode -eq 3) {
    Write-Host ""
    Write-Host "+- CLIENT DEVICE NETWORK TESTS ---------------------------+" -ForegroundColor Blue
    $allResults += Test-EndpointList -Endpoints $endpointData -FilterMode 'Client'
    Write-Host ""
    Write-Host "+---------------------------------------------------------+" -ForegroundColor Blue
}

# -- Step 4: Summary -----------------------------------------------------------
Write-Summary -Results $allResults

# -- Step 5: Export results (optional) ----------------------------------------
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
