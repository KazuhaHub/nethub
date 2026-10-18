param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-z0-9.-]+$')][string]$TestHostname,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-zA-Z0-9_-]+$')][string]$NetworkLabel,
    [string]$OutputDirectory = (Join-Path $env:USERPROFILE 'nethub-w0-results')
)
$ErrorActionPreference = 'Stop'
$curl = (Get-Command curl.exe -ErrorAction Stop).Source
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$repository = [IO.Path]::GetFullPath((Split-Path $PSScriptRoot -Parent))
if (Test-Path -LiteralPath (Join-Path $repository '.git')) {
    if ($OutputDirectory.Equals($repository, [StringComparison]::OrdinalIgnoreCase) -or
        $OutputDirectory.StartsWith($repository + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Keep network evidence outside the repository.'
    }
}
[IO.Directory]::CreateDirectory($OutputDirectory) > $null
$destination = Join-Path $OutputDirectory ($NetworkLabel + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.csv')
if (Test-Path -LiteralPath $destination) { throw 'An evidence file already exists; retain it and start a new run.' }
$rows = @()
for ($round = 1; $round -le 20; $round++) {
    foreach ($port in @(443,8443)) {
        $started = [DateTime]::UtcNow.ToString('o')
        $format = '%{http_code},%{time_connect},%{time_appconnect},%{time_total},%{remote_ip},%{local_ip}'
        $metrics = & $curl -4 --noproxy '*' -o NUL -s -k --connect-timeout 5 --max-time 10 -w $format "https://${TestHostname}:${port}/"
        $exitCode = $LASTEXITCODE
        $parts = ([string]$metrics).Trim().Split(',')
        if ($parts.Count -ne 6) { throw 'Unexpected curl metrics; retain existing CSV and investigate.' }
        $culture = [Globalization.CultureInfo]::InvariantCulture
        $connect = [double]::Parse($parts[1],$culture)
        $row = [pscustomobject]@{
            Network = $NetworkLabel; Round = $round; Port = $port; StartedUtc = $started
            CurlExit = $exitCode; HttpCode = $parts[0]; TcpConnected = ($connect -gt 0)
            TimeConnect = $parts[1]; TimeAppConnect = $parts[2]; TimeTotal = $parts[3]
            RemoteAddress = $parts[4]; SourceAddress = $parts[5]; AddressFamily = 'IPv4'
        }
        $row | Export-Csv -LiteralPath $destination -Append -NoTypeInformation -Encoding UTF8
        $rows += $row
        Write-Host ('Round {0}/20, port {1}: TCP {2}, curl exit {3}' -f $round,$port,$row.TcpConnected,$exitCode)
    }
    if ($round -lt 20) { Start-Sleep -Seconds 2 }
}
$baseline = @($rows | Where-Object { $_.Port -eq 443 -and $_.TcpConnected }).Count
$tunnel = @($rows | Where-Object { $_.Port -eq 8443 -and $_.TcpConnected }).Count
$sanitized = [IO.Path]::ChangeExtension($destination, 'sanitized.csv')
$rows | Select-Object Network,Round,Port,StartedUtc,CurlExit,HttpCode,TcpConnected,TimeConnect,TimeAppConnect,TimeTotal,AddressFamily | Export-Csv -LiteralPath $sanitized -NoTypeInformation -Encoding UTF8
[pscustomobject]@{
    Network=$NetworkLabel; SamplesPerPort=20; Tcp443=$baseline; Tcp8443=$tunnel
    DifferencePercentagePoints=5*($baseline-$tunnel)
    Q2Triggered=(($baseline-$tunnel -ge 4) -or ($tunnel -eq 0))
    BothZero=($baseline -eq 0 -and $tunnel -eq 0); SanitizedCsv=$sanitized; PrivateCsv=$destination
} | Format-List
