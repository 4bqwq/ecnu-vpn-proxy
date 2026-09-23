$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../vpn.ps1')
$script:Passed = 0

function Check([string]$Label, [scriptblock]$Body) {
    & $Body
    $script:Passed++
    Write-Output "PASS: $Label"
}
function Assert-True($Value) { if (-not $Value) { throw 'Assertion failed.' } }
function Assert-Throws([scriptblock]$Body, [string]$Pattern = '.') {
    $exception = $null
    try { & $Body | Out-Null } catch { $exception = $_ }
    if ($null -eq $exception -or $exception.Exception.Message -notmatch $Pattern) { throw 'Expected a matching exception.' }
}
function Parse-Config([string]$Text) { return ConvertTo-VpnConfig ($Text | ConvertFrom-Json) }

Check 'An empty forwarding list is valid' {
    $c = Parse-Config '{"proxy_port":11080,"forwards":[],"check":null}'
    Assert-True ($c.forwards.Count -eq 0 -and $null -eq $c.check)
}
Check 'A numeric alias stays a string and an SSH user is optional' {
    $c = Parse-Config '{"proxy_port":11080,"forwards":[{"name":"001","host":"192.0.2.10","local_port":2222,"remote_port":22}]}'
    Assert-True ($c.forwards[0].name -ceq '001' -and $null -eq $c.forwards[0].ssh_user)
}
Check 'A health target does not require any forwarding rules' {
    $c = Parse-Config '{"proxy_port":11080,"forwards":[],"check":{"host":"service.internal.example","port":443}}'
    Assert-True ($c.check.port -eq 443 -and $c.forwards.Count -eq 0)
}
Check 'Reject an unknown key rather than silently ignoring a typo' {
    Assert-Throws { Parse-Config '{"proxy_port":11080,"forward":[]}' }
}
Check 'Reject non-array forwarding data' {
    Assert-Throws { Parse-Config '{"proxy_port":11080,"forwards":{}}' }
    Assert-Throws { Parse-Config '{"proxy_port":11080,"forwards":null}' }
}
Check 'Reject fractional, string and out-of-range ports' {
    foreach ($port in @('11080.5', '"11080"', '0', '65536', 'true')) {
        Assert-Throws { Parse-Config ('{"proxy_port":' + $port + ',"forwards":[]}') }
    }
}
Check 'Reject collisions with the fixed authentication or desktop port' {
    Assert-Throws { Parse-Config '{"proxy_port":54631,"forwards":[]}' }
    Assert-Throws { Parse-Config '{"proxy_port":18080,"forwards":[]}' }
}
Check 'Reject a forward that collides with the proxy port' {
    Assert-Throws { Parse-Config '{"proxy_port":2222,"forwards":[{"name":"a","host":"192.0.2.10","local_port":2222,"remote_port":22}]}' }
}
Check 'Reject duplicate aliases without depending on case' {
    Assert-Throws { Parse-Config '{"proxy_port":11080,"forwards":[{"name":"Demo","host":"192.0.2.10","local_port":2222,"remote_port":22},{"name":"demo","host":"192.0.2.11","local_port":2223,"remote_port":22}]}' }
}
Check 'Reject duplicate local ports' {
    Assert-Throws { Parse-Config '{"proxy_port":11080,"forwards":[{"name":"a","host":"192.0.2.10","local_port":2222,"remote_port":22},{"name":"b","host":"192.0.2.11","local_port":2222,"remote_port":22}]}' }
}
Check 'Host fields cannot inject socat options or shell syntax' {
    foreach ($target in @('example.test,reuseaddr', 'a;id', '$(id)', '-host', 'https://example.test', 'host:22')) {
        Assert-Throws { Assert-Target $target 'test.host' }
    }
}
Check 'Only exact, successful client statuses are trusted' {
    foreach ($status in @('online', 'logout', 'login', 'offline', 'connect', 'disconnect', 'networkUnavailable')) {
        Assert-True ((ConvertFrom-ClientStatus ([pscustomobject]@{code=0;status=$status})).state -ceq $status)
    }
    foreach ($sample in @('{"status":"online"}', '{"code":null,"status":"online"}', '{"code":"0","status":"online"}', '{"code":1,"status":"online"}', '{"code":0,"status":"ONLINE"}', '{"code":0}', '{"code":0,"status":"futureState"}')) {
        Assert-True ((ConvertFrom-ClientStatus ($sample | ConvertFrom-Json)).state -eq 'unknown')
    }
}
Check 'A truncated protocol response is a failure' {
    $stream = New-Object IO.MemoryStream(,[byte[]]@(5))
    try { Assert-Throws { Read-Exact $stream 2 } } finally { $stream.Dispose() }
}
Check 'Canonical config hashes ignore JSON whitespace' {
    $a = Parse-Config '{"proxy_port":11080,"forwards":[]}'
    $b = Parse-Config '{ "forwards": [ ], "proxy_port": 11080, "check": null }'
    Assert-True ((Get-ConfigHash $a) -eq (Get-ConfigHash $b))
    $b.proxy_port = 11081
    Assert-True ((Get-ConfigHash $a) -ne (Get-ConfigHash $b))
}
Check 'Generated forwards leave the upstream browser login relay available' {
    $runtime = $script:Runtime
    $script:Runtime = Join-Path $runtime ('test-' + [guid]::NewGuid().ToString('N'))
    try {
        $c = Parse-Config '{"proxy_port":11080,"forwards":[{"name":"demo","host":"192.0.2.10","local_port":20000,"remote_port":22}]}'
        Write-Runtime $c
        $row = (Get-Content -LiteralPath (Join-Path $script:Runtime 'forwards.tsv') -Raw).Trim() -split "`t"
        # The pinned upstream image redirects browser callbacks to port 20000.
        Assert-True ([int]$row[0] -ne 20000)
        $generated = Get-Content -LiteralPath (Join-Path $script:Runtime 'compose.override.json') -Raw | ConvertFrom-Json
        Assert-True ($generated.services.vpn.ports -contains "127.0.0.1:20000:$($row[0])")
        foreach ($port in $generated.services.vpn.ports) { Assert-True ($port.StartsWith('127.0.0.1:')) }
    } finally {
        if (Test-Path -LiteralPath $script:Runtime) { Remove-Item -LiteralPath $script:Runtime -Recurse }
        $script:Runtime = $runtime
    }
}
Check 'Conflicting ports are rejected before any container is stopped' {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = $listener.LocalEndpoint.Port
        $c = Parse-Config ('{"proxy_port":' + $port + ',"forwards":[]}')
        $ownedFixedPorts = [pscustomobject]@{
            State = [pscustomobject]@{ Running = $true }
            NetworkSettings = [pscustomobject]@{ Ports = [pscustomobject]@{
                '8080/tcp' = @([pscustomobject]@{ HostPort = '18080' })
                '54631/tcp' = @([pscustomobject]@{ HostPort = '54631' })
            } }
        }
        Assert-Throws { Assert-AvailablePorts $c $ownedFixedPorts } ([string]$port)
    } finally { $listener.Stop() }
}
Write-Output "All $script:Passed checks passed."
