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
function New-ContainerFixture {
    return [pscustomobject]@{
        Id = 'test-container'
        State = [pscustomobject]@{ Running = $true; ExitCode = 0; OOMKilled = $false }
        Config = [pscustomobject]@{ Labels = [pscustomobject]@{
            'io.ecnu-proxy.config' = Get-ConfigHash (Parse-Config '{"proxy_port":11080,"forwards":[]}')
        } }
        HostConfig = [pscustomobject]@{ PortBindings = [pscustomobject]@{
            '54631/tcp' = @([pscustomobject]@{ HostIp = '127.0.0.1'; HostPort = '54631' })
        } }
        NetworkSettings = [pscustomobject]@{ Ports = [pscustomobject]@{ '54631/tcp' = @() } }
    }
}

function With-TestRuntime([scriptblock]$Body) {
    $runtime = $script:Runtime
    $script:Runtime = Join-Path $runtime ('test-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($script:Runtime)
    try { & $Body } finally {
        Remove-Item -LiteralPath $script:Runtime -Recurse
        $script:Runtime = $runtime
    }
}

Check 'Requested authentication bindings do not prove that Docker published them' {
    $result = Test-LoginEndpoint (New-ContainerFixture)
    Assert-True (-not $result.success -and $result.retryable -and $result.detail -match '54631')
}
Check 'A successful detection can contain an empty pubkey' {
    Assert-LoginDetection ('{"code":0,"data":{"pubkey":""}}' | ConvertFrom-Json)
    foreach ($value in @('{"code":1,"data":{"pubkey":""}}', '{"code":"0","data":{"pubkey":""}}', '{"code":0}', '{"code":0,"data":{"pubkey":null}}')) {
        Assert-Throws { Assert-LoginDetection ($value | ConvertFrom-Json) } 'aTrust'
    }
}
Check 'Already authenticated login opens no page and makes no container changes' {
    function Get-ClientStatus { return [pscustomobject]@{ state = 'online'; detail = '' } }
    function Open-LoginPage { throw 'Must not open browser' }
    function Invoke-Docker { throw 'Must not mutate container' }
    Invoke-Login (New-ContainerFixture)
}
Check 'A broken callback prevents opening the login page' {
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Open-LoginPage { throw 'Must not open browser' }
    function Invoke-Docker { throw 'Must not mutate container' }
    Assert-Throws { Invoke-Login (New-ContainerFixture) } '认证接口不可用'
}
Check 'Login returns only after the container authenticates, even if the web page opened' {
    $script:authReads = 0
    $script:pageOpens = 0
    function Get-ClientStatus {
        $script:authReads++
        $state = if ($script:authReads -lt 4) { 'logout' } else { 'online' }
        return [pscustomobject]@{ state = $state; detail = '' }
    }
    function Get-VpnContainer { return New-ContainerFixture }
    function Test-LoginEndpoint { return [pscustomobject]@{ success = $true } }
    function Open-LoginPage { $script:pageOpens++ }
    function Start-Sleep { }
    Invoke-Login (New-ContainerFixture)
    Assert-True ($script:authReads -eq 4 -and $script:pageOpens -eq 1)
}
Check 'Loss of the callback while waiting for authentication is reported' {
    $script:endpointReads = 0
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Get-VpnContainer { return New-ContainerFixture }
    function Test-LoginEndpoint {
        $script:endpointReads++
        return [pscustomobject]@{ success = ($script:endpointReads -eq 1); detail = 'test callback unavailable' }
    }
    function Open-LoginPage { }
    Assert-Throws { Invoke-Login (New-ContainerFixture) } '等待认证期间本机认证接口不可用'
}
Check 'A stopped or replaced container ends the authentication wait' {
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-LoginEndpoint { return [pscustomobject]@{ success = $true } }
    function Open-LoginPage { }
    function Get-VpnContainer {
        $c = New-ContainerFixture
        $c.State.Running = $false
        $c.State.ExitCode = 137
        return $c
    }
    Assert-Throws { Invoke-Login (New-ContainerFixture) } '退出码 137'
    function Get-VpnContainer {
        $c = New-ContainerFixture
        $c.Id = 'replacement-container'
        return $c
    }
    Assert-Throws { Invoke-Login (New-ContainerFixture) } '被另一个命令替换'
}
Check 'Publication that finishes after the first probe needs no recreation' {
    With-TestRuntime {
        $script:creates = 0
        $script:endpointReads = 0
        function Invoke-Docker { $script:creates++ }
        function Get-VpnContainer { return New-ContainerFixture }
        function Wait-Client { }
        function Start-Sleep { }
        function Test-LoginEndpoint {
            $script:endpointReads++
            return [pscustomobject]@{ success = ($script:endpointReads -gt 1); retryable = $true; detail = 'not published yet' }
        }
        $null = Start-CheckedContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}')
        Assert-True ($script:creates -eq 1 -and $script:endpointReads -eq 2)
    }
}
Check 'A failed new publication is recreated once and then verified' {
    With-TestRuntime {
        $script:creates = 0
        function Invoke-Docker { $script:creates++ }
        function Get-VpnContainer { return New-ContainerFixture }
        function Wait-Client { }
        function Start-Sleep { }
        function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
        function Test-LoginEndpoint {
            return [pscustomobject]@{ success = ($script:creates -eq 2); retryable = $true; detail = 'missing port' }
        }
        $null = Start-CheckedContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}')
        Assert-True ($script:creates -eq 2)
    }
}
Check 'Persistent publication failure is visible and cannot loop through recreations' {
    With-TestRuntime {
        $script:creates = 0
        function Invoke-Docker { $script:creates++ }
        function Get-VpnContainer { return New-ContainerFixture }
        function Wait-Client { }
        function Start-Sleep { }
        function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
        Assert-Throws { Start-CheckedContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}') } '不再自动重建'
        Assert-True ($script:creates -eq 2)
    }
}
Check 'A newly authenticated container is not recreated on callback failure' {
    With-TestRuntime {
        $script:creates = 0
        function Invoke-Docker { $script:creates++ }
        function Get-VpnContainer { return New-ContainerFixture }
        function Wait-Client { }
        function Start-Sleep { }
        function Get-ClientStatus { return [pscustomobject]@{ state = 'online'; detail = '' } }
        Assert-Throws { Start-CheckedContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}') } '不再自动重建'
        Assert-True ($script:creates -eq 1)
    }
}
Check 'Certificate or protocol errors do not trigger a container recreation' {
    With-TestRuntime {
        $script:creates = 0
        function Invoke-Docker { $script:creates++ }
        function Get-VpnContainer { return New-ContainerFixture }
        function Wait-Client { }
        function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
        function Test-LoginEndpoint { return [pscustomobject]@{ success = $false; retryable = $false; detail = 'TrustFailure' } }
        Assert-Throws { Start-CheckedContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}') } 'TrustFailure'
        Assert-True ($script:creates -eq 1)
    }
}
Check 'Status distinguishes a broken callback from a login requirement without SSH configuration' {
    $config = Parse-Config '{"proxy_port":11080,"forwards":[]}'
    function Read-ActiveConfig { return $config }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-Socks { return [pscustomobject]@{ success = $true } }
    $output = @(Show-VpnStatus $config (New-ContainerFixture) 6>&1)
    Assert-True ($output[-1] -eq 1)
    Assert-True (($output -join "`n") -match 'Docker 未成功发布')
    Assert-True (($output -join "`n") -notmatch '请执行 .\\vpn.ps1 login')
    function Test-LoginEndpoint { return [pscustomobject]@{ success = $true } }
    $output = @(Show-VpnStatus $config (New-ContainerFixture) 6>&1)
    Assert-True ($output[-1] -eq 2)
    Assert-True (($output -join "`n") -match '请执行 .\\vpn.ps1 login')
    function Get-ClientStatus { return [pscustomobject]@{ state = 'online'; detail = '' } }
    $output = @(Show-VpnStatus $config (New-ContainerFixture) 6>&1)
    Assert-True ($output[-1] -eq 0)
    Assert-True (($output -join "`n") -match '校内访问：未配置独立检查目标')
}
Check 'An existing running container with a broken callback is never recreated by start' {
    $script:Command = 'start'
    function Assert-Docker { }
    function Get-VpnContainer { return New-ContainerFixture }
    function Read-VpnConfig { return Parse-Config '{"proxy_port":11080,"forwards":[]}' }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Invoke-Docker { throw 'Must not recreate existing container' }
    function Open-LoginPage { throw 'Must not open browser' }
    Assert-Throws { Invoke-VpnMain } '认证接口不可用'
}
Write-Output "All $script:Passed checks passed."
