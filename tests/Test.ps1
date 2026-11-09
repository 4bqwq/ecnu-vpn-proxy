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

# Exercise the real NetworkStream reads without Docker or campus services.
if (-not ('VpnNetworkFixture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

public sealed class VpnNetworkFixture : IDisposable
{
    private readonly TcpListener listener;
    private readonly Thread worker;
    private readonly ManualResetEvent stopped = new ManualResetEvent(false);
    private readonly string scenario;
    private TcpClient connection;
    private Exception failure;
    public int Port { get; private set; }

    public VpnNetworkFixture(string scenario)
    {
        this.scenario = scenario;
        listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Port = ((IPEndPoint)listener.LocalEndpoint).Port;
        worker = new Thread(Serve);
        worker.IsBackground = true;
        worker.Start();
    }

    private static byte[] ReadBytes(NetworkStream stream, int count)
    {
        byte[] bytes = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = stream.Read(bytes, offset, count - offset);
            if (read == 0) throw new IOException("The test client closed its request.");
            offset += read;
        }
        return bytes;
    }

    private static void WriteBytes(NetworkStream stream, byte[] bytes)
    {
        stream.Write(bytes, 0, bytes.Length);
    }

    private void Serve()
    {
        try
        {
            connection = listener.AcceptTcpClient();
            if (stopped.WaitOne(0)) return;
            using (NetworkStream stream = connection.GetStream())
            {
                if (scenario == "ssh-silent") { stopped.WaitOne(); return; }
                if (scenario == "ssh-partial-silent")
                {
                    WriteBytes(stream, Encoding.ASCII.GetBytes("SSH-2.0-"));
                    stopped.WaitOne();
                    return;
                }
                if (scenario == "ssh-close") return;
                if (scenario == "ssh-reset")
                {
                    connection.Client.LingerState = new LingerOption(true, 0);
                    connection.Close();
                    return;
                }
                if (scenario == "ssh-success")
                {
                    WriteBytes(stream, Encoding.ASCII.GetBytes("SSH-2.0-fixture\r\n"));
                    stopped.WaitOne();
                    return;
                }
                if (scenario == "ssh-invalid")
                {
                    WriteBytes(stream, Encoding.ASCII.GetBytes("fixture-response-secret\r\n"));
                    stopped.WaitOne();
                    return;
                }

                byte[] hello = ReadBytes(stream, 3);
                if (hello[0] != 5 || hello[1] != 1 || hello[2] != 0)
                    throw new InvalidOperationException("The SOCKS5 test request was invalid.");
                if (scenario == "socks-hello-silent") { stopped.WaitOne(); return; }
                if (scenario == "socks-hello-eof")
                {
                    WriteBytes(stream, new byte[] { 5 });
                    return;
                }
                if (scenario == "socks-hello-version")
                {
                    WriteBytes(stream, new byte[] { 4, 0 });
                    return;
                }
                WriteBytes(stream, new byte[] { 5, 0 });
                if (scenario == "socks-hello-success") { stopped.WaitOne(); return; }

                byte[] request = ReadBytes(stream, 4);
                if (request[0] != 5 || request[1] != 1 || request[2] != 0 || request[3] != 3)
                    throw new InvalidOperationException("The SOCKS5 target request was invalid.");
                int length = ReadBytes(stream, 1)[0];
                ReadBytes(stream, length + 2);
                if (scenario == "socks-connect-silent") { stopped.WaitOne(); return; }
                if (scenario == "socks-connect-prefix")
                {
                    WriteBytes(stream, new byte[] { 5, 0 });
                    stopped.WaitOne();
                    return;
                }
                if (scenario == "socks-connect-eof")
                {
                    WriteBytes(stream, new byte[] { 5, 0, 0, 1, 127, 0 });
                    return;
                }

                byte[] reply = new byte[] { 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 };
                if (scenario == "socks-refused") reply[1] = 5;
                if (scenario == "socks-connect-version") reply[0] = 4;
                if (scenario == "socks-connect-reserved") reply[2] = 1;
                if (scenario == "socks-connect-address") reply[3] = 9;
                if (scenario == "socks-connect-domain")
                    reply = new byte[] { 5, 0, 0, 3, 3, 118, 112, 110, 0, 0 };
                if (scenario == "socks-connect-ipv6")
                {
                    reply = new byte[22];
                    reply[0] = 5;
                    reply[3] = 4;
                }
                WriteBytes(stream, reply);
                stopped.WaitOne();
            }
        }
        catch (IOException) { }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
        catch (Exception error) { failure = error; }
        finally { if (connection != null) connection.Close(); }
    }

    public void Dispose()
    {
        stopped.Set();
        listener.Stop();
        if (connection != null) connection.Close();
        if (!worker.Join(5000)) throw new InvalidOperationException("The network fixture did not stop.");
        stopped.Dispose();
        if (failure != null) throw new InvalidOperationException("The network fixture failed.", failure);
    }
}
'@
}

function With-NetworkFixture([string]$Scenario, [scriptblock]$Body) {
    $timeout = $script:NetworkTimeout
    $script:NetworkTimeout = 1000
    $server = New-Object VpnNetworkFixture($Scenario)
    try { & $Body $server.Port } finally {
        $script:NetworkTimeout = $timeout
        $server.Dispose()
    }
}

function Assert-NetworkFailure($Result, [string[]]$Patterns) {
    Assert-True (-not $Result.success)
    foreach ($pattern in $Patterns) {
        if ($Result.detail -notmatch $pattern) { throw "Expected network failure pattern '$pattern'." }
    }
    Assert-True ($Result.detail -notmatch '(Read|ReadByte|Wait).*(参数|argument)|fixture-response-secret')
}

Check 'A refused local port identifies the proxy or forwarding endpoint' {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    Assert-NetworkFailure (Test-Socks $port) @('无法连接本机代理', [string]$port, '连接被拒绝')
    $item = [pscustomobject]@{ local_port = $port; ssh_user = 'fixture-user' }
    Assert-NetworkFailure (Test-Forward $item) @('本机转发端口', [string]$port, '连接被拒绝')
}
Check 'An unanswered SOCKS5 greeting identifies the handshake and configured timeout' {
    With-NetworkFixture 'socks-hello-silent' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port) @('代理未回应', '握手', '1 秒')
    }
}
Check 'An unanswered SOCKS5 target request is distinct from the initial handshake' {
    With-NetworkFixture 'socks-connect-silent' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port 'campus.example' 443) @('校内连接检查超时', '代理', '1 秒', '没有回复|未回复')
    }
}
Check 'Partial SOCKS5 replies report both incompleteness and the underlying cause' {
    With-NetworkFixture 'socks-connect-prefix' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port 'campus.example' 443) @('代理回复未接收完整', '读取超时')
    }
    With-NetworkFixture 'socks-connect-eof' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port 'campus.example' 443) @('代理回复未接收完整', '对端关闭')
    }
    With-NetworkFixture 'socks-hello-eof' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port) @('SOCKS5 握手回复未接收完整', '对端关闭')
    }
}
Check 'An explicit SOCKS5 refusal preserves the reply code and describes the target failure' {
    With-NetworkFixture 'socks-refused' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port 'campus.example' 443) @('代理报告目标端口拒绝连接', '响应码 5')
    }
}
Check 'Invalid SOCKS5 versions, reserved bytes and address types are protocol errors' {
    foreach ($scenario in @('socks-connect-version', 'socks-connect-reserved', 'socks-connect-address')) {
        With-NetworkFixture $scenario {
            param($port)
            Assert-NetworkFailure (Test-Socks $port 'campus.example' 443) @('回复格式不正确')
        }
    }
    With-NetworkFixture 'socks-hello-version' {
        param($port)
        Assert-NetworkFailure (Test-Socks $port) @('回复格式不正确')
    }
}
Check 'SSH response timeouts and graceful or reset closes preserve the failing step' {
    foreach ($scenario in @('ssh-silent', 'ssh-partial-silent')) {
        With-NetworkFixture $scenario {
            param($port)
            $item = [pscustomobject]@{ local_port = $port; ssh_user = 'fixture-user' }
            Assert-NetworkFailure (Test-Forward $item) @('SSH 响应超时', '连续 1 秒未收到 SSH 数据')
        }
    }
    foreach ($scenario in @('ssh-close', 'ssh-reset')) {
        With-NetworkFixture $scenario {
            param($port)
            $item = [pscustomobject]@{ local_port = $port; ssh_user = 'fixture-user' }
            Assert-NetworkFailure (Test-Forward $item) @('SSH 响应', '对端关闭')
        }
    }
}
Check 'An invalid SSH response does not echo the received payload' {
    With-NetworkFixture 'ssh-invalid' {
        param($port)
        $item = [pscustomobject]@{ local_port = $port; ssh_user = 'fixture-user' }
        Assert-NetworkFailure (Test-Forward $item) @('SSH')
    }
}
Check 'Valid SOCKS5 replies and SSH banners still pass the real stream checks' {
    With-NetworkFixture 'socks-hello-success' {
        param($port)
        Assert-True ((Test-Socks $port).success)
    }
    foreach ($scenario in @('socks-connect-success', 'socks-connect-domain', 'socks-connect-ipv6')) {
        With-NetworkFixture $scenario {
            param($port)
            Assert-True ((Test-Socks $port 'campus.example' 443).success)
        }
    }
    With-NetworkFixture 'ssh-success' {
        param($port)
        $item = [pscustomobject]@{ local_port = $port; ssh_user = 'fixture-user' }
        $result = Test-Forward $item
        Assert-True ($result.success -and $result.detail -eq '收到 SSH 响应')
    }
}
Check 'Unclassified connection errors retain their underlying reason' {
    function Open-Tcp { throw 'fixture unclassified connection error' }
    Assert-NetworkFailure (Test-Socks 12345) @('fixture unclassified connection error')
    function Open-Tcp {
        $inner = New-Object InvalidOperationException('fixture deepest failure')
        throw (New-Object IO.IOException('fixture wrapper', $inner))
    }
    $result = Test-Socks 12345
    Assert-NetworkFailure $result @('fixture deepest failure')
    Assert-True ($result.detail -notmatch 'fixture wrapper')
}

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
    function Invoke-Docker { param([string[]]$Arguments) return '' }
    # Socket enumeration can omit live listeners on the affected Windows/WSL
    # host. Supply a confirmed owner here; the next check covers no owner.
    function Get-NetTCPConnection {
        return [pscustomobject]@{ LocalPort = $port; LocalAddress = '127.0.0.1'; OwningProcess = $PID }
    }
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = $listener.LocalEndpoint.Port
        $c = Parse-Config ('{"proxy_port":' + $port + ',"forwards":[]}')
        $ownedFixedPorts = [pscustomobject]@{
            Id = 'port-test-container'
            State = [pscustomobject]@{ Running = $true }
            NetworkSettings = [pscustomobject]@{ Ports = [pscustomobject]@{
                '8080/tcp' = @([pscustomobject]@{ HostPort = '18080' })
                '54631/tcp' = @([pscustomobject]@{ HostPort = '54631' })
            } }
        }
        Assert-Throws { Assert-AvailablePorts $c $ownedFixedPorts } ([string]$port)
        $script:Command = 'restart'
        $script:stopAttempted = $false
        function Assert-Docker { }
        function Get-VpnContainer { return $ownedFixedPorts }
        function Read-VpnConfig { return $c }
        function Invoke-Docker { $script:stopAttempted = $true; throw 'Must not stop a working VPN' }
        function Get-PortConflict { return "fixture process (PID $PID)" }
        Assert-Throws { Invoke-VpnMain } "PID $PID"
        Assert-True (-not $script:stopAttempted)
    } finally { $listener.Stop() }
}
Check 'An unconfirmed address conflict reaches Docker and preserves Docker errors' {
    $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $port = $listener.LocalEndpoint.Port
        $c = Parse-Config ('{"proxy_port":' + $port + ',"forwards":[]}')
        $owned = [pscustomobject]@{
            Id = 'port-test-container'
            State = [pscustomobject]@{ Running = $true }
            NetworkSettings = [pscustomobject]@{ Ports = [pscustomobject]@{
                '8080/tcp' = @([pscustomobject]@{ HostPort = '18080' })
                '54631/tcp' = @([pscustomobject]@{ HostPort = '54631' })
            } }
        }
        function Get-PortConflict { return $null }
        $output = @(Assert-AvailablePorts $c $owned 6>&1)
        Assert-True (($output -join "`n") -match '未找到占用者；继续尝试 Docker 启动')
        $script:Command = 'restart'
        $script:dockerStartAttempted = $false
        function Assert-Docker { }
        function Get-VpnContainer { return $owned }
        function Read-VpnConfig { return $c }
        function Invoke-Docker { return '' }
        function Save-ClientConfig { }
        function Write-Runtime { }
        function Start-CheckedContainer { $script:dockerStartAttempted = $true; throw 'Docker bind error fixture' }
        Assert-Throws { Invoke-VpnMain } 'Docker bind error fixture'
        Assert-True $script:dockerStartAttempted
    } finally { $listener.Stop() }
}
Check 'Port conflicts identify the Docker container publishing the host port' {
    function Invoke-Docker {
        param([string[]]$Arguments)
        if ($Arguments[0] -eq 'ps') { return 'abcdef0123456789' }
        return '[{"Id":"abcdef0123456789","Name":"/another-service","NetworkSettings":{"Ports":{"8080/tcp":[{"HostIp":"127.0.0.1","HostPort":"18080"}]}}}]'
    }
    Assert-True ((Get-PortConflict 18080 $null) -match 'another-service.*abcdef012345')
}
Check 'Running container ports do not undergo the exclusive binding check' {
    $c = Parse-Config '{"proxy_port":11080,"forwards":[]}'
    $container = [pscustomobject]@{
        State = [pscustomobject]@{ Running = $true }
        NetworkSettings = [pscustomobject]@{ Ports = [pscustomobject]@{
            '8080/tcp' = @([pscustomobject]@{ HostPort = '18080' })
            '54631/tcp' = @([pscustomobject]@{ HostPort = '54631' })
            '1080/tcp' = @([pscustomobject]@{ HostPort = '11080' })
        } }
    }
    function Get-PortConflict { throw 'Owned ports must not be treated as conflicts' }
    Assert-AvailablePorts $c $container
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
    function Get-VpnContainer { return New-ContainerFixture }
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
        function Restart-PendingContainer { return New-VpnContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}') }
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
        function Restart-PendingContainer { return New-VpnContainer (Parse-Config '{"proxy_port":11080,"forwards":[]}') }
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
    function Get-RecoverySummary { return '等待校园认证；当前不触发数据通道重建。' }
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
function Expired-Endpoint {
    return [pscustomobject]@{ success = $false; retryable = $false; kind = 'certificateExpired'; detail = 'expired' }
}
Check 'Certificate updates finish in the same command and do not open the page early' {
    $script:ready = $false
    $script:pages = 0
    function Get-VpnContainer { return New-ContainerFixture }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-LoginEndpoint {
        if ($script:ready) { return [pscustomobject]@{ success = $true } }
        return Expired-Endpoint
    }
    function Get-CertificateUpdate { return [pscustomobject]@{ state = 'pending' } }
    function Restart-PendingContainer { throw 'Must wait for the current download' }
    function Start-Sleep { $script:ready = $true }
    function Open-LoginPage { $script:pages++; throw 'TEST_LOGIN_PAGE' }
    Assert-Throws { Invoke-Login (New-ContainerFixture) } 'TEST_LOGIN_PAGE'
    Assert-True ($script:ready -and $script:pages -eq 1)
}
Check 'Failed certificate downloads retry with backoff until a subsequent download succeeds' {
    $script:retries = 0
    $script:delays = @()
    function Get-VpnContainer { return New-ContainerFixture }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-LoginEndpoint {
        if ($script:retries -ge 5) { return [pscustomobject]@{ success = $true } }
        return Expired-Endpoint
    }
    function Get-CertificateUpdate { return [pscustomobject]@{ state = 'failed'; reason = 'DOWNLOAD_TIMEOUT' } }
    function Restart-PendingContainer { $script:retries++; return New-ContainerFixture }
    function Start-Sleep { param($Seconds); $script:delays += $Seconds }
    $null = Wait-LoginEndpoint (New-ContainerFixture)
    Assert-True ($script:retries -eq 5 -and ($script:delays -join ',') -eq '5,10,20,30,30')
}
Check 'A delayed successful download cancels the scheduled recreation' {
    $script:ready = $false
    function Get-VpnContainer { return New-ContainerFixture }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-LoginEndpoint {
        if ($script:ready) { return [pscustomobject]@{ success = $true } }
        return Expired-Endpoint
    }
    function Get-CertificateUpdate { return [pscustomobject]@{ state = 'failed'; reason = 'DOWNLOAD_TLS' } }
    function Restart-PendingContainer { throw 'Download has already recovered' }
    function Start-Sleep { $script:ready = $true }
    $null = Wait-LoginEndpoint (New-ContainerFixture)
}
Check 'Authentication completed during a retry protects the existing connection' {
    $script:loggedIn = $false
    function Get-VpnContainer { return New-ContainerFixture }
    function Get-ClientStatus {
        $state = if ($script:loggedIn) { 'online' } else { 'logout' }
        return [pscustomobject]@{ state = $state; detail = '' }
    }
    function Test-LoginEndpoint { return Expired-Endpoint }
    function Get-CertificateUpdate { return [pscustomobject]@{ state = 'failed'; reason = 'DOWNLOAD_TLS' } }
    function Start-Sleep { $script:loggedIn = $true }
    function Invoke-Docker { throw 'An authenticated container must not be stopped' }
    $null = Wait-LoginEndpoint (New-ContainerFixture)
    Assert-True $script:loggedIn
}
Check 'Authentication starting immediately before stop also cancels automatic replacement' {
    $script:authReads = 0
    function Get-VpnContainer { return New-ContainerFixture }
    function Get-ClientStatus {
        $script:authReads++
        $state = if ($script:authReads -eq 1) { 'logout' } else { 'login' }
        return [pscustomobject]@{ state = $state; detail = '' }
    }
    function Read-ActiveConfig { return Parse-Config '{"proxy_port":11080,"forwards":[]}' }
    function Assert-AvailablePorts { }
    function Invoke-Docker { throw 'Authentication is in progress' }
    $null = Restart-PendingContainer (New-ContainerFixture)
    Assert-True ($script:authReads -eq 2)
}
Check 'TLS failures other than expiration never cause certificate replacement' {
    function Get-VpnContainer { return New-ContainerFixture }
    function Test-LoginEndpoint {
        return [pscustomobject]@{ success = $false; retryable = $false; kind = 'certificateInvalid'; detail = 'hostname mismatch' }
    }
    function Restart-PendingContainer { throw 'Must not replace on a hostname mismatch' }
    Assert-Throws { Wait-LoginEndpoint (New-ContainerFixture) } 'hostname mismatch'
}
Check 'A stopped container ends a pending certificate retry instead of restarting it' {
    $script:stopped = $false
    function Get-VpnContainer {
        $c = New-ContainerFixture
        $c.State.Running = -not $script:stopped
        return $c
    }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-LoginEndpoint { return Expired-Endpoint }
    function Get-CertificateUpdate { return [pscustomobject]@{ state = 'failed'; reason = 'DOWNLOAD_TIMEOUT' } }
    function Start-Sleep { $script:stopped = $true }
    function Restart-PendingContainer { throw 'Must respect the stop command' }
    Assert-Throws { Wait-LoginEndpoint (New-ContainerFixture) } '容器已停止'
}
Check 'Legacy configuration is migrated before replacement and a saved copy is preserved' {
    With-TestRuntime {
        $script:copies = 0
        function Invoke-Docker {
            param([string[]]$Arguments)
            Assert-True ($Arguments[0] -eq 'cp' -and $Arguments[1] -match '/var/conf/\.$')
            $script:copies++
            [IO.File]::WriteAllText((Join-Path $Arguments[2] 'certificate'), 'test-cache-' + $script:copies)
        }
        Save-ClientConfig (New-ContainerFixture)
        Save-ClientConfig (New-ContainerFixture)
        $saved = Join-Path $script:Runtime 'state/client-config/certificate'
        Assert-True ((Get-Content -LiteralPath $saved -Raw) -eq 'test-cache-1')
        Assert-True (@(Get-ChildItem -LiteralPath $script:Runtime -Filter 'client-config-migration-*').Count -eq 0)
        $c = New-ContainerFixture
        $c | Add-Member Mounts @([pscustomobject]@{ Destination = '/usr/share/sangfor/.aTrust/var/conf' })
        Save-ClientConfig $c
        Assert-True ($script:copies -eq 2)
    }
}
Check 'Status reports certificate expiration without starting automatic recovery' {
    $config = Parse-Config '{"proxy_port":11080,"forwards":[]}'
    function Read-ActiveConfig { return $config }
    function Get-ClientStatus { return [pscustomobject]@{ state = 'logout'; detail = '' } }
    function Test-Socks { return [pscustomobject]@{ success = $true } }
    function Test-LoginEndpoint { return Expired-Endpoint }
    function Get-CertificateUpdate { throw 'Status must not wait for an update' }
    function Get-RecoverySummary { return '等待校园认证；当前不触发数据通道重建。' }
    function Restart-PendingContainer { throw 'Status must not change the container' }
    $output = @(Show-VpnStatus $config (New-ContainerFixture) 6>&1)
    Assert-True ($output[-1] -eq 1 -and ($output -join "`n") -match '自动更新认证证书')
}
Check 'Certificate log filtering receives an unambiguous UTC container start time' {
    $c = New-ContainerFixture
    $c.State | Add-Member StartedAt ([DateTime]::SpecifyKind([DateTime]'2026-01-02T03:04:05', [DateTimeKind]::Utc))
    function Invoke-Docker {
        param([string[]]$Arguments)
        Assert-True ($Arguments[-1] -eq '2026-01-02T03:04:05.0000000Z')
        return '{"state":"failed","reason":"DOWNLOAD_TIMEOUT"}'
    }
    Assert-True ((Get-CertificateUpdate $c).state -eq 'failed')
}
Check 'Recovery targets reuse private active configuration without SSH account information' {
    With-TestRuntime {
        $config = Parse-Config '{"proxy_port":11080,"check":{"host":"service.example.edu","port":443},"forwards":[{"name":"private-name","host":"192.0.2.10","remote_port":22,"local_port":2222,"ssh_user":"private-user"},{"name":"tcp","host":"192.0.2.11","remote_port":80,"local_port":8080}]}'
        Write-Runtime $config
        $text = Get-Content (Join-Path $script:Runtime 'recovery-targets.json') -Raw
        $targets = ($text | ConvertFrom-Json).targets
        Assert-True ($targets.Count -eq 3 -and $targets[0].port -eq 443 -and -not $targets[0].ssh)
        Assert-True ($targets[1].port -eq 22 -and $targets[1].ssh -and -not $targets[2].ssh)
        Assert-True ($text -notmatch 'private-user|private-name|local_port')
        Write-Runtime (Parse-Config '{"proxy_port":11080,"forwards":[]}')
        $empty = Get-Content (Join-Path $script:Runtime 'recovery-targets.json') -Raw | ConvertFrom-Json
        Assert-True ($empty.targets -is [array] -and $empty.targets.Count -eq 0)
    }
}
Check 'Recovery status is read-only and exposes failures without claiming recovery' {
    function Invoke-Docker {
        param([string[]]$Arguments)
        Assert-True ($Arguments[-2] -eq '/ecnu/recovery.js' -and $Arguments[-1] -eq 'status')
        return '{"state":"recovering","summary":"已请求重建数据通道。"}'
    }
    Assert-True ((Get-RecoverySummary (New-ContainerFixture)) -eq '已请求重建数据通道。')
    function Invoke-Docker { throw 'monitor missing' }
    Assert-True ((Get-RecoverySummary (New-ContainerFixture)) -match '无法读取监控状态：monitor missing')
}
Write-Output "All $script:Passed checks passed."
