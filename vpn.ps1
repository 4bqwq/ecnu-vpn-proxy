[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('start', 'restart', 'stop', 'status', 'login', 'ssh', 'help')]
    [string]$Command = 'status',
    [Parameter(Position = 1)][string]$Name
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$script:ProjectRoot = $PSScriptRoot
$script:Runtime = Join-Path $PSScriptRoot '.runtime'
$script:ConfigPath = Join-Path $PSScriptRoot 'config.local.json'
$script:LoginUrl = 'https://vpn.ecnu.edu.cn'
$script:ClientLabels = @{
    online = '已登录'; logout = '未登录或认证已失效'; login = '认证中'
    offline = '客户端离线'; connect = '连接中'; disconnect = '连接中断'
    networkUnavailable = '网络不可用'; unknown = '无法判断'
}
$script:Utf8 = New-Object System.Text.UTF8Encoding($false)
# A status request is an interactive diagnostic, so individual network
# operations have a five-second deadline. Login itself has no deadline.
$script:NetworkTimeout = 5000

function Get-Field($Object, [string]$Key) {
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Key]) { return $Object.$Key }
    return $null
}

function Assert-Fields($Object, [string[]]$Allowed, [string]$Location) {
    if ($Object -isnot [pscustomobject]) { throw "$Location 必须是 JSON 对象。" }
    foreach ($property in $Object.PSObject.Properties.Name) {
        if ($Allowed -cnotcontains $property) { throw "$Location 包含未知字段 '$property'。" }
    }
}

function Assert-Port($Value, [string]$Location) {
    if (($Value -isnot [int] -and $Value -isnot [long]) -or $Value -lt 1 -or $Value -gt 65535) {
        throw "$Location 必须是 1 到 65535 之间的整数。"
    }
}

function Assert-Target($Value, [string]$Location) {
    if ($Value -isnot [string] -or $Value.Length -gt 253 -or
        $Value -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$' -or
        [Uri]::CheckHostName($Value) -eq [UriHostNameType]::Unknown) {
        throw "$Location 必须是 IPv4 地址或域名，不包含协议、端口或路径。"
    }
}

function ConvertTo-VpnConfig($Value) {
    Assert-Fields $Value @('proxy_port', 'forwards', 'check') '配置'
    $proxyPort = Get-Field $Value 'proxy_port'
    Assert-Port $proxyPort 'proxy_port'
    $ports = @{ 18080 = '远程桌面'; 54631 = '学校认证' }
    if ($ports.ContainsKey([int]$proxyPort)) { throw "proxy_port 与 $($ports[[int]$proxyPort]) 端口重复。" }
    $ports[[int]$proxyPort] = 'SOCKS5'
    $sourceForwards = Get-Field $Value 'forwards'
    if ($null -eq $Value.PSObject.Properties['forwards'] -or $Value.forwards -isnot [array]) {
        throw 'forwards 必须是数组；不需要端口映射时请填写 []。'
    }
    $names = @{}
    $forwards = @()
    foreach ($item in $sourceForwards) {
        $location = "forwards[$($forwards.Count)]"
        Assert-Fields $item @('name', 'host', 'remote_port', 'local_port', 'ssh_user') $location
        $alias = Get-Field $item 'name'
        if ($alias -isnot [string] -or [string]::IsNullOrWhiteSpace($alias) -or $alias -match '[\x00-\x1f\x7f]') {
            throw "$location.name 必须是非空字符串；数字别名也需要加双引号。"
        }
        if ($names.ContainsKey($alias)) { throw "$location.name 与已有别名重复（不区分大小写）。" }
        $names[$alias] = $true
        $target = Get-Field $item 'host'
        Assert-Target $target "$location.host"
        $remotePort = Get-Field $item 'remote_port'
        $localPort = Get-Field $item 'local_port'
        Assert-Port $remotePort "$location.remote_port"
        Assert-Port $localPort "$location.local_port"
        if ($ports.ContainsKey([int]$localPort)) { throw "$location.local_port 与 $($ports[[int]$localPort]) 端口重复。" }
        $ports[[int]$localPort] = $alias
        $user = Get-Field $item 'ssh_user'
        if ($null -ne $user -and ($user -isnot [string] -or $user -notmatch '^[A-Za-z0-9_][A-Za-z0-9_.@\\-]*$')) {
            throw "$location.ssh_user 不是有效的 SSH 用户名。"
        }
        $forwards += [pscustomobject][ordered]@{
            name = $alias; host = $target; remote_port = [int]$remotePort
            local_port = [int]$localPort; ssh_user = $user
        }
    }
    # Upstream reserves 20000 for the browser authentication relay. Keep our
    # internal listeners in 10000-19999, separate from that relay and aTrust.
    if ($forwards.Count -gt 10000) { throw '容器可分配的转发端口（10000–19999）不足。' }
    $check = Get-Field $Value 'check'
    if ($null -ne $check) {
        Assert-Fields $check @('host', 'port') 'check'
        Assert-Target (Get-Field $check 'host') 'check.host'
        Assert-Port (Get-Field $check 'port') 'check.port'
        $check = [pscustomobject][ordered]@{ host = $check.host; port = [int]$check.port }
    }
    return [pscustomobject][ordered]@{ proxy_port = [int]$proxyPort; forwards = @($forwards); check = $check }
}

function Read-VpnConfig([switch]$Create) {
    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        if (-not $Create) { throw '找不到 config.local.json。请先运行 .\vpn.ps1 start 创建默认配置。' }
        Copy-Item -LiteralPath (Join-Path $script:ProjectRoot 'config.example.json') -Destination $script:ConfigPath
        Write-Host '已创建 config.local.json，默认没有服务器映射。'
    }
    try { $value = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json }
    catch { throw 'config.local.json 不是有效的 JSON。请检查引号、逗号和括号；JSON 不支持注释。' }
    return ConvertTo-VpnConfig $value
}

function Get-Hash([string]$Text) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-ConfigHash($Config) { return Get-Hash ($Config | ConvertTo-Json -Depth 8 -Compress) }
function Get-WorkspaceHash { return Get-Hash ([IO.Path]::GetFullPath($script:ProjectRoot).TrimEnd('\', '/').ToLowerInvariant()) }

function Invoke-Docker([string[]]$Arguments, [switch]$Live) {
    # Windows PowerShell treats native stderr as ErrorRecord objects. Docker
    # also uses stderr for successful progress output; its exit code decides.
    $ErrorActionPreference = 'Continue'
    $lines = @(& docker @Arguments 2>&1 | ForEach-Object {
        $line = $_.ToString()
        if ($Live) { Write-Host $line }
        $line
    })
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "Docker 命令失败（$code）：$($lines -join [Environment]::NewLine)" }
    return ($lines -join "`n")
}

function Assert-Docker {
    if (-not (Get-Command docker -CommandType Application -ErrorAction SilentlyContinue)) {
        throw '未找到 Docker CLI。请安装并启动 Docker Desktop。'
    }
    $type = Invoke-Docker @('info', '--format', '{{.OSType}}')
    if ($type.Trim() -ne 'linux') { throw '请将 Docker Desktop 切换到 Linux containers。' }
}

function Get-VpnContainer {
    $ids = Invoke-Docker @('ps', '-aq', '--filter', 'label=com.docker.compose.project=ecnu-proxy', '--filter', 'label=com.docker.compose.service=vpn')
    if ([string]::IsNullOrWhiteSpace($ids)) { return $null }
    $entries = @($ids -split '\s+' | Where-Object { $_ })
    if ($entries.Count -ne 1) { throw '发现多个 ecnu-proxy 服务容器，请先检查 Docker Desktop。' }
    $info = @( (Invoke-Docker @('inspect', $entries[0])) | ConvertFrom-Json )[0]
    $workspace = Get-Field $info.Config.Labels 'io.ecnu-proxy.workspace'
    if ($workspace -ne (Get-WorkspaceHash)) {
        throw 'ecnu-proxy 容器属于另一份项目目录。请从原目录停止它，避免误操作其他部署。'
    }
    return $info
}

function Get-ComposeArguments {
    return @('compose', '--project-directory', $script:ProjectRoot,
        '-f', (Join-Path $script:ProjectRoot 'compose.yaml'),
        '-f', (Join-Path $script:Runtime 'compose.override.json'))
}

function Get-DesiredPorts($Config) {
    return @(18080, 54631, $Config.proxy_port) + @($Config.forwards | ForEach-Object { $_.local_port })
}

function Assert-AvailablePorts($Config, $Container) {
    $owned = @()
    if ($null -ne $Container -and $Container.State.Running) {
        foreach ($binding in $Container.NetworkSettings.Ports.PSObject.Properties) {
            foreach ($endpoint in @($binding.Value)) {
                if ($null -ne $endpoint) { $owned += [int]$endpoint.HostPort }
            }
        }
    }
    foreach ($port in (Get-DesiredPorts $Config)) {
        if ($owned -contains $port) { continue }
        $listener = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        $listener.Server.ExclusiveAddressUse = $true
        try { $listener.Start() }
        catch { throw "本机端口 $port 已被占用或不允许绑定。请释放该端口，或修改私人配置中的对应端口。认证端口 54631 和桌面端口 18080 固定。" }
        finally { $listener.Stop() }
    }
}

function Write-Runtime($Config) {
    [void][IO.Directory]::CreateDirectory((Join-Path $script:Runtime 'state/root'))
    [void][IO.Directory]::CreateDirectory((Join-Path $script:Runtime 'state/user'))
    [void][IO.Directory]::CreateDirectory((Join-Path $script:Runtime 'state/database'))
    [void][IO.Directory]::CreateDirectory((Join-Path $script:Runtime 'state/client-config'))
    $envPath = Join-Path $script:Runtime 'client.env'
    if (-not (Test-Path -LiteralPath $envPath)) {
        $bytes = New-Object byte[] 6
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        [IO.File]::WriteAllText($envPath, ('PASSWORD=' + [Convert]::ToBase64String($bytes) + "`n"), $script:Utf8)
    }
    $ports = @("127.0.0.1:$($Config.proxy_port):1080")
    $rows = @()
    for ($i = 0; $i -lt $Config.forwards.Count; $i++) {
        $item = $Config.forwards[$i]
        $internalPort = 10000 + $i
        $ports += "127.0.0.1:$($item.local_port):$internalPort"
        $rows += "$internalPort`t$($item.host)`t$($item.remote_port)"
    }
    $override = @{ services = @{ vpn = @{
        ports = $ports
        labels = @{
            'io.ecnu-proxy.workspace' = Get-WorkspaceHash
            'io.ecnu-proxy.config' = Get-ConfigHash $Config
        }
    } } }
    [IO.File]::WriteAllText((Join-Path $script:Runtime 'compose.override.json'), ($override | ConvertTo-Json -Depth 8), $script:Utf8)
    $forwardText = if ($rows.Count) { ($rows -join "`n") + "`n" } else { '' }
    [IO.File]::WriteAllText((Join-Path $script:Runtime 'forwards.tsv'), $forwardText, $script:Utf8)
}

function Save-ClientConfig($Container) {
    if ($null -eq $Container) { return }
    $destination = '/usr/share/sangfor/.aTrust/var/conf'
    if (@(Get-Field $Container 'Mounts' | Where-Object { $null -ne $_ -and $_.Destination -eq $destination }).Count -gt 0) { return }
    # Called after stopping the old container, before Compose replaces it.
    # Keep a previously saved file if migration is resumed after interruption.
    $target = Join-Path $script:Runtime 'state/client-config'
    [void][IO.Directory]::CreateDirectory($target)
    $staging = Join-Path $script:Runtime ('client-config-migration-' + [guid]::NewGuid().ToString('N'))
    [void][IO.Directory]::CreateDirectory($staging)
    try {
        $null = Invoke-Docker @('cp', "$($Container.Id):$destination/.", $staging)
        foreach ($item in (Get-ChildItem -LiteralPath $staging -Force)) {
            $saved = Join-Path $target $item.Name
            if (-not (Test-Path -LiteralPath $saved)) { Copy-Item -LiteralPath $item.FullName -Destination $saved -Recurse }
        }
    } finally { Remove-Item -LiteralPath $staging -Recurse -Force }
}

function ConvertFrom-ClientStatus($Response) {
    $code = Get-Field $Response 'code'
    $status = Get-Field $Response 'status'
    if (($code -isnot [int] -and $code -isnot [long]) -or $code -ne 0) {
        $reason = Get-Field $Response 'error'
        if (-not $reason) { $reason = "客户端返回错误或缺少状态码：$code" }
        return [pscustomobject]@{ state = 'unknown'; detail = $reason }
    }
    if (@('online', 'logout', 'login', 'offline', 'connect', 'disconnect', 'networkUnavailable') -cnotcontains $status) {
        return [pscustomobject]@{ state = 'unknown'; detail = '客户端返回了无法识别的状态。' }
    }
    return [pscustomobject]@{ state = $status; detail = '' }
}

function Get-ClientStatus($Container) {
    try {
        $data = Invoke-Docker @('exec', '-e', 'ELECTRON_RUN_AS_NODE=1', $Container.Id,
            '/usr/share/sangfor/aTrust/aTrustTray', '/ecnu/status.js')
        return ConvertFrom-ClientStatus ($data | ConvertFrom-Json)
    } catch {
        return [pscustomobject]@{ state = 'unknown'; detail = $_.Exception.Message }
    }
}

function Assert-LoginDetection($Result) {
    $code = Get-Field $Result 'code'
    # This client returns an empty pubkey on a successful detection. It is
    # not an authentication token and its contents must not decide readiness.
    $key = Get-Field (Get-Field $Result 'data') 'pubkey'
    if (($code -isnot [int] -and $code -isnot [long]) -or $code -ne 0 -or $key -isnot [string]) {
        throw '认证接口未返回有效的 aTrust 检测结果。'
    }
}

function New-LoginCertificateCheck {
    if (-not ('EcnuLoginCertificateCheck' -as [type])) {
        # A .NET callback can run on a worker without a PowerShell runspace.
        # Record validation errors in C# and preserve the normal TLS decision.
        Add-Type -TypeDefinition @'
using System;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public sealed class EcnuLoginCertificateCheck {
    public bool Received;
    public bool Expired;
    public bool NotYetValid;
    public bool NameMismatch;
    public string Errors;
    public string NotAfter;
    public RemoteCertificateValidationCallback Callback { get { return Validate; } }
    public bool Validate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors) {
        Received = true;
        Errors = errors.ToString();
        NameMismatch = (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0;
        if (certificate != null) {
            using (var leaf = new X509Certificate2(certificate)) {
                NotAfter = leaf.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'");
                NotYetValid = leaf.NotBefore.ToUniversalTime() > DateTime.UtcNow;
                bool onlyLeafExpired = chain != null && errors == SslPolicyErrors.RemoteCertificateChainErrors;
                if (chain != null) {
                    foreach (var status in chain.ChainStatus)
                        if (status.Status != X509ChainStatusFlags.NotTimeValid) onlyLeafExpired = false;
                    for (int i = 1; i < chain.ChainElements.Count; i++)
                        if (chain.ChainElements[i].ChainElementStatus.Length != 0) onlyLeafExpired = false;
                }
                Expired = onlyLeafExpired && leaf.NotAfter.ToUniversalTime() < DateTime.UtcNow;
            }
        }
        return errors == SslPolicyErrors.None;
    }
}
'@
    }
    return New-Object EcnuLoginCertificateCheck
}

function Test-LoginEndpoint($Container) {
    # HostConfig only describes the requested ports. Inspect the ports Docker
    # actually published, then make the same read-only detection request as
    # the school page, directly from Windows (without the system proxy).
    $bindings = @(Get-Field $Container.NetworkSettings.Ports '54631/tcp')
    $published = @($bindings | Where-Object {
        $null -ne $_ -and $_.HostIp -eq '127.0.0.1' -and $_.HostPort -eq '54631'
    }).Count -gt 0
    if (-not $published) {
        return [pscustomobject]@{
            success = $false; retryable = $true
            detail = 'Docker 未成功发布本机认证端口 127.0.0.1:54631。'
        }
    }
    $request = $null
    $response = $null
    $reader = $null
    $certificateCheck = New-LoginCertificateCheck
    try {
        # Connect to Docker's loopback binding without a DNS lookup. Host keeps
        # the client's hostname for SNI and normal TLS certificate validation
        # in both Windows PowerShell 5.1 and PowerShell 7.
        $request = [Net.HttpWebRequest]::Create('https://127.0.0.1:54631/v1/detect')
        $request.Host = 'localhost.sangfor.com.cn:54631'
        $request.Proxy = $null
        $request.ServerCertificateValidationCallback = $certificateCheck.Callback
        $request.AllowAutoRedirect = $false
        $request.Timeout = $script:NetworkTimeout
        $request.ReadWriteTimeout = $script:NetworkTimeout
        $request.Method = 'POST'
        $request.ContentType = 'text/plain;charset=UTF-8;application/json'
        $request.Referer = "$script:LoginUrl/portal/"
        $request.Headers['Origin'] = $script:LoginUrl
        $body = [Text.Encoding]::UTF8.GetBytes((@{
            addr = $script:LoginUrl; type = 'web'; guid = ''; lang = 'zh-CN'
            sdpTraceId = ''; token = ''; data = @{}
        } | ConvertTo-Json -Compress))
        $request.ContentLength = $body.Length
        $stream = $request.GetRequestStream()
        try { $stream.Write($body, 0, $body.Length) } finally { $stream.Dispose() }
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw "认证接口返回 HTTP $([int]$response.StatusCode)。" }
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        # Do not log the response: only the result of detection is needed.
        try { $result = $reader.ReadToEnd() | ConvertFrom-Json }
        catch { throw '认证接口未返回有效的 JSON。' }
        Assert-LoginDetection $result
        return [pscustomobject]@{ success = $true; retryable = $false; detail = '' }
    } catch {
        if ($certificateCheck.Expired) {
            return [pscustomobject]@{
                success = $false; retryable = $false; kind = 'certificateExpired'
                detail = "本机认证证书已过期（到期时间：$($certificateCheck.NotAfter)），需要更新证书。"
            }
        }
        if ($certificateCheck.Received -and $certificateCheck.Errors -ne 'None') {
            $reason = '证书信任检查失败'
            if ($certificateCheck.NameMismatch) { $reason = '证书域名与 localhost.sangfor.com.cn 不匹配' }
            elseif ($certificateCheck.NotYetValid) { $reason = '证书尚未生效，需要核对系统时间和证书有效期' }
            return [pscustomobject]@{
                success = $false; retryable = $false; kind = 'certificateInvalid'
                detail = "本机认证接口 HTTPS 校验失败：$reason（$($certificateCheck.Errors)）。"
            }
        }
        $cause = $_.Exception
        while ($null -ne $cause.InnerException -and $cause -isnot [Net.WebException]) { $cause = $cause.InnerException }
        $retryable = $false
        $detail = $cause.Message
        if ($cause -is [Net.WebException]) {
            $retryable = $cause.Status.ToString() -in @('ConnectFailure', 'Timeout', 'ConnectionClosed', 'ReceiveFailure', 'SendFailure')
            $reasons = @{
                ConnectFailure = '无法建立连接'; Timeout = '连接或响应超时'
                ConnectionClosed = '连接被关闭'; ReceiveFailure = '接收响应失败'; SendFailure = '发送请求失败'
                TrustFailure = 'HTTPS 证书验证失败'
                SecureChannelFailure = '无法建立 HTTPS 连接'
            }
            $reason = $reasons[$cause.Status.ToString()]
            if (-not $reason) {
                # UnknownError can wrap a useful socket or TLS exception.
                $inner = $cause
                while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
                $reason = $inner.Message
            }
            $detail = "Windows 访问本机认证接口 127.0.0.1:54631 失败：$reason（$($cause.Status)）。"
            if ($null -ne $cause.Response) {
                $detail = "认证接口返回 HTTP $([int]$cause.Response.StatusCode)。"
                $cause.Response.Dispose()
            }
        }
        return [pscustomobject]@{ success = $false; retryable = $retryable; detail = $detail }
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Abort() }
    }
}

function Open-Tcp([string]$Target, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Target, $Port)
        if (-not $task.Wait($script:NetworkTimeout)) { throw (New-Object TimeoutException('TCP 连接超时。')) }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $script:NetworkTimeout
        $stream.WriteTimeout = $script:NetworkTimeout
        return $client
    } catch { $client.Dispose(); throw }
}

function Read-Exact($Stream, [int]$Count) {
    $buffer = New-Object byte[] $Count
    $offset = 0
    try {
        while ($offset -lt $Count) {
            $read = $Stream.Read($buffer, $offset, $Count - $offset)
            if ($read -eq 0) { throw (New-Object IO.EndOfStreamException('连接被对端关闭。')) }
            $offset += $read
        }
    } catch {
        # Distinguish no reply from a reply that stopped partway through.
        $_.Exception.Data['ecnu-proxy.bytes-read'] = $offset
        throw
    }
    return ,$buffer
}

function Get-NetworkFailure([Exception]$Exception) {
    $cause = $Exception
    $received = 0
    while ($true) {
        if ($cause.Data.Contains('ecnu-proxy.bytes-read')) { $received = [int]$cause.Data['ecnu-proxy.bytes-read'] }
        if ($null -eq $cause.InnerException) { break }
        $cause = $cause.InnerException
    }
    $kind = 'other'
    $reason = $cause.Message
    if ($cause -is [TimeoutException]) {
        $kind = 'timeout'; $reason = '超时'
    } elseif ($cause -is [IO.EndOfStreamException]) {
        $kind = 'closed'; $reason = '连接被对端关闭'
    } elseif ($cause -is [Net.Sockets.SocketException]) {
        switch ($cause.SocketErrorCode.ToString()) {
            'TimedOut' { $kind = 'timeout'; $reason = '超时' }
            # A synchronous NetworkStream read can report WouldBlock when its
            # configured read timeout expires.
            'WouldBlock' { $kind = 'timeout'; $reason = '超时' }
            'ConnectionReset' { $kind = 'closed'; $reason = '连接被对端关闭' }
            'ConnectionAborted' { $kind = 'closed'; $reason = '连接被关闭' }
            'NetworkReset' { $kind = 'closed'; $reason = '连接被关闭' }
            'ConnectionRefused' { $reason = '连接被拒绝' }
            'NetworkUnreachable' { $reason = '网络不可达' }
            'HostUnreachable' { $reason = '目标主机不可达' }
            'HostNotFound' { $reason = '域名无法解析' }
        }
    }
    return [pscustomobject]@{ kind = $kind; reason = $reason; received = $received }
}

function Test-Socks([int]$Port, [string]$Target = '', [int]$TargetPort = 0) {
    $client = $null
    $stage = 'connect'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $client = Open-Tcp '127.0.0.1' $Port
        $stream = $client.GetStream()
        $hello = [byte[]]@(5, 1, 0)
        $stage = 'sendHello'; $timer.Restart()
        $stream.Write($hello, 0, $hello.Length)
        $stage = 'hello'; $timer.Restart()
        $reply = Read-Exact $stream 2
        $stage = 'protocol'
        if ($reply[0] -ne 5) { throw '代理回复格式不正确：SOCKS5 版本不是 5。' }
        if ($reply[1] -ne 0) { throw '代理未接受无密码的 SOCKS5 握手。' }
        if ($Target) {
            # ATYP=DOMAIN keeps campus DNS resolution inside the container.
            $address = [Text.Encoding]::ASCII.GetBytes($Target)
            $packet = [byte[]](@(5, 1, 0, 3, $address.Length) + @($address) + @(($TargetPort -shr 8), ($TargetPort -band 255)))
            $stage = 'sendTarget'; $timer.Restart()
            $stream.Write($packet, 0, $packet.Length)
            $stage = 'target'; $timer.Restart()
            $response = Read-Exact $stream 4
            $stage = 'protocol'
            if ($response[0] -ne 5 -or $response[2] -ne 0) {
                throw '代理回复格式不正确：SOCKS5 版本或保留字段无效。'
            }
            if ($response[1] -ne 0) {
                $reasons = @{
                    1 = '代理处理连接请求失败'; 2 = '代理禁止连接此目标'
                    3 = '代理报告目标网络不可达'; 4 = '代理报告目标主机不可达'
                    5 = '代理报告目标端口拒绝连接'; 6 = '代理报告目标连接的生存时间已耗尽'
                    7 = '代理不支持此连接请求'; 8 = '代理不支持目标地址类型'
                }
                $reason = $reasons[[int]$response[1]]
                if (-not $reason) { $reason = '代理返回未知的目标连接结果' }
                throw "校内连接检查失败：$reason（响应码 $($response[1])）。"
            }
            $stage = 'tail'; $timer.Restart()
            switch ($response[3]) {
                1 { $null = Read-Exact $stream 4 }
                3 { $length = Read-Exact $stream 1; $null = Read-Exact $stream $length[0] }
                4 { $null = Read-Exact $stream 16 }
                default { $stage = 'protocol'; throw '代理回复格式不正确：返回了未知地址类型。' }
            }
            $null = Read-Exact $stream 2
        }
        return [pscustomobject]@{ success = $true; detail = '' }
    } catch {
        $failure = Get-NetworkFailure $_.Exception
        $limit = ($script:NetworkTimeout / 1000.0).ToString('0.###', [Globalization.CultureInfo]::InvariantCulture)
        $readReason = if ($failure.kind -eq 'timeout') { '读取超时' } else { $failure.reason }
        $detail = switch ($stage) {
            'connect' { "无法连接本机代理 127.0.0.1:${Port}：$($failure.reason)。" }
            'sendHello' { "发送 SOCKS5 握手请求失败：$($failure.reason)。" }
            'hello' {
                if ($failure.received -gt 0) { "SOCKS5 握手回复未接收完整：$readReason。" }
                elseif ($failure.kind -eq 'timeout') { "代理未回应：已连接本机端口，但 $limit 秒内未收到 SOCKS5 握手回复。" }
                else { "读取 SOCKS5 握手回复失败：$($failure.reason)。" }
            }
            'sendTarget' { "发送校内连接检查请求失败：$($failure.reason)。" }
            'target' {
                if ($failure.received -gt 0) { "代理回复未接收完整：$readReason。" }
                elseif ($failure.kind -eq 'timeout') { "校内连接检查超时：代理在 $limit 秒内没有回复。" }
                else { "读取校内连接检查结果失败：$($failure.reason)。" }
            }
            'tail' { "代理回复未接收完整：$readReason。" }
            'protocol' { $failure.reason }
        }
        if ($failure.kind -eq 'timeout') {
            $elapsed = $timer.Elapsed.TotalSeconds.ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
            $detail += "（本步骤耗时 $elapsed 秒）"
        }
        return [pscustomobject]@{ success = $false; detail = $detail }
    }
    finally { if ($null -ne $client) { $client.Dispose() } }
}

function Test-Forward($Item) {
    $client = $null
    $stage = 'connect'
    $timer = [Diagnostics.Stopwatch]::StartNew()
    try {
        $client = Open-Tcp '127.0.0.1' $Item.local_port
        if ($Item.ssh_user) {
            $stream = $client.GetStream()
            $line = New-Object Text.StringBuilder
            $stage = 'ssh'; $timer.Restart()
            # SSH RFC 4253 limits the identification string to 255 characters.
            while ($line.Length -lt 255) {
                $value = $stream.ReadByte()
                if ($value -lt 0) { throw (New-Object IO.EndOfStreamException('连接被对端关闭。')) }
                if ($value -eq 10) {
                    $stage = 'protocol'
                    if (-not $line.ToString().StartsWith('SSH-')) { throw '目标未返回 SSH 标识。' }
                    return [pscustomobject]@{ success = $true; detail = '收到 SSH 响应' }
                }
                [void]$line.Append([char]$value)
            }
            $stage = 'protocol'
            throw '目标未返回有效的 SSH 标识。'
        }
        return [pscustomobject]@{ success = $true; detail = '本机转发端口接受连接' }
    } catch {
        $failure = Get-NetworkFailure $_.Exception
        $limit = ($script:NetworkTimeout / 1000.0).ToString('0.###', [Globalization.CultureInfo]::InvariantCulture)
        if ($stage -eq 'connect') {
            $detail = "无法连接本机转发端口 127.0.0.1:$($Item.local_port)：$($failure.reason)。"
        } elseif ($stage -eq 'protocol') { $detail = $failure.reason }
        elseif ($failure.kind -eq 'timeout') {
            $detail = "SSH 响应超时：已连接本机转发端口，但连续 $limit 秒未收到 SSH 数据。"
        } else { $detail = "读取 SSH 响应失败：$($failure.reason)。" }
        if ($failure.kind -eq 'timeout') {
            $elapsed = $timer.Elapsed.TotalSeconds.ToString('0.00', [Globalization.CultureInfo]::InvariantCulture)
            $detail += "（本步骤耗时 $elapsed 秒）"
        }
        return [pscustomobject]@{ success = $false; detail = $detail }
    }
    finally { if ($null -ne $client) { $client.Dispose() } }
}

function Read-ActiveConfig($Container) {
    $activePath = Join-Path $script:Runtime 'active-config.json'
    if (-not (Test-Path -LiteralPath $activePath)) { throw '缺少当前运行配置。请执行 restart 重新建立运行配置。' }
    $active = ConvertTo-VpnConfig (Get-Content -LiteralPath $activePath -Raw -Encoding UTF8 | ConvertFrom-Json)
    $activeHash = Get-Field $Container.Config.Labels 'io.ecnu-proxy.config'
    if ((Get-ConfigHash $active) -ne $activeHash) { throw '当前运行配置与容器不一致。请执行 restart。' }
    return $active
}

function Show-VpnStatus($Config, $Container) {
    if ($null -eq $Container -or -not $Container.State.Running) {
        Write-Host '容器：未运行。请执行 .\vpn.ps1 start。'
        if ($null -ne $Container) {
            Write-Host "上次退出：退出码 $($Container.State.ExitCode)，OOMKilled=$($Container.State.OOMKilled)。详情见 Docker Desktop 中该容器的日志。"
        }
        return 2
    }
    Write-Host '容器：运行中'
    $activeHash = Get-Field $Container.Config.Labels 'io.ecnu-proxy.config'
    if ($activeHash -ne (Get-ConfigHash $Config)) {
        Write-Host '配置：已修改但尚未应用；下面检查当前运行配置。执行 restart 应用修改。'
    }
    $active = Read-ActiveConfig $Container
    $auth = Get-ClientStatus $Container
    Write-Host "VPN：$($script:ClientLabels[$auth.state])"
    if ($auth.state -eq 'unknown') { Write-Host "原因：$($auth.detail)" }
    $endpoint = Test-LoginEndpoint $Container
    if ($endpoint.success) {
        Write-Host '认证接口：Windows 可直接访问本机 54631；浏览器仍需允许本站的 Apps on device 权限。'
    } else {
        Write-Host "认证接口：检查失败；$($endpoint.detail)"
        Write-Host (Get-LoginEndpointAdvice $endpoint)
    }
    if ($endpoint.success -and $auth.state -in @('logout', 'offline')) {
        Write-Host '请执行 .\vpn.ps1 login，在学校网页完成认证。'
    }
    $proxy = Test-Socks $active.proxy_port
    if ($proxy.success) { Write-Host "SOCKS5：协议检查通过，127.0.0.1:$($active.proxy_port)" }
    else { Write-Host "SOCKS5：检查失败；$($proxy.detail)" }
    $failed = -not $proxy.success -or -not $endpoint.success
    if ($null -eq $active.check) {
        Write-Host '校内访问：未配置独立检查目标。'
    } elseif ($auth.state -ne 'online' -or -not $proxy.success) {
        Write-Host '校内访问：尚未检查，需客户端已登录且代理可响应。'
    } else {
        $checked = Test-Socks $active.proxy_port $active.check.host $active.check.port
        if ($checked.success) { Write-Host '校内访问：通过代理连接检查目标成功。' }
        else { Write-Host "校内访问：目标连接失败；$($checked.detail)"; $failed = $true }
    }
    if ($active.forwards.Count -eq 0) { Write-Host '端口映射：未配置。' }
    foreach ($item in $active.forwards) {
        if ($auth.state -ne 'online' -or -not $proxy.success) {
            Write-Host "映射 $($item.name)：127.0.0.1:$($item.local_port)，尚未检查目标。"
            continue
        }
        $target = Test-Socks $active.proxy_port $item.host $item.remote_port
        $forward = Test-Forward $item
        if ($target.success -and $forward.success) {
            Write-Host "映射 $($item.name)：127.0.0.1:$($item.local_port)，目标 TCP 可达；$($forward.detail)。"
        } else {
            $failed = $true
            Write-Host "映射 $($item.name)：连接检查失败；目标：$($target.detail)；转发：$($forward.detail)"
        }
    }
    if ($auth.state -eq 'unknown' -or $failed) { return 1 }
    if ($auth.state -ne 'online') { return 2 }
    return 0
}

function Open-LoginPage {
    Write-Host "学校认证：$script:LoginUrl"
    try { Start-Process $script:LoginUrl -ErrorAction Stop | Out-Null }
    catch { Write-Host "浏览器未能自动打开，请手动访问以上网址。原因：$($_.Exception.Message)" }
    Write-Host '若停在下载客户端页面：点地址栏左侧的网站信息，允许 Apps on device（Allow），再刷新网页。'
    Write-Host '等待容器内 aTrust 确认登录；Ctrl+C 可结束等待，容器会保留运行。'
}

function Get-LoginEndpointAdvice($Endpoint) {
    if ((Get-Field $Endpoint 'kind') -eq 'certificateExpired') {
        return 'start 或 login 会自动更新认证证书；status 只检查当前情况。'
    }
    if ($Endpoint.retryable) {
        return '请检查本机 54631 的端口占用及 Docker 端口转发，再执行 .\vpn.ps1 restart；此时反复网页登录不能修复认证接口。'
    }
    return '认证接口尚未通过 HTTPS 或协议检查，学校网页暂时无法把认证交给客户端。'
}

function Get-RunningVpnContainer($Expected) {
    $current = Get-VpnContainer
    if ($null -eq $current -or -not $current.State.Running) {
        $detail = if ($null -ne $current) { "退出码 $($current.State.ExitCode)，OOMKilled=$($current.State.OOMKilled)。" } else { '' }
        throw "容器已停止。${detail}请检查 Docker Desktop 中该容器的日志，再执行 .\vpn.ps1 start。"
    }
    if ($null -ne $Expected -and $current.Id -ne $Expected.Id) {
        throw '容器已被另一个命令替换，本次等待已停止。请执行 .\vpn.ps1 status 检查。'
    }
    return $current
}

function Wait-Client($Container) {
    Write-Host '等待 aTrust 启动；Ctrl+C 可结束等待，容器会保留运行。'
    while ($true) {
        $current = Get-RunningVpnContainer $Container
        $auth = Get-ClientStatus $current
        if ($auth.state -ne 'unknown') { return $auth }
        if ($auth.detail -notmatch 'ECONNREFUSED|ECONNRESET|TIMEOUT') { throw "无法读取客户端状态：$($auth.detail)" }
        Start-Sleep -Milliseconds 1000
    }
}

function Get-CertificateUpdate($Container) {
    $startedAt = $Container.State.StartedAt
    if ($startedAt -is [datetime]) { $startedAt = $startedAt.ToUniversalTime().ToString('o') }
    $data = Invoke-Docker @('exec', '-e', 'ELECTRON_RUN_AS_NODE=1', $Container.Id,
        '/usr/share/sangfor/aTrust/aTrustTray', '/ecnu/status.js', 'certificate-update', [string]$startedAt)
    $update = $data | ConvertFrom-Json
    if ((Get-Field $update 'state') -notin @('pending', 'ready', 'failed', 'unknown')) {
        throw '无法识别客户端的证书更新状态。'
    }
    return $update
}

function Get-CertificateUpdateReason($Update) {
    $reasons = @{
        DOWNLOAD_TIMEOUT = '下载超时'; DOWNLOAD_TLS = '下载服务器的 HTTPS 连接失败'
        DOWNLOAD_DNS = '无法解析证书下载地址'; DOWNLOAD_CONNECT = '无法连接证书下载服务器'
        DOWNLOADED_CERTIFICATE_EXPIRED = '下载的证书不在有效期内'; UPDATE_FAILED = '客户端证书更新失败'
        NO_UPDATE_EVENT = '暂未读取到本次客户端的证书更新结果'
    }
    $reason = $reasons[[string](Get-Field $Update 'reason')]
    if (-not $reason) { throw '客户端证书更新状态缺少可识别的原因。' }
    return $reason
}

function New-VpnContainer($Config) {
    $null = Invoke-Docker (@(Get-ComposeArguments) + @('up', '-d', '--force-recreate', 'vpn')) -Live
    [IO.File]::WriteAllText((Join-Path $script:Runtime 'active-config.json'), ($Config | ConvertTo-Json -Depth 8), $script:Utf8)
    $container = Get-VpnContainer
    $null = Wait-Client $container
    return Get-RunningVpnContainer $container
}

function Restart-PendingContainer($Container) {
    $current = Get-RunningVpnContainer $Container
    # A user may finish authenticating while the retry delay is running.
    # Only the explicitly logged-out state permits automatic replacement.
    $auth = Get-ClientStatus $current
    if ($auth.state -ne 'logout') { return $current }
    $config = Read-ActiveConfig $current
    Assert-AvailablePorts $config $current
    $current = Get-RunningVpnContainer $current
    if ((Get-ClientStatus $current).state -ne 'logout') { return $current }
    $null = Invoke-Docker @('stop', $current.Id)
    Save-ClientConfig $current
    Write-Runtime $config
    return New-VpnContainer $config
}

function Wait-LoginEndpoint($Container, [switch]$NewContainer) {
    $current = $Container
    $publicationRetries = 0
    $certificateWait = $false
    $retryDelay = 5
    $lastNotice = ''
    while ($true) {
        $current = Get-RunningVpnContainer $current
        $endpoint = Test-LoginEndpoint $current
        if ($endpoint.success) {
            if ($certificateWait) { Write-Host '认证证书更新完成，Windows HTTPS 检查通过。' }
            return $current
        }
        if ((Get-Field $endpoint 'kind') -eq 'certificateExpired') {
            $auth = Get-ClientStatus $current
            if ($auth.state -eq 'online') {
                Write-Host 'VPN 已登录；认证证书已过期，本次保留现有连接。'
                return $current
            }
            if ($auth.state -eq 'unknown') { throw "无法读取客户端状态：$($auth.detail)" }
            if (-not $certificateWait) {
                Write-Host '本机认证证书已过期，正在等待 aTrust 更新；Ctrl+C 可结束等待，容器和数据会保留。'
                $certificateWait = $true
            }
            $update = Get-CertificateUpdate $current
            if ($update.state -eq 'failed' -and $auth.state -eq 'logout') {
                $reason = Get-CertificateUpdateReason $update
                Write-Host "证书更新失败：$reason。将在 $retryDelay 秒后自动重试。"
                Start-Sleep -Seconds $retryDelay
                $current = Get-RunningVpnContainer $current
                # Recheck both the endpoint and the updater after waiting:
                # a delayed official update may already have recovered.
                $latest = Test-LoginEndpoint $current
                if ($latest.success) { continue }
                if ((Get-Field $latest 'kind') -ne 'certificateExpired') {
                    throw "认证接口不可用：$($latest.detail)"
                }
                if ((Get-CertificateUpdate $current).state -ne 'failed') { continue }
                Write-Host '正在重试证书更新；仅重新启动本项目尚未登录的客户端。'
                $current = Restart-PendingContainer $current
                $NewContainer = $true
                $retryDelay = [Math]::Min(30, $retryDelay * 2)
                $lastNotice = ''
                continue
            }
            if ($update.state -eq 'unknown') {
                $notice = Get-CertificateUpdateReason $update
                if ($notice -ne $lastNotice) { Write-Host "$notice，继续等待。"; $lastNotice = $notice }
            }
            Start-Sleep -Seconds 2
            continue
        }
        # Preserve the existing single retry for a newly published Docker
        # port. Other TLS/protocol errors never trigger certificate retries.
        if ($NewContainer -and $endpoint.retryable) {
            Write-Host "认证接口尚未就绪：$($endpoint.detail)正在再次检查。"
            Start-Sleep -Milliseconds 1000
            $current = Get-RunningVpnContainer $current
            $endpoint = Test-LoginEndpoint $current
            if ($endpoint.success) { return $current }
            if ((Get-Field $endpoint 'kind') -eq 'certificateExpired') { continue }
            if ($endpoint.retryable -and $publicationRetries -eq 0 -and (Get-ClientStatus $current).state -eq 'logout') {
                $publicationRetries++
                Write-Host '本次启动的认证端口仍不可用，将重建未登录容器重试一次。'
                $current = Restart-PendingContainer $current
                continue
            }
        }
        throw "认证接口不可用：$($endpoint.detail)容器已保留，不再自动重建。$(Get-LoginEndpointAdvice $endpoint)"
    }
}

function Invoke-Login($Container) {
    $auth = Get-ClientStatus $Container
    if ($auth.state -eq 'online') { Write-Host 'VPN：已登录，无需重新认证。'; return }
    if ($auth.state -eq 'unknown') { throw "无法读取客户端状态：$($auth.detail)" }
    if ($auth.state -in @('disconnect', 'networkUnavailable')) {
        throw "VPN：$($script:ClientLabels[$auth.state])。请先检查客户端网络，并运行 .\vpn.ps1 status。"
    }
    $Container = Wait-LoginEndpoint $Container
    if ((Get-ClientStatus $Container).state -eq 'online') { Write-Host 'VPN：已登录，无需重新认证。'; return }
    Open-LoginPage
    $previous = ''
    while ($true) {
        $current = Get-RunningVpnContainer $Container
        $auth = Get-ClientStatus $current
        if ($auth.state -eq 'online') {
            Write-Host 'VPN：已登录（容器内 aTrust 已确认）。现在可以关闭学校网页，请勿点击“退出登录”。'
            return
        }
        if ($auth.state -eq 'unknown') { throw "无法读取客户端状态：$($auth.detail)" }
        if ($auth.state -in @('disconnect', 'networkUnavailable')) {
            throw "VPN：$($script:ClientLabels[$auth.state])。请检查客户端网络，并运行 .\vpn.ps1 status。"
        }
        $endpoint = Test-LoginEndpoint $current
        if (-not $endpoint.success) { throw "等待认证期间本机认证接口不可用：$($endpoint.detail)请执行 .\vpn.ps1 status 检查。" }
        if ($auth.state -ne $previous) {
            Write-Host "VPN：$($script:ClientLabels[$auth.state])；继续等待容器确认登录。"
            $previous = $auth.state
        }
        Start-Sleep -Milliseconds 2000
    }
}

function Start-CheckedContainer($Config) {
    $container = New-VpnContainer $Config
    return Wait-LoginEndpoint $container -NewContainer
}

function Invoke-VpnMain {
    if ($Command -eq 'help') {
        Write-Host '用法：.\vpn.ps1 start | restart | stop | status | login | ssh <别名>'
        Write-Host '私人配置：config.local.json。配置字段及认证说明见 README.md。'
        return 0
    }
    Assert-Docker
    $container = Get-VpnContainer
    if ($Command -eq 'stop') {
        if ($null -eq $container) { Write-Host '容器：未创建，无需停止。'; return 0 }
        $null = Invoke-Docker @('stop', $container.Id) -Live
        Write-Host '容器已停止，私人配置与客户端数据保留。'
        return 0
    }
    $config = Read-VpnConfig -Create:($Command -in @('start', 'restart'))
    switch ($Command) {
        'status' { return Show-VpnStatus $config $container }
        'login' {
            if ($null -eq $container -or -not $container.State.Running) { throw '请先执行 .\vpn.ps1 start。' }
            Invoke-Login $container
            return 0
        }
        'ssh' {
            if (-not $Name) { throw '请提供私人服务器别名：.\vpn.ps1 ssh <别名>。' }
            if ($null -eq $container -or -not $container.State.Running) { throw '请先执行 .\vpn.ps1 start。' }
            $active = Read-ActiveConfig $container
            $items = @($active.forwards | Where-Object { $_.name -eq $Name })
            if ($items.Count -ne 1) { throw '当前运行配置没有该别名。修改配置后请执行 restart。' }
            $item = $items[0]
            if (-not $item.ssh_user) { throw '该映射未配置 ssh_user。请填写用户名，或使用原生 ssh 命令自行指定用户名。' }
            $auth = Get-ClientStatus $container
            if ($auth.state -ne 'online') { throw "VPN 尚未确认已登录（$($auth.state)）。请先运行 status 检查。" }
            if (-not (Get-Command ssh -CommandType Application -ErrorAction SilentlyContinue)) { throw '未找到 Windows OpenSSH 客户端；也可以使用其他 SSH 软件连接该映射端口。' }
            & ssh -p $item.local_port -l $item.ssh_user 127.0.0.1
            return $LASTEXITCODE
        }
    }
    if ($Command -eq 'start' -and $null -ne $container -and $container.State.Running) {
        Invoke-Login $container
        return Show-VpnStatus $config (Get-VpnContainer)
    }
    Assert-AvailablePorts $config $container
    # Validate before stopping a working container. Generated bind-mounted
    # files are changed only after the old processes have stopped.
    if ($null -ne $container -and $container.State.Running) {
        $null = Invoke-Docker @('stop', $container.Id) -Live
    }
    Save-ClientConfig $container
    Write-Runtime $config
    $container = Start-CheckedContainer $config
    Invoke-Login $container
    return Show-VpnStatus $config (Get-VpnContainer)
}

if ($MyInvocation.InvocationName -ne '.') {
    try { $exitCode = Invoke-VpnMain; exit $exitCode }
    catch { Write-Host "错误：$($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}
