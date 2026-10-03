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
    try {
        # Use the client's certificate hostname; keep normal TLS validation.
        $request = [Net.HttpWebRequest]::Create('https://localhost.sangfor.com.cn:54631/v1/detect')
        $request.Proxy = $null
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
        $cause = $_.Exception
        while ($null -ne $cause.InnerException -and $cause -isnot [Net.WebException]) { $cause = $cause.InnerException }
        $retryable = $false
        $detail = $cause.Message
        if ($cause -is [Net.WebException]) {
            $retryable = $cause.Status.ToString() -in @('ConnectFailure', 'Timeout', 'ConnectionClosed', 'ReceiveFailure', 'SendFailure')
            $reasons = @{
                ConnectFailure = '无法建立连接'; Timeout = '连接或响应超时'
                ConnectionClosed = '连接被关闭'; ReceiveFailure = '接收响应失败'; SendFailure = '发送请求失败'
                NameResolutionFailure = '无法解析本机认证域名'; TrustFailure = 'HTTPS 证书验证失败'
                SecureChannelFailure = '无法建立 HTTPS 连接'
            }
            $reason = $reasons[$cause.Status.ToString()]
            if (-not $reason) { $reason = $cause.Status.ToString() }
            $detail = "Windows 访问认证接口 localhost.sangfor.com.cn:54631 失败：$reason（$($cause.Status)）。"
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
        if (-not $task.Wait($script:NetworkTimeout)) { throw 'TCP 连接超时。' }
        $stream = $client.GetStream()
        $stream.ReadTimeout = $script:NetworkTimeout
        $stream.WriteTimeout = $script:NetworkTimeout
        return $client
    } catch { $client.Dispose(); throw }
}

function Read-Exact($Stream, [int]$Count) {
    $buffer = New-Object byte[] $Count
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -eq 0) { throw '连接在协议响应完成前关闭。' }
        $offset += $read
    }
    return ,$buffer
}

function Test-Socks([int]$Port, [string]$Target = '', [int]$TargetPort = 0) {
    $client = $null
    try {
        $client = Open-Tcp '127.0.0.1' $Port
        $stream = $client.GetStream()
        $hello = [byte[]]@(5, 1, 0)
        $stream.Write($hello, 0, $hello.Length)
        $reply = Read-Exact $stream 2
        if ($reply[0] -ne 5 -or $reply[1] -ne 0) { throw 'SOCKS5 未接受无密码认证。' }
        if ($Target) {
            # ATYP=DOMAIN keeps campus DNS resolution inside the container.
            $address = [Text.Encoding]::ASCII.GetBytes($Target)
            $packet = [byte[]](@(5, 1, 0, 3, $address.Length) + @($address) + @(($TargetPort -shr 8), ($TargetPort -band 255)))
            $stream.Write($packet, 0, $packet.Length)
            $response = Read-Exact $stream 4
            if ($response[0] -ne 5 -or $response[1] -ne 0 -or $response[2] -ne 0) {
                throw "SOCKS5 目标连接失败，响应码 $($response[1])。"
            }
            switch ($response[3]) {
                1 { $null = Read-Exact $stream 4 }
                3 { $length = Read-Exact $stream 1; $null = Read-Exact $stream $length[0] }
                4 { $null = Read-Exact $stream 16 }
                default { throw 'SOCKS5 返回未知地址格式。' }
            }
            $null = Read-Exact $stream 2
        }
        return [pscustomobject]@{ success = $true; detail = '' }
    } catch { return [pscustomobject]@{ success = $false; detail = $_.Exception.Message } }
    finally { if ($null -ne $client) { $client.Dispose() } }
}

function Test-Forward($Item) {
    $client = $null
    try {
        $client = Open-Tcp '127.0.0.1' $Item.local_port
        if ($Item.ssh_user) {
            $stream = $client.GetStream()
            $line = New-Object Text.StringBuilder
            # SSH RFC 4253 limits the identification string to 255 characters.
            while ($line.Length -lt 255) {
                $value = $stream.ReadByte()
                if ($value -lt 0) { throw 'SSH 目标在发送标识前关闭连接。' }
                if ($value -eq 10) {
                    if (-not $line.ToString().StartsWith('SSH-')) { throw '目标未返回 SSH 标识。' }
                    return [pscustomobject]@{ success = $true; detail = '收到 SSH 响应' }
                }
                [void]$line.Append([char]$value)
            }
            throw '目标未返回有效的 SSH 标识。'
        }
        return [pscustomobject]@{ success = $true; detail = '本机转发端口接受连接' }
    } catch { return [pscustomobject]@{ success = $false; detail = $_.Exception.Message } }
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
    if ($Endpoint.retryable) {
        return '请检查本机 54631 的端口占用及 Docker 端口转发，再执行 .\vpn.ps1 restart；此时反复网页登录不能修复认证接口。'
    }
    return '请先解决上述域名、HTTPS 或客户端接口错误，再运行 .\vpn.ps1 status；此时反复网页登录不能修复认证接口。'
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

function Invoke-Login($Container) {
    $auth = Get-ClientStatus $Container
    if ($auth.state -eq 'online') { Write-Host 'VPN：已登录，无需重新认证。'; return }
    if ($auth.state -eq 'unknown') { throw "无法读取客户端状态：$($auth.detail)" }
    if ($auth.state -in @('disconnect', 'networkUnavailable')) {
        throw "VPN：$($script:ClientLabels[$auth.state])。请先检查客户端网络，并运行 .\vpn.ps1 status。"
    }
    $endpoint = Test-LoginEndpoint $Container
    if (-not $endpoint.success) {
        throw "认证接口不可用：$($endpoint.detail)$(Get-LoginEndpointAdvice $endpoint)"
    }
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
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        $null = Invoke-Docker (@(Get-ComposeArguments) + @('up', '-d', '--force-recreate', 'vpn')) -Live
        [IO.File]::WriteAllText((Join-Path $script:Runtime 'active-config.json'), ($Config | ConvertTo-Json -Depth 8), $script:Utf8)
        $container = Get-VpnContainer
        $null = Wait-Client $container
        $current = Get-RunningVpnContainer $container
        $endpoint = Test-LoginEndpoint $current
        if (-not $endpoint.success -and $endpoint.retryable) {
            # Docker Desktop can finish publishing just after the client starts.
            # Confirm a failed probe before considering a single recreation.
            Write-Host "认证接口尚未就绪：$($endpoint.detail)正在再次检查。"
            Start-Sleep -Milliseconds 1000
            $current = Get-RunningVpnContainer $container
            $endpoint = Test-LoginEndpoint $current
        }
        if ($endpoint.success) { return $current }
        $auth = Get-ClientStatus $current
        if ($attempt -eq 0 -and $endpoint.retryable -and $auth.state -eq 'logout') {
            Write-Host "认证接口检查失败：$($endpoint.detail)将重建本次刚启动的未登录容器，重试一次。"
            continue
        }
        throw "认证接口检查失败：$($endpoint.detail)容器已保留，不再自动重建。$(Get-LoginEndpointAdvice $endpoint)"
    }
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
    Write-Runtime $config
    $container = Start-CheckedContainer $config
    Invoke-Login $container
    return Show-VpnStatus $config (Get-VpnContainer)
}

if ($MyInvocation.InvocationName -ne '.') {
    try { $exitCode = Invoke-VpnMain; exit $exitCode }
    catch { Write-Host "错误：$($_.Exception.Message)" -ForegroundColor Red; exit 1 }
}
