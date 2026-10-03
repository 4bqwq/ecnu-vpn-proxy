# ECNU VPN Proxy

在 Docker 中运行学校 aTrust VPN，并通过本机 SOCKS5 代理与 TCP 端口转发，为其他应用提供华东师范大学校园网访问能力。

---

## 快速开始

先按[官方说明](https://docs.docker.com/desktop/setup/install/windows-install/)安装并启动 Docker Desktop，使用 Linux 容器模式。在项目目录打开 PowerShell：

```powershell
.\vpn.ps1 start
```

首次运行时会自动创建个人配置文件 `config.local.json`，下载包含 aTrust 的镜像并启动 VPN 容器。首次下载需要联网，若已有镜像则会直接复用，无需手动下载镜像或安装 aTrust。

如果需要登录：

1. 命令会打开学校 VPN 登录页面；
2. 根据学校页面完成认证；
3. 等终端提示“VPN：已登录（容器内 aTrust 已确认）”，再关闭浏览器页面；
4. 查看运行状态：

```powershell
.\vpn.ps1 status
```

如果网页停留在客户端下载页面，可以点击地址栏左侧的网站信息，将 **Apps on device** 开关打开（**Allow**），再刷新网页。

网页显示登录成功后可能仍需等待终端确认；以容器内 aTrust 的登录状态为准。

登录成功后，本机应用可以通过以下 SOCKS5 地址访问校园网：

```
127.0.0.1:11080
```

如果应用支持代理 DNS 查询，建议使用：

```
socks5h://127.0.0.1:11080
```

例如：

```
curl --proxy socks5h://127.0.0.1:11080 https://xxx
```

---

## 配置端口转发

个人配置位于：

```
config.local.json
```

示例：

```json
{
  "proxy_port": 11080,
  "forwards": [
    {
      "name": "gpu-server",
      "host": "192.0.2.10",
      "remote_port": 22,
      "local_port": 2222,
      "ssh_user": "user"
    }
  ],
  "check": null
}
```

字段说明：

| 字段                       | 说明             |
| ------------------------ | -------------- |
| `proxy_port`             | 本机 SOCKS5 代理端口 |
| `forwards[].name`        | 转发规则名称         |
| `forwards[].host`        | 目标服务器地址        |
| `forwards[].remote_port` | 服务器目标端口        |
| `forwards[].local_port`  | 本机开放端口         |
| `forwards[].ssh_user`    | SSH 用户名（可选）    |
| `check`                  | 可选的校园网连接检查目标   |

例如：

本机 `127.0.0.1:2222`  
通过端口转发连接到  
校园网服务器 `192.0.2.10:22`  

之后可以执行:

`ssh -p 2222 user@127.0.0.1`

如果配置了名称，也可以：

```powershell
.\vpn.ps1 ssh gpu-server
```

端口转发不仅限于 SSH，也可以用于其他 TCP 服务。

多台服务器直接添加多个 `forwards` 项：

```json
{
  "forwards": [
    {
      "name": "server1",
      "host": "xxx",
      "remote_port": 22,
      "local_port": 2222
    },
    {
      "name": "server2",
      "host": "xxx",
      "remote_port": 8080,
      "local_port": 8080
    }
  ]
}
```

修改配置后重新加载：

```powershell
.\vpn.ps1 restart
```

---

## 命令说明

| 命令           | 功能             |
| ------------ | -------------- |
| `start`      | 创建配置并启动 VPN 容器 |
| `restart`    | 重新加载配置并重启容器    |
| `stop`       | 停止容器           |
| `status`     | 查看 VPN、代理和连接状态 |
| `login`      | 打开认证页面并等待 VPN 登录完成；已登录时直接返回 |
| `ssh <name>` | 使用配置中的 SSH 转发  |
| `help`       | 查看帮助           |

---

## 状态检查

`status` 会检查：

* VPN 客户端是否运行；
* 当前登录状态；
* Windows 能否访问本机认证接口（54631）；
* SOCKS5 服务是否可用；
* 配置中的目标连接情况。

示例：

```json
"check": {
  "host": "service.example.edu.cn",
  "port": 443
}
```

执行：

```powershell
.\vpn.ps1 status
```

即可检查该服务是否可以通过校园网访问。

---

## 数据目录

| 路径                               | 用途          |
| -------------------------------- | ----------- |
| `config.example.json`            | 公共配置模板      |
| `config.local.json`              | 个人配置        |
| `.runtime/compose.override.json` | Docker 运行配置 |
| `.runtime/active-config.json`    | 当前生效配置      |
| `.runtime/state/`                | VPN 客户端数据   |
| `.runtime/client.env`            | 远程桌面访问密码    |

---

## 查看官方客户端

日常使用不需要进入客户端桌面。

如需查看容器中的 aTrust：

打开：

```
http://127.0.0.1:18080/
```

登录密码位于：

```
.runtime/client.env
```

中的：

```
PASSWORD=
```

该密码仅用于远程桌面访问，不是校园账号密码。

默认端口：

| 功能     | 端口    |
| ------ | ----- |
| VPN 回调 | 54631 |
| 远程桌面   | 18080 |
