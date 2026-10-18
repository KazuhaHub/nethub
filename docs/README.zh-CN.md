# NetHub

> 本文是 [`README.md`](../README.md) 的中文版。两者不一致时，以英文版为准。

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Stars](https://img.shields.io/github/stars/KazuhaHub/nethub?style=social)

面向开源路由器和防火墙的自托管远程访问与设备管理工具。首先支持 OPNsense，架构上为 OpenWrt 和 VyOS 留了位置。

**状态：pre-alpha，W2 隧道集成。** W0 实测已接受，OPNsense 开发插件已通过隧道、恢复、定时任务生命周期及共存验证。
设备加入和控制面尚未实现。使用开发文件前，请先看[项目状态](#项目状态)。

**自己部署之前，你需要：**

- 一个能自己管理 DNS 的域名；
- 一条**泛解析记录**（`*.router.example.com` → 中继服务器的公网 IP）；
- 一台能从公网访问的中继服务器，开放 **443**、**7000**、**8443** 三个端口。

没有托管版，也没有绕过这些前提的捷径。完整清单见[部署前提](#部署前提)。

## 目录

- [v1 打算做什么](#v1-打算做什么)
- [v1 不做什么](#v1-不做什么)
- [为什么不用 Tailscale、Cloudflare Tunnel，或者直接暴露 Web 界面](#为什么不用-tailscalecloudflare-tunnel或者直接暴露-web-界面)
- [工作原理](#工作原理)
- [仓库结构](#仓库结构)
- [部署前提](#部署前提)
- [快速开始（尚不可用）](#快速开始尚不可用)
- [安全模型](#安全模型)
- [项目状态](#项目状态)
- [路线图](#路线图)
- [许可证](#许可证)
- [参与贡献](#参与贡献)

## v1 打算做什么

下面的功能都还不存在，这是 v1 的计划范围。

- 让一台在 CGNAT 或动态 IP 后面的 OPNsense 拥有一个稳定可用的 Web 管理界面地址：不用做端口转发，不用折腾动态 DNS，你的电脑上也不用装 VPN 客户端。
- 用一次性 token 让设备加入（enroll），给它分配一个随机的专属子域名（例如 `abcd1234.router.example.com`），并保持一条从设备到你自己中继的长连接隧道。
- 在控制台里显示设备在线/离线状态和基本的连接信息。
- 控制台支持多个用户：`admin` 和 `member` 两种角色，只能通过邀请加入；可以用本地密码登录，也可以用 OIDC 登录（可以配置多个身份提供方）。

这就是 v1 的计划范围。v1 的最终功能清单还有待确认。

## v1 不做什么

- **不做配置管理。** 控制面不能读设备的 `config.xml`，不能改防火墙规则，也不能重启服务。这不是疏忽，而是有意划定的 v1 边界，见下面的[安全模型](#安全模型)。
- **不做批量运维。** 没有批量升级、定时任务，也没有全网配置下发。
- **不做遥测。** 不采集指标，没有监控面板，除了"隧道是否在线"之外不做告警。
- **不支持 OpenWrt 和 VyOS。** 目录结构和协议设计上不绑定单一平台，但 v1 只面向 OPNsense。

如果你要的是一个批量管理设备配置的工具，那在[路线图](#路线图)里，不在 v1。

## 为什么不用 Tailscale、Cloudflare Tunnel，或者直接暴露 Web 界面

问得好。对大多数人来说，老实的回答是：用 Tailscale。

- **Tailscale** 更容易上手，不需要自己运行服务器，跨 NAT 也能直接用。如果你只有一台或几台设备，也不介意连接路径上有第三方的协调服务，就用 Tailscale。NetHub 不打算在方便程度上和它比。
- **Cloudflare Tunnel** 也是类似的取舍：不用自己维护基础设施，背后是 Cloudflare 的边缘网络。同样要注意：连接路径、以及一定程度上的身份认证，都交给了 Cloudflare。
- **直接把 OPNsense 的 Web 界面暴露到公网**（端口转发或其他方式）：Tailscale 和 Cloudflare Tunnel 存在的意义，就是帮你避开这个风险，而 NetHub **并不是**绕开它的办法。
  按照设计，NetHub 同样会让设备自己的登录页可以经由你的中继从公网访问到（见[设备 Web 界面的暴露面](#设备-web-界面的暴露面)）。
  NetHub 省掉的是"在设备所在网络上做入站端口转发"这一步（在 CGNAT 下往往本来就做不到），而不是暴露面本身。
  如果你不能接受 OPNsense 登录页能从公网访问，请用 Tailscale。

NetHub 适合一个更窄的场景，同时满足下面三点：

- 你想**完全掌握中继**：自己部署，跑在你能控制的基础设施上，中间没有第三方协调服务；
- 你要管理**不止一台设备**；
- 你预期以后要做**配置备份和下发**，不想到时候再换工具。

三点都不符合的话，NetHub 对你来说是多余的基础设施，直接装 Tailscale 吧。

## 工作原理

下面描述的是设计好的架构（设计 v0.3），都还没有实现。

```
             SNI = abcd1234.router.example.com                    frp 隧道
                     （TLS 端到端一直到设备）                   （每台设备一条，长连接）

+-----------+          +----------------------------+          +------------------------+
|  浏览器   |  HTTPS   |         frps :8443         |  :7000   |   插件自带的 frpc      |
|           | ───────► |      (vhostHTTPSPort)      | ───────► |    -> 127.0.0.1:443    |
|           | ◄─────── |      只做 SNI 透传         | ◄─────── | （OPNsense Web 界面）  |
+-----------+          +----------------------------+          +------------------------+
                                      │  Login / NewProxy 校验
                                      ▼  （httpPlugins，内部网络）
                  +--------------------------------------+
                  |           Go control plane           |
                  |      nethub web + nethub authz       |
                  |     behind Caddy :443 + Postgres     |
                  +--------------------------------------+
            控制台、enroll、设备身份、状态（不在 Web 界面的数据路径上）
```

- 每台加入的设备都会得到一个由服务端随机分配的子域名，例如 `abcd1234.router.example.com`，通过你自己的泛解析记录指向中继的 IP。
- 设备上的 `frpc` 主动连接 `frps` 的 **7000** 端口（TLS），并保持这条控制通道。访问这台设备子域名的浏览器流量从 **8443** 端口进来，经由设备主动建立的隧道送到设备上。
- 中继上的 `frps` 接收 TCP 连接，但只读取 TLS ClientHello 里的 **SNI** 字段，用它决定把字节转发给哪台设备的隧道——它从不解密连接。
- 因为没有任何环节解密、终止或改写流量，OPNsense 由 PHP 渲染的页面和内嵌的 JS 会原封不动地到达你的浏览器。不存在会破坏相对路径的路径前缀改写，也不需要一层代理去跟着 OPNsense 前端的每次改动调整。
- 控制面是一个 Go 二进制 `nethub`，以两种角色运行：`nethub web`（控制台）和 `nethub authz`（设备 API 和 `frps` 插件接口），后面是 Postgres，前面是监听 **443** 端口的 Caddy。
  `frps` 在每台设备登录、注册代理时，都会请 `nethub authz` 审批。控制面负责控制台、enroll、设备身份和状态，但**不在** Web 界面流量的数据路径上——这正是整个设计的要点。

## 仓库结构

```
proto/            协议定义（JSON Schema），平台中立，唯一事实来源
server/           控制面：Go，一个二进制 `nethub`（web | authz | migrate | init | doctor）
  web/              控制台源码：React + TypeScript + Vite（构建产物嵌入二进制）
agents/opnsense/  OPNsense agent：os-nethub-agent 插件源码（PHP MVC、rc.d、agentctl.py）
deploy/           docker-compose、Caddy 配置、按服务划分的密钥目录
docs/             DESIGN.md（v0.3，中文）、威胁模型与控制台 API（草案）、中文 README
weekend0/         Weekend 0 传输层测试工具（RUNBOOK、frps/frpc 配置、probe.py）
```

这是计划中的结构。目前仓库里只有文档和 Weekend 0 测试工具，没有代码。

NetHub 的全部源码都在这个仓库里，包括 `agents/opnsense/plugin/` 下的 OPNsense 插件源码。FreeBSD 软件包在别处**构建**：
[`KKazuhaK/OPNsense-repo`](https://github.com/KKazuhaK/OPNsense-repo) 将会放一份打包配方：拉取打了 tag 的 NetHub release、校验 checksum，
再交给现成的 FreeBSD 构建、签名、发布流水线——和它现在打包 sing-box、frp 的方式一样。从那个仓库的角度看，NetHub 只是又一个上游项目。
详见 [`CONTRIBUTING.md`](../CONTRIBUTING.md#license-and-repository-layout)。

## 部署前提

自己部署 NetHub，需要事先具备：

1. **一个域名**，你能管理它的 DNS。
2. **一条泛解析记录**：`*.router.example.com` → 中继服务器的公网 IP（例如 `203.0.113.10`）。
3. **一台能从公网访问的中继服务器**，开放三个端口：
   - **443**：Caddy，提供 Web 控制台和设备 enroll 接口；
   - **7000**：`frps` 的 `bindPort`，设备的控制通道（TLS）；
   - **8443**：`frps` 的 `vhostHTTPSPort`，浏览器到设备，SNI 透传。

   其他组件（`frps` 的 admin API、`nethub authz` 的插件接口、Postgres）都只在内部 Docker 网络里，不对外发布。
4. 这台服务器上装好 **Docker 和 Docker Compose**。

没有托管版。如果你不想自己运行服务器，请看上面的[为什么不用 Tailscale、Cloudflare Tunnel，或者直接暴露 Web 界面](#为什么不用-tailscalecloudflare-tunnel或者直接暴露-web-界面)。

## 快速开始（尚不可用）

> **注意：下面的命令还不存在。** NetHub 处于 pre-alpha（见[项目状态](#项目状态)）。下面描述的是计划中的 v1 流程，让你知道"做完是什么样子"；
> `nethub init` 和控制台尚未实现，已有插件只用于隔离开发测试。

| 步骤 | 做什么 | 时间 |
|---|---|---|
| 1 | `nethub init`：询问你的域名，在本地生成全部密钥并按服务写成单独的文件，提示你备份，创建首个管理员（本地密码），运行预检 | 约 2 分钟 |
| 2 | `docker compose up -d`：启动 `nethub web`、`nethub authz`、Postgres、Caddy、`frps`（以及一个备份任务） | 约 2 分钟 |
| 3 | 以首个管理员登录控制台；可以添加 OIDC 提供方、邀请其他用户 | 约 1 分钟 |
| 4 | 新建一台设备，复制一次性 enroll token（15 分钟后过期） | 约 1 分钟 |
| 5 | 在 OPNsense 上安装 NetHub agent 插件，在它的页面里粘贴 token | 约 3 分钟 |
| 6 | 设备完成 enroll，隧道建立，状态变成在线 | 约 1 分钟 |
| 7 | 在控制台的设备列表里点"打开"，看到 OPNsense 登录页（仍然要用 OPNsense 自己的账号登录） | — |

**合计约 10 分钟**，大部分时间花在安装插件上。

## 安全模型

v1 在设计上要保证的几件事：

- **控制面不能读取或修改设备配置。** 这是架构上的，不是政策承诺：设计里不存在从控制面通往 `config.xml`、防火墙规则或服务重启的路径。
- **enroll token 一次性使用，15 分钟后过期。**
- **设备身份是 enroll 时签发的域名归属签名声明**（HMAC-SHA256）。设备的 `frpc` 登录或注册代理时，`frps` 会询问 `nethub authz`，由它同时检查签名有效**并且**与数据库记录一致——两道独立的检查，而不是一道。
- **签名密钥只在 `nethub authz` 里。** 公网控制台 `nethub web` 是另一个进程，使用自己的数据库角色。它从不持有签名密钥和 `frps` 的管理凭证，不能新建设备记录，也不能写子域名和声明字段。
  所以即使控制台被完全攻破，也无法为一台已有设备签出有效声明，也无法改变子域名的归属。
  不过它**仍然**可以：生成 enroll token（以一个新子域名加入一台新设备）、撤销设备、读取设备元数据和审计日志、管理用户和登录提供方——也就是接管整个控制台。完整的边界见 [`DESIGN.md`](DESIGN.md) §6。
- **控制台登录方式是本地密码或 OIDC。** `nethub init` 用本地密码（argon2id）创建首个管理员，它作为应急账号一直保留。OIDC 支持多个提供方（SAML 计划在 v1.1）。
  外部身份按 `(issuer, subject)` 绑定，从不只凭 email；不开放自助注册，其他用户都通过邀请加入。会话保存在服务端，有 CSRF 防护和严格的 Content-Security-Policy。
- **v1 之前必须解决：设备到中继的控制通道还没有做服务端认证。** 按目前的设计，`frpc` 不校验中继的证书。
  设备所在网络路径上的攻击者因此可以冒充中继，窃取设备的签名声明（[`DESIGN.md`](DESIGN.md) §14 Q10；[威胁模型](threat-model.md) F1）。修复方案已经设计好，但还没有拍板。
- **每台设备都有一个本地熔断开关文件。** 运维人员可以在设备本机上停用远程访问，不依赖控制面。
- **全部密钥都由 `nethub init` 在部署者自己的机器上生成**，并按服务分别写出，每个容器只拿到它需要的那几个。NetHub 项目本身不持有、不签发、也接触不到任何全局密钥，你的实例也不依赖任何中央服务。

### 设备 Web 界面的暴露面

要清楚认识 SNI 透传设计意味着什么：任何知道或猜到某台设备主机名的人，都能打开 `https://<subdomain>.router.example.com:8443`，看到这台设备自己的 OPNsense 登录页。
控制台的登录和 SSO **并不**挡在它前面——它们保护的是控制台，设备仍然用它自己的登录。
子域名是随机的，这提高了猜中的成本；但 v1.1 引入每台设备独立的公共证书之后，这些证书会被记进证书透明度（Certificate Transparency）日志，主机名就可以被枚举出来。

一个候选的缓解办法是按来源 IP 放行：`frps` 把每一条进来的浏览器连接报告给 `nethub authz`（`NewUserConn` 钩子），authz 只放行这样的连接：最近有已登录的控制台用户从这个 IP 对这台设备点过"打开"。
这个钩子对这类代理是否会触发、能否报出真实的客户端 IP，要在 Weekend 0 实测确认；是否采用这个门禁也还没有决定（[`DESIGN.md`](DESIGN.md) §14 Q7）。这个门禁检查的是网络位置，而不是人。

另外，OPNsense 自带的 DNS 重绑定检查和 HTTP_REFERER 检查可能会拦下经由中继的访问（[`DESIGN.md`](DESIGN.md) §14 Q9，尚未实测）。遇到时，把这个主机名加进 OPNsense 的"Alternate Hostnames"，而不是关掉这两项检查。

无论如何，请在每台加入的设备上开启 OPNsense 自带的 TOTP 两步验证。

完整的分析见[威胁模型初稿](threat-model.md)和 [`DESIGN.md`](DESIGN.md)。

## 项目状态

仓库已有设计、[W0 实测结果](../weekend0/results-2026-10-17.md)和
[W2 开发插件](../agents/opnsense/plugin/README.md)。[原生验证](../agents/opnsense/plugin/tests/w2-progress.md)覆盖隧道启动、中继 TLS 认证、安全配置应用、有限回滚、定时任务生命周期、WAN 重连、重启及 os-frp 共存。尚无正式版本或完整部署，接口仍可能变化。

已选定 shadcn/ui 配合原生 dialog、来源 IP 门禁及显式心跳撤销机制；这些产品控制仍待实现。
其余设计决策见 [DESIGN](DESIGN.md) §14。

## 路线图

表里的内容都是计划，没有一项已经发布。

| 版本 | 重点 |
|---|---|
| v1 | 远程访问 CGNAT 或动态 IP 后面的 OPNsense 设备的 Web 界面，外加多用户控制台（admin / member，邀请制）和 OIDC 登录——不读写设备配置 |
| v1.1 | SAML 登录、每台设备独立的 TLS 证书、arm64 |
| v1.2 | 遥测：隧道和设备的健康指标 |
| v2 | 加密的配置备份：设备用一把在设备上派生的密钥加密 `config.xml` 后再上传，控制面只保存它无法解密的密文（因此不做服务端比对） |
| v2.5 | 配置下发（把配置变更发到设备） |

以后可能加入的控制台登录方式：passkey。

## 许可证

Apache-2.0，见 [`LICENSE`](../LICENSE)。

## 参与贡献

贡献需要做 **Developer Certificate of Origin**（DCO）签署（sign-off，`git commit -s`），不需要 CLA。DCO、本仓库和打包仓库的关系、PR 检查清单，见 [`CONTRIBUTING.md`](../CONTRIBUTING.md)。

---

*OPNsense® 是 Deciso B.V. 的注册商标。NetHub 是独立项目，与 Deciso B.V. 没有隶属、认可或赞助关系。*
