# NetHub

> 本文是 [`README.md`](../README.md) 的中文版。两者不一致时，以英文版为准。

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Stars](https://img.shields.io/github/stars/KazuhaHub/nethub?style=social)

面向开源路由器和防火墙的自托管远程访问与设备管理工具。首先支持 OPNsense，架构上为 OpenWrt 和 VyOS 留了位置。

**状态：pre-alpha，W7 实现和验收。** 控制面和 OPNsense 开发插件已实现，并有按版本和环境记录的原生／公网证书与信任验收。W5–W7 尚未全部完成，没有正式生产版本。使用前请看[项目状态](#项目状态)。

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
- [快速开始](#快速开始)
- [部署与协议文档](#部署与协议文档)
- [安全模型](#安全模型)
- [项目状态](#项目状态)
- [路线图](#路线图)
- [许可证](#许可证)
- [参与贡献](#参与贡献)

## v1 打算做什么

下面是 v1 的范围。实现与集成仍在进行，不代表已有正式发布版本。

- 让一台在 CGNAT 或动态 IP 后面的 OPNsense 拥有一个稳定可用的 Web 管理界面地址：不用做端口转发，不用折腾动态 DNS，你的电脑上也不用装 VPN 客户端。
- 用一次性 token 让设备加入（enroll），给它分配一个随机的专属子域名（例如 `abcd1234.router.example.com`），并保持一条从设备到你自己中继的长连接隧道。
- 在控制台里显示设备在线/离线状态和基本的连接信息。
- 控制台支持多个用户：`admin` 和 `member` 两种角色，只能通过邀请加入；可以用本地密码登录，也可以通过 authcore 使用 OIDC 或 SAML 登录，可配置多个身份提供方。
- 为设备签发、续签公共 GUI 证书；私钥保留在设备，安装由设备原生校验后完成。

执行计划记录了已确认的范围及尚未完成的验收。

## v1 不做什么

- **不提供通用设备配置接口。** 没有防火墙、任意命令或配置下发接口。插件管理自己的设置和隧道，受限的 GUI 证书安装路径可能重载 GUI 服务，见[安全模型](#安全模型)。
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

控制面和 OPNsense 开发插件已实现下面的架构；已验收流程及剩余验证见[项目状态](#项目状态)。

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
docs/             DESIGN.md（v0.3，中文）、部署/协议/安全/API 参考、中文 README
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

## 快速开始

按[部署说明](deployment.md)和[当前命令示例](../deploy/QUICKSTART.md)，在独立测试主机上操作。开发插件尚未正式签名发布，从零部署耗时也尚无验收结论。

1. 准备 DNS、监听端口，以及受保护的部署和备份父目录。
2. 运行 `nethub init`，核对密钥备份并确认。
3. 构建、启动生成的 Compose 栈，再单独运行 `admin-bootstrap`，通过隐藏提示输入首个管理员密码。
4. 本地管理员登录；按需配置 OIDC/SAML 和邀请。
5. 创建一次性入网 token，在 OPNsense 插件里填写控制台 HTTPS 地址和 token。
6. 核对隧道观测与当前 GUI 证书应用状态。
7. 点击“打开”放行当前来源 IP，再用 OPNsense 自己的账号登录，正常核验证书和主机名。

## 部署与协议文档

- [部署与运维说明](deployment.md)：当前命令、反代和证书的职责、故障排查，以及尚未完成的备份恢复验收。
- [设备协议说明](protocol.md)：入网、证书和信任更新、版本兼容，以及其他路由系统的适配边界。
- [文档索引](README.md)与[已验收记录和剩余工作](HANDOFF_PROMPT.md)。

这些说明不代表已有正式生产版本，也不代表 W5–W7 已全部验收。本文其余历史状态说明仍需按 W7 计划与当前实现逐项核对。

## 安全模型

v1 在设计上要保证的几件事：

- **没有通用设备配置或命令接口。** 插件只管理本地 NetHub 设置、隧道生命周期及经过校验的 GUI 证书应用；证书路径可能重载 GUI，不提供防火墙或任意服务控制。
- **enroll token 一次性使用，15 分钟后过期。**
- **设备身份是 enroll 时签发的域名归属签名声明**（HMAC-SHA256）。设备的 `frpc` 登录或注册代理时，`frps` 会询问 `nethub authz`，由它同时检查签名有效**并且**与数据库记录一致——两道独立的检查，而不是一道。
- **签名密钥只在 `nethub authz` 里。** 公网控制台 `nethub web` 是另一个进程，使用自己的数据库角色。它从不持有签名密钥和 `frps` 的管理凭证，不能新建设备记录，也不能写子域名和声明字段。
  所以即使控制台被完全攻破，也无法为一台已有设备签出有效声明，也无法改变子域名的归属。
  不过它**仍然**可以：生成 enroll token（以一个新子域名加入一台新设备）、撤销设备、读取设备元数据和审计日志、管理用户和登录提供方——也就是接管整个控制台。完整的边界见 [`DESIGN.md`](DESIGN.md) §6。
- **控制台支持本地密码、OIDC 和 SAML 登录。** 独立的 `admin-bootstrap` 服务用本地密码（argon2id）创建首个管理员，它作为应急账号保留。OIDC/SAML 的协议验证直接使用 authcore。
  OIDC 按 `(issuer, subject)` 绑定；SAML 使用限定于 IdP 和 SP 的持久 NameID。两者都不只凭 email 绑定；不开放自助注册，其他用户都通过邀请加入。会话保存在服务端，有 CSRF 防护和严格的 Content-Security-Policy。
- **客户端校验中继 TLS。** 入网返回指定服务端名称和部署 CA 公共信任包，frpc 显式使用 `serverName` 和 `trustedCaFile`。保留认证信任分发和受保护的 CA 切换步骤。[原生信任记录](../deploy/validation-relay-trust-native.md)仅证明其中写明的环境，不是生产安全审计。

- **每台设备都有一个本地熔断开关文件。** 运维人员可以在设备本机上停用远程访问，不依赖控制面。
- **部署密钥由 `nethub init` 在部署者自己的机器上生成**，并按服务分别写出，每个容器只拿到它需要的那几个。NetHub 项目本身不持有、不签发、也接触不到任何全局密钥，你的实例也不依赖任何中央服务。

### 设备 Web 界面的暴露面

SNI 透传保留设备自己的登录。正常运行时，新连接还需要匹配设备和浏览器来源 IP 的有效门禁授权。登录控制台后点击“打开”，放行 30 分钟；再次点击续期，访问和列表轮询不会延长授权。单凭主机名不获得新连接权限，见[打开行为](../deploy/device-open.md)。

门禁检查网络位置，不识别人。CGNAT 用户可能共用 IP，控制台和路由器访问使用不同 IPv4/IPv6 来源时可能被拒；已有连接也可能持续到授权过期之后。被攻破的中继还可以跳过钩子。公共 GUI 证书属于 v1，证书透明度日志可能暴露主机名，随机子域名不是授权机制。

公共证书已有[限定环境的原生／公网记录](../deploy/validation-native-public-certificate.md)。安装报告不证明后来的外部连接实际看到什么，浏览器仍需正常核验 CA 链和主机名。按 [W0 决策](../weekend0/results-2026-10-17.md)添加精确 Alternate Hostname，保留 OPNsense 的 DNS 重绑定和 HTTP_REFERER 检查。

无论如何，请在每台加入的设备上开启 OPNsense 自带的 TOTP 两步验证。

完整的分析见[威胁模型](threat-model.md)和 [`DESIGN.md`](DESIGN.md)。

## 项目状态

[交接记录](HANDOFF_PROMPT.md)将验收结果绑定到源代码、CI 和原生／公网测量。W0、W2 是历史基础，不代表后续产品流程全部完成。

[原生公共证书记录](../deploy/validation-native-public-certificate.md)覆盖隔离环境的签发、定时安装、认证公网 GUI 访问和恢复。[心跳与撤销记录](../deploy/validation-native-w5-heartbeat.md)保留撤销速度偏差，以及尚未完成的手机 Open 样本。

两家 Dex 已有 [OIDC 部署验收](../deploy/validation-two-dex.md)。SAML 后端、页面及独立 [Keycloak 部署](../deploy/validation-keycloak-saml.md)已有范围明确的验收；公开 IdP 和 W6 整体验收尚未完成。

[定时数据库备份服务](../deploy/database-backups.md)已通过[范围明确的容器和恢复检查](../deploy/validation-database-backups.md)。[单设备凭证轮换](../deploy/device-rotation.md)已通过隔离环境的原生安装验收，包括两种真实中断后的恢复。[部署级共享 token 更换](../deploy/shared-relay-token-rotation.md)已有范围明确的服务端／参考客户端切换记录，原生设备事件恢复仍在验证；公网／手机门禁另行验收。完整的全新主机／当前密钥／已入网设备恢复、文档全面核对、朋友从零部署和正式签名／故障版本发布仍是 W7 待办。没有正式发布包，也不宣称已适合生产。

## 路线图

表里的内容都是计划，没有一项已经发布。

| 版本 | 重点 |
|---|---|
| v1 | 远程访问 CGNAT 或动态 IP 后面的 OPNsense 设备的 Web 界面，外加多用户控制台（admin / member，邀请制）、OIDC/SAML 登录及每设备公共 GUI 证书——不提供通用设备配置接口 |
| v1.1 | arm64 |
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
