# NetHub —— 开源的 OPNsense 远程接入与车队管理平台

> 设计方案 v0.3（草案，2026-10-16）。v0.2 基于一轮调研与两轮对抗评审（15 条完整性评审 + 8 个红队灾难场景；
> §13 已把这 8 个扩展为 12 个，v0.3 再补 2 个，现为 14 个），并按「全部开源、个人与企业均可自行搭建」的前提重写。
> v0.3 纳入用户在 2026-09-17 会话里做出的决定（服务端改 Go、React 控制台、v1 多用户 + OIDC 等），
> 并修正 v0.2 的若干事实错误与自相矛盾之处，逐条见 §0。**目前没有任何代码；下文描述的全部是设计，不是现状。**
>
> 仓库 `github.com/KazuhaHub/nethub` · 许可证 Apache-2.0 · 贡献协议 DCO（不用 CLA）
>
> 命名说明：`net` + `hub`，两个零门槛的常用词，`hub` 在计算机语境里本就是「中枢服务」的标准用法
> （Docker Hub、Azure IoT Hub、AWS Security Hub）。**产品名与仓库名不含 "OPNsense"**——那是
> Deciso B.V. 的商标；描述里写 "for OPNsense" 没有问题。插件包名保留社区惯例的 `os-` 前缀：`os-nethub-agent`。

---

## 0. v0.3 变更记录

v0.2 写完之后，用户在 2026-09-17 的会话里拍板了一批事项，它们覆盖 v0.2 的原文；2026-10-16 用户解除 HOLD，
并确认共享认证模块的拆分已经完成，本轮修订随之进行。

「决定者」一列：**用户** = 用户明确拍板；**建议** = 本方案的设计建议或事实修正，用户尚未逐条确认，可以被推翻；
**待定** = 明确留给用户，本文不替用户回答。

| 变更 | 原因 | 决定者（用户/建议） | 日期 |
|---|---|---|---|
| 服务端从 Python 单体（v0.2 的 FastAPI + SQLAlchemy + Jinja2 SSR）改为 **Go 单二进制 `nethub`**（决策 #5 重写） | 用户选择「Go（推荐）」；v0.2 否决 Go 的前提"团队没有自写 Go"不成立 | 用户 | 2026-09-17 |
| 控制台改为 **React + TypeScript + Vite SPA**，构建产物 `go:embed` 进二进制；不再有服务端模板 | 用户选择 React；具体组件库以 2–3 个示例的形式再选（Q8） | 用户（React）/ 待定（组件库） | 2026-09-17 |
| v1 新增**多用户**（`admin` / `member`、邀请制）与 **OIDC 登录（支持多个 IdP）**（§6、新增决策 #22） | 用户："要，计划着，需要做支持 SSO" | 用户（范围）/ 建议（具体设计） | 2026-09-17 |
| SSO 范围：v1 只做 OIDC，**SAML 放 v1.1**（经 `authcore/saml`） | 用户："先 OIDC，SAML 放 v1.1" | 用户 | 2026-09-17 |
| 共享认证代码拆到独立 Go 模块 `KazuhaHub/authcore`；NetHub 按 authcore 自己的准入逻辑选择性使用，v1 不依赖其任何包（§6、新增决策 #23） | 用户 2026-10-16 确认拆分已完成，authcore 当前 v0.6.1 | 用户（拆分）/ 建议（NetHub 怎么用） | 2026-09-17 / 2026-10-16 |
| 许可证定为 **Apache-2.0**，Q0 关闭；与组织分层策略的关系留一个待确认子项 | 用户："那就这么确定了" | 用户（子项待定） | 2026-09-17 |
| 确认 NetHub 作为组织许可证分层策略的例外，保持 **Apache-2.0**，继续 P0；Q0 子项关闭 | Kazuha 确认 D1 | 用户 | 2026-10-17 |
| 产品名定为 **NetHub**，Q6 关闭 | 用户拍板 | 用户 | 2026-09-17 |
| 打包仓库 `KKazuhaK/OPNsense-repo` 定性为 owner 自己的 fork、独立开发；删掉"先跟 fang 打声招呼"（§2） | 用户：不再与原作者共有，准备独立开发 | 用户 | 2026-09-17 |
| 决策 #4 落地为 **`nethub web` / `nethub authz` 进程拆分** + Postgres 列级授权 + 一个窄的 `SECURITY DEFINER` 函数，并如实写出被攻破的 web 能做什么、不能做什么（§6） | 让"web 拿不到签名密钥、改不了子域名归属"成为可测试的属性，而不是一句承诺 | 建议 | 2026-10-16 |
| 决策 #21 的密钥清单按进程拆分重写，新增 `NETHUB_SECRETS_KEY`；密钥按服务分文件，不再用一个共享 `.env`（§3、§7） | 每个容器只拿自己需要的密钥 | 建议 | 2026-10-16 |
| 控制台防护改为服务端 session 表 + CSRF 自定义请求头 + 严格 CSP，无服务端模板；可信代理客户端 IP 规则（§6、§9） | 架构从 SSR 改为 SPA；多用户与登录审计需要可靠的客户端 IP | 建议 | 2026-10-16 |
| 公网端口统一写成 **443 / 7000 / 8443**（§5、§7） | v0.2 部分地方只写了 443 和 8443，漏了 frps `bindPort` 7000 | 建议（事实修正） | 2026-10-16 |
| 数据模型修正与扩展：`devices` 补 `platform` / `capabilities`、`opnsense_version` 改名 `platform_version`、加 `revoked_at` / `revoked_by_user_id` 与展示用 `label`；`audit_log` 补 `tenant_id`；`users` 调整；新增 `user_identities` / `oidc_providers` / `invites` / `sessions`（§6） | v0.2 的 DDL 与 §2、与 RLS 策略自相矛盾；新范围需要新表；列级授权需要一个明确的"展示标签"列 | 建议 | 2026-10-16 |
| `os-frp` 同机共存规则写进 §4；`status` 不再使用 frpc `[webServer]` | 其默认 `127.0.0.1:7400` 与 os-frp 的管理界面冲突 | 建议 | 2026-09-17（分析）/ 2026-10-16（写入） |
| frp 暂时继续锁 0.71.0；0.71.1 的升级计划为三处一起升、在 Weekend 2 之前（§5） | 与 os-frp 保持一致（决策 #19） | 建议（升级本身待用户确认） | 2026-10-16 |
| 更正：frp 默认 `--strict_config=true`，未知字段直接报错退出，不会被静默忽略（§5） | v0.2 的 Weekend 0 套件文字有误，且套件里 TOML 表作用域的写法会让 frps/frpc 启动即退出 | 建议（事实修正） | 2026-10-16 |
| 新增 **Q7：设备 GUI 的公网暴露面**，以及基于 frps `NewUserConn` 的候选缓解（§14） | v0.2 完全没写这个暴露面 | 待定（用户） | 2026-10-16 |
| 新增 **Q8：React UI 组件库**（§14） | 用户要求以示例形式比较后再选 | 待定（用户） | 2026-10-16 |
| MVP 重排为 **W0–W7 + 缓冲**，新增"测试环境"小节（§10）；路线图 v1.1 加入 SAML、passkey 列为以后的选项（§11） | 范围增长；估算的不确定性随之变大 | 建议 | 2026-10-16 |
| OPNsense 26.7 WAN 默认路由 regression 更新为 opnsense/core#10597，已在 26.7.1_1 修复（§10、§12、§13）；当前稳定版 26.7.7 | 上游已于 2026-07-23 热修复 | 建议（事实更新） | 2026-10-16 |
| 插件数量统一为"13 个（截至 2026-10-16）"；修正悬空引用"见第 11 节"；页首灾难场景数量说明 | v0.2 里 14 / 15 混用，与 `packaging/plugins.json` 不符 | 建议（事实修正） | 2026-10-16 |
| §13 场景 #1 的触发路径改写（不再有 SSR），场景 #2 按新角色改写，新增 #13（按 email 绑定导致 OIDC 账号接管）与 #14（经中继爆破/利用设备 GUI）；§9、§12 相应加行 | 架构变化 + 新范围带来的新攻击面 | 建议 | 2026-10-16 |
| 更正：frps 0.71.0 的 admin API 只能列出客户端 / 代理、清理**离线**代理，没有断开在线连接的接口。轮询器降为"只负责发现"，断线机制改为候选方案（拒绝 `Ping` + 显式心跳、拒绝 `NewUserConn`、重启 frps）并列为 Weekend 0 验证项；W5 不再承诺断线时延（§5、§9、§10、§12、§15） | 已对 frp v0.71.0 源码核实；v0.2 的"踢线"假设了一个不存在的接口 | 建议（事实修正） | 2026-10-16 |
| 设备侧代理改用 `subdomain = "<subdomain>"`，不再用 `customDomains`；`NewProxy` 比对的是 `subdomain`（§5、§10） | frps 0.71.0 拒绝落在 `subDomainHost` 之下的 `customDomains`，按 v0.2 的写法代理注册会失败 | 建议（事实修正） | 2026-10-16 |
| OIDC 认领邀请必须从邀请链接发起：邀请 token 有效、`email_verified=true`、email 一致三者同时成立（§6、决策 #22、§13 #13、W6） | 只凭 email 匹配任意一条待处理邀请，等于让任何一个已配置、会断言 `email_verified` 的 IdP 领走别人的邀请 | 建议 | 2026-10-16 |
| 新增只读备份角色 `nethub_backup`（`BYPASSRLS`）；密钥清单补上它和 Postgres 引导超级用户的密码（§6、§7、决策 #21） | 所有租户表都 `FORCE ROW LEVEL SECURITY`，普通角色跑 `pg_dump` 会直接报错 | 建议 | 2026-10-16 |
| 删掉 `devices.frp_token_hash`：frps auth token 是每部署一份的共享密钥，设备身份靠签名声明 + `device_secret`（§6、决策 #21） | 共享 token 的"每设备哈希"没有意义，且与决策 #21 自相矛盾 | 建议 | 2026-10-16 |
| §6"被攻破的 web 能做什么"补两条：能为任意 IP 打开 Q7 门禁，能生成任意有效期的 enroll token；enroll token 的有效期改由数据库默认值和 `consume_enroll_token` 强制 | 如实写出边界 | 建议 | 2026-10-16 |
| 候选断线机制 1（拒绝 `Ping`）补上可用性代价：`Ping` 订阅给 authz 后同样 fail-closed，authz 一次崩溃、挂起或数据库卡顿会在心跳窗口内切断**全部**已建立的隧道，"新连接的单点"变成"全部远程访问的单点"；写明缓解（`Ping` 只查内存撤销状态、不碰数据库，严格内部超时，健康检查重启），并写明这些缓解只能缩短恢复时间、挡不住断线；断线机制的推荐组合改标为"待 Weekend 0 数据，未定"；Weekend 0 第 6 项加测这一代价（§5、§9、§10、§12、§13、§15） | 原文只写了这条机制能断线，没写它把 authz 的故障从"挡新连接"放大成"断掉所有远程访问"；已对 frp v0.71.0 源码核实 `Ping` 的处理路径 | 建议 | 2026-10-16 |
| 撤销相关表述统一为"轮询器只负责发现，断线机制待 Weekend 0"：§5 人工「立即断」旁路、§9 撤销一行、W5 验收不再暗示轮询器能断线或 W5 一定能断线；§2 不再拿 `os-mihomo` 当打包仓库正在发布的例子（它只有 `src/` 目录，不在 `plugins.json` 里，见 §15）；Q2 写明 443 也是 0/20 时的处理，与 Weekend 0 套件一致；§15 措辞去掉具体工具名 | 消除与 §5、§15、Weekend 0 套件之间的不一致 | 建议（事实修正） | 2026-10-16 |
| 新增 **Q9：OPNsense 自己的 DNS 重绑定 / HTTP_REFERER 检查**可能拦下经中继的访问（§14） | 设备 GUI 看到的主机名是中继分配的子域名，不是设备自己的主机名；v0.3 之前没有考虑 | 待定（先实测） | 2026-10-16 |
| 新增 **Q10：设备 ↔ 中继控制通道没有服务端认证**（frpc 未配 CA 时不校验 frps 证书），可被路径上的中间人截取 domain claim（§14） | 写威胁模型时对 frp v0.71.0 源码核实发现 | 待定（v1 前必须解决） | 2026-10-16 |
| 威胁模型与控制台 API 初稿审查后的补充：`NewProxy` 拒绝任何 custom domain、设备不能承载控制台域名、控制台 HSTS 不带 `includeSubDomains`（§5）；被攻破的控制台能借设备列表钓鱼、frps / Caddy 被攻破的后果、authz 能取消撤销（§6）；web 对 `enroll_tokens` 少数列的 `SELECT`（§6）；始终保留一个本地密码 admin（§6）；Q10 修复方案细化（部署 CA、PEM、frps 不热加载证书、`Login` 可重放） | 写 `docs/threat-model.md` 与 `docs/console-api.md` 时的审查发现 | 建议 | 2026-10-16 |

**仍未决定（本文不替用户回答）：** 控制通道的服务端认证（Q10）；OPNsense 主机名检查的处理（Q9）；React UI 组件库（Q8）；v1 功能清单的最终确认；
设备 GUI 公网暴露面的处理（Q7）；frp 升到 0.71.1 的时机（§5）。

---

## 1. 结论与定位

**v1 只做一件事：让任何一台装了 `os-nethub-agent` 的 OPNsense，在不做端口转发、不绕 CGNAT、
浏览器不装任何客户端的前提下，被一台你自己部署的中继点一下就能打开它的 Web UI。
除此之外，控制面不能读你的 `config.xml`、不能改一条防火墙规则、不能重启任何服务。**

这不是「又一个 UniFi」，差异在三处，而且每一处都是架构事实而不是营销话术：

1. **权限窄是设计出来的，不是承诺出来的。** v1 的控制面在架构上就不知道你的 `config.xml` 长什么样。
   对标的是 BeyondTrust（一把云端 key 重置所有客户密码）、SonicWall MySonicWall（云备份"加密"但云端能解）
   这类真实事故——爆炸半径最小化是可验证的属性，不是信任声明。
2. **全开源 + 自建。** 控制面不是某个厂商的 SaaS，是一个 `docker compose up` 起得来的东西。
   个人放在自己 VPS 上，企业放在自己机房里。数据去哪、日志留多久、中继在哪个国家，全由部署者决定。
   爱快云 / Meraki / UniFi 在这件事上只能说"信我"。
3. **它是给 v2/v2.5 打地基的第一块砖。** 设备身份、enroll 流程、租户模型从第一天就按"以后要撑起配置托管"
   的形状设计，只是**故意**把写权限推迟到证明了"有人愿意为了这一个按钮装插件"之后。

**v0.3 补充：控制台本身是多用户的。** 按用户 2026-09-17 的要求，v1 的控制台支持多个账号
（`admin` / `member`，邀请制）和 OIDC 登录（可配置多个 IdP），SAML 在 v1.1。这扩大的是"谁能登录控制台"，
**不**扩大控制面对设备的权限——控制面对设备唯一的写权限仍然只是"这台设备的隧道能不能连上"。
同样要说清楚：控制台的登录与 SSO **不保护**设备自己的 OPNsense GUI，那个页面仍由 OPNsense 自己的登录把守
（暴露面见 Q7）。v1 功能清单的最终确认仍待用户。

**明确不与谁竞争：**

- **不打 Tailscale Funnel。** 只想给自己一台路由器开个远程入口、不在乎控制面在哪的用户，Tailscale 更简单。
  NetHub 的价值在"我要自己掌握这条通道 + 我有不止一台设备 + 我以后要做配置托管"。
- **不打爱快云。** 它真正的护城河是计费、Portal 认证、实名合规——网吧/酒店客户付费的理由。
  NetHub（包括可预见的 v2/v2.5）完全不做这些，也不该假装在做。

---

## 2. 项目形态与仓库划分

### 许可证

| 组件 | 许可证 |
|---|---|
| NetHub 全部代码（控制面、协议、OPNsense 插件源码） | **Apache-2.0** |
| 贡献协议 | **DCO**（`git commit -s`），不用 CLA |

用户已于 2026-09-17 拍板：两部分（控制面与设备侧插件）都用 Apache-2.0。2026-10-17 再次确认：NetHub 作为组织许可证分层策略的例外，保持 Apache-2.0，继续 P0（Q0 子项关闭）。

选 Apache-2.0 而不是 MIT，是因为它多一条显式**专利授权**（§3）和一条贡献条款（§5），
企业法务审查更容易过——而「企业也能自行搭建」正是这个项目的目标之一。
没有托管版计划，所以不需要 AGPL 来保护什么。注意这个门是单向的：不用 CLA 就意味着
以后想收紧到 AGPL 需要所有贡献者同意，基本回不了头。这是清醒接受的取舍。
v0.3 引入的共享模块 `authcore` 同为 Apache-2.0，许可证兼容。

### 一个仓库装全部源码，另一个仓库只负责打包

```
KazuhaHub/nethub                  ← 全部 NetHub 源码，Apache-2.0，单一版权
  proto/                            协议单一事实源（JSON Schema），平台中立
  server/                           控制面：Go 单二进制 nethub（web / authz / migrate / init / doctor）
    web/                            控制台 React + TypeScript + Vite 源码（构建产物 go:embed，dist 不入库）
  agents/opnsense/plugin/           os-nethub-agent 插件源码（PHP MVC / rc.d / configd / agentctl.py）
  deploy/                           docker-compose、Caddy 配置、按服务分的密钥目录布局
  docs/                             本文档、威胁模型、部署文档
  weekend0/                         Weekend 0 传输层验证套件（RUNBOOK、frps/frpc 配置、probe.py）

KKazuhaK/OPNsense-repo            ← 只有打包配方，不含 NetHub 源码
  packaging/plugins.json            一条 os-nethub-agent 的 entry
  src/os-nethub-agent/build.sh      拉取 NetHub 的 release tarball、校验 sha256、进流水线
```

以上目录是规划；目前仓库里只有文档和 Weekend 0 套件，没有代码。`nethub init` / `nethub doctor`
是 `server/` 里同一个二进制的子命令，不再"位置待定"。

**为什么源码不放进打包仓库。** 那个仓库是 2026-09-12 从 `Opnwall/OPNsense-repo` fork 来的，
根 LICENSE 是 MIT 且署着 `Copyright (c) 2026 Opnwall`（另一位作者的实体），
`src/os-unboundcustom/` 是第三方的 BSD-2，`src/os-ddclient-opnwall/` 里 21 个文件带着
12 位 OPNsense 上游作者的 BSD-2 版权头。把一个新项目的代码混进去，NetHub 归谁所有会长期含糊。
全部留在 `KazuhaHub/nethub` 则是单一版权、单一许可证，无论是接受贡献还是被人审计都干净。

**而这样反而更顺，不是妥协。** `OPNsense-repo` 本来就是干这个的——`packaging/plugins.json` 里的
`os-sing-box`、`os-frp`、`os-easytier` 全是打包第三方软件（sing-box、frp、EasyTier）。从它的视角看，NetHub 就是又一个上游，
走的是它已经跑熟的那条路，没有任何特殊逻辑。

**唯一的代价**是开发插件 Web 界面时要跨两个 checkout。绕法：开发阶段把
`agents/opnsense/plugin/` symlink 或 rsync 进 `src/os-nethub-agent/`，只有发布流程才真正跨仓。

**没有需要协调的共同维护者。** 这个打包仓库是 owner 自己的 fork，用户已决定独立开发（2026-09-17），
往 `packaging/plugins.json` 加 entry 不需要先征求任何人。独立开发改变的是"跟谁商量"，
不改变上面那段许可证历史——那正是 NetHub 源码不放进那里的原因。

### 协议漂移仍然要防（只是不再是跨仓问题）

源码同仓消除了「两个仓库各自定义协议」这种漂移，但没有消除问题本身：
**一台部署在现场的 agent 可能比它连的服务端老好几个月**。所以：

- `proto/` 是唯一事实源，用 JSON Schema 描述，随 release 打 tag；
- 任何改 `proto/` 的 PR 必须在同一个 PR 里更新 `agents/` 下受影响的所有 agent，并跑契约测试——
  契约测试在**本仓库的 CI** 里跑，**同时**校验 Go 服务端（`nethub authz` 提供的设备 API）与 Python agent 两侧；
- agent 在 enroll 时上报 `agent_protocol_version`，服务端对不兼容版本**明确拒绝并返回可读错误**，
  而不是让它半死不活地连上。

### 多平台留门（现在两小时，以后是重构）

以后可能支持 OpenWrt / VyOS。成本曲线是分裂的：**v1 的远程接入几乎免费**
（agent 就是 vendored frpc + 几个脚本，搬到 OpenWrt 是一个 LuCI app + opkg 装 frpc）；
**v2.5 的配置下发非常贵**（config.xml / UCI / VyOS commit 三套配置语义共享不了，基本每平台重写）。

所以现在不做多平台，但三条留门现在做几乎零成本：

1. 目录用 `agents/opnsense/`，不在根上假设只有一个 agent；
2. `proto/` 保持平台中立——协议里不出现 `config_xml` 这类平台特定词，用 `device` / `platform` / `capabilities`；
3. `devices` 表第一天就带 `platform` 和 `capabilities` 字段，控制面按设备上报的能力开关功能，
   任何地方不硬编码 OPNsense。v1 的 OPNsense agent 只声明一个能力：`remote.web`。
   （v0.2 的 DDL 实际漏了这两列，v0.3 已补上，见 §6。）

## 3. 关键架构决策

| # | 决策 | 选了什么 | 否决了什么 | 理由 | 后悔成本 |
|---|---|---|---|---|---|
| 1 | 控制/远程通道协议 | **复用 frp 0.71.0**（vhost-https + SNI passthrough；0.71.1 的升级计划见 §5） | MQTT/EMQX、gRPC 双向流、WebRTC/TURN、Cloudflare Tunnel、自研 QUIC/WireGuard mesh | v1 没有任何需要控制面主动下发的指令。"在不在线"这一件事，frp 的控制连接本身就回答了 | 低 |
| 2 | 是否复用用户已装的 `os-frp` | **不复用，自带独立 vendored frpc 实例** | 读写用户 `os-frp` 的 `frpc.toml` | `frpc.toml` 全局只有一个 `serverAddr`/`token`，会和用户自己的 os-frp 配置冲突。同机共存的具体规则见 §4 | 低（多打包约 12MB 已验证二进制） |
| 3 | `frpc.toml` 生成方式 | **Jinja2 + OPNsense 官方 `+TARGETS`** | `tomllib` 只读 + 手写 emitter、vendor `tomlkit` | 决策 2 成立后这份文件由本插件独占，不存在合并需求 | 低 |
| 4 | 设备身份 / 域名归属校验 | **签名声明（HMAC-SHA256）+ DB 记录双重校验，签名与验签只发生在 `nethub authz` 进程里**。`httpPlugins` 的 `Login`/`NewProxy` 做主校验；authz 每 15s 轮询 frps admin API 核对，**连续 3 次（~45s）异常才判定要断线**，另留人工「确认失窃、立即断」旁路。frps 0.71.0 的 admin API 没有断开在线连接的接口，所以轮询只负责发现，真正断线另走候选机制（§5，待 Weekend 0 实测）。公网控制台 `nethub web` 与 authz 分进程、分 Postgres 角色、按列授权：web 拿不到签名密钥，不能新建设备行，不能写 `subdomain`、声明字段和密钥哈希列；子域名由 authz 随机生成（落地细节见 §6） | 只用共享 token、单次不一致即踢线；web 与授权逻辑同进程、只靠"代码里不去读密钥" | 如果只信任 DB 一行记录，公网控制台一旦被打穿（API 越权/SQLi/XSS/session 伪造），攻击者改一行 SQL 就能让自己的 frpc 冒充任意设备抢占它的子域名（`subdomain`）——用户看到的还是"和平时一样"的证书警告，一次渗透 = 全量钓鱼。签名密钥**不暴露给 web 进程**，DB 整表被篡改也伪造不出有效声明。v0.3 把"不暴露"落到进程、文件挂载和列级授权三层上，并如实写出被攻破的 web 仍然能做什么（§6） | 中 |
| 5 | 控制面技术栈 | **Go 单二进制 `nethub`**（Go 1.26，与组织内其它 Go 仓库同一条线；源码在 `server/`，模块路径 `github.com/KazuhaHub/nethub/server`），两个运行角色 `nethub web` / `nethub authz`；控制台 React + TypeScript + Vite SPA，构建产物 `go:embed` 进二进制（与组织内 Report-Portal 同构）；Postgres 16 + Caddy，单机 docker compose。**设备侧不变**：Python 3.13 `agentctl.py` + PHP/Phalcon MVC（由 OPNsense 决定） | Python/FastAPI 单体（v0.2 的选择）；Go 微服务 | **更正 v0.2 的理由**：v0.2 以"团队'用 Go'的全部经验是打包上游预编译二进制，仓库里没有一行自己写的 `.go`"否决 Go——这在 2026-09-17 就不成立：owner 维护着约 18 万行自写 Go（Passwall-Sub-Panel、Report-Portal、Passwall-Node、AlertHub）。v0.2 的另一半理由"自建项目的部署简单度直接决定采用率"仍然成立，而且更支持 Go：单个静态二进制；与 frp 同语言同工具链；能直接用 `authcore`。微服务仍然否决——一个二进制两个角色就够了。用户 2026-09-17 拍板 | 低 |
| 6 | 设备侧是否需要常驻 daemon | **不需要**，唯一常驻进程是 vendored `frpc` | 自写 Go/Python `agentd` | 在线状态 = frpc 控制连接是否存活，frp 自己已经在维护 | 低 |
| 7 | 租户模型 | **v1 就上 `owner_user_id` + Postgres `FORCE ROW LEVEL SECURITY`**，但不做递归 org 树 | 完全不做 RLS；第一天上完整 org 树 | 自建 = 一个组织一个实例，**递归 org 树/计费**确实可以推迟；但 RLS 是防御纵深，防的是代码 bug。企业实例里天然有多个管理员、多个部门，任何一条查询忘了加过滤就是越权。几十行迁移脚本换"哪怕 handler 漏了 WHERE，DB 也返回空集"。**v0.3 注**：v1 每个实例恰好一个租户，所以租户级 RLS 在 v1 防的是"`app.tenant_id` 设错/漏设"一类 bug，并让 v3 多租户不用补课；租户**内**按用户的隔离（`member` 只看自己的设备）是应用层的 `owner_user_id` 过滤，不是 RLS 提供的（§6） | 低 |
| 8 | 首个账号与准入 | **`nethub init` 创建首个管理员**（本地密码，argon2id，作为 break-glass 账号长期保留）；其他人只能经管理员**邀请**加入（一次性链接、只存哈希、会过期），接受邀请时设置密码或用 OIDC 登录完成绑定；设备侧用一次性 enroll token 带外交付 | 公开自助注册（不适用于自建）；OIDC JIT 自动开户（v1 不做，按域名白名单的 JIT 可作为以后的选项） | 自建项目的边界天然就是实例本身。v0.2 曾以"v1 无意义"否决邀请制，前提是 v1 只有安装者一个账号；v1 改为多用户后（用户 2026-09-17），邀请就是最窄的准入方式 | 低 |
| 9 | 远程 UI 的 TLS 信任模型 | v1 **接受**自签名证书 + 浏览器警告；v1.1 用 DNS-01 给每台设备独立签发 Let's Encrypt 证书 | v1 就上通配符证书、控制面终止 TLS 再转发 | 自签名警告确实会训练用户"看到警告就点过去"，这条批评成立——但它指向的修复点是**决策 #4（域名归属）**而不是证书类型：域名归属校验若是坏的，攻击者照样能给钓鱼后端签出同一子域名的"真"证书。另注意 v1.1 的每设备证书会进入 Certificate Transparency 日志，主机名从此可枚举（见 Q7） | 中 |
| 10 | 本地熔断开关 | 独立 flat file `/var/db/nethub-agent/disabled`，reconcile 每次运行前先查 | 只用 config.xml 里的 `Enabled` 字段 | 提前建立"本地永远优先、控制面只能优雅降级" | 低 |
| 11 | 是否复用 `common/config_backup.py` | **v1 完全不用** | 把凭证或渲染出的 `frpc.toml` 镜像进 config_backup | `config_backup` 是给"daemon 在 config.xml 之外维护状态"的场景用的；本插件的凭证是普通 MVC 标量字段，`frpc.toml` 是它们的确定性渲染产物，恢复后重渲染一次即可 | 低 |
| 12 | 打包管线 | 复用仓库统一 native 管线：`packaging/plugins.json` 加一条 entry（`staging: tree`、`abi: target`、`deps: {"python313": "lang/python313"}`），与 os-staticarp / os-easytier / os-ddns-go / os-lucky / os-sing-box 写法一致（截至 2026-10-16，`plugins.json` 的 13 个 entry 里有 6 个声明 `python313` 依赖，其中这 5 个同时是 `tree` + `target`） | 官方 `Mk/plugins.mk` | 和现有 13 个插件（截至 2026-10-16）走同一条已跑通的构建/签名/发布流程 | 低 |
| 13 | reconcile 写 `frpc.toml` 的流程 | **渲染到临时文件 → `frpc verify --strict_config=true` 通过才 `mv` 覆盖 → 校验不过保留旧文件、不重启、GUI/控制面标红** | 「渲染 → 比哈希 → 变了就重启」 | 已核对 `src/os-frp/src/usr/local/etc/rc.d/frpc`：`daemon(8)` 故意不带 `-r`，原注释是 `--strict_config` turns a single misspelled key into a permanent exit(1)。这对 os-frp 是对的（用户手改配置错了自己看日志），但本插件的 `frpc.toml` 是**模板渲染产物**——一次坏的模板升级会让进程停在"已停止"且无人重试，而远程访问正是这个产品存在的唯一理由 | 低 |
| 14 | 独立看门狗 | 一条**独立于 agent 代码之外**的 cron（每 5 分钟）：服务 `stopped` 且存在"上一份能跑的 `frpc.toml`" → 回滚并重启**一次**，不无限重试 | 依赖用户自己发现 | 回滚计时器必须活在能被这次变更拖死的进程之外 | 低 |
| 15 | 插件发布方式 | **灰度 canary**：复用 `os-kazuha-repo` 现有的 series 切换，先切一小撮（自己 + 志愿者），观察 `last_seen_at` 正常再全量 | 新版本直接全量推送 | 批量升级把一片设备变砖是最坏的失败模式，而这套机制不需要新组件 | 低 |
| 16 | config.xml 写路径的并发与输入安全 | `enroll`/`unenroll` **幂等**（已有非空 `DeviceId` 直接返回成功）；控制面返回的字段写入前**严格白名单校验**（`subdomain` 只匹配 `^[a-z0-9-]{1,63}$`）；复用 OPNsense 全局配置锁 | 假设"走官方 setAction 就天然安全" | 本插件引入了三条别的插件都没有的高频脚本化写入路径。对一台边界防火墙，config.xml 损坏比远程 UI 打不开严重一个数量级 | 低 |
| 17 | `newwanip` 触发 reconcile 的防抖 | 最短间隔 60s 合并 + 0–30s 随机抖动 | 无防抖直接注册 | CARP 主备切换/上联抖动会让多台机器几乎同时触发，叠加决策 #4 的轮询容易把正常 failover 误判成异常 | 低 |
| 18 | 凭证/服务端地址原地轮换 | `agentctl.py rotate` 子命令：拉一套新凭证后原地更新并重启，不走完整 enroll | 只有 enroll/unenroll，轮换 = 重新带外交付 | 中继地址/端口/token 一旦需要轮换（迁移、泄露），否则唯一补救是要求每个用户手动重新 enroll | 低 |
| 19 | 供应链版本一致性 | CI 检查：`os-frp` 与 `os-nethub-agent` 两份 vendored frp 版本号必须一致，否则构建失败——两个包各带一份 `FRP_VERSION` 文件供 CI 直接比对；server 侧 `frps` 版本由 compose 锁定且与之匹配 | 无机制防止悄悄分叉 | 决策 2 让版本从"1 处要更新"变成"3 处必须同步"，需要机制兜底而不是靠记性 | 低 |
| 20 | 签名私钥主机的部署边界 | **明确排除**持有 Kazuha 仓库签名私钥的那台路由器于本插件的部署范围之外；端到端验收用一台不持私钥的独立测试路由器 | 在日常路由器上装新插件做验收 | 一旦决策 #4 的劫持路径成立而受害机恰好是私钥主机，攻击者拿到管理员凭证登入 shell 就能拿到签名私钥，把"控制面被攻破"升级成"能对仓库里的全部插件（截至 2026-10-16 共 13 个）重新签名推给所有用户"。这是产品自己给现有生态制造的新攻击面 | 低（纯运维纪律） |
| 21 | 每部署独立密钥 | **所有密钥由 `nethub init` 在部署者机器上生成，按服务分文件存放，每个容器只拿到自己需要的那几份**：domain-claim 签名密钥（只给 authz）；frps auth token（每部署一份、所有设备共用；frps 与 authz 持有，authz 在 enroll 响应里把它交给设备。它只是进入 frps 的第一道门，每台设备的身份靠签名声明 + `device_secret`，见 §6）；frps admin 用户名/密码（frps + authz）；`nethub_owner` / `nethub_web` / `nethub_authz` / `nethub_backup` 四个 Postgres 角色的密码（各归对应服务：`nethub_owner` 只给 `nethub migrate`，`nethub_backup` 只给 `backup`）；Postgres 引导超级用户的密码（官方镜像的 `POSTGRES_PASSWORD`，只给 postgres 容器首次初始化用，运行时没有服务使用）；`NETHUB_SECRETS_KEY`（只给 web，用于加密 OIDC client secret）；session key（如果需要的话，只给 web）。上游不持有任何全局密钥 | 任何形式的内置默认密钥 / 上游签发；所有密钥写进一个共享 `.env` | 全开源自建的结构性红利：不存在"一把钥匙开所有实例"的东西。按服务分文件让决策 #4 的进程拆分在密钥层面也成立。同时也意味着**没有任何人能替部署者找回密钥**，`init` 必须强制提示备份，`doctor` 检查备份是否存在 | 低 |
| 22 | 控制台登录与外部身份绑定 | 本地密码（argon2id）+ **OIDC**（Authorization Code + PKCE、state + nonce，`coreos/go-oidc/v3` 做 issuer discovery 与 ID token 校验，支持多个 IdP）；外部身份**只按 `(issuer, subject)` 绑定**；新绑定只发生在从邀请链接发起的 OIDC 流程里，邀请 token 有效（未过期、未使用）、`email_verified=true`、email 与这条邀请一致三者同时成立；SAML 在 v1.1 | 按 email 绑定；只凭 email 认领任意一条待处理邀请；自助注册 / JIT 开户；v1 就做 SAML | email 在不同 IdP 之间不能证明是同一个人，按 email 绑定就是 §13 场景 #13 的账号接管。`email_verified` 本身也不能跨 IdP 信任——自建 Dex / Keycloak 的管理员可以把任意 email 标成已验证，也有 IdP 会发出未验证或可变的 email 声明——所以认领邀请的凭据是一次性的邀请 token，email 只是附加校验。OIDC 先行、SAML 放 v1.1 是用户 2026-09-17 的决定 | 低 |
| 23 | 共享认证模块 `authcore` 的用法 | **遵循 authcore 自己的准入逻辑**：只在某个包能替 NetHub 省掉一件"必须自己做对"的事时才引入，并钉到核实过的 tag（如 `@v0.6.1`）。v1 不需要它的任何包；可选 `captcha`（N 次登录失败后）与 `geoip`（审计视图里显示登录地点）；v1.1 用 `saml`；以后 `passkey` 作为控制台登录方式 | 为了"复用"而整体引入 | 依赖越少，自建者要信任的东西越少；authcore 为 Apache-2.0，许可证兼容 | 低 |

---

## 4. 设备侧插件设计

**包名** `os-nethub-agent` · **目标平台** OPNsense 26.7 / FreeBSD:15:amd64（arm64 留 v1.1）

```
src/os-nethub-agent/
  FRP_VERSION                                  # 决策 #19：CI 与 os-frp 的同名文件比对
  vendor/
    frp_0.71.0_freebsd_amd64.tar.gz            # 与 os-frp 同一份已验证产物，独立打包
    frp_0.71.0_freebsd_amd64.tar.gz.sha256
  src/
    usr/local/etc/rc.syshook.d/start/20-nethub-agent   # 开机后 reconcile 一次
    （看门狗的定时入口）                       # 决策 #14：独立看门狗；用哪种定时机制待实现时定
    usr/local/etc/rc.d/nethub_agent_frpc       # 结构照抄 os-frp/frpc 的 rc.d；独立的 pidfile / 日志 / daemon 标题
    usr/local/etc/inc/plugins.inc.d/nethub_agent.inc   # 文件名必须用下划线：OPNsense 用它拼钩子函数名
    usr/local/opnsense/
      mvc/app/controllers/OPNsense/NetHubAgent/
        Api/SettingsController.php
        Api/ServiceController.php
        Api/EnrollController.php                # enroll / unenroll / rotate
        IndexController.php
      mvc/app/models/OPNsense/NetHubAgent/
        NetHubAgent.xml  ACL/ACL.xml  Menu/Menu.xml
      mvc/app/views/OPNsense/NetHubAgent/index.volt
      scripts/nethub-agent/agentctl.py
      service/conf/actions.d/actions_nethub-agent.conf
      service/templates/OPNsense/NetHubAgent/{+TARGETS,frpc.toml.j2}   # 渲染到 /usr/local/etc/nethub-agent/frpc.toml
      version/nethub-agent
  tests/                                        # pytest + 协议契约测试（见 §2）
```

### 语言

**设备侧全部是 Python 3.13（`agentctl.py`）+ PHP/Phalcon MVC，这是 OPNsense 决定的，v0.3 不变。
设备侧 v1 没有一行自己写的 Go/daemon 代码**——唯一的二进制是 vendored、未经修改的 `frpc`。
（服务端改成了 Go，见决策 #5；整个项目里 Python 只用于 `agentctl.py` 和 `weekend0/probe.py`。）

### `agentctl.py` 的五个子命令（全部幂等）

| 命令 | 行为 |
|---|---|
| `enroll <token>` | POST 控制面 `/api/v1/devices/enroll`（经 Caddy 443 转给 `nethub authz`），请求里上报 `platform`、`platform_version`、`agent_version`、`agent_protocol_version` 与 `capabilities`（v1 只有 `remote.web`）；把返回的 `device_id / device_secret / frp_token / server_addr / server_port（7000）/ subdomain（authz 随机分配）/ domain_claim` 写入 Settings 模型。写入前逐字段白名单校验；已有非空 `DeviceId` 直接返回成功 |
| `reconcile` | 先查 kill switch 文件（决策 #10）→ 渲染 `frpc.toml` 到临时文件 → `frpc verify` 通过才 `mv` + 按需 restart（决策 #13）；不通过则保留旧文件、写本地状态、**不重启**。由 `newwanip` 触发时带防抖（决策 #17） |
| `status` | rc.d 状态 + 本插件 frpc 日志的尾部 + 上次 reconcile 的结果/失败原因 + 证书剩余天数（v1.1），拼 JSON 给 GUI。**不启用 frpc 的 `[webServer]`**（原因见下方共存规则）；设备在不在线由控制面另行通过 `last_seen_at` 掌握 |
| `unenroll` | 停服务、清空凭证字段、通知控制面注销 |
| `rotate` | 拉一套新凭证/新中继地址，原地更新并 reconcile 一次，不需要重走带外流程（决策 #18） |

### 与 configd / MVC / rc.d 的关系

- 所有特权动作走 `actions_nethub-agent.conf` 里**显式注册**的 configd action，PHP Controller 只是转发。
  控制面无法执行任意 shell——这是 OPNsense 原生权限分离模型送给我们的，必须守住。
- 渲染走官方 `service/templates` + `+TARGETS`，不自己写文件 I/O。
- 开机收敛走 `rc.syshook.d/start/`，补上「config.xml 被恢复到一台已装本插件的机器上」这条 `+POST_INSTALL` 覆盖不到的路径。
- **`+POST_INSTALL` 必须手写四步**（native 管线不走官方 `Mk/plugins.mk`，这几步官方流程下是自动生成的）：
  `configctl template reload OPNsense/NetHubAgent` → `run_migrations.php` → ACL/菜单缓存刷新 → `configd restart`。
  直接抄 `os-mihomo`/`os-sing-box` 现成实现，不重新发明。
- `plugins.inc.d/nethub_agent.inc` 注册 Services 状态页 + `bootup`/`newwanip` 钩子（函数名 `nethub_agent_services()` 等；PHP 函数名不能含连字符）。是否注册 `newwanip` 待确认：打包仓库的 `os-frp` 故意不注册，理由是 frpc 自己会重连（见其 `frp.inc` 注释），与决策 #17 的取舍需要用户拍板。
- **HA/CARP**：enroll 时加一个可选字段标注"本机是 CARP 集群成员"，v1 不做任何自动化，只在控制台标注，
  供人工判断"这几台同时异常是不是同一次 failover"，并作为决策 #4 降级为告警的参考信号。

### 与 `os-frp` 同机共存

用户可能同时装着 `os-frp`（用于他自己的 frpc/frps）。决策 #2 已经决定不复用它；这里把"互不干扰"落成具体规则
（来自 2026-09-17 的分析）：

- **os-frp 装的东西**：`/usr/local/sbin/frpc`、`/usr/local/etc/frp/frpc.toml`、rc.d `frpc`、`rc.conf.d/frpc`，
  以及它自己的 pidfile 和日志（它还带 frps 的 rc.d，同样不碰）。
- **NetHub 一样都不复用**：
  - 二进制 `/usr/local/opnsense/nethub-agent/bin/frpc`；
  - 配置 `/usr/local/etc/nethub-agent/frpc.toml`，由模板渲染；
  - rc.d 名 `nethub_agent_frpc`；
  - 独立的 pidfile、日志路径和 daemon 标题。
- **不启用 frpc `[webServer]`**：它的默认 `127.0.0.1:7400` 会和 os-frp 的管理界面撞端口。`agentctl.py status`
  改用三个来源：rc.d 状态、日志尾部、上次 reconcile 的结果；控制面另有 `last_seen_at`。
- **`FRP_VERSION` 文件**：两个包各带一份，CI 据此执行决策 #19。
- Weekend 2 的验收就在一台同时装着且正在运行 os-frp 的测试机上做（§10）。

### 与现有 Kazuha 仓库的复用点

- **打包**：`packaging/plugins.json` 加一条 entry，写法与现有声明 `python313` 依赖的插件一致
  （截至 2026-10-16 共 6 个：os-staticarp、os-easytier、os-ddns-go、os-lucky、os-sing-box、os-unboundcustom）。
- **version_file**：每个插件各自在 `plugins.json` 里声明 `version_file` 路径，由通用管线生成。
  （注意：`os-kazuha-repo` **只**维护它自己的 `version/kazuha-repo`，包内容被显式校验为只含 3 个文件，
  它不会替其它插件写版本文件——照惯例加一条自己的即可。）
- **vendor 二进制**：复用与 `os-frp` 相同的 `frp_0.71.0_freebsd_amd64.tar.gz`，
  安装到 `/usr/local/opnsense/nethub-agent/bin/frpc` 避免冲突；版本一致性由决策 #19 的 CI 兜底。
- **`+TARGETS`/Jinja2/pytest/native builder**：整套复用。

---

## 5. 传输层与远程访问

### 端口（v0.3 统一口径）

**公网：**

- **443**：Caddy，承载控制台和设备 enroll API（`/api/v1/devices/*` 转给 `nethub authz`，其余给 `nethub web`）；
- **7000**：frps `bindPort`，设备控制通道，TLS；
- **8443**：frps `vhostHTTPSPort`，浏览器 → 设备，SNI 透传。

**只在内部**（docker 内部网络，不映射到公网）：frps admin API / `[webServer]`（authz 轮询它）；authz 的 `httpPlugins` 端点；Postgres。

### 控制通道 = 远程 UI 通道

- frp 0.71.0，client → server 走 TCP，连到 frps `bindPort = 7000`，`[transport.tls] enable = true`。
  **注意：只开 TLS、不配 CA 时 frpc 不校验 frps 的证书，控制通道没有服务端认证，见 Q10。**
- `frps` 开 `vhostHTTPSPort = 8443`、`subDomainHost = "<部署者的域名>"`。
- 设备侧渲染出唯一一块 `[[proxies]]`：`localIP = "127.0.0.1"`、`localPort = 443`、
  `subdomain = "<subdomain>"`，由 frps 拼成 `<subdomain>.<subDomainHost>`。
  不能写成 `customDomains = ["<subdomain>.<部署者域名>"]`：frps 0.71.0 会拒绝落在 `subDomainHost` 之下的
  custom domain（`pkg/config/v1/validation/proxy.go` 的 `validateDomainConfigForServer`，https 代理同样走这条校验），
  代理注册直接失败。`customDomains` 只留给以后"客户自带域名"的场景。
- **SNI/TCP 层透传，不解密、不改写 HTML/JS。** OPNsense 自己的 Phalcon 前端完全不受影响——
  path-prefix 反向代理（绝对路径、CSRF token、WebSocket 全都会炸）从一开始就排除。
- **frp 遇到未知配置字段直接失败（fail closed）。** frp 默认 `--strict_config=true`：frps / frpc 解析到不认识的字段
  会报错退出，**不会**静默忽略。这对决策 #13 的"验证后应用"是好事；对手写配置则意味着 TOML 表作用域一旦写错
  （本该是顶层的键写在了某个表头之后，被解析进那张表）就起不来。v0.2 的 Weekend 0 套件就有这个问题，
  v0.3 已修正，并在启动前加了 `frps verify` / `frpc verify` 一步。

### 域名归属校验（决策 #4 的落地）

- `httpPlugins` 做主校验：`Login` + `NewProxy`——**签名声明有效 且 与 DB 记录一致**才放行；
  `NewProxy` 比对的是请求里的 `subdomain`。v1 的 `NewProxy` 拒绝规则写死为：
  `custom_domains` 非空、`proxy_type` 不是 `https`、`subdomain` 与该设备的 DB 记录不一致，三者任一即拒绝。
  原因：frps 0.71.0 本身只拒绝落在 `subDomainHost` 之下的 custom domain，泛域名的根本身、以及任何外部域名都能注册。
  如果允许，一台设备就能在 8443 上注册**控制台自己的域名**；cookie 不区分端口，访问 `https://<控制台域名>:8443` 的管理员浏览器
  会把控制台 cookie 发给这台设备（任何 member 的设备都行）。所以**任何设备都不能承载控制台的域名**。
  另外，若控制台放在设备泛域名的根上，控制台的 HSTS 不能带 `includeSubDomains`，否则浏览器不再允许点过设备自签名证书的警告。
  （`custom_domains` 留给以后的"客户自带域名"场景，届时另行设计校验。）
  v0.3 另加 `NewUserConn`：Weekend 0 先只收集数据，只有 Q7 获批才用于拦截。
- 签名声明 = 对规范化载荷 `{device_id, subdomain, tenant_id, issued_at, key_id}` 做 HMAC-SHA256；
  `key_id` 让签名密钥可以轮换。只有 authz 签名、也只有 authz 验签，所以对称密钥（HMAC）就够了。
- 签名密钥由 `nethub init` 生成，是一个**只挂进 authz 容器**的文件；web 进程读不到这个文件，
  它的 Postgres 角色也写不了子域名和声明字段（§6）。
- authz 每 15s 轮询 frps admin API（只在内部网络）核对活跃代理；连续 3 次异常才判定要断线，避免单次竞态误伤；
  判定和执行结果都写入 `audit_log`。人工「确认失窃、立即断」旁路保留（跳过连续确认）：web 只能写撤销标记，
  断线由 authz 经下面的候选机制执行——轮询器自己断不了线，"立即"实际能有多快取决于 Weekend 0 选定的机制。
- **轮询只能发现，不能断线。** 已对 frp v0.71.0 源码核实（`server/api_router.go`、`server/http/controller.go`、
  `server/http/controller_v2.go`）：admin API 除了列出客户端 / 代理 / 流量的只读接口，只有两个写接口——
  `DELETE /api/proxies?status=offline` 与 `POST /api/v2/system/prune`——都只清理**离线**代理；
  没有任何接口能断开一个在线的客户端或代理。不另找机制的话，被撤销或被盗的设备会一直保持隧道，
  直到它自己因为别的原因重连（重连时 `Login` 校验才会把它挡住）。候选机制如下，**全部未经实测**，列为 Weekend 0 验证项（§10）：
  1. **拒绝 `Ping`，配合显式心跳。** `tcpMux = true`（默认）时 frpc 的应用层心跳默认关闭（`heartbeatInterval` 默认 -1，
     见 `pkg/config/v1/client.go` 的 `Complete`），frps 的 `heartbeatTimeout` 同样默认 -1。所以要由设备侧模板渲染显式的
     `transport.heartbeatInterval`、frps 设置显式的 `transport.heartbeatTimeout`，并把 `Ping` 加进 `httpPlugins` 的 ops
     （`Ping` 请求带 `user.metas` 与 `run_id`，足以对应到设备）。之后 authz 对已撤销设备的 `Ping` 返回 reject。
     按源码，frps 会回一个带错误的 `Pong` 且不刷新心跳时间：正常的 frpc 收到后自己关闭整个会话，
     所以撤销后**约 0 到一个 `heartbeatInterval`**（下一次 `Ping`）就会断开；重连时再被 `Login` 挡住。
     不理会错误 `Pong`、也不再发心跳的（被改过的）frpc，要等 frps 的 `heartbeatTimeout` 到期——而且按源码，
     frps 这一侧的超时只关闭控制流和代理监听，**已经打开的工作流可能继续存活**。这是残余风险（见 §12），正常 frpc 测不出来。
  2. **拒绝 `NewUserConn`。** 对已撤销设备的每条新浏览器连接直接拒绝，能立即挡住新访问；
     但控制连接和代理注册都还在，已建立的连接也不受影响——这是"挡访问"，不是"断线"。
  3. **重启 frps。** 断开全部设备，再由 `Login` 挡住被撤销的那台。影响所有设备，只适合作人工「立即断」的最后手段。
  4. **给 frps 打补丁**加一个断开接口。最直接，但要长期维护 frp 分支，与决策 #19 的"同版本、未修改"相冲突。

  **机制 1 的可用性代价（必须和它的断线能力放在一起权衡）。** 一旦 frps 把 `Ping` 订阅给 authz 插件，`Ping` 就和
  `Login` / `NewProxy` 一样 fail-closed：`pkg/plugin/server/manager.go` 的 `handleMutableContent` 把插件调用的任何错误
  （连接失败、HTTP 状态码非 200、响应解析失败）都当作拒绝处理。下面的路径已对 v0.71.0 源码核实（只读过源码，未经实测）：
  - authz 崩溃、正在重启（连接被拒）或返回 500：frps 回一个带错误的 `Pong`、不刷新心跳时间（`server/control.go` 的 `handlePing`），
    frpc 收到后立即关闭会话（`client/control.go` 的 `handlePong`）；
  - authz 挂起（进程卡死、数据库卡住）：frps 调插件用的 `http.Client` 没有超时，请求上下文也没有 deadline；
    同一条控制连接上的消息是串行处理的（`pkg/msg/handler.go`，`Ping` 没有包 `AsyncHandler`），所以 `Ping` 一直卡着、
    心跳时间不刷新，`heartbeatTimeout` 到期后 frps 断开这台设备；
  - 断开后重连要先过 `Login`，authz 没恢复就连不上；authz 恢复后 frpc 会按自己的退避自动重连。

  也就是说，authz 的一次故障会切断**每一条**已建立的隧道：崩溃、重启、返回 500 时约在一个 `heartbeatInterval` 内
  （各设备的下一次 `Ping`），挂起时在 `heartbeatTimeout` 内，
  而不只是挡住新连接。不订阅 `Ping` 时，authz 是**新连接**的单点：`Login` / `NewProxy` fail-closed，已在线的隧道不受影响。
  订阅之后，它就成了**全部远程访问**的单点。计划内的 authz 重启或升级同样会断掉恰好在那几秒里发心跳的设备。

  采用机制 1 时，下面三条缓解都是硬要求：
  - `Ping` 处理器只查 authz 内存里的撤销状态，**不碰数据库**。这份状态由后台定时从库里刷新，刷新失败时沿用上一份，
    不能因此把所有 `Ping` 都拒掉。何况每台设备每个心跳间隔都会来一次 `Ping`，这个量本来也不该每次查库；
  - authz 的插件处理器设严格的内部超时：`Login` / `NewProxy` 查库超时就明确返回拒绝，不让 HTTP 请求一直挂着
    （frps 不会替你超时）；`Ping` 的处理路径上不应有任何会阻塞的调用；
  - 健康检查 + 自动重启：docker 的 `restart` 策略只在进程退出时生效，容器被标成 `unhealthy` 并不会触发重启，
    所以 authz 要在自检失败时主动退出（或另配看门狗）。

  这三条只能缩短恢复时间，**挡不住断线**：authz 只要不可达超过约一个 `heartbeatInterval`，所有订阅了 `Ping` 的隧道
  都会被断开，`heartbeatTimeout` 设多大都没用（它只管挂起这一种情况）。真要避免断线，`Ping` 端点就必须始终可达，
  例如同一个地址后面跑两个 authz 实例——这超出 v1 的单机部署设定，只作为可选方向记下。

  这个代价到底多大由 Weekend 0 第 6 项实测：订阅 `Ping` 后让后端整体停掉 / 返回 500 / 挂起，看已在线的设备多久被断开、
  后端恢复后多久自动连回来（§10）。

  建议（**待 Weekend 0 数据，未定**）：1 作主机制，2 同时生效作补充（若 Q7 门禁落地，`NewUserConn` 本来就要接入），3 只作人工旁路的兜底。
  另一种取舍是不订阅 `Ping`，只用 2 挡新访问、等重连时被 `Login` 挡住，并如实接受"已建立的隧道断不掉"这一缺口。
  选哪一种，要看第 6 项测出的断线时延和可用性代价。
  控制连接断开后，已建立的浏览器连接是否随之断开、实际断线时延是多少，都要 Weekend 0 实测；在那之前本文不承诺任何断线时延。
- **`httpPlugins` 的具体字段名和 fail-open/fail-closed 行为需 Weekend 0 用真实二进制实测**——
  轮询的"发现"不依赖这些细节；但上面的候选断线机制本身就建立在 `httpPlugins`（`Ping` / `NewUserConn` / `Login`）之上，
  所以断线能否成立同样取决于实测结果。`NewUserConn` 对 `type = "https"` vhost 代理是否触发、
  `remote_addr` 是否为真实客户端 IP、拒绝是否真能挡住连接，同样要 Weekend 0 实测。

### 设备 GUI 的公网暴露面（Q7）

SNI 透传意味着：任何知道或猜到主机名的人，都能直接打开 `https://<subdomain>.<domain>:8443`，
看到这台设备的 OPNsense 登录页——控制台的登录和 SSO 不挡在它前面。v0.2 没写这一点。
候选缓解（frps `NewUserConn` 源 IP 门禁）、它的局限与推荐见 §14 Q7。无论是否上门禁，
文档都要如实写明这个暴露面，并建议在设备上开启 OPNsense 自带的 TOTP 两步验证。

### 一处诚实的删除

原方案有一条「远程会话并发上限 1、TTL 20 分钟」。**在 SNI passthrough 架构下这条无法实现**——
控制面连一次 HTTP 请求的边界都看不到，谈不上"会话"何时开始结束。删掉它，而不是留一条编不出实现方式的控制。
结构上每台设备本来就只有一个 `[[proxies]]` 绑定（模板渲染的产物），这是结构性保证；
真正管暴露窗口的是上面的断线机制（具体机制待 Weekend 0 实测）。保留"按租户每月中继流量的可见软计数器"（这是真实可测的指标）。

**v0.3 注**：如果 Q7 的 `NewUserConn` 门禁落地，它会以可测量的形式重新带回一个"远程会话"的概念——
但可见粒度是每条 TCP 连接，不是每个 HTTP 请求。

### frp 版本

- 暂时继续锁 **0.71.0**：与打包仓库里的 `os-frp` 一致（截至 2026-10-16 仍锁 0.71.0），守住决策 #19。
- frp v0.71.1 于 2026-10-14 发布：重连与控制连接修复、yamux 替换；配置字段名和 `pkg/plugin/server` 都没有变化。
- 计划（升级本身待用户确认）：`os-frp`、NetHub vendored 的 frpc、frps 镜像**三处一起**升到 0.71.1，
  在 Weekend 2 之前完成。按上面这份 diff，Weekend 0 在 0.71.0 上得到的结果可以沿用到 0.71.1。
- 两个 frp 安全公告（GHSA-26gq-p25f-99cp，影响 ≤0.70.0；GHSA-pq96-pwvg-vrr9，影响 ≤0.68.0）不影响 0.71.x。

### 被否决的方案

MQTT/NATS/gRPC 常驻双向通道（v1 没有下发需求，白付一个常驻连接的成本）、
Cloudflare Tunnel（隧道数硬上限、不支持 SNI passthrough、且与"自建"的定位冲突）、
frp XTCP P2P 打洞（成功率不可控，做不了"点一下就开"的 UX）、
`os-easytier` mesh（把 L3 mesh 引进来解决一个 L7 问题）、自研 QUIC/WireGuard mesh。

---

## 6. 控制面架构

### 服务组成（单台 VM，docker compose，无 K8s）

| 服务 | 说明 |
|---|---|
| `frps` | frp 0.71.0（与设备侧严格同版本）。公网 `bindPort 7000`、`vhostHTTPSPort 8443`，`subDomainHost=<域名>`；`[webServer]`（admin API）只监听内部网络，供 authz 轮询；`[[httpPlugins]]` 指向 `nethub-authz` 的内部端点，ops 为 `Login`、`NewProxy`（`NewUserConn` 视 Q7 而定；`Ping` 是候选断线机制，待 Weekend 0，见 §5）。admin API 没有断开在线连接的接口 |
| `nethub-web` | `nethub web`：公网控制台，React SPA + `/api/v1/console/...` JSON API。功能：本地与 OIDC 登录、用户与邀请、OIDC 提供方、设备列表、enroll token、撤销、审计视图。Postgres 角色 `nethub_web`。**永远不持有**签名密钥、frps admin 凭证和 frps auth token |
| `nethub-authz` | `nethub authz`：面向设备与中继。设备 API `/api/v1/devices/{enroll,rotate,unenroll,status}`（Caddy 从 443 转来）；frps `httpPlugins` 处理器（只在内部网络）；frps admin API 轮询器（只能发现异常，断不了在线连接；断线走 §5 的候选机制，待 Weekend 0 实测）。持有签名密钥（只挂进这个容器的文件）、frps admin 凭证，以及要交给设备的 frps auth token。Postgres 角色 `nethub_authz` |
| `caddy` | 公网 443，自动 Let's Encrypt；`/api/v1/devices/*` → `nethub-authz`，其余 → `nethub-web` |
| `postgres` | Postgres 16 单实例，不对外；四个角色 `nethub_owner`（只给迁移用）/ `nethub_web` / `nethub_authz` / `nethub_backup`（只给 `backup` 用）；另有官方镜像的引导超级用户，只在首次初始化时使用 |
| `backup` | 每日 `pg_dump` + 可选 `rclone` 到对象存储（自建者自己配）；以只读角色 `nethub_backup` 连接（见下） |

`nethub migrate` 以属主角色 `nethub_owner` 执行迁移，是一次性任务；运行时没有任何进程使用这个角色。

`backup` 不能用普通角色跑 `pg_dump`：所有租户表都 `FORCE ROW LEVEL SECURITY`，`pg_dump` 默认把 `row_security` 设为 off，
连接角色既不是超级用户、又没有 `BYPASSRLS` 时会直接报错，而不是导出一份不完整的数据。所以建议一个专用角色 `nethub_backup`：
`LOGIN` + `BYPASSRLS`，只读（例如授予预定义角色 `pg_read_all_data`；它本身不绕过 RLS，`BYPASSRLS` 仍要单独给），
没有任何写权限，密码只放进 `backup` 服务自己的密钥目录。具体做法随迁移定稿。
`nethub init` 与 `nethub doctor` 是同一个二进制的子命令（§7）。

### 进程拆分与权限边界（决策 #4 的落地）

一个二进制、两个运行角色、两个容器：

- **`nethub web`**（公网控制台，Postgres 角色 `nethub_web`）：
  - 可以 INSERT `enroll_tokens`（建议只按列授予，`created_at` / `expires_at` 只取数据库默认值，见下方安全论证）；
  - 可以 UPDATE `devices` 的 `revoked`、`revoked_at`、`revoked_by_user_id` 和展示用的 `label`；
  - **不能** INSERT `devices`；
  - **不能**写 `devices.subdomain`、声明字段（`domain_claim_issued_at`）、`device_secret_hash`，
    也不能改 `owner_user_id`、`tenant_id`、`cluster_hint`（后者是决策 #4 降级为告警的参考信号）。
- **`nethub authz`**（设备与中继，Postgres 角色 `nethub_authz`）：
  - 消费 enroll token、创建设备行、分配子域名——子域名由服务端随机生成，**客户端和 web 都不能指定**；
    新设备的 `owner_user_id` 取自该 enroll token 的 `created_by_user_id`；
  - 签发声明（只有它持有签名密钥）；
  - enroll 时租户尚未确定，按 token 查找走一个窄的 `SECURITY DEFINER` 函数（如 `consume_enroll_token(token_hash)`），
    除此之外不跨租户；
  - 对用户、会话、邀请、OIDC 相关的表没有任何权限。

**安全论证（如实写）：**

- 被攻破的 web **能**：
  - 生成 enroll token，从而以一个**新**子域名 enroll 一台**新**设备——这不是劫持已有设备；
  - 撤销设备（可用性攻击）；
  - 读设备元数据和审计日志；
  - 生成任意有效期的 enroll token：如果它对 `enroll_tokens` 有整表 INSERT 权限，就能直接把 `expires_at` 写到很久以后，
    §9 的"15 分钟过期"对被攻破的 web 就不成立，web 被清理之后攻击者手里仍可能留着能用的 token。
    建议：INSERT 只按列授予（`tenant_id`、`token_hash`、`created_by_user_id`），`created_at` / `expires_at` 取数据库默认值，
    `consume_enroll_token` 再在服务端按 `created_at` 强制一次最长有效期；
  - **借控制台钓鱼**：哪怕只有以 `nethub_web` 身份的 SQL 注入，也能插入一条攻击者知道明文、归属记到受害用户名下的 enroll token，
    用它 enroll 自己的机器，再把展示用的 `label` 改成和受害者某台真实设备一样——受害者在自己的设备列表里点"打开"，
    就到了一个仿冒的登录页；拿到代码执行时更简单，直接让"打开"返回任意 URL。它做不到的是在已有设备的**真实**主机名上放仿冒页；
    不核对主机名的用户不受保护（控制台打开设备时要显示主机名，见 `docs/console-api.md`）；
  - 如果 Q7 门禁落地：为任意设备登记任意源 IP，让门禁形同虚设。用户点"打开"这个动作只有 web 看得到，
    所以门禁的强度上限就是控制台的强度；
  - 以及它本来就拥有的：发邀请/建用户、改 OIDC 提供方配置、解密 OIDC client secret（它持有 `NETHUB_SECRETS_KEY`）——
    也就是拿下整个控制台。
- 被攻破的 web **不能**：
  - 为某个已有子域名拿到有效声明；
  - 改变某个子域名归谁。
- 这正是决策 #4 需要的性质：控制台被打穿 ≠ 能冒充已有设备去钓鱼。
- authz 被攻破 = 中继身份层被攻破。这和 v0.2 的"内部授权组件"是同一个信任点，只是现在它的暴露面小而明确：
  不提供控制台、没有用户会话、不碰用户表。它对 `devices` 有写权限，所以也能取消撤销、改设备归属。
  frps 进程被攻破的效果类似（它能不调插件、把任意子域名的流量转走，并且能读到每台设备 `Login` 里的声明）；
  Caddy 被攻破则能看到控制台密码与会话、enroll token，以及 enroll / rotate 响应里的设备凭证。见 `docs/threat-model.md` §4.6。
- web 角色还需要对 `enroll_tokens` 的少数列有 `SELECT`（`id`、`created_by_user_id`、`created_at`、`expires_at`、`used_at`），
  否则 `INSERT … RETURNING` 拿不回有效期，生成 token 的接口没法告诉用户何时过期。建议加上，具体随迁移定稿。
- **列级授权本身挡不住的一个口子**：web 能 UPDATE `revoked`，也就能把它改回 `false`，让一台已撤销（比如被盗）的设备重新连上。
  建议撤销做成单向的（例如用触发器只允许 `false → true`，恢复 = 重新 enroll），具体随迁移定稿。

### 规划中的 `server/` 目录（代码落地时定稿）

```
server/
  go.mod
  cmd/nethub/          子命令：web | authz | migrate | init | doctor
  internal/
    web/               控制台 JSON API + SPA 托管
    authz/             设备 API、frps httpPlugins 处理器、frps admin 轮询器
    claim/             domain-claim 格式、签名、验签
    auth/              本地密码（argon2id）、session、CSRF、登录限流
    oidc/              OIDC relying party（coreos/go-oidc v3 + x/oauth2）
    store/             Postgres 访问、角色、迁移
    audit/             audit_log 写入 + 哈希链
    clientip/          可信代理下的客户端 IP 解析
    frps/              frps admin API 客户端
  web/                 React + TS + Vite 源码
```

### 用户、角色与登录（v1 新范围）

**首个管理员。** `nethub init` 用本地密码（argon2id）创建首个管理员。这是 break-glass 账号；
本地密码登录始终保留，不因为配了 OIDC 就关掉。控制台要保证**任何时候都至少有一个启用中、带本地密码的 admin**：
停用或降级会破坏这一条时直接拒绝，避免 break-glass 账号被删光、只剩依赖 IdP 的管理员。

**角色（v1）：**

- `admin`：用户、邀请、OIDC 提供方、本租户的全部设备、审计。
- `member`：只管自己的设备（生成 enroll token、打开、撤销自己的设备）以及与自己相关的审计条目。

member 的设备查询额外按 `owner_user_id` 过滤；RLS 仍然只按租户。也就是说，**租户内按用户的隔离是应用层的**，
靠 `store` 层统一加过滤 + 测试覆盖（W3 验收），不是数据库强制的。

**单租户。** v1 每个实例恰好一个租户，每条数据库连接都把 `app.tenant_id` 设成实例租户。
这让登录查找保持简单——登录时不需要先确定"你是哪个租户"。

**邀请：**

- 管理员按 email + 角色发邀请；
- 邀请是一次性链接 token，库里只存哈希，会过期（如 72 小时）；
- 被邀请人接受时设置密码，或用 OIDC 登录完成绑定（OIDC 绑定必须从邀请链接发起，见下）。

**OIDC（v1）：**

- 支持多个提供方（"多 SSO"），由管理员在控制台里配置；
- 流程：Authorization Code + PKCE，带 state 与 nonce；
- ID token 用 `github.com/coreos/go-oidc/v3` 校验，走 issuer discovery（配合 `golang.org/x/oauth2`）；
- 身份按 `(issuer, subject)` 绑定，**从不只凭 email**；
- 登录只在两种情况下成功：
  1. `(issuer, subject)` 已经绑定到某个用户；
  2. 被邀请人**从邀请链接**发起 OIDC 登录：服务端把这条邀请绑进这次流程的 state（服务端记录，不交给浏览器决定），
     回调时**同时**满足三条才完成绑定并把邀请标为已用——该邀请 token 有效、未过期、未使用；ID token 带 `email_verified=true`；
     email 与这条邀请的 email 一致。没有从邀请链接进来的 OIDC 登录，即使 email 恰好匹配某条待处理邀请，也一律拒绝：
     `email_verified` 不能跨 IdP 信任（自建 IdP 的管理员可以把任意 email 标成已验证），认领邀请的凭据是一次性的邀请 token。
     可选：管理员把一条邀请限定到某一个提供方（例如在 `invites` 上加一个可空的 `provider_id`，随迁移定稿）。
- v1 不做自助注册，也不做 JIT 开户；按域名白名单的 JIT 可以作为以后的选项。
- OIDC client secret 落库前用 AES-256-GCM 加密，密钥 `NETHUB_SECRETS_KEY` 由 `nethub init` 生成，只有 web 持有。
- 被停用（`disabled_at` 非空）的用户不能再登录，其会话一并吊销。

**SAML（v1.1）。** 通过 `authcore/saml`，NetHub 只做纯 SP。

**会话：**

- 服务端 `sessions` 表；cookie 里只放不透明的随机 token（`HttpOnly`、`Secure`、`SameSite=Lax`），库里只存它的哈希；
- 空闲超时 + 绝对超时；会话可吊销。

**CSRF。** 每个 session 一个同步器 token，所有改变状态的请求都必须在自定义请求头里带上它。

**其他 Web 加固：**

- 严格的 Content-Security-Policy（例如 `default-src 'self'`、不允许内联脚本、`frame-ancestors 'none'`）；
- **没有服务端模板。** v0.2 的"SSR 模板注入"风险因此不复存在，换成"API 或 authz 的漏洞、XSS、SQLi、session 伪造"。

**登录限流。** 按 IP 和按账号，在进程内计数。v1 假设只有一个 web 实例（横向扩展时要换成共享存储，见 §12）。
可选：N 次失败后要求 `authcore/captcha`。

**客户端 IP：**

- 在 Caddy 后面，只信任来自配置的可信代理地址的 `X-Forwarded-For`；
- 如果代理头来自未声明的对端，打一条醒目的警告日志（Report-Portal 的 `proxySeen` 做法；
  authcore ADR 0003 解释了为什么它没有做成共享包）；
- 解析出的 IP 用于登录限流和审计。authz 的设备 API 同样在 Caddy 后面，适用同一规则。

**SSO 不保护设备 GUI。** 隧道后面的 OPNsense GUI 仍由它自己的登录把守；控制台的密码、OIDC 和会话都不在那条路径上。见 Q7。

### authcore 的使用

`KazuhaHub/authcore`（用户 2026-10-16 确认模块拆分已完成）当前为 v0.6.1，包含 `captcha`、`geoip`、`passkey`、`saml`
四个包；没有 `oidc` 包；`audit` 已移除（authcore ADR 0002）；`ratelimit` 已移除、`clientip` 已回退（authcore ADR 0003）。

NetHub 遵循 authcore 自己的准入逻辑（决策 #23）：

- 某个包能替 NetHub 省掉一件"必须自己做对"的事，才引入；钉到核实过的 tag（如 `@v0.6.1`）。
- v1：不需要任何包。可选 `captcha`（N 次登录失败后）、`geoip`（审计视图里显示登录地点）。
- v1.1：`saml`。
- 以后：`passkey`，作为控制台登录方式之一。
- 因此 OIDC RP（`internal/oidc`）、审计哈希链（`internal/audit`）、登录限流（`internal/auth`）、
  可信代理 IP 解析（`internal/clientip`）都在 NetHub 自己的代码里。
- authcore 是 Apache-2.0，许可证兼容。

### 数据模型

```sql
tenants(id, name, created_at)                  -- v1：每个实例恰好一行

users(id, tenant_id, email,
      password_hash /* argon2id；只用 OIDC 登录的用户为 NULL */,
      role /* 'admin' | 'member' */,
      created_at, disabled_at,
      UNIQUE (tenant_id, email))

user_identities(id, tenant_id, user_id, provider_id /* → oidc_providers */,
                issuer, subject, email_at_link, created_at,
                UNIQUE (issuer, subject))      -- 绑定只认 (issuer, subject)

oidc_providers(id, tenant_id, slug UNIQUE, display_name, issuer_url,
               client_id, client_secret_enc /* AES-256-GCM，密钥 NETHUB_SECRETS_KEY */,
               scopes, enabled, created_at)

invites(id, tenant_id, email, role, token_hash UNIQUE, created_by_user_id,
        created_at, expires_at /* 如 72h */, used_at)

sessions(id, tenant_id, user_id, token_hash UNIQUE,
         created_at, expires_at, last_seen_at, ip, user_agent)

devices(id, tenant_id, owner_user_id,
        hostname,
        label,                         -- 控制台可改的展示名，不参与任何校验（v0.3 新增）
        platform TEXT NOT NULL,        -- v1 只有 'opnsense'，见 §2 多平台留门
        capabilities TEXT[] NOT NULL,  -- v1 OPNsense agent 只声明 {'remote.web'}
        device_secret_hash /* argon2id */,
        subdomain UNIQUE,              -- authz 随机生成，客户端与 web 都不能指定
        domain_claim_issued_at,
        cluster_hint,                  -- CARP 标注，可空，纯展示；也是决策 #4 降级为告警的参考信号
        agent_protocol_version,        -- 见 §2 协议漂移
        enrolled_at,
        revoked BOOLEAN DEFAULT false, revoked_at, revoked_by_user_id,
        last_seen_at,
        platform_version,              -- v0.2 叫 opnsense_version
        agent_version)

enroll_tokens(id, tenant_id, token_hash UNIQUE, created_by_user_id,
              created_at DEFAULT now(), expires_at DEFAULT now() + interval '15 min', used_at)
              -- web 只按列 INSERT，两个时间列只取默认值；consume_enroll_token 另行强制最长有效期

audit_log(id, tenant_id,
          actor_type,   -- 'user' | 'system' | 'device'
          actor_id, action, target_device_id,
          payload JSONB, prev_hash, entry_hash, created_at)
```

**没有 `frp_token_hash`。** v0.2 的 DDL 有这一列，但 frps auth token 是每部署一份、所有设备共用的密钥（决策 #21），
frps 内置的 `auth.token` 也只能校验这一份，每设备存一份它的哈希没有意义。每台设备的身份靠两样东西：
`Login` / `NewProxy` 时校验的签名声明（+ DB 记录），以及设备 API（rotate / unenroll / status）用的 `device_secret`。
共享 token 泄露的补救是换掉它并对在线设备 `rotate`（决策 #18）。

**RLS**：上面每张带 `tenant_id` 的表——`users`、`user_identities`、`oidc_providers`、`invites`、`sessions`、
`devices`、`enroll_tokens`、`audit_log`——都 `ENABLE` + `FORCE ROW LEVEL SECURITY`，
策略 `USING (tenant_id = current_setting('app.tenant_id')::uuid)`（写入同样加 `WITH CHECK`）。
每条连接建立时把 `app.tenant_id` 设为实例租户（v1 单租户）。`tenants` 表本身没有 `tenant_id` 列，不挂这条策略。
member 的设备/审计查询额外按 `owner_user_id` 过滤（应用层，见上）。

实现时注意：`FORCE` 让表属主同样受 RLS 约束，所以 `consume_enroll_token` 这类需要在租户未知时查到行的
`SECURITY DEFINER` 函数，其属主要带 `BYPASSRLS`（例如由不参与任何运行时连接的 `nethub_owner` 持有）；
函数固定 `search_path`、只返回最少字段、只把 `EXECUTE` 授给 `nethub_authz`。具体做法随迁移定稿。

**列级授权**（与上面的进程拆分一一对应；示意，不是最终 SQL）：

```sql
-- nethub_web：公网控制台
GRANT INSERT (tenant_id, token_hash, created_by_user_id) ON enroll_tokens TO nethub_web;
--   created_at / expires_at 不授予，只能取默认值
GRANT UPDATE (revoked, revoked_at, revoked_by_user_id, label) ON devices TO nethub_web;
--   没有 INSERT ON devices；
--   没有 subdomain / domain_claim_issued_at / device_secret_hash /
--   owner_user_id / tenant_id / cluster_hint 的 UPDATE；
--   建议 SELECT 也按列授予，不给 web 读哈希列。
--   users / invites / sessions / oidc_providers / user_identities 由 web 管理。

-- nethub_authz：设备与中继
GRANT EXECUTE ON FUNCTION consume_enroll_token(...) TO nethub_authz;
GRANT SELECT, INSERT, UPDATE ON devices TO nethub_authz;  -- 建设备行、分配子域名、更新 last_seen_at 等
--   对 users / invites / sessions / oidc_providers / user_identities 没有任何权限。

-- audit_log：两个运行时角色都只能追加（INSERT），没有 UPDATE / DELETE。

-- nethub_backup：只给 backup 服务的 pg_dump
--   LOGIN BYPASSRLS；GRANT pg_read_all_data TO nethub_backup；没有任何写权限。
```

两个进程都会追加 `audit_log`，哈希链的 `prev_hash` 需要串行化计算（例如在一个函数里加锁后取链头），随实现定稿。

**审计链的诚实限定**：`audit_log` 的哈希链只防意外损坏与误操作追溯，
**不**构成对抗"数据库写权限已泄露"（SQLi、主机被攻破、内部人员）的强证据——
真正防这类威胁的是决策 #4 的签名声明，不是哈希链。文档里就这么写，不要包装成"简化版 Rekor"。
v0.3 的"只追加"授权让误操作更难，但不改变这个结论。

### 规模与成本（自建者视角）

| 规模 | 配置 | 月成本（参考 Hetzner/同档 VPS） |
|---|---|---|
| 1–100 台 | 2 vCPU / 4GB | ~$5–15 |
| 100–1000 台 | 4 vCPU / 8GB | ~$20–40 |
| 1000–5000 台 | 需要把 frps 与 `nethub web` / `nethub authz` 拆到不同主机，中继带宽成为主成本 | 按带宽计，不是按 CPU |
| >5000 台 | **超出本架构范围，需要另行设计**；不为不存在的规模编数字 | — |

真正的成本变量不是 CPU 而是**中继带宽**：远程 UI 流量全部经过中继。
一次典型的 OPNsense GUI 操作会话在几 MB 量级，但如果有人用它传文件就不是了——
所以每租户流量软计数器（可见、可告警，v1 不硬拦截）是必须的。

---

## 7. 自建部署体验（P0，不是收尾工作）

**这一节是开源自建项目的生死线。** 自建类项目死在"装不起来"这一关的，比死在功能上的多得多。
原方案假设部署者就是作者本人、域名和 DNS 都是现成的——对外发布时这个假设不成立。

### 部署者必须先具备的前置条件（README 第一屏就要写清）

1. 一个域名，且能配 DNS 记录；
2. 一条**通配符 A/AAAA 记录** `*.router.example.com` → 中继服务器 IP（subdomain-per-device 的硬前提）；
3. 服务器的 **443**（控制台 + 设备 enroll API）、**7000**（frps `bindPort`，设备控制通道，TLS）与
   **8443**（vhost-https，浏览器 → 设备）可从公网访问；
4. v1.1 起：DNS-01 所需的 DNS 服务商 API token（用于每设备独立证书）。

### `nethub init` 交互式向导（`nethub` 二进制的子命令，Weekend 3 就要有雏形）

一条命令走完：询问域名 → 生成全部密钥（清单见决策 #21：签名密钥、frps auth token、frps admin 凭证、
四个 Postgres 角色（含 `nethub_backup`）的密码、Postgres 引导超级用户的密码、`NETHUB_SECRETS_KEY`、如需要的 session key）→ **按服务写出各自的密钥文件**
（如 `deploy/secrets/web/`、`deploy/secrets/authz/`，每个容器只挂自己的那一份；不写一个装着全部密钥的共享 `.env`）
与 `docker-compose.override.yml` → **强制提示备份密钥**（没有任何人能替你找回）
→ 创建首个管理员账号（本地密码，break-glass）→ 跑**启动前**的那部分预检（DNS、端口、密钥备份；
迁移跑过之后再加角色权限检查）。证书、`frps` ↔ authz 回环、最近一次 `pg_dump` 这几项要等栈跑起来才有意义，
由 `docker compose up -d` 之后单独运行的 `nethub doctor` 覆盖。

OIDC 提供方不在 init 里配：init 完成后由管理员在控制台里添加（可选；不配就只用本地密码登录）。

### `nethub doctor` 预检脚本（同样 P0，同一个二进制的子命令）

逐项检查并给出人话级的修复建议：

- `*.<域名>` 通配符解析是否指向本机公网 IP；
- 443 / 7000 / 8443 是否真的可从外部连通（用外部回响服务验证，不是 `netstat`）；
- 证书是否签发成功、剩余天数；
- `frps` ↔ `nethub authz` 的 `httpPlugins` 回环是否通；
- **web ↔ authz 分离是否成立**：web 容器里没有签名密钥文件、frps admin 凭证和 frps auth token；`nethub_web` 角色对 `devices`
  的身份列没有写权限（查 `information_schema.column_privileges` 一类的元数据，不做真实写入）；
- 密钥备份是否存在，且覆盖全部密钥（包括 `nethub_backup` 与 Postgres 引导超级用户的密码；决策 #21 / §13 场景 #12）；
  `backup` 最近一次 `pg_dump` 是否成功（连接角色缺 `BYPASSRLS` 时它会直接报错，见 §6）；
- `frps` 与已发布的 `os-nethub-agent` 的 frp 版本是否匹配（决策 #19）。

### 首次使用的 10 分钟路径

`nethub init`（生成密钥、写配置、创建首个管理员）→ `docker compose up -d` → 用管理员登录控制台 →
点"添加设备"拿到一次性 token → 在路由器 GUI 里 Services → NetHub Agent 粘贴 token 点 Enroll →
15 秒内设备列表显示在线 → 点"打开"，新标签页打开这台 OPNsense 的 GUI
（仍需用 OPNsense 自己的账号登录；若 Q7 的门禁落地，"打开"同时登记你当前的源 IP）。

**这条路径上任何一步需要读文档，就是一个要修的 bug。**

---

## 8. 配置模型

**v1 里这一整块是空的，这是故意的，不是没想到。**

- 控制面**从不**读写设备的 `config.xml`。唯一被本插件写入的是它自己 Settings 模型里的标量字段。
- 渲染出的 `frpc.toml` 是这些字段的**确定性函数**：恢复 config.xml → 开机 hook 重渲染 → 自动恢复。
  不需要 diff / patch / 镜像机制。
- `rotate` 不构成"控制面下发配置"——触发者仍是设备侧的显式调用，控制面无法推送任意内容。
- 3-way diff、漂移检测、Jinja2 渲染 config.xml 子树、commit-confirm 自动回滚——**全部推迟到 v2.5**。

推迟的真实理由（不是懒）：`config.xml` 里存在重复且无天然唯一键的节点，
通用 patch 语义在这种结构上不安全。v2.5 只做「全量渲染子树 + 替换」，不做通用 patch。

---

## 9. 安全设计

| 环节 | 设计 |
|---|---|
| 设备身份 / 域名归属 | 签名声明（HMAC-SHA256，`key_id` 可轮换）+ DB 记录双重校验（决策 #4；控制通道的服务端认证见 Q10）；`NewProxy` 拒绝任何 custom domain，设备不能承载控制台域名（§5）；`nethub web` / `nethub authz` 进程拆分，签名密钥只挂进 authz；列级授权：web 不能新建设备行、不能写子域名 / 声明 / 哈希列、不能改归属；子域名由 authz 随机生成 |
| 密钥归属 | 每部署自生成，上游不持有任何全局密钥；按服务分文件，每个容器只拿自己的（决策 #21） |
| 准入 | 设备：enroll token 一次性、15 分钟过期（由数据库默认值和 `consume_enroll_token` 强制，web 定不了有效期，见 §6）、带外交付；用户：只能经邀请（一次性、只存哈希、会过期），无自助注册 / JIT |
| 远程会话撤销 | authz 每 15s 轮询 frps admin API，连续 3 次（~45s）异常才判定该断线；轮询器**只负责发现**，**frps 0.71.0 的 admin API 断不了在线连接**。速率限制降级为告警；人工「确认失窃、立即断」旁路跳过连续确认（web 只写撤销标记）；判定与执行都在 authz。断线机制待 Weekend 0：候选为拒绝 `Ping` + 显式心跳、拒绝 `NewUserConn`、重启 frps（人工兜底），推荐组合（`Ping` 为主）**待 Weekend 0 数据，未定**；全部未经实测，验证之前不承诺断线时延。**代价**：订阅 `Ping` 后它同样 fail-closed，authz 的一次故障会在心跳窗口内切断全部已建立的隧道；缓解为 `Ping` 只查内存撤销状态、不碰数据库 + 严格内部超时 + 健康检查重启，代价由 Weekend 0 第 6 项实测（§5、§12） |
| 爆炸半径 | 控制面唯一写权限 = "决定这台设备的隧道能不能连上"。不能改防火墙规则、不能重启服务、不能读 config.xml |
| 设备侧权限 | 所有特权动作限定在显式注册的 configd action 内，无任意 shell 执行路径 |
| 本地熔断 | `/var/db/nethub-agent/disabled` flat file，不写 config.xml；onboarding 明确提示用户确认拥有**独立于本产品之外**的带外/物理访问手段 |
| 控制台防护 | 服务端 session（cookie 只放不透明随机 token：HttpOnly / Secure / SameSite=Lax，库里只存哈希；空闲 + 绝对超时，可吊销）+ 每 session 同步器 CSRF token（自定义请求头）+ 严格 CSP、无服务端模板 + 按 IP 与按账号的登录限流 + argon2id + OIDC 只按 `(issuer, subject)` 绑定（新绑定只在从邀请链接发起的流程里发生：邀请 token 有效 + `email_verified` + email 与邀请一致） |
| 控制台角色 | `admin` / `member`；member 只能操作自己的设备（应用层按 `owner_user_id` 过滤，RLS 按租户）；本地 break-glass 管理员不依赖任何 IdP |
| 客户端 IP | 只信任可信代理发来的 `X-Forwarded-For`；未声明的对端发来代理头时醒目告警；结果用于登录限流与审计 |
| 设备 GUI 暴露面 | SNI 透传下 `https://<subdomain>.<domain>:8443` 对任何知道或猜到主机名的人都是 OPNsense 登录页，控制台登录 / SSO 不在这条路径上。候选缓解：frps `NewUserConn` 源 IP 门禁（Q7，待 Weekend 0 实测与用户决定）；无论如何都如实写明，并建议开启 OPNsense 自带 TOTP 两步验证 |
| 审计 | `audit_log` 哈希链，人工动作**和**系统自动行为（断线、rotate、reconcile 失败）都记，认证事件（登录成功/失败、身份绑定、邀请）也记；运行时角色只能追加；防护范围有诚实限定（见 §6） |
| config.xml 写入安全 | 幂等 + 字段白名单 + 复用全局配置锁（决策 #16） |
| 灰度与回滚 | canary 发布（#15）+ 验证后才应用（#13）+ 独立看门狗回滚一次（#14） |
| CARP/HA | `newwanip` 防抖 + 抖动 + 控制台标注 + 异常判定降级为告警（#17） |
| 证书批量到期 | v1.1 存量迁移**打散签发时间**（按 device_id 哈希分桶）；到期前 30 天开始重试；`status` 上报剩余天数，<14 天标红 |
| 供应链 | frps/frpc 锁同版本 + CI 一致性检查（#19，两个包各带 `FRP_VERSION`）；签名私钥主机排除在部署范围外（#20）；`authcore` 钉到核实过的 tag（#23） |
| 可观测性 | 部署文档提供 uptime 监控接入示例（自建者自己接）；`doctor` 可定期跑 |

### 威胁模型要写进 docs/ 并公开

初稿已写在 [`docs/threat-model.md`](threat-model.md)（2026-10-16），以本文为准，随 Weekend 0 结果修订。

对一个能碰防火墙的开源项目，**公开的威胁模型本身就是产品的一部分**。
至少回答：控制面被攻破能做什么/不能做什么（分开写 web 被攻破与 authz 被攻破，§6）；单个租户越权的边界；
IdP 或 IdP 账号被攻破的后果；设备 GUI 的公网暴露面（Q7）；
设备被物理窃取的后果；供应链（pkg 签名 + docker 镜像）的信任根在哪。

---

## 10. MVP：W0–W7 + 缓冲

v0.2 的计划是 7 个周末（W0–W6 + 0.5 缓冲）。v0.3 的范围更大（多用户、OIDC、进程拆分），
排期变成 W0–W7 再加一段缓冲，**估算的不确定性也随之变大**——下面是计划，不是承诺。

### 测试环境

不写真实主机名、IP 或路径；需要的是：

- 一台公网 VPS 做中继；
- 一个能配通配符 DNS 的域名；
- 一台 OPNsense 26.7.x 机器或虚拟机（26.7.1_1 或更新），并且：
  - **不是**插件包的构建/签名主机——决策 #20 要求如此；打包仓库的专用测试机就是构建和签名主机，因此排除；
  - 不是生产路由器；
- 这台机器上同时装 `os-frp`，用于测试共存；
- 一部走 4G/5G 的手机，提供真实的 CGNAT 路径；
- 至少一个受限网络样本（运营商网络、公司网络等）。

### Weekend 0 — 传输层可行性尖峰（不写插件代码）

用修正后的 `weekend0/` 套件：手起一个 `frps`（`bindPort 7000`、`vhostHTTPSPort` / `subDomainHost`），
手工加一条 `[[proxies]]`，写几十行 Python `http.server`（`probe.py`）当 `httpPlugins` 后端打印真实 payload。
启动前先跑 `frps verify -c frps.toml` / `frpc verify -c frpc.toml`（`strict_config` 下配置写错会直接退出）。
**这是任何安全模型代码之前的闸门。**

**验收：**
1. 从真实 4G/CGNAT 打开 `https://test.<域名>:8443`，看到完整可用的 OPNsense 登录页并成功登录；
2. 拿到 `Login` / `NewProxy` 的真实字段名，确认能否按 `device_id` / `subdomain` 校验（`custom_domains` 只在以后的自带域名场景才需要）；
3. 让后端故意超时/返回 500/拒绝，并**按 op 分开**观察：`Login` 放行、只让 `NewProxy` deny / error500 / hang，
   看 frps 是 fail-closed 还是 fail-open；另跑一组 `Login` deny / error500，记录 Login 的行为——
   **这条直接决定"控制面单点故障"的真实严重程度**，结果写进风险清单（若订阅 `Ping`，单点的范围还要看第 6 项）；
4. 从至少一个受限网络样本（运营商 4G/5G、公司网络）测 8443 可达性与稳定性，**在同一个循环里交替采样同一台 VPS 上的 443 基线**，
   按 Q2 的规则决定是否需要 443 复用；
5. （Q7 数据）`NewUserConn`：对 https vhost 代理是否触发；`remote_addr` 是否等于手机的公网 IP（与手机上 IP 回显网站显示的对比）；
   一次 OPNsense 登录页加载会触发多少次；`deny` 时浏览器是否打不开页面而隧道保持注册；
   已打开页面的 keep-alive 连接是否不受影响、新连接是否被拦；
6. （断线机制）frps admin API 断不了在线连接（§5），验证候选机制：frpc 配显式 `transport.heartbeatInterval`、
   frps 配显式 `transport.heartbeatTimeout`、`Ping` 加进 ops 后，让后端对 `Ping` 返回 deny——frpc 是否断开、多久断开；
   frpc 不再发心跳时，frps 是否在 `heartbeatTimeout` 后断开它；断开后重连时 `Login` deny 是否挡得住；
   控制连接断开时，已建立的浏览器连接是否随之断开；`NewUserConn` deny 时控制连接是否保持。实测的断线时延写进风险清单。
   同时测机制 1 的可用性代价：订阅 `Ping` 之后，让后端**整体**停掉 / 返回 500 / 挂起（不是只拒某一台设备），
   已在线的设备是否在心跳窗口内全部被断开、多久断开，后端恢复后多久自动连回来。这组数字决定 §5 的建议能否成立，同样写进风险清单。

任一项不通过，先解决再继续。

### Weekend 1 — 插件骨架

`packaging/plugins.json` 加 entry；`Settings.xml` + ACL + Menu + 空 `index.volt`。

**验收：** ①`pkg install` 到测试路由器，Services 下出现菜单，能存 `Enabled` 并在 config.xml 看到字段；
②逐条核对 `+POST_INSTALL` 四步（`template reload` / `run_migrations.php` / ACL·菜单缓存 / `configd restart`）；
③确认测试机运行 OPNsense **26.7.1_1 或更新**：26.7 已知的 WAN 默认路由丢失 regression
（opnsense/core#10597，静态 WAN 网关 + gateway monitoring 开启时重启后默认路由可能不装载）已在 26.7.1_1 热修复（2026-07-23）。
"重启后失联，先查默认路由和 gateway monitoring"作为通用建议保留在 runbook 里。

### Weekend 2 — frpc 集成

vendor 二进制；rc.d；`+TARGETS` / `frpc.toml.j2`；reconcile 的「验证后应用」逻辑。在一台同时装着且正在运行 `os-frp` 的测试机上做。

**验收：** 手填 Weekend 0 的中继地址/token，服务能启动并连上；
**并且**故意渲染一份坏 `frpc.toml`，确认 reconcile 不重启、保留旧文件；
**并且** os-frp 照常工作（它的进程、配置和端口都不受影响）。

### Weekend 3 — Go 控制面骨架 + 部署体验

`nethub` 二进制；迁移 + Postgres 角色（§6；含 `nethub_backup`）+ RLS（含 `owner_user_id`）；`nethub web` 带本地管理员登录；
session / CSRF / 限流；React 外壳（登录、设备列表、生成 enroll token）；**`nethub init` 向导雏形**。

**验收：** 能登录、生成 enroll token、看到空设备列表；
`docker compose up` 在一台干净 VPS 上一次成功；
双账号 RLS 检查通过（两个租户各一个账号——v1 只有一个租户，测试里手工插入第二个——A 的连接看不到 B 手工插入的设备行；
同一租户内 member 只看到自己的设备）；
有一个测试证明 `nethub_web` 写不了设备身份列（`subdomain`、声明字段、哈希列），也 INSERT 不了 `devices`。

### Weekend 4 — 真实 enroll 全流程

`nethub authz`（enroll API、子域名分配、声明签发）；`frps` 的 `httpPlugins` 接到 authz；`proto/` JSON Schema；
契约测试同时覆盖 Go 服务端与 Python agent；`agentctl.py enroll`。

**验收：** 控制台生成 token → 路由器 GUI 粘贴点 Enroll → Settings 自动填好 → 服务连上 → 设备列表 15 秒内显示在线。

### Weekend 5 — 远程 UI 端到端 + 撤销

SNI 子域名链路打通；kill switch；撤销 = 轮询发现（连续确认）+ 按 Weekend 0 第 6 项结果选定的断线机制（见 §5；轮询器自己断不了线）；开机收敛 + cron reconcile（带防抖）；
若 Q7 获批，加上 `NewUserConn` 门禁。

**验收：** 手机开 4G，从控制台点开设备远程 UI 能登录 GUI；
切 kill switch 后隧道立即停且不碰 config.xml；点"撤销"后，被撤销设备的新浏览器连接被拒；
如果 Weekend 0 验证出了可用的断线机制，控制连接按它被断开，并记录实测断线时延（~45 秒是目标，不是承诺）；
如果没有，这一条只验"新连接被拒 + 重连时被 `Login` 挡住"，"已建立的隧道断不掉"如实写进风险清单；
若采用了拒绝 `Ping`，再验一次停掉 authz 时全部隧道的断开与恢复（§5）；
enroll 流程里提示"确认拥有独立于本产品之外的带外访问手段"；
若上了门禁：没在控制台点过"打开"的源 IP 连不上 8443。

### Weekend 6 — 多用户 + OIDC

角色、邀请、多个 OIDC 提供方、身份绑定规则、可信代理客户端 IP、认证事件写审计。

**验收：** 经两个不同的 OIDC 提供方都能登录（例如在 compose 里自建一个 Dex 或 Keycloak，外加一个公共提供方）；
通过邀请完成的绑定可用；**只凭 email 的绑定被拒绝**；
**没有邀请链接、经另一个 IdP 用相同 email 认领邀请被拒绝**。

### Weekend 7 — 收尾加固与首次公开

即 v0.2 的 Weekend 6：`audit_log` 接上人工与系统动作；流量软计数器；`nethub doctor`；`rotate` 联调；
部署 runbook + 威胁模型文档；灰度发布演练一次；README / LICENSE / DCO。

**验收：** ①一台**不持签名私钥**的测试路由器走完"装插件 → 手机远程打开 GUI"全流程；
②找一位朋友**在他自己的服务器上**从零部署一次控制面并 enroll 他自己的设备——
这一条验的是第 7 节，是整个 MVP 里最容易被自己人忽略的验收项；
③故意推一个带 bug 的插件版本给 canary，验证 reconcile 拒绝应用、看门狗未误报、灰度流程工作正常。

### 缓冲

保留一段缓冲（对应 v0.2 的 "+6.5"）。范围变大之后，它更有可能被用掉。

---

## 11. 路线图

| 版本 | 内容 | 粗估 |
|---|---|---|
| **v1.1** | SAML（经 `authcore/saml`，纯 SP）；DNS-01 broker + 每设备独立 Let's Encrypt 证书（存量**打散签发时间**，避免到期扎堆撞限速）——注意证书会进入 CT 日志，主机名从此可枚举，Q7 的门禁因此更重要；续期失败告警；arm64 打包；评估 mTLS（Q1） | 2–4 周（v0.2 的估算，未含 SAML 与 mTLS 评估） |
| **v1.2 遥测** | 已装 `os-telegraf` 的设备，agent 读本地 `127.0.0.1:9273` 转发摘要指标；控制面加一张 `device_metrics` 表 + 折线图 | 2–3 周 |
| **v2 配置备份** | agent 定期用**设备自身派生的** AES-256-GCM key 本地加密 `/conf/config.xml` 后上传；控制面只存密文、**不持有解密能力**。仿 pfSense AutoConfigBackup 做滚动保留，不做 diff | 2 周 |
| **v2.5 配置下发** | 最难的一步。Postgres "intent" + Jinja2 全量渲染子树 + 3-way diff（仅展示漂移）+ **独立于 agent 进程之外的本地 commit-confirm 看门狗**（`rc.syshook config` + `bectl` 命名快照）+ interface 名漂移解析 + CARP master 探测。开工前必须单独跑一轮 CARP/接口漂移真机验证。（v0.3 注：控制面已改为 Go，渲染放在设备侧还是服务端随 v2.5 设计再定） | 3–5 周 |
| **v3 多租户** | `tenants` 从一行变多行，递归 org 树。v1 已上的 RLS 直接复用，不用补课。**仅在真有需求时做** | 按需 |

**以后的控制台登录选项**：经 `authcore/passkey` 的 passkey 登录。

**已知上游不确定性**：OPNsense 27.1 的官方 python/php 版本组合目前在仓库 `targets.json` 里标记为 disabled/pending。
决策 #12 把 `python313` 硬编码为依赖，v1 阶段无需处理，但升到 27.1 series 时可能要重新打包。
截至 2026-10-16，当前稳定版为 26.7.7（2026-10-13），27.1 预计在 2027 年 1 月前后发布。

---

## 12. 风险与 Non-goals

### 明确接受的风险

- 设备侧凭证明文落盘（与 OPNsense 自身存 API key 的方式同级）。
- v1 自签名证书浏览器警告（v1.1 有明确修复路径；根因层面的域名劫持已在决策 #4 修复）。
- `httpPlugins` 的 fail-open/fail-closed 行为在 Weekend 0 实测前是未知项；`NewUserConn` 对 https vhost 代理的行为同样未知。
- **断线机制未定**：frps 0.71.0 的 admin API 没有断开在线客户端或代理的接口（§5）。在 Weekend 0 验证候选机制之前，
  被撤销或被盗的设备可能一直保持隧道，直到它自己重连、被 `Login` 校验挡住为止；"撤销后 ~45 秒断线"只是目标。
- **authz 是新连接的单点；若订阅 `Ping`，就成了全部远程访问的单点。** 按源码 `Login` / `NewProxy` fail-closed：
  authz 故障时，新建或重连的设备连不上，已在线的隧道不受影响。候选断线机制 1 把 `Ping` 也交给 authz 之后，
  authz 的一次崩溃、挂起或数据库卡顿会在心跳窗口内切断**每一条**已建立的隧道，计划内的重启也会断掉一部分设备（§5）。
  缓解：`Ping` 只查内存里的撤销状态、不碰数据库；严格的内部超时；健康检查 + 自检失败即退出、由容器重启。
  这些只缩短恢复时间：authz 不可达超过约一个心跳间隔，订阅了 `Ping` 的隧道仍会全部断开。
  代价大小由 Weekend 0 第 6 项实测；是否采用机制 1 待这组数据，未定。
- **被改过的 frpc 可能让已打开的连接活过撤销。** 不理会错误 `Pong`、不再发心跳的 frpc，只会在 frps 的
  `heartbeatTimeout` 到期后失去控制流和代理监听；按源码，它已经打开的工作流可能继续存活。正常 frpc 会自己关闭整个会话，
  所以这条只针对被篡改的设备端，Weekend 0 用正常 frpc 测不出来（§5）。
- **单台控制面 VM 是单点故障**：中继挂了，所有设备远程访问同时失效。v1 明确接受，无热备。
  自建场景下这是部署者自己的运维选择，文档要说清楚而不是假装没有。
- 在线状态只反映 frpc 控制连接是否存活，**不反映 OPNsense GUI 本身是否健康**。
- **重启后默认路由没装上**：OPNsense 26.7 的 WAN 默认路由丢失 regression（opnsense/core#10597）已在 26.7.1_1 热修复
  （2026-07-23），测试与部署要求 26.7.1_1 或更新。但同一大类故障仍可能由别的原因引起，
  而 `newwanip` 触发的 reconcile 救不了这种情况（路由都没装上，frpc 根本连不出去）。
  **无技术防线**，runbook 写清"重启后失联第一排查项：检查默认路由与 gateway monitoring"。
- `rotate` 依赖设备在线：强制轮换窗口内恰好离线的设备需要手动重走 enroll。
- 签名私钥主机的隔离（决策 #20）是**运维纪律而非技术强制**，彻底方案（离线签名机）见 Q4。
- **设备 GUI 公网暴露（Q7）**：知道或猜到主机名就能打到 OPNsense 登录页；v1.1 证书进 CT 日志后主机名可枚举。
  门禁定下来之前，这个暴露面只能靠 OPNsense 自己的登录与两步验证兜底。
- **IdP 或 IdP 账号被攻破**：等于拿到所有与之绑定的用户的控制台访问（若绑定的是 admin，就是管理员权限：
  发邀请、撤销全部设备、看审计）。边界由决策 #4 限定：照样拿不到已有子域名的有效声明、改不了归属、读不了 config.xml；
  设备 GUI 仍有自己的登录；本地 break-glass 管理员不依赖任何 IdP。
- **被攻破的 web 能撤销全部设备、读元数据与审计**（§6 安全论证）：接受；这是可用性攻击与信息泄露，不是设备冒充。
  若 Q7 门禁落地，它还能为任意 IP 打开门禁——门禁的强度上限就是控制台的强度。
- **登录限流在进程内**：v1 假设单个 web 实例，横向扩展时要换成共享存储。
- **范围增长**：多用户、OIDC、进程拆分让 MVP 从 7 个周末变成 W0–W7 + 缓冲，估算更不确定。

### Non-goals（长期不做，明确划界）

- **不做爱快式计费 / Portal 认证 / 实名认证**——那是它真正的护城河，不该假装在做。
- **不做 TR-069/CWMP**——FreeBSD/OPNsense 生态零先例。
- **不做自建通用配置下发协议**——config.xml 的结构决定了通用 patch 语义不安全；v2.5 只做全量渲染替换。
- **不做 WeChat/企业微信集成**（v1–v2.5 范围内）。
- **v1 不做设备级 mTLS 客户端证书**（见 Q1）、**不做 8443→443 复用**（见 Q2）。
- **v1 不做自助注册与 OIDC JIT 开户**、**不做 SAML**（v1.1）。

---

## 13. 灾难场景与设计防线

| # | 场景 | 触发路径 | 防线 |
|---|---|---|---|
| 1 | 控制面被攻破 → 拿用户"点掉警告"的习惯钓鱼 | 控制台出洞（API 越权/SQLi/XSS/session 伪造）→ 改 DB 域名归属 → 自己的 frpc 冒充受害设备；另一条路径是设备到中继之间的中间人截取声明（Q10） | 决策 #4 双重校验 + web/authz 进程拆分 + 列级授权（web 写不了子域名与声明列、拿不到签名密钥）；控制通道服务端认证（Q10）；根因不是证书类型而是归属校验。残余：被攻破的控制台仍能在设备列表里放仿冒条目（§6），靠用户核对主机名 |
| 2 | 租户内越权（member A 看到/撤销 member B 的设备） | 某个端点漏了 `owner_user_id` 过滤 | `store` 层统一按 `owner_user_id` 过滤 + Weekend 3 测试；`FORCE RLS`（决策 #7）只按租户，v1 每实例一个租户，所以这里**不能**指望 RLS 兜底 |
| 3 | 撤销逻辑自我锁死（用户在异地被误踢，够不着本地开关） | 单次不一致即踢线，DB 竞态/轮询 bug 会误伤；若采用拒绝 `Ping` 断线，authz 自身故障也会在心跳窗口内断掉全部隧道（§5） | 连续 3 次确认 + 限流降级为告警 + 人工强制旁路；`Ping` 只查内存撤销状态 + 严格内部超时 + 健康检查重启（是否采用待 Weekend 0 第 6 项）；onboarding 要求用户确认有带外手段 |
| 4 | 批量升级把一片设备变砖 | 新版模板有 bug → 渲染坏配置 → `verify` 失败 → restart 失败 → 停机且无人重试（`daemon(8)` 故意不带 `-r`） | #13 验证后应用 + #14 独立看门狗回滚一次 + #15 canary |
| 5 | Agent bug 写坏 config.xml | enroll/reconcile/unenroll 高频脚本化写路径 | #16 幂等 + 白名单 + 全局配置锁 |
| 6 | CARP 双机惊群式重连 | failover → 两台几乎同时 `newwanip` → 撞上轮询判定 | #17 防抖 + 抖动 + HA 标注 + 降级为告警 |
| 7 | 证书批量到期集中失效 | v1.1 存量同批迁移，90 天窗口高度集中 | 打散签发时间 + 提前 30 天重试 + 剩余天数上报 |
| 8 | **签名私钥被当跳板：控制面渗透升级为全生态沦陷** | 场景 1 成立 + 受害机恰好持有仓库全部插件（截至 2026-10-16 共 13 个）的签名私钥 | #20 该主机排除在部署范围外（测试环境同样排除，见 §10）；离线签名机见 Q4 |
| 9 | 设备失联却没法远程修 | 重启后默认路由未装载（26.7 的 core#10597 已在 26.7.1_1 修复，同类故障仍可能由别的原因引起） | 要求 26.7.1_1 或更新；此类故障**无技术防线**，runbook 兜底 |
| 10 | 8443 在受限网络不可达 | 非标准端口被运营商/公司网络封锁，恰在最需要的"手机 4G 打开 GUI"场景失效 | Weekend 0 实测数据（443 基线与 8443 同一循环交替采样）→ Q2 决策规则 |
| 11 | 中继地址/token 需轮换但设备离线 | 迁移或泄露触发强制轮换 | #18 `rotate`（在线设备原地轮换）；离线设备仍需手动，已接受 |
| 12 | **部署者丢失密钥** | 决策 #21 的代价：没有任何人能替他找回 | `init` 强制备份提示 + `doctor` 检查备份是否存在 |
| 13 | **OIDC 账号接管：按 email 绑定** | 攻击者在某个已配置的 IdP 上拿到一个 email 与受害者相同的账号（例如该 IdP 不验证邮箱、发出可变的 email 声明，或者是一个管理员能把任意 email 标成已验证的自建 IdP）→ 如果控制面按 email 认人，就直接登成受害者；如果只凭 email 认领待处理邀请，就领走发给别人的邀请（可能是 admin 角色） | 只按 `(iss, sub)` 绑定（决策 #22）；新绑定必须从邀请链接发起，邀请 token 有效、`email_verified=true`、email 与邀请一致同时成立，不把 `email_verified` 当作跨 IdP 可信的证据；可选把邀请限定到一个提供方；不做 JIT；W6 验收"只凭 email 的绑定被拒绝""没有邀请链接、经另一个 IdP 认领邀请被拒绝" |
| 14 | **经中继爆破或利用设备 GUI** | 主机名被猜到（v1.1 起可从 CT 日志枚举）→ 直接访问 `https://<subdomain>.<domain>:8443` → 对 OPNsense 登录页爆破，或利用 GUI 漏洞 | Q7 的 `NewUserConn` 源 IP 门禁（待 Weekend 0 与用户决定）+ OPNsense 自带 TOTP 两步验证；子域名随机生成提高 v1 的猜测成本 |

---

## 14. 待拍板的问题

另有两件事不单列编号但同样待用户：v1 功能清单的最终确认；frp 升到 0.71.1 的时机（§5）。

**Q0：许可证。已决定 Apache-2.0（用户，2026-09-17）。**
v0.2 的推荐理由保留作背景：目标是"个人和企业都能自建"，而 AGPL 卡的恰恰是企业——
很多企业法务对 AGPL 一刀切禁用，哪怕纯内部自建根本不触发分发义务。这个产品也没有网络效应，
AGPL 能替你保住的东西不多。**唯一该选 AGPL 的情况**：你觉得有 30% 以上概率将来做付费托管版，
或在意别人拿走闭源套壳。注意方向性——AGPL 改宽松需要所有贡献者同意，基本回不了头；
反过来，在不用 CLA 的前提下从 Apache-2.0 收紧到 AGPL 同样需要所有贡献者同意。
贡献协议用 **DCO 而不是 CLA**（CLA 在这个体量会明显劝退贡献者）。

- **已确认子项：与组织分层策略的关系。** 2026-09-17 用户为另外 8 个仓库（不含 NetHub）定下了"产品 AGPL，库/节点 Apache"
  的分层策略。2026-10-17 Kazuha 确认 NetHub 作为这条策略的例外，保持 Apache-2.0，继续 P0。

**Q1：域名归属完整性，用轻量的「签名声明」还是红队建议的「设备级 mTLS + 提前到 v1」？**
推荐 **v1 用签名声明，v1.1 再评估 mTLS**。签名声明已经解决了核心问题——DB 单点被篡改不再等于域名可劫持；
mTLS 需要一整套设备端 PKI（签发/分发/吊销/CA 维护），对 W0–W7 的 MVP 不成比例。
而 v1.1 本来就要为 UX 上每设备独立证书，到时顺带评估复用同一套基础设施做 mTLS 是否更合算。

**Q2：如果 Weekend 0 测出 8443 在受限网络经常不可达，要不要让 frps 也 listen 443？**
推荐 **先不做，用明确的数据规则等结果**。这需要第二个公网 IP（做 SNI 分流）或一个与 Caddy 共用 IP 的
SNI dispatcher，是有意义的额外复杂度。建议规则：**实测样本中 8443 成功率比 443 低 20 个百分点以上，
或出现完全无法建连的样本，才启动这项工作**，否则维持现状。Weekend 0 套件按这条规则在同一循环里交替采样
同一台 VPS 上的 443 基线与 8443；"成功率 90% / 建连 1 秒"的绝对值只作次要参考。
按这条规则的原文，某个网络下 8443 是 0/20 时，即使同一网络下 443 也是 0/20，照样算触发；但要先复核这个样本是不是
采样或路径本身出了问题（基线监听没起、防火墙 443 没放行、这条网络整体不通）——那样原因就不在端口上。
照实记录，不悄悄豁免。

**Q3：`audit_log` 哈希链要不要做外部锚定？**
推荐 **v1 不做，先加诚实免责声明**。自建场景下每个实例的链头锚定到哪里本身就是个问题，
边际价值低还多一个暴露面。等有真实第三方审计/合规要求时再加。

**Q4：签名私钥的离线签名机改造，要不要现在启动？**
推荐 **作为独立项目单独排期，不阻塞 v1，但尽快做**。这个风险保护的是现有全部插件（截至 2026-10-16 共 13 个）的**全部**用户，
敞口比 NetHub 这一个新产品大得多；但它和 NetHub 的技术方案无关，硬塞进来会稀释两边的注意力。

**Q5：HA/CARP 场景 v1 只做"标注 + 降级为告警"，还是索性明确不支持？**
推荐 **维持轻量支持，不排除**。完全排除会让一部分用 HA 网关的潜在用户直接用不了，
而"标注 + 降级"的实现成本很低（#17），一刀切得不偿失。

**Q6：产品名。已决定 NetHub（用户，2026-09-17）。**
满足唯一的硬约束（不含 "OPNsense"）。GitHub 仓库名（`KazuhaHub/nethub`）、域名、插件包名（`os-nethub-agent`）
一起按这个名字定，不要后面改。
v0.2 列过的其它候选（`sallyport` / `gatehouse` / `beacon`）不再考虑。

**Q7（新，待用户决定）：设备 GUI 的公网暴露面怎么处理？**

*缺口：*

- SNI 透传下，`https://<subdomain>.<domain>:8443` 对任何知道或猜到主机名的人，都直接是这台设备的 OPNsense 登录页；
- 控制台的登录和 SSO 不挡在它前面；
- v0.2 一字未提，README 甚至建议"不要把 OPNsense Web UI 暴露到公网"——而 NetHub 做的恰恰是把它挂到公网上；
- v1.1 起每设备公开证书会进入 Certificate Transparency 日志，主机名从此可枚举。

*与透传兼容的候选缓解：* 用 frps 的 server plugin op `NewUserConn`——frp 对每条进来的用户连接调用它，带 `remote_addr` 与代理名。

- authz 只放行这样的连接：其源 IP 在一个滑动窗口内（如 30 分钟）由一位已登录的控制台用户对这台设备点过"打开"而登记；
- Weekend 0 必须先确认三件事：这个钩子对 `type = "https"` 的 vhost 代理会触发；`remote_addr` 是真实客户端 IP；
  拒绝确实能挡住连接。

*局限：*

- 手机在 CGNAT 后面，与陌生人共享出口 IP；
- 会话中途 IP 变了，要重新点"打开"；
- 门禁检查的是网络位置，不是人；
- 另需留意：双栈网络下，浏览器访问控制台（443）与访问设备（8443）可能走不同的地址族或不同的 IPv6 临时地址，
  登记的 IP 与实际连接的 IP 会对不上，Weekend 0 顺带记录。

*推荐：*

- 如果 Weekend 0 证实钩子可用，v1 就实现这个门禁；
- 无论是否上门禁，都在文档里如实写明这个暴露面，并建议在设备上开启 OPNsense 自带的 TOTP 两步验证；
- 注意它会以可测的形式带回 v0.2 §5 删掉的"远程会话"概念——可见粒度是每条 TCP 连接，不是每个 HTTP 请求。

*状态：* 待用户决定。

**Q8（新，待用户决定）：React UI 组件库。**
会做 2–3 个示例给用户比较后再选。组织内的 Report-Portal 用的是 antd，但这不构成 NetHub 的决定。
W3 要搭 React 外壳，所以建议在 W3 之前定下来。

**Q9（新，待实测与用户决定）：OPNsense 自己的主机名检查。**
OPNsense 的 Web GUI 自带 DNS 重绑定检查和 HTTP_REFERER 检查（System → Settings → Administration，另有"Alternate Hostnames"一栏）。
浏览器经中继用 `<subdomain>.<域名>:8443` 访问时，请求里的主机名不是设备自己的主机名，很可能被这两项检查拦下，显示错误页而不是登录页。
这一点尚未实测，Weekend 0 第 ① 项要先确认。若确认会拦，可选做法有：
（1）由用户手动把设备子域名加进 Alternate Hostnames（最简单，但每台设备多一步手工操作）；
（2）插件在 enroll 时自动写入 Alternate Hostnames——这会写到插件自己 Settings 模型之外的系统配置，与决策 #16 和 §8"只写自己的标量字段"的边界冲突，需要单独评估；
（3）让用户关闭这两项检查（降低设备自身的防护，不推荐）。
建议：先按 Weekend 0 实测；若会拦，v1 采用（1）并在 enroll 页面给出明确的操作提示，（2）另行评估。待用户决定。

**Q10（新，待用户决定）：设备 ↔ 中继控制通道没有服务端认证。**
已对 frp v0.71.0 源码核实（`pkg/transport/tls.go`）：frpc 开了 `transport.tls.enable` 但没配 `transport.tls.trustedCaFile` 时，
`NewClientTLSConfig` 直接设 `InsecureSkipVerify = true`，接受任何证书；frps 没配证书时每次启动随机生成一对密钥。
也就是说，按目前的设计，7000 端口上的控制通道**只加密、不认证**：设备到中继这段路径上的中间人（运营商、CGNAT、被攻破的上游设备）
可以冒充中继，读到 `Login` 元数据里的 domain claim，再拿它以这台设备的身份登录真正的中继，在设备离线时抢注它的子域名——
效果等同于 §13 场景 #1，却不需要攻破控制面。
按源码阅读还有两点让它更严重：frp 的 token 认证不检查时间戳新鲜度，截获的 `Login` 可以原样重放（攻击者连 frps token 都不需要）；
路径上的中间人还能随时让真设备掉线，再趁机抢注；冒充中继时它也能直接访问设备 GUI，绕过 Q7 门禁。
建议：（1）`nethub init` 生成一个部署 CA，签发一张长有效期的中继服务器证书，frps 只拿这张证书和它的私钥；
CA 私钥只进部署者的密钥备份、不挂进任何容器（决策 #21 新增一项密钥）。不建议直接用公信证书：它大约 90 天续期一次，
而 frps 只在启动时加载证书，换证书就得重启 frps、断掉所有隧道；frpc 也不会回退到系统根证书，同样要配 `trustedCaFile`。
（2）enroll / rotate 响应经已校验的 HTTPS 通道下发 CA 证书（PEM 格式；frpc 只读 PEM 文件，不支持指纹钉扎）。
（3）设备侧模板渲染 `transport.tls.trustedCaFile` 与 `transport.tls.serverName`。
另外 claim 本身是持有即可用的凭据，长期方案见 Q1（设备级 mTLS）。v1 发布前必须解决。待用户决定具体做法。

---

## 15. 本方案的可信度说明

- 设备侧的结构性论断（`plugins.json` 写法、`os-frp` 的 `rc.d` 实现与其中关于 `--strict_config` 的注释、
  `os-kazuha-repo` 只维护自己的 version 文件）**已对 `~/Codes/OPNsense-repo` 真实源码核实**。
- OPNsense 插件框架、MVC/configd/`+TARGETS` 机制、核心 REST API 面，来自 `docs.opnsense.org`
  与 `opnsense/core`、`opnsense/plugins` 源码。
- **调研过程中网络检索配额中途耗尽**，以下结论可信度较低、使用前请自行复核：
  爱快云的内部协议细节（唯一来源是一篇 2022 年的第三方抓包博客，非官方规范）、
  部分竞品的定价数字、部分中间件的性能基准数字、以及许可与商业模式那一路调研（这一路调研没有产出）。
- `httpPlugins` 的精确字段与 fail-open/fail-closed 行为**未经实测**，是 Weekend 0 的第一优先级验证项。
- 中国大陆网络可达性相关的一切判断**均未实测**，Weekend 0 才有数据。

### v0.3 补充说明

- **2026-10-16 复核过的内容**：
  - frp 0.71.0 → 0.71.1 的 diff：重连与控制连接修复、yamux 替换；配置字段名与 `pkg/plugin/server` 没有变化；
  - opnsense/core#10597 及其 26.7.1_1 热修复（2026-07-23）；当前稳定版 26.7.7（2026-10-13）；
  - 打包仓库现状：`packaging/plugins.json` 有 13 个 entry，其中 6 个声明 `python313` 依赖；`os-frp` 仍锁 0.71.0，
    其 `rc.d/frpc` 关于 `--strict_config` 的注释仍在；`src/` 下还有 `os-mihomo` 的源码目录，但它不在 `plugins.json` 里。
    v0.2 的"14 个"与 `src/` 下的插件目录数（14，含 `os-mihomo`）吻合，"15 个"没有找到依据；v0.3 统一以 `plugins.json` 为准；
  - authcore v0.6.1：包含 `captcha` / `geoip` / `passkey` / `saml`；没有 `oidc`；`audit` 已移除（ADR 0002）；
    `ratelimit` 已移除、`clientip` 已回退（ADR 0003）。
- **Weekend 0 套件的 TOML 表作用域 bug**：`frpc.toml` / `frps.toml` 里本该是顶层的键（`log.*`、`metadatas.*` 等）写在了表头之后，
  会被解析进前一张表；在 `strict_config` 下 frps / frpc 启动即退出。已发现并修正，并在 RUNBOOK 里加了 verify 步骤。
- **`NewUserConn` 对 https vhost 代理的行为在 Weekend 0 之前未经验证**；Q7 的候选缓解完全建立在它之上。
- **frps 0.71.0 的 admin API 没有断线接口**（已对 v0.71.0 源码核实：只读接口之外，只有清理离线代理的
  `DELETE /api/proxies?status=offline` 与 `POST /api/v2/system/prune`）。v0.2 的"轮询后踢线"假设了一个不存在的接口；
  §5 的候选断线机制（拒绝 `Ping` + 显式心跳、拒绝 `NewUserConn`、重启 frps）只做过源码阅读，**未经实测**。
  订阅 `Ping` 之后 authz 故障会断掉全部隧道这一推论同样只来自源码（`handleMutableContent` 把插件错误当拒绝、
  `handlePing` / `handlePong` 的处理、插件 HTTP 请求没有超时、同一控制连接上的消息串行处理），由 Weekend 0 第 6 项实测。
- **frps 0.71.0 拒绝落在 `subDomainHost` 之下的 `customDomains`**（`validateDomainConfigForServer`，已对源码核实），
  所以 §5 改为 `subdomain`；Weekend 0 套件本来就用 `subdomain`，这一点不会被 Weekend 0 暴露出来，是读源码发现的。
- `pg_dump` 遇到 `FORCE ROW LEVEL SECURITY` 时需要 `BYPASSRLS` 或超级用户（Postgres 文档的行为），§6 的 `nethub_backup` 角色据此设计，
  尚未实际跑过。
- **v0.2 决策 #5 的前提是错的**（"没有自写 Go"），v0.3 已更正。
- §6 的 DDL 与授权语句是示意，迁移落地时定稿。
- 仍然没有任何代码；本文所有"会 / 将 / 设计为"都是计划，不是现状。

---

*本文档为草案，v1 开工前应随 Weekend 0 的实测结果修订第 5、10、12、13、14 节。*
