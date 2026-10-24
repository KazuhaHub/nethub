# NetHub 实施计划

> 编写日期：2026-10-16 · 对应设计：`docs/DESIGN.md` v0.3 · 项目负责人（拍板的人）：Kazuha · 执行人：你
>
> 这份计划写给接手做 NetHub 的人。它把 `docs/DESIGN.md` 里的设计拆成按顺序做的任务，
> 每个任务都写了要做什么、怎么做、做到什么程度算完成，以及什么时候必须停下来问 Kazuha。
> 请从第 0 节开始按顺序读，不要跳着看。

---

## 目录

- [0. 先读这一节：这份计划怎么用](#0-先读这一节这份计划怎么用)
- [1. 项目一页纸](#1-项目一页纸)
- [2. 需要 Kazuha 拍板的事](#2-需要-kazuha-拍板的事)
- [3. 必读材料与术语表](#3-必读材料与术语表)
- [4. 工作规范](#4-工作规范)
- [5. 环境与测试资源准备](#5-环境与测试资源准备)
- [6. 阶段 P0：仓库启动](#6-阶段-p0仓库启动)
- [7. 阶段 W0：传输层验证](#7-阶段-w0传输层验证)
- [8. 阶段 W1：OPNsense 插件骨架](#8-阶段-w1opnsense-插件骨架)
- [9. 阶段 W2：frpc 集成](#9-阶段-w2frpc-集成)
- [10. 阶段 W3：Go 控制面骨架](#10-阶段-w3go-控制面骨架)
- [11. 阶段 W4：真实 enroll 全流程](#11-阶段-w4真实-enroll-全流程)
- [12. 阶段 W5：远程打开 + 撤销](#12-阶段-w5远程打开--撤销)
- [13. 阶段 W6：多用户 + OIDC](#13-阶段-w6多用户--oidc)
- [14. 阶段 W7：加固与首次公开](#14-阶段-w7加固与首次公开)
- [15. 缓冲与 v1 之后](#15-缓冲与-v1-之后)
- [16. 执行风险清单](#16-执行风险清单)
- [17. 附录：模板与命令速查](#17-附录模板与命令速查)

---

## 0. 先读这一节：这份计划怎么用

### 0.1 你和 Kazuha 的分工

- **Kazuha 负责拍板。** 所有"选哪个方案""要不要做""能不能公开"的问题都归他。第 2 节列出了目前已知要他决定的事。
- **你负责执行。** 按本计划一步步做，做完拿出证据（日志、截图、命令输出），交给 Kazuha 看。
- 遇到计划里没写到的情况，**不要自己猜一个方案就做下去**，先问。

### 0.2 这份计划和 DESIGN.md 的关系

- `docs/DESIGN.md` 回答"做什么、为什么这样做"。本计划回答"按什么顺序做、具体怎么做、做到什么算完"。
- 两者说法不一致时，**以 DESIGN.md 为准**，并把不一致的地方告诉 Kazuha，由他决定改哪一份。
- DESIGN.md 里有些设计点标着「建议」或「待定」。**这些都还没定**，不能当成已经决定的事去实现。
  动手之前，看第 2 节对应的决策是不是已经有结论。

### 0.3 本计划里的标记

| 标记 | 含义 |
|---|---|
| **【停】** | 到这里必须停下来，找 Kazuha 确认之后才能继续 |
| **【D编号】** | 对应第 2 节决策清单里的一项，例如【D3】 |
| `- [ ]` | 验收项。每一项都要附证据，全部勾上才算这个阶段完成 |
| **常见坑** | 前人踩过或很容易踩的错误，先读再动手 |

### 0.4 阶段总览

原则上按表里的顺序做，后一个阶段依赖前一个阶段的结果。例外：W6 只依赖 W3，可以和 W5 交错着做；W3-0（UI 示例）不需要测试资源，可以在等资源时先做。

| 阶段 | 内容 | 预计工作量（按每天 6 小时专注） | 依赖 |
|---|---|---|---|
| P0 | 仓库启动：第一次提交、GitHub 仓库、CI 骨架 | 1–2 天 | 【D1】【D2】 |
| W0 | 传输层验证：用真实 frp 跑完 6 项实验 | 3–5 天（不含等资源） | P0、【D3】 |
| W1 | OPNsense 插件骨架：菜单、设置页、能装能卸 | 5–8 天 | W0 通过、【D10】【D20】 |
| W2 | frpc 集成：渲染配置、验证后才应用、服务能连上中继 | 6–10 天 | W1、【D4】【D21】【D22】 |
| W3 | Go 控制面骨架：数据库、登录、设备列表、React 外壳 | 10–15 天 | W0、【D8】【D9】【D11】【D15】【D18】 |
| W4 | 真实 enroll：控制台发 token → 路由器粘贴 → 自动连上 | 10–15 天 | W2、W3、【D17】【D19】【D22】 |
| W5 | 远程打开设备 GUI、本地熔断开关、撤销断线 | 6–10 天 | W4、【D6】【D7】 |
| W6 | 多用户与 OIDC 登录 | 8–12 天 | W3（可与 W5 交错） |
| W7 | 加固、文档、首次公开 | 8–12 天 | W5、W6 |
| 缓冲 | 处理延误和返工 | 5–10 天 | — |

合计约 60–100 个工作日。这个估算的不确定性很大：DESIGN.md 原来按"7 个周末"估，那是在加入多用户、OIDC 之前，
而且假设执行人很熟悉 OPNsense 和 frp。**每个阶段做完都要和 Kazuha 一起重新估一次剩下的工作量。**

### 0.5 五条工作原则

1. **先验证，再写代码。** W0 没跑完，不写任何安全相关的代码。很多设计依赖 W0 的实测结果。
2. **不确定就问。** 卡住超过 2 小时，或者发现要偏离计划，就去问 Kazuha（提问模板见附录 D）。
3. **Use test environments only.** Production routers remain excluded. Kazuha permits building, signing, and NetHub use on the designated packaging test machine (DESIGN #20, revised 2026-10-17; §4.1 and §5.2).
4. **小步提交。** 一个 PR 只做一件事，最好一两天内能合并。大 PR 很难审，也很难回退。
5. **说实话。** 没测过的就写"没测过"，失败了就贴失败的输出。验收项必须有证据，不能凭感觉勾。

### 0.6 "完成"的定义

一个任务只有同时满足下面几条，才算完成：

- 代码和测试都写了，本地测试通过，CI 全绿；
- 相关文档同步更新了（README、DESIGN 里受影响的段落）；
- PR 描述里写清楚了做了什么、为什么、怎么验证的（模板见附录 B），并附上证据；
- Kazuha 审过、合并了；
- 对应阶段的验收清单里，这一项打了勾。

---

## 1. 项目一页纸

### 1.1 NetHub 是什么

NetHub 是一个**开源、自己部署**的路由器远程管理平台，先支持 OPNsense（一种开源防火墙/路由器系统）。

它要解决的问题：家里或公司的 OPNsense 往往在运营商的 CGNAT 后面，或者只有动态 IP，外面没法直接访问它的管理网页。
NetHub 的做法是：在路由器上装一个插件，让路由器主动连到你自己的一台公网服务器（"中继"）上；
之后你在任何地方打开 `https://<设备子域名>.router.example.com:8443`，就能看到这台路由器的登录页。

### 1.2 v1 做什么、不做什么

**v1 要做（DESIGN.md §1、§6）：**

- 设备用一次性 token 加入（enroll），自动分配一个随机子域名；
- 路由器到中继保持一条长连接隧道，浏览器流量经中继原样转发到路由器，**中继不解密**；
- 控制台能看到设备在线/离线状态；
- 控制台支持多个用户（`admin` / `member` 两种角色，邀请制），可以用本地密码、OIDC 或 SAML 单点登录（可以配多个身份提供方）；
- 可以撤销设备、本地有熔断开关。

**v1 明确不做：** 读取或修改路由器配置（`config.xml`）、批量升级、监控指标、OpenWrt/VyOS 支持。

### 1.3 架构

```
浏览器 ──HTTPS:8443──► frps（中继，只看 SNI，不解密） ◄──隧道:7000── 路由器上的 frpc ──► 路由器自己的网页 127.0.0.1:443
                         │
                         │ httpPlugins（Login / NewProxy / NewUserConn / Ping）内部网络
                         ▼
                 nethub authz（设备身份、签名、准入）
                 nethub web（控制台：React 页面 + JSON API）   ◄── 用户浏览器 HTTPS:443（经 Caddy）
                 Postgres 16
```

| 组件 | 是什么 | 谁写 |
|---|---|---|
| `frps` / `frpc` | 开源项目 frp 的服务端和客户端，版本锁定 0.71.1（D4 confirmed） | 不改源码，只写配置 |
| `nethub web` | Go 程序，公网控制台 | 你写（W3、W6） |
| `nethub authz` | Go 程序（同一个二进制的另一种运行方式），处理设备 enroll 和 frps 的校验回调 | 你写（W4、W5） |
| `os-nethub-agent` | OPNsense 插件：PHP 页面 + Python 脚本 `agentctl.py` + 自带的 frpc | 你写（W1、W2、W4） |
| Caddy | 公网 443 的反向代理，自动申请证书 | 只写配置 |
| Postgres 16 | 数据库 | 写表结构和权限 |

公网端口一共三个：**443**（控制台和设备 enroll 接口）、**7000**（设备到 frps 的控制通道）、**8443**（浏览器到设备）。

### 1.4 Initial state (2026-10-17; historical)

Current update (2026-10-21): Kazuha explicitly requested public visibility.
The repository is public; authenticated and anonymous GitHub API checks agree.
Main protection now requires a PR and all six current CI jobs, including for
administrators. W4 certificate automation and W5-W7 acceptance remain incomplete;
public visibility does not establish release readiness. See HANDOFF_PROMPT.md
and the stage validation records for implementation evidence.

- 只有文档和一套验证工具，**一行产品代码都没有**；
- GitHub 仓库 <https://github.com/KazuhaHub/nethub> 已于 2026-10-17 建好，**私有**。第一次提交 `f529e1d`（包含全部现有文档）和之后的状态更新都已推送到 `main`；`main` 还没有分支保护和 CI；
- `weekend0/` 里的传输层验证工具已经修好，但**还没在真实环境跑过**。

### 1.5 仓库地图

| 路径 | 内容 | 什么时候读 |
|---|---|---|
| `README.md` | 项目对外介绍 | 第一天 |
| `docs/DESIGN.md` | 完整设计（中文），21+2 条架构决策、数据模型、安全设计、MVP 计划、待定问题 | 第一天读 §0–§2，之后每个阶段开始前读对应章节 |
| `docs/PLAN.md` | 本文件 | 一直 |
| `docs/threat-model.md` | 威胁模型初稿（英文） | W3 前、W7 |
| `docs/console-api.md` | 控制台 API 草稿（英文） | W3 前、W6 前 |
| `docs/README.zh-CN.md` | README 的中文版 | 第一天 |
| `weekend0/RUNBOOK.md` | W0 的操作手册，非常详细 | W0 开始前通读两遍 |
| `weekend0/results-template.md` | W0 结果记录模板 | W0 期间 |
| `weekend0/probe.py`、`frps.toml`、`frpc.toml` | W0 用的探针和配置 | W0 期间 |
| `proto/README.md` | 控制面和设备之间的协议说明 | W4 前 |
| `server/README.md` | 控制面的技术栈和目录规划 | W3 前 |
| `deploy/README.md` | 部署、`nethub init`、`nethub doctor` | W3 前 |
| `agents/opnsense/README.md` | OPNsense 插件的说明 | W1 前 |
| `CONTRIBUTING.md` | 提交规范（DCO、Conventional Commits） | 第一天 |

---

## 2. 需要 Kazuha 拍板的事

下表是目前已知、需要 Kazuha 决定的事项。**"最晚什么时候定"那一列到了还没定，就停在那里，不要往下做。**
每次 Kazuha 做了决定，请把结论和日期写进"状态"一列，并记进决策记录（模板见附录 E）。

| 编号 | 问题 | 最晚什么时候定 | 卡住哪个阶段 | 推荐（来源） | 状态 |
|---|---|---|---|---|---|
| D1 | 许可证：NetHub 已定 Apache-2.0，但组织里另有"产品用 AGPL、库和节点用 Apache"的分层规则，NetHub 要不要按这条改？（DESIGN §14 Q0） | 第一次公开 commit 之前 | P0 | 保持 Apache-2.0（DESIGN）；作为分层规则的例外写进决策记录（本计划建议） | 已确认（2026-10-17）：保持 Apache-2.0，作为组织分层规则的例外，继续 P0 |
| D2 | GitHub 仓库 `KazuhaHub/nethub` 什么时候建、一开始私有还是公开；谁做第一次提交 | P0 开始 | P0 | 先建私有仓库，W7 公开（本计划建议） | Updated 2026-10-21: Kazuha explicitly requested public visibility. GitHub authenticated and anonymous API checks confirmed public visibility. This supersedes the earlier private-until-W7 decision; release and disclosure review remain separate W7 gates. |
| D3 | 测试资源由谁准备、费用谁出：一台公网 VPS、一个能配泛解析的域名、一台 OPNsense 测试机，以及测试机上要装好 `os-frp`（W2 共存测试用）；两家不同运营商的 4G/5G 网络（RUNBOOK ④ 要求至少两家） | W0 开始前 | W0 及以后 | 见第 5.2 节 | 部分决定（2026-10-17）：Local Windows OPNsense NAT client and remote LXC server/relay selected. OPNsense 26.7.7, dedicated SSH, outbound TLS, and bounded NAT transport preparation passed; complete mobile GUI ① and hook experiments ②/③ now pass. Windows restart and WHPX readiness passed. Native Hyper-V now passes complete local/public GUI diagnostics using a verified copy of the restored disk at 1 GiB; Kazuha approved the recorded 1 GiB resource exception; W0 accepted by Kazuha on 2026-10-18. A/B samples from two mobile carriers pass; Kazuha explicitly waived company/campus sampling. Relay SSH and wildcard DNS verified; temporary port windows authorized. The earlier packaging host retains its co-hosting exception |
| D4 | frp 从 0.71.0 升到 0.71.1 的时机。要同时改打包仓库里 `os-frp` 的版本，那是 Kazuha 的仓库 | W2 开始前 | W2 | W2 之前三处一起升（DESIGN §5） | Confirmed 2026-10-18: upgrade os-frp, NetHub frpc, and frps together to 0.71.1 before W2 integration. |
| D5 | 8443 端口在受限网络下不好用的话，要不要把浏览器入口也放到 443（DESIGN §14 Q2） | W0 第 ④ 项结果出来后 | W5、W7 | 按 Q2 的数据规则判断（DESIGN） | Confirmed 2026-10-18: retain 8443; measured A/B networks did not trigger Q2. |
| D6 | 撤销设备时怎么断开它已在线的隧道（DESIGN §5 候选机制 1–4） | W0 第 ⑥ 项结果出来后、W5 之前 | W5 | 待 W0 数据（DESIGN） | Confirmed 2026-10-18: heartbeat 10s, timeout 30s; deny Ping/Login/NewProxy together. Accept backend-outage costs, stale admin status, and recovery instability; bound hook work internally. |
| D7 | 设备登录页会暴露在公网上，要不要用 `NewUserConn` 做"点了打开才放行"的门禁；放行窗口要不要随访问顺延（DESIGN §14 Q7） | W0 第 ⑤ 项结果出来后、W5 之前 | W5 | 钩子可用就在 v1 做（DESIGN） | Confirmed 2026-10-18: v1 source-IP gating; authenticated Open grants 30 minutes, another explicit Open renews; traffic never extends the window. |
| D8 | v1 功能清单的最终确认（DESIGN §1、§6） | W3 开始前 | W3 | 按 DESIGN v0.3 | Confirmed 2026-10-18: approve v1 scope, including SAML via authcore/saml. |
| D9 | 控制台用哪个 React 组件库（DESIGN §14 Q8）。你先在 W3-0 做 2–3 个示例给他挑 | W3-0 做完后 | W3 | 无，看示例再定 | Confirmed: shadcn/ui with native dialog (2026-10-17) |
| D10 | 插件源码在 `agents/opnsense/plugin/` 里的目录结构；以及正式发布时，打包仓库怎样从 NetHub 的 release 构建这个插件（打包仓库按 `plugins.json` 的记录逐文件核对，具体怎么接还没定） | W1 开始前 | W1、W7 | 结构参照 `os-easytier` 的布局（本计划建议）；发布方式由 Kazuha 定 | Confirmed 2026-10-18: src/, packaging/freebsd/, build.sh, tests under agents/opnsense/plugin; unsigned development packaging now, release integration deferred. |
| D11 | DESIGN v0.3 里标「建议」的设计点逐条确认，重点是 §6：web/authz 进程拆分和列级授权、`nethub_backup` 角色、删掉 `frp_token_hash`、一次性撤销。另外还有几处 DESIGN §6 没写到、需要补表或补权限的地方：W5 的"立即断"请求、Q7 门禁的 IP 登记、Postgres 初始化时容器要拿到全部角色密码（和决策 #21"每个容器只拿自己的密钥"有出入）、邀请有效期（本计划暂按 72 小时）和"邀请限定身份提供方"是否要做 | W3 写数据库迁移之前 | W3、W4、W5、W6 | 按 DESIGN v0.3 | Confirmed 2026-10-18: use the process/data permissions and additions in w3-decisions.md; no per-device frp_token_hash, one-way revocation, scoped Open/cutoff records, backup role, bootstrap password exception, and invitation rules. |
| D12 | `docs/DESIGN.md` 公开之前要不要删改敏感内容：第三方名字、本地路径、针对签名主机的攻击路径描述；本计划 `docs/PLAN.md` 要不要放进公开仓库 | 仓库公开之前 | W7 | 公开前删改；PLAN.md 不公开（本计划建议） | 待定 |
| D13 | 插件的正式包（签名后发布到软件源）由谁构建和发布 | 第一次给别人装插件之前 | W4 以后 | Kazuha 做；你只做未签名的开发包（本计划建议） | 待定 |
| D14 | DESIGN §14 的 Q1、Q3、Q4、Q5（mTLS、审计链锚定、离线签名机、CARP） | W7 之前 | W7 | 按 DESIGN 里的推荐 | 待定 |
| D15 | 首个管理员账号的创建顺序：`nethub init` 在 `docker compose up` 之前运行，那时数据库还没起来，管理员在哪一步创建；如果按 W3-8 的建议，就要新增一个 `nethub admin create` 子命令 | W3-8 之前 | W3 | 见 W3-8（本计划建议） | Confirmed 2026-10-18: init, Compose/migrate, then one-shot admin create; never grant owner credentials to web. |
| D16 | 技术选型：数据库迁移工具、协议版本号规则、命令行写法、运行镜像等（W3、W4 里会逐个提出） | 对应任务开始前 | W3、W4 | 各任务里给出推荐（本计划建议） | Confirmed for W3 on 2026-10-18: standard net/http, flag, slog, pgx/v5, goose/v3, nonroot static runtime; reuse matching authcore packages. W4 protocol SemVer and incompatible-major rejection confirmed 2026-10-18; see w4-decisions.md. |
| D17 | OPNsense 自己的 DNS 重绑定 / HTTP_REFERER 检查会不会拦下经中继的访问；会拦的话怎么处理（DESIGN §14 Q9） | W0 第 ① 项结果出来后、W4 之前 | W4、W5 | 先实测；会拦就让用户手动加 Alternate Hostnames，并在 enroll 页面提示（DESIGN） | Confirmed 2026-10-18: manually add the exact Alternate Hostnames entry; preserve both security checks and explain the step during enrollment. |
| D18 | 控制台用哪个域名：泛域名的根（例如 `router.example.com`）还是它下面的某个子域名。如果在泛域名下面，这个前缀必须保留、永远不分给设备 | W3-8 之前 | W3、W4 | 无，Kazuha 定 | Confirmed 2026-10-18: separate console hostname and device wildcard, configured by the deployer. |
| D19 | 路由器上的插件怎么知道控制台地址：enroll 页面多一个"控制台地址"输入框，还是把地址编进 enroll token 里 | W4-1 之前（协议里要写清楚） | W4 | 无，Kazuha 定 | Confirmed 2026-10-18: separate HTTPS console address input; keep the opaque enrollment token. See w4-decisions.md. |
| D20 | 打包仓库里的现有插件文件能不能直接复制进 NetHub。打包仓库的根许可证是 MIT，而且有其他版权人；NetHub 要保持单一版权的 Apache-2.0（DESIGN §2） | W1 开始前 | W1、W2 | 只当结构参考、自己重写；确实要复制某个文件前，先问 Kazuha 那个文件是谁写的（本计划建议） | Confirmed 2026-10-18: independently write NetHub files; reference structure only, no third-party copying. Omit kazuha.sh mirror. |
| D21 | 要不要注册 `newwanip` 钩子：DESIGN 决策 #17 要求注册（带防抖），但打包仓库的 `os-frp` 故意不注册，理由是 frpc 自己会重连，WAN 地址变化时重启反而会断掉正常的隧道 | W2-6 之前 | W2 | 无，Kazuha 定（看 `os-frp` 的 `frp.inc` 里那段注释） | Confirmed 2026-10-18: do not register newwanip; use frpc reconnect and periodic reconcile. W2 must measure recovery after a real WAN address change; if automatic recovery fails, switch to the debounced hook in DESIGN #17. |
| D22 | 设备到中继 7000 端口的控制通道怎么做服务端认证（DESIGN §14 Q10）：frpc 不配 CA 时根本不校验 frps 的证书，路径上的中间人能截下 domain claim | W2-3 写模板之前定方向，W4 enroll 之前定细节 | W2、W4 | `nethub init` 生成部署 CA、给 frps 签长期证书 + enroll 响应下发 CA 证书（PEM）+ 模板写 `transport.tls.trustedCaFile`（DESIGN Q10） | Confirmed direction 2026-10-18: deployment CA, relay server certificate, device trustedCaFile and serverName; keep the CA private key outside runtime containers. On 2026-10-18 Kazuha required automatic renewal/distribution/configuration, referenced PSP, selected option 2, including router GUI certificate issuance, installation and renewal in v1 (scope record corrected 2026-10-19). Console TLS belongs to the reverse proxy. Implementation details: certificate-automation.md; not yet implemented. |

---

## 3. 必读材料与术语表

### 3.1 必读顺序

**第一天：**

1. `README.md`（全文）
2. `CONTRIBUTING.md`（全文）
3. `docs/DESIGN.md` §0（变更记录）、§1（定位）、§2（仓库划分）
4. 本计划第 0–6 节

**每个阶段开始前**，再读对应的材料：

| 阶段 | 要读的 |
|---|---|
| W0 | `weekend0/RUNBOOK.md` 全文两遍；DESIGN §5 |
| W1、W2 | DESIGN §3（决策 #2、#3、#10、#11–#17）、§4；`agents/opnsense/README.md` |
| W3 | DESIGN §6、§7、§9；`server/README.md`；`deploy/README.md` |
| W4 | DESIGN §5、§6；`proto/README.md` |
| W5 | DESIGN §5（断线机制、Q7）、§13 |
| W6 | DESIGN §6（用户、邀请、OIDC）、决策 #22、§13 场景 #13 |
| W7 | DESIGN §7、§9、§12、§13 |

### 3.2 外部资料

- frp 官方文档与源码：<https://github.com/fatedier/frp>（本项目用 v0.71.0 tag；配置字段以源码 `pkg/config/v1/` 为准）
- OPNsense 插件开发文档：<https://docs.opnsense.org/development/>（重点看 "Frontend"、"Backend"（configd）、"Models"、"Templates"）
- Go 语言入门：<https://go.dev/tour/>；标准库 `net/http`、`database/sql` 文档
- Postgres 行级安全（RLS）：<https://www.postgresql.org/docs/16/ddl-rowsecurity.html>
- OIDC 入门：OpenID Connect Core 1.0 规范的 "Authorization Code Flow" 一节；PKCE 是 RFC 7636
- 参考实现（只读，不要改）：打包仓库 `KKazuhaK/OPNsense-repo` 里的 `src/os-easytier/`、`src/os-frp/`、`src/os-sing-box/`。
  组织内的 Go 项目 `KazuhaHub/authcore` 的 `.github/workflows/`，用来参考 CI 写法。

### 3.3 术语表

| 术语 | 一句话解释 |
|---|---|
| CGNAT | 运营商级 NAT。你的路由器拿不到公网 IP，外面无法主动连进来 |
| 中继（relay） | 一台有公网 IP 的服务器，路由器主动连它，浏览器也连它，它在中间转发 |
| frp / frps / frpc | 开源内网穿透工具。frps 跑在中继上，frpc 跑在路由器上 |
| SNI | TLS 握手第一个包（ClientHello）里明文带的域名。frps 只看它来决定转发给哪台设备 |
| SNI 透传 / passthrough | 中继不解密 HTTPS，原样转发加密流量。证书和私钥都在路由器上 |
| `vhostHTTPSPort` | frps 上接收浏览器 HTTPS 的端口，本项目是 8443 |
| `subDomainHost` | frps 的泛域名后缀，例如 `router.example.com`。设备的 `subdomain` 会拼在它前面 |
| `httpPlugins` | frps 的回调机制：处理某些操作（`Login`、`NewProxy`、`NewUserConn`、`Ping`）时，先 POST 给你的程序问"放不放行" |
| fail-closed / fail-open | 回调出错时，frps 是拒绝（closed）还是放行（open）。按源码是 fail-closed |
| `strict_config` | frp 默认开启的严格配置检查：配置里有不认识的字段，程序直接退出 |
| OPNsense | 基于 FreeBSD 的开源防火墙系统，管理界面是 PHP 写的 |
| `config.xml` | OPNsense 的全部配置都存在 `/conf/config.xml` 一个文件里 |
| MVC / Volt / Phalcon | OPNsense 网页的写法：模型（XML）+ 控制器（PHP）+ 视图（Volt 模板），框架是 Phalcon |
| configd / action | OPNsense 的后台命令服务。网页不能直接执行命令，只能调 `actions_*.conf` 里注册过的 action |
| `+TARGETS` / 模板 | OPNsense 用 Jinja2 模板生成配置文件，`+TARGETS` 声明模板生成到哪个路径 |
| rc.d | FreeBSD 的服务启动脚本，在 `/usr/local/etc/rc.d/` |
| pkg | FreeBSD 的软件包工具。`.pkg` 文件可以用 `pkg add` 安装 |
| enroll / enroll token | 设备"加入"控制面的过程 / 控制台生成的一次性口令，15 分钟过期 |
| 域名归属签名声明（domain claim） | authz 用 HMAC 签的一段数据，证明"这个子域名属于这台设备"。frps 回调时校验它 |
| kill switch（本地熔断） | 路由器本地的一个文件 `/var/db/nethub-agent/disabled`，存在就停隧道，控制面管不了 |
| reconcile | agent 的"收敛"操作：按设置重新生成 frpc 配置，验证通过才替换并重启 |
| RLS（行级安全） | Postgres 功能：数据库自己按规则过滤行，即使程序忘了加 `WHERE tenant_id = ...` 也不会串数据 |
| 列级授权 | Postgres 可以只允许某个角色改某几列，例如 web 角色不能改 `devices.subdomain` |
| `SECURITY DEFINER` 函数 | 以函数属主的权限执行的数据库函数，用来开一个很窄的特权口子 |
| OIDC | OpenID Connect，常见的单点登录协议（Google、Keycloak、Dex 都支持） |
| PKCE | OIDC 授权码流程里的一层防护，防止授权码被截获后冒用 |
| `iss` / `sub` | ID token 里的签发方和用户唯一标识。本项目按 `(iss, sub)` 绑定账号，**不按 email** |
| `email_verified` | ID token 里"这个邮箱已验证"的标记。只在认领邀请时、配合邀请链接使用 |
| argon2id | 密码哈希算法。本项目存密码只存 argon2id 哈希 |
| CSRF / CSP | 跨站请求伪造防护 / 内容安全策略（限制页面能加载哪些脚本） |
| DCO | 提交时加 `Signed-off-by` 行，声明代码是你写的、可以按项目许可证贡献 |
| Conventional Commits | 提交信息格式：`feat(server): ...`、`fix(agent): ...` 等 |
| 示例地址 | 文档里只能用 `example.com`、`router.example.com`、`203.0.113.10`（RFC 5737 文档专用地址），不能写任何真实地址 |

---

## 4. 工作规范

### 4.1 红线：绝对不能做的事

下面每一条都不能做。拿不准某件事算不算，就当它算，先问。

1. **不把任何真实信息写进仓库、issue、PR、截图或聊天记录**：真实域名、IP、端口、token、密码、密钥、证书私钥都不行。
   文档和示例里一律用 `example.com`、`router.example.com`、`203.0.113.10`。截图前先把地址栏和日志里的真实地址打码。
2. **不在任何生产路由器上安装或运行 NetHub 的任何部分。**
3. **The designated packaging test machine may build and sign packages while running NetHub.** Kazuha explicitly revised DESIGN decision #20 on 2026-10-17. Removing its signing keys or build/signing scratch, or moving signing elsewhere, is no longer a prerequisite. Other signing hosts remain outside scope. Official package and release work follows the relevant stage and D13.
4. **不构建、不签名、不发布正式软件包，不改打包仓库 `KKazuhaK/OPNsense-repo`。** 需要改那边时，写清楚要改什么，交给 Kazuha。
5. **不 force push，不改写 git 历史，不直接推 `main`。** 所有改动走 PR。
6. **提交、PR、代码注释里不出现任何 AI 工具的署名**（例如 `Co-authored-by: <AI 工具>`、"Generated with ..."），分支名也不能带工具名。
   这是项目规则（`CONTRIBUTING.md`）。
7. **不提交密钥文件。** `.env`、`*.key`、`*.pem`、`deploy/secrets/` 已经在 `.gitignore` 里，不要用 `git add -f` 强行加。
8. **改 `proto/` 必须在同一个 PR 里**：改版本号、改所有受影响的 agent、更新契约测试、在 PR 描述里写兼容性影响（`CONTRIBUTING.md`）。
9. **不把 DESIGN 里标「建议」「待定」的东西当成已决定的去实现。** 先看第 2 节。

### 4.2 Git 工作流

每个任务一个分支，分支名按内容取：

```bash
git switch main
git pull
git switch -c feat/agent-plugin-skeleton   # 新功能用 feat/，修 bug 用 fix/，文档用 docs/，CI 用 ci/
```

提交时**一定要加 `-s`**（DCO 签名），提交信息按 Conventional Commits 格式：

```bash
git add <具体文件>            # 不要用 git add . 一把全加，先 git status 看清楚
git commit -s -m "feat(agent): add settings model and menu entry"
```

- 提交信息第一行用英文、祈使语气，不超过约 72 个字符。正文写"为什么"。
- 常用类型：`feat` 新功能、`fix` 修复、`docs` 文档、`test` 测试、`refactor` 重构、`ci` CI、`build` 构建、`chore` 杂项。
- 常用范围：`agent`（OPNsense 插件）、`server`（Go 控制面）、`web`（React 控制台）、`proto`、`deploy`、`weekend0`、`docs`。

推送并开 PR：

```bash
git push -u origin feat/agent-plugin-skeleton
gh pr create --fill     # 然后在网页上按附录 B 的模板补全描述
```

PR 合并之前要满足：CI 全绿，Kazuha 审过。

### 4.3 本地环境注意事项

- **`go.work` 陷阱**：如果你的仓库放在某个上级目录里，而那个目录有 `go.work` 文件，Go 会把它当成工作区，导致依赖解析出错。
  在 `server/` 里运行 `go env GOWORK`，输出不是空的，就在命令前加 `GOWORK=off`，或者 `export GOWORK=off`。
- **编辑器、AI 工具等本地文件不进仓库**：把它们写进你自己的全局忽略文件，不要改项目的 `.gitignore`：

  ```bash
  git config --global core.excludesFile     # 先看有没有设置过；有输出就往那个文件里加，不要覆盖
  git config --global core.excludesFile ~/.config/git/ignore   # 没设置过才运行这一行
  mkdir -p ~/.config/git
  echo ".idea/" >> ~/.config/git/ignore     # 按你用的工具添加
  ```

- 在 macOS 上运行 Python 测试时用 `python3 -I`，避免读到当前目录里同名的模块。

### 4.4 汇报节奏

- **每天结束**：在约定的地方（问 Kazuha 用哪里）发一条日报，模板见附录 C。三行就够：做了什么、卡在哪、明天做什么。
- **每个阶段结束**：发阶段总结，附验收清单和证据链接，并和 Kazuha 一起重新估剩余工作量。

### 4.5 卡住了怎么办

- 同一个问题卡住超过 **2 小时**，就去问，不要硬耗。
- 提问时按附录 D 的模板写清楚：你想做什么、做了哪些步骤、预期是什么、实际看到什么（贴完整的错误输出，真实地址先打码）、你自己的猜测。
- 写得清楚的问题，通常能更快拿到答案。

---

## 5. 环境与测试资源准备

### 5.1 你的开发机

下面以 macOS + Homebrew 为例。用 Linux 的话，换成对应的包管理器。

```bash
brew install git gh go python@3.13 jq openssl libpq
brew install node@24           # 装 Node.js 的 LTS 版本；先用 brew info node 看当前 LTS 是哪个大版本，按实际改数字
brew install --cask docker     # 或者用 OrbStack、colima 之类的 Docker 替代品
```

`brew install node` 装的是最新的 Current 版本，不是 LTS，所以要带版本号。`node@24`、`libpq` 这类带版本或只提供工具的包，
Homebrew 默认不放进 PATH，装完按它最后打印的提示，把对应的 `bin` 目录加进 PATH（`psql` 来自 `libpq`）。

装完逐个检查版本，把输出记下来：

```bash
git --version
gh --version
go version            # 要求 go1.26.x；版本不对就装对应版本
node -v               # 用 Node.js 当前的 LTS 版本
npm -v
python3.13 --version  # 要求 3.13.x
docker version
docker compose version
psql --version        # 只用客户端，不需要在本机跑 Postgres 服务
```

然后：

1. `gh auth login`，用你自己的 GitHub 账号登录。
2. 请 Kazuha 把你加进 `KazuhaHub` 组织，并给你这些权限：`nethub` 的写权限（P0 之后）；
   打包仓库 `KKazuhaK/OPNsense-repo`、`KazuhaHub/authcore`、`StockAnalysisPrediction-Report-Portal` 的**只读**权限（本计划多处让你参考它们）。
3. 设置 git 身份（用你自己的名字和邮箱，DCO 签名会用到）：

   ```bash
   git config --global user.name "你的名字"
   git config --global user.email "你的邮箱"
   ```

4. 给 GitHub 账号开两步验证。

**执行环境检查（2026-10-17）：** Git 2.53.0.windows.3、GitHub CLI 2.102.0、Go 1.26.9、Node 24.14.0、npm 11.9.0、Python 3.12.14、actionlint 1.7.12。GitHub CLI、Go、actionlint 的下载包已经对照上游 SHA256 校验。Python 3.12 可执行当前 W0 文件检查，后续设备侧开发仍需 3.13；Docker/Compose、psql、jq、OpenSSL 未在 PATH 找到。上述版本来自本次执行环境，不代表用户另开的 PowerShell 可直接使用相同路径。

### 5.2 测试资源【D3】

这些资源由 Kazuha 决定谁准备。资源到位之前，只能做 P0 和读文档。

| 资源 | 要求 | 用在哪 | 注意 |
|---|---|---|---|
| 公网 VPS | Linux（推荐 Debian/Ubuntu），有独立公网 IPv4；W0 用 1 核 1GB 就够，W3 起建议 2 核 4GB | 中继 + 控制面 | W0 放行 7000 和 8443，做第 ④ 项时临时放行 443；W3 起长期放行 443、7000、8443。SSH 只允许你自己的 IP |
| 域名 | 能自己改 DNS 记录 | 子域名路由 | 要加一条泛解析 `*.router.example.com → VPS 的 IP`（换成真实域名） |
| OPNsense test VM | Local Windows OPNsense guest behind NAT; current native Hyper-V diagnostic, amd64, OPNsense 26.7.x **≥ 26.7.1_1**, outbound Internet access | Run frpc and test the plugin | No public bridge or public inbound port mapping; local management forwards bind only to loopback. The configured guest has been updated to 26.7.7; mobile GUI ① now passes. Install `os-frp` before W2 coexistence testing. Keep access details outside the repository |
| 4G/5G 网络 | 能关掉 Wi-Fi、只走移动网络的手机；最好有两家不同运营商（RUNBOOK ④ 要求至少两家） | 从"真实的外部网络"访问 | W0 第 ①④⑤ 项要用。只有一家的话，在结果里写明 |
| （可选）第二个受限网络 | 公司网络、校园网等 | W0 第 ④ 项 | 有就测，没有在结果里写明 |

**Selected topology (owner clarification, 2026-10-17):** the current Windows machine hosts the OPNsense NAT client; the remote LXC runs the NetHub server/relay. Hyper-V is installed and the Windows host now has about 8 GiB RAM. The Generation 1 guest has separate internal LAN/WAN switches, outbound NAT, and no static inbound mappings. Earlier startup attempts are historical; current native Hyper-V diagnostics are described below. Startup attempts at 3, 2, and 1.5 GiB failed because the host could not allocate memory (`0x8007000E`). Closing auxiliary windows was insufficient; the Hyper-V memory-balancer counter remained below 1 GiB available for guests. It later started at 1 GiB after reclaiming application working sets; this reduced-memory diagnostic is described below. The signed 26.7 Nano image and transferred VHDX were verified; the updated QEMU guest is described below. The exploratory LXC guest has been stopped.

**Guest preparation history; current transition below:** the two-vCPU QEMU guest first booted with 2 GiB and TCG from the verified image using a separate QCOW2 overlay. LAN setup and root-password replacement are complete. Public-key SSH passed with the host key verified against the console; local GUI form login and outbound package-mirror TLS verification also passed. Management forwards bind only to loopback. All templates regenerated successfully after the initial boot warning; its original cause is unproven. The stock minor firmware update and reboot completed: OPNsense 26.7.7 and matching running/installed FreeBSD 15.1-RELEASE-p4 kernel and userland passed checks. Earlier Chrome observations established widget containers and initial API responses, but did not prove periodic updates or full GUI usability. Full acceptance remains pending. This is preparation history; current Hyper-V and restore evidence follows below.

**GUI failure history and runtime transition (2026-10-17; current result below):** the earlier readiness observations above do not prove full GUI usability. The relay-domain login POST was rejected by HTTP_REFERER enforcement; its error page also contained a logout link, making that an insufficient authentication predicate. Adding the exact test hostname through the stock Administration form removed the rejection with both checks still enabled. Dashboard containers and initial API responses subsequently loaded, but the mobile owner reported persistent Dashboard loading. W0① was not accepted at that point. The short AJAX-count observation did not establish periodic widget updates.

TCG showed load averages near 29 and queued backend work, with free guest RAM and no guest swapping; the loading root cause is unproven. The owner-authorized Windows restart and WHPX capability check now pass. The existing overlay checksum matched the shutdown checkpoint. Earlier attempts ended through QMP before root mount after zero writes on every block device and process exits were checked. Disabling legacy VGA and parallel ports alone did not resolve startup; with the userspace interrupt controller, the existing guest reached its shell in about 15 minutes. That WHPX boot passed checks for dedicated public-key SSH with an unchanged host key, OPNsense 26.7.7, matching kernel and userland, and package-mirror TLS. A five-second sleep advanced guest wall and monotonic clocks by about five seconds; guest swap counters were zero. The calibration warning remains. The disk and NAT layout are preserved, with no TCG fallback. See the [QEMU WHPX prerequisites and debugging options](https://www.qemu.org/docs/master/system/whpx.html).

The full local GUI failed under WHPX. Later runs populated interface rows, charts, and EventSource messages, but system-information data and periodic clock updates did not pass; widget requests timed out. The failure reproduced without the public relay. A temporary CPU-affinity comparison did not resolve it; the original two-CPU mask was independently verified through the serial console afterward. The initial-wizard flag was cleared through the stock Abort button after console configuration. XML comparison confirmed that all other settings were preserved, excluding revision metadata; the test hostname and both security checks remain correct.

The 3 GiB, two-vCPU WHPX VirtIO profile booted in about nine minutes and passed SSH, version, mirror TLS, and clock checks, but complete GUI checks still failed. Checksum, TSO, and LRO offloading were already disabled. Sequential HTTP/2 and HTTP/1.1 API probes both succeeded; they did not establish a protocol-specific cause. A later host-CPU-model trial panicked in `devfs_find` and exited. Its failed state was preserved before restoring the preceding disk-only snapshot; the generic-CPU launcher was restored. The restored source QCOW2 has not been rebooted. Monitor serial output from each launch's recorded offset rather than treating older appended boot messages as current evidence.

The current native Hyper-V diagnostic uses a separate VHDX converted from that restored disk, with 1 GiB RAM and two vCPUs. Content comparison passed before and after clearing the host sparse-file flag required by Hyper-V. The converted copy booted successfully. Synthetic NICs were verified by pinned MAC; LAN was preserved and WAN was configured through the stock console for host NAT. Public-key SSH retained the verified host key. Current firmware/kernel/userland, package-mirror TLS, and five-second clock-progress checks passed with no guest swap activity. Local management forwards bind only to loopback. Complete local and public-relay desktop checks passed with the stock five-second widget timeout: system information, interface rows, charts, periodic clock updates, menu navigation, and no widget, request, HTTP, or page-script errors. Both GUI security checks remain enabled and the backend TLS leaf certificate matches through the relay. Original relay services/listeners were independently verified after cleanup, test listeners are closed, and the restoration timer was cancelled. The temporary credential page remains closed.

These 1 GiB desktop checks are preparation, not numbered W0 acceptance. On 2026-10-17, Kazuha explicitly approved continuing W0 at 1 GiB with the deviation from the [documented 3 GiB VM minimum](https://docs.opnsense.org/manual/virtuals.html) recorded in the report. Keep memory, swapping, and performance observations; do not generalize this environment to production sizing. Public desktop self-testing and mobile ① now pass. Experiments ②/③ also pass; ④ now passes within the owner-approved two-mobile-network scope. Experiment ⑤ now passes; ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18. No product implementation has started.

**Earlier public packaging test device:** this remains owner-approved under the co-hosting exception, but is not the selected NAT client. The following caveats apply if it is used for a separate comparison:

1. **GUI 不在 443 端口。** 实际端口问 Kazuha，W0 时把 `frpc.toml` 里的 `localPort` 改成这个端口（RUNBOOK 2.1）。
2. **它有公网 IP，GUI 端口在 WAN 上对外开放。** 这样 W0 第 ① 项证明不了"不开入站端口也能访问"。
   做 W0 之前，请 Kazuha 把 GUI 那条 WAN 放行规则改成只允许你自己的 IP，测完再改回去。
   W0 结果里写明"测试机有公网 IP，不在 NAT/CGNAT 后面"。
3. **它可能没有快照。** 能不能做快照问 Kazuha。不能的话，每次测完都按 RUNBOOK 的清理清单逐项恢复，弄坏了马上找他。

**开始用之前：**

1. Configure the local guest through its console, replace the default password, and verify dedicated SSH access through the loopback management forward.
2. Verify outbound NAT and the absence of public inbound mappings; do not expose the guest GUI or SSH through the public host adapter. The earlier packaging host retains its separate co-hosting exception (§4.1, rule 3).
3. 在 SSH 里运行 `opnsense-version`，确认版本 ≥ 26.7.1_1。
4. 记录：OPNsense 版本、虚拟机还是物理机、有公网 IP 还是在 NAT/CGNAT 后面。这些要填进 W0 的结果模板。

---

## 6. 阶段 P0：仓库启动

**目标：** 把现有文档变成一个有历史、有 CI、受保护的 GitHub 仓库，让后面每一步都能走 PR。

**前置条件：**【D1】许可证、【D2】仓库怎么建，都已经有结论。

**产出：** GitHub 仓库 `KazuhaHub/nethub`；第一次提交；一个最小 CI；Dependabot 配置。

**预计：** 1–2 天。

### 步骤

**P0-1 通读文档，列问题。**
把第 3.1 节"第一天"的材料读完。把看不懂的地方、发现的矛盾，写成一个列表发给 Kazuha。这是正常步骤，不是打扰。

**P0-2【停】确认【D1】【D2】。**
没有结论就不往下做。

**P0-3 建仓库和第一次提交（Kazuha 做，或者他明确授权你做）。**
**进度（2026-10-17）：** 第一次提交已经由 Kazuha 在本地完成（`f529e1d`）。`docs/PLAN.md` 和 `docs/HANDOFF_PROMPT.md` 也在这次提交里，所以仓库将来如果公开，它们会留在历史中（见【D12】）。同一天仓库已建为**私有**的 `KazuhaHub/nethub` 并推送（Kazuha 让推送时没有指定可见性，按本计划的建议先私有）。这一步已经完成，下面的命令留作参考。
仓库属于 Kazuha 的组织，建仓库、设可见性、做第一次提交，默认由他来做。如果他让你做，参考命令：

```bash
cd nethub
git status                        # 确认只有现有的那些文件，没有 .env 之类的东西
git add -A
git status                        # 再看一遍要提交的文件列表
git commit -s -m "docs: add design v0.3, component READMEs and Weekend 0 kit"
gh repo create KazuhaHub/nethub --private --source . --push   # --private 或 --public 按【D2】
```

`docs/PLAN.md`（本文件）要不要进仓库，按【D12】决定。如果不进，提交前把它挪出仓库目录。

**P0-4 加最小 CI（你做，走 PR）。**
**进度（2026-10-17）：** [PR #1](https://github.com/KazuhaHub/nethub/pull/1) 已实现 CI 与 Dependabot；actionlint v1.7.12、TOML 结构检查与探针语法检查通过。GitHub CLI 的 `workflow` scope 已补充授权，推送恢复。线上[正常配置运行](https://github.com/KazuhaHub/nethub/actions/runs/39025182708) 的两个检查通过；将 `metadatas.device_id` 移到代理表下后，[负例运行](https://github.com/KazuhaHub/nethub/actions/runs/39025232350) 的结构检查按预期拒绝有效但字段错位的 TOML。配置已恢复，恢复后的线上运行链接见 PR。PR #1 merged as `6612cdb` with Kazuha's approval on 2026-10-17; main CI passed. P0 remains incomplete because branch protection is unavailable.

现在还没有代码，CI 先检查已有的东西：Weekend 0 的两份 TOML 能正确解析，`probe.py` 语法正确，workflow 文件本身没错。
写法参考 `KazuhaHub/authcore` 的 `.github/workflows/ci.yml`，主要学这几点：

- 顶层 `permissions: {}`，每个 job 只开自己需要的权限；
- 用 `concurrency` 取消同一个 PR 上过时的运行；
- **每个 action 都按完整的 commit SHA 固定，后面用注释写版本号**。例如 authcore 用的是
  `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`。直接从 authcore 的文件里复制这一行，不要自己编 SHA；
- 用 actionlint 检查 workflow 文件。

新建 `.github/workflows/ci.yml`，第一版大致是：

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

concurrency:
  group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

permissions: {}

jobs:
  weekend0-kit:
    name: weekend0 kit checks
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Parse TOML configs
        run: |
          python3 - <<'EOF'
          import tomllib
          c = tomllib.load(open("weekend0/frpc.toml", "rb"))
          s = tomllib.load(open("weekend0/frps.toml", "rb"))
          # frpc: every top-level key must stay top-level
          assert set(c.get("metadatas", {})) == {"device_id", "claim_placeholder"}, "frpc metadatas must be top-level and complete"
          assert "metadatas" not in c["transport"] and "metadatas" not in c["proxies"][0], "frpc metadatas misplaced"
          assert "log" in c and "log" not in c["proxies"][0], "frpc log must be top-level"
          assert c["transport"].get("heartbeatInterval") == 10 and c["transport"].get("heartbeatTimeout") == 30, "frpc heartbeat keys missing"
          # frps
          assert "log" in s and "log" not in s["httpPlugins"][0], "frps log must be top-level"
          assert s["transport"].get("heartbeatTimeout") == 30, "frps heartbeatTimeout missing"
          assert s["httpPlugins"][0]["ops"] == ["Login", "NewProxy", "NewUserConn", "Ping"], "frps ops changed"
          print("TOML structure OK")
          EOF
      - name: probe.py syntax
        run: python3 -I -m py_compile weekend0/probe.py
```

再加一个 actionlint 的 job（authcore 用 `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12`，需要先 setup-go，照抄它的两步即可）。

验证 CI：

1. 推一个分支开 PR，确认 CI 跑起来并且是绿的。
2. **故意改坏一次**：在分支上把 `frpc.toml` 里的 `metadatas.device_id` 一行挪到 `[[proxies]]` 下面，推上去，确认 CI 变红。
3. 再改回来。

这一步是为了证明检查真的会拦住错误。把红和绿两次运行的链接都贴进 PR。

**P0-5 加 Dependabot。**
新建 `.github/dependabot.yml`，先只配 `github-actions`（每周一次）。Go 和 npm 的配置等 W3 有代码了再加。可以参考 authcore 的 `.github/dependabot.yml`。

**P0-6 仓库保护规则（Kazuha 做）。**
**Completed 2026-10-21:** after the owner requested public visibility, the main
protection API accepted the policy and readback confirmed it. PRs and strict
up-to-date checks are required for administrators as well. The required jobs are
`Control plane checks`, `Go vulnerability checks`, `Deployment checks`,
`OPNsense plugin checks`, `weekend0 kit checks`, and `workflow lint`.
Force pushes and branch deletion are disabled; review conversations must be
resolved. Required approving reviews are zero for this single-owner repository;
this is not an independent-review claim. No direct-push negative test was used.
PR #106 then merged normally after all six exact-head jobs and their logs were
inspected; its main [run](https://github.com/KazuhaHub/nethub/actions/runs/39571062527)
also passed all six jobs. The earlier platform limitation below is historical.

**进度（2026-10-17）：** 查询 `repos/KazuhaHub/nethub/rules/branches/main` 返回 HTTP 403：`Upgrade to GitHub Pro or make this repository public to enable this feature.` 仓库保持私有；升级套餐或其他处理方式由 Kazuha 决定，不把这项标为已完成。CI 配置中的检查名为 `weekend0 kit checks` 与 `workflow lint`。

请 Kazuha 按组织里其他仓库的规则，给 `main` 开保护：禁止直推、必须走 PR、必须 CI 通过。
你需要告诉他 CI 里 job 的名字（例如 `weekend0 kit checks`），因为保护规则要按名字引用必过的检查。

### 验收

- [x] GitHub 上有 `KazuhaHub/nethub`，第一次提交包含现有的文件（`f529e1d`，见 P0-3）
- [x] 提交里没有任何真实地址、密钥，也没有 AI 署名。History audit on 2026-10-17 covered all eight main commits through `db3ff7b`: IPv4 literals were documentation/loopback/unspecified addresses only; the sole valid IPv6 literal was `::`; no private-key block or tracked secret-file candidate was found. The long token assignment was a configuration-template expression. Commit author, committer, and message checks found no prohibited attribution. 检查署名用下面这条，它只看作者、提交者和提交信息，不会被 CONTRIBUTING 里的规则文字误报，应该没有输出：
  `git log --format='%an <%ae>%n%cn <%ce>%n%B' | grep -niE 'co-authored-by|generated with'`
- [x] CI 在 PR 上能跑，绿；故意改坏时会红（[pass](https://github.com/KazuhaHub/nethub/actions/runs/39025182708)、[expected failure](https://github.com/KazuhaHub/nethub/actions/runs/39025232350)、[restored](https://github.com/KazuhaHub/nethub/actions/runs/39025309568)）
- [x] Dependabot 配置已合并（PR #1，`6612cdb`；Kazuha approved the merge on 2026-10-17）
- [x] Main protection was verified on 2026-10-21 through `gh api repos/KazuhaHub/nethub/branches/main/protection`: strict six-job checks, required PRs, administrator enforcement, resolved conversations, and no force pushes or branch deletion. Do not test protection by pushing directly to main.

### 常见坑

- `git add -A` 之前没看 `git status`，把本地的临时文件也提交了。每次提交前都看一遍文件列表。
- action 的 SHA 是自己编的或者抄错了。只从 authcore 现有的文件里复制。

---

## 7. 阶段 W0：传输层验证

**目标：** 在写任何产品代码之前，用真实的 frp 0.71.0，在真实网络里回答 6 个问题。答案会决定后面好几处设计（DESIGN §5、§10）。

| 编号 | 问题 | 影响什么 |
|---|---|---|
| ① | 在 NAT/CGNAT 后面的 OPNsense，不做端口转发，能不能从外部打开它的完整登录页并正常登录 | 产品能不能成立 |
| ② | frps 回调 `Login` / `NewProxy` 时，能不能同时拿到"设备身份"和"它要注册的子域名" | 安全模型（决策 #4） |
| ③ | 回调后端出错、卡住时，frps 是拒绝还是放行 | 控制面单点故障有多严重 |
| ④ | 受限网络（运营商 4G/5G、公司网）下 8443 好不好用，和 443 比差多少 | 【D5】 |
| ⑤ | `NewUserConn` 回调能不能拿到浏览器的真实 IP，拒绝它能不能挡住访问 | 【D7】 |
| ⑥ | 拒绝 `Ping` 能不能断开在线设备；控制面挂掉时在线隧道会不会全断 | 【D6】 |

**前置条件：** P0 完成；【D3】的资源全部到位（VPS、域名和泛解析、OPNsense 测试机、4G 手机）。

**产出：** 填好的结果记录；更新后的 DESIGN 相关章节；一次和 Kazuha 的结果评审。

**预计：** 3–5 天，不含等资源的时间。

### 步骤

**W0-1 通读 `weekend0/RUNBOOK.md` 两遍。**
第一遍了解全貌；第二遍拿笔记下每一步要在哪台机器上执行（VPS、OPNsense 测试机、手机、你的电脑）。
RUNBOOK 写得很细，**本阶段以 RUNBOOK 为准**，这里只列顺序和要特别注意的地方。

**W0-2 准备一份私人记录。**
复制一份 `weekend0/results-template.md` 到**仓库之外**的地方（例如 `~/nethub-w0/results-私人.md`），所有真实数据先记在这里。
真实 IP、域名不能进仓库。

**W0-3 按 RUNBOOK 第 0–2 步搭环境。**

1. 下载 frp 0.71.0 并校验 sha256（RUNBOOK 第 0 步）。校验不过就停，重新下载。
2. 配 DNS 泛解析，用 `dig` 确认生效（RUNBOOK 1.1）。
3. VPS 防火墙放行 7000 和 8443（RUNBOOK 1.2）。7500 和 9000 只绑本机，**不要**放行。
4. 在 VPS 上替换 `frps.toml` 里的 `CHANGE_ME` 占位值（RUNBOOK 1.4）。
   **本计划要求一定要配 `auth.token`**：用 `openssl rand -base64 32` 生成，`frps.toml` 和 `frpc.toml` 填同一个值，放在顶层。
   否则 frps 会在公网 7000 端口上开好几天，谁都能连。
5. 两边都先运行 `verify`，并跑 RUNBOOK 1.5 里的 `tomllib` 结构检查。`verify` 两边都输出 `syntax is ok`、结构检查的输出和 RUNBOOK 写的一致，才能继续。
6. 用模式文件的方式启动探针（RUNBOOK 1.6），再启动 frps（RUNBOOK 1.7）。
7. 在 OPNsense 测试机上**前台**手工运行 frpc（RUNBOOK 第 2 步）。不装插件，不改任何开机启动项。

**W0-4 按顺序做 ①→⑥。**
① 不通过，后面的都不用做，直接【停】找 Kazuha。每做完一项，马上把结果填进私人记录。

**W0-5 清理。**
按 RUNBOOK 附录的清理清单逐项做完。测试机有快照就恢复快照；GUI 的 WAN 放行规则如果为 W0 改过，请 Kazuha 改回去。

**W0-6 整理结果，【停】找 Kazuha 评审。**
把私人记录里的真实地址全部替换成 `example.com` / `203.0.113.10` 之类的占位值，另存为脱敏版。
评审会上，按结果和 Kazuha 一起定下【D5】【D6】【D7】【D17】。

**W0-7 提交脱敏结果，更新 DESIGN。**
Kazuha 同意之后：

1. 把脱敏版存成 `weekend0/results-<日期>.md`，开 PR；
2. 再开一个 `docs:` PR，按结果更新 DESIGN §5、§10、§12、§13、§14：
   - 把"待 Weekend 0 实测"的地方改成实测结论；
   - 在 §0 变更记录里加一行；
   - DESIGN 最后一行说过，第 5、10、12、13、14 节要随 W0 结果修订。

### 验收

- [x] Six experiments recorded; limits, omitted coverage, and failed attempts are documented in `weekend0/results-2026-10-17.md`.
- [x] Redacted Login/NewProxy JSON inputs are stored with the accepted results.
- [x] Fail-closed and blocking-hook risks are recorded.
- [x] ④ A/B each provide 20 rounds per port; Q2 did not trigger. Company/campus sampling was explicitly waived by Kazuha; see `weekend0/network-results.md`.
- [x] Exact Alternate Hostnames resolved the observed rejection; both checks remained enabled.
- [x] Kazuha accepted the findings and confirmed D5/D6/D7/D17 on 2026-10-18.
- [ ] 测试机已按清理清单恢复（有快照就恢复快照），VPS 上的临时进程、证书、443 规则已清理
- [ ] 仓库里提交的结果文件不含任何真实地址（提交前自己用 `grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}"` 检查一遍）

### 常见坑

- **TOML 表的作用域。** 写在 `[transport]` 或 `[[proxies]]` 这类表头下面的键，会归到那张表里。
  所有顶层键必须写在第一个表头之前。frp 默认 `strict_config`，放错位置会直接报错退出。
- **做 ①–⑤ 时 `Ping` 必须是 `allow`，探针不能停。** 探针一停，订阅了 `Ping` 的隧道会断开，测出来的结果就不对。
  切模式用模式文件，**不要靠重启探针**。实在要重启，先停掉 frpc。
- **③ 的 hang 组要用 `PROBE_HANG_SECONDS=120`。** 用默认的 30 秒，会和 30 秒的心跳超时撞在一起，结果不可复现。
- **用手机测时，一定要关掉 Wi-Fi。** 否则走的是家里的网络，测不出"跨 NAT"的效果。
- **① 看到错误页，不一定是穿透失败。** OPNsense 自己有 DNS 重绑定检查和 HTTP_REFERER 检查。
  经中继访问时，主机名是中继分配的子域名，很可能被拦下，页面上会出现"DNS Rebind"之类的字样。
  按 RUNBOOK ① 的说明，把测试子域名加进测试机的"Alternate Hostnames"再测。**不要关掉这两项检查。**
  把"是否被拦、加了之后是否正常"记下来，这是【D17】的依据。
- 如果 ② 发现 `NewProxy` 请求里没有 `user.metas`：这是架构级的坏消息，**立刻【停】**。

---

Experiment ⑤ (2026-10-17): mobile source IPv4 matched NewUserConn remote_addr; proxy identity and device metadata matched registration. New connections were denied while the existing mobile Dashboard remained usable and control heartbeats stayed allowed. Desktop HTTP 500 and restored-allow checks passed. Original relay services were restored. See [the user-connection report](../weekend0/userconn-results.md). Experiment ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18.

## 8. 阶段 W1：OPNsense 插件骨架

**目标：** 做出一个能安装、能卸载的 OPNsense 插件 `os-nethub-agent`。
装上后，Services 菜单下出现 "NetHub Agent"，设置页能保存一个"启用"开关，并且能在 `config.xml` 里看到这个字段。
本阶段不碰 frpc。

**前置条件：**

- W0 ① ② 通过；
- 【D10】目录布局已确认；
- OPNsense 测试机就绪；有快照的话，先做一个干净快照。

**产出：** `agents/opnsense/plugin/` 下的插件骨架；能在测试机上构建的未签名开发包；CI 里的插件静态检查。

**预计：** 5–8 天。第一次接触 OPNsense 插件开发的话，前两天主要在读参考实现。

### 先读参考实现（只读，不要改）

**先看版权【D20】。** 打包仓库的根许可证是 MIT，而且有其他版权人；里面个别插件还是第三方的 BSD-2 代码。
NetHub 要保持单一版权的 Apache-2.0（DESIGN §2）。所以：

- 参考实现**只用来看结构、学写法**，NetHub 的文件由你自己写；
- 确实想原样复制某个文件或某段代码时，先【停】问 Kazuha 那部分是谁写的、能不能这样用；
- `os-ddclient-opnwall` 和 `os-unboundcustom` 里有第三方版权的代码，**可以读，绝对不要复制**。

下表每一项都标明了"看什么"。没有哪个插件能把所有部分都示范到，要分开看：

| 参考 | 看什么 |
|---|---|
| OPNsense 官方示例插件 `devel/helloworld`（GitHub 上 `opnsense/plugins` 仓库） | 最标准的写法：设置模型 + `forms/` 表单 + 继承 `ApiMutableModelControllerBase` 的设置控制器 + 模板 `+TARGETS` |
| 打包仓库 `src/os-easytier/` | 目录布局、`build.sh`、`packaging/freebsd/` 下的四个安装钩子、JSON 版本文件、configd action，以及用临时文件把参数交给 configd 的做法（W4 会用到）。注意：它**没有**设置模型和 `forms/`，它的设置控制器也不是标准写法，这两部分看 helloworld |
| 打包仓库 `src/os-frp/` | frpc 的 rc.d 脚本（`src/usr/local/etc/rc.d/frpc`）和为什么 `daemon` 不加 `-r`；`/etc/rc.conf.d/frpc` 启用变量的做法；`build.sh` 里对 vendored frp 压缩包的 sha256 固定和二进制检查；`plugins.inc.d/frp.inc` 里关于 `newwanip` 的注释【D21】 |
| 打包仓库 `src/os-sing-box/`、`src/os-mihomo/` | `+POST_INSTALL` 的写法；`plugins.inc.d` 文件名用下划线（`sing_box.inc`）；`mihomo.inc` 里注册 `newwanip` 钩子的写法 |
| 打包仓库 `src/os-ddclient-opnwall/` | **只读**：`+POST_INSTALL` 里 `configctl template reload` 的用法，表单的写法 |

先把 helloworld 和 `os-easytier` 各看一遍，弄清楚每个文件是干什么的，再动手。

### 步骤

**W1-1【停】确认目录布局和版权做法【D10】【D20】。**
本计划建议 `agents/opnsense/plugin/` 采用和 `os-easytier` 一样的目录布局（`src/`、`packaging/freebsd/`、`build.sh`）。
这样开发时可以直接在测试机上构建，也方便打包仓库以后接手。

正式发布时，打包仓库具体怎么从 NetHub 的 release 构建这个插件，还没定。打包仓库的发布流程会按 `packaging/plugins.json` 的记录逐文件核对，不是简单调用一个脚本。这件事归 Kazuha，见【D10】【D13】。

请 Kazuha 确认这两点。

**W1-2 建目录和空文件。** 建议结构（`NetHubAgent` 是 MVC 名字空间，`nethub-agent` 是脚本和路径用的名字）：

```
agents/opnsense/plugin/
  build.sh
  packaging/freebsd/
    +MANIFEST.in
    +PRE_INSTALL
    +POST_INSTALL
    +PRE_DEINSTALL
    +POST_DEINSTALL
    pkg-descr
  src/usr/local/opnsense/
    mvc/app/models/OPNsense/NetHubAgent/
      NetHubAgent.xml
      NetHubAgent.php
      ACL/ACL.xml
      Menu/Menu.xml
    mvc/app/controllers/OPNsense/NetHubAgent/
      IndexController.php
      Api/SettingsController.php
      Api/ServiceController.php
      forms/settings.xml
    mvc/app/views/OPNsense/NetHubAgent/index.volt
    version/nethub-agent
  tests/                     # 插件自己的单元测试和静态检查
agents/opnsense/
  capabilities.md            # 这个平台向控制面声明的能力（v1 只有 remote.web），W4 写
  tests/                     # 针对 proto/ 的契约测试，W4 写（agents/opnsense/README.md 里规划的位置）
```

**W1-3 写模型 `NetHubAgent.xml` 和 `NetHubAgent.php`。**

- 挂载点 `//OPNsense/NetHubAgent`，版本从 `0.0.1` 开始。
- 字段这一阶段就全部定义好（后面的阶段才会用到大部分），字段类型和写法看 helloworld 的模型：

| 字段 | 类型 | 说明 |
|---|---|---|
| `enabled` | 布尔，默认 0 | 本阶段唯一在页面上显示的字段 |
| `server_addr` | 文本 | 中继地址，W4 由 enroll 填写 |
| `server_port` | 整数 1–65535 | 中继控制端口，通常 7000 |
| `subdomain` | 文本，格式限制 `^[a-z0-9-]{1,63}$` | DESIGN 决策 #16 要求严格白名单 |
| `device_id` | 文本 | 设备 ID |
| `device_secret` | 文本 | 敏感，页面上不显示 |
| `frp_token` | 文本 | 敏感，页面上不显示 |
| `domain_claim` | 文本 | 签名声明 |
| `cluster_hint` | 布尔 | 是否为 CARP 集群成员，只用于展示 |

- `NetHubAgent.php` 是一个空的 `BaseModel` 子类，写法看 helloworld。
- 文本字段都要加格式限制（模型里的 mask），不允许出现引号、换行这类字符。W2 会把这些值写进 TOML 配置，
  不加限制的话，一个引号或换行就能往配置里塞进别的内容。

**W1-4 写菜单和权限。**

- `Menu.xml`：在 Services 下加一项 "NetHub Agent"，链接 `/ui/nethubagent/`。
- `ACL.xml`：加一个权限项，覆盖 `ui/nethubagent/*` 和 `api/nethubagent/*`。

**W1-5 写控制器和页面。**

- `IndexController.php`：渲染 `index.volt`，把 `forms/settings.xml` 生成的表单传给页面。
- `Api/SettingsController.php`：继承 OPNsense 的 `ApiMutableModelControllerBase`，提供 get/set。
- `Api/ServiceController.php`：本阶段先返回固定的状态，W2 再接 configd。
- `forms/settings.xml`：只放 `enabled` 一个字段。
- `index.volt`：一个表单 + 一个"保存"按钮。照 helloworld 的写法，用 OPNsense 自带的表单和 AJAX 保存。

**W1-6 写版本文件 `version/nethub-agent`。** 格式必须是 JSON，字段和 `os-easytier` 的版本文件一样：

```json
{"product_abi":"26.7","product_arch":"amd64","product_id":"os-nethub-agent","product_name":"nethub-agent","product_tier":"4","product_version":"0.0.1","product_email":"<问 Kazuha>","product_website":"https://github.com/KazuhaHub/nethub"}
```

`product_email`、`product_website` 填什么，问 Kazuha。

**W1-7 写安装钩子。**

- `+POST_INSTALL` 依次做下面几步。打包仓库里没有哪个插件把这几步全做了，所以按这个清单写，每一步的写法到对应的参考里看：

  ```sh
  # 1. 登记插件（写法见 os-easytier 的 +POST_INSTALL）
  /usr/local/opnsense/scripts/firmware/register.php install os-nethub-agent
  # 2. 运行模型迁移（先在测试机上 ls 确认这个路径存在）
  /usr/local/opnsense/mvc/script/run_migrations.php
  # 3. 重新生成配置模板 —— W2 有了模板之后才加这一行（写法见 os-ddclient-opnwall 的 +POST_INSTALL）
  configctl template reload OPNsense/NetHubAgent
  # 4. 删掉菜单和权限缓存，否则菜单要等一个小时才出现
  rm -f /var/lib/php/tmp/opnsense_menu_cache.xml /var/lib/php/tmp/opnsense_acl_cache.json
  # 5. 重启 configd，让新的 action 生效
  service configd restart
  ```

  `os-easytier` 的 `+POST_INSTALL` 里还有一行调用 `kazuha.sh mirror`，**要不要加，【停】问 Kazuha**。
- `+PRE_DEINSTALL`：W2 之后要在这里停掉服务（`service nethub_agent_frpc onestop`），否则 `pkg delete` 之后 frpc 还在跑。
- `+POST_DEINSTALL`：重启 configd、删掉菜单和权限缓存，写法看 `os-easytier`。**不要删除用户在 `config.xml` 里的设置。**

**W1-8 写 `build.sh`。** 参照 `os-easytier/build.sh` 的步骤自己写（要原样复制的话先按【D20】问 Kazuha）。它要做的事：

1. 检查在 FreeBSD/OPNsense 上运行（需要 `pkg` 和 `sha256` 命令）；
2. 把 `src/` 整个复制到一个临时的 stage 目录，排除 `.DS_Store`、`._*`、`__pycache__`；
3. 检查脚本里的 `VERSION` 和版本文件里的 `product_version` 一致，不一致就报错退出——两处要一起改；
4. 给可执行文件设 `0755`（W2 起有 rc.d 脚本和 frpc）；
5. 生成文件清单，用 `packaging/freebsd/+MANIFEST.in` 填出 `+MANIFEST`；
6. 用 `pkg create` 打出 `dist/os-nethub-agent.pkg`，再用 `pkg info -F` 检查一遍。

包名是 `os-nethub-agent`。ORIGIN、COMMENT、WWW 按 NetHub 填，MAINTAINER 问 Kazuha。
NetHub 不使用打包仓库的 `common/` 共享文件（DESIGN 决策 #11），`os-easytier` 里复制它们的那一段不要照做。

**W1-9 开发循环：在测试机上构建并安装。** `build.sh` 需要 FreeBSD 的 `pkg` 命令，所以要在 OPNsense 测试机上运行：

```bash
# 在你的电脑上，把插件目录传到测试机（COPYFILE_DISABLE=1 防止 macOS 塞进 ._ 开头的垃圾文件）
COPYFILE_DISABLE=1 tar -C agents/opnsense/plugin -cf - . \
  | ssh root@<测试机地址> 'rm -rf /root/nethub-plugin && mkdir -p /root/nethub-plugin && tar -C /root/nethub-plugin -xf -'

# 在测试机上构建并安装未签名的开发包
ssh root@<测试机地址> 'cd /root/nethub-plugin && sh build.sh && pkg add -f dist/os-nethub-agent.pkg'

# 卸载
ssh root@<测试机地址> 'pkg delete -y os-nethub-agent'
```

建议把这几行写成一个脚本 `agents/opnsense/dev-deploy.sh`。测试机地址从环境变量读，**不要写死在脚本里**。

**W1-10 加测试和 CI。** 在 `agents/opnsense/plugin/tests/` 加 Python 测试，并接进 CI。DESIGN 定的是用 pytest：pytest 只在 CI 和你的电脑上装，设备上不需要。要测的内容：

- 所有 XML 文件都能解析（`xml.etree.ElementTree`）；
- 版本文件是合法 JSON，`product_id` 是 `os-nethub-agent`，`product_version` 和 `build.sh` 里的 `VERSION` 一致；
- 所有 PHP 文件通过 `php -l`（GitHub 的 ubuntu 运行环境自带 PHP）；
- 所有 shell 文件（钩子、`build.sh`）通过 `sh -n`。

### 验收（对应 DESIGN §10 W1）

- [x] 在测试机上 `pkg add` 后，Services 下出现 NetHub Agent 菜单（截图）
- [x] 勾选"启用"保存后，`grep -A 3 "<NetHubAgent" /conf/config.xml` 能看到 `enabled` 为 1（贴输出）
- [x] `+POST_INSTALL` 的每一步都核对过（贴安装时的输出）；卸载后再装一次也正常
- [x] `pkg delete` 之后菜单消失（刷新页面确认），`config.xml` 里的设置还在
- [x] 测试机的 OPNsense 版本 ≥ 26.7.1_1（贴 `opnsense-version` 的输出；DESIGN §10 W1 ③）
- [x] CI 里的插件静态检查是绿的，并且故意弄坏一个 XML 时会变红

### 常见坑

- **页面空白或 500。** 一般是 Volt 模板或 PHP 语法错误。看 System → Log Files → Web GUI，也可以在测试机上用 `php -l` 检查。
- **菜单不出现。** OPNsense 会缓存菜单，`+POST_INSTALL` 里要删缓存文件。手动测时也可以删掉缓存再刷新。
- **版本文件不是 JSON，或者少了 `product_id`。** 包能装上，但 OPNsense 不把它当插件登记，固件同步时也不会恢复它。
  打包仓库的 `DEPLOYMENT.md` 专门提醒过这个问题。
- **不要往打包仓库的 `packaging/plugins.json` 里加任何东西。** 那是正式发布才做的事，由 Kazuha 来做【D13】。
- **`pkg delete` 之后，插件在 OPNsense 的插件列表里可能还是"已登记"状态**（因为 `+POST_INSTALL` 调过 `register.php`）。
  只在开发测试机上会这样，不影响功能。要彻底恢复干净状态：有快照就恢复快照，没有就找 Kazuha。

---

## 9. 阶段 W2：frpc 集成

**目标：** 插件自带一份 frpc，按设置自动生成 `frpc.toml`，验证通过才替换，然后启动服务连上中继。
配置坏了不重启、保留旧配置；和用户自己装的 `os-frp` 互不干扰。

**前置条件：** W1 完成；【D4】frp 版本已定；W0 的 ② ③ 有结论。

**产出：** 带 frpc 的插件；`agentctl.py` 的 `reconcile` / `status` 子命令；rc.d 服务；看门狗；单元测试。

**预计：** 6–10 天。

### 步骤

**W2-0 给 W2 准备一个专用的中继。**
W0 cleanup removed its temporary relay. Prepare an isolated W2 relay using the
confirmed D6/D7/D22 settings; do not reuse an unauthenticated W0 control channel.

1. 在 VPS 上复制一份 `weekend0/frps.toml`，命名为 `frps-w2.toml`（放在 VPS 上，不进仓库）；
2. Keep the D6 server heartbeat timeout at 30 seconds; configure the client with a 10-second interval and 30-second timeout.
3. Keep `Login`, `NewProxy`, `NewUserConn`, and `Ping` subscribed with the isolated all-allow probe; product authorization remains later work.
4. 配上 `auth.token`（顶层），把这个值记下来，W2-8 手填时要用；
5. Generate a temporary deployment CA and a relay server certificate with the expected DNS SAN. Configure frps with the server certificate/key, and frpc with the CA PEM and matching serverName. Keep the CA private key outside the relay process working directory and runtime mounts. Validate both configurations with 0.71.1 before starting the probe and relay. Later negative tests must reject an unrelated CA and an incorrect serverName.

W2 做完照样清理。

**W2-1 放入 frpc 二进制【停】。**
Confirmed 2026-10-18: download the official frp 0.71.1 FreeBSD amd64 archive at build time, verify its repository-pinned SHA256 against the upstream checksum manifest, and stage only `frpc` under `/usr/local/opnsense/nethub-agent/bin/frpc` with `FRP_VERSION`. Do not commit the binary archive to NetHub.

不管哪种做法：

- 只用 GitHub 上 fatedier/frp 官方 release 的文件；
- 用官方的 `frp_sha256_checksums.txt` 校验，并把 sha256 固定写在仓库里，构建时再校验一次；
- 解压后检查拿到的确实是 FreeBSD amd64 的可执行文件。这一点和上一点的写法，都看 `os-frp/build.sh`；
- 版本必须和打包仓库里 `os-frp` 用的一致（见【D4】）。

DESIGN 决策 #19 还要求有一个 CI 检查，保证两边的 frp 版本一致。在本仓库的 CI 里加一步：比较 NetHub 的 `FRP_VERSION` 和 `deploy/` 里 frps 镜像或二进制的版本。
os-frp 那边也要有一个 `FRP_VERSION` 文件，那是 Kazuha 的仓库，写清楚需求交给他。

**W2-2 写 rc.d 服务脚本 `src/usr/local/etc/rc.d/nethub_agent_frpc`。**
照 `os-frp` 的 `frpc` 脚本改，下面这些名字和路径**全部要换成 NetHub 自己的**，一个都不能和 os-frp 重复（DESIGN §4 共存规则）：

| 项 | os-frp 用的 | NetHub 用的 |
|---|---|---|
| 服务名 / rcvar | `frpc` / `frpc_enable` | `nethub_agent_frpc` / `nethub_agent_frpc_enable` |
| 二进制 | `/usr/local/sbin/frpc` | `/usr/local/opnsense/nethub-agent/bin/frpc` |
| 配置 | `/usr/local/etc/frp/frpc.toml` | `/usr/local/etc/nethub-agent/frpc.toml` |
| pid 文件 | `/var/run/frpc.pid` | `/var/run/nethub_agent_frpc.pid` |
| 日志 | `/var/log/frpc.log` | `/var/log/nethub-agent/frpc.log` |
| `daemon -t` 标题 | `frpc` | `nethub_agent_frpc` |

`daemon` 同样**不加 `-r`**。原因见 os-frp 脚本里的注释，以及 DESIGN 决策 #13、#14。

另外两点：

- **启用变量。** FreeBSD 的 rc 系统只有在 `nethub_agent_frpc_enable=YES` 时才允许 `service ... start`。
  参照 os-frp 的做法，由 reconcile 写 `/etc/rc.conf.d/nethub_agent_frpc`：设置里 `enabled` 为 1 且没有熔断文件时写 `YES`，否则写 `NO`。
  不能用 `service ... start` 的地方（例如卸载钩子），用 `onestart` / `onestop`。
- **日志。** frpc 的日志交给 `daemon -o` 写进 `/var/log/nethub-agent/frpc.log`。模板里要写 `log.to = "console"`，
  不要让 frpc 自己也写这个文件，否则两个进程同时写一个文件。
  rc 脚本的启动前步骤用 `install -d -m 0700 /var/log/nethub-agent` 建好目录。

**W2-3 写配置模板。**
`src/usr/local/opnsense/service/templates/OPNsense/NetHubAgent/` 下放两个文件：

- `+TARGETS`：一行，`frpc.toml.j2:/usr/local/etc/nethub-agent/frpc.toml.candidate`。
  渲染到 `.candidate` 文件，而不是直接覆盖正在用的配置（决策 #13）。
- `frpc.toml.j2`：模板。读配置值的语法看 helloworld 的模板。要点：
  - **所有顶层键写在 `[[proxies]]` 之前**，这是 W0 学到的教训；
  - 加 `loginFailExit = false`，让 frpc 在控制面暂时不可用时一直重试；W0 工具里用的是默认值 true，产品里不能这样；
  - `metadatas.device_id`、`metadatas.domain_claim` 放顶层，W4 的校验要用；
  - `transport.tls.enable = true`；心跳参数按【D6】的结论决定写不写；
  - **服务端证书校验【D22】**：只开 `transport.tls.enable` 时，frpc 不校验 frps 的证书（frp v0.71.0 源码：没配 CA 就 `InsecureSkipVerify`），
    链路上的中间人能冒充中继、截下 domain claim。按【D22】的结论，在模板里加上 `transport.tls.trustedCaFile` 和 `transport.tls.serverName`；
    W2 阶段先留好字段，W4 由 enroll 响应把 CA 证书（PEM 格式，frpc 不支持指纹）带下来；
  - `[[proxies]]` 里：`type = "https"`、`localIP = "127.0.0.1"`；`localPort` 从 OPNsense 的 Web GUI 端口设置读，为空时用 443；
    `subdomain` 用设置里的 `subdomain`（**不要用 `customDomains`**，frps 会拒绝，见 DESIGN §5）；
  - 设置里 `enabled` 不是 1 时，渲染出一个空文件或者带明显标记的文件，`reconcile` 看到它就停服务。

  模板示意（具体语法以 helloworld 和 OPNsense 文档为准）：

  ```toml
  serverAddr = "{{ OPNsense.NetHubAgent.server_addr }}"
  serverPort = {{ OPNsense.NetHubAgent.server_port }}
  auth.token = "{{ OPNsense.NetHubAgent.frp_token }}"
  loginFailExit = false
  log.to = "console"
  log.level = "info"
  metadatas.device_id = "{{ OPNsense.NetHubAgent.device_id }}"
  metadatas.domain_claim = "{{ OPNsense.NetHubAgent.domain_claim }}"
  transport.tls.enable = true

  [[proxies]]
  name = "nethub-webgui"
  type = "https"
  localIP = "127.0.0.1"
  localPort = {{ system.webgui.port|default('443', true) }}
  subdomain = "{{ OPNsense.NetHubAgent.subdomain }}"
  ```

  所有填进双引号里的值，都必须已经过模型的格式限制（W1-3），保证里面没有引号和换行。
  W2-9 要写一个测试：故意给一个带引号或换行的值，确认模型保存时就被拒绝。

**W2-4 写 `agentctl.py`。** 路径 `src/usr/local/opnsense/scripts/nethub-agent/agentctl.py`。

- 只用 Python 标准库，因为 OPNsense 上没有额外的包。
- 用 `argparse` 做子命令，本阶段实现 `reconcile` 和 `status`；`enroll`、`unenroll`、`rotate` 先留占位，返回"未实现"。

`reconcile` 的流程（DESIGN 决策 #10、#13、#17），每一步都要写日志：

1. 如果存在本地熔断文件 `/var/db/nethub-agent/disabled`：停掉服务，记录状态，退出。**不碰 `config.xml`。**
2. 用文件锁（`fcntl.flock`）保证同一时间只有一个 reconcile 在跑。
3. D21: do not register `newwanip`. Let frpc reconnect and run periodic reconcile. If W2 WAN-address recovery fails, implement the fallback hook with a 60-second minimum interval and 0–30-second jitter.
   这个等待**不能卡住 OPNsense 的 WAN 事件处理**：钩子里只负责把 reconcile 放到后台启动，立刻返回。
4. 运行 `configctl template reload OPNsense/NetHubAgent`，生成 `.candidate` 文件，**马上** `os.chmod(candidate, 0o600)`。
   里面有 token，不能让其他用户读到。`/usr/local/etc/nethub-agent/` 目录本身也设成 `0700`。
5. 运行 `<frpc> verify --strict_config=true -c <candidate>`。
6. 验证不通过：**保留旧配置，不重启**，把错误写进状态文件，退出码非 0。
7. 验证通过：
   - 和当前配置比较内容。
   - **内容相同**：不重启。但如果服务应该运行（`enabled` 为 1、没有熔断文件）而实际没在运行，就启动它。
     这样才能覆盖三种情况：关掉熔断开关后要恢复、重启后要自动起来、frpc 崩溃后要拉起来。
   - **内容不同**：先把当前配置另存为 `frpc.toml.last-good`，再用 `os.replace` 原子替换，然后重启服务。
8. 状态写进 `/var/db/nethub-agent/state.json`：上次运行时间、是否成功、错误信息。先写临时文件，再 `os.replace`，保证不会写出半个文件。

`status`：把 rc.d 服务状态、日志最后几行、`state.json` 合成一个 JSON 输出给 GUI。**不要开 frpc 的 `[webServer]`**，它的默认端口和 os-frp 冲突（DESIGN §4）。

**W2-5 注册 configd action。**
`src/usr/local/opnsense/service/conf/actions.d/actions_nethub-agent.conf` 里注册 `reconcile`、`status`、`start`、`stop`、`restart`，格式照 `os-easytier`。
注册好后，在测试机上用 `configctl nethub-agent status` 测试。`ServiceController.php` 改成调这些 action。

**W2-6 接 OPNsense 的钩子。**

- `src/usr/local/etc/inc/plugins.inc.d/nethub_agent.inc`。**文件名用下划线**：OPNsense 用文件名拼出钩子函数名（`nethub_agent_services()`、`nethub_agent_configure()`），
  PHP 函数名里不能有连字符，写成 `nethub-agent.inc` 的话服务和钩子都不会生效。打包仓库的 `os-sing-box` 就是用 `sing_box.inc`。
  - 注册服务，让它出现在 Services 状态页。写法看 `os-frp` 的 `frp.inc`。
  - D21 confirmed: omit `newwanip`; use automatic reconnect and periodic reconcile. Register a debounced hook only if the WAN-address recovery acceptance test fails.
- 开机收敛：OPNsense 的开机钩子目录在 `/usr/local/etc/rc.syshook.d/`（先在测试机上 `ls` 确认），
  在插件里对应放 `src/usr/local/etc/rc.syshook.d/start/20-nethub-agent`。
  这一步补上"`config.xml` 被恢复到一台已经装了插件的机器上"的情况（DESIGN §4）。

**W2-7 看门狗【停】。**
Confirmed by Kazuha on 2026-10-18: use package-owned system-format entries under
`/usr/local/etc/cron.d/`, with root user fields, absolute paths, and output in the
plugin log. Run reconcile each minute and an independent watchdog every five
minutes. Both use `lockf -t 0` on the same persistent lock; contention skips a run.
The cron file must be in the package plist and removed by pkg during uninstall.

Before rollback, persist the rejected live configuration SHA256 and the attempt
budget in `recovery.json`. Reconcile must not reapply that desired configuration
or restart an abandoned service until the desired configuration changes. The
watchdog may attempt rollback/start only once, as recorded in that file. It must
not import agentctl. Disabled, locally stopped, kill-switched, and locally known
revoked devices cannot be recovered or restarted. W5 will supply verified remote
revocation receipt; W2 tests the persistent local revoked marker without claiming
that remote revocation propagation already exists.

**W2-8 页面加状态显示和调试区。**

- 设置页显示：服务状态、上次 reconcile 的结果和错误。
- 为了本阶段能手工测试，加一个"高级（仅调试）"区，可以手填 `server_addr`、`server_port`、`subdomain`、`frp_token`、`device_id`。
  **在 PR 描述里写明：W4 做完 enroll 之后要删掉这个调试区或者改成只读。** 然后在 W4 的任务里落实。

**W2-9 单元测试。**

- **模板渲染**：在测试里用 `jinja2`（只在 CI 和你的电脑上装）加载 `frpc.toml.j2`，传入一个模拟的配置字典，例如
  `{"OPNsense": {"NetHubAgent": {...}}, "system": {"webgui": {"port": ""}}}`，以及 OPNsense 模板会用到的辅助对象（用一个简单的假对象代替）。
  检查：
  - 结果能被 `tomllib` 解析；
  - 顶层键都在 `[[proxies]]` 之前；
  - 没有 `customDomains`；
  - Web GUI 端口为空时 `localPort` 是 443。
- reconcile 的几条分支，用假的 frpc、configctl、service（写几个小脚本，返回你想要的结果）：
  - 验证通过、内容不同 → 替换并重启；
  - 验证失败 → 不重启，`state.json` 里有错误；
  - 熔断文件存在 → 停服务，rc 启用变量是 `NO`；
  - 内容相同、服务在运行 → 什么都不做；
  - **内容相同、服务没在运行 → 启动服务**；
  - `.candidate` 文件的权限是 `0600`。
- 防抖逻辑（如果【D21】决定注册 `newwanip`）：60 秒内第二次触发被跳过。
- 模型的格式限制：带引号、换行的值保存时被拒绝。

### 验收（对应 DESIGN §10 W2）

Native checks completed 2026-10-18; see [evidence and limits](../agents/opnsense/plugin/tests/w2-progress.md).

- [x] Install the package without restarting cron and observe its first scheduled execution within one minute.
- [x] Reboot the guest and verify the package-owned cron entries still execute.
- [x] Uninstall the package and verify pkg removed the cron file and scheduled jobs no longer run.
- [x] Exercise shared-lock contention, one-attempt rollback quarantine, changed-desired release, abandoned-service suppression, and revoked-device suppression.
- [x] Change the WAN address on the NAT test guest while an isolated tunnel is active. Record address-change, disconnect, registration, and GUI-recovery times. Do not invoke reconcile manually. If frpc and scheduled reconcile cannot recover automatically, implement and retest the debounced newwanip fallback before W2 passes (D21).
- [x] 用调试区手填 W2-0 中继的地址和 token，服务启动并连上。frps 日志里有这台设备的 `new proxy ... success`（贴日志，地址打码）
- [x] 故意把模板改坏（例如加一个不存在的键），reconcile 报错、**不重启**、旧配置还在、页面上显示错误（贴输出）
- [x] 熔断文件存在时，隧道停下，`config.xml` 没有变化（对比前后的 sha256）；删掉熔断文件再 reconcile，隧道恢复
- [x] `pkg delete` 之后没有残留的 frpc 进程（`ps aux | grep nethub_agent_frpc` 只看到 grep 自己）
- [x] 在同一台测试机上装 `os-frp` 并让它运行：两个服务同时正常，`sockstat -4 -l` 里没有端口冲突，os-frp 的配置文件前后 sha256 一致
- [x] 重启测试机后，服务自动起来并连上
- [x] 渲染出的 `frpc.toml` 权限不是所有人可读（`ls -l` 贴输出），因为里面有 token
- [x] 单元测试在 CI 里跑，绿

### 常见坑

- **配置文件权限。** `frpc.toml` 里有 token，要确认模板渲染出来的文件、替换后的文件都是 `0600`。
  os-frp 也有同样的问题，看它是怎么处理的。
- **rc 变量名只能用下划线**，不能用连字符，所以服务名是 `nethub_agent_frpc`。
- **不要往 frpc 加 `-r` 或者别的自动重启机制。** 配置一坏，自动重启只会变成看不见的死循环。
- **不要在 agentctl 里直接手写 `config.xml`。** 本阶段 agentctl 只读设置（通过模板），不写。写设置的问题在 W4 处理。

---

## 10. 阶段 W3：Go 控制面骨架

**目标：** 用 Go 做出控制面 `nethub` 二进制的骨架，包括：

- 数据库表结构、角色、行级安全（RLS）；
- `nethub web` 的本地管理员登录；
- React 控制台的外壳：登录页、空设备列表、生成 enroll token；
- `nethub init` 的雏形。

最后要能在一台干净的 VPS 上用 `docker compose up` 一次跑起来。

**前置条件：**

- W0 完成；
- 【D8】v1 功能清单、【D11】数据模型、【D15】首个管理员的创建顺序都已确认；
- 【D9】组件库在 W3-0 之后确认。

**产出：** `server/` 下的 Go 模块和 React 工程；`deploy/docker-compose.yml`；数据库迁移；单元测试和集成测试；CI 扩展。

**预计：** 10–15 天。

### 技术选型（大部分已定，个别【D16】要确认）

| 方面 | 选择 | 状态 |
|---|---|---|
| Go 版本 | 1.26.x（与组织其他 Go 仓库同一条线） | 已定 |
| 模块位置和路径 | `server/`，`github.com/KazuhaHub/nethub/server` | 已定 |
| HTTP | 标准库 `net/http`（Go 1.22 起支持按方法和路径路由） | 建议 |
| 命令行子命令 | 标准库 `flag`，自己分发 `web` / `authz` / `migrate` / `init` / `doctor` | 建议【D16】 |
| 数据库驱动 | `github.com/jackc/pgx/v5`（`pgxpool`） | 建议【D16】 |
| 迁移工具 | `github.com/pressly/goose/v3`，SQL 文件用 `embed` 打进二进制 | 建议【D16】 |
| 密码哈希 | `golang.org/x/crypto/argon2`（argon2id） | 已定（DESIGN） |
| 日志 | 标准库 `log/slog` | 建议 |
| 前端 | React + TypeScript + Vite，构建产物用 `go:embed` 打进二进制 | 已定 |
| 组件库 | 看 W3-0 的示例再定 | 【D9】 |

### 步骤

**W3-0 做 UI 组件库示例，交给 Kazuha 选【D9】。**
**Progress (2026-10-17):** The three samples and strict-CSP measurements are complete; see [the comparison and raw evidence](ui-study/README.md). Gzip totals: Ant Design 274.5 KiB, Mantine 143.2 KiB, shadcn/ui 102.3 KiB. All default integrations inject blocked style elements. A shadcn/native-dialog variant passed the tested flows with zero CSP events, including focus containment, Escape dismissal, focus return, and mobile layout. Kazuha confirmed shadcn/ui with native dialog for D9; no sample source or product dependency has been added to main.

在仓库之外新建一个临时的 Vite + React + TypeScript 工程，分别用三个候选库各做两页：登录页和设备列表页（用假数据，3–5 台设备，有在线和离线）。
三个候选：

- **Ant Design**：组织里的 Report-Portal 在用；
- **Mantine**；
- **shadcn/ui**（Tailwind + Radix）。

给每个候选整理这些信息：

- 截图：浅色、深色各一张；
- `npm run build` 后的产物大小；
- **能不能在严格的 CSP（`style-src 'self'`，不允许内联样式）下正常工作。** 有的库运行时往页面里插 `<style>` 标签，在严格 CSP 下会失效，必须实测；
- 你自己用下来的感受。

示例代码不进 `main`。截图和结论发给 Kazuha，等他选定。

**W3-1 初始化 Go 模块。**

```bash
cd server
go env GOWORK                 # 有输出就 export GOWORK=off
go mod init github.com/KazuhaHub/nethub/server
```

然后：

- 把 `go.mod` 的 `go` 行设成 1.26 系列，例如 `go mod edit -go=1.26.0`（具体小版本和 Kazuha 对一下，组织里其他仓库用的是 1.26.x）；
- 按 DESIGN §6 的规划建目录：`cmd/nethub/`，`internal/{web,authz,claim,auth,oidc,store,audit,clientip,frps}/`，以及 `web/`（前端）；
- `cmd/nethub/main.go` 先把五个子命令搭好，每个打印一行"未实现"。

**W3-2 本地开发数据库。**
新建 `deploy/compose.dev.yml`，只有一个 `postgres:16` 服务，端口只绑 `127.0.0.1`，密码从一个被 `.gitignore` 忽略的本地文件读。
用 `docker compose -f deploy/compose.dev.yml up -d` 启动，用 `psql` 能连上。

**W3-3 写第一个迁移（核心表、角色、RLS、列级授权）。**
照 DESIGN §6 的 DDL 写。分两部分：**数据库和角色**由 Postgres 容器初始化时创建；**表和权限**由迁移创建。

**数据库和角色（容器初始化脚本）：**

- 角色是整个数据库集群级别的，必须用超级用户创建。
- 用官方镜像的初始化目录 `/docker-entrypoint-initdb.d/` 放一个 **shell 脚本**（例如 `00-nethub-roles.sh`），不要用纯 `.sql` 文件。原因是 `.sql` 文件读不了密钥文件。
- 这个脚本要做的事：
  1. 创建四个角色 `nethub_owner`、`nethub_web`、`nethub_authz`、`nethub_backup`，密码从各自的密钥文件读；
  2. `CREATE DATABASE nethub OWNER nethub_owner;`。Postgres 15 起，普通角色默认不能在 `public` schema 里建表，所以要让 `nethub_owner` 当库的属主；
  3. 按 DESIGN §6 和【D11】的结论设置各角色属性（谁有 `BYPASSRLS` 等）。
- Passwords must never appear in argv or generated SQL text. The initialization
  hook reads service-specific mounted files with PostgreSQL pg_read_file inside
  a privileged bootstrap block. Disable statement/error-statement logging for
  that session, validate generated hex secrets, and never print them. PostgreSQL
  owns the mounted files before dropping root privileges. The earlier psql -v
  password example is superseded by the confirmed D11 input/file requirement.

- **这个目录里的脚本只在数据卷为空、第一次初始化时运行。** 改了脚本要重新测，就先删掉开发库的数据卷。
- 这样做，Postgres 容器在初始化时要拿到全部四个角色的密码，和决策 #21"每个容器只拿自己的密钥"有出入，列在【D11】里请 Kazuha 确认。

**迁移本身（以 `nethub_owner` 运行，`nethub migrate`）：**

1. 建 DESIGN §6 列出的全部表；
2. **在同一个迁移里插入唯一的那一行租户数据**（v1 一个实例一个租户），并 `GRANT SELECT ON tenants` 给 web 和 authz；
3. 每张租户表都执行 `ENABLE ROW LEVEL SECURITY` 和 `FORCE ROW LEVEL SECURITY`，并建策略；
4. 按 DESIGN §6 的列级授权示例给 `nethub_web` 和 `nethub_authz` 分配权限；
5. 建 `consume_enroll_token` 函数，并按下面的方式收紧它的执行权限。

示意（以 `devices` 为例，完整的列清单以 DESIGN §6 和【D11】为准）：

```sql
ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON devices
  USING (tenant_id = current_setting('app.tenant_id')::uuid)
  WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- 读权限也按列给：哈希列（device_secret_hash 等）不给 web 读。待【D11】确认最终列清单
GRANT SELECT (id, tenant_id, owner_user_id, label, hostname, subdomain, platform, platform_version,
              agent_version, capabilities, cluster_hint, enrolled_at, revoked, revoked_at,
              revoked_by_user_id, last_seen_at)
  ON devices TO nethub_web;
GRANT UPDATE (revoked, revoked_at, revoked_by_user_id, label) ON devices TO nethub_web;
-- nethub_web 没有 INSERT，也不能改 subdomain、声明、哈希等身份列
```

`consume_enroll_token` 是以属主权限执行的特权函数（`SECURITY DEFINER`），要注意两点：

```sql
CREATE FUNCTION consume_enroll_token(p_token_hash bytea)
  RETURNS TABLE (tenant_id uuid, created_by_user_id uuid)
  LANGUAGE sql SECURITY DEFINER
  SET search_path = pg_catalog, public
AS $$ ... $$;
-- Postgres 默认把新函数的执行权限给 PUBLIC，必须先收回，否则 nethub_web 也能调用它
REVOKE ALL ON FUNCTION consume_enroll_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION consume_enroll_token(bytea) TO nethub_authz;
```

参数类型要和 DESIGN §6 里 `enroll_tokens.token_hash` 列的类型一致（上面写的 `bytea` 只是示意）。
它要返回 `created_by_user_id`，因为 W4 建设备时要用它来设置 `devices.owner_user_id`（DESIGN §6）。

DESIGN §6 还建议做"一次性撤销"（web 只能把 `revoked` 设成 true，不能改回 false）。这属于【D11】，确认后再加。

**W3-4 数据库访问层 `internal/store`。**

- 每种角色一个连接池：web 进程只用 `nethub_web` 的连接。
- **每个请求一个事务**，事务开始时执行 `SELECT set_config('app.tenant_id', $1, true)`。第三个参数 `true` 表示只在本事务内有效。
- v1 一个实例只有一个租户（DESIGN §6），租户 ID 在启动时读出来。
- **按用户隔离在这一层做**：`member` 的设备查询统一加 `owner_user_id = 当前用户` 过滤。RLS 只按租户隔离，管不到同一租户里的不同用户（DESIGN §6、§13 场景 #2）。
  不要让每个接口自己记得加这个过滤，要在 store 层提供"只查当前用户设备"的函数。

**W3-5 认证 `internal/auth`。**

- 密码：用 argon2id 哈希，参数先用 OWASP 的推荐值（内存 19 MiB、迭代 2 次、并行 1），存成带参数的标准字符串格式，这样以后能调参数。
- 会话：
  - 用 `crypto/rand` 生成 32 字节随机 token，数据库里只存它的 SHA-256；
  - cookie 用 `__Host-` 前缀（例如 `__Host-nethub_session`），设 `HttpOnly`、`Secure`、`SameSite=Lax`、`Path=/`，不设 `Domain`。
    设备页面跑在同站的兄弟子域名上，内容由设备主人控制，`__Host-` 前缀能防止它们设置或覆盖控制台的 cookie（`docs/console-api.md` §2）；
  - 设空闲超时和绝对超时（具体时长问 Kazuha，没有结论时先用 30 分钟空闲、12 小时绝对）。
- CSRF：每个会话一个同步令牌。所有会修改数据的请求，必须在自定义请求头（例如 `X-CSRF-Token`）里带上它，否则返回 403。
- 登录限流：按客户端 IP 和按账号各限一份，存在内存里。
- 客户端 IP（`internal/clientip`）：只有请求来自配置里声明的可信代理时，才读 `X-Forwarded-For`。
  - 可信代理就是 Caddy 容器。在 compose 里给内部网络固定一个子网和 Caddy 的地址，否则容器重启后地址会变。
  - 如果不可信的来源也带了这类头，打一条明显的警告日志。这是 Report-Portal 的 `proxySeen` 做法，DESIGN §6 有说明。

**W3-6 控制台 API `internal/web`。** 接口的约定、字段和错误码以 [`docs/console-api.md`](console-api.md) 为准；实现时如果要改，在同一个 PR 里更新这份文档。本阶段的接口：

| 方法与路径 | 作用 |
|---|---|
| `POST /api/v1/console/login` | 邮箱 + 密码登录，设置会话 cookie，返回用户信息和 CSRF 令牌 |
| `POST /api/v1/console/logout` | 退出，删除服务端的会话记录 |
| `GET /api/v1/console/session` | 返回当前登录状态和 CSRF 令牌 |
| `GET /api/v1/console/devices` | 设备列表（本阶段为空） |
| `POST /api/v1/console/enroll-tokens` | 生成一次性 enroll token，**只在这次响应里返回明文**，数据库只存哈希；有效期由数据库默认值决定（15 分钟） |

所有响应都加安全头：

- 严格的 `Content-Security-Policy`（至少包括 `default-src 'self'`、`frame-ancestors 'none'`、`base-uri 'none'`）；
- `X-Content-Type-Options: nosniff`；
- `Referrer-Policy: no-referrer`；
- API 响应加 `Cache-Control: no-store`。

**W3-7 React 外壳 `server/web`。**

- 用 Vite + React + TypeScript 和【D9】选定的组件库。
- 三个页面：登录、设备列表（显示"还没有设备"）、生成 enroll token（显示 token 和倒计时，提示"只显示这一次"）。
- 所有请求走一个统一的封装函数：自动带上 CSRF 头；收到 401 就跳回登录页。
- 构建输出到 `server/internal/webui/dist/`，Go 端用 `//go:embed all:dist` 嵌入，参考 Report-Portal 的 `internal/web/web.go`。
- `dist/` 里的构建产物不提交，只提交一个 `.gitkeep` 占位。注意三件事：
  1. `.gitignore` 里已经有 `dist/` 规则。整个目录被忽略之后，单独一行 `!` 是救不回来的，要这样写：

     ```gitignore
     !server/internal/webui/dist/
     server/internal/webui/dist/*
     !server/internal/webui/dist/.gitkeep
     ```

  2. Vite 构建时会清空输出目录，把 `.gitkeep` 也删掉。在 Vite 配置里关掉 `emptyOutDir`，或者在构建脚本里构建完再把 `.gitkeep` 放回去。
  3. `.gitignore` 里还有一条 `lib/` 规则（Python 用的），会把前端的 `src/lib/` 也忽略掉（shadcn/ui 默认就用这个目录）。
     选了组件库之后检查一遍，需要的话加例外。

**W3-8 `nethub init` 雏形【D15】【D18】。**
Confirmed D15/D18 order (2026-10-18):

1. `nethub init`：
   - 问两个域名：设备用的泛域名（例如 `router.example.com`）、控制台用的域名（【D18】）；
   - 生成全部密钥，按服务分别写进 `deploy/secrets/<服务名>/`；
   - 写 `docker-compose.override.yml`；
   - **强制备份提示**（要求输入一句确认的话才能继续）。
2. `docker compose up -d`。
3. Confirmed D15: use `docker compose run --rm admin-bootstrap --email ...` after migration. This separate one-shot service has owner credentials; web does not. Init prints the command.
   The separate owner-only bootstrap command is implemented; see D15 and w3-decisions.md.

密钥清单以 DESIGN 决策 #21 和 §7 为准。随机数一律用 `crypto/rand`。

**W3-9 `deploy/docker-compose.yml` 和 Dockerfile。**

- 本阶段的服务：`postgres`、`migrate`、`nethub-web`、`caddy`。`nethub-authz` 和 `frps` 在 W4 加，`backup` 在 W7 加。
- `migrate` 是一个一次性服务：用同一个镜像运行 `nethub migrate`，只挂 `nethub_owner` 的密钥，跑完就退出。
  `nethub-web` 用 `depends_on` 的 `condition: service_completed_successfully` 等它成功，再启动。
- 每个服务只挂自己那份密钥目录。
- **密钥文件的属主和权限。** 文件在宿主机上是 `0600` 的话，容器里用别的用户身份运行的进程读不到。
  要按每个容器实际运行的 UID 设置文件属主，例如官方 Postgres 镜像里是 `postgres` 用户，distroless 镜像默认是 nonroot 用户。
  在 `nethub init` 里写清楚每个文件给哪个 UID，并在 `deploy/README.md` 里说明。
- Dockerfile 分三段：Node 构建前端 → Go 构建（`CGO_ENABLED=0`）→ 一个很小的运行镜像。运行镜像用哪个【D16】。

**W3-10 测试。**

单元测试：

- 密码哈希能验证、错误密码失败；
- 会话 token 的哈希；
- 缺 CSRF 头时返回 403；
- 限流生效；
- 不可信来源的 `X-Forwarded-For` 被忽略。

集成测试（需要真实的 Postgres）：

- **RLS 双租户**：以 `nethub_owner` 再手工插入第二个租户和它的设备，然后以 `nethub_web` 把 `app.tenant_id` 设为租户 A 查询，只能看到 A 的设备。
- **同租户按用户隔离**：插入一个 `member` 用户，以及分别属于 admin 和这个 member 的设备，通过 store 层的"只查当前用户设备"函数查，member 只能看到自己的。
- **列级授权**：以 `nethub_web` 执行 `UPDATE devices SET subdomain = 'x'`，必须报权限错误（SQLSTATE `42501`）；以 `nethub_web` 向 `devices` 插入一行，也必须报 `42501`。
- **特权函数**：以 `nethub_web` 调用 `consume_enroll_token(...)`，必须报 `42501`。
- **没设置 `app.tenant_id` 时**：查询报错或返回空，绝不能返回数据。

**W3-11 扩展 CI。** 参考 authcore 的 `ci.yml`：

- Go job：`go build`、`go vet`、`gofmt` 检查、`go test -race`。
- 集成测试的数据库：用 GitHub Actions 的 `services: postgres:16`。
  注意 `services` 容器在代码检出**之前**就启动了，挂不了仓库里的初始化脚本。所以要在测试之前加一步，用超级用户运行 `psql`，执行 W3-3 里的建角色、建库步骤，再运行 `nethub migrate`。
- `govulncheck` job。
- 前端 job：`npm ci`、`npx tsc --noEmit`、`npm run build`。
- Dependabot 加上 `gomod`（目录 `/server`）和 `npm`（目录 `/server/web`）。
- 新增的 job 名字告诉 Kazuha，让他加进 `main` 的必过检查。

**W3-12 在干净 VPS 上部署一次。**
找一台全新的 VPS（或者把 W0 的 VPS 重装），按 `deploy/README.md` 的步骤从零部署。**一次成功**才算过。
过程中凡是需要你"临时想办法"的地方，都要改进文档或脚本。

### 验收（对应 DESIGN §10 W3）

- [x] 能用首个管理员登录、生成 enroll token、看到空设备列表（截图）
- [x] RLS 双租户测试、同租户按用户隔离测试、列级授权测试（不能改身份列、不能插入 `devices`）、特权函数测试、未设租户测试，都在 CI 里跑，绿
- [x] 在干净 VPS 上 `docker compose up -d` 一次成功（贴命令输出），`migrate` 服务正常退出，控制台有有效的 HTTPS 证书
- [x] 页面在严格 CSP 下没有被拦截的资源（浏览器开发者工具的 Console 里没有 CSP 报错）
- [x] CI 全绿；`govulncheck` 没有报告漏洞

Evidence: source e27e908, main CI run 39192294899, and the combined clean-host public run in [deployment validation](../deploy/validation-w3.md). Go advisory scope is recorded separately. The isolated clean-VM/public run passed. Kazuha accepted the fresh Debian VM with bounded public TCP forwarding through the existing LXC in place of a new VPS on 2026-10-18. The closing record PR must pass the normal exact-head CI gate before W4 implementation.

### 常见坑

- **租户设置泄漏。** 用 `SET` 而不是 `SET LOCAL`（或者 `set_config(..., false)`），租户设置会留在连接池的连接上，被下一个请求带走。
  必须在事务里用本地设置。
- **只在 Go 代码里加 `WHERE tenant_id`、不开 RLS。** RLS 就是为了防"某个查询忘了加过滤"，两样都要有。
- **enroll token 明文写进日志。** 任何 token、密码、密钥都不能打日志。
- **用 `math/rand` 生成 token。** 必须用 `crypto/rand`。
- 组件库在严格 CSP 下样式失效。W3-0 就要测出来，不要等到 W3-7。

---

## 11. 阶段 W4：真实 enroll 全流程

**目标：** 把整条链路串起来——控制台生成 token → 在路由器页面粘贴 token、点 Enroll → 设置自动填好 → 服务连上 →
控制台设备列表在 15 秒内显示"在线"。

**前置条件：** W2、W3 完成；W0 ② 的真实字段名已保存；协议版本规则【D16】已确认。

**产出：**

- `proto/` 下的 JSON Schema 和契约测试；
- `internal/claim`（签名声明）；
- `nethub authz`：设备 API、frps 回调处理、只读轮询；
- frps、Caddy 的部署配置；
- 插件的 enroll 页面和 `agentctl.py enroll`。

**预计：** 10–15 天。

### 步骤

**W4-1 写协议 Schema【D16】【D19】。**
这是第一个改 `proto/` 的 PR，要按 `CONTRIBUTING.md` 的协议修改规则来：写版本号、写契约测试、在 PR 描述里写兼容性影响（第一版就写"首个版本，无已部署的 agent"）。
【D19】决定插件怎么拿到控制台地址；如果地址编进 token，token 的格式也要写进协议。
在 `proto/` 下按版本建目录，例如 `proto/v1/`，每条消息一个 `.schema.json`：

- enroll 请求、enroll 响应；
- status；
- rotate 请求和响应、unenroll 请求和响应；
- domain claim。

**Version policy (confirmed 2026-10-18; see w4-decisions.md):**

- `proto/VERSION` 放一个整体的语义化版本号；
- agent 在 enroll 请求里上报的 `agent_protocol_version` 就是这个值；
- 服务端只接受主版本号相同的 agent，其他版本明确拒绝，并返回一句人能看懂的错误（`proto/README.md`）。

**字段：**

- enroll 请求至少包含：
  - `enroll_token`、`agent_protocol_version`；
  - `platform` (bounded platform-neutral identifier; the OPNsense builder reports `"opnsense"`), `platform_version`, `agent_version`;
  - `capabilities`（v1 只有 `["remote.web"]`）；
  - `hostname`、`cluster_hint`。
- enroll 响应：`device_id`、`device_secret`、`frp_token`、`server_addr`、`server_port`、`subdomain`、`domain_claim`，
  以及按【D22】的结论下发的中继 CA 证书（PEM）。这个响应走的是已校验的 HTTPS，所以用它分发中继的信任根是安全的。
- **协议里不能出现 OPNsense 专用的词**，例如 `config_xml`（`proto/README.md`）。

**示例和契约测试：**

- 在 `proto/examples/` 下放合法和非法两类示例；agent 这一侧的契约测试放在 `agents/opnsense/tests/`，同时写 `agents/opnsense/capabilities.md`（v1 只声明 `remote.web`）；
- Go 端用 `github.com/santhosh-tekuri/jsonschema/v6` 校验示例和 handler 的真实输出；
- Python 端只在 CI 里装 `jsonschema` 包，校验 `agentctl.py` 组装出的请求。设备上不装这个包。

**W4-2 签名声明 `internal/claim`。**

- 载荷：`{device_id, subdomain, tenant_id, issued_at, key_id}`（DESIGN §5）。
- 规范编码：用固定字段顺序的 Go 结构体做 JSON 序列化（Go 按字段声明顺序输出，结果是确定的）。
- 格式：`base64url(载荷) + "." + base64url(HMAC-SHA256(密钥, base64url(载荷)))`。
- 验证时用 `hmac.Equal` 做常数时间比较。按 `key_id` 选密钥，以后可以轮换。
- 测试：
  - 正常签发能通过验证；
  - 改动载荷里的任何一个字段都会失败；
  - 改签名会失败；
  - 未知的 `key_id` 会失败；
  - 载荷不是合法 JSON 会失败。

**W4-3 设备 API：`POST /api/v1/devices/enroll`（在 `nethub authz` 里）。** 处理顺序：

1. 按 Schema 校验请求；
2. 检查 `agent_protocol_version`，不兼容就拒绝；
3. 调 `consume_enroll_token(token 的哈希)`：一步完成检查有效期、检查是否用过、标记为已用，并返回所属租户和生成这个 token 的用户。
   **在同一个事务里**，接着执行 `set_config('app.tenant_id', <返回的租户>, true)`，后面的写入才能通过 RLS；
4. 生成 `device_id`（UUID）和 `subdomain`：8 位 `[a-z0-9]` 随机串，撞了唯一约束就重新生成，并跳过保留字（见常见坑）；
5. 生成 `device_secret`（32 字节随机数），数据库里只存 argon2id 哈希；
6. 签发 domain claim；
7. 以 `nethub_authz` 的身份写入 `devices`，`owner_user_id` 设为生成 token 的那个用户，同时写 `audit_log`；
8. 返回响应。

另外：这个接口按 IP 限流；token 错误、过期、已用，都返回同一种错误，不告诉调用方具体是哪一种。

**W4-4 frps 回调处理（`nethub authz`，只在内部网络监听）。**

- 收 frps 的 POST，按 `op` 分发。字段名以 W0 ② 实测的 JSON 为准。
- **`Login`**：从 `metas` 里取 `device_id` 和 `domain_claim`。检查四件事：
  - 签名有效；
  - 设备存在且没被撤销；
  - 声明里的 `device_id` 和 `metas` 里的一致；
  - 声明里的子域名和数据库记录一致。
- **`NewProxy`**：从 `user.metas` 里取同样的身份信息再验一遍。还要检查：
  - 请求里的 `subdomain` 等于声明和数据库里的子域名；
  - `proxy_type` 是 `https`；
  - `custom_domains` 为空。**这一条不能省**：frps 自己会接受泛域名根和外部域名作为 custom domain，
    放过的话，任何一台设备都能在 8443 上注册控制台的域名，拿到管理员浏览器发来的控制台 cookie（DESIGN §5）。
- 返回格式：
  - 放行：`{"reject": false, "unchange": true}`；
  - 拒绝：`{"reject": true, "reject_reason": "..."}`。
- **每次数据库查询都设很短的超时**（例如 300–500 毫秒），超时就明确拒绝。frps 本身不设超时（W0 ③），不能让请求一直挂着。
- 记录每次放行或拒绝的原因，**不记 token 和声明的内容**。
- `NewUserConn`、`Ping` 本阶段先不订阅。W5 按【D6】【D7】的结论再加。

W4-4 implementation note (2026-10-19): the internal callback handler and separate
runtime listener now exist, with exact socket-peer restrictions, bounded parsing,
500 ms database contexts, current signed assignment checks and HTTPS route policy.
Local Go tests/vet pass. Genuine PostgreSQL callback/revocation/lock-race tests and
compiled dual-listener checks are added but still need CI. Real frps traffic and
production network isolation remain W4 deployment acceptance; Ping/NewUserConn
remain W5. See [the callback boundary](../server/internal/relayhook/README.md).

**W4-5 只读轮询和在线状态。**
`nethub authz` polls the private frps admin API every five seconds to refresh
`devices.last_seen_at` for matching online proxies.
本阶段只读、只更新状态，不做任何断线动作（DESIGN §5：admin API 断不了在线连接）。

W4-5 implementation note (2026-10-19): the bounded admin poller and authz
runtime integration now exist. Storage refreshes only matching nonrevoked routes,
uses database time and tenant RLS, and skips busy rows. Local Go tests/vet pass;
new genuine storage/console cases and a compiled-process 15-second HTTP-fixture
probe still need CI. Real frps interoperability remains W4-6 deployment acceptance.
See [the observation boundary](../server/internal/relaystate/README.md).

W4-5 latency correction (2026-10-23): a retained native run completed enrollment
in 1.854 seconds but rendered online in 16.862 seconds. The former 15-second
display-poll period left no budget for enrollment and rendering. The display
period is now five seconds; its 45-second recent-observation window, separate
revocation discovery/confirmation policy and D6 heartbeat settings are unchanged.
The production-timer regression covers a proxy appearing just after an empty
snapshot. Fresh native acceptance must be repeated against the corrected image.
The visible inventory also refreshes every five seconds without overlapping
requests. Background reads revalidate sessions without extending idle activity;
hidden pages pause polling. Native acceptance must observe the row without reload.

**W4-6 frps 和 Caddy 的部署配置。**

- frps 的配置：仓库里只提交模板 `deploy/frps/frps.toml.tmpl`（只有占位值）。`nethub init` 把它渲染成 `deploy/secrets/frps/frps.toml`（在被忽略的目录里），只挂进 frps 容器。
  **填好真实 token 和管理密码的文件，绝对不能放在会被提交的路径下。**
  - 照搬 W0 修好的写法：顶层键放在最前面；`bindPort = 7000`、`vhostHTTPSPort = 8443`、`subDomainHost`、`auth.token`（从密钥文件读）；
  - `webServer` 只绑内部网络，并设管理账号；
  - `httpPlugins` 指向 `nethub-authz` 的内部地址，`ops = ["Login", "NewProxy"]`；
  - 想强制客户端必须用 TLS，先在 v0.71.0 源码 `pkg/config/v1/server.go` 里核实对应的字段名再加。
- 在 CI 里加一步：用样例值渲染这份模板，下载官方 frps（校验 sha256），运行 `frps verify`。
- `deploy/Caddyfile`：控制台域名下，`/api/v1/devices/*` 转给 `nethub-authz`，其余转给 `nethub-web`，证书自动申请。
- `docker-compose.yml` 加上 `nethub-authz` 和 `frps`。只有 7000 和 8443 对外，admin API 和回调端口都不对外。
- Certificate automation (Kazuha, 2026-10-18): implement automatic relay leaf renewal/application and authenticated public trust distribution, with durable retries and applied-generation verification. Console TLS is owned by the selected reverse proxy (bundled Caddy or external); do not add a competing application ACME manager. Add and test the external-proxy deployment path with explicit proxy trust and no publicly exposed origin listener. Include per-device router GUI certificate issuance, installation and renewal in v1 through platform-specific adapters. Follow [the certificate automation design](certificate-automation.md); CA signing keys remain outside application runtime containers.
- frps 放进 docker 之后，它看到的浏览器地址可能变成 docker 网关的地址，而不是真实的客户端 IP（和 docker 的端口转发方式有关）。
  W0 是直接在 VPS 上跑的 frps，测出的结论不一定适用。W5 的门禁要用这个地址，所以这里就要确认：要么让 frps 用宿主机网络（`network_mode: host`），
  要么在 compose 环境里按 RUNBOOK ⑤ 的方法重测一次 `remote_addr`。结果写进 PR。

**W4-7 插件的 enroll。**
The configuration writer and private temporary-file handoff were confirmed by Kazuha on 2026-10-18; see [the decision record](w4-decisions.md). Implement the following split:

1. **谁写 `config.xml`。** 推荐的做法：
   - `agentctl.py enroll` 只负责发 HTTPS 请求、严格校验响应，然后把结果输出成 JSON；
   - 由 PHP 的 `EnrollController` 拿到结果后，再校验一遍，通过 OPNsense 的模型保存设置（模型保存会走 OPNsense 自己的配置锁，满足决策 #16），最后触发 reconcile；
   - 这样就不用在 Python 里手写 `config.xml`。
2. **token 怎么从网页传到 agentctl。** configd 的参数可能出现在日志或进程列表里。
   推荐由 PHP 把 token 写进一个 0600 权限的临时文件，只把文件路径传给 agentctl；agentctl 读完就删。

其余要求：

- 控制台地址从哪里来，按【D19】的结论实现（页面上多一个输入框，或者从 token 里解析）。地址必须是 `https://` 开头；
- agentctl 用系统的 CA 证书校验控制台的 HTTPS，**绝对不能关掉证书校验**；
- 响应的每个字段都按白名单校验：`subdomain` 符合 `^[a-z0-9-]{1,63}$`，端口在 1–65535，地址是合法的主机名或 IP，所有字符串都有长度上限；
- 幂等：设置里已经有 `device_id`，就直接返回成功，不再请求服务端。

页面：在设置页加一个 Enroll 区域，包括 token 输入框、Enroll 按钮、结果提示。
**删掉或锁定 W2 加的"高级（仅调试）"区。**

**W4-8 unenroll 和 status。**
协议里的这两条消息也在本阶段做完（`proto/README.md`）：

- `agentctl.py unenroll`：停服务、清空凭证字段（同样由 PHP 写配置），通知 authz。authz 把设备标为撤销，释放子域名，写审计记录。
- `status`：agent 定时（以及页面上手动）把状态报给 authz，内容只有服务状态、版本、上次 reconcile 结果这类健康信息，**不包含设备配置**。
  authz 更新 `devices` 里对应的展示字段。

**W4-9 端到端测试。** 在干净的环境里，从头走一遍下面的流程，并录屏或者逐步截图：
控制台登录 → 添加设备、拿到 token → 路由器页面粘贴 token、点 Enroll → 设置自动填好 → 服务连上 → 控制台显示在线。

### 验收（对应 DESIGN §10 W4）

- [x] 上面的端到端流程走通，设备在 15 秒内显示在线（截图或录屏） — The earlier fresh run passed in 3.723 seconds. After the later 16.862-second failure, the corrected tested runtime rendered a new native device online in 2.511 seconds without reloading or manually refreshing the console. Token, model, key and credential binding plus five retained screenshots were independently verified. This retained-backend repeat closes the timing regression; its separate certificate failure remains archived. [Earlier evidence and lab limits](../deploy/validation-native-offline-recovery.md). The corrected 0.0.15 repeat displayed online in 7.788 seconds and passed private-CA offline renewal and reboot persistence. [Follow-up measurements](../deploy/validation-native-offline-renewal.md).
- [x] 同一个 token 用第二次会失败；过期 token 会失败（贴输出） — Immediate unexpired replay and a naturally expired unused token returned 401 without database mutation. The same expired request with a fresh token enrolled successfully. [Responses and independent controls](../deploy/validation-enrollment-boundaries.md).
- [x] 手工改坏声明里的一个字符，frpc 登录被拒（贴 frps 日志） — Actual official client/frps logs and Login/invalid_claim matched in PR #134/run 39917999149. [Observed output](../deploy/validation-enrollment-boundaries.md#operation-specific-relay-rejection).
- [x] 把一台设备的 `subdomain` 改成另一台设备的，`NewProxy` 被拒（贴日志） — A valid Login was followed by NewProxy/proxy_policy before either route existed; both legitimate routes subsequently passed verified TLS. [Observed output](../deploy/validation-enrollment-boundaries.md#operation-specific-relay-rejection).
- [x] 协议版本不兼容的 enroll 请求被拒，并返回能看懂的错误 — Protocol 99.0.0 returned 400/incompatible_protocol with the supported major; the same unused token then enrolled with 1.5.0. [Evidence](../deploy/validation-enrollment-boundaries.md).
- [x] 契约测试（Go 和 Python 两端）在 CI 里跑，绿；故意改坏一个示例时会变红 — PR #40/run 39207923123; both real suites failed on the deliberately broken valid fixture, then passed after restoration.
- [x] 日志里搜不到 token、`device_secret`、声明的内容（`docker compose logs | grep` 检查） — Retained API/native runs checked 20 known credential values in six service logs; hosted denial tests also scanned every enrollment request, nested auth tokens and original/tampered claims across client/authz/frps logs. [Scope](../deploy/validation-enrollment-boundaries.md).
- [x] web 容器里没有签名密钥、frps 的管理凭证、frps auth token（`docker compose exec nethub-web ls` 对应的密钥目录，贴输出）；`nethub doctor` 的分离检查通过 — The stopped distroless container's actual secret-directory archive contained only pg_nethub_web and secrets_key; read-only mount/image checks and the protected file doctor passed. [Scope and output](../deploy/validation-enrollment-boundaries.md).
- [x] unenroll 之后，设备在控制台里显示已撤销，它原来的子域名打不开 — Actual native UI removal returned complete cleanup; a fresh console login rendered Revoked and PostgreSQL confirmed it. The former subdomain reached the live public TCP listener but could no longer complete TLS. [Evidence and private CA/1 GiB scope](../deploy/validation-native-gui-lifecycle.md).
- [ ] Relay certificate renewal automatically issues and applies changed material, retries application without reissuing, verifies the served certificate and records recovery time.
- [ ] Public trust distribution records authenticated applied generations and exercises an offline-device/root-transition recovery path; issuer private keys remain outside application runtime containers.
- [ ] The external reverse-proxy path owns console TLS, exposes no unprotected origin listener, and rejects spoofed forwarding headers. Router GUI certificate issuance, installation and renewal are required in v1; test wrong-host/key rejection, rollback, offline recovery and reboot persistence.

Native GUI certificate progress (2026-10-23): genuine package cron installed and
confirmed two generations from one native key/CSR through the public NAT relay.
Natural renewal produced exactly two real orders/finalizations; both served
leaves passed independent chain/name/fingerprint checks. [Scoped measurements](../deploy/validation-native-gui-lifecycle.md).
The corrected 0.0.15 package also passed natural renewal while the guest was off,
cron-driven application after boot, native UUID/key/reference retention and
independent restoration. Boot DNS readiness to generation-2 confirmation took
77.521 seconds, with 95.703 seconds of validity remaining. [Offline measurements](../deploy/validation-native-offline-renewal.md).
A separate native restart failure restored the previous configuration and usable
GUI; genuine cron then confirmed the unchanged generation on attempt 2, with
one CA order and the original tunnel PID/key retained. [Rollback and retry](../deploy/validation-native-certificate-rollback.md).
Controlled native wrong-host/key inputs now pass both installed verification
boundaries, followed by genuine private-CA application and baseline restoration.
[Identity controls and limits](../deploy/validation-native-certificate-identity.md).
Public CA acceptance remains open; the combined certificate
checkbox is not complete.

### 常见坑

- **保留子域名。** 如果控制台域名也落在设备泛域名下面（例如 `console.router.example.com`），这个前缀必须保留，永远不能分给设备。
  `www`、`api`、`admin` 这类常见前缀也一起保留。
- **控制台的 HTTPS 证书无效时，agentctl 应该报错停下，而不是跳过校验。** 先把证书弄好。
- **改了 `proto/` 却没在同一个 PR 里改 agent 和版本号。** CONTRIBUTING 明确禁止。

---

## 12. 阶段 W5：远程打开 + 撤销

**目标：**

- 手机开 4G，从控制台点"打开"，能登录路由器的 GUI；
- 本地熔断开关一打开，隧道立刻停下，而且不碰 `config.xml`；
- 撤销设备后，它的隧道按【D6】选定的机制被断开，并且连不回来。

**前置条件：** W4 完成；【D6】断线机制、【D7】是否做门禁都已定。

**产出：** "打开"按钮；熔断开关；撤销和断线；轮询异常判定；（如果【D7】决定做）`NewUserConn` 门禁；开机和定时收敛。

**预计：** 6–10 天。

### 步骤

**W5-1 "打开"按钮。**
设备列表里每台设备加一个"打开"，新标签页打开 `https://<subdomain>.<域名>:8443`。旁边写明两点：

- 打开后还要用 OPNsense 自己的账号登录；
- Show the device certificate deployment state. v1 includes per-device public certificates; do not report certificate setup as complete until installation and a verified relayed connection succeed. Surface pending or failed issuance explicitly.

**W5-2 本地熔断开关。**
插件页面加一个"停止远程访问（本地熔断）"开关，通过 configd action 创建或删除 `/var/db/nethub-agent/disabled`，然后触发 reconcile。
**不写 `config.xml`**（决策 #10）。状态显示里要能看出熔断已生效。

**W5-3 撤销与断线（按【D6】实现）。**

- 控制台"撤销"：web 只写撤销标记（`revoked`、`revoked_at`、`revoked_by_user_id`），并写审计记录。
- `Login` 和 `NewProxy` 照旧**查数据库**，拒绝已撤销的设备。它们不频繁，查库是对的；用内存里可能过时的数据，会把刚撤销的设备放回来。
- 如果用到 `Ping`（见下），authz 另外在内存里维护一份已撤销设备的集合，**只给 `Ping` 用**。
  定时从数据库刷新（刷新间隔和 Kazuha 定，建议 5–10 秒），刷新失败时继续用上一份。
- 如果【D6】选的是"拒绝 Ping"：
  - frps 的 `ops` 加上 `Ping`；
  - 插件模板里写上 W0 实测后定下的心跳参数；
  - `Ping` 的处理**只查内存，不碰数据库**。
  - 还要把 DESIGN §5 列的三条缓解都做上：严格的内部超时；自检失败时进程主动退出，让容器重启；authz 停掉时会断掉全部隧道这一点，写进部署文档。
- "立即断"按钮：web 没有 frps 的管理凭证，所以它只写一条"立即断"的请求，由 authz 读到后执行。
  这条请求存在哪张表、web 对它有什么权限，DESIGN §6 没写，按【D11】先和 Kazuha 定下来。

**W5-4 轮询异常判定。**
在 W4 只读轮询的基础上，增加异常判定：

- 已撤销的设备还在线；
- 在线代理对不上任何设备；
- 代理的子域名和记录不一致。

**连续 3 次**（大约 45 秒）都异常才判定，写进审计记录并提醒管理员（决策 #4）；单次异常不处理。
异常数量超过阈值时，降级为只告警、不执行动作（决策 #4、#17），避免 CARP 切换之类的正常事件触发大面积误判。

**W5-5 （如果【D7】决定做）`NewUserConn` 门禁。**

- 用户在控制台点"打开"时，web 记下这个用户的客户端 IP（经可信代理解析，见 W3-5）。
  放行条件：这个 IP 在最近 30 分钟内，由一个已登录的用户对这台设备点过"打开"（DESIGN §14 Q7）。
  **不要做成"有访问就自动顺延"**：共用 CGNAT 出口的陌生人，也能借着这个 IP 一直保持放行。要不要顺延，由【D7】决定。
- 这个登记存在哪张表、web 有什么写权限，DESIGN §6 没写，同样按【D11】先定下来。
- authz 处理 `NewUserConn`：来源 IP 在放行列表里就放行，否则拒绝。
- 页面上写明限制：
  - 手机走 CGNAT 时，同一个出口 IP 可能还有别人在用；
  - 换了网络要重新点"打开"；
  - IPv4 和 IPv6 混用时，控制台看到的地址可能和访问设备时用的地址不是同一个（DESIGN §14 Q7 提到的双栈限制）。
- frps 在 docker 里时 `remote_addr` 是否还是真实 IP，W4-6 已经确认过；没确认的话先回去做。

**W5-6 开机和定时收敛。**
DESIGN §10 W5 要求开机收敛和定时收敛都要有：除了开机钩子，再加一个定时的 reconcile（防抖照旧；和 W2-7 的看门狗用同一种定时机制）。
确认这几种情况都能自动恢复：

- 重启路由器；
- 在 OPNsense 里恢复一份备份的 `config.xml`；
- WAN address changes: rely on frpc reconnect and periodic reconcile; enable the debounced hook only if W2 recovery testing requires it (D21).

**W5-7 enroll 页面加提醒。**
Enroll 前提示用户：请确认你有**不依赖 NetHub** 的其他访问方式（本地控制台、物理接入），以防远程访问出问题时进不去（DESIGN W5 验收项）。

### 验收（对应 DESIGN §10 W5）

- [ ] 手机关 Wi-Fi、用 4G，从控制台点"打开"，能登录路由器 GUI（录屏，地址打码）
- [ ] 打开熔断开关后隧道立刻停下，`config.xml` 前后 sha256 一致；关掉后恢复
- [ ] 撤销后，隧道按【D6】机制断开，断开时间在 W0 测出的范围内（贴时间记录）；设备之后一直连不回来
- [ ] 撤销后，浏览器新开的连接也被拒绝
- [ ] 如果 W0 发现没有哪种断线机制可用：已经按 DESIGN §5 的另一种取舍（只挡新访问，接受"已建立的隧道断不掉"），并且把这一点写进了文档
- [ ] 如果用了 `Ping` 机制：停掉 authz，确认在线隧道全部断开，再启动 authz，确认它们自动恢复（贴时间记录）
- [ ] （如果做了门禁）没点"打开"的 IP 访问不了；点了之后可以
- [ ] 重启路由器、恢复 `config.xml`、WAN 换 IP 三种情况都自动恢复
- [ ] enroll 页面有带外访问的提醒

### 常见坑

- **只测了"能断开"，没测"断开后连不回来"。** 两样都要测。
- **在 `Ping` 处理里查数据库。** 每台设备每个心跳都会来一次，查库既慢又会把数据库的故障放大成全部断线。
- **把单次异常当成要断线。** 必须连续 3 次。

---

## 13. 阶段 W6：多用户 + OIDC

**目标：** 控制台支持多个用户（`admin` / `member`），通过邀请加入，可以用本地密码或 OIDC 登录，并且支持配置多个身份提供方。

**前置条件：** W3 完成（可以和 W5 交错做）；读完 DESIGN §6 的用户、邀请、OIDC 部分，决策 #22，§13 场景 #13。

**产出：** 角色权限；邀请；OIDC 提供方管理；OIDC 登录和账号绑定；认证事件审计；集成测试。

**预计：** 8–12 天。

### 步骤

**W6-1 角色权限。**

- 写一个统一的权限检查，例如"必须是 admin"。
- `member` 只能看到和操作自己的设备：查询时按 `owner_user_id` 过滤，并为此写测试。
- 管理员能停用用户。停用后，这个用户的所有会话立即失效。

**W6-2 邀请。**

- 管理员输入邮箱和角色，生成邀请链接：一次性 token，数据库只存哈希。有效期本计划暂按 72 小时，最终以【D11】为准。
- v1 不发邮件。链接显示在页面上，由管理员自己复制、发给对方。
- 管理员能看到待处理的邀请，也能作废邀请。
- 被邀请的人打开链接后，二选一：
  - 设置本地密码；
  - 点"用 SSO 认领"，从这里进入 OIDC 流程。

**W6-3 OIDC 提供方管理（只有 admin 能用）。**

- 字段：`slug`、显示名称、Issuer URL、Client ID、Client Secret、scopes（默认 `openid email profile`）、是否启用。
- Client Secret 用 AES-256-GCM 加密后存库：密钥是 `NETHUB_SECRETS_KEY`，每次加密用新的随机 nonce。**任何 API 都不返回它的明文。**
- 页面上显示需要在身份提供方那边填的回调地址，例如 `https://<控制台域名>/api/v1/console/oidc/<slug>/callback`。

**W6-4 OIDC 登录流程。** 用 `github.com/coreos/go-oidc/v3` 和 `golang.org/x/oauth2`。

1. **发起**：
   - 通过 Issuer 的 discovery 拿到端点（可以缓存）；
   - 生成 `state`、`nonce`、PKCE verifier（用 `oauth2.GenerateVerifier()`），存在服务端，有效期很短，并用一个 cookie 绑定到当前浏览器；
   - 带着 S256 challenge 跳转到身份提供方。
2. **回调**：
   - 核对 `state`；
   - 用 verifier 换 token；
   - 用 go-oidc 校验 ID token（签发方、受众是本应用的 Client ID、有效期）；
   - 核对 `nonce`。
3. **绑定**：
   - 用 `(iss, sub)` 查 `user_identities`。找到了，并且用户没被停用 → 登录成功。
   - 找不到时，只有这次流程**是从邀请链接发起的**，才继续认领邀请。必须同时满足：
     - 邀请有效、没用过、没过期；
     - ID token 里 `email_verified` 为 true；
     - token 里的邮箱和邀请的邮箱一致（不区分大小写）；
     - 如果邀请限定了身份提供方，还要是那一家（这个功能是 DESIGN 里的可选项，做不做按【D11】）。

     全部满足，才创建用户和绑定关系，并把邀请标为已用。
   - 其他情况一律拒绝，提示信息不要透露具体原因。
4. **不按邮箱自动绑定已有账号**，也不允许自助注册（DESIGN §6、决策 #22）。

**W6-4a SAML login through authcore.** Directly import the shared module's saml
package. Follow the integration and negative-test requirements in w3-decisions.md:
SP-initiated browser-bound state, trusted metadata, durable replay protection,
provider/issuer and stable NameID identity, invitation-only new binding, and no
email-only matching. Include metadata/configuration UI and signed IdP integration
tests; existing local-password emergency-admin access remains available.

**W6-5 审计。**
登录成功和失败、邀请的创建和使用、提供方配置的变更、用户被停用、会话被吊销，都写进 `audit_log`。
记录客户端 IP（经可信代理解析）。

**W6-6 测试。**

- 用 Dex（`ghcr.io/dexidp/dex`）在 docker compose 里起**两个**身份提供方，用静态用户。
  Dex 的静态用户很可能总是返回 `email_verified=true`（先查 Dex 文档确认）。所以 `email_verified=false` 的情况，
  要么用 Keycloak 这类能自己设置这个字段的提供方，要么在 Go 测试里写一个假的 OIDC 提供方来覆盖。
- 集成测试覆盖：
  - 已绑定的用户能登录；
  - 从邀请链接用 SSO 认领能成功；
  - **不经邀请链接、只凭邮箱匹配不能登录**；
  - **用另一家身份提供方、不经邀请链接，认领不了别人的邀请**；
  - `email_verified` 为 false 时不能认领；
  - 篡改 `state`、重放回调都会失败。
- 用一家公网身份提供方（例如 Google）实测一次，需要 Kazuha 提供或注册应用【停】。

### 验收（对应 DESIGN §10 W6）

- [ ] 能用两家不同的身份提供方各登录一次（截图）
- [ ] 通过邀请链接认领成功；只凭邮箱绑定被拒；用别家身份提供方、不经链接认领被拒（测试输出）
- [ ] `member` 看不到别人的设备（测试输出）
- [ ] Client Secret 在数据库里是密文，任何接口都拿不到明文
- [ ] 认证相关事件都写进了审计记录

### 常见坑

- **按邮箱找人。** 这正是 DESIGN 场景 #13 说的账号接管漏洞。身份只认 `(iss, sub)`。
- **忘了核对 `nonce` 或 `state`。**
- **把 Client Secret 打进日志，或者在"编辑提供方"接口里原样返回给前端。**

---

## 14. 阶段 W7：加固与首次公开

**目标：** 补齐 v1 剩下的加固项和文档，完成三项关键验收，然后公开仓库。三项验收是：

- 朋友从零部署；
- Use the owner-approved non-production test router for the complete workflow;
- 推一个有 bug 的版本，验证会被拦下。

**前置条件：** W5、W6 完成；【D12】【D13】【D14】已定。

**预计：** 8–12 天。

### 步骤

**W7-1 审计哈希链。**
`audit_log` 的每条记录带上前一条的哈希。web 和 authz 两个进程都会写，所以计算 `prev_hash` 时要串行，例如用数据库的咨询锁，避免两条记录指向同一个前驱。
`nethub doctor` 加一个链完整性检查。

DESIGN §6 写明了：这条哈希链只防意外损坏，**不能当成防篡改的证据**，文档里照实写。

**W7-2 流量软计数。**
定时从 frps 的 admin API 读每个代理的流量，按设备记录，再**按租户、按月**汇总后在控制台显示（DESIGN §5、§6 定义的是"每租户每月"的软计数）。超过阈值只提示，**不拦截**。

**W7-3 `nethub doctor` 补全。**
DESIGN §7 列的所有检查项都要实现，并分成两组：

- 启动前就能跑的：DNS、端口、密钥备份；
- 栈跑起来之后才能跑的：证书、frps 和 authz 之间的回环、最近一次 `pg_dump`。

每一项失败时，都要给出一句人能看懂的修复建议。

**W7-4 rotate（凭证原地轮换，决策 #18）。**

- authz 提供 rotate 接口；`agentctl.py rotate` 拉一套新凭证，原地更新后执行一次 reconcile；页面上加按钮。
- 把"frps auth token 泄露后怎么轮换"写成运维步骤。
- 离线的设备需要手动重新 enroll，这一点也写清楚。

**W7-5 备份和恢复演练。**

- `backup` 服务每天用 `nethub_backup` 角色跑 `pg_dump`，并按保留策略清理旧备份。
- **在一台全新的 VPS 上做一次完整的恢复演练**：用 `nethub init` 时备份的密钥 + 最近一次数据库备份，恢复出一个能用的控制面，已经 enroll 的设备能自动重新连上。
- 演练的每一步写进文档。

**W7-6 文档。**

- 新写 `docs/deployment.md`：部署、升级、备份恢复、故障排查。`nethub-authz` 是单点这件事要写清楚。
- 完善 `docs/threat-model.md`：初稿已有（2026-10-16），按 W0 结果和实际实现逐条更新，把标着 unverified / open 的地方改成实测结论。
- 新写 `docs/protocol.md`；核对 `docs/console-api.md` 和实际接口一致；`docs/README.zh-CN.md` 跟着英文 README 的改动同步。
- 更新 `README.md` 和 `docs/README.md` 的索引；凡是"还没实现"的说法，按实际情况改掉。
- 每份文档都要通读一遍，确认没有把没做的东西写成已经做了。

**W7-7【停】公开前的内容审查【D12】。**
按 Kazuha 的决定，删改 DESIGN.md 里的敏感内容，决定 `docs/PLAN.md` 留不留。改完由 Kazuha 本人确认，再公开仓库。

**W7-8 正式包和灰度发布【D13】。**

- 你负责：给出一个打了 tag 的 release 压缩包、它的 sha256，以及测试报告。
- Kazuha 负责：在打包仓库里加 `os-nethub-agent` 的打包配方，构建、签名、发布，并用现有的灰度机制先推给一小部分设备（决策 #15）。

**W7-9 三项关键验收。**

1. On the **owner-approved non-production test router**, install the plugin from the package repository and complete installation, enrollment, and remote GUI access over a mobile network.
2. 请 Kazuha 找一位朋友，在**他自己的服务器上**，只看文档从零部署控制面，并 enroll 他自己的设备。
   他问的每一个问题、卡住的每一个地方，都记下来，当成文档 bug 修掉。
3. 故意做一个带 bug 的插件版本（例如模板会渲染出坏配置），推给灰度设备。
   确认三件事：reconcile 拒绝应用；看门狗没有误报；灰度流程工作正常。

### 验收（对应 DESIGN §10 W7）

- [ ] 上面三项关键验收都完成，各有记录
- [ ] 恢复演练成功，步骤写进了 `docs/deployment.md`
- [ ] `docs/deployment.md`、`docs/threat-model.md`、`docs/protocol.md` 已合并
- [ ] 公开前的内容审查由 Kazuha 确认通过
- [ ] CI 全绿，`govulncheck` 没有报告漏洞，没有积压未处理的 Dependabot PR

---

## 15. 缓冲与 v1 之后

**缓冲（5–10 天）** 用来处理前面各阶段的延误、W0 结论带来的返工、首次公开后收到的第一批问题。
缓冲用完了还没做完，就和 Kazuha 一起砍范围或者重新排期，**不要悄悄加班硬撑**。

**v1 之后**（DESIGN §11，现在不做，先知道就行）：

- v1 includes per-device public certificates through DNS-01, automatic installation and renewal. v1.1 retains arm64 packaging and mTLS evaluation; certificate acceptance expands the original v1 estimate.
- v1.2：遥测；
- v2：加密的配置备份；
- v2.5：配置下发；
- v3：多租户。

---

## 16. 执行风险清单

| 风险 | 早期信号 | 怎么办 |
|---|---|---|
| W0 结果不理想（① 打不开、② 拿不到身份字段、③ 是 fail-open） | W0 记录里出现"不通过" | 立刻【停】，和 Kazuha 重新看设计。不要带着问题往下做 |
| 测试资源迟迟不到位 | 第 5.2 节的东西一周内没备齐 | 先做不依赖资源的事（读文档、写测试框架、W3-0 的 UI 示例），并告诉 Kazuha 进度被卡住了 |
| 不熟悉 OPNsense 插件开发 | W1 头两天看不懂参考插件 | 先只看 `os-easytier` 一个插件，每个文件弄懂再看下一个；半天还没进展就问 |
| 范围悄悄变大 | 发现自己在做计划里没写的东西 | 停下来，问 Kazuha 要不要做 |
| 不小心提交了密钥或真实地址 | 自查脚本（附录 F）报警，或者推上去之后才发现 | **不要自己去改写 git 历史。** 立刻告诉 Kazuha，并把泄露的密钥换掉 |
| 弄坏了测试机的系统或 `config.xml` | 测试机启动不了，或者 GUI 打不开 | 有快照就恢复快照；没有就马上找 Kazuha。正因为这样才只用测试机 |
| 依赖库出现漏洞 | `govulncheck` 报警、Dependabot 发安全更新 | 当天处理，处理不了就告诉 Kazuha |
| 上游 frp 发了新版本 | GitHub 上有新 release | **不要自己升级**，按【D4】的方式请 Kazuha 决定 |
| 估算明显不准 | 某个阶段用掉了预估上限的 1.5 倍 | 阶段中途就和 Kazuha 重新估，不要等到最后 |

---

## 17. 附录：模板与命令速查

### A. 命令速查

**Git / GitHub**

```bash
git status                          # 每次提交前都看
git diff                            # 看改了什么
git switch -c feat/xxx              # 新建分支
git commit -s -m "feat(scope): ..." # 一定带 -s
git push -u origin feat/xxx
gh pr create --fill
gh pr checks                        # 看 CI 状态
```

**Go（在 `server/` 目录下）**

```bash
export GOWORK=off                   # 如果 go env GOWORK 有输出
go build ./...
go vet ./...
gofmt -l .                          # 有输出就说明有文件没格式化，用 gofmt -w . 修
go test ./... -race -count=1
go run golang.org/x/vuln/cmd/govulncheck@<版本号> ./...   # 用和 CI 一样的固定版本，不要用 @latest
```

**前端（在 `server/web/` 目录下）**

```bash
npm ci
npx tsc --noEmit
npm run build
```

**Docker Compose**

```bash
docker compose up -d
docker compose ps
docker compose logs -f nethub-authz
docker compose exec nethub-web sh
docker compose down                 # 加 -v 会删数据卷，慎用
```

**Postgres**

```bash
psql "postgres://nethub_web@127.0.0.1:5432/nethub"   # 密码从本地密钥文件读，不要写进命令历史
\dp devices                          # 看这张表的权限
\d devices                           # 看表结构
```

**OPNsense 测试机**

```bash
opnsense-version
pkg info | grep nethub
configctl nethub-agent status
service nethub_agent_frpc status
sockstat -4 -l                       # 看哪些端口在监听
tail -f /var/log/nethub-agent/frpc.log
grep -A 5 "<NetHubAgent" /conf/config.xml
ls -l /var/db/nethub-agent/
```

**frp**

```bash
./frps verify -c frps.toml
./frpc verify -c frpc.toml
```

### B. PR 描述模板

```markdown
## 做了什么
（一两句话）

## 为什么
（对应计划里的哪个任务，例如 W2-4；对应 DESIGN 的哪一节或哪条决策）

## 怎么验证的
- 本地：（运行了哪些命令，结果如何）
- 测试机：（做了哪些操作，贴日志或截图，地址已打码）
- CI：（链接）

## 验收项
- [ ] （从计划里复制本任务相关的验收项）

## 没做的 / 不确定的
（照实写；没有就写"无"）

## 如果改了 proto/
- 版本号：
- 兼容性影响：旧 agent 能不能连新服务端？新 agent 能不能连旧服务端？
```

### C. 日报和阶段总结模板

日报：

```
日期：
今天做了：
卡在哪里：（没有就写"无"）
明天打算：
```

阶段总结：

```
阶段：（例如 W2）
完成情况：验收清单 x/y 项完成（附清单链接）
用时：预计 __ 天，实际 __ 天
遇到的主要问题：
需要 Kazuha 决定的事：
对后面阶段的影响和重新估算：
```

### D. 提问模板

```
我想做的事：（对应计划里的哪个任务）
我做了什么：（按顺序列出步骤和命令）
我期望看到：
实际看到：（贴完整的输出或报错，真实地址已打码）
我已经试过：
我的猜测：
```

### E. 决策记录模板

每个【D编号】有结论时，记一条（可以记在 issue 里，也可以是一个单独的文件，问 Kazuha 放哪）：

```
编号：D_
问题：
选项：
结论：
决定人：Kazuha
日期：
影响到的计划任务和 DESIGN 章节：
```

### F. 推送前自查

每次 `git push` 之前，在仓库根目录跑一遍。检查的是"这个分支相对 `main` 的全部改动"，所以提交之后再跑也有效：

```bash
git fetch origin
RANGE="origin/main...HEAD"

# 1. 像 IPv4 地址的（文档专用的 203.0.113.x、127.0.0.1、0.0.0.0 之外的都要逐条看）
git diff "$RANGE" | grep -nE "^\+.*([0-9]{1,3}\.){3}[0-9]{1,3}"

# 2. 像 IPv6 地址的（W0 第 ⑤ 项可能记下 IPv6 的 remote_addr）
git diff "$RANGE" | grep -niE "^\+.*([0-9a-f]{1,4}:){3,}[0-9a-f]{1,4}"

# 3. 真实域名（把 <你们的真实域名> 换成实际的域名再跑）
git diff "$RANGE" | grep -ni "<你们的真实域名>"

# 4. 私钥块，或者像 token 的长字符串
git diff "$RANGE" | grep -nE "BEGIN [A-Z ]*PRIVATE KEY|token[[:space:]]*=[[:space:]]*\"[^\"]{16,}"

# 5. 提交信息、作者、提交者里有没有 AI 工具署名（应该没有输出）
git log --format='%an <%ae>%n%cn <%ce>%n%B' origin/main..HEAD | grep -niE 'co-authored-by|generated with'
```

有命中的，逐条确认是不是占位值。拿不准就问。

### G. 已确认的决策记录

- 编号：D1
  - 问题：NetHub 是否作为组织许可证分层规则的例外。
  - 选项：保持 Apache-2.0；按组织分层规则调整许可证。
  - 结论：保持 Apache-2.0，作为例外，继续 P0。
  - 决定人：Kazuha
  - 日期：2026-10-17
  - 影响：P0-2；DESIGN §2、§14 Q0 子项。
- 编号：D2
  - 问题：仓库可见性与公开时间。
  - 选项：现在公开；先保持私有，到 W7 再决定公开。
  - 结论：先保持私有，到 W7 再决定公开；本次没有授权变更可见性。
  - 决定人：Kazuha
  - 日期：2026-10-17
  - 影响：P0-2、W7 公开前审查。内部文档已经进入历史，D12 仍需另行决定。

D3 update (2026-10-17): Kazuha delegated isolated VM provisioning and authorized the operations in this chat. The local 4 GiB execution host is too small for the guest; PR #2 has verified a signed, restricted live-image boot on a standard hosted runner: [evidence](https://github.com/KazuhaHub/nethub/actions/runs/39026961946). The guest reached its login prompt in 56 seconds and was terminated; it has not been installed or updated for W0. Public relay, DNS, and carrier-network availability remain unconfirmed. This is preflight work, not W0 acceptance.

- Decision: D9
  - Question: Which React component library should the console use?
  - Options: Ant Design, Mantine, or shadcn/ui with the tested native dialog adaptation.
  - Resolution: shadcn/ui with native dialog, explicitly confirmed in this chat.
  - Owner: Kazuha
  - Date: 2026-10-17
  - Impact: W3-0 selection complete; W3 console implementation uses this choice. W0 remains a prerequisite for product implementation.

D3 update (2026-10-17): Kazuha provided access details for a dedicated OPNsense test machine and confirmed it is suitable for testing, with no production workload or signing private keys. A dedicated SSH public key has been supplied for installation. Connection and system readiness have not yet been verified. Access details and private key material stay outside this repository. Public relay, DNS, and two carrier networks remain unconfirmed.

D3 verification (2026-10-17): Dedicated SSH access succeeded. Read-only checks confirmed an installed UFS root at `/dev/gpt/rootfs`, OPNsense 26.7.7, FreeBSD 15.1-RELEASE-p4 amd64, Python 3.13.15, os-frp 1.0.1, and frpc 0.71.0. There were no running frpc processes. The unchanged W0 client TOML passed `frpc verify` on the device; its temporary copy was removed. No service, firmware, or system configuration was changed. This verifies device preparation only; public relay, DNS, and the six W0 experiments are still outstanding.


Decision #20 / D3 revision (2026-10-17): Kazuha explicitly permits package building, signing, and NetHub use on the designated packaging test machine. This supersedes the earlier requirement to move signing keys and build/signing scratch off that machine or relocate signing to another host. Device key presence was not inspected and is no longer a readiness gate for this approved host. Production-router restrictions and the remaining stage/release decisions still apply. Relay SSH access and wildcard DNS checks have now passed on the Debian 12 x86_64 LXC. Kazuha authorized temporarily stopping the existing Xray and OpenResty listeners during the W0 window and restoring them afterward.

D3 initial topology clarification and preparation (2026-10-17; superseded by guest preparation below): Kazuha selected the local Windows machine for the OPNsense NAT client and the remote LXC for the NetHub server/relay. Hyper-V installation and reboot completed; approximately 8 GiB host RAM is visible. The local Generation 1 guest and its internal networks/NAT exist. Startup attempts at 3, 2, and 1.5 GiB failed with insufficient host memory; the guest is now configured at 2 GiB. Closing auxiliary windows did not free enough memory according to the Hyper-V memory-balancer counter. No guest configuration or update is complete. The verified 26.7 Nano disk must be updated before acceptance. A preceding temporary relay preflight reached the earlier public device's login form and matched its TLS leaf certificate; it did not test authenticated GUI use or prove NAT traversal. Test processes and the exploratory LXC guest are stopped; original relay listeners are restored. None of the six W0 experiments is accepted by this preparation.

D3 initial runtime fallback observation (2026-10-17; superseded by guest preparation below): following Kazuha's request for another framework, the local QEMU TCG guest is running with 2 GiB pageable memory and the verified VHDX as a read-only backing image. Initial boot has not completed verification; a template-generation failure must be diagnosed. Local management forwards bind only to loopback. The remote LXC remains the server/relay, and W0 remains unaccepted.

D3 guest preparation (2026-10-17): the local QEMU guest reached its console, received LAN configuration and a replacement root password, and passed dedicated SSH, local GUI HTTP form login, and outbound package-mirror TLS verification. Its initial template warning did not recur during successful full template regeneration. A disk-only snapshot preceded the stock minor firmware update. After reboot, OPNsense 26.7.7 and matching running/installed FreeBSD 15.1-RELEASE-p4 kernel and userland passed checks; SSH and mirror TLS verification passed again. Snapshot restore remains untested. These are device-preparation checks, not acceptance of the six W0 experiments.

D3 external-network availability (2026-10-17): Kazuha confirmed access to two different mobile carriers and a company or campus network. This confirms resource availability only; no external samples or mobile GUI acceptance have been collected.

D3 local NAT transport preparation (2026-10-17): the pinned FreeBSD client and private server/client configurations passed verification. A bounded relay window reached the local NAT guest login form with the same TLS leaf certificate as local access. The owned client and relay test processes were stopped; original listeners were rechecked and the restoration timer was cancelled. No authenticated mobile flow or numbered W0 experiment is accepted.

D3 native Hyper-V diagnostic (2026-10-17): the restored updated disk copy passed content comparison and boot verification. Complete local and public desktop GUI checks passed at 1 GiB, with actual widget data, periodic refresh, navigation, unchanged security checks, and matching backend TLS. Relay restoration was independently verified. Kazuha explicitly approved continuing W0 at 1 GiB with the resource deviation recorded. Subsequent mobile ①, hook experiments ②/③, and scoped network experiment ④ now pass; ⑤ now passes; ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18.


W0 progress (2026-10-17): experiment ① passed after the owner reported normal mobile login, Dashboard data, periodic refresh, menu navigation, and reload. Carrier, phone OS, and browser were left unrecorded at the owner's explicit request. The exact Alternate Hostnames entry was required; DNS rebinding and HTTP_REFERER checks remain enabled. Experiment ② passed using the fresh all-allow connection: Login metadata matches the configured top-level values, NewProxy `user.metas` matches Login, the requested subdomain matches, and the server-assigned NewProxy `user.run_id` is nonempty. The Login JSON omitted initial `client_id` and `run_id`. The control peer matched an independent connection through the same host NAT. See the [observed hook inputs](../proto/frp-hooks-0.71.0.md).

Experiment ③ passed six isolated fault groups: Login and NewProxy each with deny, HTTP 500, and a 120-second sleeping hook. Deny/500 prevented registration. The NewProxy sleeping request remained pending at 115 seconds while the frps admin API responded; heartbeat timeout was observed by the 35-second sample. Future requests were switched to allow at 110 seconds for recovery, without interrupting the existing sleep. At 125 seconds its delayed response had completed but the route was still unavailable; by 140 seconds registration and access had recovered. Login hang caused the client to exit and did not create a proxy after the delayed response. Restoring all allow recovered registration, access, and approximately ten-second heartbeats. Original relay services and listeners were independently verified after cleanup. These bounded observations found no fail-open and do not prove an infinite timeout.

Availability risk retained for review: a slow ownership hook blocks new registration; heartbeat timeout and control handoff can delay recovery even when frps itself remains responsive. Product hooks need bounded internal work and explicit failure handling. Decisions about NewUserConn/Ping gating and revocation latency still require ⑥ and the W0 review. Experiment ④ passes within the owner-approved two-mobile-network scope: A and B each returned TCP, TLS, and HTTP success in all 20 rounds on both ports, without triggering Q2. Company/campus sampling was explicitly waived by Kazuha and remains untested. See [the network report](../weekend0/network-results.md). Experiment ⑤ now passes; ⑥ measurements are complete; W0 was accepted by Kazuha on 2026-10-18. All results use the owner-approved 1 GiB exception, with no guest swapping in the recorded samples. Raw payloads, credentials, and deployment details stay outside the repository. W0 was accepted with the recorded limits on 2026-10-18; no product code has started.


W0 review readiness (2026-10-17): all six experiments now have measurements.
Three repeated combined Ping/Login/NewProxy denial trials disconnected the stock
client after 2.136, 3.032, and 4.958 seconds. Disabling client heartbeats produced
server timeouts about 30 seconds after registration. Backend process loss and
HTTP 500 interrupted registered tunnels and blocked re-registration. The
120-second backend hang exposed stale admin online status after heartbeat timeout
and intermittent recovery; it must not be described as a clean 30-second revoke.
Private evidence, failed/interrupted attempts, and a review draft are preserved
outside Git. Kazuha accepted W0 and D5/D6/D7/D17 on 2026-10-18; no product work
has started. Original relay services/listeners were independently verified
restored, owned test processes and tracked temporary stages removed after private
archival, and the Mac download publication removed. The updated local diagnostic
VM is retained; no Hyper-V checkpoint exists to restore. The W0 review is complete. Product implementation
must pass the separate W1 gates.


W0 acceptance (2026-10-18): Kazuha accepted the six measured experiments and
recorded limits, confirmed D5/D6/D7/D17, and authorized the DESIGN update and
progression through the W1 gates. See [accepted results](../weekend0/results-2026-10-17.md).
No product code exists yet; D10/D20 and package metadata remain W1 decisions.


W1 decisions (2026-10-18): Kazuha confirmed D10/D20, independent source and
standalone unsigned development packaging, without kazuha.sh mirror. Release
recipe integration remains deferred. Public product_email is admin@kazuha.org
(the owner input used a full-width dot, normalized to an ASCII dot); product_website
is https://github.com/KazuhaHub/nethub. A clean powered-off Hyper-V checkpoint
was created before installing the development plugin. Implementation is in progress.


W1 validation (2026-10-18): the unsigned development skeleton passed native build,
installation, enabled save, uninstall with retained settings, and reinstall on
OPNsense 26.7.7. Firmware registration cleanup was fixed and retested. See
[the evidence](../agents/opnsense/plugin/tests/native-validation.md). The plugin
remains installed for W2 and starts no tunnel. D4/D21/D22 and the pinned-download
choice were confirmed on 2026-10-18; the three-way 0.71.1 upgrade is now a W2 prerequisite. Test access was simplified
at the owner's request; credentials remain outside Git.
