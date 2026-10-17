# Weekend 0 验证结果记录

> 配合 `RUNBOOK.md` 使用；每项验收对应 RUNBOOK 里的同名小节，判定标准和
> "不通过意味着什么"都写在 RUNBOOK 里，这里只填实测数据和结论。

## 基本信息

| 项目 | 值 |
|---|---|
| 测试日期 | |
| frp 版本 | 0.71.0（应该保持不变，除非你故意测别的版本；跟 os-frp 锁的版本一致） |
| VPS 提供商 / 地区 | |
| VPS 公网 IP（测完记得脱敏或直接删掉这一行再分享出去） | |
| VPS 前面有没有云厂商的负载均衡 / 会改写源地址的东西（影响⑤的 `remote_addr`） | ☐ 没有　☐ 有（写明）： |
| 测试域名（如 `router.example.com`） | |
| OPNsense 版本（应为 26.7.1_1 或更新） | |
| OPNsense 测试机是虚拟机还是物理机 | |
| 测试机上**没有**仓库签名私钥（DESIGN 决策 #20；签名已改到 Irvine Home，Kazuha 已确认移走） | ☐ 已确认 |
| 测试机 GUI 的 WAN 放行规则在①期间只允许测试人员自己的 IP | ☐ 已确认　☐ 不适用（测试机在 NAT 后面） |
| 测试机**不是**生产路由器 | ☐ 已确认 |
| 测试机上是否同时装着 os-frp | ☐ 是　☐ 否 |
| 测试机是否真的在 CGNAT / 动态 IP 后面（还是只是同一局域网直连） | |
| VPS 和 OPNsense 测试机的时钟是否都开着 NTP（影响⑥跨机器的时延计算；不确定就只用 VPS 上的时间） | ☐ 都开着　☐ 不确定 |
| sha256 校验：`frp_0.71.0_linux_amd64.tar.gz` | ☐ 通过　☐ 不通过 |
| sha256 校验：`frp_0.71.0_freebsd_amd64.tar.gz` | ☐ 通过　☐ 不通过 |

## 配置检查（RUNBOOK 第 1.5 步、第 2.4 步，启动前做）

| 检查 | 结果 |
|---|---|
| `frps.toml` 的 `webServer.user` / `password` 已从 `CHANGE_ME` 改掉 | ☐ 已改 |
| `./frps verify -c frps.toml`（VPS） | ☐ `syntax is ok`　☐ 报错（贴在下面） |
| `./frpc verify -c frpc.toml`（VPS 上用 linux 包里的 frpc） | ☐ `syntax is ok`　☐ 报错（贴在下面） |
| `./frpc verify -c frpc.toml`（OPNsense 测试机上，改完占位值之后） | ☐ `syntax is ok`　☐ 报错（贴在下面） |
| `tomllib` 打印的 `frpc.toml` 顶层字段里有 `metadatas`、`log`、`transport`，`proxies[0]` 里没有 `log` / `auth` / `metadatas` | ☐ 符合　☐ 不符合 / 没有 tomllib，已人眼检查 |
| `frpc.toml` 的 `transport` 是 `{'tls': {'enable': True}, 'heartbeatInterval': 10, 'heartbeatTimeout': 30}`（心跳两行在顶层，没被删） | ☐ 符合　☐ 不符合 / 没有 tomllib，已人眼检查 |
| `tomllib` 打印的 `frps.toml` 顶层字段里有 `log` 和 `transport`，`httpPlugins[0].ops` 是 `['Login', 'NewProxy', 'NewUserConn', 'Ping']` | ☐ 符合　☐ 不符合 / 没有 tomllib，已人眼检查 |
| `frps.toml` 的 `transport` 是 `{'heartbeatTimeout': 30}` | ☐ 符合　☐ 不符合 / 没有 tomllib，已人眼检查 |
| 探针用 `PROBE_MODES_FILE=/tmp/w0-modes.json` 启动，模式文件是 `{}`，启动时打印的四个 op（Login / NewProxy / NewUserConn / Ping）都是 `allow` | ☐ 符合　☐ 不符合 |
| 是否加了 `auth.token`（加了的话两边一致、都在顶层） | ☐ 加了　☐ 没加 |

**报错/告警原文**（`WARNING: ...` 也贴上）：

```

```

**frpc 启动日志里代理注册成功那一行**（应为 `[opnsense-webui] start proxy success`）：

```

```

**frpc 连上之后，探针是否约每 10 秒收到一条 `op=Ping`**（`距本 op 上一次 ... 秒` 的典型值）：☐ 是，约 ___ 秒一条　☐ 收不到（先查 1.5 步的 `transport` 和 `ops`）

**os-frp 共存（测试机装了 os-frp 才填）**：手工 frpc 运行期间，os-frp 自己的 frpc
服务是否正常、有没有端口或进程冲突：

---

## 验收项 ①：外部网络能打开、能登录 OPNsense 登录页

| 字段 | 记录 |
|---|---|
| 测试用的外部网络（运营商/地区） | |
| 访问的完整 URL | |
| 探针模式（应为全 `allow`） | ☐ 全 allow |
| 页面是否加载出登录界面 | ☐ 是　☐ 否 |
| 是否出现证书警告（预期会出现，不算失败） | ☐ 是　☐ 否 |
| 是否被 OPNsense 的 DNS 重绑定 / HTTP_REFERER 检查拦下（DESIGN Q9） | ☐ 没被拦　☐ 被拦，加了 Alternate Hostnames 后正常　☐ 被拦，加了也不行（写明） |
| 账号密码是否登录成功 | ☐ 是　☐ 否 |
| Dashboard 页面 / AJAX 请求是否正常，有没有资源 404 | ☐ 正常　☐ 有异常（记录在下面） |
| 从打开页面到登录成功，主观感受的加载速度 | ☐ 很快　☐ 能接受　☐ 明显卡 |

**异常/截图/日志摘录**：

（把 frps 日志里对应这次连接的片段，或者浏览器开发者工具里失败的请求，贴在这里）

**结论**：☐ 通过　☐ 不通过

---

## 验收项 ②：Login / NewProxy 真实字段名，能否做归属校验

**Login 请求实际收到的字段**（从 `probe.log` 里摘录，或者直接把这次请求的
JSON 原样粘贴在下面的代码块里）：

```json

```

- `content.metas` 是否包含 `frpc.toml` 里配的 `device_id` / `claim_placeholder`：
  ☐ 是　☐ 否（选"否"之前先确认配置检查里的 `tomllib` 那一行是"符合"）
- `content.client_address` 的实际值，是否是测试机的出口地址：
- `content.client_id` / `content.hostname` / `content.run_id` 等字段的实际值：

**NewProxy 请求实际收到的字段**：

```json

```

- `content.custom_domains` 或 `content.subdomain` 是否等于 frpc.toml 里配的值：
  ☐ 是　☐ 否
- `content.user.metas` 是否包含跟 Login 请求一致的 `device_id`：
  ☐ 是　☐ 否（**如果这里是"否"，这是本次验证里最需要立刻找 kazuha 复核的一项**）
- `content.user.run_id` 是否是非空字符串：☐ 是　☐ 否

**能否仅凭单次 NewProxy 请求（不额外维护跨请求状态）完成归属校验？**

☐ 能——`user.metas` 里的设备身份信息和 `custom_domains`/`subdomain` 同时出现在
同一次请求里，可以在 NewProxy 这一步一次性验签 + 查库比对。

☐ 不能——需要说明具体卡在哪个字段缺失/为空，以及打算退化成什么方案
（比如"Login 阶段校验 + 控制面自己维护 run_id → device_id 映射表"）：



**结论**：☐ 通过（安全模型按原计划走）　☐ 不通过（安全模型需要重新设计，见上）

---

## 验收项 ③：探针 deny / hang / error500 时，fail-open 还是 fail-closed

每一组都是先停 frpc、用 `w0modes` 切模式、再起 frpc；开始后把**探针记录里的 `mode=... 来源=...`**
核对一遍（确认 Login / NewProxy / NewUserConn / Ping 各自真的是你想要的模式，没有
`!!! 注意：模式文件当前无效` 的提醒）。NewUserConn 和 Ping 在这几组里都应该是 `allow`。

### NewProxy 隔离（模式文件 `{"Login":"allow","NewProxy":"..."}`）

| 字段 | `NewProxy=deny` | `NewProxy=error500` | `NewProxy=hang` |
|---|---|---|---|
| frpc 是否先登录成功（`login to server success`） | ☐ 是　☐ 否 | ☐ 是　☐ 否 | ☐ 是　☐ 否 |
| frpc 日志里这次 NewProxy 的表现（预期 `[opnsense-webui] start error: ...`） | | | |
| frps 日志里的对应行（预期 `new proxy [opnsense-webui] type [https] error: ...`） | | | |
| 探针里 `NewProxy` 的最终计数（看 frpc 有没有重发） | | | |
| 域名此时是否仍能访问到 OPNsense | ☐ 能（=放行/fail-open）　☐ 不能（=拒绝/fail-closed） | ☐ 能（=放行/fail-open）　☐ 不能（=拒绝/fail-closed） | ☐ 能（=放行/fail-open）　☐ 不能（=拒绝/fail-closed） |

hang 这一组的补充记录：

| 字段 | 记录 |
|---|---|
| `PROBE_HANG_SECONDS` 设的值（应为 120；用默认 30 会和心跳超时撞上竞态，结果不可复现） | |
| frpc 从发起连接到最终报错/成功，实际等了多久（掐表或 `time` 命令的结果） | |
| 这段时间里 frpc 是"卡住无输出"还是有中间状态日志；探针里 NewProxy 请求的时间戳间隔（对照源码预期的约 20 秒重发） | |
| frpc / frps 两边是否出现 `heartbeat timeout` 及随后的断开重连（开着心跳时按源码约 30 秒后第一次断开，因为 NewProxy 卡住时 frps 不处理这台设备的 Ping）；实际间隔 | ☐ 出现，约 ___ 秒后断开　☐ 没出现 |
| 断开后重连是否一直卡到探针 hang 结束（按源码同一 `run_id` 的重连要等 `WaitForHandoff`，期间 frpc 报 Login 超时）；hang 结束到 `start proxy success` 隔了多久 | ☐ 是，隔 ___ 秒　☐ 否（写明） |
| （可选）去掉两边心跳配置后重测 hang，NewProxy 的纯重发节奏 | ☐ 未测　☐ 已测（写在下面） |
| hang 期间，frps 本身（`/api/serverinfo` 或 dashboard，或第二台设备连一次）是否仍能正常响应，间接确认不是整个 frps 卡死 | ☐ 已验证，仍正常　☐ 已验证，也异常　☐ 未验证 |
| 代理最终是怎么注册上（或没注册上）的 | ☐ 一直没注册上（fail-closed）　☐ 探针睡满、回了 allow **之后**才注册（仍是 fail-closed：frps 没有超时、一直在等插件）　☐ 探针回应**之前**就注册了（fail-open，立刻标红） |

### Login 单独测

| 字段 | `Login=deny` | `Login=error500` | `Login=hang`（可选） |
|---|---|---|---|
| frpc 日志（预期 `connect to server error: ...`，然后因 `loginFailExit` 退出） | | | |
| frpc 是立刻退出、重试，还是一直卡着 | | | |
| frps 日志（预期 `register control error: ...`） | | | |
| 探针里是否只有 `Login`、没有 `NewProxy` | ☐ 是　☐ 否 | ☐ 是　☐ 否 | ☐ 是　☐ 否 |
| 最终 frpc 是否登录成功 | ☐ 是（=fail-open）　☐ 否（=fail-closed） | ☐ 是（=fail-open）　☐ 否（=fail-closed） | ☐ 是（=fail-open）　☐ 否（=fail-closed） |

### 综合结论（这条无论结果如何都要填，直接进风险清单）

frps 0.71.0 对 httpPlugins 的 Login / NewProxy 调用失败（含超时挂起）时的实际行为是：

☐ **fail-closed**（跟源码分析一致：拒绝登录 / 拒绝新代理注册，不会误放行）
☐ **fail-open**（跟源码分析不一致，**需要立刻标红上报**，附上复现步骤；写明是哪个 op）
☐ 结果不一致 / 不确定，需要重测：

**如果是 fail-closed，且 hang 场景下确认没有 frps 侧超时兜底**——把下面这条
原样抄进项目的风险清单/威胁模型文档：

> 归属校验控制面插件是单点故障：一旦插件后端（HMAC 校验、数据库查询等）
> 卡死或持续报错，所有需要重新走 Login+NewProxy 的设备连接尝试（新设备接入、
> frpc/frps 重启、网络抖动重连）都会被拒绝或无限期挂起，且 frps 自身不提供
> 超时保护；只订阅 Login / NewProxy 时，已经成功注册、无需重新走 NewProxy 的既有隧道
> 预计不受直接影响——但如果订阅了 `Ping`（⑥的断线机制），既有隧道也会在约一个心跳
> 间隔内被切断（见⑥的 6.6）。
> 缓解方向：控制面插件内部必须自己实现严格的超时（对数据库查询、签名校验
> 均设置上限，超时即明确拒绝），不能依赖 frps 兜底。

**实测是否验证了"已建立的隧道在插件挂掉期间不受影响"这条假设？**
本套件订阅了 `Ping`，按源码这条假设在本套件的配置下**不成立**，实测结果记在⑥的 6.6；
不订阅 `Ping` 时它是否成立，只有做了 6.6 的可选对照才算验证过。
☐ 6.6 的可选对照已做，不订阅 `Ping` 时既有隧道不受影响　☐ 已做，也受影响　☐ 未做

---

## 验收项 ④：受限网络下 8443 的可达性与稳定性（对照 443 基线）

按 RUNBOOK 里的交替采样脚本，每个网络环境跑 20 轮（每轮 443、8443 各一次），把
统计结果填在下表（原始输出整段贴在表格下面的代码块里）。成功率差 = 443 成功率 −
8443 成功率（单位：百分点）。

| 网络环境 | 443 TCP 成功/20 | 8443 TCP 成功/20 | 成功率差（百分点） | 443 TLS 握手中位数 | 8443 TLS 握手中位数 | 8443 总耗时中位数 | 观察到的异常模式 |
|---|---|---|---|---|---|---|---|
| 运营商 A（4G/5G，写明具体运营商） | | | | | | | |
| 运营商 B（4G/5G，写明具体运营商） | | | | | | | |
| 公司/校园网络 | | | | | | | |
| 境外网络（如有） | | | | | | | |
| 家用宽带（作为对照组，非受限网络） | | | | | | | |

（两边的 TLS 握手耗时不能直接比：443 在 VPS 上结束，8443 要穿过隧道到 OPNsense 才结束。）

**原始采样输出**（每个网络环境一段，方便复查）：

```

```

**是否观察到"前几次失败后面变稳定"或反过来的非均匀模式？具体是哪个网络、
什么现象？**



**DESIGN Q2 规则判定**（主判据）：

- 是否有任何网络环境下 8443 成功率比 443 低 20 个百分点以上：☐ 有（写明哪个网络）　☐ 没有
- 是否有任何网络环境下 8443 是 0/20（不论 443 的结果，照 Q2 原文）：☐ 有（写明哪个网络）　☐ 没有
  - 上一条选"有"时，该网络下 443 是否也是 0/20：☐ 是（照样记为触发，在这里写明，并复核采样是否有问题）　☐ 否　☐ 不适用

☐ 两条都没有触发——维持 8443，不启动 443 复用。
☐ 至少一条触发——按 Q2 启动"vhost-https 复用 443"的评估（具体见上表）。
☐ 样本量不够/环境覆盖不全，需要补测（写明还差哪些网络环境）。

**次要参考（绝对值）**：两个以上不同运营商的移动网络下，8443 成功率都 ≥ 18/20 且
TLS 握手中位数 < 1 秒：☐ 是　☐ 否

**443 基线已清理**（`s_server` 已停、证书和私钥已删、防火墙 443 已关）：☐ 已清理

---

## 验收项 ⑤：Q7 数据——`NewUserConn`

| 字段 | 记录 |
|---|---|
| 整项期间没有重启过探针，换模式都用 `w0modes`，计数用前后相减 | ☐ 是　☐ 否（重启过的话，那次前后的结果要复核） |
| 开始前 `NewUserConn` 的累计计数（基线） | |
| 探针是否收到了 `op=NewUserConn` | ☐ 是　☐ 否（=钩子对 https 代理不触发） |
| `content.proxy_type` / `content.proxy_name` 的实际值 | |
| `content.user.metas.device_id` 是否等于 `weekend0-test-device` | ☐ 是　☐ 否 |
| 手机上 IP 网站显示的公网 IP（注意 IPv4/IPv6） | |
| 同一时间 `content.remote_addr` 的值 | |
| `remote_addr` 的 IP 部分是否等于手机公网 IP | ☐ 是　☐ 否（写明差异）： |
| 无痕窗口打开一次登录页，`NewUserConn` 计数增加了几 | |
| 登录 + 进 Dashboard 等图表刷新一两轮，计数又增加了几 | |
| `w0modes '{"NewUserConn":"deny"}'` 后新开无痕窗口：能否打开页面 | ☐ 打不开（=拒绝有效）　☐ 仍能打开 |
| deny 期间 frps 日志是否出现 `the user conn [...] was rejected` | ☐ 是　☐ 否 |
| deny 期间隧道是否仍在线（frpc 无重连日志，探针里 `Ping` 仍约每 10 秒一条且 `mode=allow`，`/api/proxy/https` 里 `opnsense-webui` 为 `online`；⑥引用这一行作为"`NewUserConn` deny 时控制连接保持"的结果） | ☐ 是　☐ 否 |
| deny 之前已打开的标签页 A 还能不能用、能用多久 | ☐ 一直能用　☐ 大约 ___ 后不能用　☐ 立刻不能用 |
| （可选）`w0modes '{"NewUserConn":"error500"}'` 时新窗口能否打开 | ☐ 打不开　☐ 仍能打开　☐ 未测 |

**`NewUserConn` 请求原样摘录**（一条就够）：

```json

```

**结论**：

☐ 钩子触发、`remote_addr` 是真实客户端 IP、拒绝能挡住新连接且不伤隧道——Q7 的
来源 IP 门控在技术上可行。
☐ 至少一条不成立（写明哪条）——门控按现方案不可行，Q7 只剩文档提示 + OPNsense
自身 TOTP 2FA。

---

## 验收项 ⑥：撤销/断线机制（拒绝 `Ping` + 显式心跳）

时间都用 VPS 上的：`w0modes` 回显的时间和 frps 日志的时间戳（格式一致）。frpc 的日志用来看发生了
什么；两台机器时钟同步时也可以用它的时间。

### 6.0 准备

| 字段 | 记录 |
|---|---|
| 探针里 `Ping` 相邻两条的间隔（`距本 op 上一次 ... 秒`，预期约 10 秒） | |
| Ping 请求里 `content.user.metas.device_id` 是否等于 `weekend0-test-device`、`content.user.run_id` 是否非空 | ☐ 是　☐ 否 |
| Ping 请求的 `content` 里除了 `user` 还有没有别的字段（预期没有：没配 `HeartBeats` 时不带 `privilege_key` / `timestamp`） | |

**第一条 Ping 请求原样摘录**：

```json

```

### 6.1 只拒绝 `Ping`（`w0modes '{"Ping":"deny"}'`）

| 字段 | 记录 |
|---|---|
| T0：`w0modes` 回显的时间 | |
| T1：frps `received invalid ping: ...` 的时间 | |
| T2：frps `client exit success` 的时间 | |
| 断线时延 T2 − T0（以及 T1 − T0） | |
| frpc 日志是否出现 `pong message contains error: denied by probe ...` 并断开 | ☐ 是　☐ 否（=主机制不成立，先排除配置问题） |
| 标签页 A（断开前停在 Dashboard）的表现 | ☐ 立刻断（图表停、操作报错）　☐ 卡一下又自己恢复　☐ 不受影响　其他： |
| 之后 1～2 分钟 frpc 的表现 | ☐ 反复"登录成功 → 代理注册 → 马上又被断开"　☐ 断开后没再连上　☐ 其他： |
| 每一轮重连的间隔；这段时间里 `Login` / `NewProxy` / `Ping` 计数各涨了多少 | |
| 重连时 Login 记录里的 `content.run_id` 是否一直是同一个旧 run id | ☐ 是　☐ 否（写明）： |

### 6.2 模拟"已撤销设备"（`w0modes '{"Ping":"deny","Login":"deny","NewProxy":"deny"}'`）

| 字段 | 记录 |
|---|---|
| 观察了多久 | |
| 期间 frpc 是否再也没有出现 `login to server success` | ☐ 是（=设备被挡在外面）　☐ 否（写明） |
| frpc `connect to server error: denied by probe ...` 的出现间隔（预期约 2、4、8、16 秒，之后约 20 秒） | |
| frps 每次是否对应一条 `register control error: ...` | ☐ 是　☐ 否 |
| 探针里是否只剩 `Login` 计数在涨 | ☐ 是　☐ 否 |
| 新开无痕窗口能否打开页面 | ☐ 打不开　☐ 仍能打开（写明） |
| `/api/proxy/https` 里 `opnsense-webui` 的状态 | ☐ `offline`　☐ 不在列表里　☐ 仍是 `online`（写明） |

### 6.3 恢复（`w0modes '{}'`）

| 字段 | 记录 |
|---|---|
| T3：`w0modes` 回显的时间 | |
| T4：frps 下一次 `new proxy [opnsense-webui] type [https] success` 的时间 | |
| 恢复时延 T4 − T3（按源码不超过约 20 秒） | |
| 刷新标签页 A 后是否恢复正常 | ☐ 是　☐ 否 |

### 6.4 一次性撤销，重复测断线时延

| 第几次 | T0（写入） | T2（frps `client exit success`） | 断线时延 T2 − T0 | 标签页 A 是否断开 |
|---|---|---|---|---|
| 1 | | | | ☐ 断　☐ 没断 |
| 2 | | | | ☐ 断　☐ 没断 |
| 3 | | | | ☐ 断　☐ 没断 |

断线时延范围：最短 ___ 秒，最长 ___ 秒（按源码不应超过一个心跳间隔 10 秒多一点）。

### 6.5 frps 侧兜底：frpc 不发心跳（`transport.heartbeatInterval = -1`）

| 字段 | 记录 |
|---|---|
| 探针里是否不再有 `Ping` | ☐ 是　☐ 否 |
| frps 从 `new proxy [opnsense-webui] type [https] success` 到 `heartbeat timeout` 过了多久（预期约 30 秒） | |
| 之后是否约 30 秒一轮地断开重连 | ☐ 是　☐ 否（写明） |
| 测完 `heartbeatInterval` 已改回 10、`Ping` 已恢复 | ☐ 是 |

### 6.6 代价：探针整个停掉（模拟 authz 宕机）

| 字段 | 记录 |
|---|---|
| T5：停掉探针的时间 | |
| frps 是否出现 `send Ping request to plugin [nethub-probe] error: ...` 和 `received invalid ping: send Ping request to plugin error` | ☐ 是　☐ 否 |
| T6：frps `client exit success` 的时间；断线时延 T6 − T5 | |
| 已在线的隧道是否在一个心跳间隔左右被切断 | ☐ 是（=authz 宕机会切断所有在线隧道）　☐ 否（写明，并复核 Ping 是否真的在发） |
| 标签页 A 的表现 | ☐ 立刻断　☐ 卡一下又自己恢复　☐ 不受影响　其他： |
| 探针停着期间 frpc 的重连表现（预期 `connect to server error: send Login request to plugin error`，约 20 秒一次） | |
| T7：重新起探针的时间；T8：frps 下一次 `new proxy ... success` 的时间；恢复时延 T8 − T7 | |
| （可选对照）从 `ops` 去掉 `Ping`、重启 frps 后重做本步：既有隧道和标签页 A 是否不受影响 | ☐ 未做　☐ 不受影响　☐ 也受影响（写明） |

### 6.6b 代价：控制面整体返回 500（`Login` / `NewProxy` / `Ping` 全部 `error500`）

| 字段 | 记录 |
|---|---|
| T9：切换的时间；T10：frps `client exit success` 的时间；断线时延 T10 − T9 | |
| 已在线的隧道是否在一个心跳间隔左右被切断 | ☐ 是　☐ 否（写明） |
| 标签页 A 的表现 | ☐ 立刻断　☐ 卡一下又自己恢复　☐ 不受影响　其他： |
| `w0modes '{}'` 之后的恢复时延 | |

### 6.6c 代价：控制面整体挂起（三个 op 全部 `hang`，`PROBE_HANG_SECONDS=120`）

| 字段 | 记录 |
|---|---|
| T11：切换的时间；T12：断开的时间；断线时延 T12 − T11（按源码约 30 秒，等心跳超时） | |
| 重连是否一直卡到探针睡满 120 秒（`WaitForHandoff`） | ☐ 是　☐ 否（写明） |
| 标签页 A 的表现 | ☐ 立刻断　☐ 卡一下又自己恢复　☐ 不受影响　其他： |
| 恢复后探针已按默认 `PROBE_HANG_SECONDS` 重启 | ☐ 是 |

### 6.7（可选）`Ping` 卡住（`w0modes '{"Ping":"hang"}'`）

| 字段 | 记录 |
|---|---|
| 从切换到断开过了多久；frpc / frps 两边是否都记了 `heartbeat timeout`（预期约 30 秒） | ☐ 未测　记录： |
| 重连是否卡到探针 hang 结束（`WaitForHandoff`），之后又被卡住；实际节奏 | ☐ 未测　记录： |

**⑥的结论**（无论结果如何都要填，直接进风险清单）：

- 主机制（拒绝 `Ping` + 显式心跳 + 同时拒绝 `Login`）：☐ 可行　☐ 不可行（写明卡在哪一步）　☐ 部分成立
- 实测断线时延：___ ～ ___ 秒（心跳间隔 10 秒时）
- 已打开的浏览器连接：☐ 随断线一起断开　☐ 不受影响　☐ 不确定
- 断开后设备能否被 `Login` 拒绝挡在外面：☐ 能　☐ 不能
- authz 故障对在线隧道的影响：停掉（6.6）☐ 约 ___ 秒内全部切断，恢复约 ___ 秒　☐ 不受影响　☐ 未测；
  返回 500（6.6b）约 ___ 秒切断；挂起（6.6c）约 ___ 秒切断
- 按源码记录、原版 frpc 测不出的剩余风险：被改过、收到带错误的 Pong 也不关会话的 frpc，frps 会在
  `heartbeatTimeout` 内断开它的控制连接，但已经打开的工作流按源码可能继续存活。

---

## 总体结论与风险清单（给 kazuha 复核用）

**六项验收的整体通过情况**：

| 验收项 | 结果 |
|---|---|
| 配置检查（verify + 表作用域） | ☐ 全部通过　☐ 有问题 |
| ① 外部访问 + 登录 | ☐ 通过　☐ 不通过 |
| ② Login/NewProxy 字段可用于归属校验 | ☐ 通过　☐ 不通过 |
| ③ fail-open/fail-closed（结论本身，不是"通过/不通过"） | Login：☐ fail-closed　☐ fail-open　☐ 不确定；NewProxy：☐ fail-closed　☐ fail-open　☐ 不确定 |
| ④ 受限网络可达性（Q2 规则） | ☐ 未触发，维持 8443　☐ 触发，需要评估 443 复用　☐ 需补测 |
| ⑤ Q7：`NewUserConn` 门控是否可行 | ☐ 可行　☐ 不可行　☐ 部分成立 / 需补测 |
| ⑥ 撤销/断线：拒绝 `Ping` + 显式心跳能否断开在线设备并把它挡在外面 | ☐ 可行，断线时延 ___ ～ ___ 秒　☐ 不可行　☐ 部分成立 / 需补测 |
| ⑥ 代价：authz 停掉 / 返回 500 / 挂起时在线隧道是否被切断（结论本身，不是"通过/不通过"） | 停掉 ___ 秒、500 ___ 秒、挂起 ___ 秒内全部切断　☐ 不受影响　☐ 未测 |

**Q7 一句话结论**（给 Q7 决策用：钩子是否触发、`remote_addr` 是否可信、拒绝是否有效、
一次页面加载触发几次）：



**撤销/断线一句话结论**（给 DESIGN §5 的机制选择和 W5 的时延目标用：能不能断、多快断、
已打开的页面断不断、断开后能不能挡住、authz 宕机的代价）：



**本次验证发现的、需要写进项目风险清单/威胁模型文档的条目**（哪怕验收都
"通过"，③的 fail-closed-无超时、⑥的断线时延和"authz 宕机切断在线隧道"这几条也应该出现在这里）：

1.
2.
3.

**需要 kazuha 复核 / 拍板的问题**（比如②如果不通过、③如果测出 fail-open、
④如果 Q2 规则触发、⑤的结果是否足以支持 Q7 门控、⑥的主机制和它的代价能不能接受、
生产上的心跳间隔取多少）：

1.
2.
