#!/usr/bin/env python3
"""
probe.py —— Weekend 0 传输层验证套件的 frps httpPlugins 探针后端。

用途：
  frps 的 [[httpPlugins]] 会把 Login / NewProxy / NewUserConn / Ping 等操作的请求，以
  POST + JSON body 的形式转发到这个进程（操作名同时出现在查询串 ?op=xxx 和
  body 的 "op" 字段里）。这个脚本原样把每个请求的 JSON body 打印出来，这样我们
  才能拿到验收项②⑤⑥要的"真实字段名"，而不是靠猜配置文档。
  例外：Ping 每个心跳间隔就来一次，只在本次运行的第 1 次打印完整 body，之后每次
  只打印一行摘要（模式、来源、计数照样每次都打印）。

  应答模式（用来测验收项③ fail-open / fail-closed、验收项⑤ 拒绝能否挡住连接、
  验收项⑥ 拒绝 Ping 能否断线）：
    allow     （默认）正常放行：{"reject": false, "unchange": true}
    deny      直接拒绝：{"reject": true, "reject_reason": "..."}
    hang      先 sleep PROBE_HANG_SECONDS 秒（默认 30）再放行——制造"探针卡死"的场景
    error500  返回 HTTP 500——制造"探针进程崩了/返回非 200"的场景

  模式按 op 分别设置，优先级从高到低：
    1. 模式文件 PROBE_MODES_FILE 里这个 op 的键（可选，见下面，运行中可以改）
    2. PROBE_MODE_<OP> 环境变量：
         PROBE_MODE_LOGIN        只覆盖 op=Login
         PROBE_MODE_NEWPROXY     只覆盖 op=NewProxy
         PROBE_MODE_NEWUSERCONN  只覆盖 op=NewUserConn
         PROBE_MODE_PING         只覆盖 op=Ping
    3. PROBE_MODE               所有 op 的默认模式
    4. 都没设就是 allow
  （不在这四个里的 op 一律走 PROBE_MODE / allow。）
  这样才能把 NewProxy 单独隔离出来测：只设一个全局 deny 的话，Login 会先被拒，
  frpc 根本走不到 NewProxy 那一步。环境变量里的模式值写错会直接拒绝启动，不会悄悄
  当成 allow——否则一个拼写错误就会被误读成"fail-open"。

  模式文件（运行中切换模式，不用重启探针）：
    frps 订阅了 Ping、frpc 又开了显式心跳之后，frpc 每个心跳间隔都会经 frps 问一次
    探针。重启探针的那一两秒里到达的 Ping 连不上探针，frps 就回给 frpc 一个带错误的
    Pong，frpc 随即断开整条隧道——"重启探针"这个动作本身就会切断隧道，干扰验收项
    ⑤⑥的观察。所以运行中换模式用模式文件：
      PROBE_MODES_FILE=/tmp/w0-modes.json python3 probe.py
    文件内容是一个 JSON 对象，键是 op 名（Login / NewProxy / NewUserConn / Ping，大小写
    要一致），值是模式，例如 {"Ping": "deny", "NewUserConn": "allow"}；文件里没写的 op
    照旧按环境变量走；{} 表示不覆盖任何 op。探针在每个请求到来时重读一次这个文件
    （文件很小，代价可以忽略），内容一变就从这个请求开始生效，并打印一条"模式文件已
    重新加载"。
    文件内容不合法（不是 JSON 对象、键不认识、模式值写错、空文件）、读不了、或者
    文件不见了：大声报错，忽略这次的内容，沿用上一次合法的内容，并且之后每条请求
    记录里都带一行提醒，直到文件恢复合法。
    启动时文件存在但内容不合法：直接拒绝启动（跟环境变量写错一样）；启动时文件
    不存在：只打印警告，按"没有覆盖"启动，之后文件一出现就生效。
    不设 PROBE_MODES_FILE 时，应答行为跟没有这个功能时完全一样。
    写文件请用"先写临时文件再 mv"的方式（RUNBOOK 里给了一个现成的 shell 函数），
    避免探针刚好读到写了一半的内容（那种情况会被当成不合法、沿用上次的内容，不会
    误生效，只是会多一条报错）。

  每个 op 都单独计数，每条记录都打印当前累计计数和"距本 op 上一次请求过了几秒"。
  验收项⑤用计数数"打开一次 OPNsense 登录页会触发多少次 NewUserConn"（记下前后的
  计数相减；不要为了清零去重启探针，原因见上）；验收项⑥用时间间隔看心跳节奏和
  frpc 的重连节奏。

  只用标准库（http.server + json），不装任何第三方依赖，这样在一台干净 VPS 上
  `python3 probe.py` 就能跑，不需要先 pip install。

用法：
  PROBE_MODE=allow PROBE_PORT=9000 python3 probe.py
  PROBE_MODE_LOGIN=allow PROBE_MODE_NEWPROXY=deny python3 probe.py
  PROBE_MODES_FILE=/tmp/w0-modes.json python3 probe.py
  # 另开一个终端: tail -f probe.log 看历史记录
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# 探针监听地址：默认只听 127.0.0.1，因为 frps 的 httpPlugins.addr 也应该指向
# 本机回环地址——这个探针不应该暴露在公网上（真实的控制面服务当然要暴露，
# 但 Weekend 0 我们只是在验证协议，没必要多开一个公网攻击面）。
HOST = os.environ.get("PROBE_HOST", "127.0.0.1")
PORT = int(os.environ.get("PROBE_PORT", "9000"))

# hang 模式睡多久：30 秒足够看出 frps/frpc 有没有给这次请求设置超时上限。
HANG_SECONDS = float(os.environ.get("PROBE_HANG_SECONDS", "30"))

# 相对路径就是相对于启动探针时的当前工作目录。
LOG_FILE = os.environ.get("PROBE_LOG_FILE", "probe.log")

# 模式文件路径；不设（或设成空串）就不启用这个功能。
MODES_FILE = os.environ.get("PROBE_MODES_FILE", "").strip() or None

# 模式文件正常只有几十个字节；超过这个大小直接当成不合法，免得误指向一个大文件。
MAX_MODES_FILE_BYTES = 64 * 1024

VALID_MODES = ("allow", "deny", "hang", "error500")

# frps 订阅了的、可以单独覆盖模式的 op（跟 frps.toml 里 [[httpPlugins]] 的 ops 一致）。
KNOWN_OPS = ("Login", "NewProxy", "NewUserConn", "Ping")

NO_OP = "<无>"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _read_mode(env_name: str, default: str | None) -> str | None:
    """读一个模式环境变量；值不合法就报错退出，避免拼写错误被当成 allow。"""
    raw = os.environ.get(env_name)
    if raw is None or raw.strip() == "":
        return default
    mode = raw.strip().lower()
    if mode not in VALID_MODES:
        sys.stderr.write(
            f"probe.py: {env_name}={raw!r} 不是合法模式，只能是 {' | '.join(VALID_MODES)}。拒绝启动。\n"
        )
        sys.exit(2)
    return mode


# 环境变量启动时一次性解析好：进程的环境变量在运行中不会变。运行中要换模式就用模式文件。
DEFAULT_MODE = _read_mode("PROBE_MODE", "allow")
# PROBE_MODE 是真的设了，还是用的内置默认值 allow——只影响日志里写的"来源"。
DEFAULT_MODE_FROM_ENV = os.environ.get("PROBE_MODE", "").strip() != ""


def _override_env(op: str) -> str:
    return "PROBE_MODE_" + op.upper()


# 已知 op 的覆盖值在启动时一次性读好并校验，写错的变量当场就能发现。
OP_MODES = {op: _read_mode(_override_env(op), None) for op in KNOWN_OPS}

_counts: dict[str, int] = {}
_last_seen: dict[str, float] = {}
_counts_lock = threading.Lock()
_log_lock = threading.Lock()


def _log(text: str) -> None:
    """把一段文本同时写到 stdout 和 probe.log，方便一边盯着终端一边留存证据。"""
    with _log_lock:
        sys.stdout.write(text)
        sys.stdout.flush()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(text)


def _loud(lines: list[str]) -> str:
    """拼一段醒目的报错块：上下两条感叹号横线，每行前面加 '!!! '。"""
    bar = "!" * 72
    body = "".join(f"!!! {line}\n" for line in lines)
    return f"\n{bar}\n{body}{bar}\n"


def _fmt_modes(modes: dict[str, str]) -> str:
    return json.dumps(modes, ensure_ascii=False, sort_keys=True)


class ModesFile:
    """运行中可切换的模式文件。线程安全；每个请求调用一次 refresh()。"""

    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        # 上次看到的文件状态：("unseen", None) / ("missing", None) / ("unreadable", 错误文本) /
        # ("read", 原始字节)。状态和内容都没变就什么都不做。
        self._last_seen: tuple[str, object] = ("unseen", None)
        self._good: dict[str, str] = {}  # 上一次合法的覆盖表（还没加载过合法内容时是空的 = 没有覆盖）
        self._good_since: str | None = None  # 上一次合法内容是什么时候加载的
        self.problem: str | None = None  # 当前文件的问题说明；None = 当前内容合法
        self.state = "unseen"  # 最近一次检查的结论：ok / missing / unreadable / invalid

    @staticmethod
    def parse(raw: bytes) -> dict[str, str]:
        """把文件内容解析成 {op: mode}；任何不合法都抛 ValueError（带中文原因）。"""
        if len(raw) > MAX_MODES_FILE_BYTES:
            raise ValueError(f"文件超过 {MAX_MODES_FILE_BYTES} 字节，不像是模式文件")
        text = raw.decode("utf-8")  # UnicodeDecodeError 是 ValueError 的子类
        if text.strip() == "":
            raise ValueError("文件是空的（要清空所有覆盖请写 {}）")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"不是合法 JSON：{exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"顶层必须是 JSON 对象，实际是 {type(data).__name__}")
        modes: dict[str, str] = {}
        for key, value in data.items():
            if key not in KNOWN_OPS:
                raise ValueError(f"不认识的键 {key!r}，只能是 {' / '.join(KNOWN_OPS)}（大小写要一致）")
            mode = value.strip().lower() if isinstance(value, str) else None
            if mode not in VALID_MODES:
                raise ValueError(f"{key} 的值 {value!r} 不是合法模式，只能是 {' | '.join(VALID_MODES)}")
            modes[key] = mode
        return modes

    def _kept_text(self) -> str:
        if self._good_since is None:
            return "还没有加载过合法内容，等于没有任何覆盖（全部按环境变量）"
        return f"{_fmt_modes(self._good)}（加载于 {self._good_since}）"

    def refresh(self) -> tuple[dict[str, str], list[str]]:
        """重读一次文件。返回 (现在生效的覆盖表, 这次需要打印的事件文本)。"""
        events: list[str] = []
        try:
            with open(self.path, "rb") as fh:
                seen: tuple[str, object] = ("read", fh.read(MAX_MODES_FILE_BYTES + 1))
        except FileNotFoundError:
            seen = ("missing", None)
        except OSError as exc:
            seen = ("unreadable", f"{type(exc).__name__}: {exc}")

        with self._lock:
            if seen == self._last_seen:
                return dict(self._good), events
            self._last_seen = seen
            kind, payload = seen
            if kind == "read":
                assert isinstance(payload, bytes)
                try:
                    modes = self.parse(payload)
                except ValueError as exc:
                    self.state = "invalid"
                    self.problem = f"内容不合法：{exc}"
                    preview = payload[:200].decode("utf-8", "replace")
                    events.append(
                        _loud(
                            [
                                f"[{_now()}] 模式文件 {self.path} {self.problem}",
                                f"文件内容（前 200 字节）：{preview!r}",
                                f"已忽略这次内容，继续沿用上一次合法的内容：{self._kept_text()}",
                                "修好文件之前，每条请求记录里都会带一行提醒。",
                            ]
                        )
                    )
                else:
                    self.state = "ok"
                    self.problem = None
                    self._good = modes
                    self._good_since = _now()
                    events.append(
                        f"\n[{self._good_since}] >>> 模式文件已重新加载：{self.path} -> {_fmt_modes(modes)}"
                        "（从这个请求开始生效；文件里没写的 op 按环境变量）\n"
                    )
            else:
                self.state = kind
                self.problem = "文件不存在" if kind == "missing" else f"文件读不了：{payload}"
                events.append(
                    _loud(
                        [
                            f"[{_now()}] 模式文件 {self.path} {self.problem}",
                            f"继续沿用上一次合法的内容：{self._kept_text()}",
                            "恢复文件之前，每条请求记录里都会带一行提醒。",
                        ]
                    )
                )
            return dict(self._good), events

    def warning_line(self) -> str:
        """当前文件有问题时，给每条请求记录加的一行提醒；没问题返回空串。"""
        with self._lock:
            if self.problem is None:
                return ""
            return f"!!! 注意：模式文件当前无效（{self.problem}），本次沿用上一次合法的内容：{self._kept_text()}\n"


MODES = ModesFile(MODES_FILE) if MODES_FILE else None


def _mode_for(op: str, file_modes: dict[str, str]) -> tuple[str, str, str]:
    """返回 (这个 op 用的模式, 来源类别 file/env/default, 来源名字)。

    来源名字会写进 deny 的 reject_reason；环境变量来源时跟以前完全一样（变量名本身）。
    """
    if op in file_modes:
        return file_modes[op], "file", f"PROBE_MODES_FILE[{op}]"
    override = OP_MODES.get(op)
    if override is not None:
        return override, "env", _override_env(op)
    if DEFAULT_MODE_FROM_ENV:
        return DEFAULT_MODE, "env", "PROBE_MODE"
    return DEFAULT_MODE, "default", "PROBE_MODE"


def _describe_source(op: str, kind: str, name: str) -> str:
    if kind == "file":
        return f"来源=file（{MODES_FILE} 里的 \"{op}\"）"
    if kind == "env":
        return f"来源=env（{name}）"
    return "来源=default（没设 PROBE_MODE，也没有针对这个 op 的覆盖，默认 allow）"


def _bump(op: str) -> tuple[int, str, float | None]:
    """给这个 op 计数 +1，返回 (这个 op 的新计数, 所有 op 的计数摘要, 距本 op 上一次的秒数)。"""
    now = time.monotonic()
    with _counts_lock:
        _counts[op] = _counts.get(op, 0) + 1
        prev = _last_seen.get(op)
        _last_seen[op] = now
        summary = " ".join(f"{k}={v}" for k, v in sorted(_counts.items()))
        return _counts[op], summary, (now - prev) if prev is not None else None


def _dict_at(obj: object, key: str) -> dict:
    value = obj.get(key) if isinstance(obj, dict) else None
    return value if isinstance(value, dict) else {}


class ProbeHandler(BaseHTTPRequestHandler):
    # 屏蔽 BaseHTTPRequestHandler 默认的访问日志格式，我们自己打印更有用的内容。
    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        pass

    def do_POST(self) -> None:  # noqa: N802 (http.server 的命名约定如此)
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw_body = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw_body) if raw_body else {}
        except json.JSONDecodeError as exc:
            body = {"<json解析失败>": str(exc), "raw": raw_body.decode("utf-8", "replace")}

        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        reqid = self.headers.get("X-Frp-Reqid", "<无>")

        # 模式文件每个请求重读一次；文件变了，就从这个请求开始生效。
        file_modes: dict[str, str] = {}
        if MODES is not None:
            file_modes, events = MODES.refresh()
            if events:
                _log("".join(events))

        # op 以查询串为准（frps 的 pkg/plugin/server/http.go 会同时设 ?op= 和 body.op）。
        op = query.get("op", [NO_OP])[0]
        mode, src_kind, mode_src = _mode_for(op, file_modes)
        op_count, summary, since_prev = _bump(op)

        body_op = body.get("op") if isinstance(body, dict) else None
        op_note = ""
        if body_op is not None and body_op != op:
            op_note = f"（注意：body.op={body_op} 跟查询串不一致）"

        since_text = "本次运行第一次" if since_prev is None else f"距本 op 上一次 {since_prev:.1f} 秒"
        banner = (
            "\n" + "=" * 72 + "\n"
            f"[{_now()}] op={op}{op_note} "
            f"mode={mode} {_describe_source(op, src_kind, mode_src)} "
            f"path={parsed.path} version={query.get('version', ['<无>'])[0]} reqid={reqid}\n"
            f"--- 计数：本 op 第 {op_count} 次（{since_text}）；累计 {summary}\n"
        )
        if MODES is not None:
            banner += MODES.warning_line()

        content = _dict_at(body, "content")
        user = _dict_at(content, "user")
        metas = _dict_at(user, "metas")
        if op == "NewUserConn" and isinstance(body, dict):
            # 验收项⑤最关心的几个字段先单独拎出来，方便直接跟手机上看到的公网 IP 对比。
            banner += (
                "--- NewUserConn 摘要："
                f"remote_addr={content.get('remote_addr')} "
                f"proxy_name={content.get('proxy_name')} "
                f"proxy_type={content.get('proxy_type')} "
                f"user.user={user.get('user')!r} "
                f"user.run_id={user.get('run_id')} "
                f"user.metas.device_id={metas.get('device_id')}\n"
            )
        if op == "Ping" and isinstance(body, dict):
            # 验收项⑥：Ping 里能不能对应到设备（user.metas / run_id），以及心跳节奏。
            banner += (
                "--- Ping 摘要："
                f"user.run_id={user.get('run_id')} "
                f"user.metas.device_id={metas.get('device_id')} "
                f"timestamp={content.get('timestamp')} "
                f"privilege_key={'有' if content.get('privilege_key') else '无'}\n"
            )
        if op == "Ping" and op_count > 1:
            banner += "--- （Ping 的完整 body 只在本次运行的第 1 次打印，这里省略）\n"
        else:
            banner += (
                "--- 收到的 JSON body（这就是验收项②⑤⑥要核对的真实字段名）---\n"
                f"{json.dumps(body, indent=2, ensure_ascii=False)}\n"
            )
        _log(banner)

        if mode == "hang":
            # 制造"探针卡住不回应"的场景：sleep 期间这个 HTTP 连接、以及 frps 里
            # 处理这次 Login/NewProxy/NewUserConn/Ping 的那个 goroutine，都会被一直挂起。
            _log(f"[hang] op={op} 开始睡眠 {HANG_SECONDS} 秒……\n")
            time.sleep(HANG_SECONDS)
            _log(f"[hang] op={op} 睡眠结束，现在补发一个 allow 应答。\n")
            self._reply_json(200, {"reject": False, "unchange": True})

        elif mode == "deny":
            self._reply_json(
                200,
                {
                    "reject": True,
                    "reject_reason": f"denied by probe ({mode_src}=deny, op={op})",
                },
            )

        elif mode == "error500":
            # 故意返回非 200，模拟"控制面探针进程本身出错/崩溃"的情况。
            self._reply_json(
                500,
                {"error": f"probe forced 500 ({mode_src}=error500, op={op})"},
                status_text="Internal Server Error",
            )

        else:  # allow（默认）
            self._reply_json(200, {"reject": False, "unchange": True})

    def _reply_json(self, status: int, payload: dict, status_text: str | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        try:
            self.send_response(status, status_text)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError) as exc:
            # hang 期间 frps 那一侧可能已经断开；这本身就是值得记录的现象。
            _log(f"--- 回应 HTTP {status} 失败，对端已断开：{exc!r}\n")
            return
        _log(f"--- 已回应 HTTP {status}: {json.dumps(payload, ensure_ascii=False)}\n")


def main() -> None:
    file_modes: dict[str, str] = {}
    if MODES is not None:
        file_modes, _ = MODES.refresh()
        if MODES.state in ("invalid", "unreadable"):
            sys.stderr.write(
                f"probe.py: PROBE_MODES_FILE={MODES.path!r} {MODES.problem}。拒绝启动"
                "（启动时就不合法的模式文件不会被悄悄忽略；修好文件、或者不设 PROBE_MODES_FILE 再启动）。\n"
            )
            sys.exit(2)

    server = ThreadingHTTPServer((HOST, PORT), ProbeHandler)
    print(f"probe.py 已启动：监听 http://{HOST}:{PORT}")
    if DEFAULT_MODE_FROM_ENV:
        print(f"  PROBE_MODE（默认模式）= {DEFAULT_MODE}")
    else:
        print(f"  PROBE_MODE 未设置，默认模式 = {DEFAULT_MODE}")
    if MODES is None:
        print("  PROBE_MODES_FILE 未设置：模式只看环境变量，运行中不能切换。")
    elif MODES.state == "missing":
        print(
            f"  !!! 警告：PROBE_MODES_FILE={os.path.abspath(MODES.path)} 现在不存在，先按没有覆盖启动；"
            "文件一出现，下一个请求就按它生效。"
        )
    else:
        print(f"  PROBE_MODES_FILE = {os.path.abspath(MODES.path)}，当前内容 {_fmt_modes(file_modes)}")
    for op in KNOWN_OPS:
        mode, kind, name = _mode_for(op, file_modes)
        print(f"  {op:<12} -> {mode}（{_describe_source(op, kind, name)}）")
    print(f"  PROBE_HANG_SECONDS = {HANG_SECONDS}")
    print(f"日志同时写入 stdout 和 {os.path.abspath(LOG_FILE)}。Ctrl+C 停止。")
    # stdout 被重定向到文件或管道（比如 | tee）时 print 是块缓冲的，先刷出去，启动信息才能马上看到。
    sys.stdout.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n收到 Ctrl+C，正在关闭探针……")
    finally:
        with _counts_lock:
            summary = " ".join(f"{k}={v}" for k, v in sorted(_counts.items())) or "（没有收到请求）"
        print(f"本次运行各 op 累计请求数：{summary}")
        server.server_close()


if __name__ == "__main__":
    main()
