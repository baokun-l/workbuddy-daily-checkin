#!/usr/bin/env python3
"""
WorkBuddy 每日积分自动领取脚本

原理：
  通过逆向 WorkBuddy 桌面客户端 (Electron app.asar)，找到签到领积分的 API：
    1. 查询签到状态: POST https://copilot.tencent.com/v2/billing/meter/checkin-activity-status
    2. 领取每日积分: POST https://copilot.tencent.com/v2/billing/meter/daily-checkin
    3. 刷新 token:   POST https://copilot.tencent.com/v2/auth/token/refresh

  认证方式:
    - Authorization: Bearer <accessToken>  (JWT)
    - X-User-Id: <uid>
    - token 存储在本地 auth 文件中，客户端运行时会自动刷新

  凭据来源（重要）:
    新版客户端（约 2026-09-26 起）会把 workbuddy-desktop.info 里的敏感字段
    用 AES-GCM 信封加密，形如 {"$wbEncrypted":1,"envelope":"..."}，脚本无法解密。
    因此本脚本按以下优先级取凭据：
      1) Tencent-Cloud.coding-copilot.info —— 同一账号，字段为明文（长期有效）
      2) workbuddy-desktop.info           —— 仅当其字段仍是明文时可用
    两个文件都在 %LOCALAPPDATA%/CodeBuddyExtension/Data/Public/auth/ 下。
    若两处都是加密的，脚本会明确报错并提示打开客户端。

  脚本逻辑:
    1. 按优先级读取凭据文件（每次运行都读最新的）
    2. 若 token 已过期，用 refreshToken 刷新
    3. 查询签到状态，如果今天未签到则自动领取
    4. 记录日志

用法:
    python workbuddy_checkin.py            # 执行一次签到
    python workbuddy_checkin.py --status   # 仅查看状态，不领取
    python workbuddy_checkin.py --dry-run  # 模拟运行，不实际调用领取接口

定时任务:
    配合 Windows 任务计划程序自动执行（见 README 或 setup_event_trigger.ps1）
"""

import json
import os
import sys
import time
import base64
import datetime
import urllib.request
import urllib.error
import ssl
import traceback
from pathlib import Path
import socket

# ============================================================
# 输出编码安全：Windows 控制台/管道默认 GBK，无法编码 emoji 会崩溃
# 强制 stdout/stderr 用 UTF-8 且出错时替换字符，不中断脚本
# ============================================================
def _safe_reconfigure(stream):
    try:
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

_safe_reconfigure(sys.stdout)
_safe_reconfigure(sys.stderr)

# ============================================================
# 配置
# ============================================================

_AUTH_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "CodeBuddyExtension", "Data", "Public", "auth",
)

# 首选：同账号的明文凭据文件（CodeBuddy 插件写入）
PLAIN_AUTH_FILE = os.path.join(_AUTH_DIR, "Tencent-Cloud.coding-copilot.info")

# 次选：WorkBuddy 桌面客户端凭据（新版会加密，仅在仍为明文时可用）
AUTH_FILE = os.path.join(_AUTH_DIR, "workbuddy-desktop.info")

# 新版客户端字段加密信封的标记
ENCRYPTED_MARKER = "$wbEncrypted"

# API 配置
ENDPOINT = "https://copilot.tencent.com"
STATUS_API = "/v2/billing/meter/checkin-activity-status"
CHECKIN_API = "/v2/billing/meter/daily-checkin"
REFRESH_API = "/v2/auth/token/refresh"

# 日志文件
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_FILE = SCRIPT_DIR / "checkin.log"

# 请求超时（秒）
TIMEOUT = 20

# 网络请求重试配置
MAX_RETRIES = 3          # 最多尝试次数（含首次）
RETRY_BACKOFF = 2.0      # 退避基数（秒），第 n 次重试等待 backoff * n 秒

# 启动前网络等待配置（应对开机后 DNS/网络尚未就绪导致领取失败）
NETWORK_WAIT_TIMEOUT = 120   # 最多等待秒数（在任务 5 分钟时限内）
NETWORK_PROBE_INTERVAL = 5   # 探测间隔秒数

# 日志轮转阈值（字节），超过则备份为 checkin.log.old
LOG_ROTATE_SIZE = 512 * 1024

# 国内站点直连：显式禁用代理，避免系统代理残留导致连接被拒
_SSL_CTX = ssl.create_default_context()
_OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}),
    urllib.request.HTTPSHandler(context=_SSL_CTX),
)


# ============================================================
# 日志
# ============================================================

def log(msg, level="INFO"):
    """写入日志并打印到控制台（打印失败不影响主流程）"""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    try:
        print(line)
    except Exception:
        try:
            print(line.encode("ascii", "replace").decode("ascii"))
        except Exception:
            pass
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ============================================================
# Auth 文件读取
# ============================================================

def is_encrypted_field(value):
    """判断某个字段是否被客户端加密（{"$wbEncrypted":1,"envelope":"..."}）"""
    return isinstance(value, dict) and value.get(ENCRYPTED_MARKER) == 1


def candidate_auth_paths():
    """返回按优先级排列的候选凭据文件路径（去重）"""
    paths = [PLAIN_AUTH_FILE, AUTH_FILE]
    home = Path.home()
    paths.append(str(home / "AppData" / "Local" / "CodeBuddyExtension"
                     / "Data" / "Public" / "auth" / "Tencent-Cloud.coding-copilot.info"))
    paths.append(str(home / "AppData" / "Local" / "CodeBuddyExtension"
                     / "Data" / "Public" / "auth" / "workbuddy-desktop.info"))
    seen, result = set(), []
    for p in paths:
        if p and p not in seen:
            seen.add(p)
            result.append(p)
    return result


def load_session():
    """读取登录会话，返回 (session, auth_path)。

    优先使用字段为明文的凭据文件；新版客户端会给字段加 AES-GCM 信封
    （{"$wbEncrypted":1,...}），脚本无法解密，遇到时跳过并尝试下一个。
    若所有候选文件都被加密，则报错退出并提示用户。
    """
    encrypted_hits = []
    for raw_path in candidate_auth_paths():
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                session = json.load(f)
        except Exception as e:
            log(f"读取凭据文件失败（{path}）: {e}", "WARN")
            continue

        auth = session.get("auth") if isinstance(session, dict) else None
        if not isinstance(auth, dict):
            continue

        if is_encrypted_field(auth.get("accessToken")):
            encrypted_hits.append(str(path))
            continue

        token = auth.get("accessToken")
        if isinstance(token, str) and token:
            log(f"凭据来源: {path}")
            return session, path

    if encrypted_hits:
        log("所有凭据文件的 accessToken 都已被客户端加密（AES-GCM 信封），脚本无法解密：", "ERROR")
        for p in encrypted_hits:
            log(f"  - {p}", "ERROR")
        log("请打开 WorkBuddy / CodeBuddy 客户端登录后重试；", "ERROR")
        log("或确认 %LOCALAPPDATA%/CodeBuddyExtension/Data/Public/auth/ 下存在明文凭据文件。", "ERROR")
        sys.exit(1)

    log("未找到可用的凭据文件，已查找：", "ERROR")
    for p in candidate_auth_paths():
        log(f"  - {p}", "ERROR")
    log("请确保 WorkBuddy 桌面客户端已安装并登录", "ERROR")
    sys.exit(1)


def require_plain_token(value, label):
    """确保 token 是明文字符串；否则给出可读的错误并退出。

    这能避免把 dict（加密信封）塞进请求头时抛出
    "expected string or bytes-like object, got 'dict'" 这种费解的异常。
    """
    if isinstance(value, str) and value:
        return value
    if is_encrypted_field(value):
        log(f"{label} 已被客户端加密（AES-GCM 信封），无法用于请求", "ERROR")
    else:
        log(f"{label} 缺失或类型异常: {type(value).__name__}", "ERROR")
    log("请打开客户端重新登录以刷新凭据", "ERROR")
    sys.exit(1)


def validate_session(session):
    """校验 auth 文件结构，缺少关键字段时优雅退出"""
    try:
        if not isinstance(session, dict):
            raise KeyError("session 不是 dict")
        _ = session["account"]["uid"]
        _ = session["auth"]["accessToken"]
    except (KeyError, TypeError):
        log("auth 文件结构异常：缺少 account.uid 或 auth.accessToken", "ERROR")
        log("请打开 WorkBuddy 客户端重新登录以重建 auth 文件", "ERROR")
        sys.exit(1)


def decode_jwt_exp(token):
    """解码 JWT token，返回过期时间 (datetime)；非字符串/无法解析返回 None"""
    try:
        if not isinstance(token, str):
            return None
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        data = json.loads(base64.b64decode(payload))
        exp = data.get("exp")
        if exp:
            return datetime.datetime.fromtimestamp(exp)
        return None
    except Exception:
        return None


def is_token_expired(token, skew_seconds=300, expires_at_ms=None):
    """检查 token 是否过期（预留 5 分钟缓冲）。

    优先使用凭据文件里的明文 expiresAt 毫秒时间戳（新版客户端仍保留该字段），
    避免依赖 JWT payload 解码（字段被加密时无法解码）。
    """
    now = datetime.datetime.now()

    exp_ms = None
    try:
        if expires_at_ms:
            exp_ms = datetime.datetime.fromtimestamp(float(expires_at_ms) / 1000.0)
    except Exception:
        exp_ms = None

    if exp_ms is not None:
        if now >= (exp_ms - datetime.timedelta(seconds=skew_seconds)):
            log(f"token 已过期（expiresAt={exp_ms:%Y-%m-%d %H:%M:%S}）")
            return True
        log(f"token 有效，过期时间: {exp_ms:%Y-%m-%d %H:%M:%S}")
        return False

    exp = decode_jwt_exp(token)
    if not exp:
        log("无法判断 token 过期时间（无 expiresAt 且 JWT 不可解码），假设已过期", "WARN")
        return True
    if now >= (exp - datetime.timedelta(seconds=skew_seconds)):
        return True
    return False


# ============================================================
# API 调用
# ============================================================

def _safe_json(raw):
    """把响应文本安全解析为 dict，失败则返回 {'raw': text}"""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def make_request(url, headers, body=b"{}", retries=MAX_RETRIES, backoff=RETRY_BACKOFF):
    """发送 POST 请求，返回 (status_code, response_json)。

    重试策略：
      - 网络层错误（超时 / DNS / 连接失败等，status=-1）按指数退避重试
      - HTTP 5xx 服务端错误也重试
      - HTTP 4xx（含 401）不重试，直接返回
    领取接口本身幂等（重复领取服务端返回 10001），因此重试安全。
    """
    # 防御：请求头必须是字符串，否则底层会抛出难以理解的异常
    req_headers = {}
    for k, v in headers.items():
        if not isinstance(v, str):
            log(f"请求头 {k} 不是字符串（{type(v).__name__}），无法发送请求", "ERROR")
            return -1, {"error": f"header {k} is not a string"}
        req_headers[k] = v
    req_headers.setdefault("User-Agent", "WorkBuddyCheckin/1.0")

    last_err = ""
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with _OPENER.open(req, timeout=TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", "replace")
                return resp.status, _safe_json(raw)
        except urllib.error.HTTPError as e:
            raw = ""
            try:
                raw = e.read().decode("utf-8", "replace")
            except Exception:
                pass
            if 500 <= e.code < 600 and attempt < retries:
                last_err = f"HTTP {e.code}"
                time.sleep(backoff * attempt)
                continue
            return e.code, _safe_json(raw)
        except Exception as e:
            last_err = str(e)
            if attempt < retries:
                time.sleep(backoff * attempt)
                continue
            return -1, {"error": str(e)}

    return -1, {"error": f"重试 {retries} 次仍失败: {last_err}"}


def build_headers(session):
    """构造鉴权请求头"""
    token = require_plain_token(session["auth"]["accessToken"], "accessToken")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-User-Id": session["account"]["uid"],
    }
    # 企业账号额外头
    enterprise_id = session.get("account", {}).get("enterpriseId", "")
    if enterprise_id:
        headers["X-Enterprise-Id"] = enterprise_id
        headers["X-Tenant-Id"] = enterprise_id
    domain = session.get("auth", {}).get("domain", "")
    if domain:
        headers["X-Domain"] = domain
    return headers


def _persist_auth(session, auth_path):
    """只写回 auth token 字段，并先合并磁盘最新内容，降低并发覆盖风险。

    风险说明：客户端可能同时写同一 auth 文件。若整文件覆盖，会用旧快照
    覆盖客户端刚写入的其他字段。这里改为：重新读取磁盘最新内容 ->
    仅更新 token 相关字段 -> 原子替换，从而保留其他字段。
    """
    try:
        latest = {}
        try:
            with open(auth_path, "r", encoding="utf-8") as f:
                latest = json.load(f)
        except Exception:
            latest = session  # 读取失败则用内存中的 session
        if not isinstance(latest.get("auth"), dict):
            latest["auth"] = {}
        latest["auth"]["accessToken"] = session["auth"]["accessToken"]
        if "refreshToken" in session["auth"]:
            latest["auth"]["refreshToken"] = session["auth"]["refreshToken"]
        for key in ("expiresIn", "expiresAt", "refreshExpiresAt", "lastRefreshTime"):
            if key in session["auth"]:
                latest["auth"][key] = session["auth"][key]
        tmp = Path(str(auth_path) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(latest, f, ensure_ascii=False, indent=2)
        os.replace(tmp, auth_path)  # 原子替换，避免半写文件
        log("已将新 token 写回凭据文件")
    except Exception as e:
        log(f"写回凭据文件失败（不影响本次签到）: {e}", "WARN")


def refresh_token(session, auth_path):
    """使用 refreshToken 刷新 accessToken，返回新的 session 或 None"""
    log("token 已过期，尝试刷新...")
    access = require_plain_token(session["auth"].get("accessToken"), "accessToken")
    refresh_val = require_plain_token(session["auth"].get("refreshToken"), "refreshToken")

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {access}",
        "Content-Type": "application/json",
        "X-User-Id": session["account"]["uid"],
        "X-Refresh-Token": refresh_val,
        "X-Auth-Refresh-Source": "plugin",
    }

    status, resp = make_request(f"{ENDPOINT}{REFRESH_API}", headers)

    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        new_auth = resp["data"]
        log("token 刷新成功")
        session["auth"]["accessToken"] = new_auth.get("accessToken", session["auth"]["accessToken"])
        if "refreshToken" in new_auth:
            session["auth"]["refreshToken"] = new_auth["refreshToken"]
        for key in ("expiresIn", "expiresAt", "refreshExpiresAt", "lastRefreshTime"):
            if key in new_auth:
                session["auth"][key] = new_auth[key]
        _persist_auth(session, auth_path)
        return session
    else:
        log(f"token 刷新失败: HTTP {status}, {json.dumps(resp, ensure_ascii=False)[:300]}", "ERROR")
        log("请打开 WorkBuddy 客户端重新登录", "ERROR")
        return None


def get_checkin_status(session):
    """查询签到状态"""
    headers = build_headers(session)
    status, resp = make_request(f"{ENDPOINT}{STATUS_API}", headers)
    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        return resp["data"]
    log(f"查询签到状态失败: HTTP {status}, {json.dumps(resp, ensure_ascii=False)[:300]}", "WARN")
    return None


def claim_daily_checkin(session):
    """领取每日积分"""
    headers = build_headers(session)
    status, resp = make_request(f"{ENDPOINT}{CHECKIN_API}", headers)

    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        return "success", resp["data"]
    elif resp.get("code") == 10001:
        return "already", resp
    else:
        return "error", {"http_status": status, "response": resp}


# ============================================================
# 主流程
# ============================================================

def wait_for_network(timeout=NETWORK_WAIT_TIMEOUT, interval=NETWORK_PROBE_INTERVAL):
    """启动前探测 endpoint 是否可达，避免‘开机后网络/DNS 尚未就绪’导致领取失败。

    反复探测直到 DNS 可解析且 TCP 443 可连通，或超过 timeout 秒。
    返回 True 表示网络已就绪，False 表示超时仍不可达。
    """
    host = ENDPOINT.replace("https://", "").replace("http://", "").strip("/")
    deadline = time.time() + timeout
    attempt = 0
    while time.time() < deadline:
        attempt += 1
        try:
            socket.gethostbyname(host)  # DNS 解析
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with _SSL_CTX.wrap_socket(sock, server_hostname=host):
                    if attempt == 1:
                        log(f"网络就绪：已连通 {ENDPOINT}")
                    else:
                        log(f"网络就绪：第 {attempt} 次探测后连通 {ENDPOINT}")
                    return True
        except Exception as e:
            if attempt == 1:
                log(f"网络暂不可用（{e}），等待网络就绪后重试...", "WARN")
            time.sleep(interval)
    log(f"等待网络就绪超时（{timeout}秒）：{ENDPOINT} 仍不可达", "ERROR")
    return False


def rotate_log():
    """日志超过阈值时轮转，避免无限增长"""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > LOG_ROTATE_SIZE:
            old = LOG_FILE.with_suffix(".log.old")
            os.replace(LOG_FILE, old)
    except Exception:
        pass


def main():
    try:
        rotate_log()

        # 0. 等待网络就绪（应对开机后 DNS/网络尚未就绪的场景）
        if not wait_for_network():
            log("网络不可用，本次跳过领取", "ERROR")
            sys.exit(1)

        dry_run = "--dry-run" in sys.argv
        status_only = "--status" in sys.argv

        log("=" * 50)
        log("WorkBuddy 每日积分自动领取")
        if dry_run:
            log("【模拟运行模式】不会实际调用领取接口")
        if status_only:
            log("【仅查询状态模式】不会调用领取接口")
        log("=" * 50)

        # 1. 读取并校验凭据文件
        session, auth_path = load_session()
        validate_session(session)
        uid = session["account"]["uid"]
        nickname = session["account"].get("nickname", "未知")
        if is_encrypted_field(nickname):
            nickname = "(已加密)"
        log(f"当前用户: {nickname} (uid: {uid})")

        # 2. 检查 token 是否过期（优先用明文 expiresAt）
        token = session["auth"]["accessToken"]
        if is_token_expired(token, expires_at_ms=session["auth"].get("expiresAt")):
            session = refresh_token(session, auth_path)
            if session is None:
                log("无法刷新 token，退出", "ERROR")
                sys.exit(1)

        # 3. 查询签到状态
        log("正在查询签到状态...")
        checkin_data = get_checkin_status(session)

        if checkin_data:
            today_checked = checkin_data.get("today_checked_in", False)
            streak = checkin_data.get("streak_days", 0)
            daily_credit = checkin_data.get("daily_credit", 0)
            total = checkin_data.get("total_credits", 0)
            activity = checkin_data.get("activity_name", "")
            log(f"活动: {activity}")
            log(f"今日已签到: {'是' if today_checked else '否'}")
            log(f"连续签到: {streak} 天")
            log(f"每日积分: {daily_credit}")
            log(f"累计积分: {total}")

            if today_checked:
                log("今天已经签到过了，无需重复领取")
                log(f"✅ 完成（今日已签到，连续 {streak} 天，累计 {total} 积分）")
            elif status_only:
                log("今日未签到（仅查询模式，不领取）")
            elif dry_run:
                log(f"【模拟】今日未签到，将调用领取接口获取 {daily_credit} 积分")
            else:
                # 4. 领取积分
                log(f"今日未签到，正在领取 {daily_credit} 积分...")
                time.sleep(1)  # 短暂延迟，避免请求过快
                result, data = claim_daily_checkin(session)

                if result == "success":
                    credit = data.get("today_credit", data.get("credit", daily_credit))
                    new_streak = data.get("streak_days", streak)
                    new_total = data.get("total_credits", total)
                    bonus = data.get("streak_bonus_credit", 0)
                    log(f"🎉 领取成功！获得 {credit} 积分" + (f"（含连签奖励 {bonus}）" if bonus else ""))
                    log(f"连续签到: {new_streak} 天，累计: {new_total} 积分")
                elif result == "already":
                    log("今天已签到，无需重复领取")
                else:
                    log(f"领取失败: {json.dumps(data, ensure_ascii=False)[:300]}", "ERROR")
        else:
            log("无法获取签到状态，尝试直接领取...")
            if not dry_run and not status_only:
                result, data = claim_daily_checkin(session)
                if result == "success":
                    log(f"🎉 领取成功！{json.dumps(data, ensure_ascii=False)[:300]}")
                elif result == "already":
                    log("今天已签到，无需重复领取")
                else:
                    log(f"领取失败: {json.dumps(data, ensure_ascii=False)[:300]}", "ERROR")

        log("=" * 50)
    except SystemExit:
        raise
    except Exception as e:
        log(f"未预期的错误: {e}", "ERROR")
        try:
            log(traceback.format_exc(), "ERROR")
        except Exception:
            pass
        sys.exit(1)


if __name__ == "__main__":
    main()
