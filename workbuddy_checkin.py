#!/usr/bin/env python3
"""
WorkBuddy 每日积分自动领取脚本

原理：
  通过逆向 WorkBuddy 桌面客户端 (Electron app.asar)，找到签到领积分的 API：
    1. 查询签到状态: POST https://copilot.tencent.com/v2/billing/meter/checkin-activity-status
    2. 领取每日积分: POST https://copilot.tencent.com/v2/billing/meter/daily-checkin
    3. 刷新 token:   POST https://copilot.tencent.com/v2/auth/token/refresh

  认证方式:
    - Authorization: Bearer <accessToken>  (JWT, 60天有效期)
    - X-User-Id: <uid>
    - token 存储在本地 auth 文件中，WorkBuddy 客户端运行时会自动刷新

  脚本逻辑:
    1. 从本地 auth 文件读取 accessToken（每次运行都读最新的）
    2. 如果 token 已过期，用 refreshToken 刷新
    3. 查询签到状态，如果今天未签到则自动领取
    4. 记录日志

用法:
    python workbuddy_checkin.py            # 执行一次签到
    python workbuddy_checkin.py --status   # 仅查看状态，不领取
    python workbuddy_checkin.py --dry-run  # 模拟运行，不实际调用领取接口

定时任务:
    配合 Windows 任务计划程序每天自动执行（见脚本末尾说明或 README）
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

# auth 文件路径（WorkBuddy 桌面客户端存储登录凭证的位置）
AUTH_FILE = os.path.join(
    os.environ.get("LOCALAPPDATA", ""),
    "CodeBuddyExtension", "Data", "Public", "auth", "workbuddy-desktop.info"
)

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

def load_session():
    """从本地 auth 文件读取登录会话，返回 (session, auth_path)"""
    auth_path = Path(AUTH_FILE)
    if not auth_path.exists():
        # 尝试备用路径（用户名可能不同）
        home = Path.home()
        alt = home / "AppData" / "Local" / "CodeBuddyExtension" / "Data" / "Public" / "auth" / "workbuddy-desktop.info"
        if alt.exists():
            auth_path = alt
        else:
            log(f"auth 文件不存在: {AUTH_FILE}", "ERROR")
            log("请确保 WorkBuddy 桌面客户端已安装并登录", "ERROR")
            sys.exit(1)

    try:
        with open(auth_path, "r", encoding="utf-8") as f:
            session = json.load(f)
    except Exception as e:
        log(f"读取 auth 文件失败: {e}", "ERROR")
        sys.exit(1)
    return session, auth_path


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
    """解码 JWT token，返回过期时间 (datetime)"""
    try:
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


def is_token_expired(token, skew_seconds=300):
    """检查 token 是否过期（预留 5 分钟缓冲）"""
    exp = decode_jwt_exp(token)
    if not exp:
        log("无法解码 token 过期时间，假设已过期", "WARN")
        return True
    now = datetime.datetime.now()
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
    req_headers = dict(headers)
    req_headers.setdefault("User-Agent", "WorkBuddyCheckin/1.0")

    last_err = ""
    for attempt in range(1, retries + 1):
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, data=body, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=TIMEOUT) as resp:
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
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {session['auth']['accessToken']}",
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

    风险说明：WorkBuddy 客户端可能同时写同一 auth 文件。若整文件覆盖，
    会用旧快照覆盖客户端刚写入的其他字段。这里改为：重新读取磁盘最新
    内容 -> 仅更新 token 相关字段 -> 原子替换，从而保留其他字段。
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
        if "expiresIn" in session["auth"]:
            latest["auth"]["expiresIn"] = session["auth"]["expiresIn"]
        tmp = Path(str(auth_path) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(latest, f, ensure_ascii=False, indent=2)
        os.replace(tmp, auth_path)  # 原子替换，避免半写文件
        log("已将新 token 写回 auth 文件")
    except Exception as e:
        log(f"写回 auth 文件失败（不影响本次签到）: {e}", "WARN")


def refresh_token(session, auth_path):
    """使用 refreshToken 刷新 accessToken，返回新的 session 或 None"""
    log("token 已过期，尝试刷新...")
    refresh_token_val = session["auth"].get("refreshToken", "")
    if not refresh_token_val:
        log("无 refreshToken，请打开 WorkBuddy 客户端重新登录", "ERROR")
        return None

    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {session['auth']['accessToken']}",
        "Content-Type": "application/json",
        "X-User-Id": session["account"]["uid"],
        "X-Refresh-Token": refresh_token_val,
        "X-Auth-Refresh-Source": "plugin",
    }

    status, resp = make_request(f"{ENDPOINT}{REFRESH_API}", headers)

    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        new_auth = resp["data"]
        log("token 刷新成功")
        session["auth"]["accessToken"] = new_auth.get("accessToken", session["auth"]["accessToken"])
        if "refreshToken" in new_auth:
            session["auth"]["refreshToken"] = new_auth["refreshToken"]
        if "expiresIn" in new_auth:
            session["auth"]["expiresIn"] = new_auth["expiresIn"]
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
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
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

        # 1. 读取并校验 auth 文件
        session, auth_path = load_session()
        validate_session(session)
        uid = session["account"]["uid"]
        nickname = session["account"].get("nickname", "未知")
        log(f"当前用户: {nickname} (uid: {uid})")

        # 2. 检查 token 是否过期
        token = session["auth"]["accessToken"]
        exp = decode_jwt_exp(token)
        if exp:
            log(f"token 过期时间: {exp.strftime('%Y-%m-%d %H:%M:%S')}")

        if is_token_expired(token):
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
                    credit = data.get("today_credit", daily_credit)
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
