#!/usr/bin/env python3
"""
WorkBuddy 每日积分自动领取脚本

原理：
  通过逆向 WorkBuddy 桌面客户端 (Electron app.asar)，找到签到领积分的 API：
    1. 查询签到状态: POST https://copilot.tencent.com/v2/billing/meter/checkin-activity-status
    2. 领取每日积分: POST https://copilot.tencent.com/v2/billing/meter/daily-checkin
    3. 刷新 token:   POST https://copilot.tencent.com/v2/plugin/auth/token/refresh

  认证方式:
    - Authorization: Bearer <accessToken>  (JWT)
    - X-User-Id: <uid>
    - X-Domain: <domain>

  凭据解析顺序（重要，客户端两次加固后的应对）:
    客户端曾两次破坏第三方读取凭据的方式：
      (1) 约 2026-09-26：auth 文件敏感字段改为 AES-GCM 信封
          {"$wbEncrypted":1,"envelope":"..."}，无法解密；
      (2) 约 2026-10-24：同账号的明文凭据文件（coding-copilot）服务端会话失效，
          之后一直 401。
    因此本脚本按下列顺序逐个探测，取第一个真正可用的 token：
      1) 本地缓存 wb_token_cache.json
      2) 明文凭据文件 Tencent-Cloud.coding-copilot.info
      3) 从 WorkBuddy 客户端进程内存中提取（客户端持有解密后的明文 JWT）
    找到可用 token 后写入缓存，供后续运行直接复用，减少内存扫描。

  脚本逻辑:
    1. 解析可用凭据（见上）
    2. 查询签到状态
    3. 今日未签到则领取（接口幂等）
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
import re
import subprocess
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

# 首选：同账号的明文凭据文件（CodeBuddy 插件写入，可能已失效，仅作候选）
PLAIN_AUTH_FILE = os.path.join(_AUTH_DIR, "Tencent-Cloud.coding-copilot.info")

# 次选：WorkBuddy 桌面客户端凭据（新版字段加密，仅取 account 元信息）
AUTH_FILE = os.path.join(_AUTH_DIR, "workbuddy-desktop.info")

# 新版客户端字段加密信封的标记
ENCRYPTED_MARKER = "$wbEncrypted"

# API 配置
ENDPOINT = "https://copilot.tencent.com"
STATUS_API = "/v2/billing/meter/checkin-activity-status"
CHECKIN_API = "/v2/billing/meter/daily-checkin"
REFRESH_API = "/v2/plugin/auth/token/refresh"

DEFAULT_DOMAIN = "www.codebuddy.cn"

# 日志与缓存
SCRIPT_DIR = Path(__file__).parent.resolve()
LOG_FILE = SCRIPT_DIR / "checkin.log"
TOKEN_CACHE_FILE = SCRIPT_DIR / "wb_token_cache.json"

# 客户端进程名（内存提取用）
CLIENT_EXE = "WorkBuddy.exe"

# 客户端可执行文件候选路径（缓存失效且客户端未运行时，尝试自动拉起）
CLIENT_EXE_CANDIDATES = [
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Programs", "WorkBuddy", "WorkBuddy.exe"),
    os.path.join(os.environ.get("PROGRAMFILES", ""), "WorkBuddy", "WorkBuddy.exe"),
    r"D:\Users\刘宝杰\AppData\Local\Programs\WorkBuddy\WorkBuddy.exe",
]

# 缓存 token 剩余有效期低于该天数时，优先从客户端内存换新 token（让缓存持续向前滚动）
CACHE_REFRESH_MARGIN_DAYS = 10

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

# 内存扫描总量上限（MB），避免扫描过久
MEMORY_SCAN_MAX_MB = 1500

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
# 基础工具
# ============================================================

def is_encrypted_field(value):
    """判断某个字段是否被客户端加密（{"$wbEncrypted":1,"envelope":"..."}）"""
    return isinstance(value, dict) and value.get(ENCRYPTED_MARKER) == 1


def decode_jwt_exp(token):
    """解码 JWT token，返回过期时间 (datetime)；非字符串/无法解析返回 None"""
    try:
        if not isinstance(token, str):
            return None
        parts = token.split(".")
        if len(parts) < 2:
            return None
        seg = parts[1]
        payload = seg + "=" * (-len(seg) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        exp = data.get("exp")
        if exp:
            return datetime.datetime.fromtimestamp(exp)
        return None
    except Exception:
        return None


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


def read_auth_files():
    """读取所有候选凭据文件，返回 [(path, session_dict), ...]"""
    out = []
    for raw_path in candidate_auth_paths():
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                session = json.load(f)
            if isinstance(session, dict):
                out.append((path, session))
        except Exception as e:
            log(f"读取凭据文件失败（{path}）: {e}", "WARN")
    return out


def read_account_meta():
    """从凭据文件读取账号元信息（uid / nickname / domain）。

    即使 token 字段被加密，account 段与 domain 仍是明文，足够构造请求头。
    """
    account, domain = {}, DEFAULT_DOMAIN
    for _path, session in read_auth_files():
        acct = session.get("account") or {}
        auth = session.get("auth") or {}
        if not account and isinstance(acct.get("uid"), str) and acct["uid"]:
            account = acct
            if isinstance(auth.get("domain"), str) and auth["domain"]:
                domain = auth["domain"]
    return account, domain


# ============================================================
# token 缓存
# ============================================================

def load_token_cache():
    """读取本地 token 缓存，返回 dict 或 None"""
    try:
        if not TOKEN_CACHE_FILE.exists():
            return None
        with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("accessToken"), str) and data["accessToken"]:
            return data
    except Exception as e:
        log(f"读取 token 缓存失败（忽略）: {e}", "WARN")
    return None


def save_token_cache(access_token, uid, source):
    """写入 token 缓存（仅本用户可读，且已加入 .gitignore）"""
    try:
        exp = decode_jwt_exp(access_token)
        payload = {
            "accessToken": access_token,
            "uid": uid,
            "source": source,
            "savedAt": int(time.time() * 1000),
            "expiresAt": int(exp.timestamp() * 1000) if exp else None,
        }
        tmp = Path(str(TOKEN_CACHE_FILE) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        os.replace(tmp, TOKEN_CACHE_FILE)
        try:
            os.chmod(TOKEN_CACHE_FILE, 0o600)
        except Exception:
            pass
        if exp:
            log(f"已缓存可用 token（来源: {source}，过期: {exp:%Y-%m-%d %H:%M:%S}）")
        else:
            log(f"已缓存可用 token（来源: {source}）")
    except Exception as e:
        log(f"写入 token 缓存失败（不影响本次签到）: {e}", "WARN")


# ============================================================
# 从客户端进程内存提取 token（应对凭据文件字段加密）
# ============================================================

_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")


def enum_processes_by_name(exe_name):
    """返回指定映像名的进程 PID 列表（Windows / ctypes）"""
    if os.name != "nt":
        return []
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x00000002
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == INVALID_HANDLE_VALUE:
        return []

    pids = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile and entry.szExeFile.lower() == exe_name.lower():
                pids.append(int(entry.th32ProcessID))
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return pids


def _read_process_jwts(pid, max_bytes):
    """读取单个进程内存中的 JWT 候选，返回 set(str)"""
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_GUARD = 0x100
    PAGE_NOACCESS = 0x01
    MAX_REGION = 64 * 1024 * 1024

    class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_ulonglong),
            ("AllocationBase", ctypes.c_ulonglong),
            ("AllocationProtect", wintypes.DWORD),
            ("__alignment1", wintypes.DWORD),
            ("RegionSize", ctypes.c_ulonglong),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("__alignment2", wintypes.DWORD),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = wintypes.HANDLE
    k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]

    handle = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return set()

    found, total, address = set(), 0, 0
    mbi = MEMORY_BASIC_INFORMATION64()
    try:
        while k32.VirtualQueryEx(handle, ctypes.c_void_p(address),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi)):
            base, size, state, protect = mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect
            if not size:
                break
            readable = (
                state == MEM_COMMIT
                and not (protect & PAGE_GUARD)
                and protect != PAGE_NOACCESS
                and 0 < size <= MAX_REGION
            )
            if readable:
                buf = ctypes.create_string_buffer(size)
                read = ctypes.c_size_t(0)
                if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size,
                                         ctypes.byref(read)) and read.value:
                    data = buf.raw[:read.value]
                    for m in _JWT_RE.finditer(data):
                        found.add(m.group().decode("ascii", "ignore"))
                    total += read.value
            address = base + size
            if total >= max_bytes:
                break
    finally:
        k32.CloseHandle(handle)
    return found


def scan_client_memory_for_tokens(exe_name=CLIENT_EXE, max_total_mb=MEMORY_SCAN_MAX_MB):
    """扫描客户端进程内存，返回按 exp 降序排列的 JWT 候选列表"""
    if os.name != "nt":
        return []
    pids = enum_processes_by_name(exe_name)
    if not pids:
        log(f"未发现 {exe_name} 进程，无法从内存提取 token", "WARN")
        return []
    log(f"扫描 {len(pids)} 个 {exe_name} 进程内存以提取 token（可能耗时十几秒）...")
    per_proc = max_total_mb * 1024 * 1024 // max(1, len(pids))
    tokens = set()
    for pid in pids:
        try:
            tokens |= _read_process_jwts(pid, per_proc)
        except Exception as e:
            log(f"扫描进程 {pid} 失败: {e}", "WARN")

    scored = []
    for tok in tokens:
        exp = decode_jwt_exp(tok)
        if exp:
            scored.append((exp, tok))
    scored.sort(key=lambda x: x[0], reverse=True)
    log(f"内存中提取到 {len(tokens)} 个 JWT 片段，其中 {len(scored)} 个可解析过期时间")
    return [tok for _exp, tok in scored]


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


def build_headers(token, uid, domain=DEFAULT_DOMAIN):
    """构造鉴权请求头"""
    return {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "X-User-Id": uid,
        "X-Domain": domain,
    }


def probe_token(token, uid, domain):
    """用状态接口验证 token 是否可用；可用返回 data，否则 None"""
    status, resp = make_request(
        f"{ENDPOINT}{STATUS_API}", build_headers(token, uid, domain), retries=1
    )
    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        return resp["data"]
    return None


def claim_daily_checkin(token, uid, domain):
    """领取每日积分"""
    status, resp = make_request(f"{ENDPOINT}{CHECKIN_API}", build_headers(token, uid, domain))
    if status == 200 and resp.get("code") == 0 and resp.get("data"):
        return "success", resp["data"]
    if resp.get("code") == 10001:
        return "already", resp
    return "error", {"http_status": status, "response": resp}


# ============================================================
# 凭据解析：找出一个真正可用的 token
# ============================================================

def cache_remaining_days(cache):
    """返回缓存 token 剩余有效天数；无法判断返回 None"""
    if not cache:
        return None
    exp = cache.get("expiresAt")
    if not exp:
        return None
    try:
        return (float(exp) / 1000.0 - time.time()) / 86400.0
    except Exception:
        return None


def _attempt(tokens, uid, domain):
    """依次实测 token，命中返回 (token, status_data, source)，否则 None"""
    for token, source in tokens:
        data = probe_token(token, uid, domain)
        if data:
            log(f"token 可用（来源: {source}）")
            save_token_cache(token, uid, source)
            return token, data, source
        log(f"token 不可用（来源: {source}），换下一个", "WARN")
    return None


def _attempt_from_memory(uid, domain):
    """从客户端进程内存提取并实测 token"""
    tokens = scan_client_memory_for_tokens()
    if not tokens:
        return None
    return _attempt([(t, "客户端进程内存") for t in tokens], uid, domain)


def try_launch_client(wait_seconds=60):
    """客户端未运行时尝试拉起，以便从内存提取 token。

    仅在所有凭据都失效时调用；可用 --no-launch 关闭该行为。
    """
    if "--no-launch" in sys.argv:
        log("已指定 --no-launch，跳过自动拉起客户端")
        return False
    if enum_processes_by_name(CLIENT_EXE):
        return True
    exe = next((p for p in CLIENT_EXE_CANDIDATES if p and os.path.exists(p)), None)
    if not exe:
        log("未找到 WorkBuddy.exe，无法自动拉起客户端", "WARN")
        return False
    try:
        log(f"WorkBuddy 客户端未运行，尝试自动启动以提取 token：{exe}")
        subprocess.Popen([exe], close_fds=True)
    except Exception as e:
        log(f"启动客户端失败: {e}", "WARN")
        return False

    deadline = time.time() + wait_seconds
    while time.time() < deadline:
        time.sleep(5)
        if enum_processes_by_name(CLIENT_EXE):
            log("客户端已启动，等待其初始化后重新提取...")
            time.sleep(8)   # 给客户端留出加载与刷新 token 的时间
            return True
    log("等待客户端启动超时", "WARN")
    return False


def resolve_credentials(force_refresh=False):
    """返回 (token, uid, domain, status_data, source)。

    解析顺序（每个候选都用状态接口实测，取第一个真正可用的）：
      - 缓存剩余不足 CACHE_REFRESH_MARGIN_DAYS 天（或指定 --refresh）时，
        先从客户端内存换新 token，让缓存不断向前滚动；
      - 否则先试本地缓存、再试明文凭据文件；
      - 都失败则从客户端进程内存提取；
      - 客户端未运行则尝试自动拉起后重试。
    """
    if "--refresh" in sys.argv:
        force_refresh = True

    account, domain = read_account_meta()
    uid = account.get("uid")
    if not uid:
        log("未能从任何凭据文件读到 uid，请先打开 WorkBuddy 客户端登录", "ERROR")
        sys.exit(1)

    nickname = account.get("nickname", "未知")
    if is_encrypted_field(nickname):
        nickname = "(已加密)"
    log(f"当前用户: {nickname} (uid: {uid})")

    cache = load_token_cache()
    remaining = cache_remaining_days(cache)

    cache_tokens = []
    if cache and cache.get("uid") == uid and isinstance(cache.get("accessToken"), str):
        cache_tokens.append((cache["accessToken"], "本地 token 缓存"))

    file_tokens = []
    seen = {t for t, _ in cache_tokens}
    for path, session in read_auth_files():
        tok = (session.get("auth") or {}).get("accessToken")
        if isinstance(tok, str) and tok and tok not in seen:
            seen.add(tok)
            file_tokens.append((tok, f"凭据文件 {path.name}"))

    if remaining is not None:
        log(f"缓存 token 剩余 {remaining:.1f} 天")

    near_expiry = remaining is not None and remaining < CACHE_REFRESH_MARGIN_DAYS
    if force_refresh or near_expiry:
        reason = "已指定 --refresh" if force_refresh else f"缓存仅剩 {remaining:.1f} 天"
        log(f"{reason}，尝试从客户端内存获取更新的 token...")
        hit = _attempt_from_memory(uid, domain)
        if hit:
            token, data, source = hit
            return token, uid, domain, data, source

    hit = _attempt(cache_tokens + file_tokens, uid, domain)
    if hit:
        token, data, source = hit
        return token, uid, domain, data, source

    if not (force_refresh or near_expiry):
        log("缓存与凭据文件均无效，尝试从客户端进程内存提取...")
        hit = _attempt_from_memory(uid, domain)
        if hit:
            token, data, source = hit
            return token, uid, domain, data, source

    # 最后一招：拉起客户端后再试一次
    if try_launch_client():
        hit = _attempt_from_memory(uid, domain)
        if hit:
            token, data, source = hit
            return token, uid, domain, data, source

    log("=" * 50, "ERROR")
    log("无法获得可用的 accessToken。可能原因：", "ERROR")
    log("  1) WorkBuddy 客户端未运行或启动失败（内存提取依赖客户端）", "ERROR")
    log("  2) 客户端登录已失效，需要重新登录", "ERROR")
    log("请手动打开 WorkBuddy 客户端并确认已登录，然后重试。", "ERROR")
    sys.exit(1)


# ============================================================
# 主流程
# ============================================================

def wait_for_network(timeout=NETWORK_WAIT_TIMEOUT, interval=NETWORK_PROBE_INTERVAL):
    """启动前探测 endpoint 是否可达，避免‘开机后网络/DNS 尚未就绪’导致领取失败。"""
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

        # 1. 解析可用凭据（内部已用状态接口实测）
        token, uid, domain, checkin_data, _source = resolve_credentials()

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
            # 2. 领取积分
            log(f"今日未签到，正在领取 {daily_credit} 积分...")
            time.sleep(1)  # 短暂延迟，避免请求过快
            result, data = claim_daily_checkin(token, uid, domain)

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
