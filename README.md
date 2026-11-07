# WorkBuddy 每日积分自动领取

## 这是什么

一个自动领取 WorkBuddy（腾讯云 AI 代码助手）每日签到积分的脚本。

通过逆向分析 WorkBuddy 桌面客户端（Electron 应用），找到签到领积分的 API 接口，
直接调用后端 API 实现自动签到，无需手动打开客户端点击领取。

## 工作原理

```
┌─────────────────────────────────────────────────────────┐
│  WorkBuddy 桌面客户端 (Electron)                         │
│  ├── app.asar (应用代码)                                 │
│  │   └── 签到 API:                                        │
│  │       POST /v2/billing/meter/checkin-activity-status  │ ← 查询签到状态
│  │       POST /v2/billing/meter/daily-checkin            │ ← 领取每日积分
│  │       POST /v2/auth/token/refresh                     │ ← 刷新 token
│  │                                                        │
│  ├── auth 文件 (登录凭证)                                 │
│  │   %LOCALAPPDATA%/CodeBuddyExtension/Data/Public/auth/ │
│  │   └── workbuddy-desktop.info  (含 accessToken)        │
│  │                                                        │
│  └── 后端: https://copilot.tencent.com                   │
└─────────────────────────────────────────────────────────┘
          ↑ 脚本读取 auth 文件获取 token，直接调用 API
```

### 认证机制
- **accessToken**: JWT 格式，存在本地 auth 文件中
- **refreshToken**: 用于 token 过期后刷新
- **请求头**: `Authorization: Bearer <token>` + `X-User-Id: <uid>`
- WorkBuddy 客户端运行时会自动刷新 token 并写回文件

> **凭据来源（客户端两次加固后的应对）**
>
> 客户端先后两次破坏了第三方读取凭据的方式：
>
> 1. 约 2026-09-26：把 `workbuddy-desktop.info` 的敏感字段改成 AES-GCM 信封
>    `{"$wbEncrypted":1,"envelope":"..."}`，无法解密；
> 2. 约 2026-10-24：同账号的明文凭据文件 `Tencent-Cloud.coding-copilot.info`
>    的**服务端会话失效**，此后一直返回 `HTTP 401`（JWT 里写着远期过期时间，
>    但服务端已不认——自报的 `exp` 不等于服务端会话有效期）。
>
> 因此脚本按下列顺序逐个**实测**（用状态接口验证），取第一个真正可用的 token：
>
> | 顺序 | 来源 | 说明 |
> |---|---|---|
> | 1 | `wb_token_cache.json` | 上次成功获取的 token 缓存（命中时秒回） |
> | 2 | `Tencent-Cloud.coding-copilot.info` | 明文凭据文件，可能已失效 |
> | 3 | WorkBuddy 客户端进程内存 | 客户端持有解密后的明文 JWT，扫描进程内存提取 |
>
> 找到可用 token 后写入本地缓存（已加入 `.gitignore`，权限 600）。
> **第 3 步要求 WorkBuddy 客户端正在运行**；缓存有效期约 2 个月，
> 期间只要有任意一次运行成功，就会自动续上新 token。

### 脚本逻辑
1. 从本地 auth 文件读取最新的 accessToken（每次运行都读，确保拿到最新 token）
2. 检查 token 是否过期，过期则用 refreshToken 自动刷新
3. 查询签到状态，如果今天未签到则自动领取
4. 记录运行日志到 `checkin.log`

## 文件说明

| 文件 | 说明 |
|------|------|
| `workbuddy_checkin.py` | 主脚本，执行签到逻辑（凭据解析 + 状态查询 + 领取） |
| `run_checkin.bat` | Windows 批处理入口，供任务计划程序调用 |
| `setup_event_trigger.ps1` | 一键注册计划任务（联网即领 + 每日 5 次兜底） |
| `checkin.log` | 运行日志（自动生成，已 gitignore） |
| `wb_token_cache.json` | token 缓存（自动生成，**已 gitignore，切勿提交**） |

## 使用方法

### 手动执行
```bash
# 正常签到（查询状态 + 自动领取）
python workbuddy_checkin.py

# 仅查看签到状态，不领取
python workbuddy_checkin.py --status

# 模拟运行（不实际调用领取接口）
python workbuddy_checkin.py --dry-run
```

### 设置每天自动执行（Windows 任务计划程序）

#### 方法一：用脚本一键创建（推荐，含联网即领 + 每日5次兜底）

最简单：以管理员身份打开 PowerShell，进入本仓库目录，运行自带脚本即可（自动用当前目录定位入口，无需改路径）：

```powershell
& ".\setup_event_trigger.ps1"
```

它会创建一个任务：① 网络一连上就领（EventID 10000）② 每天 09/12/15/18/21 点各兜底一次。脚本幂等，重复领不会出错。

> 若只想手动创建「每天 09:00 一次」的简单任务，在仓库目录内执行：
> ```powershell
> $scriptDir = (Get-Location).Path   # 当前仓库目录
> $action = New-ScheduledTaskAction -Execute "$scriptDir\run_checkin.bat" -WorkingDirectory $scriptDir
> $trigger = New-ScheduledTaskTrigger -Daily -At "09:00"
> $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopIfGoingOnBatteries -AllowStartIfOnBatteries
> Register-ScheduledTask -TaskName "WorkBuddy每日签到" -Action $action -Trigger $trigger -Settings $settings -Description "自动领取 WorkBuddy 每日签到积分"
> ```

> 把时间 `09:00` 改成你想要的时间。建议设在白天，确保 WorkBuddy 客户端可能已刷新过 token。

#### 方法二：图形界面手动创建

1. 按 `Win + R`，输入 `taskschd.msc`，打开任务计划程序
2. 右侧点击「创建基本任务」
3. 名称填 `WorkBuddy每日签到`
4. 触发器选「每天」，设置时间（如 09:00）
5. 操作选「启动程序」
6. 程序路径填：`<本仓库目录>\run_checkin.bat`
7. 起始位置填：`<本仓库目录>`
8. 勾选「不管用户是否登录都要运行」(可选)
9. 完成

### 管理 / 删除定时任务
```powershell
# 查看任务
Get-ScheduledTask -TaskName "WorkBuddy每日签到"

# 删除任务
Unregister-ScheduledTask -TaskName "WorkBuddy每日签到" -Confirm:$false
```

## 注意事项

1. **需要先登录**: 首次使用前，必须打开 WorkBuddy 桌面客户端并登录账号，
   这样才会生成 auth 文件。脚本从该文件读取登录凭证。
   若缓存过期且凭据文件失效，脚本会从**客户端进程内存**提取 token，
   因此该模式下**要求 WorkBuddy 客户端正在运行**；都取不到时会提示你先打开客户端登录。

2. **Token 过期**: accessToken 有效期 60 天。脚本会自动用 refreshToken 刷新。
   但 refreshToken 有效期 90 天，如果超过 90 天没打开 WorkBuddy 客户端，
   需要重新登录。建议偶尔打开一下客户端保持登录状态。

3. **签到规则**: 每天可领 100 积分，连续签到有额外奖励。每天只能领一次。

4. **隐私安全**: 脚本只读取本地 auth 文件和调用官方 API，不会上传任何信息。
   auth 文件包含你的登录 token，请勿泄露。

5. **API 可能变更**: WorkBuddy 更新后 API 可能变化，届时需要重新分析。
