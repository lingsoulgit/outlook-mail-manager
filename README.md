# Outlook Mail Manager

面向 Outlook/Hotmail/Gmail OAuth2 账号的自托管管理工具，提供账号导入、Graph/IMAP 取件、令牌状态、代理配置、邮件查看和签名自动更新。

## 主要功能

- Microsoft Graph API 与 IMAP XOAUTH2 双模式取件。
- Gmail IMAP OAuth2 取件。
- 全局 HTTP/SOCKS 代理及账号专用代理；账号代理优先。
- 批量导入、筛选、健康检测、新邮件预警、令牌轮换和稳定 UID 去重。
- 服务端会话、CSRF、登录限速、scrypt 密码哈希和凭据加密。
- 邮件 HTML 清洗、沙箱 iframe、CSP 和远程内容阻断。
- 登录后检查 GitHub Release；有新版本时可在页面一键更新。

## 快速运行

需要 Python 3.11 或更高版本。未设置环境变量时，首次登录用户名为 `admin`、密码为 `admin123`；部署完成后应立即在设置页修改密码。

### Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
pip install --require-hashes -r requirements.lock

# 可选：覆盖新数据库的默认初始密码
export OMM_ADMIN_PASSWORD='replace-with-a-long-random-password'
export OMM_SECRET_KEY_FILE="$PWD/secret.key"
export OMM_SECURE_COOKIE=0  # 仅限本机 HTTP 调试
python app.py
```

### Windows PowerShell

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --require-hashes -r requirements.lock

# 可选：覆盖新数据库的默认初始密码
$env:OMM_ADMIN_PASSWORD = 'replace-with-a-long-random-password'
$env:OMM_SECRET_KEY_FILE = "$PWD\secret.key"
$env:OMM_SECURE_COOKIE = '0'  # 仅限本机 HTTP 调试
python app.py
```

本机访问 `http://127.0.0.1:8899`，用户名为 `admin`。

`OMM_ADMIN_PASSWORD` 仅在新建数据库时用于初始化。未设置时使用兼容默认值 `admin123`；数据库已有管理员哈希后，环境变量不会覆盖现有密码。页面修改的新密码至少 8 位，且必须同时包含英文字母和数字。

## 导入格式

导入页支持“使用 Microsoft 登录”：填写一次 Entra 应用的 `client_id`，按页面提示完成设备码授权后，服务会通过 Microsoft Graph 识别邮箱，并自动加密保存 `refresh_token`。同一个 `client_id` 可用于添加多个账号。

Microsoft 应用必须：

- 开启“允许公共客户端流”；
- 配置 Microsoft Graph 委托权限 `Mail.Read` 和 `User.Read`；
- 允许请求 `offline_access`，以便微软签发 refresh token。

设备码、access token 和 refresh token 不会返回浏览器；未完成的授权状态仅短暂保存在服务端内存中。

也可以继续手工批量导入。每行一个账号，使用四个连字符分隔：

```text
邮箱----第二字段----client_id----refresh_token
```

- Microsoft：第二字段已不保存，可留空；Graph 模式要求 refresh token 具有 `Mail.Read` 权限。
- Gmail：第二字段填写 OAuth2 应用的 `client_secret`。
- 邮箱地址会转为小写；重复导入只更新凭据，保留账号 ID、状态和历史邮件。

## 代理

设置页中的全局代理同时用于：

- OAuth2 token 刷新；
- Graph API 请求；
- IMAP 连接；
- GitHub Release 检查、更新包下载和更新依赖安装。

代理设置提供三种模式：

- **不使用代理**：所有请求明确直连；
- **系统代理**：HTTP 请求跟随操作系统及 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`，IMAP 使用系统提供的静态 HTTP/SOCKS 代理；
- **手动设置**：使用页面填写的代理地址。

手动模式支持 `http://`、`socks4://`、`socks5://` 和 `socks5h://`。账号页面配置的专用代理优先于全局代理。旧版本尚未保存代理模式时，会继续兼容已保存的地址及 `OMM_PROXY`；一旦在页面选择并保存模式，便以页面选择为准。

## 凭据和备份

账号密码、client secret、refresh token 及代理凭据使用 Fernet 加密后写入 SQLite。密钥来源按优先级为：

1. `OMM_SECRET_KEY`：必须是 32 个随机字节的 URL-safe Base64 Fernet key；
2. `OMM_SECRET_KEY_FILE`：推荐用于部署；
3. 数据库同目录的 `.omm_secret.key`。

必须把数据库和密钥作为同一个备份集。只恢复 `data.db` 而没有原密钥时，服务会拒绝启动，避免静默生成新密钥造成凭据混用。

```bash
sudo systemctl stop outlook-mail-manager
sudo tar -C /var/lib/outlook-mail-manager -czf omm-backup.tgz data.db secret.key
sudo systemctl start outlook-mail-manager
```

导出功能会返回 refresh token 明文，因此要求再次输入当前管理员密码，并设置 `Cache-Control: no-store`。

## 生产部署

不要直接把 Uvicorn 暴露到公网。应用默认启用 `Secure` Cookie，应由 Nginx/Caddy 提供 HTTPS，并只让应用监听回环地址。

```bash
sudo useradd --system --home /var/lib/outlook-mail-manager \
  --shell /usr/sbin/nologin outlook-mail-manager
sudo install -d -m 0700 -o outlook-mail-manager -g outlook-mail-manager \
  /opt/outlook-mail-manager /var/lib/outlook-mail-manager
sudo cp -a . /opt/outlook-mail-manager/
sudo chown -R outlook-mail-manager:outlook-mail-manager /opt/outlook-mail-manager

sudo -u outlook-mail-manager python3 -m venv /opt/outlook-mail-manager/venv
sudo -u outlook-mail-manager /opt/outlook-mail-manager/venv/bin/pip \
  install --require-hashes -r /opt/outlook-mail-manager/requirements.lock

sudo install -m 0644 outlook-mail-manager.service /etc/systemd/system/
sudo install -d -m 0750 /etc/outlook-mail-manager
sudo sh -c 'umask 077; cat > /etc/outlook-mail-manager/env <<EOF
OMM_ADMIN_PASSWORD=replace-with-a-long-random-password
EOF'
sudo systemctl daemon-reload
sudo systemctl enable --now outlook-mail-manager
```

Nginx 示例：

```nginx
server {
    listen 443 ssl http2;
    server_name mail-manager.example.com;

    ssl_certificate     /etc/letsencrypt/live/mail-manager.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail-manager.example.com/privkey.pem;

    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:8899;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

应用使用跨进程单实例锁和数据库账号租约。不要配置 Gunicorn/Uvicorn 多 worker；扩展为多实例前需要重新设计后台调度与重启编排。

## 新邮件预警

后台默认每 10 分钟检测一次启用账号，只读取收件箱与垃圾箱各自最新的 1 封邮件。首次写入的收件箱邮件会生成持久化通知，包含账号、发件人、主题和约 100 字正文摘要；垃圾箱只参与健康检测，不触发提醒。网页打开时会轮询通知队列，并在获得浏览器权限后显示桌面通知。完整邮件同步仍由通知中心的“立即完整取件”或首页取件按钮触发。

## 自动更新

页面版本框在登录后请求 GitHub `releases/latest`。仅当 Release 的语义化版本高于本地 `VERSION` 时显示更新按钮。

更新器会验证：

- HTTPS、允许的 GitHub 下载域名、超时和重定向；
- Ed25519 签名的版本清单及每个文件的 SHA-256；
- ZIP 路径、符号链接、设备名、成员数和解压大小；
- 目标版本必须严格高于当前版本。

更新保留数据库、密钥、`.env`、现有 `venv`、日志和未知本地文件。依赖变化时会依据带哈希的 `requirements.lock` 构建独立的版本虚拟环境，不直接修改当前环境。源码更新使用持久化事务日志；进程中断后，下次启动会先恢复未完成更新。

自动更新依赖正式 GitHub Release。只推送提交或 tag，不会被 `releases/latest` 发现。

## 环境变量

| 变量 | 说明 | 默认值 |
|---|---|---|
| `OMM_ADMIN_PASSWORD` | 可选的新数据库初始管理员密码，必须非空 | `admin123` |
| `OMM_DB_PATH` | SQLite 数据库路径 | 项目目录 `data.db` |
| `OMM_SECRET_KEY_FILE` | Fernet 密钥文件路径 | 数据库目录 `.omm_secret.key` |
| `OMM_SECRET_KEY` | 32 字节随机 Fernet key 的 URL-safe Base64 | 无 |
| `OMM_PROXY` | 未在页面保存设置时使用的全局代理 | 空 |
| `OMM_FETCH_CONCURRENCY` | 批量取件/健康检测时同时处理的账号数（1-20） | `5` |
| `OMM_MS_CLIENT_ID` | 导入页预填的 Microsoft 应用程序（客户端）ID | 空 |
| `OMM_MS_FETCH_MODE` | 新 Microsoft 账号默认模式：`graph`/`imap` | `graph` |
| `OMM_AUTO_CHECK_MINUTES` | 未在页面保存设置时的自动检测间隔（分钟） | `10` |
| `OMM_AUTO_CHECK_HOURS` | 旧版自动检测间隔；仅在未设置分钟变量时兼容读取 | 空 |
| `OMM_MAX_REQUEST_BYTES` | POST/PUT/PATCH 请求体上限 | `2097152` |
| `OMM_HOST` | 监听地址 | `127.0.0.1` |
| `OMM_PORT` | 监听端口 | `8899` |
| `OMM_SECURE_COOKIE` | Cookie 是否添加 `Secure` | `1` |
| `OMM_CHECK_ORIGIN` | 是否启用 Origin 来源校验，个人直连可设为 `0` | `1` |
| `OMM_ALLOWED_ORIGINS` | 反向代理对外地址白名单，多个地址用英文逗号分隔 | 空 |
| `OMM_FORWARDED_ALLOW_IPS` | 信任的反向代理地址 | `127.0.0.1` |

`OMM_SECURE_COOKIE=0` 只用于本机 HTTP 测试。

## 测试与审计

```bash
python -m compileall -q .
python -m pytest -q
python smoke_test.py
ruff check .
bandit -r app.py db.py mail_fetcher.py security.py update_manager.py web_security.py
pip-audit -r requirements.txt
```

详细审查记录见 `SECURITY_REVIEW.md`。
