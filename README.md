# Deploy Certificate to Aliyun

每两个月自动签发 Let's Encrypt 证书，并按域名列表自动匹配后部署到阿里云 **CDN（国内）** 与 **ESA（国际）**。

## ✨ 功能特点

- 🔄 按 `CERT_DOMAINS` 申请证书（支持单域名与泛域名，可混写）
- ☁️ 按 `ALIYUN_CDN_DOMAINS` 自动匹配证书并部署到 CDN
- 🌍 按 `ALIYUN_ESA_BINDINGS` 自动匹配证书并上传到 ESA 站点证书池
- ⏰ 每两个月自动运行一次
- 🔒 使用 GitHub Secrets 保护敏感信息

## 🚀 如何使用

### 第一步：Fork 项目仓库

1. 打开本项目的 GitHub 仓库页面
2. 点击页面右上角的 **"Fork"** 按钮
3. 这会在您的 GitHub 账户下创建一个完整的副本

### 第二步：配置阿里云访问密钥（AK/SK）

1. 登录[阿里云控制台](https://homenew.console.aliyun.com/)，进入 **访问控制 (RAM)** 页面
2. 创建一个专用于此项目的用户（推荐）
3. 为该用户授权以下策略权限：
   - `AliyunDNSFullAccess`（DNS 验证）
   - `AliyunCDNFullAccess`（CDN 证书部署）
   - `AliyunESAFullAccess`（ESA 证书上传）
   - `AliyunYundunCertFullAccess`（SSL 证书服务）
4. 创建 **AccessKey (AK/SK)** 并妥善保存

### 第三步：ESA 前置处理（若曾用过 ESA 免费证书）

1. ESA 控制台关闭/删除该站点的**免费自动证书**
2. 云解析中删除 `_acme-challenge` → `*.dcv.aliyun-esa.com` 的 **CNAME**
3. 记下 ESA **站点 ID（SiteId）**

### 第四步：配置 GitHub Secrets

| 变量名 | 说明 | 示例 |
| :----- | :--- | :--- |
| `ALIYUN_ACCESS_KEY_ID` | AccessKey ID | `LTAI5t...` |
| `ALIYUN_ACCESS_KEY_SECRET` | AccessKey Secret | `h6J9Z...` |
| `CERT_DOMAINS` | **要申请的证书域名**，逗号分隔；支持 `example.com` 与 `*.example.com` | `example.com,*.example.com` |
| `ALIYUN_CDN_DOMAINS` | CDN 加速域名列表，自动匹配可覆盖的证书后上传 | `example.com,cdn.example.com,api.example.com` |
| `ALIYUN_ESA_BINDINGS` | ESA 绑定：`站点ID:域名1+域名2`，多站点用逗号分隔。不填则跳过 ESA | `123456789:example.com+www.example.com+api.example.com` |
| `EMAIL` | 通知邮箱 | `you@example.com` |

**匹配规则：**

- 主机名与某张证书完全一致 → 用该证书
- 否则若存在 `*.example.com`，且主机名是其单级子域（如 `cdn.example.com`）→ 用泛域名证书
- 注意：`*.example.com` **不覆盖** 裸域 `example.com`，裸域需单独写入 `CERT_DOMAINS`

**配置示例（CDN 国内 + ESA 国际，同一主域）：**

```text
CERT_DOMAINS=example.com,*.example.com
ALIYUN_CDN_DOMAINS=example.com,cdn.example.com,api.example.com
ALIYUN_ESA_BINDINGS=123456789:example.com+www.example.com+api.example.com
```

### 第五步：触发工作流

在仓库中任意提交一次（或手动 Run workflow），到 **Actions** 查看结果；再到 CDN / ESA 控制台确认证书已更新。

## ⚠️ 重要注意事项

- 旧 Secret `DOMAINS` / `ALIYUN_ESA_SITE_IDS` 已废弃，请改用 `CERT_DOMAINS` 与 `ALIYUN_ESA_BINDINGS`
- 不要混用 ESA 免费证书（会与 DNS-01 TXT 冲突）
- 多个值一律用**英文逗号**分隔；ESA 同一站点下多个域名用 `+` 连接
- Let's Encrypt 免费；CDN / ESA / DNS 按阿里云计费

## 🔧 排错

1. `DomainRecordConflict`：删除 `_acme-challenge` 的 ESA DCV CNAME
2. `无法为域名 xxx 找到可覆盖的证书`：把对应单域或泛域补进 `CERT_DOMAINS`
3. 确认 RAM 权限与 Secrets 拼写正确

------

设置完成后，约每 60 天会自动续期，并按域名列表部署到 CDN 与 ESA。
