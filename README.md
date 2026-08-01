# Deploy Certificate to Aliyun

每两个月自动签发 Let's Encrypt 证书，并根据 CDN / ESA 域名列表自动匹配部署到阿里云 **CDN（国内）** 与 **ESA（国际）**。

## ✨ 功能特点

- 🔄 默认根据 CDN / ESA 域名列表**自动推导**要申请的证书（单域 + 泛域）
- ☁️ 按 CDN 域名列表自动匹配证书并部署
- 🌍 按 ESA 绑定自动匹配证书并上传到站点证书池
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

| 变量名 | 必填 | 说明 | 示例 |
| :----- | :--- | :--- | :--- |
| `ALIYUN_ACCESS_KEY_ID` | 是 | AccessKey ID | `LTAI5t...` |
| `ALIYUN_ACCESS_KEY_SECRET` | 是 | AccessKey Secret | `h6J9Z...` |
| `ALIYUN_CDN_DOMAINS` | 是* | CDN 加速域名，逗号分隔 | `example.com,cdn.example.com,api.example.com` |
| `ALIYUN_ESA_BINDINGS` | 否 | ESA：`站点ID:域名1+域名2`，多站点逗号分隔 | `123456789:example.com+www.example.com+api.example.com` |
| `EMAIL` | 是 | 通知邮箱 | `you@example.com` |
| `CERT_DOMAINS` | 否 | **可选覆盖**签发列表；不填则自动推导 | `example.com,*.example.com` |

\* CDN 与 ESA 至少配置一侧域名，否则无法推导证书。

### 自动推导规则

汇总 `ALIYUN_CDN_DOMAINS` 与 `ALIYUN_ESA_BINDINGS` 中的主机名后：

| 主机名类型 | 申请的证书 |
| ---------- | ---------- |
| 裸域 `example.com` | `example.com` |
| 单级子域 `cdn.example.com` | `*.example.com`（同主域多个子域合并为一张） |
| 多级子域 `a.b.example.com` | 精确证书 `a.b.example.com` |

已内置常见复后缀（如 `com.cn`）。若推导不符合预期，可设置 `CERT_DOMAINS` 覆盖。

**配置示例：**

```text
ALIYUN_CDN_DOMAINS=example.com,cdn.example.com,api.example.com
ALIYUN_ESA_BINDINGS=123456789:example.com+www.example.com+api.example.com
```

将自动申请：`example.com`、`*.example.com`，再分别部署到 CDN / ESA。

### 第五步：触发工作流

在仓库中任意提交一次（或手动 Run workflow），到 **Actions** 查看结果；再到 CDN / ESA 控制台确认证书已更新。

## 工作流概览

```text
CDN 域名 ∪ ESA 域名
        │
        ▼
  推导 CERT_DOMAINS（可被 Secret 覆盖）
        │
        ▼
  acme.sh DNS-01 签发
        │
        ├─► CDN：按主机名匹配证书上传
        └─► ESA：按站点所需证书上传
```

## ⚠️ 重要注意事项

- 旧 Secret `DOMAINS` / `ALIYUN_ESA_SITE_IDS` 已废弃
- 不要混用 ESA 免费证书（会与 DNS-01 TXT 冲突）
- ESA 同一站点下多个域名用 `+` 连接；多项用英文逗号分隔
- Let's Encrypt 免费；CDN / ESA / DNS 按阿里云计费

## 🔧 排错

1. `DomainRecordConflict`：删除 `_acme-challenge` 的 ESA DCV CNAME
2. `无法为域名 xxx 找到可覆盖的证书`：检查推导结果或设置 `CERT_DOMAINS`
3. 确认 RAM 权限与 Secrets 拼写正确

------

设置完成后，约每 60 天会自动续期，并按域名列表部署到 CDN 与 ESA。
