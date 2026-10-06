# MsdkLogin-rs

用于 QQ / 微信扫码登录及 MSDK token 交换的 Rust 库，提供创建客户端、获取二维码、轮询、取消和读取结果五类接口。应用通过 Rust 参数构造配置。

## 快速开始

在 `Cargo.toml` 中添加依赖：

```toml
[dependencies]
msdk-login-rs = { git = "https://github.com/King-Maple/MsdkLogin-rs.git" }
# 下方异步示例使用 Tokio。
tokio = { version = "1", features = ["rt", "macros", "time"] }
```

以下函数展示一次完整登录会话，在 Tokio 运行时中调用。先替换示例参数，并将 `qr.qr_image` 交给界面展示；切换到微信时将 `Channel::Qq` 改为 `Channel::Wechat`。

```rust,no_run
use msdk_login::{Channel, MsdkConfig, MsdkCredentials, MsdkLogin};

async fn scan_login() -> Result<MsdkCredentials, Box<dyn std::error::Error>> {
    let config = MsdkConfig::builder(
        "https://login.example.com", // 当前游戏的 MSDK_URL，示例地址需替换
        "1234",                     // game_id
        "project-sdk-key",          // sdk_key
        "project-channel",          // channel_dis
        "com.example.game",         // package_name
    )
    .qq("123456", "0123456789abcdef0123456789abcdef") // QQ AppID、应用签名摘要
    .wechat("wx0123456789abcdef")                     // 微信 AppID
    .build()?;

    // 1. 创建客户端，只初始化配置和 HTTP 客户端，不发起登录请求。
    let login = MsdkLogin::new(config)?;
    // 2. 获取二维码。也可以传 Channel::Wechat。
    let qr = login.get_qrcode(Channel::Qq).await?;
    // 将 qr.qr_image（图片 data URI）显示在界面上，保存 qr.id。

    loop {
        tokio::time::sleep(std::time::Duration::from_millis(qr.poll_interval_ms)).await;
        // 3. 轮询。授权完成后，内部进行 MSDK 交换。
        let status = match login.poll(&qr.id).await {
            Ok(status) => status,
            Err(error) => {
                login.cancel(&qr.id).await;
                return Err(error.into());
            }
        };
        if status.status == "confirmed" {
            // 4. 读取登录结果，只在 Rust 后端使用账号和 token。
            let account = login.get_result(&qr.id).await.ok_or("认证结果已取消")?;
            // 5. 取消／清理会话。此处已取出的 account 仍归调用方所有。
            login.cancel(&qr.id).await;
            return Ok(account);
        }
        if !matches!(status.status, "waiting" | "scanned") {
            login.cancel(&qr.id).await;
            return Err(status.message.unwrap_or_else(|| status.status.to_owned()).into());
        }
    }
}
```

示例使用占位参数，需替换为目标应用的配置。库不会自动启动后台轮询；按 `poll_interval_ms` 调用 `poll`，直到成功、取消或出现终止状态。

## 核心接口

| 动作 | Rust 调用 | 返回值 |
|---|---|---|
| 创建客户端 | `MsdkLogin::new(config)` | `Result<MsdkLogin, String>`，初始化配置与 HTTP 客户端 |
| 获取二维码 | `login.get_qrcode(channel).await` | `Result<QrChallenge, String>` |
| 轮询 | `login.poll(&id).await` | `Result<QrStatus, String>` |
| 取消 | `login.cancel(&id).await` | `()`，移除会话并清理缓存 |
| 读取结果 | `login.get_result(&id).await` | `Option<MsdkCredentials>` |

`QrChallenge` 包含：

| 字段 | 用途 |
|---|---|
| `id` | 后续轮询、取消和读取结果使用的会话 ID |
| `qr_image` | 图片 data URI，可交给界面图片组件展示 |
| `expires_at` | 二维码过期时间，Unix 时间戳，单位为秒 |
| `poll_interval_ms` | 轮询间隔，单位为毫秒 |

认证成功后，`MsdkCredentials` 包含 `openid`、`token` 和 `channel_id`（微信为 `1`，QQ 为 `2`）。`get_result` 只读取缓存，不发起网络请求；未认证或已取消时返回 `None`，重复读取成功结果会返回副本。

取消按钮、切换账号或关闭登录页时调用 `cancel(&id)`。如果业务还需要读取缓存结果，可推迟清理；已经取出的结果由调用方持有，后续取消不会销毁这份副本。游戏服务器连接和心跳由调用方实现。

## 游戏参数与版本设置

`builder(msdk_url, game_id, sdk_key, channel_dis, package_name)` 直接填写五个核心参数，再通过 `.qq(app_id, signature_md5)` 和／或 `.wechat(app_id)` 启用渠道。至少启用一个；QQ 签名摘要不能借用另一款游戏的值。

| 核心参数 | 含义 |
|---|---|
| `msdk_url` | 当前应用的 MSDK HTTPS 基址，对应 `MSDK_URL` |
| `game_id` | MSDK 游戏 ID |
| `sdk_key` | 当前应用的 MSDK SDK key |
| `channel_dis` | 分发渠道，区别于 QQ / 微信的登录渠道编号 |
| `package_name` | 应用包名 |

`MSDK_URL` 没有默认值，空地址会校验失败。地址使用 HTTPS 基址，不能包含用户信息、业务路径、查询参数或片段。QQ 的 `signature_md5` 使用 APK 签名证书的 MD5，填写不带冒号的 32 位十六进制字符串。

| 可选设置 | 默认值 |
|---|---|
| `.msdk_version(...)` | `5.42.102.7425` |
| `.qq_sdk_version(...)` | `3.5.18` |

这些默认值对应当前实现的协议版本；应用使用其他 SDK 版本时显式覆盖。不同应用分别构造配置；SDK key 的 Debug 输出会脱敏。配置校验会拒绝缺项、不合法的版本、QQ 签名摘要和非 HTTPS 的 MSDK 地址。

HTTP 适配器支持 QQ 移动授权二维码、微信应用扫码入口，以及通过 HTTPS 向 MSDK `/v2/auth/login` 发送 JSON 交换请求。

## 状态、重试与凭据

`poll` 成功返回的 `QrStatus` 包含 `status` 和可选的 `message`：

| `status` | 含义 | 建议处理 |
|---|---|---|
| `waiting` | 等待扫码 | 按返回的间隔继续轮询 |
| `scanned` | 已扫码，等待确认 | 继续轮询 |
| `confirmed` | MSDK 认证成功 | 调用 `get_result` |
| `expired` | 二维码或授权已过期 | 获取新二维码 |
| `rejected` | 授权被拒绝或会话已终止 | 清理会话，按需重新扫码 |
| `exchange_error` | 已取得授权，但 MSDK 交换未成功 | 查看 `message`，按可重试条件处理 |
| `error` | 登录失败或交换结果不确定 | 清理会话，重新扫码 |

`poll` 也可能直接返回 `Err`，例如会话已取消、不存在或网络请求失败。示例对错误统一清理会话并结束本次流程。只有 `confirmed` 表示已取得 MSDK 结果，扫码确认本身不等于认证完成。

- 相同会话串行轮询。切换账号时调用 `cancel` 清理旧会话，取消后的迟到响应不能发布旧账号或触发后续兑换。
- `login.retry(&id).await` 仅用于适配器明确标记为 `Retryable` 的交换失败。当前 HTTP 适配器遇到未知的 MSDK 非零返回码时要求重新扫码；请求结果不确定或交换 Future 被丢弃时，不重放授权码。
- 凭据不实现 Serialize，Debug 脱敏；`SecretString` 和 `MsdkCredentials` 释放时清零。`into_parts()` 把账号和 token 所有权交给调用方，后续清理由调用方负责。
- 二维码可能包含会话信息，不写日志。支持 PNG、JPEG、GIF、WebP；校验文件签名和 2 MiB 上限，完整解码由前端处理。
- QR 服务没有远程撤销接口：取消停止本地轮询并丢弃结果，不等于撤销平台上已经发出的 token。

## 自定义适配器

实现 `QrProvider` 和 `MsdkExchanger`，通过 `LoginClient` / `LoginSession` 或 `http::LoginService::with_adapters()` 接入自己的扫码与认证逻辑。通过 `LoginSession::image_bytes()` 读取二维码图片字节。仓库的 `shared_profiles` 示例展示了如何让不同配置共用适配器。

## 本地验证

```powershell
git clone https://github.com/King-Maple/MsdkLogin-rs.git
cd MsdkLogin-rs
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo run --example shared_profiles
python -B -m unittest discover -s skills/extract-msdk-core-params/tests -v
```

Rust 测试覆盖两种渠道的本地 HTTP 流程、认证地址与签名、响应解析、配置隔离、取消竞态、请求中断与重试限制。`shared_profiles` 是不联网的模拟适配器示例；依赖已缓存时，Cargo 命令可加 `--offline`。

## APK 核心参数 Skill

[APK 参数提取 Skill](https://github.com/King-Maple/MsdkLogin-rs/blob/HEAD/skills/extract-msdk-core-params/SKILL.md) 随仓库提供，可用于从本地 APK 分析登录配置。

提取 `msdk_url`、`game_id`、`sdk_key`、`channel_dis`、`package_name`，加上所需渠道的 QQ AppID／签名证书 MD5、微信 AppID；按需核对 SDK 版本。技能说明了资源、DEX/native 初始化位置和 APK 签名证书的定位方法，交付参数来源表及五个核心参数直接传入 `MsdkConfig::builder(...)` 的代码，无需 INI 或环境变量。

真实 SDK key 只写入调用项目的本地配置代码，公开报告仅记录定位状态和来源。不同游戏分别取值，缺失或冲突不猜测。辅助 Python 脚本提供可选的公开字段索引，其命令与覆盖范围见技能；完整核心参数按技能流程核实。
