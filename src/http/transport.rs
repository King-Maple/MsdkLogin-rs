use super::{config::MsdkConfig, wire::*};
use crate::{
    AppConfig, AuthTokens, Channel, MsdkExchanger, ProviderChallenge, QrProvider, ScanEvent,
    SdkError, SdkErrorKind, SdkFuture, SecretString,
};
use md5::{Digest, Md5};
use reqwest::header::{HeaderMap, COOKIE, REFERER, SET_COOKIE, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Default, Serialize, Deserialize)]
struct CookieBag(BTreeMap<String, String>);
impl Drop for CookieBag {
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}
impl CookieBag {
    fn absorb(&mut self, headers: &HeaderMap) {
        for value in headers.get_all(SET_COOKIE) {
            let Ok(value) = value.to_str() else { continue };
            if let Some((name, value)) = value.split(';').next().and_then(|s| s.split_once('=')) {
                self.0
                    .insert(name.trim().to_owned(), value.trim().to_owned());
            }
        }
    }

    fn header(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }
}

#[derive(Serialize, Deserialize)]
enum SessionKind {
    Wechat {
        uuid: String,
        cookies: CookieBag,
    },
    Qq {
        xlogin_url: String,
        qrsig: String,
        openlogin_data: String,
        cookies: CookieBag,
    },
}

#[derive(Serialize, Deserialize)]
struct Handle {
    profile: AppConfig,
    kind: SessionKind,
}
#[derive(Serialize, Deserialize)]
struct Grant {
    profile: AppConfig,
    credential: Credential,
}

pub struct HttpAdapter {
    client: reqwest::Client,
    config: Arc<MsdkConfig>,
    #[cfg(test)]
    mock_origin: Option<Url>,
}
impl HttpAdapter {
    pub fn new(config: MsdkConfig) -> Result<Self, crate::LoginError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(25))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| SdkError::new(SdkErrorKind::Transport, None))?;
        Ok(Self {
            client,
            config: Arc::new(config),
            #[cfg(test)]
            mock_origin: None,
        })
    }
    fn request_get(&self, url: Url) -> reqwest::RequestBuilder {
        #[cfg(test)]
        let url = if let Some(origin) = &self.mock_origin {
            let mut request = origin.clone();
            request.set_path(url.path());
            request.set_query(url.query());
            request
        } else {
            url
        };
        self.client.get(url)
    }
    pub fn app_config(&self) -> AppConfig {
        self.config.app_config()
    }
    fn check_profile(&self, config: &AppConfig) -> Result<(), SdkError> {
        if config != &self.app_config() {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    async fn begin_wechat(&self) -> Result<(SessionKind, Vec<u8>), String> {
        let mut url =
            Url::parse("https://open.weixin.qq.com/connect/app/qrconnect").expect("static URL");
        url.query_pairs_mut().extend_pairs([
            ("appid", self.config.wechat_app_id.as_str()),
            ("bundleid", self.config.package_name.as_str()),
            (
                "scope",
                "snsapi_base,snsapi_userinfo,snsapi_friend,snsapi_message",
            ),
            ("state", "weixin"),
        ]);
        let page = self
            .request_get(url.clone())
            .header(USER_AGENT, WECHAT_USER_AGENT)
            .send()
            .await
            .map_err(|_| "无法连接微信扫码服务")?;
        let mut cookies = CookieBag::default();
        cookies.absorb(page.headers());
        let html = checked_text(page, "微信二维码页面").await?;
        let (uuid, image_url) = parse_wechat_begin(&html)?;
        let image_url = url.join(&image_url).map_err(|_| "微信二维码地址无效")?;
        if !allowed_origin(&image_url, "open.weixin.qq.com") {
            return Err("微信二维码地址域名异常".into());
        }
        let mut request = self
            .request_get(image_url)
            .header(USER_AGENT, WECHAT_USER_AGENT)
            .header(REFERER, url.as_str());
        if !cookies.0.is_empty() {
            request = request.header(COOKIE, cookies.header());
        }
        let image = checked_bytes(
            request.send().await.map_err(|_| "无法获取微信二维码图片")?,
            "微信二维码图片",
        )
        .await?;
        Ok((SessionKind::Wechat { uuid, cookies }, image))
    }

    async fn poll_wechat(&self, uuid: &str, cookies: &CookieBag) -> Result<PollEvent, String> {
        let mut url =
            Url::parse("https://long.open.weixin.qq.com/connect/l/qrconnect").expect("static URL");
        url.query_pairs_mut()
            .extend_pairs([("uuid", uuid), ("f", "url")]);
        let mut request = self.request_get(url).header(USER_AGENT, WECHAT_USER_AGENT);
        if !cookies.0.is_empty() {
            request = request.header(COOKIE, cookies.header());
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) if error.is_timeout() => return Ok(PollEvent::Waiting),
            Err(_) => return Err("微信扫码轮询失败".into()),
        };
        let body = checked_text(response, "微信扫码轮询").await?;
        parse_wechat_poll(&body)
    }

    async fn begin_qq(&self) -> Result<(SessionKind, Vec<u8>), String> {
        let ts = unix_time().to_string();
        let signature = format!(
            "{:x}",
            Md5::digest(
                format!(
                    "{}_{}_{ts}",
                    self.config.package_name, self.config.app_signature_md5
                )
                .as_bytes()
            )
        );
        let mut url =
            Url::parse("https://openmobile.qq.com/oauth2.0/m_authorize").expect("static URL");
        url.query_pairs_mut().extend_pairs([
            ("cancel_display", "1"),
            ("sdkp", "a"),
            ("display", "mobile"),
            ("format", "json"),
            ("sign", signature.as_str()),
            ("sdkv", self.config.qq_sdk_version.as_str()),
            ("response_type", "token"),
            ("status_os", "15"),
            ("client_id", self.config.qq_app_id.as_str()),
            ("switch", "1"),
            ("status_version", "30"),
            ("show_download_ui", "true"),
            ("pf", "openmobile_android"),
            ("scope", "all"),
            ("compat_v", "1"),
            ("status_machine", "Pixel"),
            ("style", "qr"),
            ("time", ts.as_str()),
            ("redirect_uri", "auth://tauth.qq.com/"),
        ]);
        let response = self
            .request_get(url.clone())
            .send()
            .await
            .map_err(|_| "无法连接 QQ 授权服务")?;
        let mut cookies = CookieBag::default();
        cookies.absorb(response.headers());
        let html = checked_text(response, "QQ 授权页面").await?;
        let xlogin = extract_qq_xlogin_url(&html)?;
        if !allowed_origin(&xlogin, "xui.ptlogin2.qq.com") {
            return Err("QQ 登录地址域名异常".into());
        }
        let mut request = self
            .request_get(xlogin.clone())
            .header(REFERER, url.as_str());
        if !cookies.0.is_empty() {
            request = request.header(COOKIE, cookies.header());
        }
        let response = request.send().await.map_err(|_| "无法获取 QQ 登录页面")?;
        cookies.absorb(response.headers());
        let xlogin_html = checked_text(response, "QQ 登录页面").await?;
        let qr_url = extract_qq_qrshow_url(&xlogin_html, &xlogin, &self.config.qq_app_id)?;
        if !allowed_origin(&qr_url, "xui.ptlogin2.qq.com") {
            return Err("QQ 二维码地址域名异常".into());
        }
        let mut request = self.request_get(qr_url).header(REFERER, xlogin.as_str());
        if !cookies.0.is_empty() {
            request = request.header(COOKIE, cookies.header());
        }
        let response = request.send().await.map_err(|_| "无法获取 QQ 二维码")?;
        cookies.absorb(response.headers());
        let image = checked_bytes(response, "QQ 二维码图片").await?;
        let qrsig = cookies
            .get("qrsig")
            .ok_or("QQ 二维码缺少 qrsig")?
            .to_owned();
        let mut openlogin_data = xlogin.query().ok_or("QQ 登录页面缺少参数")?.to_owned();
        openlogin_data.push('&');
        Ok((
            SessionKind::Qq {
                xlogin_url: xlogin.to_string(),
                qrsig,
                openlogin_data,
                cookies,
            },
            image,
        ))
    }

    async fn poll_qq(
        &self,
        xlogin: &str,
        qrsig: &str,
        openlogin_data: &str,
        cookies: &CookieBag,
    ) -> Result<PollEvent, String> {
        let mut url = Url::parse("https://xui.ptlogin2.qq.com/ssl/ptqrlogin").expect("static URL");
        let token = qq_hash33(qrsig).to_string();
        let random = format!("0.{}", unix_time());
        url.query_pairs_mut().extend_pairs([
            ("u1", "http://connect.qq.com"),
            ("from_ui", "1"),
            ("type", "1"),
            ("ptlang", "2052"),
            ("ptqrtoken", token.as_str()),
            ("daid", "381"),
            ("aid", "716027609"),
            ("pt_3rd_aid", self.config.qq_app_id.as_str()),
            ("pt_openlogin_data", openlogin_data),
            ("device", "2"),
            ("ptopt", "1"),
            ("pt_uistyle", "35"),
            ("jsver", "v1.36.0"),
            ("r", random.as_str()),
        ]);
        let mut request = self.request_get(url).header(REFERER, xlogin);
        if !cookies.0.is_empty() {
            request = request.header(COOKIE, cookies.header());
        }
        let body = checked_text(
            request.send().await.map_err(|_| "QQ 扫码轮询失败")?,
            "QQ 扫码轮询",
        )
        .await?;
        parse_qq_poll(&body)
    }
}

impl QrProvider for HttpAdapter {
    fn begin<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
    ) -> SdkFuture<'a, ProviderChallenge> {
        Box::pin(async move {
            self.check_profile(config)?;
            let started = Instant::now();
            let (kind, image) = match channel {
                Channel::Qq => self.begin_qq().await,
                Channel::Wechat => self.begin_wechat().await,
            }
            .map_err(|_| SdkError::new(SdkErrorKind::Transport, None))?;
            let handle = Handle {
                profile: config.clone(),
                kind,
            };
            Ok(ProviderChallenge {
                handle: SecretString::new(serde_json::to_string(&handle).map_err(|_| invalid())?),
                image_png: image,
                expires_in: Duration::from_secs(300).saturating_sub(started.elapsed()),
                poll_interval: Duration::from_millis(1500),
            })
        })
    }
    fn poll<'a>(&'a self, handle: &'a SecretString) -> SdkFuture<'a, ScanEvent> {
        Box::pin(async move {
            let handle: Handle =
                serde_json::from_str(handle.expose_secret()).map_err(|_| invalid())?;
            self.check_profile(&handle.profile)?;
            let event = match &handle.kind {
                SessionKind::Wechat { uuid, cookies } => self.poll_wechat(uuid, cookies).await,
                SessionKind::Qq {
                    xlogin_url,
                    qrsig,
                    openlogin_data,
                    cookies,
                } => {
                    self.poll_qq(xlogin_url, qrsig, openlogin_data, cookies)
                        .await
                }
            }
            .map_err(|_| SdkError::new(SdkErrorKind::Transport, None))?;
            Ok(match event {
                PollEvent::Waiting => ScanEvent::Waiting,
                PollEvent::Scanned => ScanEvent::Scanned,
                PollEvent::Expired => ScanEvent::Expired,
                PollEvent::Rejected => ScanEvent::Rejected,
                PollEvent::Confirmed(credential) => ScanEvent::Authorized(SecretString::new(
                    serde_json::to_string(&Grant {
                        profile: handle.profile.clone(),
                        credential,
                    })
                    .map_err(|_| invalid())?,
                )),
            })
        })
    }
    fn cancel<'a>(&'a self, _: &'a SecretString) -> SdkFuture<'a, ()> {
        // These QR flows expose no remote revoke operation. Local session removal
        // stops polling and discards its credentials; the provider QR expires.
        Box::pin(async { Ok(()) })
    }
}

impl MsdkExchanger for HttpAdapter {
    fn exchange<'a>(
        &'a self,
        config: &'a AppConfig,
        channel: Channel,
        grant: &'a SecretString,
    ) -> SdkFuture<'a, AuthTokens> {
        Box::pin(async move {
            self.check_profile(config)?;
            let grant: Grant =
                serde_json::from_str(grant.expose_secret()).map_err(|_| invalid())?;
            self.check_profile(&grant.profile)?;
            let (channel_id, body) = match (&grant.credential, channel) {
                (Credential::WechatCode(code), Channel::Wechat) => (1, serde_json::json!({"channel_info":{"code":code,"cgToken":"","allow_encryption":true,"login_type":0},"channel_dis":self.config.channel_dis}).to_string()),
                (Credential::Qq { openid, access_token, pay_token }, Channel::Qq) => (2, serde_json::json!({"channel_info":{"openid":openid,"access_token":access_token,"pay_token":pay_token},"channel_dis":self.config.channel_dis}).to_string()),
                _ => return Err(invalid()),
            };
            let url = build_auth_url(
                &self.config,
                channel_id,
                &Uuid::new_v4().simple().to_string(),
                unix_time(),
                &body,
            );
            let response = self
                .client
                .post(url)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
                .map_err(|_| SdkError::new(SdkErrorKind::Transport, None))?;
            let response = checked_text(response, "MSDK")
                .await
                .map_err(|_| SdkError::new(SdkErrorKind::Transport, None))?;
            let response = zeroize::Zeroizing::new(response);
            let json: serde_json::Value = serde_json::from_str(&response).map_err(|_| invalid())?;
            let code = json
                .get("ret")
                .or_else(|| json.get("retCode"))
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(invalid)?;
            if code != 0 {
                // No undocumented error is assumed safe for grant replay.
                return Err(SdkError::new(SdkErrorKind::Rejected, Some(code)));
            }
            let account = parse_msdk_response(&response).map_err(|_| invalid())?;
            if account.channel_id != channel_id {
                return Err(invalid());
            }
            let (openid, token, _) = account.into_parts();
            Ok(AuthTokens::new(openid, token, channel))
        })
    }
}

fn invalid() -> SdkError {
    SdkError::new(SdkErrorKind::InvalidResponse, None)
}
fn allowed_origin(url: &Url, host: &str) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(host)
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}
const WECHAT_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36 MicroMessenger/8.0.47";

async fn checked_bytes(mut response: reqwest::Response, label: &str) -> Result<Vec<u8>, String> {
    const LIMIT: usize = 2 * 1024 * 1024;
    if !response.status().is_success() {
        return Err(format!("{label}返回 HTTP {}", response.status().as_u16()));
    }
    if response
        .content_length()
        .is_some_and(|length| length > LIMIT as u64)
    {
        return Err("响应过大".into());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| "响应无法读取")? {
        if bytes.len() + chunk.len() > LIMIT {
            return Err("响应过大".into());
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
async fn checked_text(response: reqwest::Response, label: &str) -> Result<String, String> {
    String::from_utf8(checked_bytes(response, label).await?).map_err(|_| "响应文本格式错误".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Bytes,
        extract::{Query, State},
        http::{HeaderMap as AxumHeaders, Uri},
        response::IntoResponse,
        routing::{get, post},
        Router,
    };
    use std::collections::HashMap;
    use tokio::sync::Mutex;

    const SETTINGS: &str = "MSDK_URL=https://login.example.test\nMSDK_GAME_ID=1234\nMSDK_SDK_KEY=test-key\nMSDK_CHANNEL_DIS=demo-channel\nMSDK_VERSION=5.42.102.7425\nPACKAGE_NAME=com.example.test\nAPP_SIGNATURE_MD5=0123456789abcdef0123456789abcdef\nQQ_APP_ID=123456\nWECHAT_APP_ID=wx0123456789abcdef";
    type Requests = Arc<Mutex<Vec<(String, String)>>>;
    async fn pages(State(calls): State<Requests>, uri: Uri) -> impl IntoResponse {
        calls.lock().await.push((uri.to_string(), String::new()));
        let body = match uri.path() {
            "/oauth2.0/m_authorize" => br#"<script>var src = "https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&pt_3rd_aid=123456";</script>"#.to_vec(),
            "/cgi-bin/xlogin" => b"<html>fallback image path</html>".to_vec(),
            "/ssl/ptqrshow" | "/connect/qrcode/fixture" => vec![0xff, 0xd8, 0xff, 0xe0],
            "/ssl/ptqrlogin" => b"ptuiCB('0','0','auth://tauth.qq.com/?openid=qq-open&access_token=qq-access&pay_token=qq-pay','0','ok','nick')".to_vec(),
            "/connect/app/qrconnect" => br#"<script>var QR = {uuid: "fixture-uuid"};</script><img class="auth_qrcode" src="/connect/qrcode/fixture">"#.to_vec(),
            "/connect/l/qrconnect" => b"window.wx_errcode=405;window.wx_redirecturl='https://example.test/callback?code=wx-code&state=weixin';".to_vec(),
            _ => panic!("unexpected fixture path"),
        };
        let mut headers = AxumHeaders::new();
        headers.insert("set-cookie", "qrsig=fixture-qrsig; Path=/".parse().unwrap());
        (headers, body)
    }
    async fn exchange(
        State(calls): State<Requests>,
        Query(query): Query<HashMap<String, String>>,
        body: Bytes,
    ) -> impl IntoResponse {
        let text = String::from_utf8(body.to_vec()).unwrap();
        calls.lock().await.push(("exchange".into(), text.clone()));
        let json: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(query["gameid"], "1234");
        assert_eq!(query["version"], "5.42.102.7425");
        assert_eq!(json["channel_dis"], "demo-channel");
        assert!(!query.contains_key("encrypt"));
        assert_eq!(query["sig"].len(), 33);
        let channel: u8 = query["channelid"].parse().unwrap();
        if channel == 1 {
            assert_eq!(json["channel_info"]["code"], "wx-code");
        } else {
            assert_eq!(json["channel_info"]["access_token"], "qq-access");
        }
        axum::Json(
            serde_json::json!({"ret":0,"openid":"msdk-account","token":"msdk-token","channel_id":channel}),
        )
    }
    #[tokio::test]
    async fn both_channels_complete_over_loopback_using_configured_product_values() {
        let calls = Requests::default();
        let app = Router::new()
            .route("/v2/auth/login", post(exchange))
            .fallback(get(pages))
            .with_state(calls.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let mut config = MsdkConfig::from_ini(SETTINGS).unwrap();
        config.msdk_url = origin.clone(); // Test-only loopback endpoint; production parser requires HTTPS.
        let mut adapter = HttpAdapter::new(config).unwrap();
        adapter.mock_origin = Some(Url::parse(&origin).unwrap());
        let adapter = Arc::new(adapter);
        let service = super::super::LoginService::with_adapters(
            adapter.app_config(),
            adapter.clone(),
            adapter,
        )
        .unwrap();
        for (channel, expected) in [("qq", 2), ("wechat", 1)] {
            let channel = if channel == "qq" {
                Channel::Qq
            } else {
                Channel::Wechat
            };
            let qr = service.get_qrcode(channel).await.unwrap();
            assert!(qr.qr_image.starts_with("data:image/jpeg;base64,"));
            assert_eq!(service.poll(&qr.id).await.unwrap().status, "confirmed");
            assert_eq!(
                service.get_result(&qr.id).await.unwrap().channel_id,
                expected
            );
            service.cancel(&qr.id).await;
            assert!(service.get_result(&qr.id).await.is_none());
        }
        let calls = calls.lock().await;
        assert_eq!(calls.iter().filter(|(uri, _)| uri == "exchange").count(), 2);
        for (uri, _) in calls.iter().filter(|(uri, _)| {
            uri.starts_with("/oauth2.0")
                || uri.starts_with("/ssl/ptqrshow")
                || uri.starts_with("/connect/app")
        }) {
            assert!(uri.contains("123456") || uri.contains("wx0123456789abcdef"));
            if uri.starts_with("/connect/app") {
                assert!(uri.contains("bundleid=com.example.test"));
            }
        }
        server.abort();
    }

    #[tokio::test]
    async fn wrong_project_or_channel_fails_before_network() {
        let adapter = HttpAdapter::new(MsdkConfig::from_ini(SETTINGS).unwrap()).unwrap();
        let config = adapter.app_config();
        let grant = SecretString::new(
            serde_json::to_string(&Grant {
                profile: config.clone(),
                credential: Credential::WechatCode("code".into()),
            })
            .unwrap(),
        );
        assert_eq!(
            adapter
                .exchange(&config, Channel::Qq, &grant)
                .await
                .unwrap_err()
                .kind,
            SdkErrorKind::InvalidResponse
        );
        let mut wrong = config.clone();
        wrong.msdk_game_id = "other".into();
        assert_eq!(
            adapter.begin(&wrong, Channel::Qq).await.unwrap_err().kind,
            SdkErrorKind::InvalidResponse
        );
    }

    #[test]
    fn login_redirects_require_https_and_expected_origin() {
        for url in [
            "http://xui.ptlogin2.qq.com/a",
            "https://xui.ptlogin2.qq.com:444/a",
            "https://user@xui.ptlogin2.qq.com/a",
            "https://example.test/a",
        ] {
            assert!(!allowed_origin(
                &Url::parse(url).unwrap(),
                "xui.ptlogin2.qq.com"
            ));
        }
    }
}
