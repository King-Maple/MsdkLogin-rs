use super::{config::MsdkConfig, service::MsdkCredentials};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use md5::{Digest, Md5};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use zeroize::Zeroize;
#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub(super) enum Credential {
    WechatCode(String),
    Qq {
        openid: String,
        access_token: String,
        pay_token: String,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum PollEvent {
    Waiting,
    Scanned,
    Expired,
    Rejected,
    Confirmed(Credential),
}

pub(super) fn capture(body: &str, pattern: &str) -> Option<String> {
    Regex::new(pattern)
        .ok()?
        .captures(body)?
        .get(1)
        .map(|m| m.as_str().to_owned())
}

pub(super) fn parse_wechat_begin(html: &str) -> Result<(String, String), String> {
    let uuid =
        capture(html, r#"\buuid\s*:\s*["']([^"']+)["']"#).ok_or("微信页面没有二维码会话 ID")?;
    let image = capture(
        html,
        r#"(?is)<img[^>]*class=["'][^"']*auth_qrcode[^"']*["'][^>]*src=["']([^"']+)"#,
    )
    .or_else(|| {
        capture(
            html,
            r#"(?is)<img[^>]*src=["']([^"']+)["'][^>]*class=["'][^"']*auth_qrcode"#,
        )
    })
    .ok_or("微信页面没有二维码图片")?;
    Ok((uuid, image))
}

pub(super) fn query_value(text: &str, name: &str) -> Option<String> {
    text.split(['?', '#']).find_map(|part| {
        url::form_urlencoded::parse(part.trim_start_matches('&').as_bytes())
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
    })
}

pub(super) fn parse_wechat_poll(body: &str) -> Result<PollEvent, String> {
    let json = serde_json::from_str::<Value>(body).ok();
    let code = json
        .as_ref()
        .and_then(|v| v.get("wx_errcode").or_else(|| v.get("errcode")))
        .and_then(|v| {
            v.as_i64()
                .map(|n| n.to_string())
                .or_else(|| v.as_str().map(str::to_owned))
        })
        .or_else(|| capture(body, r#"wx_errcode\s*=\s*['"]?(\d+)"#))
        .ok_or("微信轮询缺少状态码")?;
    match code.as_str() {
        "408" => Ok(PollEvent::Waiting),
        "404" => Ok(PollEvent::Scanned),
        "402" => Ok(PollEvent::Expired),
        "403" => Ok(PollEvent::Rejected),
        "405" => {
            let code = json
                .as_ref()
                .and_then(|v| {
                    v.get("wx_code")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                        .or_else(|| {
                            v.get("wx_redirecturl")
                                .and_then(Value::as_str)
                                .and_then(|u| query_value(u, "code"))
                        })
                })
                .or_else(|| {
                    capture(body, r#"wx_redirecturl\s*=\s*['"]([^'"]+)['"]"#)
                        .and_then(|u| query_value(&u, "code"))
                })
                .ok_or("微信已确认但缺少授权码")?;
            Ok(PollEvent::Confirmed(Credential::WechatCode(code)))
        }
        _ => Err(format!("微信返回未识别状态 {code}")),
    }
}

pub(super) fn parse_qq_poll(body: &str) -> Result<PollEvent, String> {
    let args = capture(body, r#"(?s)ptuiCB\((.*)\)"#).ok_or("QQ 轮询响应格式错误")?;
    let quoted = Regex::new(r#"'((?:\\.|[^'\\])*)'"#).expect("static regex");
    let fields: Vec<_> = quoted
        .captures_iter(&args)
        .map(|c| decode_web_string(&c[1]))
        .collect();
    match fields.first().map(String::as_str) {
        Some("66") => Ok(PollEvent::Waiting),
        Some("67") => Ok(PollEvent::Scanned),
        Some("65") => Ok(PollEvent::Expired),
        Some("68" | "403") => Ok(PollEvent::Rejected),
        Some("0") => {
            let redirect = fields.get(2).ok_or("QQ 已确认但缺少跳转地址")?;
            let openid = query_value(redirect, "openid")
                .filter(|s| !s.is_empty())
                .ok_or("QQ 已确认但缺少 openid")?;
            let access_token = query_value(redirect, "access_token")
                .filter(|s| !s.is_empty())
                .ok_or("QQ 已确认但缺少 access_token")?;
            let pay_token = query_value(redirect, "pay_token").unwrap_or_default();
            Ok(PollEvent::Confirmed(Credential::Qq {
                openid,
                access_token,
                pay_token,
            }))
        }
        Some(status) => Err(format!("QQ 返回未识别状态 {status}")),
        None => Err("QQ 轮询缺少状态码".into()),
    }
}

pub(super) fn build_auth_url(
    config: &MsdkConfig,
    channel: u8,
    seq: &str,
    ts: i64,
    body: &str,
) -> String {
    let version = &config.msdk_version;
    let query = format!("channelid={channel}&from=msdkpix&gameid={}&lang=&os=1&seq={seq}&store_channel=0&ts={ts}&version={version}", config.game_id);
    let mut md5 = Md5::new();
    md5.update(b"/v2/auth/login?");
    md5.update(query.as_bytes());
    md5.update(config.sdk_key.expose_secret().as_bytes());
    md5.update(body.as_bytes());
    let signature = format!("{:x}1", md5.finalize());
    format!(
        "{}/v2/auth/login?{query}&sig={signature}",
        config.msdk_url.trim_end_matches('/')
    )
}

pub(super) fn parse_msdk_response(body: &str) -> Result<MsdkCredentials, String> {
    let json: Value = serde_json::from_str(body).map_err(|_| "MSDK 响应不是 JSON")?;
    let ret = json
        .get("ret")
        .or_else(|| json.get("retCode"))
        .and_then(Value::as_i64)
        .ok_or("MSDK 响应没有结果码")?;
    if ret != 0 {
        let reason = json
            .get("msg")
            .or_else(|| json.get("retMsg"))
            .or_else(|| json.get("message"))
            .and_then(Value::as_str)
            .map(redact_auth_message)
            .unwrap_or_default();
        return Err(if reason.is_empty() {
            format!("MSDK 登录失败，结果码 {ret}")
        } else {
            format!("MSDK 登录失败，结果码 {ret}：{reason}")
        });
    }
    let openid = json
        .get("openid")
        .or_else(|| json.get("openID"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("MSDK 响应缺少 openid")?
        .to_owned();
    let token = json
        .get("token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or("MSDK 响应缺少 token")?
        .to_owned();
    let channel_id = json
        .get("channel_id")
        .or_else(|| json.get("channelID"))
        .and_then(Value::as_u64)
        .and_then(|n| u8::try_from(n).ok())
        .ok_or("MSDK 响应缺少渠道")?;
    Ok(MsdkCredentials {
        openid,
        token,
        channel_id,
    })
}

pub(super) fn redact_auth_message(message: &str) -> String {
    let fields = Regex::new(r#"(?i)\b(?:openid|open_id|access_token|pay_token|refresh_token|token|code|wx_code|pf_key|pfkey|sdk_key|sig|cookie)\b[\s"']*[:=][\s"']*(?:[^\s,;&}"']+)"#).expect("static regex");
    let urls = Regex::new(r#"(?i)https?://[^\s<>"']+"#).expect("static regex");
    let opaque = Regex::new(r"[a-zA-Z0-9_+/=%.-]{24,}").expect("static regex");
    let clean = fields.replace_all(message, "[凭据已隐藏]");
    let clean = urls.replace_all(&clean, "[地址已隐藏]");
    let clean = opaque.replace_all(&clean, "[凭据已隐藏]");
    clean
        .chars()
        .filter(|c| !c.is_control())
        .take(240)
        .collect()
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Credential([REDACTED])")
    }
}
impl Drop for Credential {
    fn drop(&mut self) {
        match self {
            Self::WechatCode(code) => code.zeroize(),
            Self::Qq {
                openid,
                access_token,
                pay_token,
            } => {
                openid.zeroize();
                access_token.zeroize();
                pay_token.zeroize();
            }
        }
    }
}
pub(super) fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn extract_qq_xlogin_url(html: &str) -> Result<Url, String> {
    let raw = capture(html, r#"(?is)\bsrc\s*[:=]\s*["']([^"']+)["']"#)
        .ok_or("QQ 授权页面没有登录地址")?;
    Url::parse(&decode_web_string(&raw)).map_err(|_| "QQ 登录地址无效".into())
}

pub(super) fn decode_web_string(raw: &str) -> String {
    let escapes =
        Regex::new(r#"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|([\\/'"]))"#).expect("static regex");
    let decoded = escapes.replace_all(raw, |c: &regex::Captures<'_>| {
        if let Some(ch) = c.get(3) {
            return ch.as_str().to_owned();
        }
        let digits = c.get(1).or_else(|| c.get(2)).expect("escape digits");
        u32::from_str_radix(digits.as_str(), 16)
            .ok()
            .and_then(char::from_u32)
            .map(|ch| ch.to_string())
            .unwrap_or_else(|| c[0].to_owned())
    });
    decoded
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
}

pub(super) fn extract_qq_qrshow_url(html: &str, xlogin: &Url, app_id: &str) -> Result<Url, String> {
    let target = capture(html, r#"(?is)<img[^>]*src=["']([^"']*ptqrshow[^"']*)["']"#)
        .unwrap_or_else(|| {
            let mut fallback =
                Url::parse("https://xui.ptlogin2.qq.com/ssl/ptqrshow").expect("static URL");
            fallback.query_pairs_mut().extend_pairs([
                ("s", "8"),
                ("e", "0"),
                ("appid", "716027609"),
                ("type", "0"),
                ("t", "0.5"),
                ("daid", "381"),
                ("pt_3rd_aid", app_id),
            ]);
            fallback.to_string()
        });
    let url = xlogin
        .join(&target.replace("&amp;", "&"))
        .map_err(|_| "QQ 二维码地址无效")?;
    if url.host_str() != Some("xui.ptlogin2.qq.com") {
        return Err("QQ 二维码地址域名异常".into());
    }
    Ok(url)
}

pub(super) fn qq_hash33(value: &str) -> i32 {
    value.bytes().fold(0_i32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(i32::from(byte))
    }) & 0x7fff_ffff
}

pub(super) fn qr_data_uri(image: &[u8]) -> Result<String, String> {
    let mime = crate::image::image_mime(image).ok_or("扫码服务返回了不支持的二维码图片格式")?;
    Ok(format!("data:{mime};base64,{}", BASE64.encode(image)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_request_uses_the_endpoint_passed_to_the_builder() {
        for endpoint in [
            "https://region.example.test:8443/",
            "https://other.example.test",
        ] {
            let config = MsdkConfig::builder(
                endpoint,
                "777",
                "synthetic-sdk-key",
                "1001",
                "com.example.game",
            )
            .wechat("wx0123456789abcdef")
            .build()
            .unwrap();
            let request = url::Url::parse(&build_auth_url(&config, 1, "seq", 123, "{}")).unwrap();
            assert_eq!(
                request.origin(),
                url::Url::parse(endpoint).unwrap().origin()
            );
            assert_eq!(request.path(), "/v2/auth/login");
        }
    }

    fn config_from_ini(input: &str) -> Result<MsdkConfig, crate::LoginError> {
        MsdkConfig::from_ini(&format!("{input}\nPACKAGE_NAME=com.example.test\nAPP_SIGNATURE_MD5=0123456789abcdef0123456789abcdef\nMSDK_VERSION=5.42.102.7425"))
    }

    #[test]
    fn config_uses_the_roco_product_fields() {
        let config = config_from_ini(
            "MSDK_URL=https://itop.qq.com\nMSDK_GAME_ID = 27819\nMSDK_SDK_KEY = test-key\nMSDK_CHANNEL_DIS = 10159208\nWECHAT_APP_ID = wx-roco\nQQ_APP_ID = 1110613799\n",
        )
        .unwrap();
        assert_eq!(config.game_id, "27819");
        assert_eq!(config.wechat_app_id, "wx-roco");
        assert_eq!(config.qq_app_id, "1110613799");
        assert_eq!(config.msdk_url, "https://itop.qq.com");
    }

    #[test]
    fn wechat_qr_page_yields_uuid_and_image_url() {
        let html = r#"<script>var QR = {uuid : "0123456789abcdef"};</script><img class="auth_qrcode" src="https://open.weixin.qq.com/connect/qrcode/qr-id" />"#;
        let (uuid, image) = parse_wechat_begin(html).unwrap();
        assert_eq!(uuid, "0123456789abcdef");
        assert_eq!(image, "https://open.weixin.qq.com/connect/qrcode/qr-id");
    }

    #[test]
    fn wechat_confirmed_poll_extracts_code_from_redirect() {
        let event = parse_wechat_poll(
            r#"window.wx_errcode=405;window.wx_redirecturl='https://example.test/callback?code=wx-code&state=weixin';"#,
        )
        .unwrap();
        assert_eq!(
            event,
            PollEvent::Confirmed(Credential::WechatCode("wx-code".into()))
        );
        assert_eq!(
            parse_wechat_poll("window.wx_errcode=408;").unwrap(),
            PollEvent::Waiting
        );
        assert_eq!(
            parse_wechat_poll("window.wx_errcode=404;").unwrap(),
            PollEvent::Scanned
        );
    }

    #[test]
    fn qq_confirmed_poll_extracts_tokens_from_fragment() {
        let event = parse_qq_poll("ptuiCB('0','0','https://qq.test/proxy?#&openid=qq-open&access_token=qq-token&pay_token=qq-pay','0','ok','nick')").unwrap();
        assert_eq!(
            event,
            PollEvent::Confirmed(Credential::Qq {
                openid: "qq-open".into(),
                access_token: "qq-token".into(),
                pay_token: "qq-pay".into()
            })
        );
        assert_eq!(
            parse_qq_poll("ptuiCB('66','0','','0','waiting','')").unwrap(),
            PollEvent::Waiting
        );
        assert_eq!(
            parse_qq_poll("ptuiCB('65','0','','0','expired','')").unwrap(),
            PollEvent::Expired
        );
    }

    #[test]
    fn qq_confirmed_callback_decodes_javascript_hex_escapes() {
        let body = r#"ptuiCB('0','0','https\x3A\x2F\x2Fimgcache.qq.com\x2Fproxy.htm\x3F\x23\x26openid\x3Dqq-open\x26access_token\x3Dtoken%2Bpart\x26pay_token\x3Dpay-token','0','ok','nickname')"#;
        assert_eq!(
            parse_qq_poll(body).unwrap(),
            PollEvent::Confirmed(Credential::Qq {
                openid: "qq-open".into(),
                access_token: "token+part".into(),
                pay_token: "pay-token".into()
            })
        );
    }

    #[test]
    fn qq_token_can_be_in_query_before_a_fragment() {
        let body = "ptuiCB('0','0','auth://tauth.qq.com/?openid=qq-open&access_token=qq-token#done','0','ok','nickname')";
        assert_eq!(
            parse_qq_poll(body).unwrap(),
            PollEvent::Confirmed(Credential::Qq {
                openid: "qq-open".into(),
                access_token: "qq-token".into(),
                pay_token: String::new()
            })
        );
    }

    #[test]
    fn msdk_auth_signs_plaintext_body_in_query_order() {
        let config = config_from_ini(
            "MSDK_URL=https://itop.qq.com\nMSDK_GAME_ID=27819\nMSDK_SDK_KEY=test-key\nMSDK_CHANNEL_DIS=10159208\nWECHAT_APP_ID=wx-roco\nQQ_APP_ID=1110613799\n",
        ).unwrap();
        let body = r#"{"channel_info":{"code":"abc"}}"#;
        let url = build_auth_url(&config, 1, "seq1", 1_234_567_890, body);
        assert_eq!(url, "https://itop.qq.com/v2/auth/login?channelid=1&from=msdkpix&gameid=27819&lang=&os=1&seq=seq1&store_channel=0&ts=1234567890&version=5.42.102.7425&sig=e90119dc76d91a6d5acbcf0a739354be1");
        assert!(!url.contains("encrypt="));
    }

    #[test]
    fn failed_msdk_exchange_cannot_become_authenticated() {
        assert!(parse_msdk_response(r#"{"ret":7,"msg":"bad signature"}"#).is_err());
        assert!(parse_msdk_response(r#"{"ret":0,"openid":"account"}"#).is_err());
        let credentials = parse_msdk_response(
            r#"{"ret":0,"openid":"account","token":"msdk-token","channel_id":1}"#,
        )
        .unwrap();
        assert_eq!(credentials.openid, "account");
        assert_eq!(credentials.channel_id, 1);
    }

    #[test]
    fn qq_authorize_page_decodes_hex_escaped_xlogin_url() {
        let html = r#"<script>var src = "https\x3A\x2F\x2Fxui.ptlogin2.qq.com\x2Fcgi-bin\x2Fxlogin\x3Fappid\x3D716027609\x26pt_3rd_aid\x3D1110613799";</script>"#;
        let url = extract_qq_xlogin_url(html).unwrap();
        assert_eq!(
            url.as_str(),
            "https://xui.ptlogin2.qq.com/cgi-bin/xlogin?appid=716027609&pt_3rd_aid=1110613799"
        );
    }

    #[test]
    fn qr_data_uri_preserves_jpeg_content_type() {
        let uri = qr_data_uri(&[0xff, 0xd8, 0xff, 0xe0, 0x00]).unwrap();
        assert!(uri.starts_with("data:image/jpeg;base64,"));
    }

    #[test]
    fn msdk_error_retains_reason_but_redacts_credentials() {
        let error = parse_msdk_response(r#"{"ret":1401,"msg":"channel error openid=abc123 token=secret-value access_token=secret-access"}"#).err().unwrap();
        assert!(error.contains("1401"));
        assert!(error.contains("channel error"));
        assert!(!error.contains("abc123"));
        assert!(!error.contains("secret-value"));
        assert!(!error.contains("secret-access"));
    }
}
