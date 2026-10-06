use crate::{AppConfig, LoginError, SecretString};
use std::collections::HashMap;
use url::Url;

/// Complete product settings. Debug redacts the SDK key; no Serialize/Clone.
#[derive(Debug)]
pub struct MsdkConfig {
    pub(super) game_id: String,
    pub(super) sdk_key: SecretString,
    pub(super) channel_dis: String,
    pub(super) wechat_app_id: String,
    pub(super) qq_app_id: String,
    pub(super) msdk_url: String,
    pub(super) package_name: String,
    pub(super) app_signature_md5: String,
    pub(super) msdk_version: String,
    pub(super) qq_sdk_version: String,
}

/// Direct configuration construction. No file or environment access.
#[derive(Debug)]
pub struct MsdkConfigBuilder {
    config: MsdkConfig,
    qq_enabled: bool,
    wechat_enabled: bool,
}

impl MsdkConfig {
    /// Supply the MSDK HTTPS base URL and four product identifiers, then enable QQ and/or WeChat.
    /// The endpoint has no default. SDK version defaults: MSDK 5.42.102.7425, QQ SDK 3.5.18.
    pub fn builder(
        msdk_url: impl Into<String>,
        game_id: impl Into<String>,
        sdk_key: impl Into<String>,
        channel_dis: impl Into<String>,
        package_name: impl Into<String>,
    ) -> MsdkConfigBuilder {
        MsdkConfigBuilder {
            config: Self {
                game_id: game_id.into(),
                sdk_key: SecretString::new(sdk_key),
                channel_dis: channel_dis.into(),
                package_name: package_name.into(),
                qq_app_id: String::new(),
                wechat_app_id: String::new(),
                app_signature_md5: String::new(),
                msdk_url: msdk_url.into(),
                msdk_version: "5.42.102.7425".into(),
                qq_sdk_version: "3.5.18".into(),
            },
            qq_enabled: false,
            wechat_enabled: false,
        }
    }

    /// Compatibility parser only. Prefer `builder` for new integrations.
    /// This method parses supplied text; it never opens a file.
    pub fn from_ini(ini: &str) -> Result<Self, LoginError> {
        let mut values = HashMap::new();
        for line in ini.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(['#', ';', '[']) {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                return Err(LoginError::InvalidConfig("ini_syntax"));
            };
            if let Some(previous) = values.insert(key.trim(), value.trim()) {
                if previous != value.trim() {
                    return Err(LoginError::InvalidConfig("duplicate_field"));
                }
            }
        }
        let required = |key: &'static str| -> Result<String, LoginError> {
            values
                .get(key)
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .ok_or(LoginError::InvalidConfig(key))
        };
        let mut builder = Self::builder(
            required("MSDK_URL")?,
            required("MSDK_GAME_ID")?,
            required("MSDK_SDK_KEY")?,
            required("MSDK_CHANNEL_DIS")?,
            required("PACKAGE_NAME")?,
        )
        .msdk_version(required("MSDK_VERSION")?)
        .qq_sdk_version(values.get("QQ_SDK_VERSION").copied().unwrap_or("3.5.18"));
        if let Some(app_id) = values.get("QQ_APP_ID").filter(|s| !s.is_empty()) {
            builder = builder.qq(*app_id, required("APP_SIGNATURE_MD5")?);
        }
        if let Some(app_id) = values.get("WECHAT_APP_ID").filter(|s| !s.is_empty()) {
            builder = builder.wechat(*app_id);
        }
        builder.build()
    }

    fn validate(mut self) -> Result<Self, LoginError> {
        self.app_config().validate()?;
        let endpoint =
            Url::parse(&self.msdk_url).map_err(|_| LoginError::InvalidConfig("MSDK_URL"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || !matches!(endpoint.path(), "" | "/")
        {
            return Err(LoginError::InvalidConfig("MSDK_URL"));
        }
        self.msdk_url = endpoint.to_string().trim_end_matches('/').to_owned();
        if !self.qq_app_id.is_empty()
            && (self.app_signature_md5.len() != 32
                || !self
                    .app_signature_md5
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()))
        {
            return Err(LoginError::InvalidConfig("APP_SIGNATURE_MD5"));
        }
        self.app_signature_md5.make_ascii_lowercase();
        if !self.game_id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(LoginError::InvalidConfig("MSDK_GAME_ID"));
        }
        for (name, version) in [
            ("MSDK_VERSION", &self.msdk_version),
            ("QQ_SDK_VERSION", &self.qq_sdk_version),
        ] {
            if version.is_empty()
                || version.len() > 64
                || !version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            {
                return Err(LoginError::InvalidConfig(name));
            }
        }
        if self.package_name.split('.').count() < 2
            || !self
                .package_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
        {
            return Err(LoginError::InvalidConfig("PACKAGE_NAME"));
        }
        if self.sdk_key.is_empty() {
            return Err(LoginError::InvalidConfig("MSDK_SDK_KEY"));
        }
        Ok(self)
    }

    pub fn app_config(&self) -> AppConfig {
        AppConfig {
            profile_name: self.package_name.clone(),
            msdk_game_id: self.game_id.clone(),
            sdk_version: Some(self.msdk_version.clone()),
            channel_dis: Some(self.channel_dis.clone()),
            qq_app_id: (!self.qq_app_id.is_empty()).then(|| self.qq_app_id.clone()),
            wechat_app_id: (!self.wechat_app_id.is_empty()).then(|| self.wechat_app_id.clone()),
        }
    }
}

impl MsdkConfigBuilder {
    pub fn qq(mut self, app_id: impl Into<String>, signature_md5: impl Into<String>) -> Self {
        self.qq_enabled = true;
        self.config.qq_app_id = app_id.into();
        self.config.app_signature_md5 = signature_md5.into();
        self
    }
    pub fn wechat(mut self, app_id: impl Into<String>) -> Self {
        self.wechat_enabled = true;
        self.config.wechat_app_id = app_id.into();
        self
    }
    pub fn msdk_version(mut self, version: impl Into<String>) -> Self {
        self.config.msdk_version = version.into();
        self
    }
    pub fn qq_sdk_version(mut self, version: impl Into<String>) -> Self {
        self.config.qq_sdk_version = version.into();
        self
    }
    pub fn build(self) -> Result<MsdkConfig, LoginError> {
        if self.qq_enabled && self.config.qq_app_id.trim().is_empty() {
            return Err(LoginError::InvalidConfig("QQ_APP_ID"));
        }
        if self.wechat_enabled && self.config.wechat_app_id.trim().is_empty() {
            return Err(LoginError::InvalidConfig("WECHAT_APP_ID"));
        }
        self.config.validate()
    }
}
