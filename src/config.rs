use crate::LoginError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Channel {
    Qq,
    Wechat,
}

/// Public identifiers only. Keep official SDK credentials in the adapter, not this DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppConfig {
    pub profile_name: String,
    pub msdk_game_id: String,
    pub sdk_version: Option<String>,
    pub channel_dis: Option<String>,
    pub qq_app_id: Option<String>,
    pub wechat_app_id: Option<String>,
}

impl AppConfig {
    pub fn validate(&self) -> Result<(), LoginError> {
        for (field, value) in [
            ("profile_name", self.profile_name.as_str()),
            ("msdk_game_id", self.msdk_game_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        for (field, value) in [
            ("sdk_version", &self.sdk_version),
            ("channel_dis", &self.channel_dis),
            ("qq_app_id", &self.qq_app_id),
            ("wechat_app_id", &self.wechat_app_id),
        ] {
            if let Some(value) = value {
                validate_identifier(field, value)?;
            }
        }
        if self.qq_app_id.is_none() && self.wechat_app_id.is_none() {
            return Err(LoginError::InvalidConfig("at_least_one_channel"));
        }
        Ok(())
    }

    pub fn app_id(&self, channel: Channel) -> Result<&str, LoginError> {
        let value = match channel {
            Channel::Qq => &self.qq_app_id,
            Channel::Wechat => &self.wechat_app_id,
        };
        value
            .as_deref()
            .ok_or(LoginError::ChannelNotConfigured(channel))
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), LoginError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        Err(LoginError::InvalidConfig(field))
    } else {
        Ok(())
    }
}
