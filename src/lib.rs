//! Shared login orchestration and configurable QQ/WeChat/MSDK HTTP adapter.
//! Game parameters and SDK credentials are supplied by the consuming application.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod adapter;
mod config;
mod error;
pub mod http;
mod image;
mod secret;
mod session;

pub use adapter::{AuthTokens, MsdkExchanger, ProviderChallenge, QrProvider, ScanEvent, SdkFuture};
pub use config::{AppConfig, Channel};
pub use error::{LoginError, SdkError, SdkErrorKind};
pub use http::{
    MsdkConfig, MsdkConfigBuilder, MsdkCredentials, QrChallenge, QrLoginService as MsdkLogin,
    QrStatus,
};
pub use secret::SecretString;
pub use session::{LoginClient, LoginSession, LoginState};
