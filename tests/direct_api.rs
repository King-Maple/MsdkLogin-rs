use msdk_login::{Channel, MsdkConfig, MsdkLogin};

fn builder(msdk_url: &str) -> msdk_login::MsdkConfigBuilder {
    MsdkConfig::builder(
        msdk_url,
        "1234",
        "synthetic-sdk-key",
        "demo-channel",
        "com.example.demo",
    )
    .qq("123456", "0123456789abcdef0123456789abcdef")
    .wechat("wx0123456789abcdef")
}

#[tokio::test]
async fn direct_parameters_create_client_and_result_lifecycle_needs_no_files() {
    let config = builder("https://login.example.test").build().unwrap();
    assert_eq!(
        config.app_config().sdk_version.as_deref(),
        Some("5.42.102.7425")
    );
    assert!(!format!("{config:?}").contains("synthetic-sdk-key"));
    let login = MsdkLogin::new(config).unwrap();
    assert!(login.get_result("missing-session").await.is_none());
    login.cancel("missing-session").await;
    assert!(login.poll("missing-session").await.is_err());

    let wechat_only = MsdkConfig::builder(
        "https://login.example.test",
        "1234",
        "test-key",
        "channel",
        "com.example.demo",
    )
    .wechat("wx0123456789abcdef")
    .build()
    .unwrap();
    let login = MsdkLogin::new(wechat_only).unwrap();
    // Missing channel must fail locally, before any provider requests.
    assert!(login.get_qrcode(Channel::Qq).await.is_err());
}

#[test]
fn optional_settings_override_defaults_and_share_validation() {
    let config = builder("https://login.example.test/")
        .msdk_version("5.43.1")
        .qq_sdk_version("3.5.19")
        .build()
        .unwrap();
    assert_eq!(config.app_config().sdk_version.as_deref(), Some("5.43.1"));
    assert!(builder("https://login.example.test")
        .msdk_version("5&sig=other")
        .build()
        .is_err());
    assert!(builder("https://login.example.test")
        .qq_sdk_version("")
        .build()
        .is_err());
    assert!(MsdkConfig::builder(
        "https://login.example.test",
        "1234",
        "",
        "channel",
        "com.example.demo"
    )
    .wechat("wx-demo")
    .build()
    .is_err());
    assert!(MsdkConfig::builder(
        "https://login.example.test",
        "1234",
        "key",
        "channel",
        "com.example.demo"
    )
    .build()
    .is_err());
    assert!(MsdkConfig::builder(
        "https://login.example.test",
        "1234",
        "key",
        "channel",
        "com.example.demo"
    )
    .qq("123", "bad")
    .build()
    .is_err());
    assert!(MsdkConfig::builder(
        "https://login.example.test",
        "1234",
        "key",
        "channel",
        "com.example.demo"
    )
    .qq("", "0123456789abcdef0123456789abcdef")
    .wechat("wx-demo")
    .build()
    .is_err());
}

#[test]
fn core_endpoint_rejects_missing_or_invalid_values_without_a_fallback() {
    for endpoint in [
        "",
        "not-a-url",
        "http://login.example.test",
        "https://user:password@login.example.test",
        "https://login.example.test/v2/auth/login",
        "https://login.example.test/?token=synthetic",
        "https://login.example.test/#fragment",
    ] {
        assert!(matches!(
            builder(endpoint).build(),
            Err(msdk_login::LoginError::InvalidConfig("MSDK_URL"))
        ));
    }
}
