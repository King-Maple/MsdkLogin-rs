use msdk_login::http::{MsdkConfig, QrLoginService};

fn settings() -> String {
    [
        "MSDK_URL=https://login.example.test",
        "MSDK_GAME_ID=1234",
        "MSDK_SDK_KEY=synthetic-private-key",
        "MSDK_CHANNEL_DIS=demo-channel",
        "MSDK_VERSION=5.42.102.7425",
        "PACKAGE_NAME=com.example.demo",
        "APP_SIGNATURE_MD5=0123456789abcdef0123456789abcdef",
        "QQ_APP_ID=123456",
        "WECHAT_APP_ID=wx0123456789abcdef",
    ]
    .join("\n")
}

#[test]
fn product_config_is_required_and_diagnostics_hide_credentials() {
    let config = MsdkConfig::from_ini(&settings()).unwrap();
    assert_eq!(config.app_config().qq_app_id.as_deref(), Some("123456"));
    assert!(!format!("{config:?}").contains("synthetic-private-key"));
    QrLoginService::new(config).unwrap();
    for field in [
        "MSDK_URL",
        "MSDK_SDK_KEY",
        "PACKAGE_NAME",
        "APP_SIGNATURE_MD5",
        "MSDK_VERSION",
        "MSDK_CHANNEL_DIS",
    ] {
        let input = settings()
            .lines()
            .filter(|line| !line.starts_with(&format!("{field}=")))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(MsdkConfig::from_ini(&input).is_err(), "{field}");
    }
}

#[test]
fn configuration_rejects_unsafe_endpoint_and_conflicting_values() {
    for endpoint in [
        "http://login.example.test",
        "https://user:password@login.example.test",
        "https://login.example.test/?token=private",
    ] {
        assert!(
            MsdkConfig::from_ini(&settings().replace("https://login.example.test", endpoint))
                .is_err()
        );
    }
    assert!(MsdkConfig::from_ini(&(settings() + "\nQQ_APP_ID=999999")).is_err());
    assert!(MsdkConfig::from_ini(
        &settings().replace("MSDK_GAME_ID=1234", "MSDK_GAME_ID=1234&os=2")
    )
    .is_err());
    assert!(MsdkConfig::from_ini(
        &settings().replace("MSDK_VERSION=5.42.102.7425", "MSDK_VERSION=5&sig=other")
    )
    .is_err());
}

#[test]
fn projects_use_their_own_parameters() {
    let a = MsdkConfig::from_ini(&settings()).unwrap();
    let b = MsdkConfig::from_ini(
        &settings()
            .replace("123456", "987654")
            .replace("1234\n", "5678\n"),
    )
    .unwrap();
    assert_ne!(a.app_config().msdk_game_id, b.app_config().msdk_game_id);
    assert_ne!(a.app_config().qq_app_id, b.app_config().qq_app_id);
}
