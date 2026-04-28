use super::*;

#[test]
fn instance_url_preserves_base_path_prefix() {
    let base = Url::parse("https://cloud1.beerloga.su/rust-ws-exporter").unwrap();
    let url = instance_url(&base, "/control/summary").unwrap();
    assert_eq!(
        url.as_str(),
        "https://cloud1.beerloga.su/rust-ws-exporter/control/summary"
    );
}
