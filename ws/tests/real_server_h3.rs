#[path = "support/proxy_test_utils.rs"]
mod proxy_test_utils;

#[test]
fn tcp_connect_over_real_h3_server() -> Result<(), Box<dyn std::error::Error>> {
    proxy_test_utils::run_tcp_connect_test("RUN_REAL_SERVER_H3", "h3", "h3", "H3")
}

#[test]
fn udp_associate_over_real_h3_server() -> Result<(), Box<dyn std::error::Error>> {
    proxy_test_utils::run_udp_associate_test("RUN_REAL_SERVER_H3", "h3", "h3", "H3")
}
