#[path = "support/proxy_test_utils.rs"]
mod proxy_test_utils;

#[test]
fn tcp_connect_over_real_h1_server() -> Result<(), Box<dyn std::error::Error>> {
    proxy_test_utils::run_tcp_connect_test("RUN_REAL_SERVER_H1", "h1", "http1", "H1")
}

#[test]
fn udp_associate_over_real_h1_server() -> Result<(), Box<dyn std::error::Error>> {
    proxy_test_utils::run_udp_associate_test("RUN_REAL_SERVER_H1", "h1", "http1", "H1")
}
