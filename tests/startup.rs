use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use serial_test::serial;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test]
#[serial]
async fn boots_without_config_and_uses_port_environment_variable() {
    let Ok(database_url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let binary = std::env::var("CARGO_BIN_EXE_paystack-fanout").unwrap();
    let port = 18081u16;
    let child = Command::new(binary)
        .args(["--role", "ingest"])
        .env("DATABASE_URL", database_url)
        .env_remove("FANOUT_CONFIG")
        .env("PAYSTACK_SECRET_KEY", "sk_test_startup")
        .env(
            "FANOUT_ENCRYPTION_KEY",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .env("PORT", port.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = ChildGuard(child);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{port}/readyz");
    let mut ready = false;
    for _ in 0..120 {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            ready = true;
            break;
        }
        if child.0.try_wait().unwrap().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "service did not become ready on PORT={port}");
}
