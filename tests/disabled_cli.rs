//! Disabled CLI commands must not initialize secrets, storage, or network clients.
#[test]
fn standalone_buyback_refuses_without_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_buyback"))
        .env_clear()
        .args([
            "buyback",
            "1",
            "--netuid",
            "100",
            "--treasury-hotkey",
            "unused",
            "--network",
            &format!("ws://{}", listener.local_addr().unwrap()),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("standalone buyback disabled"));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
