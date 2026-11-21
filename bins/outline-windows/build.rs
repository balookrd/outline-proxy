fn main() {
    let channel = std::env::var("OUTLINE_BUILD_CHANNEL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nightly".to_string());

    let commit = std::env::var("OUTLINE_BUILD_COMMIT")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "--short", "HEAD"])
                .output()
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| String::from_utf8(out.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "dev".to_string())
        });

    println!("cargo:rustc-env=OUTLINE_BUILD_CHANNEL={channel}");
    println!("cargo:rustc-env=OUTLINE_BUILD_COMMIT={commit}");
    println!("cargo:rerun-if-env-changed=OUTLINE_BUILD_CHANNEL");
    println!("cargo:rerun-if-env-changed=OUTLINE_BUILD_COMMIT");

    tauri_build::build();
}
