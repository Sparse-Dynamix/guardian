//! Minimal sleep helper for smoke/interrupt tests (Frida-safe on macOS ARM64).

use std::time::Duration;

fn main() {
    let secs = std::env::args()
        .nth(1)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);
    std::thread::sleep(Duration::from_secs(secs));
}
