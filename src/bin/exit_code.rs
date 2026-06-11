fn main() {
    let code = std::env::args()
        .nth(1)
        .and_then(|arg| arg.parse::<i32>().ok())
        .unwrap_or(0);
    std::process::exit(code);
}
