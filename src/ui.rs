use std::io::{self, Write};
use std::sync::{Mutex, MutexGuard};

use colored::control;
use colored::{ColoredString, Colorize};

use crate::config::Settings;

static STDERR: Mutex<()> = Mutex::new(());

pub struct Ui {
    color: bool,
}

impl Ui {
    pub fn new(no_color: bool) -> Self {
        if no_color {
            control::set_override(false);
        }
        Self { color: !no_color }
    }

    pub fn from_settings(settings: &Settings) -> Self {
        Self::new(settings.no_color)
    }

    pub fn color_enabled(&self) -> bool {
        self.color
    }

    fn stderr_lock(&self) -> io::Result<MutexGuard<'static, ()>> {
        STDERR
            .lock()
            .map_err(|_| io::Error::other("stderr lock poisoned"))
    }

    pub fn warn(&self, msg: &str) {
        let _ = self.write_line(&format!("Warning: {msg}"), |s| s.yellow());
    }

    pub fn error(&self, msg: &str) {
        let _ = self.write_line(&format!("Error: {msg}"), |s| s.red().bold());
    }

    pub fn info(&self, msg: &str) {
        let _ = self.write_line(msg, |s| s.cyan());
    }

    pub fn success(&self, msg: &str) {
        let _ = self.write_line(msg, |s| s.green());
    }

    pub fn jsonl_line(&self, line: &str) -> String {
        if self.color {
            line.truecolor(102, 204, 255).to_string()
        } else {
            line.to_string()
        }
    }

    fn write_line<F>(&self, msg: &str, colorize: F) -> io::Result<()>
    where
        F: FnOnce(&str) -> ColoredString,
    {
        let _guard = self.stderr_lock()?;
        let mut stderr = io::stderr().lock();
        if self.color {
            writeln!(stderr, "{}", colorize(msg))?;
        } else {
            writeln!(stderr, "{msg}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_settings(no_color: bool) -> Settings {
        Settings {
            bind: "127.0.0.1".parse().unwrap(),
            port: None,
            body_limit: 256,
            filter: String::new(),
            ca_dir: PathBuf::from("/tmp/guardian-test"),
            silent: false,
            no_color,
            port_min: 1024,
            port_max: 65535,
            proxy_event_channel_capacity: 10_000,
            proxy_ready_timeout_secs: 5,
            proxy_ready_poll_ms: 10,
            process_poll_interval_ms: 50,
            ca_bundle_name: "guardian-ca-bundle.pem".into(),
            java_truststore_name: "guardian-java-truststore.p12".into(),
            java_truststore_password: "guardian".into(),
            deno_tls_ca_store: "system,mozilla".into(),
            node_options_append: "--use-openssl-ca".into(),
            tracing_prefix: "guardian: ".into(),
            tracing_default_level: "guardian=debug".into(),
            program: String::new(),
            args: vec![],
            trust_stores: vec!["system".into(), "nss".into(), "java".into()],
        }
    }

    #[test]
    fn jsonl_line_no_color_is_plain() {
        let ui = Ui::from_settings(&test_settings(true));
        assert_eq!(ui.jsonl_line(r#"{"type":"http"}"#), r#"{"type":"http"}"#);
    }

    #[test]
    fn jsonl_line_with_color_has_ansi() {
        control::set_override(true);
        let ui = Ui::new(false);
        let line = ui.jsonl_line("{}");
        assert!(line.contains('\x1b'), "expected ANSI escapes");
        control::unset_override();
    }
}
