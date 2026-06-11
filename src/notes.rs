use crate::cli::Commands;

pub const LEGAL_NOTES: &str = include_str!("../NOTICE.txt");
pub const LICENSE_NOTES: &str = include_str!("../LICENSE");
pub const SECURITY_NOTES: &str = include_str!("../SECURITY.md");

pub fn print(command: &Commands) {
    let text = match command {
        Commands::LegalNotes => LEGAL_NOTES,
        Commands::LicenseNotes => LICENSE_NOTES,
        Commands::SecurityNotes => SECURITY_NOTES,
        _ => unreachable!("print called with non-notes command"),
    };
    print!("{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_legal_contains_notice_header() {
        assert!(LEGAL_NOTES.contains("PART 1"));
    }

    #[test]
    fn embedded_license_contains_gpl() {
        assert!(LICENSE_NOTES.contains("GNU GENERAL PUBLIC LICENSE"));
    }

    #[test]
    fn embedded_security_contains_model() {
        assert!(SECURITY_NOTES.contains("Security model"));
    }
}
