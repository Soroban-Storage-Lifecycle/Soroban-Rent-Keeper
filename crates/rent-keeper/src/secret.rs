//! Secret-string wrapper that redacts `Debug` output.

/// Wraps a fee-payer secret so accidental logging cannot leak it.
///
/// `Debug` and `Display` print `[redacted]`; the raw value is only reachable
/// through [`SecretString::expose_secret`], which greps can audit.
#[derive(Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    /// Wraps a raw secret.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Accesses the raw secret. Keep call sites minimal and never log them.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "SBFIJNQVTU3QZGZSVAHBQFAKHRGFNIHQMIVJJSGV7HRPC7CLBR7QZL7VYP";

    #[test]
    fn debug_output_is_redacted() {
        let secret = SecretString::new(SECRET.to_string());
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "[redacted]");
        assert!(!rendered.contains('S'));
    }

    #[test]
    fn display_output_is_redacted() {
        let secret = SecretString::new(SECRET.to_string());
        assert_eq!(secret.to_string(), "[redacted]");
        assert!(!secret.to_string().contains(SECRET));
    }

    #[test]
    fn expose_gives_raw_value() {
        let secret = SecretString::new(SECRET.to_string());
        assert_eq!(secret.expose_secret(), SECRET);
    }
}
