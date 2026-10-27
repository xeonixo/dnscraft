//! Secret loading from environment variables and Docker `*_FILE` secrets.
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

/// An opaque secret value that never appears in [`Debug`] output and is wiped on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps an already-loaded secret string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The secret bytes as a string slice. Callers must not log this or copy it
    /// into a plain [`String`] unless the copy is also zeroized.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self(Zeroizing::new(String::new()))
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("redacted")
    }
}

/// Reads a secret from `name` or `{name}_FILE`.
///
/// Resolution order:
/// 1. `{name}_FILE` — path to a file whose contents are the secret (Docker secrets).
/// 2. `name` — the environment variable value.
///
/// Leading and trailing whitespace is trimmed. An empty result after trim is
/// treated as missing — returns `Err(name)` on failure.
pub fn read_secret(name: &str) -> Result<Secret, String> {
    let file_var = format!("{name}_FILE");
    let file_path = std::env::var(&file_var).ok();
    let env_value = std::env::var(name).ok();
    read_secret_parts(name, env_value.as_deref(), file_path.as_deref(), |path| {
        fs::read_to_string(path)
    })
}

/// Core secret resolution used by [`read_secret`] and by tests (no process
/// environment mutation).
pub fn read_secret_parts(
    name: &str,
    env_value: Option<&str>,
    file_path: Option<&str>,
    read_file: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Secret, String> {
    if let Some(path) = file_path.map(str::trim).filter(|p| !p.is_empty()) {
        let contents = read_file(Path::new(path)).map_err(|_| name.to_owned())?;
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Err(name.to_owned());
        }
        return Ok(Secret::new(trimmed));
    }
    match env_value {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(name.to_owned())
            } else {
                Ok(Secret::new(trimmed))
            }
        }
        None => Err(name.to_owned()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("super-secret-token-value");
        let shown = format!("{s:?}");
        assert_eq!(shown, "Secret([redacted])");
        assert!(!shown.contains("super-secret"));
        assert_eq!(s.expose(), "super-secret-token-value");
    }

    #[test]
    fn read_secret_from_env_value() {
        let s = read_secret_parts("DNSCRAFT_TEST", Some("  tok-from-env  "), None, |_| {
            panic!("file should not be read")
        })
        .expect("secret from env");
        assert_eq!(s.expose(), "tok-from-env");
    }

    #[test]
    fn read_secret_from_file_path() {
        let dir = std::env::temp_dir().join("dnscraft-common-secret-test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("token");
        std::fs::write(&path, "  file-token\n").unwrap();
        let s = read_secret_parts(
            "DNSCRAFT_TEST",
            Some("ignored-when-file-set"),
            Some(path.to_str().unwrap()),
            |p| std::fs::read_to_string(p),
        )
        .expect("secret from file");
        assert_eq!(s.expose(), "file-token");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_secret_missing() {
        let err = read_secret_parts("DNSCRAFT_TEST_MISSING", None, None, |_| panic!("no file"))
            .expect_err("must be missing");
        assert_eq!(err, "DNSCRAFT_TEST_MISSING");
    }

    #[test]
    fn read_secret_empty_env_is_missing() {
        let err = read_secret_parts("X", Some("   "), None, |_| unreachable!()).expect_err("empty");
        assert_eq!(err, "X");
    }

    #[test]
    fn read_secret_empty_file_is_missing() {
        let err = read_secret_parts("X", None, Some("/tmp/x"), |_| Ok("  \n".into()))
            .expect_err("empty file");
        assert_eq!(err, "X");
    }

    #[test]
    fn read_secret_missing_file_is_missing() {
        let err = read_secret_parts("X", None, Some("/no/such/token"), |_| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"))
        })
        .expect_err("missing file");
        assert_eq!(err, "X");
    }
}
