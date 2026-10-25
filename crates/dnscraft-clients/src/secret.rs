//! Secret loading from environment variables and Docker `*_FILE` secrets.

use std::fmt;
use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use crate::error::ClientsError;

/// Environment variable holding the UniFi Network Integration API key.
pub const UNIFI_API_KEY_ENV: &str = "DNSCRAFT_UNIFI_API_KEY";

/// An opaque secret value that never appears in [`Debug`] output and is wiped
/// from memory on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps an already-loaded secret string.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// The secret bytes as a string slice. Callers must not log this.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// Reads a secret from `name` or `{name}_FILE`.
///
/// Resolution order:
/// 1. `{name}_FILE` — path to a file whose contents are the secret (Docker secrets).
/// 2. `name` — the environment variable value.
///
/// Leading and trailing whitespace is trimmed. An empty result after trim is
/// treated as missing ([`ClientsError::SecretMissing`]).
pub fn read_secret(name: &str) -> Result<Secret, ClientsError> {
    let file_var = format!("{name}_FILE");
    let file_path = std::env::var(&file_var).ok();
    let env_value = std::env::var(name).ok();
    read_secret_parts(name, env_value.as_deref(), file_path.as_deref(), |path| {
        fs::read_to_string(path)
    })
}

/// Core secret resolution used by [`read_secret`] and by tests (no process
/// environment mutation — the workspace forbids `unsafe`, and `set_var` is
/// unsafe on current Rust).
pub(crate) fn read_secret_parts(
    name: &str,
    env_value: Option<&str>,
    file_path: Option<&str>,
    read_file: impl Fn(&Path) -> std::io::Result<String>,
) -> Result<Secret, ClientsError> {
    if let Some(path) = file_path.map(str::trim).filter(|p| !p.is_empty()) {
        let contents = Zeroizing::new(read_file(Path::new(path)).map_err(|_| {
            ClientsError::SecretMissing {
                name: name.to_owned(),
            }
        })?);
        let trimmed = contents.trim();
        if trimmed.is_empty() {
            return Err(ClientsError::SecretMissing {
                name: name.to_owned(),
            });
        }
        return Ok(Secret::new(trimmed));
    }
    match env_value {
        Some(value) => {
            let owned = Zeroizing::new(value.to_owned());
            let trimmed = owned.trim();
            if trimmed.is_empty() {
                Err(ClientsError::SecretMissing {
                    name: name.to_owned(),
                })
            } else {
                Ok(Secret::new(trimmed))
            }
        }
        None => Err(ClientsError::SecretMissing {
            name: name.to_owned(),
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_is_redacted() {
        let s = Secret::new("super-secret-api-key-value");
        let shown = format!("{s:?}");
        assert_eq!(shown, "Secret([redacted])");
        assert!(!shown.contains("super-secret"));
        assert_eq!(s.expose(), "super-secret-api-key-value");
    }

    #[test]
    fn read_secret_from_env_value() {
        let s = read_secret_parts("DNSCRAFT_TEST", Some("  key-from-env  "), None, |_| {
            panic!("file should not be read")
        })
        .expect("secret from env");
        assert_eq!(s.expose(), "key-from-env");
    }

    #[test]
    fn read_secret_from_file_path() {
        let dir = std::env::temp_dir().join("dnscraft-clients-secret-test");
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("token");
        fs::write(&path, "  file-key\n").unwrap();
        let s = read_secret_parts(
            "DNSCRAFT_TEST",
            Some("ignored-when-file-set"),
            Some(path.to_str().unwrap()),
            |p| fs::read_to_string(p),
        )
        .expect("secret from file");
        assert_eq!(s.expose(), "file-key");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn read_secret_missing() {
        let err = read_secret_parts("DNSCRAFT_TEST_MISSING", None, None, |_| panic!("no file"))
            .expect_err("must be missing");
        assert_eq!(err.code(), "clients.secret.missing");
        assert!(!format!("{err:?}").contains("secret-value"));
    }

    #[test]
    fn read_secret_empty_env_is_missing() {
        let err = read_secret_parts("X", Some("   "), None, |_| unreachable!()).expect_err("empty");
        assert_eq!(err.code(), "clients.secret.missing");
    }
}
