//! Hash helpers shared across crates.

/// Lowercase hex SHA-256 digest of `bytes` (64 characters).
pub fn sha256_hex(bytes: &[u8]) -> String {
    use ring::digest::{SHA256, digest};

    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = digest(&SHA256, bytes);
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for &byte in digest.as_ref() {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
