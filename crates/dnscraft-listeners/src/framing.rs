//! DNS-over-TCP / DoT / DoQ stream framing (2-byte length prefix, RFC 7766).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum DNS message length on a stream (RFC 7766).
pub const MAX_MESSAGE_LEN: usize = 65_535;

/// Framing / length-prefix errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameError {
    /// Peer closed before any length bytes arrived.
    UnexpectedEof,
    /// Truncated length/body, length 0, or length greater than [`MAX_MESSAGE_LEN`].
    InvalidLength(usize),
    /// Underlying I/O error (stored as display text for `Clone`).
    Io(String),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected EOF in length-prefixed frame"),
            Self::InvalidLength(n) => write!(f, "invalid DNS frame length {n}"),
            Self::Io(s) => write!(f, "frame I/O: {s}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            Self::UnexpectedEof
        } else {
            Self::Io(e.to_string())
        }
    }
}

/// Reads one length-prefixed DNS message.
///
/// A clean peer close with no bytes left → [`FrameError::UnexpectedEof`].
/// A half-written length prefix, truncated body, length 0, or oversize length
/// → [`FrameError::InvalidLength`].
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 2];
    let n = reader.read(&mut len_buf).await?;
    if n == 0 {
        return Err(FrameError::UnexpectedEof);
    }
    if n < 2 {
        match reader.read_exact(&mut len_buf[n..]).await {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(FrameError::InvalidLength(usize::from(len_buf[0]) << 8));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let len = u16::from_be_bytes(len_buf) as usize;
    // `len` is a u16 so it cannot exceed [`MAX_MESSAGE_LEN`] (65 535).
    if len == 0 {
        return Err(FrameError::InvalidLength(len));
    }
    let mut buf = vec![0u8; len];
    match reader.read_exact(&mut buf).await {
        Ok(_) => Ok(buf),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(FrameError::InvalidLength(len)),
        Err(e) => Err(e.into()),
    }
}

/// Writes one length-prefixed DNS message.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> Result<(), FrameError> {
    if message.len() > MAX_MESSAGE_LEN || message.is_empty() {
        return Err(FrameError::InvalidLength(message.len()));
    }
    let len = u16::try_from(message.len()).map_err(|_| FrameError::InvalidLength(message.len()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(message).await?;
    writer.flush().await?;
    Ok(())
}
