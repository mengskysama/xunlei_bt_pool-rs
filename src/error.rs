use thiserror::Error;

/// Core error type for the Xunlei BT pool client.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid infohash hex string: {0}")]
    InvalidInfohash(String),
    
    #[error("Infohash must be 40 hex chars (20 bytes), got {0}")]
    InvalidInfohashLength(usize),

    #[error("AES decrypt error: {0}")]
    AesDecrypt(String),

    #[error("RSA encryption failed: {0}")]
    RsaEncrypt(String),

    #[error("HTTP request error: {0}")]
    Http(#[from] ureq::Error),

    #[error("HTTP response validation error: {0}")]
    HttpResponse(String),

    #[error("HTTP response too short: {0} bytes")]
    HttpResponseTooShort(usize),

    #[error("Server returned error: status={0}")]
    ServerError(i32),

    #[error("Invalid bencode/torrent data")]
    InvalidBencode,
}

pub type Result<T> = std::result::Result<T, Error>;
