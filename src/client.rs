use crate::crypto::{aes_decrypt_ecb, aes_encrypt_ecb, build_rsa_header, derive_aes_key, xl_aes_decrypt, xl_aes_encrypt};
use crate::error::{Error, Result};
use crate::protocol::{
    build_query_packet, read_i32_le, read_u32_le, QueryResult, OFFSET_FILE_DATA, OFFSET_FILE_LEN,
    OFFSET_RESULT_QUERY,
};
use std::io::Read;

const USER_AGENT: &str = "AndroidDownloadManager/11 (Linux; U; Android 11; M2004J7AC)";
const SERVER: &str = "pool.bt.n0808.com:11400";

// Decrypt logic is now an instance method on `Client`.

/// Validates that the returned bytes are valid bencode logic.
fn validate_torrent(data: &[u8]) -> Result<()> {
    bt_bencode::from_slice::<bt_bencode::Value>(data).map_err(|_| Error::InvalidBencode)?;
    Ok(())
}

/// Client to interact with the XunLei BT pool.
pub struct Client {
    agent: ureq::Agent,
}

impl Client {
    /// Creates a new instance of the client with a default 10-second timeout.
    pub fn new() -> Self {
        Self {
            agent: ureq::AgentBuilder::new()
                .timeout(std::time::Duration::from_secs(10))
                .build(),
        }
    }

    /// Creates a new instance of the client with a custom timeout.
    pub fn with_timeout(timeout: std::time::Duration) -> Self {
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
        }
    }

    /// Performs the HTTP POST request across the agent.
    fn http_post(&self, server: &str, payload: &[u8]) -> Result<Vec<u8>> {
        let url = format!("http://{}/", server);
        let resp = self
            .agent
            .post(&url)
            .set("User-Agent", USER_AGENT)
            .set("Content-Type", "application/x-www-form-urlencoded")
            .send_bytes(payload)?;

        if resp.status() != 200 {
            return Err(Error::HttpResponse(format!("HTTP {}", resp.status())));
        }

        let mut body = Vec::new();
        resp.into_reader()
            .read_to_end(&mut body)
            .map_err(|e| Error::HttpResponse(e.to_string()))?;

        if body.len() < 4 {
            return Err(Error::HttpResponseTooShort(body.len()));
        }
        Ok(body)
    }

    /// Decrypts the raw HTTP response from the server into a QueryResult.
    fn decrypt_response(&self, response: &[u8], aes_key: &[u8; 16]) -> Result<QueryResult> {
        if response.len() < 4 {
            return Err(Error::HttpResponseTooShort(response.len()));
        }

        let body_len = read_u32_le(response, 0) as usize;
        if body_len == 0 {
            return Err(Error::HttpResponse("Server returned empty body".into()));
        }
        if 4 + body_len > response.len() {
            return Err(Error::HttpResponse("body_len exceeds response size".into()));
        }

        let decrypted = xl_aes_decrypt(&aes_decrypt_ecb(&response[4..4 + body_len], aes_key)?)?;

        if decrypted.len() < OFFSET_FILE_DATA {
            return Err(Error::HttpResponse(format!(
                "Decrypted payload too short: {} bytes",
                decrypted.len()
            )));
        }

        let status = read_i32_le(&decrypted, OFFSET_RESULT_QUERY);
        let file_len = read_i32_le(&decrypted, OFFSET_FILE_LEN);

        if file_len < 0 {
            return Err(Error::HttpResponse("Invalid file_len".into()));
        }
        let file_len = file_len as usize;
        if OFFSET_FILE_DATA + file_len > decrypted.len() {
            return Err(Error::HttpResponse(
                "file_len exceeds decrypted data size".into(),
            ));
        }

        Ok(QueryResult {
            status,
            torrent_data: decrypted[OFFSET_FILE_DATA..OFFSET_FILE_DATA + file_len].to_vec(),
        })
    }

    /// Fetches the torrent file bytes given a torrent's info hash in hex string format.
    pub fn fetch(&self, infohash_hex: &str) -> Result<Vec<u8>> {
        let info_hash = hex::decode(infohash_hex)
            .map_err(|e| Error::InvalidInfohash(e.to_string()))?;
        if info_hash.len() != 20 {
            return Err(Error::InvalidInfohashLength(infohash_hex.len()));
        }

        let packet = build_query_packet(&info_hash);
        let aes_key = derive_aes_key(&packet);
        let encrypted = aes_encrypt_ecb(&xl_aes_encrypt(&packet), &aes_key);

        let mut payload = build_rsa_header(&aes_key, encrypted.len() as u32)?;
        payload.extend_from_slice(&encrypted);

        let response = self.http_post(SERVER, &payload)?;

        let result = self.decrypt_response(&response, &aes_key)?;

        if result.status != 0 {
            return Err(Error::ServerError(result.status));
        }

        validate_torrent(&result.torrent_data)?;

        Ok(result.torrent_data)
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}
