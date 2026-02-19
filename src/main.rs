use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use anyhow::{ensure, Context, Result};
use md5::{Digest, Md5};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::io::Read;
use std::{env, fs, process};

// ---------------------------------------------------------------------------
// Protocol constants
// ---------------------------------------------------------------------------

const PUB_KEY_10000_DER: [u8; 140] = [
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xbc, 0x72, 0x02, 0x82, 0xf1, 0xca, 0x7f, 0xd3,
    0x15, 0xa7, 0x9b, 0x30, 0x32, 0x1f, 0x65, 0x4d, 0x69, 0x2b, 0xec, 0x63, 0x0b, 0x05, 0xf9,
    0xe9, 0xdf, 0xc1, 0xb9, 0x8a, 0x57, 0x6b, 0xf5, 0x30, 0xb0, 0x02, 0xb7, 0x63, 0x9b, 0x79,
    0x6b, 0x82, 0x22, 0x4b, 0x89, 0x31, 0xf1, 0x6a, 0x35, 0x9e, 0xef, 0x92, 0x3f, 0x77, 0x6d,
    0x4f, 0xac, 0x4a, 0x16, 0x91, 0xc3, 0xc2, 0x90, 0x2e, 0x49, 0xf5, 0x46, 0x08, 0x9f, 0x47,
    0x11, 0xca, 0x83, 0x27, 0x2b, 0x6f, 0xe9, 0x47, 0xd8, 0x34, 0xb0, 0x67, 0x53, 0x7e, 0x65,
    0x18, 0xcf, 0xc0, 0x5e, 0x8d, 0x76, 0x36, 0xeb, 0x46, 0xae, 0x18, 0x05, 0xae, 0xd5, 0x8a,
    0x1f, 0xd7, 0xe3, 0x3b, 0x9e, 0x19, 0x45, 0xba, 0x23, 0xaf, 0x0a, 0x67, 0x48, 0x36, 0xf0,
    0xc4, 0xfd, 0x8f, 0xa9, 0xab, 0x19, 0x29, 0xbb, 0x61, 0x91, 0x00, 0xc4, 0x41, 0x74, 0x6f,
    0x02, 0x03, 0x01, 0x00, 0x01,
];

const MAGIC: u32 = 0x26035888;
const KEY_TYPE: u32 = 10000;
const CMD_ID: u32 = 62;
const VERSION: u32 = 10001;
const USER_AGENT: &str = "AndroidDownloadManager/11 (Linux; U; Android 11; M2004J7AC)";
const SERVER: &str = "pool.bt.n0808.com:11400";

/// Response structure offsets (bytes into decrypted payload)
const OFFSET_RESULT_QUERY: usize = 24;
const OFFSET_FILE_LEN: usize = 32;
const OFFSET_FILE_DATA: usize = 36;

// ---------------------------------------------------------------------------
// Binary serialization helpers
// ---------------------------------------------------------------------------

/// Trait to extend `Vec<u8>` with little-endian write methods.
trait BufWriter {
    fn put_u16_le(&mut self, val: u16);
    fn put_u32_le(&mut self, val: u32);
    fn put_len_prefixed(&mut self, data: &[u8]);
}

impl BufWriter for Vec<u8> {
    fn put_u16_le(&mut self, val: u16) {
        self.extend_from_slice(&val.to_le_bytes());
    }

    fn put_u32_le(&mut self, val: u32) {
        self.extend_from_slice(&val.to_le_bytes());
    }

    /// Write `u32_le(len) + bytes`.
    fn put_len_prefixed(&mut self, data: &[u8]) {
        self.put_u32_le(data.len() as u32);
        self.extend_from_slice(data);
    }
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Packet construction
// ---------------------------------------------------------------------------

fn build_reserve6x() -> Vec<u8> {
    let version_str = b"2.0802.239.889";
    let num_str = b"10000";
    let peer_id = b"miui";

    let inner_len =
        (version_str.len() + 4 + 4 + num_str.len() + 4 + version_str.len() + 4 + peer_id.len()
            + 4) as u32;

    let mut buf = Vec::with_capacity(65);
    buf.put_u32_le(inner_len);
    buf.put_len_prefixed(version_str);
    buf.put_u32_le(0x80000001);
    buf.put_len_prefixed(num_str);
    buf.put_len_prefixed(version_str);
    buf.put_len_prefixed(peer_id);
    buf
}

fn build_query_packet(info_hash: &[u8]) -> Vec<u8> {
    let reserve6x = build_reserve6x();
    let fixed_string = b"abcdefghijklmn";

    let body_length =
        (4 + 2 + reserve6x.len() + 2 + 4 + info_hash.len() + 4 + 4 + fixed_string.len()) as u32;

    let mut buf = Vec::new();
    // 12-byte header: cmd_id, version, body_length
    buf.put_u32_le(CMD_ID);
    buf.put_u32_le(VERSION);
    buf.put_u32_le(body_length);
    // body
    buf.put_u32_le(0); // reserved
    buf.put_u16_le(0); // reserved
    buf.extend_from_slice(&reserve6x);
    buf.put_u16_le(0x0BF3);
    buf.put_len_prefixed(info_hash);
    buf.put_u32_le(0); // QueryXtPoolParam.field_08
    buf.put_len_prefixed(fixed_string);
    buf
}

// ---------------------------------------------------------------------------
// AES-128-ECB with PKCS#7
// ---------------------------------------------------------------------------

fn aes_encrypt_ecb(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let cipher = Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len() + 16);

    for chunk in data.chunks(16) {
        let mut block = aes::Block::default();
        if chunk.len() == 16 {
            block.copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
        } else {
            // Last partial block: apply PKCS#7 padding
            let pad = (16 - chunk.len()) as u8;
            block.iter_mut().for_each(|b| *b = pad);
            block[..chunk.len()].copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            out.extend_from_slice(&block);
            return out;
        }
    }

    // Input was exact multiple of 16: add full padding block
    let mut block = aes::Block::default();
    block.iter_mut().for_each(|b| *b = 16);
    cipher.encrypt_block(&mut block);
    out.extend_from_slice(&block);
    out
}

fn aes_decrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    ensure!(!data.is_empty(), "AES decrypt: empty data");
    ensure!(
        data.len() % 16 == 0,
        "AES decrypt: length {} not multiple of 16",
        data.len()
    );

    let cipher = Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(16) {
        let mut block = aes::Block::clone_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        out.extend_from_slice(&block);
    }

    // Validate and strip PKCS#7 padding
    let pad = *out.last().unwrap() as usize;
    ensure!(
        (1..=16).contains(&pad) && out[out.len() - pad..].iter().all(|&b| b == pad as u8),
        "AES decrypt: invalid PKCS#7 padding (pad={})",
        pad
    );
    out.truncate(out.len() - pad);
    Ok(out)
}

// ---------------------------------------------------------------------------
// XunLei two-layer encryption
// ---------------------------------------------------------------------------

fn md5_digest(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// First-layer: key = MD5(header[0..8]), encrypt body after 12-byte header.
fn xl_aes_encrypt(data: &[u8]) -> Vec<u8> {
    let key = md5_digest(&data[..8]);
    let encrypted_body = aes_encrypt_ecb(&data[12..], &key);

    let mut out = Vec::with_capacity(12 + encrypted_body.len());
    out.extend_from_slice(&data[..8]);
    out.put_u32_le(encrypted_body.len() as u32);
    out.extend_from_slice(&encrypted_body);
    out
}

/// Reverse of `xl_aes_encrypt`.
fn xl_aes_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    let key = md5_digest(&data[..8]);
    let enc_len = read_u32_le(data, 8) as usize;
    let decrypted_body = aes_decrypt_ecb(&data[12..12 + enc_len], &key)?;

    let mut out = Vec::with_capacity(12 + decrypted_body.len());
    out.extend_from_slice(&data[..8]);
    out.put_u32_le(decrypted_body.len() as u32);
    out.extend_from_slice(&decrypted_body);
    Ok(out)
}

/// Second-layer key: MD5(packet[0..4]).
fn derive_aes_key(packet: &[u8]) -> [u8; 16] {
    md5_digest(&packet[..4])
}

// ---------------------------------------------------------------------------
// RSA header (144 bytes)
// ---------------------------------------------------------------------------

fn build_rsa_header(aes_key: &[u8; 16], encrypted_body_len: u32) -> Result<Vec<u8>> {
    let pub_key = RsaPublicKey::from_pkcs1_der(&PUB_KEY_10000_DER)
        .context("Failed to parse RSA public key")?;
    let rsa_encrypted = pub_key
        .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, aes_key)
        .context("RSA encryption failed")?;
    ensure!(rsa_encrypted.len() == 128, "RSA output size != 128");

    let mut header = Vec::with_capacity(144);
    header.put_u32_le(MAGIC);
    header.put_u32_le(KEY_TYPE);
    header.put_u32_le(128);
    header.extend_from_slice(&rsa_encrypted);
    header.put_u32_le(encrypted_body_len);
    Ok(header)
}

// ---------------------------------------------------------------------------
// HTTP POST
// ---------------------------------------------------------------------------

fn http_post(server: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let url = format!("http://{}/", server);
    let resp = ureq::post(&url)
        .set("User-Agent", USER_AGENT)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .send_bytes(payload)
        .context("HTTP POST request failed")?;

    ensure!(resp.status() == 200, "HTTP {}", resp.status());

    let mut body = Vec::new();
    resp.into_reader()
        .read_to_end(&mut body)
        .context("Failed to read HTTP response body")?;

    ensure!(body.len() >= 4, "HTTP response too short: {} bytes", body.len());
    Ok(body)
}

// ---------------------------------------------------------------------------
// Response decryption
// ---------------------------------------------------------------------------

struct QueryResult {
    status: i32,
    torrent_data: Vec<u8>,
}

fn decrypt_response(response: &[u8], aes_key: &[u8; 16]) -> Result<QueryResult> {
    ensure!(response.len() >= 4, "Response too short: {} bytes", response.len());

    let body_len = read_u32_le(response, 0) as usize;
    ensure!(body_len > 0, "Server returned empty body (body_len=0)");
    ensure!(
        4 + body_len <= response.len(),
        "body_len={} exceeds response size={}",
        body_len,
        response.len()
    );

    // Reverse second layer → first layer
    let decrypted = xl_aes_decrypt(&aes_decrypt_ecb(&response[4..4 + body_len], aes_key)?)?;

    ensure!(
        decrypted.len() >= OFFSET_FILE_DATA,
        "Decrypted payload too short: {} bytes",
        decrypted.len()
    );

    let status = read_i32_le(&decrypted, OFFSET_RESULT_QUERY);
    let file_len = read_i32_le(&decrypted, OFFSET_FILE_LEN);

    ensure!(file_len >= 0, "Invalid file_len={}", file_len);
    let file_len = file_len as usize;
    ensure!(
        OFFSET_FILE_DATA + file_len <= decrypted.len(),
        "file_len={} exceeds decrypted data size={}",
        file_len,
        decrypted.len()
    );

    Ok(QueryResult {
        status,
        torrent_data: decrypted[OFFSET_FILE_DATA..OFFSET_FILE_DATA + file_len].to_vec(),
    })
}

// ---------------------------------------------------------------------------
// Torrent validation
// ---------------------------------------------------------------------------

fn validate_torrent(data: &[u8]) -> Result<()> {
    bt_bencode::from_slice::<bt_bencode::Value>(data)
        .context("Response is not a valid bencode/torrent file")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------

fn run(infohash_hex: &str, output_file: &str) -> Result<()> {
    // Parse infohash
    let info_hash = hex::decode(infohash_hex).context("Invalid infohash hex string")?;
    ensure!(
        info_hash.len() == 20,
        "Infohash must be 40 hex chars (20 bytes), got {}",
        infohash_hex.len()
    );

    println!("[INFO] Querying infohash: {}", infohash_hex);

    // Build & encrypt
    let packet = build_query_packet(&info_hash);
    let aes_key = derive_aes_key(&packet);
    let encrypted = aes_encrypt_ecb(&xl_aes_encrypt(&packet), &aes_key);

    // Build payload: RSA header + encrypted body
    let mut payload = build_rsa_header(&aes_key, encrypted.len() as u32)?;
    payload.extend_from_slice(&encrypted);
    println!("[INFO] Request payload: {} bytes", payload.len());

    // Send request
    let response = http_post(SERVER, &payload)?;
    println!("[INFO] Response received: {} bytes", response.len());

    // Decrypt
    let result = decrypt_response(&response, &aes_key)?;
    println!(
        "[INFO] status={}, file_len={}",
        result.status,
        result.torrent_data.len()
    );

    ensure!(result.status == 0, "Server returned error: status={}", result.status);
    ensure!(!result.torrent_data.is_empty(), "Empty torrent data");

    // Validate bencode before saving
    validate_torrent(&result.torrent_data)?;

    // Write file
    fs::write(output_file, &result.torrent_data)
        .with_context(|| format!("Failed to write {}", output_file))?;
    println!("[OK] Wrote {} bytes to {}", result.torrent_data.len(), output_file);

    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <infohash_hex> <output_file>", args[0]);
        eprintln!(
            "Example: {} 36a971dca3863ce8c27058082816a47b1ce0afe7 new.torrent",
            args[0]
        );
        process::exit(1);
    }

    if let Err(e) = run(&args[1], &args[2]) {
        eprintln!("[ERROR] {:#}", e);
        process::exit(1);
    }
}
