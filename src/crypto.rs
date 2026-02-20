use crate::error::{Error, Result};
use aes::Aes128;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
use ecb::{Decryptor, Encryptor};
use cipher::block_padding::Pkcs7;
use md5::{Digest, Md5};
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

const PUB_KEY_10000_DER: [u8; 140] = [
    0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xbc, 0x72, 0x02, 0x82, 0xf1, 0xca, 0x7f, 0xd3, 0x15,
    0xa7, 0x9b, 0x30, 0x32, 0x1f, 0x65, 0x4d, 0x69, 0x2b, 0xec, 0x63, 0x0b, 0x05, 0xf9, 0xe9, 0xdf,
    0xc1, 0xb9, 0x8a, 0x57, 0x6b, 0xf5, 0x30, 0xb0, 0x02, 0xb7, 0x63, 0x9b, 0x79, 0x6b, 0x82, 0x22,
    0x4b, 0x89, 0x31, 0xf1, 0x6a, 0x35, 0x9e, 0xef, 0x92, 0x3f, 0x77, 0x6d, 0x4f, 0xac, 0x4a, 0x16,
    0x91, 0xc3, 0xc2, 0x90, 0x2e, 0x49, 0xf5, 0x46, 0x08, 0x9f, 0x47, 0x11, 0xca, 0x83, 0x27, 0x2b,
    0x6f, 0xe9, 0x47, 0xd8, 0x34, 0xb0, 0x67, 0x53, 0x7e, 0x65, 0x18, 0xcf, 0xc0, 0x5e, 0x8d, 0x76,
    0x36, 0xeb, 0x46, 0xae, 0x18, 0x05, 0xae, 0xd5, 0x8a, 0x1f, 0xd7, 0xe3, 0x3b, 0x9e, 0x19, 0x45,
    0xba, 0x23, 0xaf, 0x0a, 0x67, 0x48, 0x36, 0xf0, 0xc4, 0xfd, 0x8f, 0xa9, 0xab, 0x19, 0x29, 0xbb,
    0x61, 0x91, 0x00, 0xc4, 0x41, 0x74, 0x6f, 0x02, 0x03, 0x01, 0x00, 0x01,
];

const MAGIC: u32 = 0x26035888;
const KEY_TYPE: u32 = 10000;

fn md5_digest(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

/// Derives the outer AES key using the first 4 bytes of the packet.
pub fn derive_aes_key(packet: &[u8]) -> [u8; 16] {
    md5_digest(&packet[..4])
}

/// Apply ECB processing with PKCS#7 padding using official standard blocks
pub fn aes_encrypt_ecb(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut buf = vec![0u8; data.len() + 16];
    buf[..data.len()].copy_from_slice(data);

    let res = Encryptor::<Aes128>::new(key.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .unwrap();

    res.to_vec()
}

pub fn aes_decrypt_ecb(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::AesDecrypt("empty data".into()));
    }

    let mut buf = data.to_vec();

    let decrypted = Decryptor::<Aes128>::new(key.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::AesDecrypt(e.to_string()))?;

    Ok(decrypted.to_vec())
}

/// Applies the first layer of Xunlei specific encryption.
pub fn xl_aes_encrypt(data: &[u8]) -> Vec<u8> {
    let key = md5_digest(&data[..8]);
    let encrypted_body = aes_encrypt_ecb(&data[12..], &key);

    let mut out = Vec::with_capacity(12 + encrypted_body.len());
    out.extend_from_slice(&data[..8]);
    out.extend_from_slice(&(encrypted_body.len() as u32).to_le_bytes());
    out.extend_from_slice(&encrypted_body);
    out
}

/// Reverses the first layer of Xunlei specific decryption.
pub fn xl_aes_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    let key = md5_digest(&data[..8]);
    let enc_len = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
    
    let decrypted_body = aes_decrypt_ecb(&data[12..12 + enc_len], &key)?;

    let mut out = Vec::with_capacity(12 + decrypted_body.len());
    out.extend_from_slice(&data[..8]);
    out.extend_from_slice(&(decrypted_body.len() as u32).to_le_bytes());
    out.extend_from_slice(&decrypted_body);
    Ok(out)
}

/// Builds the RSA encrypted header given the generated AES key.
pub fn build_rsa_header(aes_key: &[u8; 16], encrypted_body_len: u32) -> Result<Vec<u8>> {
    let pub_key =
        RsaPublicKey::from_pkcs1_der(&PUB_KEY_10000_DER).map_err(|e| Error::RsaEncrypt(e.to_string()))?;
    let rsa_encrypted = pub_key
        .encrypt(&mut rsa::rand_core::OsRng, Pkcs1v15Encrypt, aes_key)
        .map_err(|e| Error::RsaEncrypt(e.to_string()))?;

    if rsa_encrypted.len() != 128 {
        return Err(Error::RsaEncrypt("RSA output size must be 128".into()));
    }

    let mut header = Vec::with_capacity(144);
    header.extend_from_slice(&MAGIC.to_le_bytes());
    header.extend_from_slice(&KEY_TYPE.to_le_bytes());
    header.extend_from_slice(&128u32.to_le_bytes());
    header.extend_from_slice(&rsa_encrypted);
    header.extend_from_slice(&encrypted_body_len.to_le_bytes());
    Ok(header)
}
