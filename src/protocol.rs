pub const CMD_ID: u32 = 62;
pub const VERSION: u32 = 10001;

pub const OFFSET_RESULT_QUERY: usize = 24;
pub const OFFSET_FILE_LEN: usize = 32;
pub const OFFSET_FILE_DATA: usize = 36;

pub const VERSION_STR: &[u8] = b"2.0802.239.889";
pub const NUM_STR: &[u8] = b"10000";
pub const PEER_ID: &[u8] = b"miui";
pub const FIXED_STRING: &[u8] = b"abcdefghijklmn";

// Magic marker flags used during binary serialization
pub const RESERVE_FLAG_1: u32 = 0x80000001;
pub const QUERY_FLAG_1: u16 = 0x0BF3;

pub trait BufWriter {
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

    fn put_len_prefixed(&mut self, data: &[u8]) {
        self.put_u32_le(data.len() as u32);
        self.extend_from_slice(data);
    }
}

pub fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Builds the reserved 6x block payload.
fn build_reserve6x() -> Vec<u8> {
    let inner_len =
        (VERSION_STR.len() + 4 + 4 + NUM_STR.len() + 4 + VERSION_STR.len() + 4 + PEER_ID.len() + 4)
            as u32;

    let mut buf = Vec::with_capacity(65);
    buf.put_u32_le(inner_len);
    buf.put_len_prefixed(VERSION_STR);
    buf.put_u32_le(RESERVE_FLAG_1);
    buf.put_len_prefixed(NUM_STR);
    buf.put_len_prefixed(VERSION_STR);
    buf.put_len_prefixed(PEER_ID);
    buf
}

/// Builds the unencrypted query packet given an info hash.
pub fn build_query_packet(info_hash: &[u8]) -> Vec<u8> {
    let reserve6x = build_reserve6x();

    let body_length =
        (4 + 2 + reserve6x.len() + 2 + 4 + info_hash.len() + 4 + 4 + FIXED_STRING.len()) as u32;

    let mut buf = Vec::new();
    buf.put_u32_le(CMD_ID);
    buf.put_u32_le(VERSION);
    buf.put_u32_le(body_length);
    buf.put_u32_le(0);
    buf.put_u16_le(0);
    buf.extend_from_slice(&reserve6x);
    buf.put_u16_le(QUERY_FLAG_1);
    buf.put_len_prefixed(info_hash);
    buf.put_u32_le(0);
    buf.put_len_prefixed(FIXED_STRING);
    buf
}

pub struct QueryResult {
    pub status: i32,
    pub torrent_data: Vec<u8>,
}
