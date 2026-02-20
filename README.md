# xunlei_bt_pool

A Rust CLI tool to download `.torrent` files from XunLei's BT pool server by infohash.

> **Note:** This project was built entirely through reverse engineering from XunLei's application.

## How It Works

1. Builds a binary query packet with the target infohash
2. Encrypts it with two-layer AES-128-ECB
3. Wraps the encrypted payload with a RSA header
4. Sends an HTTP POST to `pool.bt.n0808.com:11400`
5. Decrypts the response (reverse two-layer AES), validates bencode structure, and writes the torrent file

## Usage

### As a CLI Tool

```bash
cargo run -- <infohash_hex> <output_file>
```

**Example:**

```bash
cargo run -- 36a971dca3863ce8c27058082816a47b1ce0afe7 output.torrent
```

**Output:**

```
[OK] Wrote 23637 bytes to output.torrent
```

### As a Library / SDK

You can also depend on this package directly in your own Rust applications to leverage the connection-pooling client.

```rust
use xunlei_bt_pool::Client;
use std::fs;

fn main() -> anyhow::Result<()> {
    // 1. Create a client instance
    let client = Client::new();
    
    // 2. Fetch torrent bytes via infohash string
    let infohash = "36a971dca3863ce8c27058082816a47b1ce0afe7";
    let torrent_data = client.fetch(infohash)?;
    
    // 3. Keep working with it (e.g., save to disk)
    fs::write("output.torrent", &torrent_data)?;
    println!("Successfully downloaded {} bytes!", torrent_data.len());
    
    Ok(())
}
```

## Build

```bash
cargo build --release
```

The binary will be at `target/release/xunlei_bt_pool`.

## Protocol Overview

```
Request:  [RSA Header (144 bytes)] [AES-encrypted body]
          ├─ magic (u32)
          ├─ key_type (u32)
          ├─ rsa_len (u32) = 128
          ├─ RSA(aes_key) (128 bytes)
          └─ body_len (u32)

Response: [body_len (u32)] [AES-encrypted body]
          → decrypt layer 2 (known key)
          → decrypt layer 1 (MD5 header key)
          → parse: status (i32 @ offset 24), file_len (i32 @ offset 32), file_data (@ offset 36)
```

## 免责声明

1. **学习研究用途**：本项目仅供个人学习、研究计算机网络协议与逆向工程技术之用，不以任何商业盈利为目的。依据《中华人民共和国著作权法》第二十四条之规定，为个人学习、研究或者欣赏而使用他人已发表的作品，属于合理使用。

2. **使用者责任**：使用者应自行承担使用本软件的全部法律责任。使用者须确保其使用行为符合中华人民共和国法律法规及相关服务的使用条款。因使用者不当使用本软件造成的任何法律纠纷或损失，与本项目作者无关。

3. **及时删除**：使用者通过本工具获取的任何数据，应仅用于学习研究目的，并在学习研究完成后及时删除，不得用于传播、分发或其他任何商业用途。
