use anyhow::{Context, Result};
use std::{env, fs, process};
use xunlei_bt_pool::Client;

fn run(infohash_hex: &str, output_file: &str) -> Result<()> {
    let client = Client::new();
    let torrent_data = client.fetch(infohash_hex)?;

    fs::write(output_file, &torrent_data)
        .with_context(|| format!("Failed to write {}", output_file))?;
    println!("[OK] Wrote {} bytes to {}", torrent_data.len(), output_file);

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
