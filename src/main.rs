/// query malware bazaar's api (https://bazaar.abuse.ch/api/) for a hash
/// if it's found, download the file to the current directory
/// 0xca7

use reqwest;
use anyhow::Result;
use serde_json::Value;
use std::{fs, io::Write};

/// download the malware file
async fn download(sha256_hash: &str) -> Result<()> {

    println!("[+] downloading {sha256_hash}");

    let response = reqwest::Client::new()
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&[("query", "get_file"), 
        ("sha256_hash", sha256_hash)])
        .send()
        .await?;

    let data = response.bytes().await?;

    let mut file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(sha256_hash)?;

    println!("[+] writing file to: {sha256_hash}");
    file.write_all(&data.slice(0..))?;

    println!("[+] download success");
    Ok(())
}

/// query a hash
async fn query(hash: &str) -> Result<Option<String>> {

    println!("[+] querying {hash}");

    let response = reqwest::Client::new()
        .post("https://mb-api.abuse.ch/api/v1/")
        .form(&[("query", "get_info"), 
        ("hash", hash)])
        .send()
        .await?;

    let response = response.text().await?;

    let json: Value = match serde_json::from_str(&response) {
        Ok(v) => v,
        Err(_) => {
            eprintln!("error, showing raw response {}", response);
            std::process::exit(0);
        }
    };

    let json = &json["data"][0];

    if !json.is_null() {
        println!("--- tags:     {}", json["tags"]);
        println!("--- type:     {}", json["file_type"]);
        println!("--- MD5:      {}", json["md5_hash"]);
        println!("--- SHA256:   {}", json["sha256_hash"]);
        println!("--- SHA1:     {}", json["sha1_hash"]);
    } else {
        println!("[!] hash not found");
        return Ok(None);
    }

    Ok(Some(json["sha256_hash"].to_string().replace("\"", "")))

}

/// just some usage information for the user
fn usage() {
    println!("[usage] ./malquery [HASH]");
    println!("        HASH: MD5, SHA256, SHA1")
}

#[tokio::main]
async fn main() -> Result<()>{

    let args: Vec<String> = std::env::args().collect();

    if args.len() != 2 {
        usage();
        std::process::exit(0);
    }

    let response = query(&args[1]).await?;
    if let Some(resp) = response {
        // download
        download(&resp).await?;
    }

    Ok(())
}