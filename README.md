# malq

query malware bazaar for a sample and download it

build and use:
```
cargo add reqwest serde serde_json anyhow
cargo add tokio --features full
cargo build --release
cp target/release/malq .
./malq [HASH]
# hash can be MD5, SHA1, SHA256
```

0xca7