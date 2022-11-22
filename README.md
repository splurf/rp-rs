# rp-rs

An extremely simple low-functionality reverse proxy with minimum TLS support

## Configuration
There's a singular configuation file that needs to be modified. It should be named `config.txt` and will should look like this:
```
80
    server: localhost
    paths:
        /donut => localhost:8888

443
    server: localhost
    paths:
        / => localhost:444
    ssl:
        certificate: sample.pem
        certificate_key: sample.rsa
```

## Usability
#### Build
```bash
cargo build --release
```

#### Run
```bash
sudo ./target/release/rp-rs
```