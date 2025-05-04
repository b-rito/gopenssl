# GOpenSSL

A lightweight CLI tool written in Go to check TLS version and certificates in a connection, similar to `openssl s_client`.

## ✨ Features

- Connects to a remote server over TLS
- Prints certificate chain details
- Shows TLS version and cipher suite used
- Minimal dependencies and cross-platform support

## 📦 Installation

Download a precompiled binary from the [Releases](https://github.com/b-rito/gopenssl/releases) page.

### Linux:

```sh
curl -L -o gopenssl https://github.com/b-rito/gopenssl/releases/download/v0.0.1/gopenssl-linux-amd64
chmod +x gopenssl
sudo mv gopenssl /usr/local/bin/
```

## 🧪 Usage

Basic command syntax for connecting to a target host with specified port:

```sh
gopenssl --connect 127.0.0.1:443
```

Command syntax for connecting to a target with a different servername:

```sh
gopenssl --connect 127.0.0.1:443 --servername my.website.com
```

Command syntax for connecting to a target with disabling certificate verification:

```sh
gopenssl --connect 127.0.0.1:443 --noverify
```
