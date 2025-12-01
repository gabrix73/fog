# 🌫️ fog

**Anonymous SMTP Relay with Sphinx Mixnet over Tor**

fog is a privacy-focused SMTP relay that routes messages through a 3-hop Sphinx mixnet, providing strong anonymity guarantees against traffic analysis, timing attacks, and metadata correlation.

## Features

### Security
- **Sphinx Mixnet**: 3-hop onion routing with layered encryption
- **Curve25519 ECDH**: Key exchange with forward secrecy
- **AES-256-GCM**: Authenticated encryption for all payloads
- **Traffic Analysis Resistance**: Fixed-size packets (64KB), batch processing, random shuffling
- **Timing Attack Resistance**: Cryptographically random delays (500ms-5s)
- **Replay Protection**: 24-hour message ID cache
- **Size Correlation Resistance**: Uniform packet sizes with random padding
- **No Metadata Retention**: Memory-only processing, no persistent logs

### Network
- All traffic routed through Tor
- Decentralized node discovery via shared PKI file
- Health monitoring with automatic failover
- Each node can be entry, middle, or exit

## Architecture

```
┌─────────┐     ┌─────────┐     ┌─────────┐     ┌─────────┐
│  Client │────▶│  Entry  │────▶│  Middle │────▶│  Exit   │────▶ Destination
│  SMTP   │     │  Node   │     │  Node   │     │  Node   │     (email/usenet)
└─────────┘     └─────────┘     └─────────┘     └─────────┘
                    │               │               │
                    ▼               ▼               ▼
              Encrypt L3      Decrypt L3      Decrypt L2
              Encrypt L2      Forward L2      Decrypt L1
              Encrypt L1      (shuffled)      Deliver
```

Each node:
- Receives Sphinx packets on port 9999
- Accepts SMTP on port 2525 (entry point)
- Decrypts one layer, applies random delay, forwards

## Requirements

- Linux (Debian/Ubuntu recommended)
- Go 1.21+
- Tor
- Minimum 3 fog nodes for mixnet operation

## Installation

### 1. Install dependencies

```bash
apt update
apt install tor golang-go
```

### 2. Create fog user and directories

```bash
# groupadd -r fog
# useradd -g fog -s /usr/sbin/nologin -r -m -d /var/lib/fog fog
```

### 3. Configure Tor Hidden Service

Add to `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/fog
HiddenServicePort 2525 127.0.0.1:2525
HiddenServicePort 9999 127.0.0.1:9999
```

Restart Tor and get your .onion address:

```bash
systemctl restart tor
cat /var/lib/tor/fog/hostname
# Example: 66ehoz4ir6beuovmgt4gbpdfpmy43iuouj36dylqvkwgyp2dwpcbvjqd.onion
```

### 4. Build fog

```bash
cd /var/lib/fog
nano fog.go  # paste the fog source code

go mod init fog
go mod tidy
go build -ldflags="-s -w" -trimpath -o fog
```

### 5. Export node info

```bash
./fog -export-node-info \
    -name YOUR_ONION_ADDRESS.onion \
    -short-name mynode
```

This creates `nodes.json` with your node's public key.

### 6. Create systemd service

Create `/etc/systemd/system/fog.service`:

```ini
[Unit]
Description=fog - Anonymous SMTP Relay with Sphinx Mixnet
Documentation=https://github.com/gabrix73/fog
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=fog
Group=fog
WorkingDirectory=/var/lib/fog

ExecStart=/var/lib/fog/fog \
    -name YOUR_ONION_ADDRESS.onion \
    -short-name mynode \
    -smtp 127.0.0.1:2525 \
    -node 127.0.0.1:9999 \
    -sphinx \
    -pki-file /var/lib/fog/nodes.json \
    -data-dir /var/lib/fog/fog-data \
    -debug

Restart=always
RestartSec=10
StartLimitInterval=200
StartLimitBurst=5
TimeoutStartSec=30
TimeoutStopSec=30

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/fog/fog-data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
PrivateDevices=true
ProtectClock=true
ProtectKernelLogs=true
ProtectHostname=true

LimitNOFILE=65535
LimitNPROC=512

StandardOutput=journal
StandardError=journal
SyslogIdentifier=fog

[Install]
WantedBy=multi-user.target
```

### 7. Set permissions and start

```bash
chown fog:fog -R /var/lib/fog
systemctl daemon-reload
systemctl enable fog
systemctl start fog
```

### 8. Verify

```bash
systemctl status fog
journalctl -u fog -f
```

You should see:
```
[FOG] Starting v2.0.1
[PKI] Loaded 4 nodes from /var/lib/fog/nodes.json
[HEALTH] Checking 3 nodes
[HEALTH] node1 OK
[HEALTH] node2 OK
[HEALTH] node3 OK
[HEALTH] Done. 3 nodes healthy
```

## Network Setup

### Combining nodes.json

Each operator exports their node info, then all nodes are combined into a single `nodes.json`:

```json
{
  "version": "2.0.1",
  "updated": "2025-12-01T00:00:00Z",
  "nodes": [
    {
      "node_id": "8342eaab81017d33...",
      "public_key": "pyva1yu+5SDFb7UzyB3ZhNtpoCEHaU/IewsDOBvg6n8=",
      "address": "ej5dj774rkmfxvo3jexcmyotkq6bwgmr45dmwrbmk366lcvalnrgolad.onion:9999",
      "name": "node1",
      "version": "2.0.1"
    },
    {
      "node_id": "340c546059a8c322...",
      "public_key": "Ult6z/aOvrzB0+149wIDjuCSFVo8xF067yp/MFQLaHM=",
      "address": "iycr4wfrdzieogdfeo7uxrj77w2vjlrhlrv3jg2ve62oe5aceqsqu7ad.onion:9999",
      "name": "node2",
      "version": "2.0.1"
    },
    {
      "node_id": "c386967674709d76...",
      "public_key": "mYeEtBhNUPQ4QTTUH0b3ngOSbvjK8ctR7kAz09cjb3g=",
      "address": "66ehoz4ir6beuovmgt4gbpdfpmy43iuouj36dylqvkwgyp2dwpcbvjqd.onion:9999",
      "name": "node3",
      "version": "2.0.1"
    },
    {
      "node_id": "ebc04620851a8a9b...",
      "public_key": "z0iNumJks/5aZ1+Zys0NUwVk5VzYdEfyL//a6J5miwE=",
      "address": "ejdrw3ka2mjhvsuz7uxjnzjircsdpoiu3a33g2xoywlafqetptjpqryd.onion:9999",
      "name": "node4",
      "version": "2.0.1"
    }
  ]
}
```

Copy the same `nodes.json` to all nodes and restart.

## Usage

### Send email via SMTP

```bash
# Connect to any fog node
telnet 127.0.0.1 2525

EHLO client
MAIL FROM:<anonymous@fog.local>
RCPT TO:<recipient@example.com>
DATA
Subject: Test message

Hello from fog mixnet!
.
QUIT
```

### Send via Tor (remote)

```bash
torify telnet YOUR_ONION.onion 2525
```

### Post to Usenet

```bash
telnet 127.0.0.1 2525

EHLO client
MAIL FROM:<anonymous@fog.local>
RCPT TO:<mail2news@dizum.com>
DATA
From: Anonymous <anon@fog.local>
Newsgroups: misc.test
Subject: Test post via fog
Date: Mon, 01 Dec 2025 12:00:00 +0000
Message-ID: <unique-id@fog.local>

Test message posted via fog mixnet.
.
QUIT
```

## Command Line Options

```
Usage: fog [options]

Options:
  -name string        Hostname (.onion address)
  -short-name string  Short name for logs (e.g., node1)
  -smtp string        SMTP listen address (default "127.0.0.1:2525")
  -node string        Node listen address (default "127.0.0.1:9999")
  -sphinx             Enable Sphinx mixnet routing
  -pki-file string    Path to nodes.json
  -data-dir string    Data directory (default "./fog-data")
  -debug              Enable debug logging
  -export-node-info   Export node info for nodes.json
  -version            Show version
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 2525 | SMTP | Client email submission |
| 9999 | Sphinx | Inter-node packet routing |

## Security Considerations

### Threat Model

fog protects against:

| Threat | Protection |
|--------|------------|
| Traffic Analysis | Fixed-size packets, cover traffic, batching |
| Timing Attacks | Randomized delays, constant-time operations |
| Replay Attacks | Message-ID cache with 24h expiration |
| Node Compromise | Forward secrecy via ephemeral keys |
| Size Correlation | Adaptive padding to fixed buckets |
| Partial Network Observation | 3-hop mixnet provides unlinkability |
| Global Adversary | Multi-hop routing breaks end-to-end correlation |
| Metadata Analysis | No persistent metadata retention |

### Limitations

- Minimum 3 nodes required for Sphinx routing
- Exit node sees unencrypted message (use PGP for E2E)
- All nodes must share the same `nodes.json`
- Tor is a hard dependency

## Troubleshooting

### "0 nodes healthy"

1. Check if `nodes.json` has all nodes
2. Verify file permissions: `chown fog:fog /var/lib/fog/nodes.json`
3. Check Tor connectivity: `torify curl http://node.onion:9999`

### "PKI Load failed: permission denied"

```bash
chown fog:fog /var/lib/fog/nodes.json
chmod 600 /var/lib/fog/nodes.json
```

### SMTP connection refused

1. Check if fog is running: `systemctl status fog`
2. Verify port binding: `ss -tlnp | grep 2525`
3. Check Tor hidden service: `cat /var/lib/tor/fog/hostname`

## Cryptographic Libraries

- `golang.org/x/crypto/curve25519` - ECDH key agreement
- `golang.org/x/crypto/hkdf` - HKDF-SHA256 key derivation
- `golang.org/x/net/proxy` - Tor SOCKS5 proxy
- `crypto/aes` + `crypto/cipher` - AES-256-GCM encryption
- `crypto/hmac` + `crypto/sha256` - HMAC authentication
- `crypto/rand` - Cryptographically secure randomness

## References

- [Sphinx: A Compact and Provably Secure Mix Format](https://cypherpunks.ca/~iang/pubs/Sphinx_Oakland09.pdf) - Danezis & Goldberg, IEEE S&P 2009
- [Tor Project](https://www.torproject.org/)
- [RFC 5321 - SMTP](https://tools.ietf.org/html/rfc5321)
- [RFC 5536 - Netnews Article Format](https://tools.ietf.org/html/rfc5536)

## License

MIT License

## Contributing

1. Fork the repository
2. Create feature branch
3. Submit pull request

## Disclaimer

This software is provided for educational and research purposes. Users are responsible for complying with applicable laws in their jurisdiction. The authors are not responsible for misuse.

---

**fog** - *When privacy is not optional*


