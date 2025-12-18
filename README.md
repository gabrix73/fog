# 🌫️ fog - Anonymous SMTP Relay Network

**fog** is a privacy-preserving SMTP relay that uses Sphinx mixnet routing to provide sender anonymity, forward secrecy, and resistance to traffic analysis. Perfect for anonymous email delivery, Usenet posting, and secure communications.

[![Version](https://img.shields.io/badge/version-3.0.8-blue.svg)](https://github.com/yourusername/fog)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.21+-00ADD8.svg)](https://go.dev/)

---

## 🎯 Features

### Core Privacy Features

- **🔐 Sphinx Mixnet Routing**: 3-hop onion routing with per-hop encryption
- **⏱️ Timing Attack Resistance**: Configurable message delays (1-24h) with multiple strategies
- **🎭 Exit Node Anonymization**: Automatic header sanitization removes all identifying information
- **🔄 Forward Secrecy**: Each message uses ephemeral keys, past messages remain secure if node compromised
- **🚫 No Logs**: Zero persistent metadata retention
- **🔀 Batch Mixing**: Messages are batched and shuffled before forwarding
- **♻️ Replay Protection**: Message-ID cache prevents replay attacks

### Technical Features

- **📦 Persistent Queue**: SQLite-backed delay pool survives restarts
- **🎲 Multiple Delay Strategies**: Exponential (default), Constant, Poisson distributions
- **🏥 Health Checking**: Automatic node monitoring and path selection
- **🔍 Debug Mode**: Detailed logging for troubleshooting
- **🐧 Linux Optimized**: Systemd integration with security hardening

---

## 🛡️ Security Guarantees

| Threat | Protection |
|--------|------------|
| **Traffic Analysis** | Padding + cover traffic |
| **Timing Attacks** | Randomized delays (1-24h) + constant-time operations |
| **Replay Attacks** | Message-ID cache with TTL expiration |
| **Node Compromise** | Forward secrecy protects older messages |
| **Size Correlation** | Fixed 64KB packet size prevents size analysis |
| **Partial Network Observation** | Mixnet architecture breaks linkability |
| **Global Adversary** | Multi-hop routing + batch mixing breaks end-to-end correlation |
| **Metadata Analysis** | Exit node header sanitization + no persistent metadata |

---

## 🚀 Quick Start (Debian/Ubuntu)

### Prerequisites

```bash
# Install dependencies
sudo apt update
sudo apt install -y golang-go tor git build-essential

# Verify Go version (1.21+ required)
go version
```

### Installation

```bash
# Clone repository
git clone https://github.com/yourusername/fog.git
cd fog

# Build
go mod tidy
go build -tags="sqlite_omit_load_extension" -ldflags="-s -w" -trimpath -o fog fog.go

# Install binary
sudo mkdir -p /var/lib/fog
sudo cp fog /var/lib/fog/
sudo chmod +x /var/lib/fog/fog
```

### Create User & Directories

```bash
# Create fog user
sudo useradd -r -s /bin/false fog

# Create directories
sudo mkdir -p /var/lib/fog/data
sudo chown -R fog:fog /var/lib/fog
sudo chmod 700 /var/lib/fog/data
```

### Generate Node Identity

```bash
# Generate your node keys
cd /var/lib/fog
sudo -u fog ./fog -name your-onion-address.onion -short-name yourname -export-node-info

# This creates nodes.json with your public key
cat nodes.json
```

### Configure Tor Hidden Service

Edit `/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/fog/
HiddenServicePort 9999 127.0.0.1:9999
HiddenServicePort 2525 127.0.0.1:2525
```

Restart Tor and get your address:

```bash
sudo systemctl restart tor
sudo cat /var/lib/tor/fog/hostname
# Example output: abc123xyz456.onion
```

### Join the Network

**Join the existing fog network or create your own!**

#### Option 1: Join Existing Network

Contact the network operators to:
1. Share your `nodes.json` (contains your public key + onion address)
2. Receive the network `nodes.json` (contains all trusted nodes)
3. Deploy to `/var/lib/fog/nodes.json`

#### Option 2: Create New Network

Start with 1 node (you), then invite others:

```bash
# Use your own nodes.json
sudo cp nodes.json /var/lib/fog/nodes.json
```

### Configure Systemd Service

Create `/etc/systemd/system/fog.service`:

```ini
[Unit]
Description=fog - Anonymous SMTP Relay
After=network.target tor.service
Wants=tor.service

[Service]
Type=simple
User=fog
Group=fog
WorkingDirectory=/var/lib/fog

ExecStart=/var/lib/fog/fog \
    -name YOUR_ONION.onion \
    -short-name yourname \
    -smtp 127.0.0.1:2525 \
    -node 127.0.0.1:9999 \
    -sphinx \
    -delay \
    -min-delay 2h \
    -max-delay 24h \
    -delay-strategy exponential \
    -pki-file /var/lib/fog/nodes.json \
    -data-dir /var/lib/fog/data \
    -debug

Restart=always
RestartSec=10

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/fog/data
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
```

**Replace:**
- `YOUR_ONION.onion` with your Tor hidden service address
- `yourname` with your chosen node name (e.g., alice, bob, relay1)

### Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable fog
sudo systemctl start fog

# Check status
sudo systemctl status fog

# Watch logs
sudo journalctl -u fog -f
```

---

## 📨 Usage

### Send Anonymous Email

```bash
{
    echo "EHLO client"
    echo "MAIL FROM:<sender@example.com>"
    echo "RCPT TO:<recipient@destination.com>"
    echo "DATA"
    echo "From: Anonymous User <user@example.com>"
    echo "To: recipient@destination.com"
    echo "Subject: Anonymous message via fog"
    echo ""
    echo "This message was sent through the fog network."
    echo "."
    echo "QUIT"
} | nc 127.0.0.1 2525
```

### Post to Usenet Anonymously

```bash
{
    echo "EHLO client"
    echo "MAIL FROM:<poster@example.com>"
    echo "RCPT TO:<mail2news@mail2news.tcpreset.net>"
    echo "DATA"
    echo "From: Anonymous Poster <poster@example.com>"
    echo "Newsgroups: alt.test"
    echo "Subject: Test post via fog"
    echo ""
    echo "This post was submitted anonymously through fog network."
    echo "."
    echo "QUIT"
} | nc 127.0.0.1 2525
```

**At the exit node, headers are automatically sanitized:**
- `From:` → `Anonymous <anonymous@exitnode.fog>`
- `Message-ID:` → `<random_hex@exitnode.fog>`
- All identifying headers removed (X-Mailer, Reply-To, etc.)

---

## ⚙️ Configuration

### Command Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-name` | required | Your .onion address |
| `-short-name` | required | Short node name (for logs) |
| `-smtp` | 127.0.0.1:2525 | SMTP listen address |
| `-node` | 127.0.0.1:9999 | Sphinx node listen address |
| `-pki-file` | required | Path to nodes.json |
| `-data-dir` | fog-data | Data directory for queue database |
| `-sphinx` | false | Enable Sphinx routing |
| `-delay` | false | Enable delay pool |
| `-min-delay` | 1h | Minimum message delay |
| `-max-delay` | 24h | Maximum message delay |
| `-delay-strategy` | exponential | Delay strategy: exponential, constant, poisson |
| `-debug` | false | Enable debug logging |

### Delay Strategies

**Exponential (Recommended):**
- More short delays, fewer long delays
- Natural traffic pattern
- Best for high-volume nodes

**Constant:**
- Uniform random delays
- Predictable average latency
- Good for testing

**Poisson:**
- Models natural arrival processes
- Best for research/analysis

### Example Configurations

**High Anonymity (24h delays):**
```bash
-delay -min-delay 6h -max-delay 24h -delay-strategy exponential
```

**Medium Latency (6h delays):**
```bash
-delay -min-delay 1h -max-delay 6h -delay-strategy constant
```

**Low Latency (no delays):**
```bash
-sphinx
# (omit -delay flag)
```

---

## 🔍 Monitoring

### Check Queue Status

```bash
# View queue size
sqlite3 /var/lib/fog/data/messages.db \
  "SELECT COUNT(*) as total FROM message_queue;"

# View ready messages
sqlite3 /var/lib/fog/data/messages.db \
  "SELECT COUNT(*) FROM message_queue WHERE send_after <= strftime('%s','now');"

# View queue details
sqlite3 /var/lib/fog/data/messages.db \
  "SELECT id, from_addr, to_addr, 
          datetime(send_after, 'unixepoch') as send_time 
   FROM message_queue 
   ORDER BY send_after LIMIT 10;"
```

### Monitor Logs

```bash
# All fog activity
sudo journalctl -u fog -f

# Pool activity only
sudo journalctl -u fog -f | grep POOL

# Statistics only
sudo journalctl -u fog -f | grep STATS

# Header sanitization
sudo journalctl -u fog -f | grep SANITIZE
```

### Statistics Output

```
[STATS] Up:2h30m R:45 S:42 F:3 | Sphinx:40 Direct:2 | Mix R:120 F:115 | Q:23 D:156 | Healthy:4
```

- **R**: Messages received
- **S**: Messages sent
- **F**: Failed deliveries
- **Sphinx**: Messages sent via Sphinx routing
- **Direct**: Messages sent directly (no Sphinx)
- **Mix R/F**: Mixed received/forwarded
- **Q**: Messages queued in delay pool
- **D**: Total delayed messages delivered
- **Healthy**: Number of healthy nodes in network

---

## 🌐 Network Information

### Current fog Network

The fog network currently consists of 5 active nodes:

| Node | Status |
|------|--------|
| kvara | ✅ Active |
| dries | ✅ Active |
| mct8 | ✅ Active |
| news | ✅ Active |
| pietro | ✅ Active |

**Join us!** Run your own node and strengthen the network's resilience.

### Minimum Network Requirements

- **3 nodes minimum** for Sphinx routing (3-hop paths)
- **5+ nodes recommended** for proper anonymity set
- **Network diversity** improves security

---

## 🔧 Troubleshooting

### Service won't start

**Error: "No such file or directory" for /var/lib/fog/data**

```bash
sudo mkdir -p /var/lib/fog/data
sudo chown fog:fog /var/lib/fog/data
sudo chmod 700 /var/lib/fog/data
sudo systemctl restart fog
```

**Error: "PKI file not found"**

```bash
# Make sure nodes.json exists
ls -l /var/lib/fog/nodes.json

# If missing, generate or obtain from network
sudo -u fog /var/lib/fog/fog -name YOUR.onion -short-name name -export-node-info
sudo cp nodes.json /var/lib/fog/
```

### Messages not being delivered

**Check Tor connectivity:**
```bash
# Test Tor is running
curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip

# Check fog can reach other nodes
sudo journalctl -u fog | grep HEALTH
```

**Check Sphinx routing:**
```bash
# Verify enough healthy nodes
sudo journalctl -u fog | grep "nodes healthy"

# Should show: "[HEALTH] Done. 4 nodes healthy" (or more)
```

### Queue not processing

**Check scheduler:**
```bash
sudo journalctl -u fog | grep "Scheduler started"

# Should show: "[POOL] Scheduler started (check every 1m0s)"
```

**Check for ready messages:**
```bash
sqlite3 /var/lib/fog/data/messages.db \
  "SELECT * FROM message_queue WHERE send_after <= strftime('%s','now');"
```

---

## 🤝 Contributing

### Run a Node

The best way to contribute is to run your own fog node! Requirements:

- Debian/Ubuntu server with static IP or dynamic DNS
- Tor hidden service
- Reliable uptime (>95% recommended)
- Bandwidth: ~100GB/month for relay node

**Get started:** Follow the Quick Start guide above and contact us to join the network.

### Development

```bash
# Clone repository
git clone https://github.com/yourusername/fog.git
cd fog

# Run tests
go test ./...

# Build
go build -tags="sqlite_omit_load_extension" -o fog fog.go

# Run locally
./fog -name test.onion -short-name test -smtp 127.0.0.1:2525 -debug
```

### Submit Issues

Found a bug? Have a feature request? [Open an issue](https://github.com/yourusername/fog/issues)

### Security Vulnerabilities

**Do not open public issues for security vulnerabilities.**

Contact: security@fog.network (PGP key available)

---

## 📚 Documentation

- **[CHANGELOG.md](CHANGELOG.md)** - Version history and release notes
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - Technical design and protocol specification
- **[SECURITY.md](SECURITY.md)** - Security model and threat analysis
- **[API.md](API.md)** - SMTP protocol and message format

---

## 🎓 How It Works

### Sphinx Mixnet Overview

```
Client → Entry Node → Middle Node → Exit Node → Destination
         (Hop 1)       (Hop 2)       (Hop 3)
```

**Each hop:**
1. Decrypts one layer of encryption
2. Cannot see final destination (onion routing)
3. Adds random delay before forwarding
4. Batches with other messages for mixing

**At exit node:**
1. Final decryption reveals cleartext message
2. Headers are sanitized (From, Message-ID, Date randomized)
3. All identifying metadata removed
4. Delivered to final destination

**Security properties:**
- No single node knows both sender and recipient
- Forward secrecy: past messages safe if node compromised
- Timing attacks mitigated by random delays + batching
- Traffic analysis resisted by fixed packet sizes + mixing

---

## 📖 License

MIT License - see [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Sphinx Mix Network**: Based on the Sphinx protocol by George Danezis and Ian Goldberg
- **Tor Project**: For anonymous networking infrastructure
- **Go Community**: For excellent cryptography libraries

---

## 📞 Contact

- **Website**: https://yamn.virebent.art
- **Usenet**: alt.privacy.anon-server

---

## ⚠️ Disclaimer

fog is designed for legal, privacy-preserving communications. Users are responsible for compliance with applicable laws. The fog network operators do not endorse or condone illegal activity.

**Exit node operators**: Be aware that running an exit node means your IP/server may be associated with traffic you did not originate. Consider legal implications in your jurisdiction.

---

<div align="center">

**🌫️ Join the fog network today and reclaim your digital privacy! 🌫️**

[![Download](https://img.shields.io/badge/Download-Latest-brightgreen.svg)](https://github.com/yourusername/fog/releases)
[![Donate](https://img.shields.io/badge/Donate-Bitcoin-orange.svg)](https://fog.network/donate)

</div>
