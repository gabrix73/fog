# Pluto2 Onion SMTP

A privacy-focused SMTP relay server designed for Tor hidden services with strong anonymity protections and mixnet architecture.

## Overview

Pluto2 is a specialized SMTP relay that operates exclusively over Tor, providing robust protection against traffic analysis, timing attacks, and metadata correlation. It accepts mail on .onion addresses and relays to both onion services and clearnet destinations via Tor circuits.

## Features

### Core Functionality
- **Tor-Only Operation**: All connections route through Tor SOCKS5 proxy
- **Hybrid Relay**: Supports both .onion and clearnet destinations
- **RFC-Compliant**: Validates email addresses according to RFC standards
- **v3 Onion Support**: Requires v3 hidden service addresses (56 characters)
- **Automatic MX Lookup**: Resolves mail exchangers for clearnet domains

### Security & Privacy

#### Traffic Analysis Protection
- **Mixnet Batching**: Groups messages in 30-second windows, shuffles order, and adds random delays
- **Cover Traffic**: Generates dummy messages every 15 seconds to mask real traffic patterns
- **Adaptive Padding**: Normalizes message sizes to 8KB blocks to prevent size correlation
- **Randomized Delays**: Applies cryptographically secure random delays (100ms-2s) to prevent timing attacks

#### Attack Mitigation
- **Replay Protection**: 24-hour message ID cache prevents duplicate message processing
- **Rate Limiting**: 10 requests per minute per IP address
- **Forward Secrecy**: Multi-hop Tor routing protects against node compromise
- **No Metadata Retention**: Zero persistent logging of message metadata

## Installation

### Prerequisites
- Go 1.19 or later
- Tor daemon running with SOCKS5 proxy on `127.0.0.1:9050`

### Dependencies
```bash
go get golang.org/x/net/proxy
```

### Build
```bash
# Standard build
go build -o pluto2 pluto2.go

# Static binary (recommended for production)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -ldflags="-s -w -extldflags '-static'" \
  -trimpath \
  -o pluto2 \
  pluto2.go
```

## Configuration

### Tor Setup

Edit `/etc/tor/torrc`:
```conf
# SOCKS5 proxy for outgoing connections
SocksPort 127.0.0.1:9050

# Hidden service for SMTP
HiddenServiceDir /var/lib/tor/pluto2_smtp/
HiddenServicePort 25 127.0.0.1:2525

# Optional: Enhanced privacy settings
IsolateDestAddr 1
IsolateDestPort 1
```

Restart Tor:
```bash
sudo systemctl restart tor
```

Get your .onion address:
```bash
sudo cat /var/lib/tor/pluto2_smtp/hostname
```

## Usage

### Starting the Server

```bash
./pluto2 -name "your56characteronionaddresshere.onion" -addr "127.0.0.1:2525"
```

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-name` | (example) | Your v3 .onion hostname (56 chars + .onion) |
| `-addr` | `127.0.0.1:2525` | Listen address for SMTP server |

### Testing Connection

```bash
# Using telnet
telnet 127.0.0.1 2525
EHLO test.local
MAIL FROM:<sender@example.onion>
RCPT TO:<recipient@destination.onion>
DATA
Subject: Test
Body content here
.
QUIT

# Using swaks
swaks --server 127.0.0.1:2525 \
      --from sender@test.onion \
      --to recipient@dest.onion \
      --body "Test message"
```

### Mail2News Gateway Example

Configure your mail2news client to use:
- **SMTP Server**: `your-onion-address.onion:25` (via Tor)
- **Local Server**: `127.0.0.1:2525` (if running locally)

## Architecture

### Message Flow

```
[Client] 
   ↓
[Pluto2 SMTP Server :2525]
   ↓
[Accept & Validate]
   ↓
[Mixnet Batcher] ← [Cover Traffic Generator]
   ↓ (30s batch window)
[Shuffle & Random Delays]
   ↓
[Relay Workers (5 workers)]
   ↓
[Tor SOCKS5 :9050]
   ↓
[Tor Network (3-6 hops)]
   ↓
[.onion:25] or [Clearnet MX:25]
```

### Components

#### MixnetBatcher
- Collects messages for 30-second windows
- Shuffles message order using cryptographic randomness
- Applies random delays to each message
- Breaks temporal correlation between input and output

#### CoverTrafficGenerator
- Generates dummy messages every 15 seconds
- Uses realistic-looking addresses
- Discarded before actual relay (marked as `IsCoverTraffic`)
- Ensures consistent traffic patterns even with low real volume

#### RelayWorkers
- 5 concurrent workers process relay queue
- Exponential backoff retry (up to 9 attempts)
- Supports both .onion and clearnet destinations
- All connections route through Tor SOCKS5

#### RateLimiter
- Per-IP rate limiting (10 requests/minute)
- Automatic cleanup of expired entries
- Prevents abuse and DoS attempts

#### MessageIDCache
- SHA-512 based message IDs with timestamp and random entropy
- 24-hour expiration window
- Prevents replay attacks
- Automatic cleanup every hour

## Security Considerations

### Threat Model

#### Protected Against
- **Passive Network Observer**: Cannot see destinations, content, or timing
- **ISP/Local Network**: Only sees encrypted Tor traffic
- **Timing Attacks**: Mixnet batching and random delays break timing correlation
- **Size Correlation**: Adaptive padding normalizes message sizes
- **Replay Attacks**: Message ID cache prevents duplicate processing
- **Node Compromise**: Forward secrecy via Tor multi-hop routing

#### Partial Protection
- **Tor Exit Node (clearnet only)**: Can see destination and SMTP protocol, but not origin
- **Clearnet Destination**: Sees Tor exit node IP and message metadata, but not real sender IP

#### Limited Protection
- **Global Adversary**: Statistical analysis may be possible with both entry and exit observation
- **Recommendation**: Use .onion destinations whenever possible for maximum anonymity

### Clearnet Relay Risks

When relaying to clearnet domains (e.g., dizum.com):
- ⚠️ Destination sees Tor exit node IP
- ⚠️ SMTP metadata is visible (FROM, TO, timestamp)
- ⚠️ Tor exit nodes may be blocked/flagged as spam
- ✅ Your real IP remains hidden
- ✅ Tor provides transport layer protection

### Best Practices

1. **Use .onion destinations** whenever possible
2. **Verify server name** matches your hidden service hostname
3. **Monitor logs** for suspicious activity (but logs contain no sensitive data)
4. **Keep Tor updated** to latest stable version
5. **Use strong server credentials** if exposing to untrusted networks
6. **Consider message content** when relaying to clearnet
7. **Regular security audits** of both Pluto2 and Tor configuration

## Configuration Constants

Can be modified in source before compilation:

```go
const (
    TorSocksProxyAddr      = "127.0.0.1:9050"  // Tor SOCKS5 proxy
    RelayWorkerCount       = 5                  // Concurrent relay workers
    DeliveryTimeout        = 30 * time.Second   // SMTP delivery timeout
    MixnetBatchWindow      = 30 * time.Second   // Batch collection window
    CoverTrafficInterval   = 15 * time.Second   // Dummy message interval
    MessageIDCacheDuration = 24 * time.Hour     // Replay protection window
    PaddingSizeUnit        = 8 * 1024           // Padding block size
    MinDelay               = 100 * time.Millisecond  // Minimum random delay
    MaxDelay               = 2 * time.Second         // Maximum random delay
    RateLimitPerIP         = 10                 // Requests per window
    RateLimitWindow        = 1 * time.Minute    // Rate limit window
)
```

## Performance

### Latency
- **Minimum**: 30 seconds (mixnet batch window)
- **Average**: 30-35 seconds (batch + random delays)
- **Clearnet**: +10-20 seconds (MX lookup + Tor circuit)

### Throughput
- **Queue Capacity**: 1000 messages
- **Concurrent Workers**: 5 relay workers
- **Batch Processing**: ~20-50 messages per batch (depends on traffic)

### Resource Usage
- **Memory**: ~10-20 MB (idle), scales with queue size
- **CPU**: Minimal (<1% idle, <5% during relay)
- **Network**: Depends on message volume + cover traffic

## Logging

Pluto2 logs operational events without exposing sensitive data:

```
[CONN]  - Connection events
[SMTP]  - SMTP protocol exchange
[BATCH] - Mixnet batching operations
[RELAY] - Delivery attempts and results
[COVER] - Cover traffic generation
```

**What is NOT logged:**
- Message content
- Persistent metadata
- Client identities beyond IP (used only for rate limiting)

## Troubleshooting

### Common Issues

**Error: `failed to create Tor dialer`**
- Solution: Ensure Tor is running on port 9050
- Check: `systemctl status tor`

**Error: `no MX records found`**
- Solution: Domain may not exist or DNS is unreachable
- Check: `dig MX domain.com`

**Error: `Rate limit exceeded`**
- Solution: Wait 1 minute between connection attempts
- Or: Increase `RateLimitPerIP` constant

**Error: `connection refused`**
- Solution: Destination .onion service may be offline
- Check: Verify destination is reachable via Tor Browser

**Slow delivery (>60s)**
- Expected: Mixnet batching adds 30s by design
- Optional: Reduce `MixnetBatchWindow` for testing (reduces anonymity)

## Development

### Testing

```bash
# Run server with verbose logging
go run pluto2.go -name "test.onion" -addr "127.0.0.1:2525"

# Send test message
echo -e "EHLO test\nMAIL FROM:<test@test.onion>\nRCPT TO:<dest@dest.onion>\nDATA\nTest\n.\nQUIT" | nc 127.0.0.1 2525
```

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure code follows Go conventions
5. Submit a pull request

### Code Structure

```
pluto2.go
├── Validation (email, domain, .onion)
├── Security Components
│   ├── MessageIDCache (replay protection)
│   ├── RateLimiter (abuse prevention)
│   ├── MixnetBatcher (traffic analysis protection)
│   └── CoverTrafficGenerator (pattern masking)
├── SMTP Server
│   ├── Connection handling
│   ├── Protocol implementation
│   └── Command processing
└── Relay System
    ├── Worker pool
    ├── Tor integration
    └── Retry logic
```

## License

[MIT]

## Disclaimer

This software is provided for legitimate privacy-enhancing purposes. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse.

## Acknowledgments

- Built on the Tor Project's anonymity network
- Inspired by mixnet research and remailer systems
- Uses Go's excellent standard library and crypto packages

## Contact

- **Issues**: [https://www.virebent.art/contacts.html]
- **Security**: [[Security contact/PGP key]](https://www.virebent.art/C6625F44806AC65957935BD848BF95F3ECACDDB3.asc)
- **Discussion**: [alt.privacy.anon-server]

---

**Note**: Pluto2 prioritizes privacy and anonymity. The 30-second batching delay is a feature, not a bug – it's essential for breaking timing correlation. If you need lower latency, consider the privacy trade-offs carefully.
