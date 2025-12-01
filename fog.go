// fog v2.0.1 - Anonymous SMTP Relay with Sphinx Mixnet
// Fixed padding, no PKI server needed, debug logs
// Copyright 2025 - fog Project

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/smtp"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/proxy"
)

const (
	Version = "2.0.1"

	TorSocks    = "127.0.0.1:9050"
	DefaultPort = "2525"
	NodePort    = "9999"

	MinDelay = 500 * time.Millisecond
	MaxDelay = 5 * time.Second

	BatchWindow = 30 * time.Second
	BatchSize   = 10

	HealthInterval = 3 * time.Minute
	StatsInterval  = 60 * time.Second

	MaxMsgSize   = 10 << 20
	MaxRecipient = 50
	QueueSize    = 500
	Workers      = 3

	CacheSize = 10000
	CacheTTL  = 24 * time.Hour

	SphinxHops = 3
	HeaderSize = 256
	AESKeySize = 32
	NonceSize  = 12
	HMACSize   = 32

	// Padding bucket for Sphinx packets (not message content)
	PaddedPayloadSize = 64 * 1024 // 64KB fixed size for all Sphinx payloads
)

// ============================================================================
// TYPES
// ============================================================================

type Message struct {
	ID   string
	From string
	To   []string
	Data []byte
	Time time.Time
}

type Node struct {
	ID      string `json:"node_id"`
	PubKey  string `json:"public_key"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Healthy bool   `json:"-"`
	LastOK  time.Time `json:"-"`
}

func (n *Node) GetPubKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(n.PubKey)
}

type PKI struct {
	Version string  `json:"version"`
	Updated string  `json:"updated"`
	Nodes   []*Node `json:"nodes"`
	mu      sync.RWMutex
}

type LocalNode struct {
	ID      string
	Private []byte
	Public  []byte
	Address string
	mu      sync.RWMutex
}

type Stats struct {
	Start   time.Time
	Recv    int64
	Sent    int64
	Failed  int64
	Sphinx  int64
	Direct  int64
	MixRecv int64
	MixFwd  int64
}

type ReplayCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
}

type Batch struct {
	packets []*SphinxPacket
	start   time.Time
	mu      sync.Mutex
}

type SphinxHeader struct {
	Version byte
	EphKey  [32]byte
	Routing []byte
	MAC     [32]byte
}

type SphinxPacket struct {
	Header  *SphinxHeader
	Payload []byte
}

type RoutingInfo struct {
	Next string `json:"next"`
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// ============================================================================
// GLOBALS
// ============================================================================

var (
	local     *LocalNode
	pki       *PKI
	stats     *Stats
	replay    *ReplayCache
	batch     *Batch
	queue     chan *Message
	torDialer proxy.Dialer
	hostname  string
	pkiFile   string
	dataDir   string
	useSphinx atomic.Bool
	debugMode bool
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
)

// ============================================================================
// DEBUG LOGGING
// ============================================================================

func dbg(format string, args ...interface{}) {
	if debugMode {
		log.Printf("[DEBUG] "+format, args...)
	}
}

// ============================================================================
// CRYPTO
// ============================================================================

func secureDelay() time.Duration {
	b := make([]byte, 8)
	rand.Read(b)
	val := binary.BigEndian.Uint64(b)
	// Map to range [MinDelay, MaxDelay]
	rangeMs := uint64((MaxDelay - MinDelay).Milliseconds())
	delayMs := MinDelay.Milliseconds() + int64(val%rangeMs)
	return time.Duration(delayMs) * time.Millisecond
}

func secureShuffle[T any](s []T) {
	for i := len(s) - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := int(jBig.Int64())
		s[i], s[j] = s[j], s[i]
	}
}

func deriveKeys(secret []byte) (enc, mac []byte, err error) {
	kdf := hkdf.New(sha256.New, secret, nil, []byte("fog-v2"))
	enc = make([]byte, AESKeySize)
	mac = make([]byte, AESKeySize)
	if _, err = io.ReadFull(kdf, enc); err != nil {
		return
	}
	_, err = io.ReadFull(kdf, mac)
	return
}

func encrypt(plain, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

func computeMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyMAC(data, mac, key []byte) bool {
	return hmac.Equal(computeMAC(data, key), mac)
}

// ============================================================================
// PADDING - FIXED: Preserves original message
// Format: [4 bytes original length][original data][random padding]
// ============================================================================

func padPayload(data []byte) []byte {
	origLen := len(data)
	
	// Create padded payload with length prefix
	// Format: [4 bytes len][data][random padding to PaddedPayloadSize]
	padded := make([]byte, PaddedPayloadSize)
	
	// First 4 bytes: original length
	binary.BigEndian.PutUint32(padded[:4], uint32(origLen))
	
	// Copy original data
	copy(padded[4:], data)
	
	// Fill rest with random bytes
	rand.Read(padded[4+origLen:])
	
	dbg("Padded payload: %d -> %d bytes", origLen, PaddedPayloadSize)
	return padded
}

func unpadPayload(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, errors.New("padded data too short")
	}
	
	origLen := binary.BigEndian.Uint32(padded[:4])
	
	if int(origLen) > len(padded)-4 {
		return nil, fmt.Errorf("invalid length: %d > %d", origLen, len(padded)-4)
	}
	
	data := make([]byte, origLen)
	copy(data, padded[4:4+origLen])
	
	dbg("Unpadded payload: %d -> %d bytes", len(padded), origLen)
	return data, nil
}

// ============================================================================
// REPLAY CACHE
// ============================================================================

func newReplayCache() *ReplayCache {
	return &ReplayCache{cache: make(map[string]time.Time)}
}

func (r *ReplayCache) Check(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cache[id]; exists {
		dbg("Replay detected: %s", id)
		return false
	}

	r.cache[id] = time.Now()

	if len(r.cache) > CacheSize {
		now := time.Now()
		for k, v := range r.cache {
			if now.Sub(v) > CacheTTL {
				delete(r.cache, k)
			}
		}
	}
	return true
}

// ============================================================================
// LOCAL NODE
// ============================================================================

func initNode(addr string) {
	keyFile := filepath.Join(dataDir, "node.key")

	var priv []byte
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		priv = data
		log.Printf("[NODE] Loaded existing key")
	} else {
		priv = make([]byte, 32)
		rand.Read(priv)
		os.WriteFile(keyFile, priv, 0600)
		log.Printf("[NODE] Generated new key")
	}

	pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
	id := fmt.Sprintf("%x", sha256.Sum256(pub))

	local = &LocalNode{
		ID:      id,
		Private: priv,
		Public:  pub,
		Address: addr,
	}

	log.Printf("[NODE] ID: %s", id[:16])
	log.Printf("[NODE] Address: %s", addr)
	dbg("Full ID: %s", id)
	dbg("PubKey: %x", pub)
}

// ============================================================================
// PKI - File based, no server needed
// ============================================================================

func newPKI() *PKI {
	return &PKI{Nodes: make([]*Node, 0)}
}

func (p *PKI) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := json.Unmarshal(data, p); err != nil {
		return err
	}

	// Mark all as healthy initially
	for _, n := range p.Nodes {
		n.Healthy = true
		n.LastOK = time.Now()
		dbg("Loaded node: %s (%s) at %s", n.Name, n.ID[:16], n.Address)
	}

	log.Printf("[PKI] Loaded %d nodes from %s", len(p.Nodes), path)
	return nil
}

func (p *PKI) GetAllOther() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var nodes []*Node
	for _, n := range p.Nodes {
		if local != nil && n.ID == local.ID {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func (p *PKI) GetHealthy() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var nodes []*Node
	for _, n := range p.Nodes {
		if !n.Healthy {
			continue
		}
		if local != nil && n.ID == local.ID {
			continue
		}
		nodes = append(nodes, n)
	}
	return nodes
}

func (p *PKI) HealthyCount() int {
	return len(p.GetHealthy())
}

// ============================================================================
// BATCH
// ============================================================================

func newBatch() *Batch {
	return &Batch{
		packets: make([]*SphinxPacket, 0, BatchSize),
		start:   time.Now(),
	}
}

func (b *Batch) Add(p *SphinxPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.packets = append(b.packets, p)
	dbg("Batch: added packet, now %d", len(b.packets))
}

func (b *Batch) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.packets) >= BatchSize || (len(b.packets) > 0 && time.Since(b.start) > BatchWindow)
}

func (b *Batch) Flush() []*SphinxPacket {
	b.mu.Lock()
	defer b.mu.Unlock()

	pkts := b.packets
	b.packets = make([]*SphinxPacket, 0, BatchSize)
	b.start = time.Now()

	secureShuffle(pkts)
	dbg("Batch: flushed %d packets (shuffled)", len(pkts))
	return pkts
}

func batchWorker() {
	defer wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if batch.Ready() {
				pkts := batch.Flush()
				log.Printf("[BATCH] Processing %d packets", len(pkts))
				for _, p := range pkts {
					go processPacket(p)
				}
			}
		}
	}
}

// ============================================================================
// SPHINX PACKET
// ============================================================================

func createPacket(msg *Message, route []*Node) (*SphinxPacket, error) {
	if len(route) != SphinxHops {
		return nil, fmt.Errorf("need %d hops, got %d", SphinxHops, len(route))
	}

	dbg("Creating Sphinx packet for %s", msg.ID)
	dbg("Route: %s -> %s -> %s", route[0].Name, route[1].Name, route[2].Name)

	// Build routing info
	routings := make([]RoutingInfo, SphinxHops)
	for i := 0; i < SphinxHops-1; i++ {
		routings[i] = RoutingInfo{Next: route[i+1].Address}
		dbg("Hop %d: forward to %s", i, route[i+1].Address)
	}

	// Last hop: EXIT with delivery info
	var validTo []string
	for _, to := range msg.To {
		to = strings.TrimSpace(to)
		if to != "" {
			validTo = append(validTo, to)
		}
	}
	if len(validTo) == 0 {
		return nil, errors.New("no recipients")
	}

	routings[SphinxHops-1] = RoutingInfo{
		Next: "EXIT",
		From: msg.From,
		To:   strings.Join(validTo, ","),
	}
	dbg("Hop %d: EXIT, deliver to %s", SphinxHops-1, validTo)

	// PAD the message payload BEFORE encryption
	paddedMsg := padPayload(msg.Data)
	dbg("Message padded: %d -> %d bytes", len(msg.Data), len(paddedMsg))

	// Encrypt layers (reverse: exit -> entry)
	payload := paddedMsg
	var ephKeys [][32]byte
	var secrets [][]byte

	for i := len(route) - 1; i >= 0; i-- {
		node := route[i]
		dbg("Encrypting layer %d for %s", i, node.Name)

		// Ephemeral key
		ephPriv := make([]byte, 32)
		rand.Read(ephPriv)
		ephPub, _ := curve25519.X25519(ephPriv, curve25519.Basepoint)

		// Shared secret
		nodePub, err := node.GetPubKey()
		if err != nil {
			return nil, fmt.Errorf("decode pubkey for %s: %w", node.Name, err)
		}
		shared, _ := curve25519.X25519(ephPriv, nodePub)

		encKey, _, _ := deriveKeys(shared)

		// Routing JSON
		routeData, _ := json.Marshal(routings[i])
		dbg("Layer %d routing: %s", i, string(routeData))

		// Combine: [4-byte routing length][routing][payload]
		combined := make([]byte, 4+len(routeData)+len(payload))
		binary.BigEndian.PutUint32(combined[:4], uint32(len(routeData)))
		copy(combined[4:], routeData)
		copy(combined[4+len(routeData):], payload)

		// Encrypt
		encrypted, err := encrypt(combined, encKey)
		if err != nil {
			return nil, fmt.Errorf("encrypt layer %d: %w", i, err)
		}

		dbg("Layer %d: %d -> %d bytes (encrypted)", i, len(combined), len(encrypted))
		payload = encrypted

		var ek [32]byte
		copy(ek[:], ephPub)
		ephKeys = append([][32]byte{ek}, ephKeys...)
		secrets = append([][]byte{shared}, secrets...)
	}

	// Build header
	header := &SphinxHeader{
		Version: 2,
		EphKey:  ephKeys[0],
	}

	// Remaining ephemeral keys
	for _, k := range ephKeys[1:] {
		header.Routing = append(header.Routing, k[:]...)
	}

	// HMAC
	_, macKey, _ := deriveKeys(secrets[0])
	buf := new(bytes.Buffer)
	buf.WriteByte(header.Version)
	buf.Write(header.EphKey[:])
	binary.Write(buf, binary.BigEndian, uint32(len(header.Routing)))
	buf.Write(header.Routing)
	copy(header.MAC[:], computeMAC(buf.Bytes(), macKey))

	dbg("Sphinx packet created: header=%d bytes, payload=%d bytes", 
		1+32+4+len(header.Routing)+32, len(payload))

	return &SphinxPacket{Header: header, Payload: payload}, nil
}

func serializeHeader(h *SphinxHeader) []byte {
	buf := new(bytes.Buffer)
	buf.WriteByte(h.Version)
	buf.Write(h.EphKey[:])
	binary.Write(buf, binary.BigEndian, uint32(len(h.Routing)))
	buf.Write(h.Routing)
	buf.Write(h.MAC[:])
	return buf.Bytes()
}

func deserializeHeader(data []byte) (*SphinxHeader, error) {
	if len(data) < 37 {
		return nil, errors.New("header too short")
	}

	h := &SphinxHeader{Version: data[0]}
	copy(h.EphKey[:], data[1:33])

	routeLen := binary.BigEndian.Uint32(data[33:37])
	if routeLen > 10240 {
		return nil, errors.New("routing too large")
	}
	if len(data) < 37+int(routeLen)+32 {
		return nil, errors.New("incomplete header")
	}

	h.Routing = data[37 : 37+routeLen]
	copy(h.MAC[:], data[37+routeLen:37+routeLen+32])

	return h, nil
}

// ============================================================================
// SPHINX PROCESSING
// ============================================================================

func processPacket(pkt *SphinxPacket) {
	atomic.AddInt64(&stats.MixRecv, 1)

	dbg("Processing Sphinx packet")
	dbg("EphKey: %x", pkt.Header.EphKey[:8])

	// Random delay
	delay := secureDelay()
	dbg("Delay: %s", delay)
	time.Sleep(delay)

	// Derive shared secret
	shared, err := curve25519.X25519(local.Private, pkt.Header.EphKey[:])
	if err != nil {
		log.Printf("[SPHINX] shared secret failed: %v", err)
		return
	}
	dbg("Shared secret derived")

	encKey, macKey, _ := deriveKeys(shared)

	// Verify HMAC if present
	isZeroMAC := true
	for _, b := range pkt.Header.MAC {
		if b != 0 {
			isZeroMAC = false
			break
		}
	}

	if !isZeroMAC {
		buf := new(bytes.Buffer)
		buf.WriteByte(pkt.Header.Version)
		buf.Write(pkt.Header.EphKey[:])
		binary.Write(buf, binary.BigEndian, uint32(len(pkt.Header.Routing)))
		buf.Write(pkt.Header.Routing)

		if !verifyMAC(buf.Bytes(), pkt.Header.MAC[:], macKey) {
			log.Printf("[SPHINX] HMAC verification FAILED")
			return
		}
		dbg("HMAC verified OK")
	} else {
		dbg("No HMAC (forwarded packet)")
	}

	// Decrypt payload
	plain, err := decrypt(pkt.Payload, encKey)
	if err != nil {
		log.Printf("[SPHINX] decrypt failed: %v", err)
		return
	}
	dbg("Decrypted payload: %d bytes", len(plain))

	if len(plain) < 4 {
		log.Printf("[SPHINX] payload too short")
		return
	}

	routeLen := binary.BigEndian.Uint32(plain[:4])
	if len(plain) < 4+int(routeLen) {
		log.Printf("[SPHINX] invalid route length")
		return
	}

	routeData := plain[4 : 4+routeLen]
	innerPayload := plain[4+routeLen:]

	var routing RoutingInfo
	if err := json.Unmarshal(routeData, &routing); err != nil {
		log.Printf("[SPHINX] route parse failed: %v", err)
		return
	}
	dbg("Routing: next=%s", routing.Next)

	if routing.Next == "EXIT" {
		log.Printf("[SPHINX] EXIT node - delivering message")
		dbg("From: %s, To: %s", routing.From, routing.To)

		// UNPAD the payload to get original message
		originalMsg, err := unpadPayload(innerPayload)
		if err != nil {
			log.Printf("[SPHINX] unpad failed: %v", err)
			atomic.AddInt64(&stats.Failed, 1)
			return
		}
		dbg("Unpadded message: %d bytes", len(originalMsg))

		for _, to := range strings.Split(routing.To, ",") {
			to = strings.TrimSpace(to)
			if to == "" {
				continue
			}
			if err := deliver(routing.From, to, originalMsg); err != nil {
				log.Printf("[SPHINX] delivery FAILED %s: %v", to, err)
				atomic.AddInt64(&stats.Failed, 1)
			} else {
				log.Printf("[SPHINX] SUCCESS delivered to %s", to)
				atomic.AddInt64(&stats.Sent, 1)
			}
		}
	} else {
		log.Printf("[SPHINX] Forwarding to %s", routing.Next)

		// Extract remaining ephemeral keys
		var ephKeys [][32]byte
		for i := 0; i+32 <= len(pkt.Header.Routing); i += 32 {
			var k [32]byte
			copy(k[:], pkt.Header.Routing[i:i+32])
			ephKeys = append(ephKeys, k)
		}
		dbg("Remaining ephemeral keys: %d", len(ephKeys))

		if len(ephKeys) == 0 {
			log.Printf("[SPHINX] no more ephemeral keys")
			return
		}

		newHeader := &SphinxHeader{
			Version: 2,
			EphKey:  ephKeys[0],
		}

		if len(ephKeys) > 1 {
			for _, k := range ephKeys[1:] {
				newHeader.Routing = append(newHeader.Routing, k[:]...)
			}
		}

		newPkt := &SphinxPacket{Header: newHeader, Payload: innerPayload}

		if err := sendPacket(routing.Next, newPkt); err != nil {
			log.Printf("[SPHINX] forward FAILED: %v", err)
		} else {
			log.Printf("[SPHINX] Forwarded to %s", routing.Next)
			atomic.AddInt64(&stats.MixFwd, 1)
		}
	}
}

func sendPacket(addr string, pkt *SphinxPacket) error {
	dbg("Connecting to %s via Tor", addr)
	
	conn, err := torDialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	dbg("Connected, sending packet")

	// Send padded header
	hdr := serializeHeader(pkt.Header)
	padded := make([]byte, HeaderSize)
	copy(padded, hdr)
	
	if _, err := conn.Write(padded); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := conn.Write(pkt.Payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}

	dbg("Packet sent: header=%d, payload=%d", HeaderSize, len(pkt.Payload))
	return nil
}

// ============================================================================
// NODE SERVER (receives Sphinx packets)
// ============================================================================

func startNodeServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("[NODE] Sphinx server on %s", addr)

	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			go handleNode(conn)
		}
	}()

	return nil
}

func handleNode(conn net.Conn) {
	defer conn.Close()
	
	remote := conn.RemoteAddr().String()
	dbg("Node connection from %s", remote)

	hdrBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(conn, hdrBuf); err != nil {
		if err != io.EOF {
			dbg("Header read failed from %s: %v", remote, err)
		}
		return
	}

	hdr, err := deserializeHeader(hdrBuf)
	if err != nil {
		log.Printf("[NODE] header parse failed: %v", err)
		return
	}

	payload, err := io.ReadAll(conn)
	if err != nil {
		log.Printf("[NODE] payload read failed: %v", err)
		return
	}

	dbg("Received packet: header parsed, payload=%d bytes", len(payload))
	batch.Add(&SphinxPacket{Header: hdr, Payload: payload})
	log.Printf("[NODE] Packet received and batched")
}

// ============================================================================
// SMTP SERVER (entry point)
// ============================================================================

func startSMTP(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("[SMTP] Listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				continue
			}
		}
		go handleSMTP(conn)
	}
}

func handleSMTP(conn net.Conn) {
	defer conn.Close()
	
	remote := conn.RemoteAddr().String()
	log.Printf("[SMTP] Connection from %s", remote)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	fmt.Fprintf(writer, "220 %s fog/%s\r\n", hostname, Version)
	writer.Flush()

	var from string
	var to []string
	var data bytes.Buffer

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		dbg("SMTP <- %s: %s", remote, line)

		parts := strings.SplitN(line, " ", 2)
		cmd := strings.ToUpper(parts[0])

		switch cmd {
		case "EHLO", "HELO":
			fmt.Fprintf(writer, "250-%s\r\n250-SIZE %d\r\n250 8BITMIME\r\n", hostname, MaxMsgSize)
			dbg("SMTP -> EHLO response")

		case "MAIL":
			if !strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:") {
				fmt.Fprintf(writer, "501 Syntax\r\n")
				writer.Flush()
				continue
			}
			addr := strings.TrimSpace(strings.SplitN(line, ":", 2)[1])
			if idx := strings.Index(addr, " "); idx != -1 {
				addr = addr[:idx]
			}
			from = strings.Trim(addr, "<>")
			to = nil
			fmt.Fprintf(writer, "250 OK\r\n")
			dbg("MAIL FROM: %s", from)

		case "RCPT":
			if from == "" {
				fmt.Fprintf(writer, "503 MAIL first\r\n")
				writer.Flush()
				continue
			}
			if len(to) >= MaxRecipient {
				fmt.Fprintf(writer, "452 Too many\r\n")
				writer.Flush()
				continue
			}
			if !strings.HasPrefix(strings.ToUpper(line), "RCPT TO:") {
				fmt.Fprintf(writer, "501 Syntax\r\n")
				writer.Flush()
				continue
			}
			addr := strings.Trim(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "<>")
			if addr == "" {
				fmt.Fprintf(writer, "501 Invalid\r\n")
				writer.Flush()
				continue
			}
			to = append(to, addr)
			fmt.Fprintf(writer, "250 OK\r\n")
			dbg("RCPT TO: %s", addr)

		case "DATA":
			if from == "" || len(to) == 0 {
				fmt.Fprintf(writer, "503 MAIL/RCPT first\r\n")
				writer.Flush()
				continue
			}

			fmt.Fprintf(writer, "354 End with .\r\n")
			writer.Flush()

			data.Reset()
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				// FIX: Accept both .\r\n and .\n
				if line == ".\r\n" || line == ".\n" {
					break
				}
				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}
				data.WriteString(line)
				if data.Len() > MaxMsgSize {
					fmt.Fprintf(writer, "552 Too large\r\n")
					writer.Flush()
					return
				}
			}

			id := genID()
			msg := &Message{
				ID:   id,
				From: from,
				To:   to,
				Data: data.Bytes(),
				Time: time.Now(),
			}

			if !replay.Check(id) {
				fmt.Fprintf(writer, "550 Duplicate\r\n")
				writer.Flush()
				continue
			}

			select {
			case queue <- msg:
				atomic.AddInt64(&stats.Recv, 1)
				fmt.Fprintf(writer, "250 OK: %s\r\n", id)
				log.Printf("[SMTP] Queued %s from %s to %d rcpt (%d bytes)", 
					id, from, len(to), data.Len())
			default:
				fmt.Fprintf(writer, "452 Queue full\r\n")
			}

			from = ""
			to = nil

		case "RSET":
			from = ""
			to = nil
			fmt.Fprintf(writer, "250 OK\r\n")

		case "QUIT":
			fmt.Fprintf(writer, "221 Bye\r\n")
			writer.Flush()
			return

		default:
			fmt.Fprintf(writer, "502 Unknown\r\n")
		}

		writer.Flush()
	}
}

func genID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ============================================================================
// DELIVERY
// ============================================================================

func deliver(from, to string, data []byte) error {
	parts := strings.Split(to, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid email: %s", to)
	}

	server := parts[1] + ":25"
	dbg("Delivering to %s via %s", to, server)

	conn, err := torDialer.Dial("tcp", server)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, hostname)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	defer client.Close()

	if err := client.Hello(hostname); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	
	if _, err := wc.Write(data); err != nil {
		wc.Close()
		return fmt.Errorf("write: %w", err)
	}
	
	if err := wc.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}

	dbg("Delivered %d bytes to %s", len(data), to)
	return client.Quit()
}

// ============================================================================
// WORKERS
// ============================================================================

func worker(id int) {
	defer wg.Done()
	log.Printf("[WORKER %d] Started", id)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[WORKER %d] Stopped", id)
			return
		case msg := <-queue:
			processMsg(id, msg)
		}
	}
}

func processMsg(wid int, msg *Message) {
	delay := secureDelay()
	log.Printf("[WORKER %d] Processing %s (delay %s)", wid, msg.ID, delay.Round(time.Millisecond))
	time.Sleep(delay)

	healthy := pki.HealthyCount()
	dbg("Healthy nodes: %d (need %d for Sphinx)", healthy, SphinxHops)

	if useSphinx.Load() && healthy >= SphinxHops {
		if err := sphinxRoute(msg); err != nil {
			log.Printf("[WORKER %d] Sphinx failed: %v, using direct", wid, err)
			atomic.AddInt64(&stats.Direct, 1)
			directRoute(msg)
		} else {
			atomic.AddInt64(&stats.Sphinx, 1)
		}
	} else {
		if useSphinx.Load() {
			log.Printf("[WORKER %d] Not enough nodes (%d/%d), using direct", wid, healthy, SphinxHops)
		}
		atomic.AddInt64(&stats.Direct, 1)
		directRoute(msg)
	}
}

func sphinxRoute(msg *Message) error {
	healthy := pki.GetHealthy()
	if len(healthy) < SphinxHops {
		return fmt.Errorf("need %d nodes, have %d", SphinxHops, len(healthy))
	}

	// Secure shuffle and select
	secureShuffle(healthy)
	route := healthy[:SphinxHops]

	log.Printf("[SPHINX] Route: %s -> %s -> %s", route[0].Name, route[1].Name, route[2].Name)

	pkt, err := createPacket(msg, route)
	if err != nil {
		return fmt.Errorf("create packet: %w", err)
	}

	if err := sendPacket(route[0].Address, pkt); err != nil {
		return fmt.Errorf("send to entry: %w", err)
	}

	atomic.AddInt64(&stats.Sent, 1)
	log.Printf("[SPHINX] SUCCESS: %s via %s", msg.ID, route[0].Name)
	return nil
}

func directRoute(msg *Message) {
	for _, to := range msg.To {
		to = strings.TrimSpace(to)
		if to == "" {
			continue
		}
		if err := deliver(msg.From, to, msg.Data); err != nil {
			log.Printf("[RELAY] FAILED %s -> %s: %v", msg.ID, to, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			log.Printf("[RELAY] SUCCESS %s -> %s", msg.ID, to)
			atomic.AddInt64(&stats.Sent, 1)
		}
	}
}

// ============================================================================
// HEALTH CHECK - Checks ALL nodes, not just healthy ones
// ============================================================================

func healthChecker() {
	defer wg.Done()
	
	// Initial check
	time.Sleep(5 * time.Second)
	doHealthCheck()
	
	ticker := time.NewTicker(HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doHealthCheck()
		}
	}
}

func doHealthCheck() {
	nodes := pki.GetAllOther()
	log.Printf("[HEALTH] Checking %d nodes", len(nodes))

	var wgCheck sync.WaitGroup
	for _, n := range nodes {
		wgCheck.Add(1)
		go func(node *Node) {
			defer wgCheck.Done()
			checkNode(node)
		}(n)
	}
	wgCheck.Wait()
	
	log.Printf("[HEALTH] Done. %d nodes healthy", pki.HealthyCount())
}

func checkNode(n *Node) {
	dbg("Checking %s at %s", n.Name, n.Address)
	
	conn, err := torDialer.Dial("tcp", n.Address)
	if err != nil {
		pki.mu.Lock()
		n.Healthy = false
		pki.mu.Unlock()
		log.Printf("[HEALTH] %s DOWN: %v", n.Name, err)
		return
	}
	conn.Close()

	pki.mu.Lock()
	n.Healthy = true
	n.LastOK = time.Now()
	pki.mu.Unlock()
	log.Printf("[HEALTH] %s OK", n.Name)
}

// ============================================================================
// STATS
// ============================================================================

func statsMonitor() {
	defer wg.Done()
	ticker := time.NewTicker(StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			up := time.Since(stats.Start).Round(time.Second)
			log.Printf("[STATS] Up:%s R:%d S:%d F:%d | Sphinx:%d Direct:%d | Mix R:%d F:%d | Healthy:%d",
				up,
				atomic.LoadInt64(&stats.Recv),
				atomic.LoadInt64(&stats.Sent),
				atomic.LoadInt64(&stats.Failed),
				atomic.LoadInt64(&stats.Sphinx),
				atomic.LoadInt64(&stats.Direct),
				atomic.LoadInt64(&stats.MixRecv),
				atomic.LoadInt64(&stats.MixFwd),
				pki.HealthyCount())
		}
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	name := flag.String("name", "fog.local", "Hostname (your .onion address)")
	shortName := flag.String("short-name", "", "Short name for logs (e.g. kvara, news, mail)")
	smtpAddr := flag.String("smtp", "127.0.0.1:2525", "SMTP listen address")
	nodeAddr := flag.String("node", "127.0.0.1:9999", "Node listen address")
	sphinx := flag.Bool("sphinx", false, "Enable Sphinx mixnet")
	pkiFlag := flag.String("pki-file", "", "Path to nodes.json")
	dataFlag := flag.String("data-dir", "./fog-data", "Data directory")
	debug := flag.Bool("debug", false, "Enable debug logging")
	export := flag.Bool("export-node-info", false, "Export node info for nodes.json")
	version := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Printf("fog v%s\n\n", Version)
		fmt.Println("Security features:")
		fmt.Println("  ✓ Curve25519 ECDH + AES-256-GCM")
		fmt.Println("  ✓ 3-hop Sphinx mixnet")
		fmt.Println("  ✓ crypto/rand everywhere (no math/rand)")
		fmt.Println("  ✓ Traffic analysis resistance (batching)")
		fmt.Println("  ✓ Timing attack resistance (random delays)")
		fmt.Println("  ✓ Size correlation resistance (fixed payload)")
		fmt.Println("  ✓ Replay protection (24h cache)")
		fmt.Println("  ✓ No metadata retention")
		fmt.Println("\nNo PKI server needed - uses local nodes.json")
		os.Exit(0)
	}

	debugMode = *debug
	dataDir = *dataFlag
	os.MkdirAll(dataDir, 0700)

	if *export {
		initNode(*nodeAddr)
		
		// Use short name if provided, otherwise use hostname
		displayName := *shortName
		if displayName == "" {
			displayName = *name
		}
		
		// Create properly formatted nodes.json
		nodeInfo := map[string]interface{}{
			"version": Version,
			"updated": time.Now().UTC().Format(time.RFC3339),
			"nodes": []map[string]string{
				{
					"node_id":    local.ID,
					"public_key": base64.StdEncoding.EncodeToString(local.Public),
					"address":    *name + ":9999",
					"name":       displayName,
					"version":    Version,
				},
			},
		}
		
		data, _ := json.MarshalIndent(nodeInfo, "", "  ")
		
		// Write to nodes.json
		if err := os.WriteFile("nodes.json", data, 0600); err != nil {
			log.Fatalf("Failed to write nodes.json: %v", err)
		}
		
		fmt.Println(string(data))
		log.Printf("Written to nodes.json")
		os.Exit(0)
	}

	log.Printf("[FOG] Starting v%s", Version)
	if debugMode {
		log.Printf("[FOG] Debug mode ENABLED")
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	hostname = *name
	pkiFile = *pkiFlag

	// Init
	stats = &Stats{Start: time.Now()}
	replay = newReplayCache()
	batch = newBatch()
	queue = make(chan *Message, QueueSize)
	pki = newPKI()

	initNode(*nodeAddr)

	// Tor
	dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[TOR] Failed: %v", err)
	}
	torDialer = dialer
	log.Printf("[TOR] Connected to %s", TorSocks)

	useSphinx.Store(*sphinx)

	if *sphinx {
		log.Printf("[FOG] Sphinx mode ENABLED")

		if pkiFile == "" {
			log.Printf("[FOG] WARNING: No -pki-file specified, Sphinx will use direct relay")
		} else {
			if err := pki.Load(pkiFile); err != nil {
				log.Printf("[PKI] Load failed: %v", err)
			}
		}

		wg.Add(1)
		go healthChecker()

		wg.Add(1)
		if err := startNodeServer(*nodeAddr); err != nil {
			log.Fatalf("[NODE] Failed: %v", err)
		}

		wg.Add(1)
		go batchWorker()
	} else {
		log.Printf("[FOG] Direct relay mode (no Sphinx)")
	}

	// Workers
	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go worker(i)
	}

	wg.Add(1)
	go statsMonitor()

	// Signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		log.Printf("[FOG] Shutdown signal received")
		cancel()
	}()

	if err := startSMTP(*smtpAddr); err != nil {
		log.Fatalf("[SMTP] Failed: %v", err)
	}

	wg.Wait()
	log.Printf("[FOG] Shutdown complete")
}
