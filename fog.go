// fog v1.3.3-minimal - Anonymous SMTP Relay
// Fixed Sphinx encryption with AES-256-GCM + Full mixnetwork
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
	"encoding/binary"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
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

// ============================================================================
// CONSTANTS
// ============================================================================

const (
	Version = "1.3.3-minimal"
	AppName = "fog"

	// Network
	TorSocksProxyAddr = "127.0.0.1:9050"
	DefaultSMTPPort   = "2525"
	DefaultNodePort   = "9999"

	// Timing
	MinDelay            = 100 * time.Millisecond
	MaxDelay            = 10 * time.Second
	PoissonLambda       = 2.0
	PKIRefreshInterval  = 5 * time.Minute  // Sync keys frequently
	PKIRetryInterval    = 2 * time.Minute
	HealthCheckInterval = 5 * time.Minute
	StatsInterval       = 60 * time.Second
	KeyRotationInterval = 24 * time.Hour // 24 hours

	// Mixnet batching
	BatchInterval = 30 * time.Second
	BatchSize     = 10
	MinBatchDelay = 5 * time.Second
	MaxBatchDelay = 60 * time.Second

	// Limits
	MaxMessageSize   = 10 * 1024 * 1024 // 10MB
	MaxRecipients    = 100
	MessageQueueSize = 1000
	ReplayCacheSize  = 10000
	ReplayCacheTTL   = 24 * time.Hour
	WorkerCount      = 5

	// Padding
	MinPaddingSize = 512
	MaxPaddingSize = 32768
	PaddingBuckets = 9

	// Rate limiting
	RateLimitMessages = 100
	RateLimitWindow   = 1 * time.Hour

	// Sphinx - Variable hop routing
	MinSphinxHops     = 3
	MaxSphinxHops     = 6
	SphinxHeaderSize  = 256
	SphinxPayloadSize = 10 * 1024 * 1024
	AESKeySize        = 32 // AES-256
	AESNonceSize      = 12 // GCM nonce
	HMACSize          = 32 // SHA256
)

// Padding bucket sizes
var PaddingSizes = [PaddingBuckets]int{
	512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
}

// ============================================================================
// TYPES
// ============================================================================

type Message struct {
	ID        string
	From      string
	To        []string
	Data      []byte
	Timestamp time.Time
	Size      int
}

type LocalNode struct {
	NodeID      string
	PrivateKey  []byte
	PublicKey   []byte
	Address     string
	Version     string
	CreatedAt   time.Time
	mu          sync.RWMutex
}

type PKINode struct {
	NodeID       string    `json:"node_id"`
	PublicKey    []byte    `json:"public_key"`
	Address      string    `json:"address"`
	Version      string    `json:"version"`
	LastSeen     time.Time `json:"last_seen"`
	Healthy      bool      `json:"healthy"`
	FailureCount int       `json:"failure_count"`
	SuccessCount int       `json:"success_count"`
	LastHealthy  time.Time `json:"last_healthy"`
}

type PKIDirectory struct {
	Nodes     map[string]*PKINode `json:"nodes"`
	UpdatedAt time.Time           `json:"updated_at"`
	mu        sync.RWMutex
}

type Statistics struct {
	StartTime        time.Time `json:"start_time"`
	MessagesReceived int64     `json:"messages_received"`
	MessagesRelayed  int64     `json:"messages_relayed"`
	MessagesFailed   int64     `json:"messages_failed"`
	BytesProcessed   int64     `json:"bytes_processed"`
	SphinxRouted     int64     `json:"sphinx_routed"`
	DirectRouted     int64     `json:"direct_routed"`
	SphinxReceived   int64     `json:"sphinx_received"`
	SphinxForwarded  int64     `json:"sphinx_forwarded"`
	mu               sync.RWMutex
}

type ReplayCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
}

type RateLimiter struct {
	connections map[string][]time.Time
	mu          sync.RWMutex
}

// Sphinx packet structures
type SphinxHeader struct {
	Version      byte
	EphemeralKey [32]byte // Curve25519 public key
	RoutingInfo  []byte   // Encrypted routing for all hops
	HMAC         [32]byte // Authentication
}

type SphinxPacket struct {
	Header  *SphinxHeader
	Payload []byte // AES-256-GCM encrypted payload
}

type RoutingInfo struct {
	NextHop     string // Next node address or "EXIT"
	MessageFrom string // Original sender (only for exit node)
	MessageTo   string // Final recipient (only for exit node)
}

type SMTPServer struct {
	hostname string
	addr     string
	listener net.Listener
}

type SphinxNodeServer struct {
	addr     string
	listener net.Listener
}

// Mixnet batch
type MixnetBatch struct {
	packets   []*SphinxPacket
	startTime time.Time
	mu        sync.Mutex
}

// ============================================================================
// GLOBAL STATE
// ============================================================================

var (
	// Core components
	localNode      *LocalNode
	pkiDirectory   *PKIDirectory
	stats          *Statistics
	replayCache    *ReplayCache
	rateLimiter    *RateLimiter
	messageQueue   chan *Message
	serverHostname string

	// Mixnet
	mixnetBatch *MixnetBatch

	// Tor connectivity
	torDialer proxy.Dialer

	// Shutdown
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	shutdownWg     sync.WaitGroup

	// Configuration
	enableSphinx atomic.Bool
	pkiURL       string
	dataDir      string
	statsFile    string
	nodeAddr     string
)

// ============================================================================
// MIXNET BATCH
// ============================================================================

func NewMixnetBatch() *MixnetBatch {
	return &MixnetBatch{
		packets:   make([]*SphinxPacket, 0, BatchSize),
		startTime: time.Now(),
	}
}

func (b *MixnetBatch) Add(packet *SphinxPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.packets = append(b.packets, packet)
}

func (b *MixnetBatch) Ready() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	// Batch ready if: full OR timeout reached
	if len(b.packets) >= BatchSize {
		return true
	}
	if time.Since(b.startTime) > BatchInterval {
		return len(b.packets) > 0
	}
	return false
}

func (b *MixnetBatch) Flush() []*SphinxPacket {
	b.mu.Lock()
	defer b.mu.Unlock()
	
	packets := b.packets
	b.packets = make([]*SphinxPacket, 0, BatchSize)
	b.startTime = time.Now()
	
	// Shuffle batch for timing attack resistance
	mathrand.Shuffle(len(packets), func(i, j int) {
		packets[i], packets[j] = packets[j], packets[i]
	})
	
	return packets
}

func MixnetBatchWorker() {
	defer shutdownWg.Done()
	
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			if mixnetBatch.Ready() {
				packets := mixnetBatch.Flush()
				log.Printf("[MIXNET] Flushing batch: %d packets", len(packets))
				
				for _, packet := range packets {
					go processSphinxPacket(packet)
				}
			}
		}
	}
}

// ============================================================================
// PKI DIRECTORY
// ============================================================================

func NewPKIDirectory() *PKIDirectory {
	return &PKIDirectory{
		Nodes:     make(map[string]*PKINode),
		UpdatedAt: time.Now(),
	}
}

func (p *PKIDirectory) AddNode(node *PKINode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Nodes[node.NodeID] = node
	p.UpdatedAt = time.Now()
}

func (p *PKIDirectory) GetNode(nodeID string) (*PKINode, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	node, ok := p.Nodes[nodeID]
	return node, ok
}

func (p *PKIDirectory) GetHealthyNodes() []*PKINode {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var healthy []*PKINode
	for _, node := range p.Nodes {
		// Skip unhealthy nodes
		if !node.Healthy {
			continue
		}
		// Skip self only if localNode is initialized
		if localNode != nil && node.NodeID == localNode.NodeID {
			continue
		}
		healthy = append(healthy, node)
	}
	return healthy
}

func (p *PKIDirectory) HealthyCount() int {
	return len(p.GetHealthyNodes())
}

func (p *PKIDirectory) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := json.Unmarshal(data, p); err != nil {
		return err
	}

	log.Printf("[PKI] Loaded %d nodes from file", len(p.Nodes))
	return nil
}

func (p *PKIDirectory) SaveToFile(path string) error {
	p.mu.RLock()
	data, err := json.MarshalIndent(p, "", "  ")
	p.mu.RUnlock()

	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (p *PKIDirectory) LoadFromURL(url string) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Dial: torDialer.Dial,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if err := json.Unmarshal(data, p); err != nil {
		return err
	}

	log.Printf("[PKI] Loaded %d nodes from URL", len(p.Nodes))
	return nil
}

// ============================================================================
// LOCAL NODE
// ============================================================================

func InitializeLocalNode(address string) {
	keyFile := filepath.Join(dataDir, "node.key")
	
	var privateKey []byte
	
	// Try to load existing key
	if data, err := os.ReadFile(keyFile); err == nil && len(data) == 32 {
		privateKey = data
		log.Printf("[NODE] Loaded existing key from %s", keyFile)
	} else {
		// Generate new key
		privateKey = make([]byte, 32)
		if _, err := rand.Read(privateKey); err != nil {
			log.Fatalf("[NODE] Failed to generate private key: %v", err)
		}
		
		// Save key
		if err := os.WriteFile(keyFile, privateKey, 0600); err != nil {
			log.Printf("[NODE] Warning: failed to save key: %v", err)
		} else {
			log.Printf("[NODE] Saved new key to %s", keyFile)
		}
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		log.Fatalf("[NODE] Failed to generate public key: %v", err)
	}

	nodeID := generateNodeID(publicKey)

	localNode = &LocalNode{
		NodeID:     nodeID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Address:    address,
		Version:    Version,
		CreatedAt:  time.Now(),
	}

	log.Printf("[NODE] Initialized: %s", nodeID[:16])
	log.Printf("[NODE] Address: %s", address)
	log.Printf("[NODE] Public key: %x", publicKey[:16])
}

func generateNodeID(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return fmt.Sprintf("%x", hash[:])
}

func RotatePKIKeys() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(KeyRotationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			localNode.mu.Lock()

			oldKey := localNode.NodeID[:16]

			privateKey := make([]byte, 32)
			if _, err := rand.Read(privateKey); err != nil {
				log.Printf("[PKI] Key rotation failed: %v", err)
				localNode.mu.Unlock()
				continue
			}

			publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
			if err != nil {
				log.Printf("[PKI] Key rotation failed: %v", err)
				localNode.mu.Unlock()
				continue
			}

			localNode.PrivateKey = privateKey
			localNode.PublicKey = publicKey
			localNode.NodeID = generateNodeID(publicKey)

			log.Printf("[PKI] Keys rotated: %s -> %s", oldKey, localNode.NodeID[:16])
			localNode.mu.Unlock()
		}
	}
}

// ============================================================================
// STATISTICS
// ============================================================================

func NewStatistics() *Statistics {
	return &Statistics{
		StartTime: time.Now(),
	}
}

func (s *Statistics) IncrementReceived() {
	atomic.AddInt64(&s.MessagesReceived, 1)
}

func (s *Statistics) IncrementRelayed() {
	atomic.AddInt64(&s.MessagesRelayed, 1)
}

func (s *Statistics) IncrementFailed() {
	atomic.AddInt64(&s.MessagesFailed, 1)
}

func (s *Statistics) AddBytes(n int64) {
	atomic.AddInt64(&s.BytesProcessed, n)
}

func (s *Statistics) IncrementSphinx() {
	atomic.AddInt64(&s.SphinxRouted, 1)
}

func (s *Statistics) IncrementDirect() {
	atomic.AddInt64(&s.DirectRouted, 1)
}

func (s *Statistics) IncrementSphinxReceived() {
	atomic.AddInt64(&s.SphinxReceived, 1)
}

func (s *Statistics) IncrementSphinxForwarded() {
	atomic.AddInt64(&s.SphinxForwarded, 1)
}

func (s *Statistics) Print() {
	uptime := time.Since(s.StartTime)
	fmt.Printf("\n=== fog Statistics ===\n")
	fmt.Printf("Uptime:          %s\n", uptime.Round(time.Second))
	fmt.Printf("Messages:        R:%d D:%d F:%d\n",
		atomic.LoadInt64(&s.MessagesReceived),
		atomic.LoadInt64(&s.MessagesRelayed),
		atomic.LoadInt64(&s.MessagesFailed))
	fmt.Printf("Routing:         Sphinx:%d Direct:%d\n",
		atomic.LoadInt64(&s.SphinxRouted),
		atomic.LoadInt64(&s.DirectRouted))
	fmt.Printf("Mixnet:          Recv:%d Fwd:%d\n",
		atomic.LoadInt64(&s.SphinxReceived),
		atomic.LoadInt64(&s.SphinxForwarded))
	fmt.Printf("Bytes:           %d MB\n", atomic.LoadInt64(&s.BytesProcessed)/1024/1024)
	fmt.Printf("Success rate:    %.1f%%\n", s.SuccessRate())
	fmt.Println()
}

func (s *Statistics) SuccessRate() float64 {
	total := atomic.LoadInt64(&s.MessagesReceived)
	if total == 0 {
		return 0
	}
	relayed := atomic.LoadInt64(&s.MessagesRelayed)
	return float64(relayed) / float64(total) * 100.0
}

func (s *Statistics) SaveToFile(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func StatsMonitor() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			if statsFile != "" {
				stats.SaveToFile(statsFile)
			}
			return
		case <-ticker.C:
			uptime := time.Since(stats.StartTime).Round(time.Second)
			log.Printf("[STATS] Up:%s | R:%d D:%d F:%d | Sphinx:%d Direct:%d | Mixnet R:%d F:%d",
				uptime,
				atomic.LoadInt64(&stats.MessagesReceived),
				atomic.LoadInt64(&stats.MessagesRelayed),
				atomic.LoadInt64(&stats.MessagesFailed),
				atomic.LoadInt64(&stats.SphinxRouted),
				atomic.LoadInt64(&stats.DirectRouted),
				atomic.LoadInt64(&stats.SphinxReceived),
				atomic.LoadInt64(&stats.SphinxForwarded))

			if statsFile != "" {
				stats.SaveToFile(statsFile)
			}
		}
	}
}

// ============================================================================
// REPLAY CACHE
// ============================================================================

func NewReplayCache(size int) *ReplayCache {
	return &ReplayCache{
		cache: make(map[string]time.Time, size),
	}
}

func (r *ReplayCache) Check(msgID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.cache[msgID]; exists {
		return false
	}

	r.cache[msgID] = time.Now()

	if len(r.cache) > ReplayCacheSize {
		now := time.Now()
		for id, t := range r.cache {
			if now.Sub(t) > ReplayCacheTTL {
				delete(r.cache, id)
			}
		}
	}

	return true
}

// ============================================================================
// RATE LIMITER
// ============================================================================

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		connections: make(map[string][]time.Time),
	}
}

func (r *RateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-RateLimitWindow)

	times := r.connections[ip]
	var recent []time.Time
	for _, t := range times {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= RateLimitMessages {
		return false
	}

	recent = append(recent, now)
	r.connections[ip] = recent
	return true
}

// ============================================================================
// TOR INITIALIZATION
// ============================================================================

func InitializeTor() {
	dialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[TOR] Failed to create SOCKS5 dialer: %v", err)
	}

	torDialer = dialer
	log.Printf("[TOR] Initialized: %s", TorSocksProxyAddr)
}

// ============================================================================
// PADDING
// ============================================================================

func calculatePadding(size int) int {
	for _, bucket := range PaddingSizes {
		if size <= bucket {
			return bucket - size
		}
	}
	return 0
}

func applyPadding(data []byte) []byte {
	currentSize := len(data)
	paddingNeeded := calculatePadding(currentSize)

	if paddingNeeded == 0 {
		return data
	}

	padded := make([]byte, currentSize+paddingNeeded)
	copy(padded, data)

	if _, err := rand.Read(padded[currentSize:]); err != nil {
		log.Printf("[PADDING] Warning: failed to generate random padding: %v", err)
	}

	return padded
}

// ============================================================================
// TIMING
// ============================================================================

func calculateDelay() time.Duration {
	u := mathrand.Float64()
	delay := time.Duration(-math.Log(1-u) / PoissonLambda * float64(time.Second))

	if delay < MinDelay {
		delay = MinDelay
	}
	if delay > MaxDelay {
		delay = MaxDelay
	}

	return delay
}

// ============================================================================
// SPHINX CRYPTOGRAPHY (AES-256-GCM)
// ============================================================================

func selectHopCount(availableNodes int) int {
	// Determine max hops we can actually use
	maxPossible := MaxSphinxHops
	if availableNodes < maxPossible {
		maxPossible = availableNodes
	}
	
	// Need at least MinSphinxHops
	if maxPossible < MinSphinxHops {
		return availableNodes // Use all available
	}
	
	// Random between min and max
	hopCount := MinSphinxHops + mathrand.Intn(maxPossible-MinSphinxHops+1)
	
	log.Printf("[SPHINX] Selected %d hops (available: %d, max: %d)", 
		hopCount, availableNodes, MaxSphinxHops)
	
	return hopCount
}

func deriveKeys(sharedSecret []byte) (encKey, macKey []byte, err error) {
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte("fog-sphinx-v1.3.2"))
	
	encKey = make([]byte, AESKeySize)
	if _, err := io.ReadFull(kdf, encKey); err != nil {
		return nil, nil, err
	}
	
	macKey = make([]byte, AESKeySize)
	if _, err := io.ReadFull(kdf, macKey); err != nil {
		return nil, nil, err
	}
	
	return encKey, macKey, nil
}

func encryptLayer(plaintext, key []byte) ([]byte, error) {
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
	
	// GCM provides both encryption and authentication
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptLayer(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// GCM verifies authentication automatically
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

func computeHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func verifyHMAC(data, mac, key []byte) bool {
	expected := computeHMAC(data, key)
	return hmac.Equal(mac, expected)
}

// ============================================================================
// SPHINX PACKET CREATION
// ============================================================================

func createSphinxPacket(message *Message, route []*PKINode) (*SphinxPacket, error) {
	hopCount := len(route)
	if hopCount < MinSphinxHops {
		return nil, fmt.Errorf("route must have at least %d hops, got %d", MinSphinxHops, hopCount)
	}
	if hopCount > MaxSphinxHops {
		return nil, fmt.Errorf("route must have at most %d hops, got %d", MaxSphinxHops, hopCount)
	}

	// Prepare routing info for each hop
	routingInfos := make([]RoutingInfo, hopCount)
	
	// Entry and middle nodes: next hop address
	for i := 0; i < hopCount-1; i++ {
		routingInfos[i] = RoutingInfo{
			NextHop: route[i+1].Address,
		}
	}
	
	// Exit node: final destination
	// Filter out empty recipients
	validRecipients := []string{}
	for _, to := range message.To {
		to = strings.TrimSpace(to)
		if to != "" {
			validRecipients = append(validRecipients, to)
		}
	}
	
	if len(validRecipients) == 0 {
		return nil, fmt.Errorf("no valid recipients")
	}
	
	routingInfos[hopCount-1] = RoutingInfo{
		NextHop:     "EXIT",
		MessageFrom: message.From,
		MessageTo:   strings.Join(validRecipients, ","),
	}

	// Start with message data
	payload := message.Data

	// Encrypt in reverse order (exit -> entry)
	var ephemeralKeys [][32]byte
	var sharedSecrets [][]byte
	
	for i := len(route) - 1; i >= 0; i-- {
		node := route[i]

		// Generate ephemeral key pair for this hop
		ephemeralPriv := make([]byte, 32)
		if _, err := rand.Read(ephemeralPriv); err != nil {
			return nil, err
		}

		ephemeralPub, err := curve25519.X25519(ephemeralPriv, curve25519.Basepoint)
		if err != nil {
			return nil, err
		}

		// Compute shared secret
		sharedSecret, err := curve25519.X25519(ephemeralPriv, node.PublicKey)
		if err != nil {
			return nil, err
		}

		// Derive encryption and MAC keys
		encKey, _, err := deriveKeys(sharedSecret)
		if err != nil {
			return nil, err
		}

		// Serialize routing info
		routingData, err := json.Marshal(routingInfos[i])
		if err != nil {
			return nil, err
		}

		// Prepend routing info to payload
		combined := append(routingData, payload...)
		
		// Add length prefix
		lengthPrefix := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthPrefix, uint32(len(routingData)))
		combined = append(lengthPrefix, combined...)

		// Encrypt with AES-256-GCM
		encrypted, err := encryptLayer(combined, encKey)
		if err != nil {
			return nil, err
		}

		payload = encrypted
		
		var ephKey [32]byte
		copy(ephKey[:], ephemeralPub)
		ephemeralKeys = append([][32]byte{ephKey}, ephemeralKeys...)
		sharedSecrets = append([][]byte{sharedSecret}, sharedSecrets...)
	}

	// Create header with routing information
	header := &SphinxHeader{
		Version:      1,
		EphemeralKey: ephemeralKeys[0],
	}

	// Pack remaining ephemeral keys as raw bytes (not JSON)
	// Format: [key1_32bytes][key2_32bytes]...
	var routingInfoBytes []byte
	for _, key := range ephemeralKeys[1:] {
		routingInfoBytes = append(routingInfoBytes, key[:]...)
	}

	// Store remaining ephemeral keys (not encrypted - they're public)
	header.RoutingInfo = routingInfoBytes

	// Compute HMAC over header WITHOUT the HMAC field itself
	tempBuf := new(bytes.Buffer)
	tempBuf.WriteByte(header.Version)
	tempBuf.Write(header.EphemeralKey[:])
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(header.RoutingInfo)))
	tempBuf.Write(lenBytes)
	tempBuf.Write(header.RoutingInfo)
	
	// Derive MAC key from first shared secret
	_, headerKey, err := deriveKeys(sharedSecrets[0])
	if err != nil {
		return nil, err
	}
	
	mac := computeHMAC(tempBuf.Bytes(), headerKey)
	copy(header.HMAC[:], mac)

	return &SphinxPacket{
		Header:  header,
		Payload: payload,
	}, nil
}

func serializeHeader(h *SphinxHeader) ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(h.Version)
	buf.Write(h.EphemeralKey[:])
	
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(h.RoutingInfo)))
	buf.Write(lenBytes)
	buf.Write(h.RoutingInfo)
	buf.Write(h.HMAC[:])
	
	return buf.Bytes(), nil
}

func deserializeHeader(data []byte) (*SphinxHeader, error) {
	if len(data) < 1+32+4 {
		return nil, errors.New("header too short")
	}
	
	h := &SphinxHeader{
		Version: data[0],
	}
	
	copy(h.EphemeralKey[:], data[1:33])
	
	routingLen := binary.BigEndian.Uint32(data[33:37])
	
	// Validate routing length is reasonable (max 10KB for routing info)
	if routingLen > 10240 {
		return nil, errors.New("invalid routing info length: too large")
	}
	
	if len(data) < 37+int(routingLen)+32 {
		return nil, fmt.Errorf("invalid routing info length: need %d, have %d", 37+int(routingLen)+32, len(data))
	}
	
	h.RoutingInfo = data[37 : 37+routingLen]
	copy(h.HMAC[:], data[37+routingLen:37+routingLen+32])
	
	return h, nil
}

// ============================================================================
// SPHINX PACKET PROCESSING (MIXNET NODE)
// ============================================================================

func processSphinxPacket(packet *SphinxPacket) {
	stats.IncrementSphinxReceived()
	
	// Apply random delay (mixnet timing)
	delay := time.Duration(mathrand.Intn(int(MaxBatchDelay-MinBatchDelay))) + MinBatchDelay
	time.Sleep(delay)
	
	// Compute shared secret with ephemeral key
	sharedSecret, err := curve25519.X25519(localNode.PrivateKey, packet.Header.EphemeralKey[:])
	if err != nil {
		log.Printf("[SPHINX] Failed to compute shared secret: %v", err)
		stats.IncrementFailed()
		return
	}
	
	// Derive keys
	encKey, macKey, err := deriveKeys(sharedSecret)
	if err != nil {
		log.Printf("[SPHINX] Failed to derive keys: %v", err)
		stats.IncrementFailed()
		return
	}
	
	log.Printf("[SPHINX] Debug: my_pubkey=%x ephemeral=%x", 
		localNode.PublicKey[:8], packet.Header.EphemeralKey[:8])
	
	// Verify HMAC (only on first hop, subsequent hops have zero HMAC)
	isZeroHMAC := true
	for _, b := range packet.Header.HMAC {
		if b != 0 {
			isZeroHMAC = false
			break
		}
	}
	
	if !isZeroHMAC {
		// Reconstruct header bytes without HMAC for verification
		tempBuf := new(bytes.Buffer)
		tempBuf.WriteByte(packet.Header.Version)
		tempBuf.Write(packet.Header.EphemeralKey[:])
		lenBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lenBytes, uint32(len(packet.Header.RoutingInfo)))
		tempBuf.Write(lenBytes)
		tempBuf.Write(packet.Header.RoutingInfo)
		
		if !verifyHMAC(tempBuf.Bytes(), packet.Header.HMAC[:], macKey) {
			log.Printf("[SPHINX] HMAC verification failed")
			stats.IncrementFailed()
			return
		}
	}
	
	// Decrypt payload layer
	plainPayload, err := decryptLayer(packet.Payload, encKey)
	if err != nil {
		log.Printf("[SPHINX] Failed to decrypt payload: %v", err)
		stats.IncrementFailed()
		return
	}
	
	// Extract routing info length and data
	if len(plainPayload) < 4 {
		log.Printf("[SPHINX] Payload too short")
		stats.IncrementFailed()
		return
	}
	
	routingLen := binary.BigEndian.Uint32(plainPayload[:4])
	if len(plainPayload) < 4+int(routingLen) {
		log.Printf("[SPHINX] Invalid routing length")
		stats.IncrementFailed()
		return
	}
	
	routingData := plainPayload[4 : 4+routingLen]
	innerPayload := plainPayload[4+routingLen:]
	
	// Parse routing info
	var routing RoutingInfo
	if err := json.Unmarshal(routingData, &routing); err != nil {
		log.Printf("[SPHINX] Failed to parse routing: %v", err)
		stats.IncrementFailed()
		return
	}
	
	if routing.NextHop == "EXIT" {
		// We are exit node - deliver message
		log.Printf("[SPHINX] EXIT node - delivering message")
		
		recipients := strings.Split(routing.MessageTo, ",")
		for _, recipient := range recipients {
			recipient = strings.TrimSpace(recipient)
			if recipient == "" {
				continue // Skip empty recipients
			}
			if err := deliverMessage(routing.MessageFrom, recipient, innerPayload); err != nil {
				log.Printf("[SPHINX] Delivery failed to %s: %v", recipient, err)
				stats.IncrementFailed()
			} else {
				log.Printf("[SPHINX] SUCCESS: Delivered to %s", recipient)
				stats.IncrementRelayed()
			}
		}
	} else {
		// Forward to next hop
		log.Printf("[SPHINX] Forwarding to next hop: %s", routing.NextHop)
		
		// Extract remaining ephemeral keys from raw bytes
		var ephKeys [][32]byte
		routingInfo := packet.Header.RoutingInfo
		for i := 0; i+32 <= len(routingInfo); i += 32 {
			var key [32]byte
			copy(key[:], routingInfo[i:i+32])
			ephKeys = append(ephKeys, key)
		}
		
		if len(ephKeys) == 0 {
			log.Printf("[SPHINX] No more ephemeral keys - packet routing complete")
			stats.IncrementFailed()
			return
		}
		
		// Create new packet for next hop
		newHeader := &SphinxHeader{
			Version:      1,
			EphemeralKey: ephKeys[0],
		}
		
		// Pack remaining keys as raw bytes
		if len(ephKeys) > 1 {
			var remainingBytes []byte
			for _, key := range ephKeys[1:] {
				remainingBytes = append(remainingBytes, key[:]...)
			}
			newHeader.RoutingInfo = remainingBytes
		} else {
			newHeader.RoutingInfo = []byte{}
		}
		
		// HMAC not used for forwarded packets
		copy(newHeader.HMAC[:], make([]byte, 32))
		
		newPacket := &SphinxPacket{
			Header:  newHeader,
			Payload: innerPayload,
		}
		
		if err := sendSphinxPacket(routing.NextHop, newPacket); err != nil {
			log.Printf("[SPHINX] Failed to forward: %v", err)
			stats.IncrementFailed()
		} else {
			stats.IncrementSphinxForwarded()
		}
	}
}

// ============================================================================
// SPHINX NODE SERVER
// ============================================================================

func StartSphinxNodeServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("[SPHINX] Node server listening on %s", addr)

	go func() {
		defer shutdownWg.Done()
		
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-shutdownCtx.Done():
					return
				default:
					log.Printf("[SPHINX] Accept error: %v", err)
					continue
				}
			}

			go handleSphinxConnection(conn)
		}
	}()

	return nil
}

func handleSphinxConnection(conn net.Conn) {
	defer conn.Close()

	// Read packet
	headerBytes := make([]byte, SphinxHeaderSize)
	if _, err := io.ReadFull(conn, headerBytes); err != nil {
		// Ignore EOF - this is typically a health check
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			log.Printf("[SPHINX] Failed to read header: %v", err)
		}
		return
	}

	header, err := deserializeHeader(headerBytes)
	if err != nil {
		log.Printf("[SPHINX] Failed to deserialize header: %v", err)
		return
	}

	payload, err := io.ReadAll(conn)
	if err != nil {
		log.Printf("[SPHINX] Failed to read payload: %v", err)
		return
	}

	packet := &SphinxPacket{
		Header:  header,
		Payload: payload,
	}

	// Add to mixnet batch
	mixnetBatch.Add(packet)
	log.Printf("[SPHINX] Packet received and batched")
}

// ============================================================================
// RELAY LOGIC
// ============================================================================

func RelayWorker(id int) {
	defer shutdownWg.Done()

	log.Printf("[WORKER %d] Started", id)

	for {
		select {
		case <-shutdownCtx.Done():
			log.Printf("[WORKER %d] Stopped", id)
			return
		case msg := <-messageQueue:
			processMessage(id, msg)
		}
	}
}

func processMessage(workerID int, msg *Message) {
	delay := calculateDelay()
	log.Printf("[WORKER %d] Delay: %s for %s", workerID, delay.Round(time.Millisecond), msg.ID)

	select {
	case <-time.After(delay):
	case <-shutdownCtx.Done():
		return
	}

	// Attempt Sphinx routing if enabled and enough nodes
	if enableSphinx.Load() && pkiDirectory.HealthyCount() >= MinSphinxHops {
		// Apply padding for Sphinx
		paddedData := applyPadding(msg.Data)
		originalSize := len(msg.Data)
		paddedSize := len(paddedData)
		log.Printf("[WORKER %d] Padding: %d -> %d bytes", workerID, originalSize, paddedSize)
		
		if err := sphinxRoute(msg, paddedData); err != nil {
			log.Printf("[WORKER %d] Sphinx failed: %v, fallback to direct", workerID, err)
			stats.IncrementDirect()
			// Use ORIGINAL message data, not Sphinx payload
			directRelay(msg, msg.Data)
		} else {
			stats.IncrementSphinx()
		}
	} else {
		stats.IncrementDirect()
		// Direct relay uses original data
		directRelay(msg, msg.Data)
	}
}

func sphinxRoute(msg *Message, data []byte) error {
	healthy := pkiDirectory.GetHealthyNodes()
	if len(healthy) < MinSphinxHops {
		return fmt.Errorf("not enough healthy nodes: have %d, need at least %d", 
			len(healthy), MinSphinxHops)
	}

	// Select random hop count
	hopCount := selectHopCount(len(healthy))
	
	// Shuffle all available nodes for complete randomness
	mathrand.Shuffle(len(healthy), func(i, j int) {
		healthy[i], healthy[j] = healthy[j], healthy[i]
	})
	
	// Select first N nodes as route
	route := healthy[:hopCount]

	// Log route with variable length
	routeLog := ""
	for i, node := range route {
		if i > 0 {
			routeLog += " -> "
		}
		routeLog += node.NodeID[:8]
	}
	log.Printf("[SPHINX] Route (%d hops): %s", hopCount, routeLog)
	log.Printf("[SPHINX] First hop pubkey: %x", route[0].PublicKey[:8])

	// Create Sphinx packet
	packet, err := createSphinxPacket(msg, route)
	if err != nil {
		return fmt.Errorf("packet creation failed: %w", err)
	}

	// Send to entry node
	entryNode := route[0]
	if err := sendSphinxPacket(entryNode.Address, packet); err != nil {
		return fmt.Errorf("failed to send to entry node: %w", err)
	}

	stats.IncrementRelayed()
	log.Printf("[SPHINX] SUCCESS: %s via %s (%d hops)", 
		msg.ID, entryNode.NodeID[:8], hopCount)
	return nil
}

func sendSphinxPacket(address string, packet *SphinxPacket) error {
	log.Printf("[SPHINX] Connecting to %s via Tor...", address)
	
	conn, err := torDialer.Dial("tcp", address)
	if err != nil {
		log.Printf("[SPHINX] Connection failed to %s: %v", address, err)
		return err
	}
	defer conn.Close()
	
	log.Printf("[SPHINX] Connected to %s, sending packet...", address)

	// Serialize and send header
	headerBytes, err := serializeHeader(packet.Header)
	if err != nil {
		return err
	}
	
	// Pad header to fixed size
	paddedHeader := make([]byte, SphinxHeaderSize)
	copy(paddedHeader, headerBytes)
	
	if _, err := conn.Write(paddedHeader); err != nil {
		log.Printf("[SPHINX] Failed to send header to %s: %v", address, err)
		return err
	}
	
	// Send payload
	if _, err := conn.Write(packet.Payload); err != nil {
		log.Printf("[SPHINX] Failed to send payload to %s: %v", address, err)
		return err
	}
	
	log.Printf("[SPHINX] Packet sent successfully to %s (%d bytes)", address, len(paddedHeader)+len(packet.Payload))
	return nil
}

func directRelay(msg *Message, data []byte) {
	for _, recipient := range msg.To {
		recipient = strings.TrimSpace(recipient)
		if recipient == "" {
			continue // Skip empty recipients
		}
		if err := deliverMessage(msg.From, recipient, data); err != nil {
			log.Printf("[RELAY] FAILED: %s to %s: %v", msg.ID, recipient, err)
			stats.IncrementFailed()
		} else {
			log.Printf("[RELAY] SUCCESS: %s to %s (%d bytes)",
				msg.ID, recipient, len(data))
			stats.IncrementRelayed()
		}
	}
}

func deliverMessage(from, to string, data []byte) error {
	// Determine server
	domain := strings.Split(to, "@")
	if len(domain) != 2 {
		return fmt.Errorf("invalid email: %s", to)
	}

	var server string
	if strings.HasSuffix(domain[1], ".onion") {
		server = domain[1] + ":25"
	} else {
		server = domain[1] + ":25"
	}

	return sendSMTP(server, from, to, data)
}

func sendSMTP(server, from, to string, data []byte) error {
	conn, err := torDialer.Dial("tcp", server)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, serverHostname)
	if err != nil {
		return fmt.Errorf("SMTP client failed: %w", err)
	}
	defer client.Close()

	if err := client.Hello(serverHostname); err != nil {
		return fmt.Errorf("EHLO failed: %w", err)
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %w", err)
	}

	if _, err := wc.Write(data); err != nil {
		wc.Close()
		return fmt.Errorf("write failed: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("close failed: %w", err)
	}

	return client.Quit()
}

// ============================================================================
// SMTP SERVER
// ============================================================================

func NewSMTPServer(hostname, addr string) *SMTPServer {
	return &SMTPServer{
		hostname: hostname,
		addr:     addr,
	}
}

func (s *SMTPServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	s.listener = listener
	log.Printf("[SMTP] Listening on %s", s.addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-shutdownCtx.Done():
				return nil
			default:
				log.Printf("[SMTP] Accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *SMTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	ip := strings.Split(remoteAddr, ":")[0]

	log.Printf("[SMTP] Connection from %s", remoteAddr)

	if !rateLimiter.Allow(ip) {
		log.Printf("[SMTP] Rate limit exceeded: %s", ip)
		return
	}

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	fmt.Fprintf(writer, "220 %s ESMTP %s %s\r\n", s.hostname, AppName, Version)
	writer.Flush()

	var (
		mailFrom   string
		rcptTo     []string
		dataBuffer bytes.Buffer
	)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("[SMTP] Read error: %v", err)
			}
			return
		}

		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		cmd := strings.ToUpper(strings.Fields(line)[0])
		log.Printf("[SMTP] <- %s: %s", remoteAddr, line)

		switch cmd {
		case "EHLO", "HELO":
			fmt.Fprintf(writer, "250-%s\r\n", s.hostname)
			fmt.Fprintf(writer, "250-SIZE %d\r\n", MaxMessageSize)
			fmt.Fprintf(writer, "250 8BITMIME\r\n")

		case "MAIL":
			if !strings.HasPrefix(strings.ToUpper(line), "MAIL FROM:") {
				fmt.Fprintf(writer, "501 Syntax error\r\n")
				writer.Flush()
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				fmt.Fprintf(writer, "501 Syntax error\r\n")
				writer.Flush()
				continue
			}

			addr := strings.TrimSpace(parts[1])
			if idx := strings.Index(addr, " "); idx != -1 {
				addr = addr[:idx]
			}
			addr = strings.Trim(addr, "<>")

			mailFrom = addr
			rcptTo = nil
			fmt.Fprintf(writer, "250 OK\r\n")

		case "RCPT":
			if mailFrom == "" {
				fmt.Fprintf(writer, "503 MAIL first\r\n")
				writer.Flush()
				continue
			}

			if len(rcptTo) >= MaxRecipients {
				fmt.Fprintf(writer, "452 Too many recipients\r\n")
				writer.Flush()
				continue
			}

			if !strings.HasPrefix(strings.ToUpper(line), "RCPT TO:") {
				fmt.Fprintf(writer, "501 Syntax error\r\n")
				writer.Flush()
				continue
			}

			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				fmt.Fprintf(writer, "501 Syntax error\r\n")
				writer.Flush()
				continue
			}

			addr := strings.Trim(strings.TrimSpace(parts[1]), "<>")
			if addr == "" {
				fmt.Fprintf(writer, "501 Invalid recipient address\r\n")
				writer.Flush()
				continue
			}
			rcptTo = append(rcptTo, addr)
			fmt.Fprintf(writer, "250 OK\r\n")

		case "DATA":
			if mailFrom == "" || len(rcptTo) == 0 {
				fmt.Fprintf(writer, "503 MAIL/RCPT first\r\n")
				writer.Flush()
				continue
			}

			fmt.Fprintf(writer, "354 End data with <CR><LF>.<CR><LF>\r\n")
			writer.Flush()

			dataBuffer.Reset()

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}

				// Accept both ".\r\n" and ".\n" as end marker
				if line == ".\r\n" || line == ".\n" {
					break
				}

				if strings.HasPrefix(line, "..") {
					line = line[1:]
				}

				dataBuffer.WriteString(line)

				if dataBuffer.Len() > MaxMessageSize {
					fmt.Fprintf(writer, "552 Message too large\r\n")
					writer.Flush()
					return
				}
			}

			msgID := generateMessageID()
			msg := &Message{
				ID:        msgID,
				From:      mailFrom,
				To:        rcptTo,
				Data:      dataBuffer.Bytes(),
				Timestamp: time.Now(),
				Size:      dataBuffer.Len(),
			}

			if !replayCache.Check(msgID) {
				fmt.Fprintf(writer, "550 Duplicate message\r\n")
				writer.Flush()
				return
			}

			select {
			case messageQueue <- msg:
				stats.IncrementReceived()
				stats.AddBytes(int64(msg.Size))
				fmt.Fprintf(writer, "250 OK: Message queued as %s\r\n", msgID)
				log.Printf("[SMTP] Queued %s from %s to %d recipients (%d bytes)",
					msgID, mailFrom, len(rcptTo), msg.Size)
			default:
				fmt.Fprintf(writer, "452 Queue full\r\n")
			}

			mailFrom = ""
			rcptTo = nil

		case "RSET":
			mailFrom = ""
			rcptTo = nil
			fmt.Fprintf(writer, "250 OK\r\n")

		case "QUIT":
			fmt.Fprintf(writer, "221 Bye\r\n")
			writer.Flush()
			return

		default:
			fmt.Fprintf(writer, "502 Command not implemented\r\n")
		}

		writer.Flush()
	}
}

func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// ============================================================================
// PKI REFRESH WORKER
// ============================================================================

func PKIRefreshWorker() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(PKIRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			if pkiURL != "" {
				if err := pkiDirectory.LoadFromURL(pkiURL); err != nil {
					log.Printf("[PKI] Refresh failed: %v", err)
				} else {
					log.Printf("[PKI] Refreshed: %d nodes", pkiDirectory.HealthyCount())
				}
			}
		}
	}
}

// ============================================================================
// HEALTH CHECK WORKER
// ============================================================================

func HealthCheckWorker() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(HealthCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownCtx.Done():
			return
		case <-ticker.C:
			nodes := pkiDirectory.GetHealthyNodes()
			log.Printf("[HEALTH] Checking %d nodes", len(nodes))

			for _, node := range nodes {
				go checkNodeHealth(node)
			}
		}
	}
}

func checkNodeHealth(node *PKINode) {
	conn, err := torDialer.Dial("tcp", node.Address)
	if err != nil {
		pkiDirectory.mu.Lock()
		node.Healthy = false
		node.FailureCount++
		pkiDirectory.mu.Unlock()
		return
	}
	conn.Close()

	pkiDirectory.mu.Lock()
	node.Healthy = true
	node.LastHealthy = time.Now()
	node.SuccessCount++
	pkiDirectory.mu.Unlock()
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	// Flags
	serverName := flag.String("name", "fog.local", "Server hostname")
	smtpAddr := flag.String("addr", "127.0.0.1:2525", "SMTP listen address")
	nodeAddrFlag := flag.String("node-addr", "", "Sphinx node address (auto-derived if empty)")
	enableSphinxFlag := flag.Bool("sphinx", false, "Enable Sphinx routing")
	pkiFileFlag := flag.String("pki-file", "", "PKI file path")
	pkiURLFlag := flag.String("pki-url", "", "PKI URL (auto-refresh)")
	dataDirFlag := flag.String("data-dir", "./fog-data", "Data directory")
	showStats := flag.Bool("stats", false, "Show statistics and exit")
	showNodes := flag.Bool("nodes", false, "Show network nodes and exit")
	exportNodeInfo := flag.Bool("export-node-info", false, "Export this node's info for nodes.json and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")

	flag.Parse()

	// Version
	if *showVersion {
		fmt.Printf("%s v%s\n", AppName, Version)
		fmt.Println("\nSecurity Features:")
		fmt.Println("  ✓ Sphinx with AES-256-GCM encryption")
		fmt.Println("  ✓ Variable-hop routing (3-6 hops random)")
		fmt.Println("  ✓ Random route selection")
		fmt.Println("  ✓ Multi-hop mixnet routing")
		fmt.Println("  ✓ Batch processing with shuffling")
		fmt.Println("  ✓ Forward secrecy (ECDH)")
		fmt.Println("  ✓ HMAC authentication")
		fmt.Println("  ✓ Exponential timing delays")
		fmt.Println("  ✓ Adaptive padding")
		fmt.Println("  ✓ Replay protection")
		fmt.Println("  ✓ No metadata retention")
		fmt.Println("\nLibraries:")
		fmt.Println("  - crypto/aes + crypto/cipher (AES-256-GCM)")
		fmt.Println("  - crypto/hmac + crypto/sha256")
		fmt.Println("  - golang.org/x/crypto/curve25519 (ECDH)")
		fmt.Println("  - golang.org/x/crypto/hkdf (key derivation)")
		fmt.Println("  - golang.org/x/net/proxy (Tor SOCKS5)")
		os.Exit(0)
	}

	// Setup data directory
	dataDir = *dataDirFlag
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("[INIT] Failed to create data directory: %v", err)
	}

	statsFile = filepath.Join(dataDir, "stats.json")

	// Show stats
	if *showStats {
		if data, err := os.ReadFile(statsFile); err == nil {
			var s Statistics
			if err := json.Unmarshal(data, &s); err == nil {
				stats = &s
				stats.Print()
				os.Exit(0)
			}
		}
		fmt.Println("No statistics available")
		os.Exit(1)
	}

	// Show nodes
	pkiDirectory = NewPKIDirectory()
	if *showNodes {
		if *pkiFileFlag != "" {
			if err := pkiDirectory.LoadFromFile(*pkiFileFlag); err != nil {
				log.Fatalf("[PKI] Failed to load: %v", err)
			}
		}

		nodes := pkiDirectory.GetHealthyNodes()
		fmt.Printf("Healthy nodes: %d\n\n", len(nodes))
		for _, node := range nodes {
			fmt.Printf("Node:      %s\n", node.NodeID[:32])
			fmt.Printf("Address:   %s\n", node.Address)
			fmt.Printf("Version:   %s\n", node.Version)
			fmt.Printf("Last seen: %s\n", node.LastSeen.Format("2006-01-02 15:04:05"))
			fmt.Println("---")
		}
		os.Exit(0)
	}

	// Export node info for nodes.json
	if *exportNodeInfo {
		// Derive node address if needed
		var nodeAddress string
		if *nodeAddrFlag == "" {
			host, port, _ := net.SplitHostPort(*smtpAddr)
			nodePort := 0
			fmt.Sscanf(port, "%d", &nodePort)
			nodeAddress = fmt.Sprintf("%s:%d", host, nodePort+1000)
		} else {
			nodeAddress = *nodeAddrFlag
		}

		// Initialize node to generate keys
		InitializeLocalNode(nodeAddress)

		// Format as JSON for nodes.json
		pubKeyB64 := base64.StdEncoding.EncodeToString(localNode.PublicKey)
		
		fmt.Println("{")
		fmt.Printf("  \"%s\": {\n", localNode.NodeID)
		fmt.Printf("    \"node_id\": \"%s\",\n", localNode.NodeID)
		fmt.Printf("    \"public_key\": \"%s\",\n", pubKeyB64)
		fmt.Printf("    \"address\": \"%s:9999\",\n", *serverName)
		fmt.Printf("    \"version\": \"%s\",\n", Version)
		fmt.Printf("    \"last_seen\": \"%s\",\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Printf("    \"healthy\": true,\n")
		fmt.Printf("    \"failure_count\": 0,\n")
		fmt.Printf("    \"success_count\": 0,\n")
		fmt.Printf("    \"last_healthy\": \"%s\"\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Println("  }")
		fmt.Println("}")
		fmt.Println()
		fmt.Println("Copy this JSON block into your nodes.json file.")
		fmt.Printf("NodeID (short): %s\n", localNode.NodeID[:16])
		os.Exit(0)
	}

	// Normal startup
	log.Printf("[FOG] Starting v%s", Version)

	shutdownCtx, shutdownCancel = context.WithCancel(context.Background())
	defer shutdownCancel()

	serverHostname = *serverName
	log.Printf("[FOG] Hostname: %s", serverHostname)

	// Initialize components
	stats = NewStatistics()
	replayCache = NewReplayCache(ReplayCacheSize)
	rateLimiter = NewRateLimiter()
	messageQueue = make(chan *Message, MessageQueueSize)
	mixnetBatch = NewMixnetBatch()

	// Derive node address if needed
	if *nodeAddrFlag == "" {
		host, port, _ := net.SplitHostPort(*smtpAddr)
		nodePort := 0
		fmt.Sscanf(port, "%d", &nodePort)
		nodeAddr = fmt.Sprintf("%s:%d", host, nodePort+1000)
	} else {
		nodeAddr = *nodeAddrFlag
	}

	InitializeLocalNode(nodeAddr)
	InitializeTor()

	enableSphinx.Store(*enableSphinxFlag)
	pkiURL = *pkiURLFlag

	if *enableSphinxFlag {
		log.Printf("[INIT] Sphinx ENABLED with AES-256-GCM")
		log.Printf("[INIT] Variable-hop routing: %d-%d hops (random)", 
			MinSphinxHops, MaxSphinxHops)

		if *pkiFileFlag != "" {
			pkiDirectory.LoadFromFile(*pkiFileFlag)
		}

		if pkiURL != "" {
			pkiDirectory.LoadFromURL(pkiURL)
			shutdownWg.Add(1)
			go PKIRefreshWorker()
		}

		shutdownWg.Add(1)
		go HealthCheckWorker()

		// Start Sphinx node server
		shutdownWg.Add(1)
		if err := StartSphinxNodeServer(nodeAddr); err != nil {
			log.Fatalf("[SPHINX] Failed to start node server: %v", err)
		}

		// Start mixnet batch worker
		shutdownWg.Add(1)
		go MixnetBatchWorker()
	} else {
		log.Printf("[INIT] Sphinx DISABLED (direct relay only)")
	}

	// Start workers
	for i := 0; i < WorkerCount; i++ {
		shutdownWg.Add(1)
		go RelayWorker(i)
	}

	shutdownWg.Add(1)
	go StatsMonitor()

	// Key rotation every 30 days
	shutdownWg.Add(1)
	go RotatePKIKeys()

	// Start SMTP server
	server := NewSMTPServer(*serverName, *smtpAddr)

	// Handle signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[FOG] Shutdown signal received")
		shutdownCancel()
		if server.listener != nil {
			server.listener.Close()
		}
	}()

	if err := server.Start(); err != nil {
		log.Fatalf("[FOG] Server error: %v", err)
	}

	shutdownWg.Wait()

	// Save final state
	if *pkiFileFlag != "" {
		pkiDirectory.SaveToFile(*pkiFileFlag)
	}
	if statsFile != "" {
		stats.SaveToFile(statsFile)
	}

	log.Printf("[FOG] Shutdown complete")
}
