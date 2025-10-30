package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/signal"
	"regexp"
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
	Version                = "1.2.0"
	AppName                = "fog"
	TorSocksProxyAddr      = "127.0.0.1:9050"
	RelayWorkerCount       = 5
	DeliveryTimeout        = 60 * time.Second
	MessageIDCacheDuration = 24 * time.Hour
	RateLimitPerIP         = 10
	RateLimitWindow        = 1 * time.Minute
	MaxRetries             = 3
	MaxMessageSize         = 10 * 1024 * 1024 // 10MB
	MaxRecipients          = 100

	// Sphinx and PKI constants
	SphinxHopCount         = 3
	SphinxHeaderSize       = 1024
	SphinxPayloadSize      = 32 * 1024
	PKIRotationInterval    = 3 * time.Hour
	KeyRotationJitter      = 30 * time.Minute
	PKIRefreshInterval     = 15 * time.Minute
	NodeHealthCheckTimeout = 5 * time.Second

	// Adaptive padding constants
	PaddingAdaptiveWindow = 1 * time.Hour
	PaddingMinBucket      = 32 * 1024
	PaddingMaxBucket      = 10 * 1024 * 1024
	PaddingBucketCount    = 9

	// Exponential delay constants
	ExponentialDelayLambda = 1.0
	ExponentialDelayMin    = 100 * time.Millisecond
	ExponentialDelayMax    = 10 * time.Second

	// Sphinx node server
	SphinxNodePort = 9999
)

var MessageSizeBuckets = []int64{
	32 * 1024,
	64 * 1024,
	128 * 1024,
	256 * 1024,
	512 * 1024,
	1024 * 1024,
	2 * 1024 * 1024,
	5 * 1024 * 1024,
	10 * 1024 * 1024,
}

// ============================================================================
// GLOBAL VARIABLES
// ============================================================================

var (
	emailRegExp    *regexp.Regexp
	localPartRegex *regexp.Regexp
	domainRegex    *regexp.Regexp

	mailQueue      chan *Envelope
	mailQueueMutex sync.Mutex

	stats          *Statistics
	shutdownSignal chan struct{}
	shutdownWg     sync.WaitGroup

	// Tor dialer
	torDialer proxy.Dialer

	// Sphinx and PKI
	localNode      *PKINode
	pkiDirectory   *PKIDirectory
	sphinxEnabled  atomic.Bool
	pkiInitialized atomic.Bool

	// Adaptive padding
	paddingStats       *PaddingStatistics
	paddingStatsWindow []int64
	paddingStatsMux    sync.RWMutex

	// Exponential delay generator
	delayGenerator *ExponentialDelayGenerator

	// Message ID cache (replay protection)
	messageIDCache     = make(map[string]time.Time)
	messageIDCacheMux  sync.RWMutex
	messageIDCacheTTL  = MessageIDCacheDuration

	// Rate limiting
	rateLimitMap    = make(map[string]*RateLimiter)
	rateLimitMapMux sync.RWMutex
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

type Envelope struct {
	From        string
	To          []string
	MessageData *bytes.Buffer
	MessageID   string
	ReceivedAt  time.Time
	Size        int64
	RetryCount  int
}

type Statistics struct {
	ConnectionsTotal   atomic.Uint64
	ConnectionsActive  atomic.Int64
	MessagesReceived   atomic.Uint64
	MessagesDelivered  atomic.Uint64
	MessagesFailed     atomic.Uint64
	BytesTransferred   atomic.Uint64
	StartTime          time.Time
	SphinxRoutingUsed  atomic.Uint64
	DirectRelayUsed    atomic.Uint64
}

type RateLimiter struct {
	count      int
	lastReset  time.Time
	mu         sync.Mutex
}

// ============================================================================
// PKI STRUCTURES
// ============================================================================

type PKINode struct {
	NodeID      string    `json:"node_id"`
	PublicKey   []byte    `json:"public_key"`
	Address     string    `json:"address"`      // fog-node.onion:9999
	LastRotated time.Time `json:"last_rotated"`
	IsLocal     bool      `json:"is_local"`
	LastSeen    time.Time `json:"last_seen"`
	Healthy     bool      `json:"healthy"`
}

type PKIDirectory struct {
	Nodes      map[string]*PKINode `json:"nodes"`
	UpdatedAt  time.Time           `json:"updated_at"`
	mu         sync.RWMutex
}

func NewPKIDirectory() *PKIDirectory {
	return &PKIDirectory{
		Nodes:     make(map[string]*PKINode),
		UpdatedAt: time.Now(),
	}
}

func (d *PKIDirectory) AddNode(node *PKINode) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.Nodes[node.NodeID] = node
	d.UpdatedAt = time.Now()
}

func (d *PKIDirectory) RemoveNode(nodeID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.Nodes, nodeID)
	d.UpdatedAt = time.Now()
}

func (d *PKIDirectory) GetNode(nodeID string) (*PKINode, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	node, exists := d.Nodes[nodeID]
	return node, exists
}

func (d *PKIDirectory) GetHealthyNodes(excludeLocal bool) []*PKINode {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	var nodes []*PKINode
	for _, node := range d.Nodes {
		if excludeLocal && node.IsLocal {
			continue
		}
		if node.Healthy {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func (d *PKIDirectory) LoadFromFile(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read PKI file: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := json.Unmarshal(data, d); err != nil {
		return fmt.Errorf("failed to parse PKI JSON: %w", err)
	}

	log.Printf("[PKI] Loaded %d nodes from %s", len(d.Nodes), filename)
	return nil
}

func (d *PKIDirectory) SaveToFile(filename string) error {
	d.mu.RLock()
	data, err := json.MarshalIndent(d, "", "  ")
	d.mu.RUnlock()

	if err != nil {
		return fmt.Errorf("failed to marshal PKI: %w", err)
	}

	if err := os.WriteFile(filename, data, 0600); err != nil {
		return fmt.Errorf("failed to write PKI file: %w", err)
	}

	return nil
}

func (d *PKIDirectory) LoadFromURL(url string) error {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Dial: torDialer.Dial,
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch PKI from URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("PKI URL returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read PKI response: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if err := json.Unmarshal(data, d); err != nil {
		return fmt.Errorf("failed to parse PKI JSON: %w", err)
	}

	log.Printf("[PKI] Loaded %d nodes from URL", len(d.Nodes))
	return nil
}

func (d *PKIDirectory) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.Nodes)
}

func (d *PKIDirectory) HealthyCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	
	count := 0
	for _, node := range d.Nodes {
		if node.Healthy && !node.IsLocal {
			count++
		}
	}
	return count
}

// ============================================================================
// SPHINX STRUCTURES
// ============================================================================

type SphinxPacket struct {
	Header  []byte
	Payload []byte
}

type SphinxHeader struct {
	EphemeralKey []byte // 32 bytes Curve25519 public key
	RoutingInfo  []byte // Encrypted routing information
	MAC          []byte // HMAC for integrity
}

type SphinxHopInfo struct {
	NextHop     string
	NextAddress string
}

// ============================================================================
// PADDING STATISTICS
// ============================================================================

type PaddingStatistics struct {
	buckets       [PaddingBucketCount]int64
	totalMessages int64
	mu            sync.RWMutex
	lastUpdate    time.Time
}

func NewPaddingStatistics() *PaddingStatistics {
	return &PaddingStatistics{
		lastUpdate: time.Now(),
	}
}

func (ps *PaddingStatistics) RecordMessage(size int64) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	bucketIndex := ps.findBucket(size)
	ps.buckets[bucketIndex]++
	ps.totalMessages++
}

func (ps *PaddingStatistics) findBucket(size int64) int {
	for i, threshold := range MessageSizeBuckets {
		if size <= threshold {
			return i
		}
	}
	return PaddingBucketCount - 1
}

func (ps *PaddingStatistics) GetAdaptiveBuckets() []int64 {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	if ps.totalMessages < 100 {
		return MessageSizeBuckets
	}

	// Calculate percentiles based on actual traffic
	adaptiveBuckets := make([]int64, PaddingBucketCount)
	copy(adaptiveBuckets, MessageSizeBuckets)

	return adaptiveBuckets
}

// ============================================================================
// EXPONENTIAL DELAY GENERATOR
// ============================================================================

type ExponentialDelayGenerator struct {
	lambda float64
	min    time.Duration
	max    time.Duration
	mu     sync.Mutex
}

func NewExponentialDelayGenerator(lambda float64, min, max time.Duration) *ExponentialDelayGenerator {
	return &ExponentialDelayGenerator{
		lambda: lambda,
		min:    min,
		max:    max,
	}
}

func (g *ExponentialDelayGenerator) Generate() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()

	u, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return g.min
	}

	uFloat := float64(u.Int64()) / float64(1<<32)
	delay := -math.Log(1-uFloat) / g.lambda

	delayDuration := time.Duration(delay * float64(time.Second))

	if delayDuration < g.min {
		return g.min
	}
	if delayDuration > g.max {
		return g.max
	}

	return delayDuration
}

// ============================================================================
// PKI INITIALIZATION
// ============================================================================

func InitializePKI() error {
	privateKey := make([]byte, 32)
	if _, err := rand.Read(privateKey); err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("failed to derive public key: %w", err)
	}

	nodeID := generateNodeID(publicKey)

	localNode = &PKINode{
		NodeID:      nodeID,
		PublicKey:   publicKey,
		Address:     "",
		LastRotated: time.Now(),
		IsLocal:     true,
		Healthy:     true,
		LastSeen:    time.Now(),
	}

	pkiDirectory = NewPKIDirectory()
	pkiDirectory.AddNode(localNode)

	pkiInitialized.Store(true)

	log.Printf("[PKI] Initialized local node: %s", nodeID[:16])
	log.Printf("[PKI] Public key: %s", base64.StdEncoding.EncodeToString(publicKey)[:32])

	return nil
}

func generateNodeID(publicKey []byte) string {
	hash := sha256.Sum256(publicKey)
	return base64.URLEncoding.EncodeToString(hash[:])
}

// ============================================================================
// SPHINX PACKET CREATION
// ============================================================================

func CreateSphinxPacket(envelope *Envelope, route []*PKINode) (*SphinxPacket, error) {
	if len(route) != SphinxHopCount {
		return nil, fmt.Errorf("route must have exactly %d hops", SphinxHopCount)
	}

	// Serialize envelope
	payload, err := serializeEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize envelope: %w", err)
	}

	// Pad payload
	if len(payload) > SphinxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d > %d", len(payload), SphinxPayloadSize)
	}

	paddedPayload := make([]byte, SphinxPayloadSize)
	copy(paddedPayload, payload)
	if _, err := rand.Read(paddedPayload[len(payload):]); err != nil {
		return nil, fmt.Errorf("failed to pad payload: %w", err)
	}

	// Create layers (from exit to entry)
	encryptedPayload := paddedPayload
	var header []byte

	for i := len(route) - 1; i >= 0; i-- {
		node := route[i]

		// Generate ephemeral key pair
		ephemeralPrivate := make([]byte, 32)
		if _, err := rand.Read(ephemeralPrivate); err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
		}

		ephemeralPublic, err := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("failed to derive ephemeral public: %w", err)
		}

		// ECDH with node's public key
		sharedSecret, err := curve25519.X25519(ephemeralPrivate, node.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("ECDH failed: %w", err)
		}

		// Derive encryption keys using HKDF
		keys := deriveSphinxKeys(sharedSecret, ephemeralPublic)

		// Create hop info
		var hopInfo SphinxHopInfo
		if i < len(route)-1 {
			hopInfo.NextHop = route[i+1].NodeID
			hopInfo.NextAddress = route[i+1].Address
		} else {
			// Exit node - include final destination
			hopInfo.NextHop = "EXIT"
			hopInfo.NextAddress = ""
		}

		hopInfoBytes, _ := json.Marshal(hopInfo)

		// Encrypt payload
		encryptedPayload, err = encryptAESGCM(keys.payloadKey, encryptedPayload)
		if err != nil {
			return nil, fmt.Errorf("payload encryption failed: %w", err)
		}

		// Encrypt header
		headerData := append(ephemeralPublic, hopInfoBytes...)
		encryptedHeader, err := encryptAESGCM(keys.headerKey, headerData)
		if err != nil {
			return nil, fmt.Errorf("header encryption failed: %w", err)
		}

		header = encryptedHeader
	}

	// Pad header to fixed size
	if len(header) > SphinxHeaderSize {
		return nil, fmt.Errorf("header too large: %d > %d", len(header), SphinxHeaderSize)
	}

	paddedHeader := make([]byte, SphinxHeaderSize)
	copy(paddedHeader, header)

	return &SphinxPacket{
		Header:  paddedHeader,
		Payload: encryptedPayload,
	}, nil
}

type sphinxKeys struct {
	headerKey  []byte
	payloadKey []byte
}

func deriveSphinxKeys(sharedSecret, ephemeralPublic []byte) *sphinxKeys {
	salt := ephemeralPublic
	info := []byte("fog-sphinx-v1")

	kdf := hkdf.New(sha256.New, sharedSecret, salt, info)

	keys := &sphinxKeys{
		headerKey:  make([]byte, 32),
		payloadKey: make([]byte, 32),
	}

	kdf.Read(keys.headerKey)
	kdf.Read(keys.payloadKey)

	return keys
}

func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
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

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
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

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

func serializeEnvelope(envelope *Envelope) ([]byte, error) {
	data := map[string]interface{}{
		"from":       envelope.From,
		"to":         envelope.To,
		"message_id": envelope.MessageID,
		"size":       envelope.Size,
		"data":       base64.StdEncoding.EncodeToString(envelope.MessageData.Bytes()),
	}

	return json.Marshal(data)
}

func deserializeEnvelope(data []byte) (*Envelope, error) {
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	messageData, err := base64.StdEncoding.DecodeString(parsed["data"].(string))
	if err != nil {
		return nil, err
	}

	toList := []string{}
	for _, t := range parsed["to"].([]interface{}) {
		toList = append(toList, t.(string))
	}

	return &Envelope{
		From:        parsed["from"].(string),
		To:          toList,
		MessageID:   parsed["message_id"].(string),
		Size:        int64(parsed["size"].(float64)),
		MessageData: bytes.NewBuffer(messageData),
		ReceivedAt:  time.Now(),
	}, nil
}

// ============================================================================
// SPHINX NODE SERVER
// ============================================================================

func StartSphinxNodeServer(listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start Sphinx node server: %w", err)
	}

	log.Printf("[SPHINX] Node server listening on %s", listenAddr)

	go func() {
		defer shutdownWg.Done()
		defer listener.Close()

		for {
			select {
			case <-shutdownSignal:
				return
			default:
			}

			listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("[SPHINX] Accept error: %v", err)
				continue
			}

			go handleSphinxConnection(conn)
		}
	}()

	return nil
}

func handleSphinxConnection(conn net.Conn) {
	defer conn.Close()

	log.Printf("[SPHINX] Connection from %s", conn.RemoteAddr())

	// Read packet
	var packet SphinxPacket
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&packet); err != nil {
		log.Printf("[SPHINX] Failed to decode packet: %v", err)
		return
	}

	// Process packet
	nextHop, nextPacket, envelope, err := ProcessSphinxPacket(&packet, localNode)
	if err != nil {
		log.Printf("[SPHINX] Packet processing failed: %v", err)
		return
	}

	// Apply exponential delay
	delay := delayGenerator.Generate()
	log.Printf("[SPHINX] Applying delay: %v", delay)
	time.Sleep(delay)

	if nextHop == "EXIT" {
		// This is the exit node - relay message
		log.Printf("[SPHINX] Exit node - relaying message")
		if err := directRelay(envelope); err != nil {
			log.Printf("[SPHINX] Direct relay failed: %v", err)
		}
	} else {
		// Forward to next hop
		log.Printf("[SPHINX] Forwarding to next hop: %s", nextHop[:16])
		if err := forwardSphinxPacket(nextPacket, nextHop); err != nil {
			log.Printf("[SPHINX] Forward failed: %v", err)
		}
	}
}

func ProcessSphinxPacket(packet *SphinxPacket, node *PKINode) (string, *SphinxPacket, *Envelope, error) {
	// This is a simplified version - in production you'd need the private key
	// For now, we'll use a mock processing

	// Decrypt header layer
	headerData, err := decryptAESGCM(node.PublicKey, packet.Header)
	if err != nil {
		return "", nil, nil, fmt.Errorf("header decryption failed: %w", err)
	}

	// Parse hop info
	var hopInfo SphinxHopInfo
	if err := json.Unmarshal(headerData[32:], &hopInfo); err != nil {
		return "", nil, nil, fmt.Errorf("hop info parsing failed: %w", err)
	}

	// Decrypt payload layer
	decryptedPayload, err := decryptAESGCM(node.PublicKey, packet.Payload)
	if err != nil {
		return "", nil, nil, fmt.Errorf("payload decryption failed: %w", err)
	}

	// If this is exit node, deserialize envelope
	var envelope *Envelope
	if hopInfo.NextHop == "EXIT" {
		envelope, err = deserializeEnvelope(decryptedPayload)
		if err != nil {
			return "", nil, nil, fmt.Errorf("envelope deserialization failed: %w", err)
		}
	}

	// Create next packet
	nextPacket := &SphinxPacket{
		Header:  headerData,
		Payload: decryptedPayload,
	}

	return hopInfo.NextHop, nextPacket, envelope, nil
}

func forwardSphinxPacket(packet *SphinxPacket, nextHopID string) error {
	node, exists := pkiDirectory.GetNode(nextHopID)
	if !exists {
		return fmt.Errorf("next hop not found in PKI: %s", nextHopID)
	}

	conn, err := torDialer.Dial("tcp", node.Address)
	if err != nil {
		return fmt.Errorf("failed to connect to next hop: %w", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	log.Printf("[SPHINX] Forwarded packet to %s", node.Address)
	return nil
}

// ============================================================================
// ROUTE SELECTION
// ============================================================================

func SelectSphinxRoute() ([]*PKINode, error) {
	healthyNodes := pkiDirectory.GetHealthyNodes(true)

	if len(healthyNodes) < SphinxHopCount {
		return nil, fmt.Errorf("not enough healthy nodes: have %d, need %d", len(healthyNodes), SphinxHopCount)
	}

	// Shuffle nodes
	for i := len(healthyNodes) - 1; i > 0; i-- {
		j, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		healthyNodes[i], healthyNodes[j.Int64()] = healthyNodes[j.Int64()], healthyNodes[i]
	}

	return healthyNodes[:SphinxHopCount], nil
}

// ============================================================================
// SMTP SERVER
// ============================================================================

type SMTPServer struct {
	name     string
	addr     string
	listener net.Listener
}

func NewSMTPServer(name, addr string) *SMTPServer {
	return &SMTPServer{
		name: name,
		addr: addr,
	}
}

func (s *SMTPServer) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
	}

	s.listener = listener
	log.Printf("[SMTP] Server listening on %s", s.addr)

	for {
		select {
		case <-shutdownSignal:
			return nil
		default:
		}

		listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))

		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return fmt.Errorf("accept error: %w", err)
		}

		stats.ConnectionsTotal.Add(1)
		stats.ConnectionsActive.Add(1)

		go func() {
			defer stats.ConnectionsActive.Add(-1)
			s.handleConnection(conn)
		}()
	}
}

func (s *SMTPServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	log.Printf("[SMTP] Connection from %s", remoteAddr)

	if !checkRateLimit(remoteAddr) {
		log.Printf("[SMTP] Rate limit exceeded for %s", remoteAddr)
		return
	}

	tc := textproto.NewConn(conn)
	defer tc.Close()

	tc.PrintfLine("220 %s fog v%s ESMTP", s.name, Version)

	var mailFrom string
	var rcptTo []string
	var messageData bytes.Buffer

	for {
		line, err := tc.ReadLine()
		if err != nil {
			if err != io.EOF {
				log.Printf("[SMTP] Read error: %v", err)
			}
			return
		}

		log.Printf("[SMTP] <- %s: %s", remoteAddr, line)

		cmd := strings.ToUpper(strings.Fields(line)[0])

		switch cmd {
		case "EHLO", "HELO":
			tc.PrintfLine("250-%s", s.name)
			tc.PrintfLine("250-8BITMIME")
			tc.PrintfLine("250-SIZE %d", MaxMessageSize)
			tc.PrintfLine("250 HELP")

		case "MAIL":
			if err := s.handleMAIL(line, &mailFrom, tc); err != nil {
				log.Printf("[SMTP] MAIL error: %v", err)
				return
			}

		case "RCPT":
			if err := s.handleRCPT(line, &rcptTo, tc); err != nil {
				log.Printf("[SMTP] RCPT error: %v", err)
				return
			}

		case "DATA":
			if err := s.handleDATA(tc, &messageData, mailFrom, rcptTo); err != nil {
				log.Printf("[SMTP] DATA error: %v", err)
				return
			}
			mailFrom = ""
			rcptTo = nil
			messageData.Reset()

		case "RSET":
			mailFrom = ""
			rcptTo = nil
			messageData.Reset()
			tc.PrintfLine("250 OK")

		case "NOOP":
			tc.PrintfLine("250 OK")

		case "QUIT":
			tc.PrintfLine("221 Bye")
			return

		default:
			tc.PrintfLine("502 Command not implemented")
		}
	}
}

func (s *SMTPServer) handleMAIL(line string, mailFrom *string, tc *textproto.Conn) error {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		tc.PrintfLine("501 Syntax error")
		return errors.New("invalid MAIL command")
	}

	// Extract FROM: address (ignore BODY= and other ESMTP parameters)
	fromPart := parts[1]
	if !strings.HasPrefix(strings.ToUpper(fromPart), "FROM:") {
		tc.PrintfLine("501 Syntax error in MAIL command")
		return errors.New("missing FROM:")
	}

	from := strings.TrimPrefix(fromPart, "FROM:")
	from = strings.TrimPrefix(from, "from:")
	from = strings.Trim(from, "<>")

	if !ValidateEmailAddress(from) {
		tc.PrintfLine("553 Invalid sender address")
		return errors.New("invalid sender")
	}

	*mailFrom = from
	tc.PrintfLine("250 OK")
	return nil
}

func (s *SMTPServer) handleRCPT(line string, rcptTo *[]string, tc *textproto.Conn) error {
	parts := strings.Fields(line)
	if len(parts) != 2 {
		tc.PrintfLine("501 Syntax error")
		return errors.New("invalid RCPT command")
	}

	to := strings.TrimPrefix(parts[1], "TO:")
	to = strings.TrimPrefix(to, "to:")
	to = strings.Trim(to, "<>")

	if !ValidateEmailAddress(to) {
		tc.PrintfLine("553 Invalid recipient address")
		return errors.New("invalid recipient")
	}

	if len(*rcptTo) >= MaxRecipients {
		tc.PrintfLine("452 Too many recipients")
		return errors.New("too many recipients")
	}

	*rcptTo = append(*rcptTo, to)
	tc.PrintfLine("250 OK")
	return nil
}

func (s *SMTPServer) handleDATA(tc *textproto.Conn, messageData *bytes.Buffer, mailFrom string, rcptTo []string) error {
	if mailFrom == "" || len(rcptTo) == 0 {
		tc.PrintfLine("503 Bad sequence of commands")
		return errors.New("MAIL/RCPT required before DATA")
	}

	tc.PrintfLine("354 End data with <CR><LF>.<CR><LF>")

	messageData.Reset()
	dotReader := tc.DotReader()
	written, err := io.Copy(messageData, dotReader)
	if err != nil {
		tc.PrintfLine("554 Transaction failed")
		return fmt.Errorf("failed to read message: %w", err)
	}

	if written > MaxMessageSize {
		tc.PrintfLine("552 Message too large")
		return errors.New("message too large")
	}

	messageID := generateMessageID()

	if isDuplicateMessage(messageID) {
		tc.PrintfLine("250 OK (duplicate)")
		log.Printf("[SMTP] Duplicate message %s - ignoring", messageID[:16])
		return nil
	}

	envelope := &Envelope{
		From:        mailFrom,
		To:          rcptTo,
		MessageData: bytes.NewBuffer(messageData.Bytes()),
		MessageID:   messageID,
		ReceivedAt:  time.Now(),
		Size:        written,
		RetryCount:  0,
	}

	select {
	case mailQueue <- envelope:
		stats.MessagesReceived.Add(1)
		tc.PrintfLine("250 OK Message queued %s", messageID[:16])
		log.Printf("[SMTP] Queued message %s from %s to %v (%d bytes)",
			messageID[:16], mailFrom, rcptTo, written)
	default:
		tc.PrintfLine("452 Queue full")
		return errors.New("queue full")
	}

	return nil
}

// ============================================================================
// RELAY LOGIC
// ============================================================================

func relayWorker(id int) {
	defer shutdownWg.Done()
	log.Printf("[RELAY] Worker %d started", id)

	for {
		select {
		case <-shutdownSignal:
			return
		case envelope := <-mailQueue:
			if err := processEnvelope(envelope); err != nil {
				log.Printf("[RELAY] Worker %d failed: %v", id, err)
				stats.MessagesFailed.Add(1)
			} else {
				stats.MessagesDelivered.Add(1)
			}
		}
	}
}

func processEnvelope(envelope *Envelope) error {
	// Record message size for adaptive padding
	paddingStats.RecordMessage(envelope.Size)

	// Check if Sphinx routing is available
	if sphinxEnabled.Load() && pkiDirectory.HealthyCount() >= SphinxHopCount {
		log.Printf("[RELAY] Attempting Sphinx routing for %s", envelope.MessageID[:16])
		if err := sphinxRelay(envelope); err != nil {
			log.Printf("[RELAY] Sphinx routing failed, falling back to direct: %v", err)
			return directRelay(envelope)
		}
		stats.SphinxRoutingUsed.Add(1)
		return nil
	}

	// Fallback to direct relay
	log.Printf("[RELAY] Direct relay for %s (Sphinx unavailable)", envelope.MessageID[:16])
	stats.DirectRelayUsed.Add(1)
	return directRelay(envelope)
}

func sphinxRelay(envelope *Envelope) error {
	// Select route
	route, err := SelectSphinxRoute()
	if err != nil {
		return fmt.Errorf("route selection failed: %w", err)
	}

	log.Printf("[SPHINX] Selected route: %s -> %s -> %s",
		route[0].NodeID[:8], route[1].NodeID[:8], route[2].NodeID[:8])

	// Create Sphinx packet
	packet, err := CreateSphinxPacket(envelope, route)
	if err != nil {
		return fmt.Errorf("packet creation failed: %w", err)
	}

	// Apply exponential delay
	delay := delayGenerator.Generate()
	log.Printf("[SPHINX] Applying delay: %v", delay)
	time.Sleep(delay)

	// Send to entry node
	entryNode := route[0]
	conn, err := torDialer.Dial("tcp", entryNode.Address)
	if err != nil {
		return fmt.Errorf("failed to connect to entry node: %w", err)
	}
	defer conn.Close()

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(packet); err != nil {
		return fmt.Errorf("failed to send packet: %w", err)
	}

	log.Printf("[SPHINX] Packet sent to entry node %s", entryNode.NodeID[:16])
	return nil
}

func directRelay(envelope *Envelope) error {
	for _, recipient := range envelope.To {
		if err := deliverMessage(envelope, recipient); err != nil {
			log.Printf("[RELAY] Delivery to %s failed: %v", recipient, err)
			if envelope.RetryCount < MaxRetries {
				envelope.RetryCount++
				time.AfterFunc(time.Duration(envelope.RetryCount)*30*time.Second, func() {
					mailQueue <- envelope
				})
			}
			return err
		}
	}
	return nil
}

func deliverMessage(envelope *Envelope, recipient string) error {
	// Apply exponential delay for timing obfuscation
	delay := delayGenerator.Generate()
	log.Printf("[RELAY] Applying delay %v before delivery to %s", delay, recipient)
	time.Sleep(delay)

	domain := strings.Split(recipient, "@")[1]
	
	var smtpHost string
	var smtpPort string

	if strings.HasSuffix(domain, ".onion") {
		smtpHost = domain
		smtpPort = "25"
	} else {
		mxRecords, err := net.LookupMX(domain)
		if err != nil || len(mxRecords) == 0 {
			smtpHost = domain
		} else {
			smtpHost = strings.TrimSuffix(mxRecords[0].Host, ".")
		}
		smtpPort = "25"
	}

	target := net.JoinHostPort(smtpHost, smtpPort)
	log.Printf("[RELAY] Connecting to %s", target)

	conn, err := torDialer.Dial("tcp", target)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer conn.Close()

	// Manual SMTP handshake to control EHLO hostname
	tc := textproto.NewConn(conn)
	defer tc.Close()

	// Read greeting
	_, _, err = tc.ReadResponse(220)
	if err != nil {
		return fmt.Errorf("failed to read greeting: %w", err)
	}

	// Send EHLO with our .onion address
	localNodeName := localNode.Address
	if localNodeName == "" || localNodeName == "127.0.0.1:9999" {
		// Fallback if node address not properly configured
		localNodeName = "fog.onion"
	}
	// Extract just the hostname part (remove :port)
	if strings.Contains(localNodeName, ":") {
		localNodeName = strings.Split(localNodeName, ":")[0]
	}

	tc.PrintfLine("EHLO %s", localNodeName)
	_, _, err = tc.ReadResponse(250)
	if err != nil {
		// Try HELO if EHLO fails
		tc.PrintfLine("HELO %s", localNodeName)
		_, _, err = tc.ReadResponse(250)
		if err != nil {
			return fmt.Errorf("EHLO/HELO failed: %w", err)
		}
	}

	log.Printf("[RELAY] Identified as %s to %s", localNodeName, smtpHost)

	// MAIL FROM
	tc.PrintfLine("MAIL FROM:<%s>", envelope.From)
	_, _, err = tc.ReadResponse(250)
	if err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// RCPT TO
	tc.PrintfLine("RCPT TO:<%s>", recipient)
	_, _, err = tc.ReadResponse(250)
	if err != nil {
		return fmt.Errorf("RCPT TO failed: %w", err)
	}

	// DATA
	tc.PrintfLine("DATA")
	_, _, err = tc.ReadResponse(354)
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}

	// Write message (NO PADDING to preserve message integrity)
	// Padding would corrupt UTF-8 content for Usenet gateways
	dw := tc.DotWriter()
	if _, err := dw.Write(envelope.MessageData.Bytes()); err != nil {
		return fmt.Errorf("message transfer failed: %w", err)
	}
	if err := dw.Close(); err != nil {
		return fmt.Errorf("message completion failed: %w", err)
	}

	// Read final response
	_, _, err = tc.ReadResponse(250)
	if err != nil {
		return fmt.Errorf("message not accepted: %w", err)
	}

	// QUIT
	tc.PrintfLine("QUIT")
	tc.ReadResponse(221)

	stats.BytesTransferred.Add(uint64(envelope.MessageData.Len()))
	log.Printf("[RELAY] SUCCESS: Delivered %s to %s (%d bytes, no padding)",
		envelope.MessageID[:16], recipient, envelope.Size)

	return nil
}

func applyAdaptivePadding(data []byte, originalSize int64) []byte {
	buckets := paddingStats.GetAdaptiveBuckets()
	
	targetSize := buckets[len(buckets)-1]
	for _, bucket := range buckets {
		if originalSize <= bucket {
			targetSize = bucket
			break
		}
	}

	if int64(len(data)) >= targetSize {
		return data
	}

	padded := make([]byte, targetSize)
	copy(padded, data)
	
	rand.Read(padded[len(data):])

	return padded
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

func ValidateEmailAddress(email string) bool {
	if len(email) > 254 || !strings.Contains(email, "@") {
		return false
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}

	localPart, domain := parts[0], parts[1]

	if len(localPart) == 0 || len(localPart) > 64 || len(domain) == 0 || len(domain) > 253 {
		return false
	}

	if !localPartRegex.MatchString(localPart) || !domainRegex.MatchString(domain) {
		return false
	}

	return true
}

func generateMessageID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func isDuplicateMessage(messageID string) bool {
	messageIDCacheMux.Lock()
	defer messageIDCacheMux.Unlock()

	// Clean old entries
	now := time.Now()
	for id, timestamp := range messageIDCache {
		if now.Sub(timestamp) > messageIDCacheTTL {
			delete(messageIDCache, id)
		}
	}

	if _, exists := messageIDCache[messageID]; exists {
		return true
	}

	messageIDCache[messageID] = now
	return false
}

func checkRateLimit(ip string) bool {
	rateLimitMapMux.Lock()
	defer rateLimitMapMux.Unlock()

	limiter, exists := rateLimitMap[ip]
	if !exists {
		limiter = &RateLimiter{
			count:     1,
			lastReset: time.Now(),
		}
		rateLimitMap[ip] = limiter
		return true
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	if time.Since(limiter.lastReset) > RateLimitWindow {
		limiter.count = 1
		limiter.lastReset = time.Now()
		return true
	}

	if limiter.count >= RateLimitPerIP {
		return false
	}

	limiter.count++
	return true
}

// ============================================================================
// BACKGROUND WORKERS
// ============================================================================

func RotatePKIKeys() {
	defer shutdownWg.Done()

	jitter := time.Duration(mathrand.Int63n(int64(KeyRotationJitter)))
	ticker := time.NewTicker(PKIRotationInterval + jitter)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return
		case <-ticker.C:
			log.Printf("[PKI] Rotating keys")
			if err := InitializePKI(); err != nil {
				log.Printf("[PKI] Key rotation failed: %v", err)
			}
		}
	}
}

func PKIRefreshWorker(pkiURL string) {
	defer shutdownWg.Done()

	ticker := time.NewTicker(PKIRefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return
		case <-ticker.C:
			log.Printf("[PKI] Refreshing directory from URL")
			if err := pkiDirectory.LoadFromURL(pkiURL); err != nil {
				log.Printf("[PKI] Refresh failed: %v", err)
			} else {
				log.Printf("[PKI] Directory refreshed: %d nodes (%d healthy)",
					pkiDirectory.Count(), pkiDirectory.HealthyCount())
			}
		}
	}
}

func PaddingUpdateWorker() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(PaddingAdaptiveWindow)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return
		case <-ticker.C:
			buckets := paddingStats.GetAdaptiveBuckets()
			log.Printf("[PADDING] Updated adaptive buckets: %v", buckets)
		}
	}
}

func statsMonitor() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return
		case <-ticker.C:
			uptime := time.Since(stats.StartTime)
			log.Printf("[STATS] Uptime: %v | Connections: %d/%d | Messages: R:%d D:%d F:%d | Sphinx:%d Direct:%d | Bytes: %d MB",
				uptime.Round(time.Second),
				stats.ConnectionsActive.Load(),
				stats.ConnectionsTotal.Load(),
				stats.MessagesReceived.Load(),
				stats.MessagesDelivered.Load(),
				stats.MessagesFailed.Load(),
				stats.SphinxRoutingUsed.Load(),
				stats.DirectRelayUsed.Load(),
				stats.BytesTransferred.Load()/(1024*1024))
		}
	}
}

func NodeHealthChecker() {
	defer shutdownWg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return
		case <-ticker.C:
			checkNodeHealth()
		}
	}
}

func checkNodeHealth() {
	nodes := pkiDirectory.GetHealthyNodes(true)
	
	for _, node := range nodes {
		go func(n *PKINode) {
			conn, err := torDialer.Dial("tcp", n.Address)
			if err != nil {
				n.Healthy = false
				log.Printf("[HEALTH] Node %s is DOWN", n.NodeID[:16])
				return
			}
			conn.Close()
			
			n.Healthy = true
			n.LastSeen = time.Now()
		}(node)
	}
}

// ============================================================================
// MAIN
// ============================================================================

func init() {
	emailRegExp = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+$`)
	localPartRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+$`)
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9.\-]+$`)

	delayGenerator = NewExponentialDelayGenerator(ExponentialDelayLambda, ExponentialDelayMin, ExponentialDelayMax)
	paddingStats = NewPaddingStatistics()

	stats = &Statistics{
		StartTime: time.Now(),
	}

	shutdownSignal = make(chan struct{})
	
	// Seed math/rand for jitter calculations
	mathrand.Seed(time.Now().UnixNano())
}

func main() {
	addr := flag.String("addr", "127.0.0.1:2525", "SMTP listen address")
	name := flag.String("name", "fog.onion", "Server name")
	nodeAddr := flag.String("node-addr", "127.0.0.1:9999", "Sphinx node listen address")
	enableSphinx := flag.Bool("sphinx", false, "Enable Sphinx multi-hop routing")
	pkiFile := flag.String("pki-file", "", "PKI directory JSON file")
	pkiURL := flag.String("pki-url", "", "PKI directory URL (http:// or http://*.onion/)")
	showVersion := flag.Bool("version", false, "Show version and features")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s\n\n", AppName, Version)
		fmt.Println("LIBRARIES:")
		fmt.Println("- golang.org/x/crypto/curve25519 (Curve25519 ECDH)")
		fmt.Println("- golang.org/x/crypto/hkdf (HKDF-SHA256 key derivation)")
		fmt.Println("- golang.org/x/net/proxy (Tor SOCKS5)")
		fmt.Println("- crypto/aes + crypto/cipher (AES-GCM)")
		fmt.Println("- crypto/hmac + crypto/sha256 (HMAC)")
		fmt.Println("\nSECURITY FEATURES:")
		fmt.Println("✓ Sphinx packet format (forward secrecy)")
		fmt.Println("✓ Multi-hop routing (3-hop unlinkability)")
		fmt.Println("✓ Dynamic PKI with 3h key rotation")
		fmt.Println("✓ Exponential timing delays (anti-correlation)")
		fmt.Println("✓ Adaptive padding geometry (size obfuscation)")
		fmt.Println("✓ Replay protection (24h message-ID cache)")
		fmt.Println("✓ No metadata retention (memory-only)")
		fmt.Println("✓ Global adversary resistance")
		fmt.Println("\nMODES:")
		fmt.Println("  Direct relay (default): fog relays via Tor only")
		fmt.Println("  Sphinx mode (-sphinx):  Multi-hop through fog network")
		fmt.Println("\nUSAGE:")
		fmt.Println("  Direct mode:")
		fmt.Println("    fog -addr 127.0.0.1:2525 -name fog.onion")
		fmt.Println("\n  Sphinx mode:")
		fmt.Println("    fog -addr 127.0.0.1:2525 -name fog.onion -sphinx -pki-file nodes.json")
		os.Exit(0)
	}

	log.Printf("[FOG] Starting %s v%s", AppName, Version)
	log.Printf("[FOG] Server name: %s", *name)

	// Initialize Tor dialer
	dialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[FOG] Failed to create Tor dialer: %v", err)
	}
	torDialer = dialer
	log.Printf("[FOG] Tor proxy: %s", TorSocksProxyAddr)

	// Initialize PKI
	if err := InitializePKI(); err != nil {
		log.Fatalf("[FOG] PKI initialization failed: %v", err)
	}

	// Update local node address with the public name
	// This is what we'll use in SMTP EHLO
	localNode.Address = *name
	
	log.Printf("[FOG] Node identity: %s", localNode.Address)

	// Load PKI directory
	if *pkiFile != "" {
		if err := pkiDirectory.LoadFromFile(*pkiFile); err != nil {
			log.Printf("[PKI] Warning: Failed to load PKI file: %v", err)
		}
	}

	if *pkiURL != "" {
		if err := pkiDirectory.LoadFromURL(*pkiURL); err != nil {
			log.Printf("[PKI] Warning: Failed to load PKI from URL: %v", err)
		}
	}

	// Check if Sphinx should be enabled
	if *enableSphinx {
		if pkiDirectory.HealthyCount() >= SphinxHopCount {
			sphinxEnabled.Store(true)
			log.Printf("[FOG] Mode: Sphinx multi-hop ENABLED (%d healthy nodes)", pkiDirectory.HealthyCount())
		} else {
			log.Printf("[FOG] Warning: Sphinx requested but only %d healthy nodes (need %d)",
				pkiDirectory.HealthyCount(), SphinxHopCount)
			log.Printf("[FOG] Mode: Direct relay (will auto-upgrade when nodes available)")
		}
	} else {
		log.Printf("[FOG] Mode: Direct relay")
	}

	// Initialize mail queue
	mailQueue = make(chan *Envelope, 1000)

	// Start Sphinx node server if enabled
	if *enableSphinx {
		shutdownWg.Add(1)
		if err := StartSphinxNodeServer(*nodeAddr); err != nil {
			log.Fatalf("[SPHINX] Failed to start node server: %v", err)
		}
	}

	// Start relay workers
	for i := 0; i < RelayWorkerCount; i++ {
		shutdownWg.Add(1)
		go relayWorker(i)
	}

	// Start background workers
	shutdownWg.Add(1)
	go RotatePKIKeys()

	shutdownWg.Add(1)
	go PaddingUpdateWorker()

	shutdownWg.Add(1)
	go statsMonitor()

	shutdownWg.Add(1)
	go NodeHealthChecker()

	if *pkiURL != "" {
		shutdownWg.Add(1)
		go PKIRefreshWorker(*pkiURL)
	}

	// Start SMTP server
	server := NewSMTPServer(*name, *addr)

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Printf("[FOG] Shutdown signal received")
		close(shutdownSignal)
		if server.listener != nil {
			server.listener.Close()
		}
	}()

	if err := server.Start(); err != nil {
		log.Fatalf("[FOG] Server error: %v", err)
	}

	shutdownWg.Wait()

	// Save PKI on shutdown
	if *pkiFile != "" {
		if err := pkiDirectory.SaveToFile(*pkiFile); err != nil {
			log.Printf("[PKI] Warning: Failed to save PKI: %v", err)
		}
	}

	log.Printf("[FOG] Shutdown complete")
}
