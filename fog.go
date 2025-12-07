// fog v2.1.1 - Anonymous SMTP Relay with Sphinx Mixnet + Header Sanitization
// Features: delay pool, exit node header sanitization (RFC compliant)
// Copyright 2025 - fog Project

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/proxy"
)

const (
	Version = "2.1.1"

	TorSocks    = "127.0.0.1:9050"
	DefaultPort = "2525"
	NodePort    = "9999"

	MinDelay = 500 * time.Millisecond
	MaxDelay = 5 * time.Second

	BatchWindow = 30 * time.Second
	BatchSize   = 10

	HealthInterval = 3 * time.Minute
	StatsInterval  = 60 * time.Second
	PoolInterval   = 1 * time.Minute

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

	PaddedPayloadSize = 64 * 1024

	DefaultMinPoolDelay = 1 * time.Hour
	DefaultMaxPoolDelay = 24 * time.Hour
)

// ============================================================================
// DELAY STRATEGIES
// ============================================================================

type DelayStrategy int

const (
	DelayExponential DelayStrategy = iota
	DelayConstant
	DelayPoisson
)

func (d DelayStrategy) String() string {
	switch d {
	case DelayExponential:
		return "exponential"
	case DelayConstant:
		return "constant"
	case DelayPoisson:
		return "poisson"
	default:
		return "unknown"
	}
}

func parseDelayStrategy(s string) DelayStrategy {
	switch strings.ToLower(s) {
	case "constant":
		return DelayConstant
	case "poisson":
		return DelayPoisson
	default:
		return DelayExponential
	}
}

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

type QueuedMessage struct {
	ID          string
	From        string
	To          string
	Data        []byte
	EnqueueTime time.Time
	SendAfter   time.Time
	Attempts    int
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
	ID        string
	Private   []byte
	Public    []byte
	Address   string
	ShortName string
	mu        sync.RWMutex
}

type Stats struct {
	Start    time.Time
	Recv     int64
	Sent     int64
	Failed   int64
	Sphinx   int64
	Direct   int64
	MixRecv  int64
	MixFwd   int64
	Queued   int64
	Delayed  int64
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
	NextHop string
	IsExit  bool
}

type DelayPool struct {
	db          *sql.DB
	minDelay    time.Duration
	maxDelay    time.Duration
	strategy    DelayStrategy
	mu          sync.RWMutex
}

// ============================================================================
// GLOBALS
// ============================================================================

var (
	pki         = &PKI{Nodes: make([]*Node, 0)}
	localNode   = &LocalNode{}
	stats       = &Stats{Start: time.Now()}
	replayCache = &ReplayCache{cache: make(map[string]time.Time)}
	batch       = &Batch{packets: make([]*SphinxPacket, 0)}
	delayPool   *DelayPool

	enableSphinx bool
	enableDelay  bool
	debug        bool
)

// ============================================================================
// DELAY POOL - SQLITE DATABASE
// ============================================================================

func NewDelayPool(dbPath string, minDelay, maxDelay time.Duration, strategy DelayStrategy) (*DelayPool, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	schema := `
		CREATE TABLE IF NOT EXISTS message_queue (
			id TEXT PRIMARY KEY,
			from_addr TEXT NOT NULL,
			to_addr TEXT NOT NULL,
			data BLOB NOT NULL,
			enqueue_time INTEGER NOT NULL,
			send_after INTEGER NOT NULL,
			attempts INTEGER DEFAULT 0,
			created_at INTEGER DEFAULT (strftime('%s', 'now'))
		);
		CREATE INDEX IF NOT EXISTS idx_send_after ON message_queue(send_after);
	`
	
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}

	pool := &DelayPool{
		db:       db,
		minDelay: minDelay,
		maxDelay: maxDelay,
		strategy: strategy,
	}

	return pool, nil
}

func (p *DelayPool) Close() error {
	return p.db.Close()
}

func (p *DelayPool) calculateDelay() time.Duration {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.strategy {
	case DelayConstant:
		return p.minDelay + time.Duration(secureRandInt64(int64(p.maxDelay-p.minDelay)))
	
	case DelayPoisson:
		lambda := float64(p.minDelay+p.maxDelay) / 2.0
		delay := time.Duration(poissonRandom(lambda))
		if delay < p.minDelay {
			delay = p.minDelay
		}
		if delay > p.maxDelay {
			delay = p.maxDelay
		}
		return delay
	
	case DelayExponential:
		fallthrough
	default:
		mean := float64(p.minDelay+p.maxDelay) / 2.0
		lambda := 1.0 / mean
		
		u := secureRandFloat64()
		delay := time.Duration(-math.Log(1.0-u) / lambda)
		
		if delay < p.minDelay {
			delay = p.minDelay
		}
		if delay > p.maxDelay {
			delay = p.maxDelay
		}
		return delay
	}
}

func (p *DelayPool) Enqueue(msg *Message) error {
	delay := p.calculateDelay()
	sendAfter := time.Now().Add(delay)
	
	for _, to := range msg.To {
		_, err := p.db.Exec(`
			INSERT INTO message_queue (id, from_addr, to_addr, data, enqueue_time, send_after)
			VALUES (?, ?, ?, ?, ?, ?)`,
			msg.ID+"-"+to,
			msg.From,
			to,
			msg.Data,
			msg.Time.Unix(),
			sendAfter.Unix(),
		)
		if err != nil {
			return fmt.Errorf("enqueue: %w", err)
		}
	}

	atomic.AddInt64(&stats.Queued, int64(len(msg.To)))
	
	if debug {
		log.Printf("[POOL] Enqueued %s: %d recipients, delay=%v, send_after=%s",
			msg.ID, len(msg.To), delay, sendAfter.Format("15:04:05"))
	}
	
	return nil
}

func (p *DelayPool) GetReady() ([]*QueuedMessage, error) {
	now := time.Now().Unix()
	
	rows, err := p.db.Query(`
		SELECT id, from_addr, to_addr, data, enqueue_time, send_after, attempts
		FROM message_queue
		WHERE send_after <= ?
		ORDER BY send_after
		LIMIT 100`,
		now,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []*QueuedMessage
	for rows.Next() {
		var m QueuedMessage
		var enqT, sendT int64
		
		err := rows.Scan(&m.ID, &m.From, &m.To, &m.Data, &enqT, &sendT, &m.Attempts)
		if err != nil {
			log.Printf("[POOL] Scan error: %v", err)
			continue
		}
		
		m.EnqueueTime = time.Unix(enqT, 0)
		m.SendAfter = time.Unix(sendT, 0)
		messages = append(messages, &m)
	}

	return messages, nil
}

func (p *DelayPool) Delete(id string) error {
	_, err := p.db.Exec("DELETE FROM message_queue WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	atomic.AddInt64(&stats.Queued, -1)
	atomic.AddInt64(&stats.Delayed, 1)
	return nil
}

func (p *DelayPool) IncrementAttempts(id string) error {
	_, err := p.db.Exec("UPDATE message_queue SET attempts = attempts + 1 WHERE id = ?", id)
	return err
}

func (p *DelayPool) Count() (int64, error) {
	var count int64
	err := p.db.QueryRow("SELECT COUNT(*) FROM message_queue").Scan(&count)
	return count, err
}

func (p *DelayPool) Stats() (total, ready int64, oldest time.Time, err error) {
	err = p.db.QueryRow("SELECT COUNT(*), MIN(send_after) FROM message_queue").Scan(&total, &oldest)
	if err != nil {
		return
	}
	
	now := time.Now().Unix()
	err = p.db.QueryRow("SELECT COUNT(*) FROM message_queue WHERE send_after <= ?", now).Scan(&ready)
	return
}

// ============================================================================
// SECURE RANDOM UTILITIES
// ============================================================================

func secureRandInt64(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0
	}
	return n.Int64()
}

func secureRandFloat64() float64 {
	n := secureRandInt64(1 << 53)
	return float64(n) / float64(1<<53)
}

func poissonRandom(lambda float64) float64 {
	L := math.Exp(-lambda)
	k := 0.0
	p := 1.0
	
	for p > L {
		k++
		p *= secureRandFloat64()
	}
	
	return k - 1.0
}

func secureRandDelay(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	delta := int64(max - min)
	return min + time.Duration(secureRandInt64(delta))
}

func secureRandBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func secureRandHex(n int) string {
	b, _ := secureRandBytes(n)
	return hex.EncodeToString(b)
}

// ============================================================================
// HEADER SANITIZATION (v2.1.1)
// ============================================================================

func sanitizeHeaders(payload []byte) []byte {
	// Parse message
	msg, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(payload))).ReadMIMEHeader()
	if err != nil {
		return payload // Can't parse, return as-is
	}

	// Find headers/body boundary
	headerEnd := bytes.Index(payload, []byte("\r\n\r\n"))
	if headerEnd == -1 {
		headerEnd = bytes.Index(payload, []byte("\n\n"))
		if headerEnd == -1 {
			return payload
		}
		headerEnd += 2
	} else {
		headerEnd += 4
	}
	
	body := payload[headerEnd:]

	// Build sanitized headers
	sanitized := make(textproto.MIMEHeader)

	// REPLACE: From
	sanitized.Set("From", fmt.Sprintf("Anonymous <anonymous@%s.fog>", localNode.ShortName))

	// REPLACE: Message-ID
	sanitized.Set("Message-ID", fmt.Sprintf("<%s@%s.fog>", secureRandHex(32), localNode.ShortName))

	// REPLACE: Date (randomize ±1-2h)
	if origDate := msg.Get("Date"); origDate != "" {
		if t, err := time.Parse(time.RFC1123Z, origDate); err == nil {
			offset := secureRandInt64(7200) - 3600 // ±1h in seconds
			newDate := t.Add(time.Duration(offset) * time.Second)
			sanitized.Set("Date", newDate.Format(time.RFC1123Z))
		} else {
			sanitized.Set("Date", time.Now().Format(time.RFC1123Z))
		}
	} else {
		sanitized.Set("Date", time.Now().Format(time.RFC1123Z))
	}

	// KEEP: Essential headers
	keepHeaders := []string{
		"To", "Newsgroups", "Subject",
		"Content-Type", "Content-Transfer-Encoding", "MIME-Version",
		"References", "In-Reply-To", // Threading (RFC 5536)
	}

	for _, h := range keepHeaders {
		if v := msg.Get(h); v != "" {
			sanitized.Set(h, v)
		}
	}

	// Rebuild message
	var buf bytes.Buffer
	for key, values := range sanitized {
		for _, value := range values {
			buf.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	buf.WriteString("\r\n")
	buf.Write(body)

	if debug {
		log.Printf("[SANITIZE] Headers cleaned: From=anonymous@%s.fog", localNode.ShortName)
	}

	return buf.Bytes()
}

// ============================================================================
// PKI MANAGEMENT
// ============================================================================

func (p *PKI) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read pki: %w", err)
	}

	if err := json.Unmarshal(data, p); err != nil {
		return fmt.Errorf("parse pki: %w", err)
	}

	p.mu.Lock()
	for _, node := range p.Nodes {
		node.Healthy = false
	}
	p.mu.Unlock()

	log.Printf("[PKI] Loaded %d nodes from %s", len(p.Nodes), path)
	return nil
}

func (p *PKI) GetHealthy() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var healthy []*Node
	for _, n := range p.Nodes {
		if n.Healthy && n.ID != localNode.ID {
			healthy = append(healthy, n)
		}
	}
	return healthy
}

func (p *PKI) GetNode(id string) *Node {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, n := range p.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (p *PKI) RandomPath(hops int) ([]*Node, error) {
	healthy := p.GetHealthy()
	
	if len(healthy) < hops {
		return nil, fmt.Errorf("insufficient nodes: need %d, have %d", hops, len(healthy))
	}

	shuffled := make([]*Node, len(healthy))
	copy(shuffled, healthy)
	
	for i := len(shuffled) - 1; i > 0; i-- {
		j := int(secureRandInt64(int64(i + 1)))
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	return shuffled[:hops], nil
}

// ============================================================================
// LOCAL NODE
// ============================================================================

func (n *LocalNode) Init(name, shortName string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		return err
	}

	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return err
	}

	hash := sha256.Sum256(public)
	n.ID = base64.RawURLEncoding.EncodeToString(hash[:])

	n.Private = private
	n.Public = public
	n.Address = name
	n.ShortName = shortName

	log.Printf("[NODE] ID=%s Address=%s Name=%s", n.ID[:16], name, shortName)
	return nil
}

func (n *LocalNode) ExportInfo(name, shortName string) error {
	n.mu.RLock()
	defer n.mu.RUnlock()

	info := map[string]interface{}{
		"version": Version,
		"updated": time.Now().UTC().Format(time.RFC3339),
		"nodes": []map[string]string{
			{
				"node_id":    n.ID,
				"public_key": base64.StdEncoding.EncodeToString(n.Public),
				"address":    name + ":" + NodePort,
				"name":       shortName,
				"version":    Version,
			},
		},
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile("nodes.json", data, 0644)
}

// ============================================================================
// REPLAY CACHE
// ============================================================================

func (r *ReplayCache) Check(id string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, exists := r.cache[id]
	return exists
}

func (r *ReplayCache) Add(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[id] = time.Now()
}

func (r *ReplayCache) Cleanup() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		r.mu.Lock()
		now := time.Now()
		for id, t := range r.cache {
			if now.Sub(t) > CacheTTL {
				delete(r.cache, id)
			}
		}
		r.mu.Unlock()
	}
}

// ============================================================================
// SPHINX PACKET FORMAT
// ============================================================================

func buildSphinxPacket(path []*Node, payload []byte) (*SphinxPacket, error) {
	if len(path) == 0 {
		return nil, errors.New("empty path")
	}

	paddedPayload := make([]byte, PaddedPayloadSize)
	binary.BigEndian.PutUint32(paddedPayload[0:4], uint32(len(payload)))
	copy(paddedPayload[4:], payload)
	
	if len(payload)+4 < PaddedPayloadSize {
		rand.Read(paddedPayload[4+len(payload):])
	}

	routing := make([]byte, 0, len(path)*64)
	for i, node := range path {
		isExit := (i == len(path)-1)
		
		info := &RoutingInfo{
			NextHop: node.Address,
			IsExit:  isExit,
		}
		
		infoBytes, _ := json.Marshal(info)
		routing = append(routing, infoBytes...)
		routing = append(routing, 0)
	}

	ephPrivate := make([]byte, 32)
	rand.Read(ephPrivate)
	ephPublic, _ := curve25519.X25519(ephPrivate, curve25519.Basepoint)

	encrypted := paddedPayload
	sharedSecrets := make([][]byte, 0)

	for i := len(path) - 1; i >= 0; i-- {
		nodePubKey, err := path[i].GetPubKey()
		if err != nil {
			return nil, err
		}

		shared, err := curve25519.X25519(ephPrivate, nodePubKey)
		if err != nil {
			return nil, err
		}
		sharedSecrets = append([][]byte{shared}, sharedSecrets...)

		kdf := hkdf.New(sha256.New, shared, nil, []byte("fog-sphinx-v2"))
		key := make([]byte, AESKeySize)
		kdf.Read(key)

		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}

		nonce := make([]byte, NonceSize)
		rand.Read(nonce)

		encrypted = gcm.Seal(nonce, nonce, encrypted, nil)
	}

	header := &SphinxHeader{
		Version: 2,
		Routing: routing,
	}
	copy(header.EphKey[:], ephPublic)

	mac := hmac.New(sha256.New, sharedSecrets[0])
	mac.Write(encrypted)
	copy(header.MAC[:], mac.Sum(nil))

	return &SphinxPacket{
		Header:  header,
		Payload: encrypted,
	}, nil
}

func processSphinxPacket(packet *SphinxPacket) (*RoutingInfo, []byte, error) {
	shared, err := curve25519.X25519(localNode.Private, packet.Header.EphKey[:])
	if err != nil {
		return nil, nil, err
	}

	kdf := hkdf.New(sha256.New, shared, nil, []byte("fog-sphinx-v2"))
	key := make([]byte, AESKeySize)
	kdf.Read(key)

	mac := hmac.New(sha256.New, shared)
	mac.Write(packet.Payload)
	if !hmac.Equal(packet.Header.MAC[:], mac.Sum(nil)[:HMACSize]) {
		return nil, nil, errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	if len(packet.Payload) < NonceSize {
		return nil, nil, errors.New("payload too short")
	}

	nonce := packet.Payload[:NonceSize]
	ciphertext := packet.Payload[NonceSize:]

	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	routingParts := bytes.Split(packet.Header.Routing, []byte{0})
	if len(routingParts) == 0 {
		return nil, nil, errors.New("no routing info")
	}

	var info RoutingInfo
	if err := json.Unmarshal(routingParts[0], &info); err != nil {
		return nil, nil, err
	}

	if info.IsExit {
		if len(decrypted) < 4 {
			return nil, nil, errors.New("invalid exit payload")
		}
		
		originalLen := binary.BigEndian.Uint32(decrypted[0:4])
		if originalLen > uint32(len(decrypted)-4) {
			return nil, nil, errors.New("invalid length")
		}
		
		original := decrypted[4 : 4+originalLen]
		
		if debug {
			log.Printf("[SPHINX] Exit node: extracted %d bytes from %d padded",
				originalLen, len(decrypted))
		}
		
		return &info, original, nil
	}

	newHeader := &SphinxHeader{
		Version: packet.Header.Version,
		EphKey:  packet.Header.EphKey,
		Routing: bytes.Join(routingParts[1:], []byte{0}),
	}
	copy(newHeader.MAC[:], packet.Header.MAC[:])

	newPacket := &SphinxPacket{
		Header:  newHeader,
		Payload: decrypted,
	}

	var buf bytes.Buffer
	json.NewEncoder(&buf).Encode(newPacket)

	return &info, buf.Bytes(), nil
}

// ============================================================================
// BATCH MIXING
// ============================================================================

func (b *Batch) Add(packet *SphinxPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.packets) == 0 {
		b.start = time.Now()
	}

	b.packets = append(b.packets, packet)

	if len(b.packets) >= BatchSize {
		go b.Flush()
	}
}

func (b *Batch) Flush() {
	b.mu.Lock()
	if len(b.packets) == 0 {
		b.mu.Unlock()
		return
	}

	toSend := b.packets
	b.packets = make([]*SphinxPacket, 0)
	b.mu.Unlock()

	for i := len(toSend) - 1; i > 0; i-- {
		j := int(secureRandInt64(int64(i + 1)))
		toSend[i], toSend[j] = toSend[j], toSend[i]
	}

	for _, packet := range toSend {
		go forwardSphinxPacket(packet)
	}

	atomic.AddInt64(&stats.MixFwd, int64(len(toSend)))
}

func (b *Batch) AutoFlush() {
	ticker := time.NewTicker(BatchWindow)
	defer ticker.Stop()

	for range ticker.C {
		b.Flush()
	}
}

// ============================================================================
// SMTP SERVER
// ============================================================================

func smtpServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("[SMTP] Listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
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

	writer.WriteString("220 fog SMTP Ready\r\n")
	writer.Flush()

	var from string
	var recipients []string
	var data bytes.Buffer

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSpace(line)
		cmd := strings.ToUpper(strings.Fields(line)[0])

		if debug {
			log.Printf("[SMTP] <- %s: %s", remote, line)
		}

		switch cmd {
		case "EHLO", "HELO":
			writer.WriteString("250 Hello\r\n")

		case "MAIL":
			from = extractEmail(line)
			writer.WriteString("250 OK\r\n")

		case "RCPT":
			to := extractEmail(line)
			recipients = append(recipients, to)
			writer.WriteString("250 OK\r\n")

		case "DATA":
			writer.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
			writer.Flush()

			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if line == ".\r\n" {
					break
				}
				data.WriteString(line)
			}

			msg := &Message{
				ID:   generateMessageID(),
				From: from,
				To:   recipients,
				Data: data.Bytes(),
				Time: time.Now(),
			}

			if enableDelay {
				if err := delayPool.Enqueue(msg); err != nil {
					log.Printf("[POOL] Enqueue error: %v", err)
					writer.WriteString("451 Queue error\r\n")
				} else {
					writer.WriteString("250 Queued for delayed delivery\r\n")
					atomic.AddInt64(&stats.Recv, 1)
				}
			} else {
				go sendMessage(msg)
				writer.WriteString("250 OK\r\n")
				atomic.AddInt64(&stats.Recv, 1)
			}

			from = ""
			recipients = nil
			data.Reset()

		case "QUIT":
			writer.WriteString("221 Bye\r\n")
			writer.Flush()
			return

		default:
			writer.WriteString("500 Unknown command\r\n")
		}

		writer.Flush()
	}
}

func extractEmail(line string) string {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start >= 0 && end > start {
		return line[start+1 : end]
	}
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}

func generateMessageID() string {
	return fmt.Sprintf("%s@fog", secureRandHex(16))
}

// ============================================================================
// MESSAGE SENDING
// ============================================================================

func sendMessage(msg *Message) {
	if enableSphinx {
		sendViaSphinx(msg)
	} else {
		sendDirect(msg)
	}
}

func sendViaSphinx(msg *Message) {
	path, err := pki.RandomPath(SphinxHops)
	if err != nil {
		log.Printf("[SPHINX] Path error: %v", err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	packet, err := buildSphinxPacket(path, msg.Data)
	if err != nil {
		log.Printf("[SPHINX] Build error: %v", err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	time.Sleep(secureRandDelay(MinDelay, MaxDelay))

	batch.Add(packet)
	atomic.AddInt64(&stats.Sphinx, 1)

	if debug {
		log.Printf("[SPHINX] Queued %s via %s → %s → %s",
			msg.ID, path[0].Name, path[1].Name, path[2].Name)
	}
}

func forwardSphinxPacket(packet *SphinxPacket) {
	info, payload, err := processSphinxPacket(packet)
	if err != nil {
		log.Printf("[SPHINX] Process error: %v", err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	if info.IsExit {
		// Sanitize headers before delivery
		sanitizedPayload := sanitizeHeaders(payload)
		
		for _, to := range extractRecipients(sanitizedPayload) {
			if err := deliverSMTP(to, sanitizedPayload); err != nil {
				log.Printf("[SPHINX] Delivery failed %s: %v", to, err)
				atomic.AddInt64(&stats.Failed, 1)
			} else {
				if debug {
					log.Printf("[SPHINX] Delivered to %s", to)
				}
				atomic.AddInt64(&stats.Sent, 1)
			}
		}
	} else {
		forwardToNode(info.NextHop, payload)
	}
}

func sendDirect(msg *Message) {
	for _, to := range msg.To {
		if err := deliverSMTP(to, msg.Data); err != nil {
			log.Printf("[DIRECT] Delivery failed %s: %v", to, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			if debug {
				log.Printf("[DIRECT] Delivered to %s", to)
			}
			atomic.AddInt64(&stats.Sent, 1)
		}
	}
	atomic.AddInt64(&stats.Direct, 1)
}

func deliverSMTP(to string, data []byte) error {
	parts := strings.SplitN(to, "@", 2)
	if len(parts) != 2 {
		return errors.New("invalid recipient")
	}
	domain := parts[1]

	host := domain + ":25"

	var conn net.Conn
	var err error

	if strings.HasSuffix(domain, ".onion") {
		dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
		if err != nil {
			return err
		}
		conn, err = dialer.Dial("tcp", host)
	} else {
		conn, err = net.DialTimeout("tcp", host, 30*time.Second)
	}

	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, domain)
	if err != nil {
		return err
	}
	defer client.Quit()

	if err := client.Mail("fog@anonymous.invalid"); err != nil {
		return err
	}
	if err := client.Rcpt(to); err != nil {
		return err
	}

	w, err := client.Data()
	if err != nil {
		return err
	}
	defer w.Close()

	_, err = w.Write(data)
	return err
}

func extractRecipients(data []byte) []string {
	lines := bytes.Split(data, []byte("\r\n"))
	for _, line := range lines {
		if bytes.HasPrefix(bytes.ToLower(line), []byte("to:")) {
			addr := strings.TrimSpace(string(line[3:]))
			return []string{addr}
		}
	}
	return []string{}
}

// ============================================================================
// SPHINX NODE SERVER
// ============================================================================

func sphinxNodeServer(addr string) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()

	log.Printf("[NODE] Listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleSphinxNode(conn)
	}
}

func handleSphinxNode(conn net.Conn) {
	defer conn.Close()

	var packet SphinxPacket
	if err := json.NewDecoder(conn).Decode(&packet); err != nil {
		return
	}

	atomic.AddInt64(&stats.MixRecv, 1)

	batch.Add(&packet)
}

func forwardToNode(addr string, payload []byte) {
	dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
	if err != nil {
		return
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return
	}
	defer conn.Close()

	conn.Write(payload)
}

// ============================================================================
// HEALTH CHECKER
// ============================================================================

func healthChecker() {
	ticker := time.NewTicker(HealthInterval)
	defer ticker.Stop()

	for range ticker.C {
		healthy := pki.GetHealthy()
		log.Printf("[HEALTH] Checking %d nodes", len(pki.Nodes)-1)

		for _, node := range pki.Nodes {
			if node.ID == localNode.ID {
				continue
			}

			go func(n *Node) {
				if checkNode(n.Address) {
					pki.mu.Lock()
					n.Healthy = true
					n.LastOK = time.Now()
					pki.mu.Unlock()
					
					if debug {
						log.Printf("[HEALTH] %s OK", n.Name)
					}
				} else {
					pki.mu.Lock()
					n.Healthy = false
					pki.mu.Unlock()
					
					log.Printf("[HEALTH] %s FAILED", n.Name)
				}
			}(node)
		}

		time.Sleep(5 * time.Second)
		healthy = pki.GetHealthy()
		log.Printf("[HEALTH] Done. %d nodes healthy", len(healthy))
	}
}

func checkNode(addr string) bool {
	dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
	if err != nil {
		return false
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ============================================================================
// DELAY POOL SCHEDULER
// ============================================================================

func delayPoolScheduler() {
	ticker := time.NewTicker(PoolInterval)
	defer ticker.Stop()

	log.Printf("[POOL] Scheduler started (check every %v)", PoolInterval)

	for range ticker.C {
		messages, err := delayPool.GetReady()
		if err != nil {
			log.Printf("[POOL] GetReady error: %v", err)
			continue
		}

		if len(messages) == 0 {
			continue
		}

		log.Printf("[POOL] Processing %d ready messages", len(messages))

		for _, qmsg := range messages {
			go func(m *QueuedMessage) {
				msg := &Message{
					ID:   m.ID,
					From: m.From,
					To:   []string{m.To},
					Data: m.Data,
					Time: m.EnqueueTime,
				}

				sendMessage(msg)

				if err := delayPool.Delete(m.ID); err != nil {
					log.Printf("[POOL] Delete error: %v", err)
				} else {
					if debug {
						waited := time.Since(m.EnqueueTime)
						log.Printf("[POOL] Sent %s after %v delay", m.ID, waited.Round(time.Second))
					}
				}
			}(qmsg)
		}
	}
}

// ============================================================================
// STATS REPORTER
// ============================================================================

func statsReporter() {
	ticker := time.NewTicker(StatsInterval)
	defer ticker.Stop()

	for range ticker.C {
		uptime := time.Since(stats.Start)
		healthy := len(pki.GetHealthy())
		
		var queued int64
		if enableDelay {
			queued = atomic.LoadInt64(&stats.Queued)
		}

		log.Printf("[STATS] Up:%v R:%d S:%d F:%d | Sphinx:%d Direct:%d | Mix R:%d F:%d | Q:%d D:%d | Healthy:%d",
			uptime.Round(time.Second),
			atomic.LoadInt64(&stats.Recv),
			atomic.LoadInt64(&stats.Sent),
			atomic.LoadInt64(&stats.Failed),
			atomic.LoadInt64(&stats.Sphinx),
			atomic.LoadInt64(&stats.Direct),
			atomic.LoadInt64(&stats.MixRecv),
			atomic.LoadInt64(&stats.MixFwd),
			queued,
			atomic.LoadInt64(&stats.Delayed),
			healthy,
		)
	}
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	var (
		name         = flag.String("name", "", "Node address (.onion:port)")
		shortName    = flag.String("short-name", "", "Short name for logs")
		smtpAddr     = flag.String("smtp", "127.0.0.1:"+DefaultPort, "SMTP listen address")
		nodeAddr     = flag.String("node", "127.0.0.1:"+NodePort, "Sphinx node address")
		pkiFile      = flag.String("pki-file", "", "PKI nodes.json file")
		dataDir      = flag.String("data-dir", "fog-data", "Data directory")
		
		minPoolDelay = flag.Duration("min-delay", DefaultMinPoolDelay, "Minimum delay pool time")
		maxPoolDelay = flag.Duration("max-delay", DefaultMaxPoolDelay, "Maximum delay pool time")
		delayStrat   = flag.String("delay-strategy", "exponential", "Delay strategy: exponential, constant, poisson")
		
		sphinx       = flag.Bool("sphinx", false, "Enable Sphinx routing")
		delay        = flag.Bool("delay", false, "Enable delay pool")
		showDebug    = flag.Bool("debug", false, "Debug logging")
		exportNode   = flag.Bool("export-node-info", false, "Export node info and exit")
	)
	
	flag.Parse()

	enableSphinx = *sphinx
	enableDelay = *delay
	debug = *showDebug

	if *name == "" {
		log.Fatal("Error: -name required")
	}

	if *shortName == "" {
		log.Fatal("Error: -short-name required")
	}

	if err := localNode.Init(*name, *shortName); err != nil {
		log.Fatal(err)
	}

	if *exportNode {
		if err := localNode.ExportInfo(*name, *shortName); err != nil {
			log.Fatal(err)
		}
		log.Printf("[EXPORT] Written to nodes.json")
		return
	}

	os.MkdirAll(*dataDir, 0700)

	if enableDelay {
		strategy := parseDelayStrategy(*delayStrat)
		dbPath := filepath.Join(*dataDir, "messages.db")
		
		var err error
		delayPool, err = NewDelayPool(dbPath, *minPoolDelay, *maxPoolDelay, strategy)
		if err != nil {
			log.Fatalf("[POOL] Init error: %v", err)
		}
		defer delayPool.Close()
		
		log.Printf("[POOL] Enabled: min=%v max=%v strategy=%s", 
			*minPoolDelay, *maxPoolDelay, strategy)
		
		go delayPoolScheduler()
	}

	if enableSphinx {
		if *pkiFile == "" {
			log.Fatal("Error: -pki-file required with -sphinx")
		}
		
		if err := pki.Load(*pkiFile); err != nil {
			log.Fatal(err)
		}

		go healthChecker()
		go batch.AutoFlush()
		go sphinxNodeServer(*nodeAddr)
	}

	go replayCache.Cleanup()
	go statsReporter()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("[SHUTDOWN] Flushing batch...")
		batch.Flush()
		time.Sleep(2 * time.Second)
		os.Exit(0)
	}()

	smtpServer(*smtpAddr)
}
