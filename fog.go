// fog v3.0.4 - Anonymous SMTP Relay with Sphinx Mixnet
// v3.0.4 fixes:
//   - Fixed Sphinx routing: each hop gets independent ephemeral key pair
//   - Removed broken key blinding, using per-hop fresh keys instead
//   - Simplified packet processing
// Previous fixes (v3.0.3):
//   - Attempted key blinding fix (had issues with curve25519 clamping)
// Features:
//   - PKI Gossip: fully decentralized node discovery
//   - Threshold Batching: pool mixing with configurable threshold
//   - Realistic Cover Traffic: low volume, irregular timing
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
	"encoding/hex"
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
	Version = "3.0.8"

	TorSocks    = "127.0.0.1:9050"
	DefaultSMTP = "127.0.0.1:2525"
	DefaultNode = "127.0.0.1:9999"

	// Timing
	HealthInterval = 3 * time.Minute
	GossipInterval = 5 * time.Minute
	StatsInterval  = 60 * time.Second

	// Threshold Batching
	BatchThresholdMin = 5  // Minimum packets before release
	BatchThresholdMax = 15 // Maximum before forced release
	BatchTimeout      = 5 * time.Minute // Max wait time

	// Cover Traffic - realistic small server pattern
	CoverMinInterval  = 30 * time.Minute  // Minimum between cover msgs
	CoverMaxInterval  = 4 * time.Hour     // Maximum between cover msgs
	CoverMaxPerHour   = 3                 // Never exceed this per hour
	CoverBurstChance  = 0.1               // 10% chance of 2-3 msg burst

	// Sphinx
	MinHops    = 3
	MaxHops    = 6
	HeaderSize = 176  // 32 (ephPub) + 128 (routing) + 16 (MAC)
	PayloadMax = 64 * 1024

	// Limits
	MaxMsgSize   = 10 << 20
	QueueSize    = 500
	Workers      = 3
	CacheSize    = 10000
	CacheTTL     = 24 * time.Hour
)

// =============================================================================
// TYPES
// =============================================================================

type Node struct {
	ID        string    `json:"id"`
	PublicKey []byte    `json:"public_key"`
	Address   string    `json:"address"`
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	LastSeen  time.Time `json:"last_seen"`
	Healthy   bool      `json:"healthy"`
}

type LocalNode struct {
	ID      string
	Public  []byte
	Private []byte
	Address string
	Name    string
}

type Message struct {
	ID         string
	From       string
	To         []string
	Data       []byte
	ReceivedAt time.Time
}

type SphinxPacket struct {
	Header  []byte
	Payload []byte
}

type Stats struct {
	Start        time.Time
	Received     int64
	Delivered    int64
	Failed       int64
	SphinxRouted int64
	DirectRelay  int64
	CoverSent    int64
	GossipExch   int64
	mu           sync.Mutex
}

// =============================================================================
// GLOBALS
// =============================================================================

var (
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	torDialer proxy.Dialer

	local    LocalNode
	hostname string
	pkiFile  string
	keyFile  string

	pki      *PKI
	pool     *BatchPool
	replay   *ReplayCache
	queue    chan *Message
	stats    *Stats
	cover    *CoverTraffic

	useSphinx atomic.Bool
	debugMode bool
)

// =============================================================================
// PKI WITH GOSSIP PROTOCOL
// =============================================================================

type PKI struct {
	nodes map[string]*Node
	mu    sync.RWMutex
}

func newPKI() *PKI {
	return &PKI{nodes: make(map[string]*Node)}
}

func (p *PKI) Add(n *Node) {
	p.mu.Lock()
	defer p.mu.Unlock()

	existing, ok := p.nodes[n.ID]
	if !ok || n.LastSeen.After(existing.LastSeen) {
		p.nodes[n.ID] = n
		if debugMode {
			log.Printf("[PKI] Added/updated node %s (%s)", n.Name, n.ID[:16])
		}
	}
}

func (p *PKI) Remove(id string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.nodes, id)
}

func (p *PKI) Get(id string) *Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.nodes[id]
}

func (p *PKI) GetAll() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Node, 0, len(p.nodes))
	for _, n := range p.nodes {
		result = append(result, n)
	}
	return result
}

func (p *PKI) GetHealthy() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Node, 0)
	for _, n := range p.nodes {
		if n.Healthy && n.ID != local.ID {
			result = append(result, n)
		}
	}
	return result
}

func (p *PKI) GetOthers() []*Node {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Node, 0)
	for _, n := range p.nodes {
		if n.ID != local.ID {
			result = append(result, n)
		}
	}
	return result
}

func (p *PKI) HealthyCount() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	count := 0
	for _, n := range p.nodes {
		if n.Healthy && n.ID != local.ID {
			count++
		}
	}
	return count
}

// CleanupDuplicates removes duplicate nodes with same address or name, keeping only the most recent
func (p *PKI) CleanupDuplicates() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Group by address
	byAddress := make(map[string][]*Node)
	for _, n := range p.nodes {
		byAddress[n.Address] = append(byAddress[n.Address], n)
	}

	removed := 0
	for addr, nodes := range byAddress {
		if len(nodes) <= 1 {
			continue
		}

		// Find the one with most recent LastSeen
		var newest *Node
		for _, n := range nodes {
			if newest == nil || n.LastSeen.After(newest.LastSeen) {
				newest = n
			}
		}

		// Remove all others
		for _, n := range nodes {
			if n.ID != newest.ID {
				delete(p.nodes, n.ID)
				removed++
				if debugMode {
					log.Printf("[PKI] Removed duplicate node %s (addr: %s, kept: %s)", n.ID[:16], addr, newest.ID[:16])
				}
			}
		}
	}

	// Also group by name (for .onion hostnames)
	byName := make(map[string][]*Node)
	for _, n := range p.nodes {
		if n.Name != "" {
			byName[n.Name] = append(byName[n.Name], n)
		}
	}

	for name, nodes := range byName {
		if len(nodes) <= 1 {
			continue
		}

		var newest *Node
		for _, n := range nodes {
			if newest == nil || n.LastSeen.After(newest.LastSeen) {
				newest = n
			}
		}

		for _, n := range nodes {
			if n.ID != newest.ID {
				delete(p.nodes, n.ID)
				removed++
				if debugMode {
					log.Printf("[PKI] Removed duplicate node %s (name: %s, kept: %s)", n.ID[:16], name, newest.ID[:16])
				}
			}
		}
	}

	return removed
}

func (p *PKI) SetHealth(id string, healthy bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n, ok := p.nodes[id]; ok {
		n.Healthy = healthy
		n.LastSeen = time.Now()
	}
}

func (p *PKI) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var nodes map[string]*Node
	if err := json.Unmarshal(data, &nodes); err != nil {
		return err
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for id, n := range nodes {
		n.ID = id
		p.nodes[id] = n
	}

	log.Printf("[PKI] Loaded %d nodes from %s", len(nodes), path)
	return nil
}

func (p *PKI) Save(path string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := json.MarshalIndent(p.nodes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// Gossip: export our node list for sharing
func (p *PKI) ExportForGossip() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, _ := json.Marshal(p.nodes)
	return data
}

// Gossip: merge received node list
func (p *PKI) MergeFromGossip(data []byte) int {
	var received map[string]*Node
	if err := json.Unmarshal(data, &received); err != nil {
		return 0
	}

	added := 0
	p.mu.Lock()

	for id, n := range received {
		if id == local.ID {
			continue // Skip ourselves
		}
		n.ID = id
		existing, ok := p.nodes[id]
		if !ok {
			p.nodes[id] = n
			added++
			log.Printf("[GOSSIP] Discovered new node: %s (%s)", n.Name, id[:16])
		} else if n.LastSeen.After(existing.LastSeen) {
			p.nodes[id] = n
		}
	}

	p.mu.Unlock()

	// Cleanup duplicates after merge
	p.CleanupDuplicates()

	return added
}

// =============================================================================
// GOSSIP PROTOCOL
// =============================================================================

func gossipWorker() {
	defer wg.Done()

	// Initial delay to let things settle
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}

	ticker := time.NewTicker(GossipInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			doGossipRound()
		}
	}
}

func doGossipRound() {
	others := pki.GetOthers()
	if len(others) == 0 {
		return
	}

	// Shuffle and pick up to 3 random nodes to gossip with
	shuffleNodes(others)
	count := 3
	if len(others) < count {
		count = len(others)
	}

	myData := pki.ExportForGossip()

	for i := 0; i < count; i++ {
		node := others[i]
		go gossipWith(node, myData)
	}
}

func gossipWith(node *Node, myData []byte) {
	conn, err := dialTor(node.Address)
	if err != nil {
		if debugMode {
			log.Printf("[GOSSIP] Failed to connect to %s: %v", node.Name, err)
		}
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send GOSSIP command
	fmt.Fprintf(conn, "GOSSIP %d\r\n", len(myData))
	conn.Write(myData)
	conn.Write([]byte("\r\n"))

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	if strings.HasPrefix(line, "GOSSIP ") {
		var size int
		fmt.Sscanf(line, "GOSSIP %d", &size)
		if size > 0 && size < 1<<20 {
			data := make([]byte, size)
			io.ReadFull(reader, data)
			added := pki.MergeFromGossip(data)
			if added > 0 {
				atomic.AddInt64(&stats.GossipExch, int64(added))
			}
		}
	}

	if debugMode {
		log.Printf("[GOSSIP] Exchanged with %s", node.Name)
	}
}

// =============================================================================
// THRESHOLD BATCH POOL
// =============================================================================

type BatchPool struct {
	packets   []*SphinxPacket
	addedAt   []time.Time
	mu        sync.Mutex
	threshold int
}

func newBatchPool() *BatchPool {
	// Random threshold between min and max
	threshold := BatchThresholdMin + cryptoRandInt(BatchThresholdMax-BatchThresholdMin+1)
	return &BatchPool{
		packets:   make([]*SphinxPacket, 0),
		addedAt:   make([]time.Time, 0),
		threshold: threshold,
	}
}

func (b *BatchPool) Add(p *SphinxPacket) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.packets = append(b.packets, p)
	b.addedAt = append(b.addedAt, time.Now())
}

func (b *BatchPool) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.packets)
}

func (b *BatchPool) ShouldFlush() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.packets) == 0 {
		return false
	}

	// Flush if threshold reached
	if len(b.packets) >= b.threshold {
		return true
	}

	// Flush if oldest packet exceeded timeout
	if len(b.addedAt) > 0 && time.Since(b.addedAt[0]) > BatchTimeout {
		return true
	}

	return false
}

func (b *BatchPool) Flush() []*SphinxPacket {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.packets) == 0 {
		return nil
	}

	// Take all packets
	result := b.packets
	b.packets = make([]*SphinxPacket, 0)
	b.addedAt = make([]time.Time, 0)

	// Shuffle for unlinkability
	shufflePackets(result)

	// New random threshold for next batch
	b.threshold = BatchThresholdMin + cryptoRandInt(BatchThresholdMax-BatchThresholdMin+1)

	log.Printf("[POOL] Flushing %d packets (next threshold: %d)", len(result), b.threshold)
	return result
}

func batchWorker() {
	defer wg.Done()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pool.ShouldFlush() {
				packets := pool.Flush()
				for _, p := range packets {
					go processSphinxPacket(p)
				}
			}
		}
	}
}

// =============================================================================
// COVER TRAFFIC - REALISTIC SMALL SERVER PATTERN
// =============================================================================

type CoverTraffic struct {
	lastSent    time.Time
	sentThisHour int
	hourStart   time.Time
	mu          sync.Mutex
}

func newCoverTraffic() *CoverTraffic {
	return &CoverTraffic{
		lastSent:  time.Now(),
		hourStart: time.Now().Truncate(time.Hour),
	}
}

func (c *CoverTraffic) shouldSend() bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	// Reset hourly counter
	currentHour := now.Truncate(time.Hour)
	if currentHour.After(c.hourStart) {
		c.sentThisHour = 0
		c.hourStart = currentHour
	}

	// Never exceed max per hour
	if c.sentThisHour >= CoverMaxPerHour {
		return false
	}

	// Check minimum interval
	if time.Since(c.lastSent) < CoverMinInterval {
		return false
	}

	// Random chance based on time since last send
	elapsed := time.Since(c.lastSent)
	
	// Probability increases with time, but stays low
	// At MinInterval: ~5% chance per check
	// At MaxInterval: ~50% chance per check
	maxWait := float64(CoverMaxInterval)
	elapsedF := float64(elapsed)
	probability := 0.05 + 0.45*(elapsedF/maxWait)
	if probability > 0.5 {
		probability = 0.5
	}

	if cryptoRandFloat() < probability {
		c.lastSent = now
		c.sentThisHour++
		return true
	}

	return false
}

func (c *CoverTraffic) shouldBurst() bool {
	return cryptoRandFloat() < CoverBurstChance
}

func coverWorker() {
	defer wg.Done()

	// Random initial delay (1-10 minutes)
	initialDelay := time.Duration(60+cryptoRandInt(540)) * time.Second
	select {
	case <-ctx.Done():
		return
	case <-time.After(initialDelay):
	}

	// Check every 5-15 minutes (random interval each time)
	for {
		interval := time.Duration(5+cryptoRandInt(10)) * time.Minute
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if cover.shouldSend() {
				sendCoverMessage()

				// Possible burst (2-3 messages close together)
				if cover.shouldBurst() {
					burstCount := 1 + cryptoRandInt(2) // 1-2 extra messages
					for i := 0; i < burstCount; i++ {
						// Small delay between burst messages (10-60 seconds)
						burstDelay := time.Duration(10+cryptoRandInt(50)) * time.Second
						select {
						case <-ctx.Done():
							return
						case <-time.After(burstDelay):
							if cover.shouldSend() {
								sendCoverMessage()
							}
						}
					}
				}
			}
		}
	}
}

func sendCoverMessage() {
	healthy := pki.GetHealthy()
	if len(healthy) < MinHops {
		return
	}

	// Create dummy message with realistic size
	size := 500 + cryptoRandInt(2000) // 500-2500 bytes
	dummy := make([]byte, size)
	rand.Read(dummy)

	// Select random route
	hopCount := MinHops + cryptoRandInt(MaxHops-MinHops+1)
	route := selectRoute(healthy, hopCount)
	if route == nil {
		return
	}

	// Create and send Sphinx packet
	packet := createSphinxPacket(dummy, route, true) // isDummy = true
	if packet == nil {
		return
	}

	// Send to first hop
	if err := sendToNode(route[0], packet); err != nil {
		if debugMode {
			log.Printf("[COVER] Failed to send: %v", err)
		}
		return
	}

	atomic.AddInt64(&stats.CoverSent, 1)
	if debugMode {
		log.Printf("[COVER] Sent dummy message via %d hops", hopCount)
	}
}

// =============================================================================
// REPLAY CACHE
// =============================================================================

type ReplayCache struct {
	items map[string]time.Time
	mu    sync.RWMutex
}

func newReplayCache() *ReplayCache {
	return &ReplayCache{items: make(map[string]time.Time)}
}

func (r *ReplayCache) Check(id string) bool {
	r.mu.RLock()
	_, exists := r.items[id]
	r.mu.RUnlock()
	return exists
}

func (r *ReplayCache) Add(id string) {
	r.mu.Lock()
	r.items[id] = time.Now()
	r.mu.Unlock()
}

func (r *ReplayCache) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := time.Now().Add(-CacheTTL)
	for id, t := range r.items {
		if t.Before(cutoff) {
			delete(r.items, id)
		}
	}
}

func cacheCleanupWorker() {
	defer wg.Done()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			replay.Cleanup()
		}
	}
}

// =============================================================================
// CRYPTO HELPERS
// =============================================================================

func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func cryptoRandFloat() float64 {
	var b [8]byte
	rand.Read(b[:])
	return float64(binary.BigEndian.Uint64(b[:])&0x1FFFFFFFFFFFFF) / float64(0x20000000000000)
}

func cryptoRandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func generateKeyPair() (pub, priv []byte) {
	priv = make([]byte, 32)
	rand.Read(priv)
	pub = make([]byte, 32)
	curve25519.ScalarBaseMult((*[32]byte)(pub), (*[32]byte)(priv))
	return
}

func sharedSecret(priv, pub []byte) []byte {
	shared := make([]byte, 32)
	curve25519.ScalarMult((*[32]byte)(shared), (*[32]byte)(priv), (*[32]byte)(pub))
	return shared
}

func deriveKeys(secret []byte) (encKey, macKey []byte) {
	hkdfReader := hkdf.New(sha256.New, secret, nil, []byte("fog-sphinx"))
	encKey = make([]byte, 32)
	macKey = make([]byte, 32)
	io.ReadFull(hkdfReader, encKey)
	io.ReadFull(hkdfReader, macKey)
	return
}

func computeMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func verifyMAC(key, data, expected []byte) bool {
	computed := computeMAC(key, data)
	// Truncate to same length as expected (16 bytes in Sphinx)
	if len(expected) < len(computed) {
		computed = computed[:len(expected)]
	}
	return hmac.Equal(computed, expected)
}

func aesEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := cryptoRandBytes(gcm.NonceSize())
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func aesDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

// =============================================================================
// SPHINX PACKET
// =============================================================================

func selectRoute(healthy []*Node, hopCount int) []*Node {
	if len(healthy) < hopCount {
		return nil
	}

	shuffleNodes(healthy)
	return healthy[:hopCount]
}

func createSphinxPacket(payload []byte, route []*Node, isDummy bool) *SphinxPacket {
	if len(route) == 0 {
		return nil
	}

	// Pad payload to fixed size
	padded := padPayload(payload)

	// Generate independent ephemeral key pairs for each hop
	// Each hop gets its own fresh key pair
	type hopInfo struct {
		ephPub  []byte
		ephPriv []byte
		encKey  []byte
		macKey  []byte
	}
	
	hops := make([]hopInfo, len(route))
	
	for i := 0; i < len(route); i++ {
		// Generate fresh ephemeral key pair for each hop
		ephPub, ephPriv := generateKeyPair()
		node := route[i]

		// Compute shared secret with this node's public key
		secret := sharedSecret(ephPriv, node.PublicKey)
		encKey, macKey := deriveKeys(secret)

		hops[i] = hopInfo{
			ephPub:  ephPub,
			ephPriv: ephPriv,
			encKey:  encKey,
			macKey:  macKey,
		}

		if debugMode {
			log.Printf("[SPHINX-CREATE] Hop %d (%s): ephPub=%s nodePub=%s secret=%s macKey=%s",
				i, node.Name,
				base64.StdEncoding.EncodeToString(ephPub)[:16],
				base64.StdEncoding.EncodeToString(node.PublicKey)[:16],
				base64.StdEncoding.EncodeToString(secret)[:16],
				base64.StdEncoding.EncodeToString(macKey)[:16])
		}
	}

	// Build layers from exit to entry (reverse order)
	// Each layer wraps the previous one
	currentPayload := padded

	for i := len(route) - 1; i >= 0; i-- {
		hop := hops[i]

		// Encrypt the current payload (which includes the next layer's header)
		encrypted, err := aesEncrypt(hop.encKey, currentPayload)
		if err != nil {
			return nil
		}

		// Build routing info - just the next hop address
		var nextHop string
		isExit := (i == len(route)-1)
		if isExit {
			if isDummy {
				nextHop = "DUMMY"
			} else {
				nextHop = "EXIT"
			}
		} else {
			nextHop = route[i+1].Address
		}

		routingPadded := make([]byte, 128)
		copy(routingPadded, []byte(nextHop))

		// MAC over routing info
		mac := computeMAC(hop.macKey, routingPadded)

		// Header = ephemeral pubkey + routing + mac (176 bytes)
		header := make([]byte, 0, 176)
		header = append(header, hop.ephPub...)      // 32 bytes
		header = append(header, routingPadded...)   // 128 bytes
		header = append(header, mac[:16]...)        // 16 bytes

		// New payload = header + encrypted previous payload
		currentPayload = append(header, encrypted...)
		
		if debugMode {
			log.Printf("[SPHINX-CREATE] Layer %d: header=%d encrypted=%d total=%d",
				i, len(header), len(encrypted), len(currentPayload))
		}
	}

	if debugMode {
		log.Printf("[SPHINX-CREATE] Final: Header=%d Payload=%d", 
			len(currentPayload[:HeaderSize]), len(currentPayload[HeaderSize:]))
	}

	return &SphinxPacket{
		Header:  currentPayload[:HeaderSize],
		Payload: currentPayload[HeaderSize:],
	}
}

func processSphinxPacket(packet *SphinxPacket) {
	if len(packet.Header) < 176 {
		log.Printf("[SPHINX] Header too short: %d bytes", len(packet.Header))
		return
	}

	// Extract ephemeral public key
	ephPub := packet.Header[:32]

	// Compute shared secret with our private key
	secret := sharedSecret(local.Private, ephPub)
	encKey, macKey := deriveKeys(secret)

	// Extract and verify routing info
	routingInfo := packet.Header[32:160]
	receivedMAC := packet.Header[160:176]

	if debugMode {
		log.Printf("[SPHINX-RECV] ephPub=%s localPub=%s secret=%s macKey=%s",
			base64.StdEncoding.EncodeToString(ephPub)[:16],
			base64.StdEncoding.EncodeToString(local.Public)[:16],
			base64.StdEncoding.EncodeToString(secret)[:16],
			base64.StdEncoding.EncodeToString(macKey)[:16])
		expectedMAC := computeMAC(macKey, routingInfo)
		log.Printf("[SPHINX-RECV] receivedMAC=%s expectedMAC=%s",
			base64.StdEncoding.EncodeToString(receivedMAC),
			base64.StdEncoding.EncodeToString(expectedMAC[:16]))
		log.Printf("[SPHINX-RECV] Header=%d Payload=%d", len(packet.Header), len(packet.Payload))
	}

	if !verifyMAC(macKey, routingInfo, receivedMAC) {
		log.Printf("[SPHINX] MAC verification failed")
		return
	}

	// Decrypt payload
	if debugMode {
		log.Printf("[SPHINX-RECV] Decrypting payload of %d bytes with encKey=%s",
			len(packet.Payload), base64.StdEncoding.EncodeToString(encKey)[:16])
	}
	decrypted, err := aesDecrypt(encKey, packet.Payload)
	if err != nil {
		log.Printf("[SPHINX] Decryption failed: %v", err)
		return
	}

	// Parse routing info to find next hop
	// Format: "address\0nextEphPub..." or just "EXIT\0..." or "DUMMY\0..."
	nullIdx := bytes.IndexByte(routingInfo, 0)
	var nextHopAddr string
	if nullIdx == -1 {
		nextHopAddr = string(routingInfo)
	} else {
		nextHopAddr = string(routingInfo[:nullIdx])
	}
	nextHopAddr = strings.TrimSpace(nextHopAddr)

	if nextHopAddr == "DUMMY" {
		if debugMode {
			log.Printf("[SPHINX] Discarded dummy message")
		}
		return
	}

	if nextHopAddr == "EXIT" {
		deliverMessage(decrypted)
		return
	}

	// Forward to next hop - decrypted payload contains the complete next packet
	if len(decrypted) > HeaderSize {
		nextPacket := &SphinxPacket{
			Header:  decrypted[:HeaderSize],
			Payload: decrypted[HeaderSize:],
		}

		node := pki.Get(findNodeByAddress(nextHopAddr))
		if node != nil {
			// Add delay before forwarding
			delay := time.Duration(500+cryptoRandInt(2000)) * time.Millisecond
			time.Sleep(delay)

			if err := sendToNode(node, nextPacket); err != nil {
				log.Printf("[SPHINX] Forward failed: %v", err)
			} else if debugMode {
				log.Printf("[SPHINX] Forwarded to %s", nextHopAddr)
			}
		} else {
			log.Printf("[SPHINX] Unknown next hop: %s", nextHopAddr)
		}
	}
}

func findNodeByAddress(addr string) string {
	for _, n := range pki.GetAll() {
		if n.Address == addr {
			return n.ID
		}
	}
	return ""
}

func sendToNode(node *Node, packet *SphinxPacket) error {
	conn, err := dialTor(node.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Send SPHINX command
	data := append(packet.Header, packet.Payload...)
	fmt.Fprintf(conn, "SPHINX %d\r\n", len(data))
	conn.Write(data)
	conn.Write([]byte("\r\n"))

	// Read response
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	if !strings.HasPrefix(line, "OK") {
		return errors.New("node rejected packet")
	}

	return nil
}

func padPayload(data []byte) []byte {
	// Format: [4 bytes length][data][random padding to PayloadMax]
	result := make([]byte, PayloadMax)
	binary.BigEndian.PutUint32(result[:4], uint32(len(data)))
	copy(result[4:], data)
	rand.Read(result[4+len(data):])
	return result
}

func unpadPayload(padded []byte) ([]byte, error) {
	if len(padded) < 4 {
		return nil, errors.New("payload too short")
	}
	length := binary.BigEndian.Uint32(padded[:4])
	if int(length) > len(padded)-4 {
		return nil, errors.New("invalid length")
	}
	return padded[4 : 4+length], nil
}

func deliverMessage(padded []byte) {
	data, err := unpadPayload(padded)
	if err != nil {
		log.Printf("[EXIT] Unpad failed: %v", err)
		return
	}

	// Parse message
	msg := parseMessage(data)
	if msg == nil {
		log.Printf("[EXIT] Parse failed")
		return
	}

	// Deliver via SMTP
	if err := deliverSMTP(msg); err != nil {
		log.Printf("[EXIT] Delivery failed: %v", err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	atomic.AddInt64(&stats.Delivered, 1)
	log.Printf("[EXIT] Delivered to %v", msg.To)
}

// =============================================================================
// SMTP SERVER
// =============================================================================

func startSMTP(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("[SMTP] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			continue
		}
		go handleSMTP(conn)
	}
}

func handleSMTP(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Minute))

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	write := func(s string) {
		writer.WriteString(s + "\r\n")
		writer.Flush()
	}

	write(fmt.Sprintf("220 %s fog/%s", hostname, Version))

	var from string
	var to []string
	var data bytes.Buffer
	inData := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)

		if inData {
			if line == "." {
				inData = false
				write("250 OK queued")

				msg := &Message{
					ID:         hex.EncodeToString(cryptoRandBytes(8)),
					From:       from,
					To:         to,
					Data:       data.Bytes(),
					ReceivedAt: time.Now(),
				}

				select {
				case queue <- msg:
					atomic.AddInt64(&stats.Received, 1)
					log.Printf("[SMTP] Queued %s from %s to %v", msg.ID, from, to)
				default:
					log.Printf("[SMTP] Queue full, dropping message")
				}

				from = ""
				to = nil
				data.Reset()
			} else {
				if strings.HasPrefix(line, ".") {
					line = line[1:]
				}
				data.WriteString(line + "\r\n")
			}
			continue
		}

		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "HELO"), strings.HasPrefix(upper, "EHLO"):
			write(fmt.Sprintf("250 %s", hostname))

		case strings.HasPrefix(upper, "MAIL FROM:"):
			from = extractAddress(line[10:])
			write("250 OK")

		case strings.HasPrefix(upper, "RCPT TO:"):
			to = append(to, extractAddress(line[8:]))
			write("250 OK")

		case upper == "DATA":
			write("354 Start mail input")
			inData = true

		case upper == "QUIT":
			write("221 Bye")
			return

		case upper == "RSET":
			from = ""
			to = nil
			data.Reset()
			write("250 OK")

		case upper == "NOOP":
			write("250 OK")

		default:
			write("500 Unknown command")
		}
	}
}

func extractAddress(s string) string {
	s = strings.TrimSpace(s)
	// Handle "Display Name <email@domain>" format
	if start := strings.Index(s, "<"); start != -1 {
		if end := strings.Index(s, ">"); end > start {
			return s[start+1 : end]
		}
	}
	// Handle "<email@domain>" format
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		return s[1 : len(s)-1]
	}
	return s
}

// =============================================================================
// NODE SERVER (receives Sphinx packets and Gossip)
// =============================================================================

func startNodeServer(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	log.Printf("[NODE] Listening on %s", addr)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			go handleNode(conn)
		}
	}()

	return nil
}

func handleNode(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(60 * time.Second))

	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)

	switch {
	case strings.HasPrefix(line, "SPHINX "):
		var size int
		fmt.Sscanf(line, "SPHINX %d", &size)
		if size > 0 && size < 1<<20 {
			data := make([]byte, size)
			io.ReadFull(reader, data)

			if len(data) > HeaderSize {
				packet := &SphinxPacket{
					Header:  data[:HeaderSize],
					Payload: data[HeaderSize:],
				}
				pool.Add(packet)
				conn.Write([]byte("OK\r\n"))
			}
		}

	case strings.HasPrefix(line, "GOSSIP "):
		var size int
		fmt.Sscanf(line, "GOSSIP %d", &size)
		if size > 0 && size < 1<<20 {
			data := make([]byte, size)
			io.ReadFull(reader, data)
			pki.MergeFromGossip(data)

			// Respond with our node list
			myData := pki.ExportForGossip()
			fmt.Fprintf(conn, "GOSSIP %d\r\n", len(myData))
			conn.Write(myData)
			conn.Write([]byte("\r\n"))
		}

	case line == "PING":
		conn.Write([]byte("PONG\r\n"))

	case line == "INFO":
		info := fmt.Sprintf("fog/%s %s %d nodes\r\n",
			Version, local.Name, pki.HealthyCount())
		conn.Write([]byte(info))
	}
}

// =============================================================================
// RELAY WORKER
// =============================================================================

func relayWorker(id int) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-queue:
			processMessage(msg, id)
		}
	}
}

func processMessage(msg *Message, workerID int) {
	// Check replay
	msgHash := hex.EncodeToString(computeMAC([]byte("replay"), msg.Data)[:16])
	if replay.Check(msgHash) {
		log.Printf("[WORKER %d] Replay detected: %s", workerID, msg.ID)
		return
	}
	replay.Add(msgHash)

	// Random delay
	delay := time.Duration(100+cryptoRandInt(2000)) * time.Millisecond
	time.Sleep(delay)

	// Always use Sphinx routing (no direct relay fallback)
	if !useSphinx.Load() {
		log.Printf("[WORKER %d] Sphinx disabled, cannot route %s", workerID, msg.ID)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	healthy := pki.GetHealthy()
	if len(healthy) < MinHops {
		log.Printf("[WORKER %d] Not enough healthy nodes (%d < %d) for %s",
			workerID, len(healthy), MinHops, msg.ID)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	hopCount := MinHops + cryptoRandInt(MaxHops-MinHops+1)
	route := selectRoute(healthy, hopCount)
	if route == nil {
		log.Printf("[WORKER %d] Failed to select route for %s", workerID, msg.ID)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	packet := createSphinxPacket(msg.Data, route, false)
	if packet == nil {
		log.Printf("[WORKER %d] Failed to create Sphinx packet for %s", workerID, msg.ID)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	if err := sendToNode(route[0], packet); err != nil {
		log.Printf("[WORKER %d] Failed to send to first hop for %s: %v", workerID, msg.ID, err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	atomic.AddInt64(&stats.SphinxRouted, 1)
	log.Printf("[WORKER %d] Sphinx routed %s via %d hops", workerID, msg.ID, hopCount)
}

func directRelay(msg *Message) error {
	for _, rcpt := range msg.To {
		if err := deliverSMTP(&Message{
			From: msg.From,
			To:   []string{rcpt},
			Data: msg.Data,
		}); err != nil {
			return err
		}
	}
	return nil
}

func deliverSMTP(msg *Message) error {
	if len(msg.To) == 0 {
		return errors.New("no recipients")
	}

	rcpt := msg.To[0]
	parts := strings.Split(rcpt, "@")
	if len(parts) != 2 {
		return errors.New("invalid recipient")
	}
	domain := parts[1]

	// Determine SMTP server
	var smtpAddr string
	if strings.HasSuffix(domain, ".onion") {
		smtpAddr = domain + ":25"
	} else {
		mx, err := net.LookupMX(domain)
		if err != nil || len(mx) == 0 {
			smtpAddr = domain + ":25"
		} else {
			smtpAddr = mx[0].Host + ":25"
		}
	}

	// Connect via Tor
	conn, err := dialTor(smtpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, domain)
	if err != nil {
		return err
	}
	defer client.Close()

	// Extract bare email address from From (remove display name if present)
	fromAddr := extractAddress(msg.From)
	if fromAddr == "" {
		fromAddr = msg.From
	}

	if err := client.Mail(fromAddr); err != nil {
		return err
	}
	if err := client.Rcpt(rcpt); err != nil {
		return err
	}

	wc, err := client.Data()
	if err != nil {
		return err
	}

	_, err = wc.Write(msg.Data)
	if err != nil {
		wc.Close()
		return err
	}

	return wc.Close()
}

func parseMessage(data []byte) *Message {
	// Simple parser - extract From and To from headers
	lines := strings.Split(string(data), "\n")
	msg := &Message{Data: data}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			break // End of headers
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "from:") {
			msg.From = extractAddress(line[5:])
		} else if strings.HasPrefix(lower, "to:") {
			msg.To = append(msg.To, extractAddress(line[3:]))
		}
	}

	if msg.From == "" {
		msg.From = "anonymous@fog.local"
	}

	return msg
}

// =============================================================================
// HEALTH CHECKER
// =============================================================================

func healthChecker() {
	defer wg.Done()

	ticker := time.NewTicker(HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkAllNodes()
		}
	}
}

func checkAllNodes() {
	others := pki.GetOthers()
	for _, node := range others {
		go checkNode(node)
	}
}

func checkNode(node *Node) {
	conn, err := dialTor(node.Address)
	if err != nil {
		pki.SetHealth(node.ID, false)
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(15 * time.Second))

	fmt.Fprintf(conn, "PING\r\n")
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "PONG") {
		pki.SetHealth(node.ID, false)
		return
	}

	pki.SetHealth(node.ID, true)
}

// =============================================================================
// STATS
// =============================================================================

func statsMonitor() {
	defer wg.Done()

	ticker := time.NewTicker(StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			uptime := time.Since(stats.Start).Truncate(time.Second)
			log.Printf("[STATS] Up:%v | R:%d D:%d F:%d | Sphinx:%d Direct:%d | Cover:%d Gossip:%d | Pool:%d Nodes:%d",
				uptime,
				atomic.LoadInt64(&stats.Received),
				atomic.LoadInt64(&stats.Delivered),
				atomic.LoadInt64(&stats.Failed),
				atomic.LoadInt64(&stats.SphinxRouted),
				atomic.LoadInt64(&stats.DirectRelay),
				atomic.LoadInt64(&stats.CoverSent),
				atomic.LoadInt64(&stats.GossipExch),
				pool.Size(),
				pki.HealthyCount())
		}
	}
}

// =============================================================================
// HELPERS
// =============================================================================

func dialTor(addr string) (net.Conn, error) {
	return torDialer.Dial("tcp", addr)
}

func shuffleNodes(nodes []*Node) {
	for i := len(nodes) - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		nodes[i], nodes[j] = nodes[j], nodes[i]
	}
}

func shufflePackets(packets []*SphinxPacket) {
	for i := len(packets) - 1; i > 0; i-- {
		j := cryptoRandInt(i + 1)
		packets[i], packets[j] = packets[j], packets[i]
	}
}

func initNode(addr string) {
	var pub, priv []byte
	var id string

	// Try to load existing key
	if keyFile != "" {
		if data, err := os.ReadFile(keyFile); err == nil {
			var saved struct {
				ID      string `json:"id"`
				Public  string `json:"public_key"`
				Private string `json:"private_key"`
			}
			if err := json.Unmarshal(data, &saved); err == nil {
				pub, _ = base64.StdEncoding.DecodeString(saved.Public)
				priv, _ = base64.StdEncoding.DecodeString(saved.Private)
				id = saved.ID
				if len(pub) == 32 && len(priv) == 32 && id != "" {
					log.Printf("[NODE] Loaded existing keypair from %s", keyFile)
				} else {
					pub, priv, id = nil, nil, ""
				}
			}
		}
	}

	// Generate new key if not loaded
	if pub == nil || priv == nil {
		pub, priv = generateKeyPair()
		id = hex.EncodeToString(computeMAC(pub, []byte("node-id"))[:16])
		log.Printf("[NODE] Generated new keypair")

		// Save new key
		if keyFile != "" {
			saved := struct {
				ID      string `json:"id"`
				Public  string `json:"public_key"`
				Private string `json:"private_key"`
			}{
				ID:      id,
				Public:  base64.StdEncoding.EncodeToString(pub),
				Private: base64.StdEncoding.EncodeToString(priv),
			}
			if data, err := json.MarshalIndent(saved, "", "  "); err == nil {
				if err := os.WriteFile(keyFile, data, 0400); err == nil {
					log.Printf("[NODE] Saved keypair to %s", keyFile)
				} else {
					log.Printf("[NODE] Warning: failed to save keypair: %v", err)
				}
			}
		}
	}

	local = LocalNode{
		ID:      id,
		Public:  pub,
		Private: priv,
		Address: addr,
		Name:    hostname,
	}

	// Determine public address for PKI (use hostname, not local bind address)
	publicAddr := addr
	if hostname != "" && hostname != "fog.onion" {
		// Extract port from addr
		port := "9999"
		if _, p, err := net.SplitHostPort(addr); err == nil {
			port = p
		}
		publicAddr = hostname + ":" + port
	}

	// Add ourselves to PKI
	pki.Add(&Node{
		ID:        local.ID,
		PublicKey: local.Public,
		Address:   publicAddr,
		Name:      local.Name,
		Version:   Version,
		LastSeen:  time.Now(),
		Healthy:   true,
	})
}

// =============================================================================
// MAIN
// =============================================================================

func main() {
	smtpAddr := flag.String("smtp", DefaultSMTP, "SMTP listen address")
	nodeAddr := flag.String("node", DefaultNode, "Node listen address")
	name := flag.String("name", "fog.onion", "Server hostname")
	sphinx := flag.Bool("sphinx", false, "Enable Sphinx routing")
	pkiFlag := flag.String("pki", "", "PKI file path")
	keyFlag := flag.String("key", "", "Node key file path (for persistent identity)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	exportInfo := flag.Bool("export-node-info", false, "Export node info and exit")
	version := flag.Bool("version", false, "Show version")

	flag.Parse()

	if *version {
		fmt.Printf("fog v%s\n\n", Version)
		fmt.Println("Features:")
		fmt.Println("  - Sphinx multi-hop routing (3-6 hops)")
		fmt.Println("  - PKI Gossip protocol (fully decentralized)")
		fmt.Println("  - Threshold batch mixing")
		fmt.Println("  - Realistic cover traffic")
		fmt.Println("  - AES-256-GCM encryption")
		fmt.Println("  - Forward secrecy (Curve25519 ECDH)")
		os.Exit(0)
	}

	debugMode = *debug

	// Initialize
	pki = newPKI()
	pool = newBatchPool()
	replay = newReplayCache()
	queue = make(chan *Message, QueueSize)
	stats = &Stats{Start: time.Now()}
	cover = newCoverTraffic()

	hostname = *name
	pkiFile = *pkiFlag
	keyFile = *keyFlag

	// Load PKI first (before initNode, so we know other nodes)
	if pkiFile != "" {
		if err := pki.Load(pkiFile); err != nil {
			log.Printf("[PKI] Load failed: %v", err)
		} else {
			removed := pki.CleanupDuplicates()
			if removed > 0 {
				log.Printf("[PKI] Cleaned up %d duplicate nodes", removed)
			}
		}
	}

	initNode(*nodeAddr)

	if *exportInfo {
		// Need to initialize for export
		hostname = *name
		keyFile = *keyFlag
		pki = newPKI()
		initNode(*nodeAddr)
		
		info := map[string]interface{}{
			"id":         local.ID,
			"public_key": base64.StdEncoding.EncodeToString(local.Public),
			"address":    fmt.Sprintf("%s:9999", *name),
			"name":       *name,
			"version":    Version,
		}
		data, _ := json.MarshalIndent(info, "", "  ")
		fmt.Println(string(data))
		os.Exit(0)
	}

	// Tor
	dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[TOR] Connection failed: %v", err)
	}
	torDialer = dialer

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[FOG] Starting v%s", Version)
	log.Printf("[FOG] Hostname: %s", hostname)

	useSphinx.Store(*sphinx)

	if *sphinx {
		log.Printf("[FOG] Sphinx mode ENABLED")
		log.Printf("[FOG] Batch threshold: %d-%d, Cover: %d-%.0fh interval",
			BatchThresholdMin, BatchThresholdMax,
			int(CoverMinInterval.Minutes()), CoverMaxInterval.Hours())

		log.Printf("[PKI] Loaded %d nodes", len(pki.GetAll()))

		wg.Add(1)
		go healthChecker()

		wg.Add(1)
		if err := startNodeServer(*nodeAddr); err != nil {
			log.Fatalf("[NODE] Failed: %v", err)
		}

		wg.Add(1)
		go batchWorker()

		wg.Add(1)
		go gossipWorker()

		wg.Add(1)
		go coverWorker()
	} else {
		log.Printf("[FOG] Direct relay mode")
	}

	// Workers
	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go relayWorker(i)
	}

	wg.Add(1)
	go statsMonitor()

	wg.Add(1)
	go cacheCleanupWorker()

	// Signals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		log.Printf("[FOG] Shutdown signal received")
		cancel()
	}()

	// Save PKI periodically
	if pkiFile != "" {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					pki.Save(pkiFile)
					return
				case <-ticker.C:
					pki.Save(pkiFile)
				}
			}
		}()
	}

	if err := startSMTP(*smtpAddr); err != nil {
		log.Fatalf("[SMTP] Failed: %v", err)
	}

	wg.Wait()

	if pkiFile != "" {
		pki.Save(pkiFile)
	}

	log.Printf("[FOG] Shutdown complete")
}
