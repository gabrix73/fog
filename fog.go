// fog v4.1.0 - Anonymous SMTP Relay with Post-Quantum Sphinx Mixnet
// v4.1.0: BUG FIXES AND SECURITY HARDENING
//   - Fixed: SMTP envelope now embedded in Sphinx payload
//   - Fixed: DNS MX lookup through Tor (no DNS leak)
//   - Fixed: Multi-recipient delivery
//   - Fixed: Exit node header sanitization restored
//   - Fixed: ESMTP capabilities (8BITMIME, SMTPUTF8, SIZE)
//   - Fixed: MIME-safe line handling (no TrimSpace corruption)
//   - Fixed: Direct relay fallback when Sphinx unavailable
//   - Fixed: Kyber key size validation in PKI
// v4.0.0: POST-QUANTUM CRYPTOGRAPHY
//   - Kyber-768 key encapsulation (quantum-resistant)
//   - Replaced Curve25519 with Kyber KEM
//   - New packet format for larger PQ keys
// Previous versions used classical cryptography (Curve25519)
// Features:
//   - PKI Gossip: fully decentralized node discovery
//   - Threshold Batching: pool mixing with configurable threshold
//   - Realistic Cover Traffic: low volume, irregular timing
//   - Forward secrecy with ephemeral Kyber keys per hop
// Copyright 2025-2026 - fog Project

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

	kyberk2so "github.com/symbolicsoft/kyber-k2so"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/proxy"
)

const (
	Version = "4.1.0"

	TorSocks    = "127.0.0.1:9050"
	DefaultSMTP = "127.0.0.1:2525"
	DefaultNode = "127.0.0.1:9999"

	// Timing
	HealthInterval = 3 * time.Minute
	GossipInterval = 5 * time.Minute
	StatsInterval  = 60 * time.Second

	// Threshold Batching
	BatchThresholdMin = 5
	BatchThresholdMax = 15
	BatchTimeout      = 5 * time.Minute

	// Cover Traffic - realistic small server pattern
	CoverMinInterval = 30 * time.Minute
	CoverMaxInterval = 4 * time.Hour
	CoverMaxPerHour  = 3
	CoverBurstChance = 0.1

	// Kyber-768 sizes
	KyberPKSize = 1184
	KyberSKSize = 2400
	KyberCTSize = 1088
	KyberSSSize = 32

	// Sphinx with Kyber
	MinHops    = 3
	MaxHops    = 6
	HeaderSize = 1232 // 1088 (Kyber CT) + 128 (routing) + 16 (MAC)
	PayloadMax = 64 * 1024

	// Limits
	MaxMsgSize = 10 << 20
	QueueSize  = 500
	Workers    = 3
	CacheSize  = 10000
	CacheTTL   = 24 * time.Hour
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

// EnvelopeWrapper embeds SMTP envelope inside Sphinx payload
// so exit node can deliver using the original MAIL FROM/RCPT TO
type EnvelopeWrapper struct {
	From string   `json:"f"`
	To   []string `json:"t"`
	Data []byte   `json:"d"`
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
	pkiFile      string // Bootstrap PKI (read-only, never overwritten)
	pkiStateFile string // Dynamic state (read-write, gossip discoveries)
	keyFile  string

	pki    *PKI
	pool   *BatchPool
	replay *ReplayCache
	queue  chan *Message
	stats  *Stats
	cover  *CoverTraffic

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

	// v4.1.0: Enforce Kyber-768 key size (1184 bytes)
	if len(n.PublicKey) != KyberPKSize {
		if debugMode {
			log.Printf("[PKI] Rejected node %s: invalid key size %d (need %d)",
				n.Name, len(n.PublicKey), KyberPKSize)
		}
		return
	}

	existing, ok := p.nodes[n.ID]
	if !ok || n.LastSeen.After(existing.LastSeen) {
		p.nodes[n.ID] = n
		if debugMode {
			idStr := n.ID
			if len(idStr) > 16 {
				idStr = idStr[:16]
			}
			log.Printf("[PKI] Added/updated node %s (%s)", n.Name, idStr)
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

// CleanupDuplicates removes duplicate nodes with same address or name
func (p *PKI) CleanupDuplicates() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	byAddress := make(map[string][]*Node)
	for _, n := range p.nodes {
		byAddress[n.Address] = append(byAddress[n.Address], n)
	}

	removed := 0
	for addr, nodes := range byAddress {
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
					nID := n.ID
					if len(nID) > 16 {
						nID = nID[:16]
					}
					log.Printf("[PKI] Removed duplicate node %s (addr: %s)", nID, addr)
				}
			}
		}
	}

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
					nID := n.ID
					if len(nID) > 16 {
						nID = nID[:16]
					}
					log.Printf("[PKI] Removed duplicate node %s (name: %s)", nID, name)
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

	loaded := 0
	skipped := 0
	for id, n := range nodes {
		n.ID = id
		// v4.1.0: Validate Kyber key size on load
		if len(n.PublicKey) != KyberPKSize {
			log.Printf("[PKI] Skipping node %s: key size %d (need %d)", n.Name, len(n.PublicKey), KyberPKSize)
			skipped++
			continue
		}
		p.nodes[id] = n
		loaded++
	}

	log.Printf("[PKI] Loaded %d nodes from %s (skipped %d invalid)", loaded, path, skipped)
	return nil
}

// SaveState saves dynamic PKI state to a SEPARATE file (never overwrites bootstrap)
func (p *PKI) SaveState(path string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := json.MarshalIndent(p.nodes, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (p *PKI) ExportForGossip() []byte {
	p.mu.RLock()
	defer p.mu.RUnlock()
	data, _ := json.Marshal(p.nodes)
	return data
}

func (p *PKI) MergeFromGossip(data []byte) int {
	var received map[string]*Node
	if err := json.Unmarshal(data, &received); err != nil {
		return 0
	}

	added := 0
	p.mu.Lock()

	for id, n := range received {
		if id == local.ID {
			continue
		}
		n.ID = id

		// v4.1.0: Validate Kyber key size from gossip
		if len(n.PublicKey) != KyberPKSize {
			if debugMode {
				log.Printf("[GOSSIP] Rejected node %s: invalid key size %d", n.Name, len(n.PublicKey))
			}
			continue
		}

		existing, ok := p.nodes[id]
		if !ok {
			p.nodes[id] = n
			added++
			idStr := id
			if len(idStr) > 16 {
				idStr = idStr[:16]
			}
			log.Printf("[GOSSIP] Discovered new node: %s (%s)", n.Name, idStr)
		} else if n.LastSeen.After(existing.LastSeen) {
			p.nodes[id] = n
		}
	}

	p.mu.Unlock()
	p.CleanupDuplicates()

	return added
}

// =============================================================================
// GOSSIP PROTOCOL
// =============================================================================

func gossipWorker() {
	defer wg.Done()

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

	fmt.Fprintf(conn, "GOSSIP %d\r\n", len(myData))
	conn.Write(myData)
	conn.Write([]byte("\r\n"))

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

	if len(b.packets) >= b.threshold {
		return true
	}

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

	result := b.packets
	b.packets = make([]*SphinxPacket, 0)
	b.addedAt = make([]time.Time, 0)

	shufflePackets(result)

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
// COVER TRAFFIC
// =============================================================================

type CoverTraffic struct {
	lastSent     time.Time
	sentThisHour int
	hourStart    time.Time
	mu           sync.Mutex
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

	currentHour := now.Truncate(time.Hour)
	if currentHour.After(c.hourStart) {
		c.sentThisHour = 0
		c.hourStart = currentHour
	}

	if c.sentThisHour >= CoverMaxPerHour {
		return false
	}

	if time.Since(c.lastSent) < CoverMinInterval {
		return false
	}

	elapsed := time.Since(c.lastSent)
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

	initialDelay := time.Duration(60+cryptoRandInt(540)) * time.Second
	select {
	case <-ctx.Done():
		return
	case <-time.After(initialDelay):
	}

	for {
		interval := time.Duration(5+cryptoRandInt(10)) * time.Minute
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			if cover.shouldSend() {
				sendCoverMessage()

				if cover.shouldBurst() {
					burstCount := 1 + cryptoRandInt(2)
					for i := 0; i < burstCount; i++ {
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

	size := 500 + cryptoRandInt(2000)
	dummy := make([]byte, size)
	rand.Read(dummy)

	hopCount := MinHops + cryptoRandInt(MaxHops-MinHops+1)
	route := selectRoute(healthy, hopCount)
	if route == nil {
		return
	}

	packet := createSphinxPacket(dummy, route, true)
	if packet == nil {
		return
	}

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
	privKey, pubKey, err := kyberk2so.KemKeypair768()
	if err != nil {
		log.Printf("[CRYPTO] Failed to generate Kyber keypair: %v", err)
		return nil, nil
	}
	return pubKey[:], privKey[:]
}

func kyberEncapsulate(pubKey []byte) (ciphertext, sharedSecret []byte, err error) {
	if len(pubKey) != KyberPKSize {
		return nil, nil, fmt.Errorf("invalid public key size: %d (need %d)", len(pubKey), KyberPKSize)
	}
	var pk [1184]byte
	copy(pk[:], pubKey)
	ct, ss, err := kyberk2so.KemEncrypt768(pk)
	if err != nil {
		return nil, nil, err
	}
	return ct[:], ss[:], nil
}

func kyberDecapsulate(ciphertext, privKey []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != KyberCTSize {
		return nil, fmt.Errorf("invalid ciphertext size: %d", len(ciphertext))
	}
	if len(privKey) != KyberSKSize {
		return nil, fmt.Errorf("invalid private key size: %d", len(privKey))
	}
	var ct [1088]byte
	var sk [2400]byte
	copy(ct[:], ciphertext)
	copy(sk[:], privKey)
	ss, err := kyberk2so.KemDecrypt768(ct, sk)
	if err != nil {
		return nil, err
	}
	return ss[:], nil
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

	padded := padPayload(payload)

	type hopInfo struct {
		ciphertext []byte
		encKey     []byte
		macKey     []byte
	}

	hops := make([]hopInfo, len(route))

	for i := 0; i < len(route); i++ {
		node := route[i]

		ciphertext, sharedSecret, err := kyberEncapsulate(node.PublicKey)
		if err != nil {
			log.Printf("[SPHINX-CREATE] Kyber encapsulation failed for hop %d: %v", i, err)
			return nil
		}

		encKey, macKey := deriveKeys(sharedSecret)

		hops[i] = hopInfo{
			ciphertext: ciphertext,
			encKey:     encKey,
			macKey:     macKey,
		}

		if debugMode {
			log.Printf("[SPHINX-CREATE] Hop %d (%s): ct=%s secret=%s",
				i, node.Name,
				base64.StdEncoding.EncodeToString(ciphertext)[:16],
				base64.StdEncoding.EncodeToString(sharedSecret)[:16])
		}
	}

	// Build layers from exit to entry (reverse order)
	currentPayload := padded

	for i := len(route) - 1; i >= 0; i-- {
		hop := hops[i]

		encrypted, err := aesEncrypt(hop.encKey, currentPayload)
		if err != nil {
			return nil
		}

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

		mac := computeMAC(hop.macKey, routingPadded)

		header := make([]byte, 0, HeaderSize)
		header = append(header, hop.ciphertext...)
		header = append(header, routingPadded...)
		header = append(header, mac[:16]...)

		currentPayload = append(header, encrypted...)

		if debugMode {
			log.Printf("[SPHINX-CREATE] Layer %d: header=%d encrypted=%d total=%d",
				i, len(header), len(encrypted), len(currentPayload))
		}
	}

	return &SphinxPacket{
		Header:  currentPayload[:HeaderSize],
		Payload: currentPayload[HeaderSize:],
	}
}

func processSphinxPacket(packet *SphinxPacket) {
	if len(packet.Header) < HeaderSize {
		log.Printf("[SPHINX] Header too short: %d bytes (need %d)", len(packet.Header), HeaderSize)
		return
	}

	ciphertext := packet.Header[:KyberCTSize]

	secret, err := kyberDecapsulate(ciphertext, local.Private)
	if err != nil {
		log.Printf("[SPHINX] Kyber decapsulation failed: %v", err)
		return
	}
	encKey, macKey := deriveKeys(secret)

	routingInfo := packet.Header[KyberCTSize : KyberCTSize+128]
	receivedMAC := packet.Header[KyberCTSize+128 : HeaderSize]

	if debugMode {
		log.Printf("[SPHINX-RECV] ct=%s secret=%s",
			base64.StdEncoding.EncodeToString(ciphertext)[:16],
			base64.StdEncoding.EncodeToString(secret)[:16])
	}

	if !verifyMAC(macKey, routingInfo, receivedMAC) {
		log.Printf("[SPHINX] MAC verification failed")
		return
	}

	decrypted, err := aesDecrypt(encKey, packet.Payload)
	if err != nil {
		log.Printf("[SPHINX] Decryption failed: %v", err)
		return
	}

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

	// Forward to next hop
	if len(decrypted) > HeaderSize {
		nextPacket := &SphinxPacket{
			Header:  decrypted[:HeaderSize],
			Payload: decrypted[HeaderSize:],
		}

		node := pki.Get(findNodeByAddress(nextHopAddr))
		if node != nil {
			delay := time.Duration(500+cryptoRandInt(2000)) * time.Millisecond
			time.Sleep(delay)

			maxRetries := 3
			var lastErr error
			for attempt := 1; attempt <= maxRetries; attempt++ {
				if err := sendToNode(node, nextPacket); err != nil {
					lastErr = err
					if attempt < maxRetries {
						backoff := time.Duration(1<<attempt) * time.Second
						if debugMode {
							log.Printf("[SPHINX] Forward attempt %d failed: %v, retrying in %v", attempt, err, backoff)
						}
						time.Sleep(backoff)
					}
				} else {
					if debugMode {
						log.Printf("[SPHINX] Forwarded to %s (attempt %d)", nextHopAddr, attempt)
					}
					lastErr = nil
					break
				}
			}
			if lastErr != nil {
				log.Printf("[SPHINX] Forward failed after %d attempts: %v", maxRetries, lastErr)
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

	data := append(packet.Header, packet.Payload...)
	fmt.Fprintf(conn, "SPHINX %d\r\n", len(data))
	conn.Write(data)
	conn.Write([]byte("\r\n"))

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

// =============================================================================
// EXIT NODE: DELIVERY WITH ENVELOPE AND HEADER SANITIZATION
// =============================================================================

func deliverMessage(padded []byte) {
	data, err := unpadPayload(padded)
	if err != nil {
		log.Printf("[EXIT] Unpad failed: %v", err)
		return
	}

	// v4.1.0: Try to unwrap envelope first
	var envelope EnvelopeWrapper
	if err := json.Unmarshal(data, &envelope); err == nil && len(envelope.To) > 0 && len(envelope.Data) > 0 {
		// Successfully unwrapped envelope
		sanitized := sanitizeHeaders(envelope.Data)

		for _, rcpt := range envelope.To {
			msg := &Message{
				From: envelope.From,
				To:   []string{rcpt},
				Data: sanitized,
			}
			if err := deliverToRecipient(msg); err != nil {
				log.Printf("[EXIT] Delivery failed to %s: %v", rcpt, err)
				atomic.AddInt64(&stats.Failed, 1)
			} else {
				atomic.AddInt64(&stats.Delivered, 1)
				log.Printf("[EXIT] Delivered to %s", rcpt)
			}
		}
		return
	}

	// Fallback: parse raw message (backward compatibility)
	msg := parseMessage(data)
	if msg == nil || len(msg.To) == 0 {
		log.Printf("[EXIT] Parse failed - no recipients found")
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	msg.Data = sanitizeHeaders(msg.Data)

	for _, rcpt := range msg.To {
		singleMsg := &Message{
			From: msg.From,
			To:   []string{rcpt},
			Data: msg.Data,
		}
		if err := deliverToRecipient(singleMsg); err != nil {
			log.Printf("[EXIT] Delivery failed to %s: %v", rcpt, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			atomic.AddInt64(&stats.Delivered, 1)
			log.Printf("[EXIT] Delivered to %s", rcpt)
		}
	}
}

// sanitizeHeaders removes identifying headers at exit node
func sanitizeHeaders(data []byte) []byte {
	// Normalize line endings: support \r\n, \n, or mixed
	normalized := strings.ReplaceAll(string(data), "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	var headers []string
	var body []string
	inHeaders := true
	fromFound := false
	headerEndIdx := -1

	for i, line := range lines {
		if inHeaders && line == "" {
			headerEndIdx = i
			inHeaders = false
			continue
		}

		if inHeaders {
			lower := strings.ToLower(line)

			// Strip identifying headers
			if strings.HasPrefix(lower, "x-") ||
				strings.HasPrefix(lower, "received:") ||
				strings.HasPrefix(lower, "reply-to:") ||
				strings.HasPrefix(lower, "user-agent:") ||
				strings.HasPrefix(lower, "x-mailer:") {
				continue
			}

			// Replace From with anonymous
			if strings.HasPrefix(lower, "from:") {
				headers = append(headers, fmt.Sprintf("From: Anonymous <anonymous@%s.fog>", local.Name))
				fromFound = true
				continue
			}

			// Replace Date with randomized
			if strings.HasPrefix(lower, "date:") {
				continue // Will inject our own below
			}

			// Replace Message-ID with random
			if strings.HasPrefix(lower, "message-id:") {
				continue // Will inject our own below
			}

			// Keep all other headers: Subject, To, Content-Type, MIME-Version,
			// Newsgroups, References, In-Reply-To, Content-Transfer-Encoding
			headers = append(headers, line)
		} else {
			body = append(body, line)
		}
	}

	// Inject required headers if missing or replaced
	if !fromFound {
		headers = append(headers, fmt.Sprintf("From: Anonymous <anonymous@%s.fog>", local.Name))
	}

	// Always inject sanitized Date (randomized ±1-2 hours)
	offset := time.Duration(cryptoRandInt(7200)-3600) * time.Second
	headers = append(headers, fmt.Sprintf("Date: %s",
		time.Now().Add(offset).UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000")))

	// Always inject random Message-ID
	headers = append(headers, fmt.Sprintf("Message-ID: <%s@%s.fog>",
		hex.EncodeToString(cryptoRandBytes(12)), local.Name))

	// If no header/body separator was found, treat entire input as body
	if headerEndIdx == -1 {
		log.Printf("[SANITIZE] Warning: no header/body separator found, treating as headerless message")
		body = lines
	}

	// Rebuild message: headers + empty line + body
	var result bytes.Buffer
	for _, h := range headers {
		result.WriteString(h)
		result.WriteString("\r\n")
	}
	result.WriteString("\r\n") // Empty line separator
	for i, b := range body {
		result.WriteString(b)
		if i < len(body)-1 {
			result.WriteString("\r\n")
		}
	}

	return result.Bytes()
}

// deliverToRecipient delivers a single message to a single recipient
func deliverToRecipient(msg *Message) error {
	if len(msg.To) == 0 {
		return errors.New("no recipient")
	}

	rcpt := msg.To[0]
	parts := strings.Split(rcpt, "@")
	if len(parts) != 2 {
		return fmt.Errorf("invalid recipient: %s", rcpt)
	}
	domain := parts[1]

	var smtpAddr string
	if strings.HasSuffix(domain, ".onion") {
		smtpAddr = domain + ":25"
	} else {
		// v4.1.0: Resolve MX through Tor (no DNS leak)
		mxHost, err := lookupMXViaTor(domain)
		if err != nil {
			if debugMode {
				log.Printf("[EXIT] MX lookup via Tor failed for %s: %v, using domain directly", domain, err)
			}
			smtpAddr = domain + ":25"
		} else {
			smtpAddr = mxHost + ":25"
		}
	}

	conn, err := dialTor(smtpAddr)
	if err != nil {
		return fmt.Errorf("connect to %s: %v", smtpAddr, err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, domain)
	if err != nil {
		return fmt.Errorf("smtp client: %v", err)
	}
	defer client.Close()

	fromAddr := extractAddress(msg.From)
	if fromAddr == "" {
		fromAddr = fmt.Sprintf("anonymous@%s.fog", local.Name)
	}

	if err := client.Mail(fromAddr); err != nil {
		return fmt.Errorf("MAIL FROM: %v", err)
	}
	if err := client.Rcpt(rcpt); err != nil {
		return fmt.Errorf("RCPT TO: %v", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA: %v", err)
	}

	if _, err := wc.Write(msg.Data); err != nil {
		wc.Close()
		return fmt.Errorf("write data: %v", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("end data: %v", err)
	}

	return nil
}

// lookupMXViaTor resolves MX records through Tor SOCKS5
// Falls back to direct domain if resolution fails
func lookupMXViaTor(domain string) (string, error) {
	// Tor exit nodes handle DNS resolution internally
	// We connect to a public DNS-over-TCP service through Tor
	conn, err := torDialer.Dial("tcp", "1.1.1.1:53")
	if err != nil {
		// Fallback: let Tor exit node resolve by connecting directly
		return domain, nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Build minimal DNS MX query
	txID := cryptoRandBytes(2)
	query := buildDNSMXQuery(txID, domain)

	// DNS over TCP: 2-byte length prefix
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(query)))
	conn.Write(lenBuf)
	conn.Write(query)

	// Read response length
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return domain, err
	}
	respLen := binary.BigEndian.Uint16(lenBuf)
	if respLen > 4096 {
		return domain, errors.New("DNS response too large")
	}

	resp := make([]byte, respLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return domain, err
	}

	// Parse MX from response
	mx := parseDNSMXResponse(resp)
	if mx != "" {
		return mx, nil
	}

	return domain, nil
}

// buildDNSMXQuery creates a raw DNS query for MX records
func buildDNSMXQuery(txID []byte, domain string) []byte {
	var buf bytes.Buffer

	// Transaction ID
	buf.Write(txID)
	// Flags: standard query, recursion desired
	buf.Write([]byte{0x01, 0x00})
	// Questions: 1
	buf.Write([]byte{0x00, 0x01})
	// Answer, Authority, Additional: 0
	buf.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	// Encode domain name
	parts := strings.Split(domain, ".")
	for _, part := range parts {
		buf.WriteByte(byte(len(part)))
		buf.WriteString(part)
	}
	buf.WriteByte(0x00) // Root label

	// Type: MX (15)
	buf.Write([]byte{0x00, 0x0f})
	// Class: IN (1)
	buf.Write([]byte{0x00, 0x01})

	return buf.Bytes()
}

// parseDNSMXResponse extracts the first MX hostname from a DNS response
func parseDNSMXResponse(resp []byte) string {
	if len(resp) < 12 {
		return ""
	}

	// Skip header (12 bytes)
	offset := 12

	// Skip question section
	qdCount := int(binary.BigEndian.Uint16(resp[4:6]))
	for i := 0; i < qdCount && offset < len(resp); i++ {
		// Skip name
		for offset < len(resp) {
			if resp[offset] == 0 {
				offset++
				break
			}
			if resp[offset]&0xC0 == 0xC0 {
				offset += 2
				break
			}
			offset += int(resp[offset]) + 1
		}
		offset += 4 // Skip type and class
	}

	// Parse answer section
	anCount := int(binary.BigEndian.Uint16(resp[6:8]))
	for i := 0; i < anCount && offset < len(resp); i++ {
		// Skip name (possibly compressed)
		if offset < len(resp) && resp[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(resp) {
				if resp[offset] == 0 {
					offset++
					break
				}
				offset += int(resp[offset]) + 1
			}
		}

		if offset+10 > len(resp) {
			break
		}

		rtype := binary.BigEndian.Uint16(resp[offset : offset+2])
		offset += 2 // Type
		offset += 2 // Class
		offset += 4 // TTL
		rdLen := int(binary.BigEndian.Uint16(resp[offset : offset+2]))
		offset += 2 // RDLENGTH

		if rtype == 15 && rdLen > 2 { // MX record
			offset += 2 // Skip preference
			// Read exchange name
			name := readDNSName(resp, offset)
			if name != "" {
				return name
			}
		}

		offset += rdLen
	}

	return ""
}

// readDNSName reads a DNS name from a response, handling compression
func readDNSName(resp []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool) // Prevent infinite loops from malicious packets

	for offset < len(resp) {
		if visited[offset] {
			break
		}
		visited[offset] = true

		length := int(resp[offset])
		if length == 0 {
			break
		}

		if length&0xC0 == 0xC0 {
			if offset+1 >= len(resp) {
				break
			}
			newOffset := int(binary.BigEndian.Uint16(resp[offset:offset+2]) & 0x3FFF)
			offset = newOffset
			continue
		}

		offset++
		if offset+length > len(resp) {
			break
		}
		parts = append(parts, string(resp[offset:offset+length]))
		offset += length
	}

	return strings.Join(parts, ".")
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

	write(fmt.Sprintf("220 fog/%s ESMTP", Version))

	var from string
	var to []string
	var data bytes.Buffer
	inData := false

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		if inData {
			// v4.1.0: Only trim \r\n, preserve internal whitespace for MIME/PGP integrity
			stripped := strings.TrimRight(line, "\r\n")

			if stripped == "." {
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
					log.Printf("[SMTP] Queued %s from %s to %v (%d bytes)", msg.ID, from, to, len(msg.Data))
				default:
					log.Printf("[SMTP] Queue full, dropping message")
				}

				from = ""
				to = nil
				data.Reset()
			} else {
				// Dot-stuffing (RFC 5321 4.5.2)
				if strings.HasPrefix(stripped, ".") {
					stripped = stripped[1:]
				}
				data.WriteString(stripped + "\r\n")
			}
			continue
		}

		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"):
			// v4.1.0: Proper ESMTP capability advertisement
			write(fmt.Sprintf("250-%s", hostname))
			write("250-8BITMIME")
			write("250-SMTPUTF8")
			write(fmt.Sprintf("250-SIZE %d", MaxMsgSize))
			write("250 PIPELINING")

		case strings.HasPrefix(upper, "HELO"):
			write(fmt.Sprintf("250 %s", hostname))

		case strings.HasPrefix(upper, "MAIL FROM:"):
			from = extractAddress(line[10:])
			write("250 OK")

		case strings.HasPrefix(upper, "RCPT TO:"):
			to = append(to, extractAddress(line[8:]))
			write("250 OK")

		case upper == "DATA":
			if from == "" || len(to) == 0 {
				write("503 Bad sequence")
				continue
			}
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
	// Use LAST '<' to handle nested brackets like <Name <email>>
	if lastStart := strings.LastIndex(s, "<"); lastStart != -1 {
		if end := strings.Index(s[lastStart:], ">"); end != -1 {
			return s[lastStart+1 : lastStart+end]
		}
	}
	if strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">") {
		return s[1 : len(s)-1]
	}
	return s
}

// =============================================================================
// NODE SERVER
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

	// v4.1.0: Wrap SMTP envelope into payload for Sphinx routing
	envelopePayload, err := json.Marshal(&EnvelopeWrapper{
		From: msg.From,
		To:   msg.To,
		Data: msg.Data,
	})
	if err != nil {
		log.Printf("[WORKER %d] Failed to marshal envelope for %s: %v", workerID, msg.ID, err)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	// Check payload size limit
	if len(envelopePayload) > PayloadMax-4 {
		log.Printf("[WORKER %d] Message %s too large for Sphinx (%d bytes), using direct relay",
			workerID, msg.ID, len(envelopePayload))
		if err := directRelay(msg); err != nil {
			log.Printf("[WORKER %d] Direct relay failed for %s: %v", workerID, msg.ID, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			atomic.AddInt64(&stats.DirectRelay, 1)
			log.Printf("[WORKER %d] Direct relayed %s (oversized)", workerID, msg.ID)
		}
		return
	}

	// v4.1.0: Fallback to direct relay if Sphinx unavailable
	if !useSphinx.Load() {
		log.Printf("[WORKER %d] Sphinx disabled, using direct relay for %s", workerID, msg.ID)
		if err := directRelay(msg); err != nil {
			log.Printf("[WORKER %d] Direct relay failed for %s: %v", workerID, msg.ID, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			atomic.AddInt64(&stats.DirectRelay, 1)
			log.Printf("[WORKER %d] Direct relayed %s", workerID, msg.ID)
		}
		return
	}

	healthy := pki.GetHealthy()
	if len(healthy) < MinHops {
		log.Printf("[WORKER %d] Not enough healthy nodes (%d < %d), using direct relay for %s",
			workerID, len(healthy), MinHops, msg.ID)
		if err := directRelay(msg); err != nil {
			log.Printf("[WORKER %d] Direct relay failed for %s: %v", workerID, msg.ID, err)
			atomic.AddInt64(&stats.Failed, 1)
		} else {
			atomic.AddInt64(&stats.DirectRelay, 1)
			log.Printf("[WORKER %d] Direct relayed %s (insufficient nodes)", workerID, msg.ID)
		}
		return
	}

	hopCount := MinHops + cryptoRandInt(MaxHops-MinHops+1)
	if hopCount > len(healthy) {
		hopCount = len(healthy)
	}
	route := selectRoute(healthy, hopCount)
	if route == nil {
		log.Printf("[WORKER %d] Failed to select route for %s", workerID, msg.ID)
		atomic.AddInt64(&stats.Failed, 1)
		return
	}

	// v4.1.0: Use envelope payload instead of raw msg.Data
	packet := createSphinxPacket(envelopePayload, route, false)
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

// v4.1.0: directRelay delivers message directly through Tor (no Sphinx)
func directRelay(msg *Message) error {
	sanitized := sanitizeHeaders(msg.Data)

	for _, rcpt := range msg.To {
		singleMsg := &Message{
			From: msg.From,
			To:   []string{rcpt},
			Data: sanitized,
		}
		if err := deliverToRecipient(singleMsg); err != nil {
			return fmt.Errorf("relay to %s: %v", rcpt, err)
		}
	}
	return nil
}

func parseMessage(data []byte) *Message {
	lines := strings.Split(string(data), "\n")
	msg := &Message{Data: data}

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "from:") {
			msg.From = extractAddress(line[5:])
		} else if strings.HasPrefix(lower, "to:") {
			msg.To = append(msg.To, extractAddress(line[3:]))
		}
	}

	if msg.From == "" {
		msg.From = fmt.Sprintf("anonymous@%s.fog", local.Name)
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
				if len(pub) == KyberPKSize && len(priv) == KyberSKSize && id != "" {
					log.Printf("[NODE] Loaded existing Kyber keypair from %s", keyFile)
				} else if len(pub) == 32 && len(priv) == 32 {
					log.Printf("[NODE] Found old Curve25519 keys, regenerating Kyber keypair")
					pub, priv, id = nil, nil, ""
				} else {
					log.Printf("[NODE] Invalid key sizes (pub=%d priv=%d), regenerating", len(pub), len(priv))
					pub, priv, id = nil, nil, ""
				}
			}
		}
	}

	if pub == nil || priv == nil {
		pub, priv = generateKeyPair()
		id = hex.EncodeToString(computeMAC(pub, []byte("node-id"))[:16])
		log.Printf("[NODE] Generated new Kyber-768 keypair")

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
				if err := os.WriteFile(keyFile, data, 0600); err == nil {
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

	publicAddr := addr
	if hostname != "" && hostname != "fog.onion" {
		port := "9999"
		if _, p, err := net.SplitHostPort(addr); err == nil {
			port = p
		}
		publicAddr = hostname + ":" + port
	}

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
		fmt.Println("  - Forward secrecy (Kyber-768 KEM)")
		fmt.Println("  - SMTP envelope preservation through mixnet")
		fmt.Println("  - Exit node header sanitization")
		fmt.Println("  - DNS MX resolution through Tor")
		fmt.Println("  - ESMTP: 8BITMIME, SMTPUTF8, PIPELINING")
		os.Exit(0)
	}

	debugMode = *debug

	pki = newPKI()
	pool = newBatchPool()
	replay = newReplayCache()
	queue = make(chan *Message, QueueSize)
	stats = &Stats{Start: time.Now()}
	cover = newCoverTraffic()

	hostname = *name
	pkiFile = *pkiFlag
	keyFile = *keyFlag

	if pkiFile != "" {
		// Derive state file path: nodes.json -> nodes_state.json
		pkiStateFile = strings.TrimSuffix(pkiFile, ".json") + "_state.json"

		// Load bootstrap PKI (hand-crafted, never overwritten by fog)
		if err := pki.Load(pkiFile); err != nil {
			log.Printf("[PKI] Bootstrap load failed: %v", err)
		}

		// Merge dynamic state (gossip discoveries from previous runs)
		if data, err := os.ReadFile(pkiStateFile); err == nil {
			added := pki.MergeFromGossip(data)
			if added > 0 {
				log.Printf("[PKI] Merged %d nodes from dynamic state", added)
			}
		}

		removed := pki.CleanupDuplicates()
		if removed > 0 {
			log.Printf("[PKI] Cleaned up %d duplicate nodes", removed)
		}
	}

	initNode(*nodeAddr)

	if *exportInfo {
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

	dialer, err := proxy.SOCKS5("tcp", TorSocks, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("[TOR] Connection failed: %v", err)
	}
	torDialer = dialer

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[FOG] Starting v%s", Version)
	log.Printf("[FOG] Hostname: %s", hostname)
	log.Printf("[FOG] PKI: %d total nodes, %d healthy", len(pki.GetAll()), pki.HealthyCount())

	useSphinx.Store(*sphinx)

	if *sphinx {
		log.Printf("[FOG] Sphinx mode ENABLED")
		log.Printf("[FOG] Batch threshold: %d-%d, Cover: %d-%.0fh interval",
			BatchThresholdMin, BatchThresholdMax,
			int(CoverMinInterval.Minutes()), CoverMaxInterval.Hours())

		// Start node server FIRST (must be ready before health checks)
		wg.Add(1)
		if err := startNodeServer(*nodeAddr); err != nil {
			log.Fatalf("[NODE] Failed: %v", err)
		}

		// Initial health check at startup (don't wait 3 minutes)
		log.Printf("[FOG] Running initial health check...")
		checkAllNodes()
		// Wait for Tor hidden service connections (can take 15-30s each)
		time.Sleep(45 * time.Second)
		healthy := pki.HealthyCount()
		log.Printf("[FOG] Initial health: %d healthy nodes", healthy)
		if healthy < MinHops {
			log.Printf("[FOG] WARNING: only %d healthy nodes (need %d for Sphinx), will use direct relay until more nodes come online", healthy, MinHops)
		}

		wg.Add(1)
		go healthChecker()

		wg.Add(1)
		go batchWorker()

		wg.Add(1)
		go gossipWorker()

		wg.Add(1)
		go coverWorker()
	} else {
		log.Printf("[FOG] Direct relay mode (Sphinx disabled)")
	}

	for i := 0; i < Workers; i++ {
		wg.Add(1)
		go relayWorker(i)
	}

	wg.Add(1)
	go statsMonitor()

	wg.Add(1)
	go cacheCleanupWorker()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sig
		log.Printf("[FOG] Shutdown signal received")
		cancel()
	}()

	if pkiStateFile != "" {
		go func() {
			ticker := time.NewTicker(10 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					pki.SaveState(pkiStateFile)
					return
				case <-ticker.C:
					pki.SaveState(pkiStateFile)
				}
			}
		}()
	}

	if err := startSMTP(*smtpAddr); err != nil {
		log.Fatalf("[SMTP] Failed: %v", err)
	}

	wg.Wait()

	if pkiStateFile != "" {
		pki.SaveState(pkiStateFile)
	}

	log.Printf("[FOG] Shutdown complete")
}
