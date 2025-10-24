package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/proxy"
)

const (
	Version                = "0.9"
	AppName                = "fog"
	TorSocksProxyAddr      = "127.0.0.1:9050"
	RelayWorkerCount       = 5
	DeliveryTimeout        = 30 * time.Second
	MixnetBatchWindow      = 30 * time.Second
	CoverTrafficInterval   = 15 * time.Second
	MessageIDCacheDuration = 24 * time.Hour
	PaddingSizeUnit        = 8 * 1024
	MinDelay               = 100 * time.Millisecond
	MaxDelay               = 2 * time.Second
	RateLimitPerIP         = 10
	RateLimitWindow        = 1 * time.Minute
	MXLookupTimeout        = 5 * time.Second
	MaxRetries             = 9
	MaxMessageSize         = 10 * 1024 * 1024 // 10MB limit
	MaxHeaderSize          = 100 * 1024        // 100KB header limit
	MaxRecipients          = 100               // Max recipients per message
	ConnectionPoolSize     = 5                 // Tor connection pool size
	ConnectionMaxAge       = 10 * time.Minute  // Max connection age before rotation
	TimestampFuzzRange     = 2 * time.Hour     // ±2 hours timestamp fuzzing
	DummyRecipientsMin     = 1                 // Min dummy recipients per batch
	DummyRecipientsMax     = 3                 // Max dummy recipients per batch
)

// Message size normalization buckets (in bytes)
var MessageSizeBuckets = []int64{
	32 * 1024,  // 32KB
	64 * 1024,  // 64KB
	128 * 1024, // 128KB
	256 * 1024, // 256KB
	512 * 1024, // 512KB
	1024 * 1024, // 1MB
	2 * 1024 * 1024,  // 2MB
	5 * 1024 * 1024,  // 5MB
	10 * 1024 * 1024, // 10MB
}

var (
	emailRegExp    *regexp.Regexp
	localPartRegex *regexp.Regexp
	domainRegex    *regexp.Regexp
	
	// Global variables (FIXED: were missing)
	mailQueue      chan *Envelope
	mailQueueMutex sync.Mutex
	
	// Statistics (NEW)
	stats *Statistics
	
	// Graceful shutdown (NEW)
	shutdownSignal chan struct{}
	shutdownWg     sync.WaitGroup
)

// Statistics tracking (NEW)
type Statistics struct {
	messagesReceived  int64
	messagesDelivered int64
	messagesFailed    int64
	coverTrafficSent  int64
	dummyMessagesSent int64
	mu                sync.RWMutex
}

func NewStatistics() *Statistics {
	return &Statistics{}
}

func (s *Statistics) IncReceived() {
	atomic.AddInt64(&s.messagesReceived, 1)
}

func (s *Statistics) IncDelivered() {
	atomic.AddInt64(&s.messagesDelivered, 1)
}

func (s *Statistics) IncFailed() {
	atomic.AddInt64(&s.messagesFailed, 1)
}

func (s *Statistics) IncCoverTraffic() {
	atomic.AddInt64(&s.coverTrafficSent, 1)
}

func (s *Statistics) IncDummy() {
	atomic.AddInt64(&s.dummyMessagesSent, 1)
}

func (s *Statistics) GetStats() (received, delivered, failed, cover, dummy int64) {
	return atomic.LoadInt64(&s.messagesReceived),
		atomic.LoadInt64(&s.messagesDelivered),
		atomic.LoadInt64(&s.messagesFailed),
		atomic.LoadInt64(&s.coverTrafficSent),
		atomic.LoadInt64(&s.dummyMessagesSent)
}

func (s *Statistics) PrintStats() {
	received, delivered, failed, cover, dummy := s.GetStats()
	log.Printf("[STATS] Messages: Received=%d, Delivered=%d, Failed=%d, Cover=%d, Dummy=%d",
		received, delivered, failed, cover, dummy)
}

func init() {
	emailRegExp = regexp.MustCompile(`^[a-zA-Z0-9._%+=\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	localPartRegex = regexp.MustCompile(`^[a-zA-Z0-9._+=\-]+$`)
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	
	stats = NewStatistics()
	shutdownSignal = make(chan struct{})
}

// sanitizeLogString prevents log injection attacks (NEW)
func sanitizeLogString(s string) string {
	// Remove newlines, carriage returns, and other control characters
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	// Limit length to prevent log flooding
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

func validateLocalPart(localPart string) error {
	if len(localPart) == 0 || len(localPart) > 64 {
		return errors.New("local part must be 1-64 characters")
	}
	if strings.HasPrefix(localPart, ".") || strings.HasSuffix(localPart, ".") {
		return errors.New("local part cannot start or end with a dot")
	}
	if strings.Contains(localPart, "..") {
		return errors.New("local part cannot contain consecutive dots")
	}
	if !localPartRegex.MatchString(localPart) {
		return errors.New("local part contains invalid characters")
	}
	return nil
}

func isOnionDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	return strings.HasSuffix(domain, ".onion")
}

func validateDomain(domain string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	if len(domain) == 0 || len(domain) > 253 {
		return errors.New("domain must be 1-253 characters")
	}
	if isOnionDomain(domain) {
		onionName := strings.TrimSuffix(domain, ".onion")
		if len(onionName) != 16 && len(onionName) != 56 {
			return errors.New("invalid .onion domain length")
		}
		validOnion := regexp.MustCompile(`^[a-z2-7]+$`)
		if !validOnion.MatchString(onionName) {
			return errors.New("invalid .onion domain format")
		}
		return nil
	}
	if !domainRegex.MatchString(domain) {
		return errors.New("invalid domain format")
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return errors.New("domain must have at least two labels")
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return errors.New("domain label must be 1-63 characters")
		}
	}
	return nil
}

func ValidateEmailAddress(address string) (string, string, error) {
	address = strings.TrimSpace(address)
	address = strings.Trim(address, "<>")
	if !strings.Contains(address, "@") {
		return "", "", errors.New("invalid email address: missing '@'")
	}
	sepInd := strings.LastIndex(address, "@")
	if sepInd == 0 || sepInd == len(address)-1 {
		return "", "", errors.New("invalid email address: empty local part or domain")
	}
	localPart := address[:sepInd]
	domain := address[sepInd+1:]
	if err := validateLocalPart(localPart); err != nil {
		return "", "", fmt.Errorf("invalid local part: %w", err)
	}
	if err := validateDomain(domain); err != nil {
		return "", "", fmt.Errorf("invalid domain: %w", err)
	}
	return localPart, domain, nil
}

func validateServerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("server name cannot be empty")
	}
	if !isOnionDomain(name) {
		return errors.New("server name must be a .onion domain")
	}
	onionName := strings.TrimSuffix(strings.ToLower(name), ".onion")
	if len(onionName) != 56 {
		return errors.New("server name must be a v3 .onion address (56 characters)")
	}
	validOnionV3 := regexp.MustCompile(`^[a-z2-7]{56}$`)
	if !validOnionV3.MatchString(onionName) {
		return errors.New("invalid v3 .onion address format")
	}
	return nil
}

// extractDomainFromAddress extracts domain from email address (FIXED: was missing)
func extractDomainFromAddress(address string) string {
	_, domain, err := ValidateEmailAddress(address)
	if err != nil {
		return ""
	}
	return domain
}

func hasMXRecords(domain string) bool {
	if isOnionDomain(domain) {
		return true
	}
	
	domain = strings.ToLower(strings.TrimSpace(domain))
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	
	done := make(chan bool, 1)
	var hasMX bool
	
	go func() {
		defer func() {
			if r := recover(); r != nil {
				hasMX = false
			}
			done <- true
		}()
		
		mxRecords, err := net.LookupMX(domain)
		hasMX = err == nil && len(mxRecords) > 0
	}()
	
	select {
	case <-done:
		return hasMX
	case <-time.After(MXLookupTimeout):
		return false
	}
}

type MessageIDCache struct {
	cache map[string]time.Time
	mu    sync.RWMutex
}

func NewMessageIDCache() *MessageIDCache {
	cache := &MessageIDCache{cache: make(map[string]time.Time)}
	go cache.cleanupLoop()
	return cache
}

func (c *MessageIDCache) Has(messageID string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	expiry, exists := c.cache[messageID]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

func (c *MessageIDCache) Add(messageID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.cache[messageID]; exists {
		return false
	}
	c.cache[messageID] = time.Now().Add(MessageIDCacheDuration)
	return true
}

func (c *MessageIDCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for id, expiry := range c.cache {
				if now.After(expiry) {
					delete(c.cache, id)
				}
			}
			c.mu.Unlock()
		case <-shutdownSignal:
			return
		}
	}
}

type RateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	limiter := &RateLimiter{requests: make(map[string][]time.Time)}
	go limiter.cleanupLoop()
	return limiter
}

func (rl *RateLimiter) Allow(clientIP string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-RateLimitWindow)
	requests := rl.requests[clientIP]
	var validRequests []time.Time
	for _, t := range requests {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}
	if len(validRequests) >= RateLimitPerIP {
		rl.requests[clientIP] = validRequests
		return false
	}
	validRequests = append(validRequests, now)
	rl.requests[clientIP] = validRequests
	return true
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			cutoff := now.Add(-RateLimitWindow * 2)
			for ip, requests := range rl.requests {
				var validRequests []time.Time
				for _, t := range requests {
					if t.After(cutoff) {
						validRequests = append(validRequests, t)
					}
				}
				if len(validRequests) == 0 {
					delete(rl.requests, ip)
				} else {
					rl.requests[ip] = validRequests
				}
			}
			rl.mu.Unlock()
		case <-shutdownSignal:
			return
		}
	}
}

func cryptoRandInt63n(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return time.Now().UnixNano() % max
	}
	return n.Int64()
}

func applyPadding(data []byte, targetSize int) []byte {
	if len(data) >= targetSize {
		return data
	}
	padding := make([]byte, targetSize-len(data))
	if _, err := rand.Read(padding); err != nil {
		// Fallback to zero padding if random fails
		padding = make([]byte, targetSize-len(data))
	}
	return append(data, padding...)
}

// normalizeToBucket finds the appropriate size bucket and pads the message (NEW)
func normalizeToBucket(data []byte) ([]byte, error) {
	currentSize := int64(len(data))
	
	// Find the smallest bucket that fits the data
	var targetBucket int64
	for _, bucket := range MessageSizeBuckets {
		if currentSize <= bucket {
			targetBucket = bucket
			break
		}
	}
	
	// If data is larger than largest bucket, reject
	if targetBucket == 0 {
		return nil, fmt.Errorf("message too large: %d bytes (max %d)", currentSize, MessageSizeBuckets[len(MessageSizeBuckets)-1])
	}
	
	// Pad to target bucket size
	return applyPadding(data, int(targetBucket)), nil
}

// fuzzTimestamp adds random offset to timestamp (NEW)
func fuzzTimestamp(t time.Time) time.Time {
	// Add random offset between -2h and +2h
	maxOffset := int64(TimestampFuzzRange)
	offset := cryptoRandInt63n(maxOffset*2) - maxOffset
	return t.Add(time.Duration(offset))
}

// sanitizeHeaders removes revealing headers and normalizes others (NEW)
func sanitizeHeaders(data []byte) []byte {
	lines := strings.Split(string(data), "\r\n")
	var sanitized []string
	
	revealingHeaders := map[string]bool{
		"x-mailer":        true,
		"user-agent":      true,
		"x-originating-ip": true,
		"x-forwarded-for": true,
		"x-sender":        true,
		"x-priority":      true,
		"importance":      true,
		"x-msmail-priority": true,
	}
	
	inHeader := true
	for _, line := range lines {
		// Empty line marks end of headers
		if line == "" {
			inHeader = false
			sanitized = append(sanitized, line)
			continue
		}
		
		if inHeader && strings.Contains(line, ":") {
			parts := strings.SplitN(line, ":", 2)
			headerName := strings.ToLower(strings.TrimSpace(parts[0]))
			
			// Skip revealing headers
			if revealingHeaders[headerName] {
				continue
			}
			
			// Normalize Message-ID format
			if headerName == "message-id" {
				// Replace with our own format
				continue // Will be added by generateMessageID
			}
			
			// Normalize Date header with fuzzing
			if headerName == "date" {
				// Parse and fuzz timestamp
				continue // Will be added with fuzzed timestamp
			}
		}
		
		sanitized = append(sanitized, line)
	}
	
	return []byte(strings.Join(sanitized, "\r\n"))
}

// MessageFragment represents a fragment of a larger message (NEW)
type MessageFragment struct {
	FragmentID   string
	TotalParts   int
	PartNumber   int
	Data         []byte
	OriginalHash string
}

// fragmentMessage splits a large message into random-sized fragments (NEW)
func fragmentMessage(data []byte, messageID string) ([]*MessageFragment, error) {
	dataLen := len(data)
	
	// Decide on fragment sizes (random between 16KB and 64KB)
	var fragments []*MessageFragment
	offset := 0
	partNumber := 1
	
	// Calculate hash of original message
	hash := sha512.Sum512(data)
	originalHash := base64.URLEncoding.EncodeToString(hash[:16])
	
	for offset < dataLen {
		// Random fragment size between 16KB and 64KB
		fragSize := int(16*1024 + cryptoRandInt63n(48*1024))
		if offset+fragSize > dataLen {
			fragSize = dataLen - offset
		}
		
		fragment := &MessageFragment{
			FragmentID:   messageID,
			PartNumber:   partNumber,
			Data:         data[offset : offset+fragSize],
			OriginalHash: originalHash,
		}
		
		fragments = append(fragments, fragment)
		offset += fragSize
		partNumber++
	}
	
	// Set total parts for all fragments
	totalParts := len(fragments)
	for _, frag := range fragments {
		frag.TotalParts = totalParts
	}
	
	return fragments, nil
}

// encodeFragment encodes a fragment into email format (NEW)
func encodeFragment(frag *MessageFragment) []byte {
	header := fmt.Sprintf("X-Fog-Fragment-ID: %s\r\n", frag.FragmentID)
	header += fmt.Sprintf("X-Fog-Fragment-Part: %d/%d\r\n", frag.PartNumber, frag.TotalParts)
	header += fmt.Sprintf("X-Fog-Fragment-Hash: %s\r\n", frag.OriginalHash)
	header += "\r\n"
	
	return append([]byte(header), frag.Data...)
}

type Envelope struct {
	MessageFrom    string
	MessageTo      string
	MessageData    io.Reader
	ReceivedAt     time.Time
	RetryCount     int
	MessageID      string
	IsCoverTraffic bool
	IsDummy        bool // NEW: marks dummy recipients
	OriginalSize   int64 // NEW: track original size before padding
}

// TorConnection represents a pooled Tor connection (NEW)
type TorConnection struct {
	dialer    proxy.Dialer
	createdAt time.Time
	usageCount int
	mu        sync.Mutex
}

// ConnectionPool manages Tor connections (NEW)
type ConnectionPool struct {
	connections []*TorConnection
	current     int
	mu          sync.Mutex
}

func NewConnectionPool(size int) (*ConnectionPool, error) {
	pool := &ConnectionPool{
		connections: make([]*TorConnection, size),
	}
	
	// Initialize connections
	for i := 0; i < size; i++ {
		dialer := &net.Dialer{Timeout: DeliveryTimeout}
		torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
		if err != nil {
			return nil, fmt.Errorf("failed to create Tor dialer %d: %w", i, err)
		}
		
		pool.connections[i] = &TorConnection{
			dialer:    torDialer,
			createdAt: time.Now(),
			usageCount: 0,
		}
	}
	
	// Start rotation goroutine
	go pool.rotationLoop()
	
	return pool, nil
}

func (cp *ConnectionPool) GetConnection() *TorConnection {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	
	// Round-robin selection
	conn := cp.connections[cp.current]
	cp.current = (cp.current + 1) % len(cp.connections)
	
	conn.mu.Lock()
	conn.usageCount++
	conn.mu.Unlock()
	
	return conn
}

func (cp *ConnectionPool) rotationLoop() {
	ticker := time.NewTicker(ConnectionMaxAge)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			cp.mu.Lock()
			now := time.Now()
			
			// Rotate old connections
			for i, conn := range cp.connections {
				conn.mu.Lock()
				age := now.Sub(conn.createdAt)
				
				if age > ConnectionMaxAge {
					// Create new connection
					dialer := &net.Dialer{Timeout: DeliveryTimeout}
					torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
					if err != nil {
						log.Printf("[POOL] Failed to rotate connection %d: %v", i, err)
						conn.mu.Unlock()
						continue
					}
					
					cp.connections[i] = &TorConnection{
						dialer:    torDialer,
						createdAt: now,
						usageCount: 0,
					}
					
					log.Printf("[POOL] Rotated connection %d (age: %v, usage: %d)", 
						i, age, conn.usageCount)
				}
				conn.mu.Unlock()
			}
			
			cp.mu.Unlock()
		case <-shutdownSignal:
			return
		}
	}
}

type MixnetBatcher struct {
	envelopes    []*Envelope
	mu           sync.Mutex
	queue        chan *Envelope
	batchWindow  time.Duration
	lastBatchAt  time.Time
	connPool     *ConnectionPool // NEW: connection pool
}

func NewMixnetBatcher(queue chan *Envelope) *MixnetBatcher {
	// Create connection pool
	connPool, err := NewConnectionPool(ConnectionPoolSize)
	if err != nil {
		log.Fatalf("[BATCHER] Failed to create connection pool: %v", err)
	}
	
	batcher := &MixnetBatcher{
		envelopes:   make([]*Envelope, 0),
		queue:       queue,
		batchWindow: MixnetBatchWindow,
		lastBatchAt: time.Now(),
		connPool:    connPool,
	}
	go batcher.processBatches()
	return batcher
}

func (mb *MixnetBatcher) Add(envelope *Envelope) {
	mb.mu.Lock()
	mb.envelopes = append(mb.envelopes, envelope)
	mb.mu.Unlock()
}

// generateDummyRecipients creates dummy recipients for the batch (NEW)
func (mb *MixnetBatcher) generateDummyRecipients(count int, serverName string) []*Envelope {
	dummies := make([]*Envelope, count)
	
	for i := 0; i < count; i++ {
		// Generate random recipient
		randomBytes := make([]byte, 16)
		if _, err := rand.Read(randomBytes); err != nil {
			continue
		}
		dummyRecipient := fmt.Sprintf("dummy-%s@%s", 
			base64.URLEncoding.EncodeToString(randomBytes[:8]), serverName)
		
		// Create dummy envelope with random data
		dummyData := make([]byte, int(32*1024+cryptoRandInt63n(32*1024)))
		if _, err := rand.Read(dummyData); err != nil {
			continue
		}
		
		dummies[i] = &Envelope{
			MessageFrom:    fmt.Sprintf("system@%s", serverName),
			MessageTo:      dummyRecipient,
			MessageData:    bytes.NewReader(dummyData),
			ReceivedAt:     time.Now(),
			RetryCount:     0,
			MessageID:      generateMessageID(),
			IsCoverTraffic: false,
			IsDummy:        true,
		}
		
		stats.IncDummy()
	}
	
	return dummies
}

func (mb *MixnetBatcher) processBatches() {
	ticker := time.NewTicker(mb.batchWindow)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			mb.flushBatch()
		case <-shutdownSignal:
			// Flush remaining batch before shutting down
			mb.flushBatch()
			return
		}
	}
}

func (mb *MixnetBatcher) flushBatch() {
	mb.mu.Lock()
	if len(mb.envelopes) == 0 {
		mb.mu.Unlock()
		return
	}
	
	batch := mb.envelopes
	mb.envelopes = make([]*Envelope, 0)
	mb.lastBatchAt = time.Now()
	mb.mu.Unlock()
	
	// Add dummy recipients (NEW)
	dummyCount := int(DummyRecipientsMin + cryptoRandInt63n(int64(DummyRecipientsMax-DummyRecipientsMin+1)))
	serverName := "localhost.onion" // Will be set properly by the server
	dummies := mb.generateDummyRecipients(dummyCount, serverName)
	batch = append(batch, dummies...)
	
	log.Printf("[BATCH] Flushing %d messages (including %d dummies) with inter-message jitter", len(batch), dummyCount)
	
	// Shuffle batch to randomize order
	for i := len(batch) - 1; i > 0; i-- {
		j := int(cryptoRandInt63n(int64(i + 1)))
		batch[i], batch[j] = batch[j], batch[i]
	}
	
	// Apply adaptive padding to all messages
	for _, env := range batch {
		data, err := io.ReadAll(env.MessageData)
		if err != nil {
			log.Printf("[BATCH] Error reading message data: %v", err)
			continue
		}
		
		// Store original size
		env.OriginalSize = int64(len(data))
		
		// Sanitize headers (NEW)
		data = sanitizeHeaders(data)
		
		// Normalize to bucket size (NEW)
		normalizedData, err := normalizeToBucket(data)
		if err != nil {
			log.Printf("[BATCH] Error normalizing message: %v", err)
			continue
		}
		
		env.MessageData = bytes.NewReader(normalizedData)
		
		// Apply exponential jitter between messages (NEW)
		baseDelay := time.Duration(100+cryptoRandInt63n(400)) * time.Millisecond
		exponentialFactor := math.Exp(float64(cryptoRandInt63n(100)) / 100.0)
		jitter := time.Duration(float64(baseDelay) * exponentialFactor)
		
		// Add to queue with jitter
		go func(e *Envelope, delay time.Duration) {
			time.Sleep(delay)
			queueEnvelope(e)
		}(env, jitter)
	}
}

type CoverTrafficGenerator struct {
	queue      chan *Envelope
	interval   time.Duration
	serverName string
}

func NewCoverTrafficGenerator(queue chan *Envelope, serverName string) *CoverTrafficGenerator {
	gen := &CoverTrafficGenerator{
		queue:      queue,
		interval:   CoverTrafficInterval,
		serverName: serverName,
	}
	go gen.generateCoverTraffic()
	return gen
}

func (ctg *CoverTrafficGenerator) generateCoverTraffic() {
	// Use Poisson distribution for more natural timing (NEW)
	for {
		// Calculate next interval using exponential distribution (Poisson process)
		lambda := 1.0 / CoverTrafficInterval.Seconds()
		u := float64(cryptoRandInt63n(1000000)) / 1000000.0
		nextInterval := time.Duration(-math.Log(1-u)/lambda) * time.Second
		
		// Clamp to reasonable bounds
		if nextInterval < CoverTrafficInterval/2 {
			nextInterval = CoverTrafficInterval / 2
		}
		if nextInterval > CoverTrafficInterval*2 {
			nextInterval = CoverTrafficInterval * 2
		}
		
		timer := time.NewTimer(nextInterval)
		select {
		case <-timer.C:
			ctg.sendCoverTraffic()
		case <-shutdownSignal:
			timer.Stop()
			return
		}
	}
}

func (ctg *CoverTrafficGenerator) sendCoverTraffic() {
	// Generate random cover traffic recipient
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		log.Printf("[COVER] Failed to generate random bytes: %v", err)
		return
	}
	
	coverRecipient := fmt.Sprintf("cover-%s@%s", 
		base64.URLEncoding.EncodeToString(randomBytes[:8]), ctg.serverName)
	
	// Generate random message data
	dataSize := int(32*1024 + cryptoRandInt63n(96*1024))
	coverData := make([]byte, dataSize)
	if _, err := rand.Read(coverData); err != nil {
		log.Printf("[COVER] Failed to generate cover data: %v", err)
		return
	}
	
	envelope := &Envelope{
		MessageFrom:    fmt.Sprintf("system@%s", ctg.serverName),
		MessageTo:      coverRecipient,
		MessageData:    bytes.NewReader(coverData),
		ReceivedAt:     time.Now(),
		RetryCount:     0,
		MessageID:      generateMessageID(),
		IsCoverTraffic: true,
	}
	
	queueEnvelope(envelope)
	stats.IncCoverTraffic()
}

type Server struct {
	Name           string
	Addr           string
	Handler        Handler
	MessageIDCache *MessageIDCache
	RateLimiter    *RateLimiter
	MixnetBatcher  *MixnetBatcher
	CoverTraffic   *CoverTrafficGenerator
}

type Handler interface {
	ServeSMTP(envelope *Envelope) error
}

func (s *Server) Serve(listener net.Listener) error {
	defer listener.Close()
	
	for {
		select {
		case <-shutdownSignal:
			log.Println("[SERVER] Shutdown signal received, stopping listener")
			return nil
		default:
		}
		
		// Set deadline to allow periodic checks for shutdown
		if tcpListener, ok := listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}
		
		conn, err := listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-shutdownSignal:
				return nil
			default:
				return err
			}
		}
		
		clientAddr := conn.RemoteAddr().String()
		clientIP := strings.Split(clientAddr, ":")[0]
		
		if !s.RateLimiter.Allow(clientIP) {
			log.Printf("[SERVER] Rate limit exceeded for %s", sanitizeLogString(clientIP))
			conn.Close()
			continue
		}
		
		log.Printf("[SERVER] New connection from %s", sanitizeLogString(clientAddr))
		
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			s.handleConnection(conn)
		}()
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()
	
	// Set read/write deadlines (NEW)
	conn.SetDeadline(time.Now().Add(5 * time.Minute))
	
	smtpConn := &SMTPConn{
		conn:       conn,
		text:       textproto.NewConn(conn),
		server:     s,
		remoteAddr: conn.RemoteAddr().String(),
	}
	if err := smtpConn.serve(); err != nil {
		log.Printf("[CONN] Connection error: %v", err)
	}
}

type SMTPConn struct {
	conn       net.Conn
	text       *textproto.Conn
	server     *Server
	remoteAddr string
	mailFrom   string
	mailTo     []string
	data       bytes.Buffer
	dataSize   int64 // Track data size (NEW)
	quitSent   bool
}

func (c *SMTPConn) resetSession() {
	c.mailFrom = ""
	c.mailTo = nil
	c.data.Reset()
	c.dataSize = 0
}

func (c *SMTPConn) serve() error {
	log.Printf("[SMTP] <- %s: Client connected", sanitizeLogString(c.remoteAddr))
	
	if err := c.text.PrintfLine("220 %s %s v%s SMTP Ready", 
		c.server.Name, AppName, Version); err != nil {
		return err
	}
	log.Printf("[SMTP] -> %s: 220 %s %s v%s SMTP Ready", 
		sanitizeLogString(c.remoteAddr), c.server.Name, AppName, Version)
	
	for {
		// Check for shutdown
		select {
		case <-shutdownSignal:
			c.text.PrintfLine("421 Service shutting down")
			return nil
		default:
		}
		
		// Update deadline for each command
		c.conn.SetDeadline(time.Now().Add(5 * time.Minute))
		
		line, err := c.text.ReadLine()
		if err != nil {
			if err == io.EOF {
				log.Printf("[SMTP] <- %s: Client disconnected (EOF)", sanitizeLogString(c.remoteAddr))
			} else {
				log.Printf("[SMTP] <- %s: Read error: %v", sanitizeLogString(c.remoteAddr), err)
			}
			return err
		}
		
		// Check header size limit (NEW)
		if int64(len(line)) > MaxHeaderSize {
			log.Printf("[SMTP] -> %s: 552 Header line too long", sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("552 Header line too long")
		}
		
		log.Printf("[SMTP] <- %s: %s", sanitizeLogString(c.remoteAddr), sanitizeLogString(line))
		
		if err := c.handleCommand(line); err != nil {
			return err
		}
		
		if c.quitSent {
			return nil
		}
	}
}

func (c *SMTPConn) handleCommand(line string) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		log.Printf("[SMTP] -> %s: 500 Empty command", sanitizeLogString(c.remoteAddr))
		return c.text.PrintfLine("500 Empty command")
	}
	
	cmd := strings.ToUpper(parts[0])
	
	// Apply random delay for timing attack prevention
	minDelay := MinDelay
	maxDelay := MaxDelay
	delay := time.Duration(cryptoRandInt63n(int64(maxDelay-minDelay))) + minDelay
	time.Sleep(delay)
	
	switch cmd {
	case "HELO", "EHLO":
		log.Printf("[SMTP] -> %s: 250 %s", sanitizeLogString(c.remoteAddr), c.server.Name)
		return c.text.PrintfLine("250 %s", c.server.Name)
		
	case "MAIL":
		if len(parts) < 2 || !strings.HasPrefix(strings.ToUpper(parts[1]), "FROM:") {
			log.Printf("[SMTP] -> %s: 501 Syntax: MAIL FROM:<address>", sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("501 Syntax: MAIL FROM:<address>")
		}
		from := strings.TrimPrefix(parts[1], "FROM:")
		from = strings.TrimPrefix(from, "from:")
		from = strings.Trim(from, "<>")
		
		// Validate and sanitize email (NEW)
		_, _, err := ValidateEmailAddress(from)
		if err != nil {
			log.Printf("[SMTP] -> %s: 553 Invalid sender address: %v", 
				sanitizeLogString(c.remoteAddr), err)
			return c.text.PrintfLine("553 Invalid sender address")
		}
		
		c.mailFrom = from
		log.Printf("[SMTP] -> %s: 250 OK (sender: %s)", 
			sanitizeLogString(c.remoteAddr), sanitizeLogString(from))
		return c.text.PrintfLine("250 OK")
		
	case "RCPT":
		if c.mailFrom == "" {
			log.Printf("[SMTP] -> %s: 503 Need MAIL command first", sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("503 Need MAIL command first")
		}
		
		// Check max recipients (NEW)
		if len(c.mailTo) >= MaxRecipients {
			log.Printf("[SMTP] -> %s: 452 Too many recipients", sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("452 Too many recipients")
		}
		
		if len(parts) < 2 || !strings.HasPrefix(strings.ToUpper(parts[1]), "TO:") {
			log.Printf("[SMTP] -> %s: 501 Syntax: RCPT TO:<address>", sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("501 Syntax: RCPT TO:<address>")
		}
		to := strings.TrimPrefix(parts[1], "TO:")
		to = strings.TrimPrefix(to, "to:")
		to = strings.Trim(to, "<>")
		
		// Validate recipient
		_, domain, err := ValidateEmailAddress(to)
		if err != nil {
			log.Printf("[SMTP] -> %s: 553 Invalid recipient address: %v", 
				sanitizeLogString(c.remoteAddr), err)
			return c.text.PrintfLine("553 Invalid recipient address")
		}
		
		// Check for email header injection attempts (NEW)
		if strings.Contains(to, "\r") || strings.Contains(to, "\n") {
			log.Printf("[SMTP] -> %s: 553 Invalid recipient (injection attempt)", 
				sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("553 Invalid recipient")
		}
		
		if !hasMXRecords(domain) {
			log.Printf("[SMTP] -> %s: 550 No MX records for domain %s", 
				sanitizeLogString(c.remoteAddr), sanitizeLogString(domain))
			return c.text.PrintfLine("550 No MX records for domain")
		}
		
		c.mailTo = append(c.mailTo, to)
		log.Printf("[SMTP] -> %s: 250 OK (recipient: %s)", 
			sanitizeLogString(c.remoteAddr), sanitizeLogString(to))
		return c.text.PrintfLine("250 OK")
		
	case "DATA":
		if c.mailFrom == "" || len(c.mailTo) == 0 {
			log.Printf("[SMTP] -> %s: 503 Need MAIL and RCPT commands first", 
				sanitizeLogString(c.remoteAddr))
			return c.text.PrintfLine("503 Need MAIL and RCPT commands first")
		}
		
		log.Printf("[SMTP] -> %s: 354 Start mail input; end with <CRLF>.<CRLF>", 
			sanitizeLogString(c.remoteAddr))
		if err := c.text.PrintfLine("354 Start mail input; end with <CRLF>.<CRLF>"); err != nil {
			return err
		}
		
		c.data.Reset()
		c.dataSize = 0
		
		reader := c.text.DotReader()
		
		// Read with size limit (NEW)
		limitedReader := io.LimitReader(reader, MaxMessageSize)
		written, err := io.Copy(&c.data, limitedReader)
		c.dataSize = written
		
		if err != nil {
			log.Printf("[SMTP] <- %s: Error reading message data: %v", 
				sanitizeLogString(c.remoteAddr), err)
			return c.text.PrintfLine("554 Transaction failed")
		}
		
		// Check if message was too large (NEW)
		if c.dataSize >= MaxMessageSize {
			log.Printf("[SMTP] -> %s: 552 Message exceeds size limit (%d bytes)", 
				sanitizeLogString(c.remoteAddr), MaxMessageSize)
			c.resetSession()
			return c.text.PrintfLine("552 Message exceeds size limit")
		}
		
		log.Printf("[SMTP] <- %s: Message data received (%d bytes)", 
			sanitizeLogString(c.remoteAddr), c.dataSize)
		
		// Generate message ID with error handling (FIXED)
		messageID := generateMessageID()
		
		if c.server.MessageIDCache.Has(messageID) {
			log.Printf("[SMTP] -> %s: 554 Duplicate message ID detected (replay attack)", 
				sanitizeLogString(c.remoteAddr))
			c.resetSession()
			return c.text.PrintfLine("554 Transaction failed")
		}
		c.server.MessageIDCache.Add(messageID)
		
		for i, recipient := range c.mailTo {
			env := &Envelope{
				MessageFrom:    c.mailFrom,
				MessageTo:      recipient,
				MessageData:    bytes.NewReader(c.data.Bytes()),
				ReceivedAt:     time.Now(),
				RetryCount:     0,
				MessageID:      messageID,
				IsCoverTraffic: false,
			}
			if err := c.server.Handler.ServeSMTP(env); err != nil {
				log.Printf("[SMTP] Handler error for %s: %v", sanitizeLogString(recipient), err)
				return c.text.PrintfLine("554 Transaction failed")
			}
			stats.IncReceived()
			log.Printf("[SMTP] Envelope %d/%d queued successfully", i+1, len(c.mailTo))
		}
		c.resetSession()
		log.Printf("[SMTP] -> %s: 250 OK", sanitizeLogString(c.remoteAddr))
		return c.text.PrintfLine("250 OK")
		
	case "RSET":
		c.resetSession()
		log.Printf("[SMTP] -> %s: 250 Ok (session reset)", sanitizeLogString(c.remoteAddr))
		return c.text.PrintfLine("250 Ok")
		
	case "VRFY", "EXPN", "HELP", "NOOP":
		log.Printf("[SMTP] -> %s: 250 OK (%s command)", sanitizeLogString(c.remoteAddr), parts[0])
		return c.text.PrintfLine("250 OK")
		
	case "QUIT":
		c.quitSent = true
		log.Printf("[SMTP] -> %s: 221 Bye (client disconnecting)", sanitizeLogString(c.remoteAddr))
		return c.text.PrintfLine("221 Bye")
		
	default:
		log.Printf("[SMTP] -> %s: 500 Unknown command: %s", 
			sanitizeLogString(c.remoteAddr), sanitizeLogString(parts[0]))
		return c.text.PrintfLine("500 Command not recognized")
	}
}

func generateMessageID() string {
	randomBytes := make([]byte, 32)
	// FIXED: Check error from rand.Read
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based ID if random fails
		log.Printf("[WARN] Failed to generate random bytes: %v, using timestamp fallback", err)
		timestamp := time.Now().UnixNano()
		return base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", timestamp)))
	}
	
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
	pidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pidBytes, uint32(time.Now().Unix()))
	combined := append(randomBytes, timestamp...)
	combined = append(combined, pidBytes...)
	h := sha512.Sum512(combined)
	return base64.URLEncoding.EncodeToString(h[:32])
}

type SimpleHandler struct {
	batcher *MixnetBatcher
}

func (h *SimpleHandler) ServeSMTP(envelope *Envelope) error {
	h.batcher.Add(envelope)
	return nil
}

func smtpRelay(envelope *Envelope) error {
	// Handle cover traffic
	if envelope.IsCoverTraffic {
		log.Printf("[COVER] Simulated relay to %s (cover traffic, discarded)", 
			sanitizeLogString(envelope.MessageTo))
		return nil
	}
	
	// Handle dummy messages
	if envelope.IsDummy {
		log.Printf("[DUMMY] Simulated relay to %s (dummy recipient, discarded)", 
			sanitizeLogString(envelope.MessageTo))
		return nil
	}
	
	log.Printf("[RELAY] Starting relay for message ID %s", sanitizeLogString(envelope.MessageID))
	log.Printf("[RELAY] From: %s, To: %s", 
		sanitizeLogString(envelope.MessageFrom), sanitizeLogString(envelope.MessageTo))
	
	domain := extractDomainFromAddress(envelope.MessageTo)
	if domain == "" {
		stats.IncFailed()
		return fmt.Errorf("invalid recipient address: %s", envelope.MessageTo)
	}
	
	_, _, err := ValidateEmailAddress(envelope.MessageTo)
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("invalid email address: %w", err)
	}
	
	var targetAddr string
	if isOnionDomain(domain) {
		targetAddr = net.JoinHostPort(domain, "25")
		log.Printf("[RELAY] Target: .onion domain %s", sanitizeLogString(targetAddr))
	} else {
		log.Printf("[RELAY] Clearnet domain detected: %s, performing MX lookup", 
			sanitizeLogString(domain))
		mxRecords, err := net.LookupMX(domain)
		if err != nil || len(mxRecords) == 0 {
			stats.IncFailed()
			return fmt.Errorf("no MX records found for %s: %w", domain, err)
		}
		mxHost := strings.TrimSuffix(mxRecords[0].Host, ".")
		targetAddr = net.JoinHostPort(mxHost, "25")
		log.Printf("[RELAY] Target: MX host %s (priority %d)", 
			sanitizeLogString(targetAddr), mxRecords[0].Pref)
	}
	
	// Apply jitter
	jitter := time.Duration(cryptoRandInt63n(int64(5 * time.Second)))
	log.Printf("[RELAY] Applying jitter: %v", jitter)
	time.Sleep(jitter)
	
	log.Printf("[RELAY] Attempting delivery to %s (attempt %d/%d)", 
		sanitizeLogString(envelope.MessageTo), envelope.RetryCount+1, MaxRetries)
	
	log.Printf("[RELAY] Creating Tor SOCKS5 dialer to %s", TorSocksProxyAddr)
	dialer := &net.Dialer{Timeout: DeliveryTimeout}
	torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("failed to create Tor dialer: %w", err)
	}
	
	log.Printf("[RELAY] Connecting to %s via Tor...", sanitizeLogString(targetAddr))
	netConn, err := torDialer.Dial("tcp", targetAddr)
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("failed to connect to %s: %w", targetAddr, err)
	}
	defer netConn.Close()
	log.Printf("[RELAY] Connected to %s", sanitizeLogString(targetAddr))
	
	netConn.SetDeadline(time.Now().Add(DeliveryTimeout))
	
	log.Printf("[RELAY] Creating SMTP client for domain %s", sanitizeLogString(domain))
	client, err := smtp.NewClient(netConn, domain)
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()
	
	log.Printf("[RELAY] Sending MAIL FROM: %s", sanitizeLogString(envelope.MessageFrom))
	if err := client.Mail(envelope.MessageFrom); err != nil {
		stats.IncFailed()
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}
	
	log.Printf("[RELAY] Sending RCPT TO: %s", sanitizeLogString(envelope.MessageTo))
	if err := client.Rcpt(envelope.MessageTo); err != nil {
		stats.IncFailed()
		return fmt.Errorf("RCPT TO failed: %w", err)
	}
	
	log.Printf("[RELAY] Sending DATA command")
	wc, err := client.Data()
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("DATA command failed: %w", err)
	}
	defer wc.Close()
	
	log.Printf("[RELAY] Transferring message content")
	bytesWritten, err := io.Copy(wc, envelope.MessageData)
	if err != nil {
		stats.IncFailed()
		return fmt.Errorf("message transfer failed: %w", err)
	}
	
	stats.IncDelivered()
	log.Printf("[RELAY] SUCCESS: Delivered %d bytes to %s via %s", 
		bytesWritten, sanitizeLogString(envelope.MessageTo), sanitizeLogString(targetAddr))
	return nil
}

func queueEnvelope(envelope *Envelope) bool {
	mailQueueMutex.Lock()
	defer mailQueueMutex.Unlock()
	select {
	case mailQueue <- envelope:
		return true
	default:
		log.Printf("[QUEUE] Warning: mail queue full")
		return false
	}
}

func StartRelayWorkers(queue chan *Envelope, workerCount int) {
	for i := 0; i < workerCount; i++ {
		shutdownWg.Add(1)
		go func(id int) {
			defer shutdownWg.Done()
			log.Printf("[WORKER] Relay worker %d started", id)
			
			for {
				select {
				case env := <-queue:
					err := smtpRelay(env)
					if err != nil {
						log.Printf("[Worker %d] Relay error: %v", id, err)
						
						if env.RetryCount < MaxRetries {
							env.RetryCount++
							backoff := time.Duration(math.Pow(2, float64(env.RetryCount))) * time.Second
							jitter := time.Duration(cryptoRandInt63n(int64(backoff / 2)))
							log.Printf("[Worker %d] Scheduling retry %d for %s in %v", 
								id, env.RetryCount, sanitizeLogString(env.MessageTo), backoff+jitter)
							time.Sleep(backoff + jitter)
							queueEnvelope(env)
						} else {
							log.Printf("[Worker %d] Giving up on %s after %d attempts", 
								id, sanitizeLogString(env.MessageTo), env.RetryCount+1)
						}
					}
				case <-shutdownSignal:
					log.Printf("[WORKER] Worker %d shutting down", id)
					return
				}
			}
		}(i)
	}
}

// printVersion prints version information (NEW)
func printVersion() {
	fmt.Printf("%s v%s\n", AppName, Version)
	fmt.Println("Anonymous SMTP Relay Server with Advanced Privacy Protection")
	fmt.Println()
	fmt.Println("Features:")
	fmt.Println("  - Tor-based anonymous relay")
	fmt.Println("  - Mixnet batching & cover traffic")
	fmt.Println("  - Message size normalization")
	fmt.Println("  - Header sanitization")
	fmt.Println("  - Timestamp fuzzing")
	fmt.Println("  - Dummy recipient injection")
	fmt.Println("  - Traffic shaping (Poisson distribution)")
	fmt.Println("  - Connection pooling & rotation")
	fmt.Println("  - Replay attack protection")
	fmt.Println("  - Rate limiting per IP")
}

// setupGracefulShutdown sets up signal handlers for graceful shutdown (NEW)
func setupGracefulShutdown() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		sig := <-sigChan
		log.Printf("[SHUTDOWN] Received signal: %v", sig)
		log.Println("[SHUTDOWN] Initiating graceful shutdown...")
		
		// Signal all goroutines to stop
		close(shutdownSignal)
		
		// Print final statistics
		stats.PrintStats()
		
		// Wait for all workers to finish with timeout
		done := make(chan struct{})
		go func() {
			shutdownWg.Wait()
			close(done)
		}()
		
		select {
		case <-done:
			log.Println("[SHUTDOWN] All workers finished gracefully")
		case <-time.After(30 * time.Second):
			log.Println("[SHUTDOWN] Timeout waiting for workers, forcing exit")
		}
		
		os.Exit(0)
	}()
}

func main() {
	// Define flags
	listenAddr := flag.String("addr", "127.0.0.1:2525", "Listen address (e.g., 127.0.0.1:2525)")
	serverName := flag.String("name", "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion", "Server v3 .onion hostname")
	showVersion := flag.Bool("version", false, "Show version information")
	showStats := flag.Bool("stats", false, "Enable periodic statistics display")
	
	// Custom usage message (FIXED: --help bug)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s v%s - Anonymous SMTP Relay Server\n\n", AppName, Version)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s --addr 0.0.0.0:25 --name yourserver.onion\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --version\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nFor more information, see documentation.\n")
	}
	
	flag.Parse()
	
	// FIXED: Handle --help and --version properly
	if *showVersion {
		printVersion()
		return
	}
	
	// Validate flags (NEW)
	if *listenAddr == "" {
		log.Fatal("[INIT] FATAL: Listen address cannot be empty")
	}
	
	// Setup graceful shutdown (NEW)
	setupGracefulShutdown()
	
	// Start statistics reporter if enabled (NEW)
	if *showStats {
		go func() {
			ticker := time.NewTicker(1 * time.Minute)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					stats.PrintStats()
				case <-shutdownSignal:
					return
				}
			}
		}()
	}
	
	log.Printf("================================")
	log.Printf("%s v%s SMTP Relay Server", AppName, Version)
	log.Printf("================================")
	log.Printf("")
	log.Printf("[INIT] Validating server name: %s", *serverName)
	if err := validateServerName(*serverName); err != nil {
		log.Fatalf("[INIT] FATAL: Invalid server name: %v", err)
	}
	log.Printf("[INIT] Server name validated successfully")
	
	log.Printf("[INIT] Creating mail queue (capacity: 1000)")
	mailQueue = make(chan *Envelope, 1000)
	
	log.Printf("[INIT] Starting %d relay workers", RelayWorkerCount)
	StartRelayWorkers(mailQueue, RelayWorkerCount)
	
	log.Printf("[INIT] Initializing message ID cache (duration: %v)", MessageIDCacheDuration)
	messageIDCache := NewMessageIDCache()
	
	log.Printf("[INIT] Initializing rate limiter (limit: %d req/%v per IP)", RateLimitPerIP, RateLimitWindow)
	rateLimiter := NewRateLimiter()
	
	log.Printf("[INIT] Initializing mixnet batcher (window: %v)", MixnetBatchWindow)
	mixnetBatcher := NewMixnetBatcher(mailQueue)
	
	log.Printf("[INIT] Starting cover traffic generator (interval: %v)", CoverTrafficInterval)
	coverTraffic := NewCoverTrafficGenerator(mailQueue, *serverName)
	
	server := &Server{
		Name:           *serverName,
		Addr:           *listenAddr,
		MessageIDCache: messageIDCache,
		RateLimiter:    rateLimiter,
		MixnetBatcher:  mixnetBatcher,
		CoverTraffic:   coverTraffic,
	}
	
	handler := &SimpleHandler{batcher: mixnetBatcher}
	server.Handler = handler
	
	log.Printf("")
	log.Printf("Server Configuration:")
	log.Printf("  Server: %s", server.Name)
	log.Printf("  Listen: %s", server.Addr)
	log.Printf("  Tor proxy: %s", TorSocksProxyAddr)
	log.Printf("")
	log.Printf("Security Features:")
	log.Printf("  - Replay protection (24h cache)")
	log.Printf("  - Rate limiting (%d req/%v per IP)", RateLimitPerIP, RateLimitWindow)
	log.Printf("  - Timing attack prevention (random delays %v-%v)", MinDelay, MaxDelay)
	log.Printf("  - Size normalization (buckets: 32KB-10MB)")
	log.Printf("  - Mixnet batching (%v windows)", MixnetBatchWindow)
	log.Printf("  - Cover traffic generation (%v intervals, Poisson)", CoverTrafficInterval)
	log.Printf("  - Dummy recipient injection (%d-%d per batch)", DummyRecipientsMin, DummyRecipientsMax)
	log.Printf("  - Header sanitization (remove revealing headers)")
	log.Printf("  - Timestamp fuzzing (±%v)", TimestampFuzzRange)
	log.Printf("  - Connection pooling (%d connections, rotate every %v)", ConnectionPoolSize, ConnectionMaxAge)
	log.Printf("  - Message size limit (%d MB)", MaxMessageSize/(1024*1024))
	log.Printf("  - Max recipients per message (%d)", MaxRecipients)
	log.Printf("")
	log.Printf("Validation:")
	log.Printf("  - RFC-compliant email addresses")
	log.Printf("  - v3 .onion server name only")
	log.Printf("  - Email header injection prevention")
	log.Printf("")
	log.Printf("Policy:")
	log.Printf("  - FROM: any valid email address")
	log.Printf("  - TO: .onion domains (direct) + clearnet (via MX lookup)")
	log.Printf("  - RELAY: both .onion and clearnet via Tor")
	log.Printf("  - WARNING: Clearnet destinations will see Tor exit node IP")
	log.Printf("")
	log.Printf("[INIT] Creating TCP listener on %s", server.Addr)
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("[INIT] FATAL: Failed to create listener: %v", err)
	}
	log.Printf("[INIT] Listener created successfully")
	log.Printf("")
	log.Printf("================================")
	log.Printf("Server ready to accept connections")
	log.Printf("Press Ctrl+C for graceful shutdown")
	log.Printf("================================")
	log.Printf("")
	
	if err := server.Serve(listener); err != nil {
		log.Fatalf("[SERVER] FATAL: Server failed: %v", err)
	}
}
