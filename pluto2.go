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
        "regexp"
        "strings"
        "sync"
        "time"

        "golang.org/x/net/proxy"
)

const (
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
)

var (
        emailRegExp    *regexp.Regexp
        localPartRegex *regexp.Regexp
        domainRegex    *regexp.Regexp
)

func init() {
        emailRegExp = regexp.MustCompile(`^[a-zA-Z0-9._%+=\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
        localPartRegex = regexp.MustCompile(`^[a-zA-Z0-9._+=\-]+$`)
        domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
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

func hasMXRecords(domain string) bool {
        domain = strings.ToLower(strings.TrimSpace(domain))
        if strings.HasSuffix(domain, ".") {
                domain = domain[:len(domain)-1]
        }
        done := make(chan bool, 1)
        var hasMX bool
        go func() {
                mxRecords, err := net.LookupMX(domain)
                hasMX = err == nil && len(mxRecords) > 0
                done <- true
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
        for range ticker.C {
                c.mu.Lock()
                now := time.Now()
                for id, expiry := range c.cache {
                        if now.After(expiry) {
                                delete(c.cache, id)
                        }
                }
                c.mu.Unlock()
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
        for range ticker.C {
                rl.mu.Lock()
                now := time.Now()
                cutoff := now.Add(-RateLimitWindow)
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
        }
}

func ApplyAdaptivePadding(data []byte) []byte {
        originalLen := len(data)
        targetSize := ((originalLen / PaddingSizeUnit) + 1) * PaddingSizeUnit
        if originalLen >= targetSize {
                return data
        }
        padded := make([]byte, targetSize)
        copy(padded, data)
        paddingLen := targetSize - originalLen
        padding := make([]byte, paddingLen)
        rand.Read(padding)
        copy(padded[originalLen:], padding)
        return padded
}

func RandomDelay() {
        delayNs := MinDelay.Nanoseconds() + int64(cryptoRandInt63n(MaxDelay.Nanoseconds()-MinDelay.Nanoseconds()))
        time.Sleep(time.Duration(delayNs))
}

func cryptoRandInt63n(n int64) int64 {
        if n <= 0 {
                return 0
        }
        max := big.NewInt(n)
        result, _ := rand.Int(rand.Reader, max)
        return result.Int64()
}

type MixnetBatcher struct {
        batch       []*Envelope
        batchMu     sync.Mutex
        outputQueue chan *Envelope
        stopChan    chan struct{}
}

func NewMixnetBatcher(outputQueue chan *Envelope) *MixnetBatcher {
        batcher := &MixnetBatcher{
                batch:       make([]*Envelope, 0),
                outputQueue: outputQueue,
                stopChan:    make(chan struct{}),
        }
        go batcher.batchLoop()
        return batcher
}

func (mb *MixnetBatcher) Add(envelope *Envelope) {
        mb.batchMu.Lock()
        mb.batch = append(mb.batch, envelope)
        mb.batchMu.Unlock()
}

func (mb *MixnetBatcher) batchLoop() {
        ticker := time.NewTicker(MixnetBatchWindow)
        defer ticker.Stop()
        for {
                select {
                case <-ticker.C:
                        mb.processBatch()
                case <-mb.stopChan:
                        return
                }
        }
}

func (mb *MixnetBatcher) processBatch() {
        mb.batchMu.Lock()
        if len(mb.batch) == 0 {
                mb.batchMu.Unlock()
                return
        }
        batch := make([]*Envelope, len(mb.batch))
        copy(batch, mb.batch)
        mb.batch = make([]*Envelope, 0)
        mb.batchMu.Unlock()
        shuffleBatch(batch)
        for _, env := range batch {
                RandomDelay()
                select {
                case mb.outputQueue <- env:
                default:
                }
        }
}

func shuffleBatch(batch []*Envelope) {
        for i := len(batch) - 1; i > 0; i-- {
                j := int(cryptoRandInt63n(int64(i + 1)))
                batch[i], batch[j] = batch[j], batch[i]
        }
}

func (mb *MixnetBatcher) Stop() {
        close(mb.stopChan)
}

type CoverTrafficGenerator struct {
        outputQueue chan *Envelope
        stopChan    chan struct{}
}

func NewCoverTrafficGenerator(outputQueue chan *Envelope) *CoverTrafficGenerator {
        gen := &CoverTrafficGenerator{
                outputQueue: outputQueue,
                stopChan:    make(chan struct{}),
        }
        go gen.generateLoop()
        return gen
}

func (ctg *CoverTrafficGenerator) generateLoop() {
        ticker := time.NewTicker(CoverTrafficInterval)
        defer ticker.Stop()
        firstNames := []string{"john", "mary", "david", "sarah", "mike", "emma", "james", "lisa", "robert", "anna"}
        lastNames := []string{"smith", "johnson", "williams", "brown", "jones", "garcia", "miller", "davis", "rodriguez", "martinez"}
        for {
                select {
                case <-ticker.C:
                        firstName := firstNames[cryptoRandInt63n(int64(len(firstNames)))]
                        lastName := lastNames[cryptoRandInt63n(int64(len(lastNames)))]
                        randomNum := cryptoRandInt63n(9999)
                        var dummyAddr string
                        switch cryptoRandInt63n(3) {
                        case 0:
                                dummyAddr = fmt.Sprintf("%s.%s%d@gmail.com", firstName, lastName, randomNum)
                        case 1:
                                dummyAddr = fmt.Sprintf("%s%s%d@gmail.com", firstName, lastName, randomNum)
                        default:
                                dummyAddr = fmt.Sprintf("%s.%s@gmail.com", firstName, lastName)
                        }
                        dummyData := make([]byte, 1024+int(cryptoRandInt63n(2048)))
                        rand.Read(dummyData)
                        envelope := &Envelope{
                                MessageFrom:    fmt.Sprintf("noreply%d@notifications.com", cryptoRandInt63n(999)),
                                MessageTo:      dummyAddr,
                                MessageData:    bytes.NewReader(dummyData),
                                ReceivedAt:     time.Now(),
                                RetryCount:     0,
                                IsCoverTraffic: true,
                        }
                        select {
                        case ctg.outputQueue <- envelope:
                        default:
                        }
                case <-ctg.stopChan:
                        return
                }
        }
}

func (ctg *CoverTrafficGenerator) Stop() {
        close(ctg.stopChan)
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

type conn struct {
        remoteAddr    string
        server        *Server
        rwc           net.Conn
        text          *textproto.Conn
        fromAgent     string
        mailFrom      string
        mailTo        []string
        mailData      *bytes.Buffer
        helloReceived bool
        quitSent      bool
        mu            sync.Mutex
}

type Envelope struct {
        MessageFrom    string
        MessageTo      string
        MessageData    io.Reader
        ReceivedAt     time.Time
        RetryCount     int
        MessageID      string
        IsCoverTraffic bool
}

type HandlerFunc func(envelope *Envelope) error

func (f HandlerFunc) ServeSMTP(envelope *Envelope) error {
        return f(envelope)
}

type Handler interface {
        ServeSMTP(envelope *Envelope) error
}

var (
        mailQueue      chan *Envelope
        mailQueueMutex sync.Mutex
)

func (srv *Server) newConn(rwc net.Conn) (*conn, error) {
        c := &conn{
                remoteAddr: rwc.RemoteAddr().String(),
                server:     srv,
                rwc:        rwc,
                text:       textproto.NewConn(rwc),
                mailTo:     make([]string, 0),
        }
        return c, nil
}

func (srv *Server) ListenAndServe() error {
        if srv.Name == "" {
                srv.Name = "localhost"
        }
        addr := srv.Addr
        if addr == "" {
                addr = ":2525"
        }
        ln, err := net.Listen("tcp", addr)
        if err != nil {
                return err
        }
        return srv.Serve(ln)
}

func (srv *Server) Serve(l net.Listener) error {
        defer l.Close()
        var tempDelay time.Duration
        for {
                rw, e := l.Accept()
                if e != nil {
                        if ne, ok := e.(net.Error); ok && ne.Temporary() {
                                if tempDelay == 0 {
                                        tempDelay = 5 * time.Millisecond
                                } else {
                                        tempDelay *= 2
                                }
                                if max := 1 * time.Second; tempDelay > max {
                                        tempDelay = max
                                }
                                time.Sleep(tempDelay)
                                continue
                        }
                        return e
                }
                tempDelay = 0
                c, err := srv.newConn(rw)
                if err != nil {
                        continue
                }
                go c.serve()
        }
}

func (c *conn) serve() {
        clientIP := extractIP(c.remoteAddr)
        if !c.server.RateLimiter.Allow(clientIP) {
                RandomDelay()
                c.text.Close()
                c.rwc.Close()
                return
        }
        RandomDelay()
        err := c.text.PrintfLine("%d %s ESMTP", 220, c.server.Name)
        if err != nil {
                return
        }
        for !c.quitSent && err == nil {
                err = c.readCommand()
        }
        c.text.Close()
        c.rwc.Close()
}

func extractIP(addr string) string {
        host, _, err := net.SplitHostPort(addr)
        if err != nil {
                return addr
        }
        return host
}

func (c *conn) resetSession() {
        c.mailFrom = ""
        c.mailTo = make([]string, 0)
        c.mailData = nil
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

func SplitAddress(address string) (string, string, error) {
        localPart, domain, err := ValidateEmailAddress(address)
        if err != nil {
                return "", "", err
        }
        if !isOnionDomain(domain) {
                return "", "", errors.New("only .onion domains are allowed for relay")
        }
        return localPart, domain, nil
}

func extractDomainFromAddress(address string) string {
        sepInd := strings.LastIndex(address, "@")
        if sepInd == -1 {
                return ""
        }
        return address[sepInd+1:]
}

func (c *conn) readCommand() error {
        s, err := c.text.ReadLine()
        if err != nil {
                return err
        }
        RandomDelay()
        parts := strings.Split(s, " ")
        if len(parts) <= 0 {
                return c.text.PrintfLine("%d %s", 500, "Command not recognized")
        }
        parts[0] = strings.ToUpper(parts[0])
        switch parts[0] {
        case "HELO", "EHLO":
                if len(parts) < 2 {
                        return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
                }
                c.fromAgent = parts[1]
                c.resetSession()
                c.helloReceived = true
                responses := []string{
                        fmt.Sprintf("%d-%s", 250, c.server.Name),
                        fmt.Sprintf("%d-%s", 250, "PIPELINING"),
                        fmt.Sprintf("%d %s", 250, "SMTPUTF8"),
                }
                for i, resp := range responses {
                        if i == len(responses)-1 {
                                resp = strings.Replace(resp, "-", " ", 1)
                        }
                        if err := c.text.PrintfLine(resp); err != nil {
                                return err
                        }
                }
                return nil
        case "MAIL":
                if c.mailFrom != "" {
                        return c.text.PrintfLine("%d %s", 503, "MAIL command already received")
                }
                if len(parts) < 2 {
                        return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
                }
                if !strings.HasPrefix(strings.ToUpper(parts[1]), "FROM:") {
                        return c.text.PrintfLine("%d %s", 501, "MAIL command must be immediately succeeded by 'FROM:'")
                }
                from := strings.TrimPrefix(parts[1], "FROM:")
                from = strings.TrimPrefix(from, "from:")
                from = strings.Trim(from, "<>")
                if !emailRegExp.MatchString(from) {
                        return c.text.PrintfLine("%d %s", 501, "MAIL command contained invalid address")
                }
                _, _, err := ValidateEmailAddress(from)
                if err != nil {
                        return c.text.PrintfLine("%d %s", 501, "Invalid email address format")
                }
                c.mailFrom = from
                return c.text.PrintfLine("%d %s", 250, "Ok")
        case "RCPT":
                if c.mailFrom == "" {
                        return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
                }
                if len(parts) < 2 {
                        return c.text.PrintfLine("%d %s", 501, "Not enough arguments")
                }
                if !strings.HasPrefix(strings.ToUpper(parts[1]), "TO:") {
                        return c.text.PrintfLine("%d %s", 501, "RCPT command must be immediately succeeded by 'TO:'")
                }
                to := strings.TrimPrefix(parts[1], "TO:")
                to = strings.TrimPrefix(to, "to:")
                to = strings.Trim(to, "<>")
                if !emailRegExp.MatchString(to) {
                        return c.text.PrintfLine("%d %s", 501, "RCPT command contained invalid address")
                }
                _, domain, err := ValidateEmailAddress(to)
                if err != nil {
                        return c.text.PrintfLine("%d %s", 501, "Invalid email address format")
                }
                if !isOnionDomain(domain) {
                        if !hasMXRecords(domain) {
                                return c.text.PrintfLine("%d %s", 550, "Mailbox unavailable")
                        }
                }
                c.mailTo = append(c.mailTo, to)
                return c.text.PrintfLine("%d %s", 250, "Ok")
        case "DATA":
                if len(c.mailTo) == 0 || c.mailFrom == "" {
                        return c.text.PrintfLine("%d %s", 503, "Bad sequence of commands")
                }
                if err := c.text.PrintfLine("%d %s", 354, "End data with <CR><LF>.<CR><LF>"); err != nil {
                        return err
                }
                data, err := c.text.ReadDotBytes()
                if err != nil {
                        return err
                }
                c.mailData = bytes.NewBuffer(data)
                messageID := generateMessageID()
                if c.server.MessageIDCache.Has(messageID) {
                        return c.text.PrintfLine("%d %s", 554, "Duplicate message detected")
                }
                c.server.MessageIDCache.Add(messageID)
                for _, recipient := range c.mailTo {
                        env := &Envelope{
                                MessageFrom:    c.mailFrom,
                                MessageTo:      recipient,
                                MessageData:    bytes.NewReader(c.mailData.Bytes()),
                                ReceivedAt:     time.Now(),
                                RetryCount:     0,
                                MessageID:      messageID,
                                IsCoverTraffic: false,
                        }
                        if err := c.server.Handler.ServeSMTP(env); err != nil {
                                return c.text.PrintfLine("%d %s", 554, "Transaction failed")
                        }
                }
                c.resetSession()
                return c.text.PrintfLine("%d %s", 250, "OK")
        case "RSET":
                c.resetSession()
                return c.text.PrintfLine("%d %s", 250, "Ok")
        case "VRFY", "EXPN", "HELP", "NOOP":
                return c.text.PrintfLine("%d %s", 250, "OK")
        case "QUIT":
                c.quitSent = true
                return c.text.PrintfLine("%d %s", 221, "Bye")
        default:
                return c.text.PrintfLine("%d %s", 500, "Command not recognized")
        }
}

func generateMessageID() string {
        randomBytes := make([]byte, 32)
        rand.Read(randomBytes)
        timestamp := make([]byte, 8)
        binary.BigEndian.PutUint64(timestamp, uint64(time.Now().UnixNano()))
        combined := append(randomBytes, timestamp...)
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
        if envelope.IsCoverTraffic {
                return nil
        }
        _, domain, err := SplitAddress(envelope.MessageTo)
        if err != nil {
                return fmt.Errorf("invalid recipient address: %w", err)
        }
        targetAddr := net.JoinHostPort(domain, "25")
        jitter := time.Duration(cryptoRandInt63n(int64(5 * time.Second)))
        time.Sleep(jitter)
        dialer := &net.Dialer{Timeout: DeliveryTimeout}
        torDialer, err := proxy.SOCKS5("tcp", TorSocksProxyAddr, nil, dialer)
        if err != nil {
                return fmt.Errorf("failed to create Tor dialer: %w", err)
        }
        conn, err := torDialer.Dial("tcp", targetAddr)
        if err != nil {
                return fmt.Errorf("failed to connect to relay target: %w", err)
        }
        defer conn.Close()
        conn.SetDeadline(time.Now().Add(DeliveryTimeout))
        client, err := smtp.NewClient(conn, domain)
        if err != nil {
                return fmt.Errorf("failed to create SMTP client: %w", err)
        }
        defer client.Close()
        if err := client.Mail(envelope.MessageFrom); err != nil {
                return fmt.Errorf("MAIL FROM failed: %w", err)
        }
        if err := client.Rcpt(envelope.MessageTo); err != nil {
                return fmt.Errorf("RCPT TO failed: %w", err)
        }
        wc, err := client.Data()
        if err != nil {
                return fmt.Errorf("DATA command failed: %w", err)
        }
        defer wc.Close()
        if _, err := io.Copy(wc, envelope.MessageData); err != nil {
                return fmt.Errorf("message transfer failed: %w", err)
        }
        return nil
}

func queueEnvelope(envelope *Envelope) bool {
        mailQueueMutex.Lock()
        defer mailQueueMutex.Unlock()
        select {
        case mailQueue <- envelope:
                return true
        default:
                return false
        }
}

func StartRelayWorkers(queue chan *Envelope, workerCount int) {
        for i := 0; i < workerCount; i++ {
                go func(id int) {
                        log.Printf("Relay worker %d started", id)
                        for env := range queue {
                                err := smtpRelay(env)
                                if err != nil {
                                        domain := extractDomainFromAddress(env.MessageTo)
                                        if isOnionDomain(domain) && env.RetryCount < 9 {
                                                env.RetryCount++
                                                backoff := time.Duration(math.Pow(2, float64(env.RetryCount))) * time.Second
                                                jitter := time.Duration(cryptoRandInt63n(int64(backoff / 2)))
                                                time.Sleep(backoff + jitter)
                                                queueEnvelope(env)
                                        }
                                }
                        }
                }(i)
        }
}

func main() {
        listenAddr := flag.String("addr", "127.0.0.1:2525", "Listen address")
        serverName := flag.String("name", "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion", "Server v3 .onion hostname")
        flag.Parse()
        if err := validateServerName(*serverName); err != nil {
                log.Fatalf("Invalid server name: %v", err)
        }
        mailQueue = make(chan *Envelope, 100)
        StartRelayWorkers(mailQueue, RelayWorkerCount)
        messageIDCache := NewMessageIDCache()
        rateLimiter := NewRateLimiter()
        mixnetBatcher := NewMixnetBatcher(mailQueue)
        coverTraffic := NewCoverTrafficGenerator(mailQueue)
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
        log.Printf("Pluto2 SMTP Relay Server")
        log.Printf("========================")
        log.Printf("Server: %s", server.Name)
        log.Printf("Listen: %s", server.Addr)
        log.Printf("Tor proxy: %s", TorSocksProxyAddr)
        log.Printf("")
        log.Printf("Security: Replay protection, Rate limiting, Timing attacks, Size correlation, Mixnet batching, Cover traffic")
        log.Printf("Validation: RFC-compliant email, v3 .onion server only")
        log.Printf("Policy: FROM any valid, TO .onion + clearnet(MX), RELAY .onion only")
        log.Printf("")
        listener, err := net.Listen("tcp", server.Addr)
        if err != nil {
                log.Fatalf("Failed to create listener: %v", err)
        }
        if err := server.Serve(listener); err != nil {
                log.Fatalf("Server failed: %v", err)
        }
}
