package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.halvorai.com/ingest/jcs"
)

// Version is the SDK version, reported in every event's source.sdk.
const Version = "0.1.0"

// SDKName is the value of source.sdk in every event.
const SDKName = "go.halvorai.com/ingest@" + Version

const (
	// ProductionEndpoint receives events for hk_live_ keys.
	ProductionEndpoint = "https://api.halvorai.com"
	// SandboxEndpoint receives events for hk_test_ keys.
	SandboxEndpoint = "https://api.sandbox.halvorai.com"

	defaultBatchSize     = 100
	defaultFlushInterval = time.Second
)

// DefaultRetryDelays is the backoff before each retry; up to 20 % jitter is added.
var DefaultRetryDelays = []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}

var apiKeyPattern = regexp.MustCompile(`^hk_(test|live)_[0-9A-Za-z]{32}$`)

// Statuses retried with backoff, and statuses that fail the same way however often a batch is
// sent. The same lists as the Node.js and Python SDKs.
var (
	retryStatuses = map[int]bool{408: true, 425: true, 429: true, 500: true, 502: true, 503: true, 504: true}
	fatalStatuses = map[int]bool{400: true, 401: true, 403: true, 404: true, 405: true, 409: true, 410: true, 415: true, 422: true}
)

// Error codes passed to [Config.OnError].
const (
	CodeConfig         = "config"
	CodeInvalidEvent   = "invalid_event"
	CodeRejected       = "rejected"
	CodeUnauthorized   = "unauthorized"
	CodeDeliveryFailed = "delivery_failed"
	CodeSpool          = "spool"
)

// Error is a problem reported through [Config.OnError]. Emit never returns errors; everything
// that goes wrong later is reported here.
type Error struct {
	Code    string
	Message string
	// ServerCode is the API's error code, such as invalid_signature or unknown_source.
	ServerCode string
	RequestID  string
	EventID    string
	Details    any
}

func (e Error) Error() string {
	var b strings.Builder
	b.WriteString("halvorai: ")
	b.WriteString(e.Code)
	if e.ServerCode != "" {
		b.WriteString(" (" + e.ServerCode + ")")
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	return b.String()
}

// Stats are the client's counters. Every emitted event ends up in exactly one of accepted,
// duplicates, rejected, dropped or a dropped_* counter, or is still queued or spooled.
type Stats struct {
	Emitted    int `json:"emitted"`
	Queued     int `json:"queued"`
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
	Rejected   int `json:"rejected"`
	// Dropped counts events the API will never accept, or that could not be delivered or spooled.
	Dropped         int `json:"dropped"`
	DroppedInvalid  int `json:"dropped_invalid"`
	DroppedDisabled int `json:"dropped_disabled"`
	DroppedClosed   int `json:"dropped_closed"`
	Retries         int `json:"retries"`
	Spooled         int `json:"spooled"`
	Replayed        int `json:"replayed"`
}

// Config configures a [Client]. The zero value reads HALVOR_API_KEY, HALVOR_SOURCE_KEY and
// HALVOR_ENDPOINT from the environment.
type Config struct {
	// APIKey is an hk_test_ or hk_live_ key. Defaults to HALVOR_API_KEY.
	APIKey string
	// SourceKey is the source's private Ed25519 JWK; its kid is the src_ id HalvorAI issued.
	// Defaults to the JSON in HALVOR_SOURCE_KEY.
	SourceKey *JWK
	// Environment is "test" or "live". Defaults to the key's environment, else "test".
	Environment string
	// Endpoint is the API's base URL. Defaults to HALVOR_ENDPOINT, else the sandbox for test
	// keys and production for live keys.
	Endpoint string
	// Sink receives signed envelopes instead of the API (offline mode, tests, custom transports).
	// An error is retried like a network error.
	Sink func(ctx context.Context, envelopes []Envelope) error
	// BatchSize is the most events per request (default and maximum 100).
	BatchSize int
	// FlushInterval is how long events wait to be batched (default 1 s).
	FlushInterval time.Duration
	// RetryDelays is the backoff before each retry. nil means DefaultRetryDelays; an empty,
	// non-nil slice disables retries.
	RetryDelays []time.Duration
	// SpoolDir keeps batches that could not be delivered on disk, to be sent again later.
	SpoolDir string
	// SpoolMaxBytes and SpoolMaxAge limit the spool (defaults 50 MB and 7 days); the oldest
	// files are evicted first.
	SpoolMaxBytes int64
	SpoolMaxAge   time.Duration
	// OnError is called from the client's goroutines with every problem. It must not block.
	OnError func(Error)
	// HTTPClient sends requests (default: a client with a 30 s timeout).
	HTTPClient *http.Client
	// RedactPatterns are removed from free-text fields as well as the built-in patterns.
	RedactPatterns []RedactPattern
}

// Client queues, signs and delivers Agent Payment Events. It is safe for concurrent use.
//
// Emit never blocks on I/O: a background goroutine batches events for one FlushInterval,
// signs them, sends them, retries on network errors, 408, 425, 429 and 5xx, and spools what it
// cannot deliver. Call [Client.Close] before the process exits; Go has no exit hook, so events
// still queued are otherwise lost.
type Client struct {
	cfg       Config
	sourceKey JWK
	sourceID  string
	spool     *spool
	http      *http.Client
	batchSize int
	interval  time.Duration
	retries   []time.Duration

	mu              sync.Mutex
	changed         chan struct{} // closed and replaced on every state change
	wake            chan struct{}
	queue           []map[string]any
	inflight        int
	sendNow         bool
	replayRequested bool
	spoolCooldown   time.Time
	workerRunning   bool
	stopping        bool
	closed          bool
	disabled        bool
	configReported  bool
	stats           Stats
}

// DefaultEndpoint is where events go for a key: production for live keys, the sandbox otherwise.
func DefaultEndpoint(apiKey, environment string) string {
	if apiKey != "" {
		if strings.HasPrefix(apiKey, "hk_live_") {
			return ProductionEndpoint
		}
		return SandboxEndpoint
	}
	if environment == "live" {
		return ProductionEndpoint
	}
	return SandboxEndpoint
}

func eventsURL(endpoint string) string {
	base := strings.TrimRight(endpoint, "/")
	if strings.HasSuffix(base, "/v1/events") {
		return base
	}
	return base + "/v1/events"
}

// NewClient creates a client. It never fails: a missing or malformed key disables the client,
// reports one CodeConfig error and counts emitted events as DroppedDisabled, so a configuration
// mistake can never break the payment path.
func NewClient(cfg Config) *Client {
	c := &Client{
		cfg:     cfg,
		changed: make(chan struct{}),
		wake:    make(chan struct{}, 1),
		http:    cfg.HTTPClient,
	}
	if c.cfg.APIKey == "" {
		c.cfg.APIKey = os.Getenv("HALVOR_API_KEY")
	}
	if c.cfg.Endpoint == "" {
		c.cfg.Endpoint = os.Getenv("HALVOR_ENDPOINT")
	}
	if c.cfg.Environment == "" {
		c.cfg.Environment = "test"
		if strings.HasPrefix(c.cfg.APIKey, "hk_live_") {
			c.cfg.Environment = "live"
		}
	}
	if c.cfg.Endpoint == "" {
		c.cfg.Endpoint = DefaultEndpoint(c.cfg.APIKey, c.cfg.Environment)
	}
	c.batchSize = cfg.BatchSize
	if c.batchSize <= 0 || c.batchSize > defaultBatchSize {
		c.batchSize = defaultBatchSize
	}
	c.interval = cfg.FlushInterval
	if c.interval <= 0 {
		c.interval = defaultFlushInterval
	}
	c.retries = cfg.RetryDelays
	if c.retries == nil {
		c.retries = DefaultRetryDelays
	}
	if c.http == nil {
		c.http = &http.Client{Timeout: 30 * time.Second}
	}

	key := cfg.SourceKey
	if key == nil {
		if raw := os.Getenv("HALVOR_SOURCE_KEY"); raw != "" {
			if parsed, err := ParseJWK(raw); err == nil {
				key = &parsed
			}
		}
	}
	switch {
	case key == nil || key.Kid == "":
		c.disable("source key is missing or has no kid; set Config.SourceKey or HALVOR_SOURCE_KEY")
	default:
		if _, err := key.privateKey(); err != nil {
			c.disable("source key is not a private Ed25519 JWK: " + err.Error())
		} else {
			c.sourceKey = *key
			c.sourceID = key.Kid
		}
	}
	if !c.disabled && cfg.Sink == nil && !apiKeyPattern.MatchString(c.cfg.APIKey) {
		c.disable("API key is missing or malformed (expected hk_test_… or hk_live_…)")
	}

	if cfg.SpoolDir != "" {
		c.spool = &spool{dir: cfg.SpoolDir, maxBytes: cfg.SpoolMaxBytes, maxAge: cfg.SpoolMaxAge}
		if c.spool.maxBytes <= 0 {
			c.spool.maxBytes = DefaultSpoolMaxBytes
		}
		if c.spool.maxAge <= 0 {
			c.spool.maxAge = DefaultSpoolMaxAge
		}
		if !c.disabled && len(c.spool.files()) > 0 {
			// Replay what a previous process left behind.
			c.mu.Lock()
			c.replayRequested = true
			c.ensureWorker()
			c.mu.Unlock()
		}
	}
	return c
}

func (c *Client) disable(message string) {
	c.disabled = true
	if !c.configReported {
		c.configReported = true
		c.notify(Error{Code: CodeConfig, Message: message})
	}
}

// Notify passes err to Config.OnError. Adapters use it to report events they could not map.
func (c *Client) Notify(err Error) { c.notify(err) }

func (c *Client) notify(err Error) {
	if c.cfg.OnError == nil {
		return
	}
	defer func() { _ = recover() }()
	c.cfg.OnError(err)
}

// Stats returns a snapshot of the counters.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Queued = len(c.queue) + c.inflight
	return s
}

func (c *Client) count(fn func(*Stats)) {
	c.mu.Lock()
	fn(&c.stats)
	c.mu.Unlock()
}

// broadcast wakes everyone waiting on a state change. Call with mu held.
func (c *Client) broadcast() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *Client) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// Emit queues one event and returns its id at once. It never returns an error, never panics
// and never waits for the network or the disk. event is an [Event], a *Event or a
// map[string]any. Agent, owner and instruction come from ctx (see [WithAgentContext]) when the
// event leaves them out.
func (c *Client) Emit(ctx context.Context, event any) (id string) {
	id = NewEventID()
	defer func() {
		if r := recover(); r != nil {
			c.count(func(s *Stats) { s.Emitted++; s.DroppedInvalid++ })
			c.notify(Error{Code: CodeInvalidEvent, Message: fmt.Sprint("emit failed: ", r), EventID: id})
		}
	}()
	c.mu.Lock()
	closed, disabled := c.closed, c.disabled
	c.mu.Unlock()
	if closed {
		c.count(func(s *Stats) { s.Emitted++; s.DroppedClosed++ })
		return id
	}
	if disabled {
		c.count(func(s *Stats) { s.Emitted++; s.DroppedDisabled++ })
		return id
	}
	input, err := toMap(event)
	if err != nil {
		c.count(func(s *Stats) { s.Emitted++; s.DroppedInvalid++ })
		c.notify(Error{Code: CodeInvalidEvent, Message: err.Error(), EventID: id})
		return id
	}
	if given, ok := input["id"].(string); ok && given != "" {
		id = given
	}
	ac, _ := AgentContextFrom(ctx)
	built := c.buildEvent(input, ac, id)
	c.redactEvent(built)
	if problems := ValidateEvent(built); len(problems) > 0 {
		c.count(func(s *Stats) { s.Emitted++; s.DroppedInvalid++ })
		c.notify(Error{Code: CodeInvalidEvent, Message: "event failed schema validation", EventID: id, Details: problems})
		return id
	}
	c.mu.Lock()
	c.queue = append(c.queue, built)
	c.stats.Emitted++
	c.ensureWorker()
	if len(c.queue) >= c.batchSize {
		c.sendNow = true
		c.signal()
	}
	c.mu.Unlock()
	return id
}

// toMap turns an Event, *Event or map into a decoded JSON object the client owns.
func toMap(event any) (map[string]any, error) {
	if event == nil {
		return nil, fmt.Errorf("event is nil")
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("event is not JSON: %w", err)
	}
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("event must be an object")
	}
	return m, nil
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func structToMap(v any) map[string]any {
	m, err := toMap(v)
	if err != nil {
		return nil
	}
	return m
}

var instructionFields = []string{"id", "hash", "summary", "channel", "issued_at", "tool_call_id"}

func (c *Client) buildEvent(in map[string]any, ac AgentContext, id string) map[string]any {
	source := map[string]any{"id": c.sourceID, "sdk": SDKName, "adapter": "custom"}
	for k, v := range asMap(in["source"]) {
		source[k] = v
	}
	source["id"], source["sdk"] = c.sourceID, SDKName

	agent := asMap(in["agent"])
	if agent == nil && ac.Agent != nil {
		agent = structToMap(ac.Agent)
	}
	if agent == nil {
		agent = map[string]any{"id": "unattributed"}
	}
	owner := asMap(in["owner"])
	if owner == nil && ac.Owner != nil {
		owner = structToMap(ac.Owner)
	}
	if owner == nil {
		owner = map[string]any{"id": "unattributed", "type": "business"}
	}
	occurredAt, _ := in["occurred_at"].(string)
	if occurredAt == "" {
		occurredAt = NowUTC()
	}
	environment, _ := in["environment"].(string)
	if environment == "" {
		environment = c.cfg.Environment
	}
	event := map[string]any{
		"ape_version": APEVersion,
		"id":          id,
		"type":        in["type"],
		"occurred_at": occurredAt,
		"environment": environment,
		"source":      source,
		"agent":       agent,
		"owner":       owner,
		"payment":     in["payment"],
		"payee":       in["payee"],
	}
	instruction := asMap(in["instruction"])
	if instruction == nil && ac.Instruction != nil {
		instruction = structToMap(ac.Instruction)
	}
	if built := buildInstruction(instruction); built != nil {
		event["instruction"] = built
	}
	for _, key := range []string{"instrument", "evidence", "related", "labels"} {
		if v, ok := in[key]; ok && v != nil {
			event[key] = v
		}
	}
	if evidence, ok := event["evidence"].([]any); ok {
		for _, item := range evidence {
			e := asMap(item)
			if e == nil {
				continue
			}
			if _, has := e["sha256"]; !has {
				if value, ok := e["value"]; ok && value != nil {
					if digest, err := EvidenceSHA256(value); err == nil {
						e["sha256"] = digest
					}
				}
			}
		}
	}
	return event
}

// buildInstruction keeps only the APE instruction fields; text is hashed locally and dropped.
func buildInstruction(raw map[string]any) map[string]any {
	if raw == nil {
		return nil
	}
	if id, _ := raw["id"].(string); id == "" {
		return nil
	}
	hash, _ := raw["hash"].(string)
	if hash == "" {
		if text, ok := raw["text"].(string); ok {
			hash = HashInstruction(text)
		}
	}
	if hash == "" {
		return nil
	}
	out := map[string]any{}
	for _, key := range instructionFields {
		if key == "hash" {
			out[key] = hash
		} else if s, ok := raw[key].(string); ok && s != "" {
			out[key] = s
		}
	}
	return out
}

func (c *Client) redactEvent(event map[string]any) {
	extra := c.cfg.RedactPatterns
	redactField := func(obj map[string]any, key string) {
		if s, ok := obj[key].(string); ok {
			obj[key] = RedactText(s, extra...)
		}
	}
	if p := asMap(event["payment"]); p != nil {
		for _, key := range []string{"description", "category", "failure_reason"} {
			redactField(p, key)
		}
	}
	for _, path := range [][2]string{{"agent", "name"}, {"owner", "display_name"}, {"payee", "name"}, {"payee", "website"}, {"payee", "resource_url"}, {"instruction", "summary"}} {
		if parent := asMap(event[path[0]]); parent != nil {
			redactField(parent, path[1])
		}
	}
	if labels := asMap(event["labels"]); labels != nil {
		out := make(map[string]any, len(labels))
		for k, v := range labels {
			out[RedactText(k, extra...)] = RedactDeep(v, extra...)
		}
		event["labels"] = out
	}
	if evidence, ok := event["evidence"].([]any); ok {
		for _, item := range evidence {
			e := asMap(item)
			if e == nil || e["format"] != "json" {
				continue
			}
			if value, ok := e["value"]; ok && value != nil {
				e["value"] = RedactDeep(value, extra...)
				if digest, err := EvidenceSHA256(e["value"]); err == nil {
					e["sha256"] = digest
				}
			}
		}
	}
}

// ensureWorker starts the background goroutine. Call with mu held.
func (c *Client) ensureWorker() {
	if !c.workerRunning {
		c.workerRunning = true
		c.stopping = c.closed // a flush after Close still stops the goroutine when done
		go c.run()
	}
}

func (c *Client) idle() bool { return !c.sendNow && !c.replayRequested }

func (c *Client) run() {
	for {
		c.mu.Lock()
		if c.idle() && len(c.queue) < c.batchSize {
			if c.stopping && len(c.queue) == 0 {
				c.workerRunning = false
				c.broadcast()
				c.mu.Unlock()
				return
			}
			// Batch up for one interval; a full batch, Flush or Close wakes the worker early.
			c.mu.Unlock()
			timer := time.NewTimer(c.interval)
			select {
			case <-c.wake:
			case <-timer.C:
			}
			timer.Stop()
			c.mu.Lock()
		}
		replay := c.replayRequested && !time.Now().Before(c.spoolCooldown)
		n := min(len(c.queue), c.batchSize)
		batch := c.queue[:n:n]
		c.queue = append([]map[string]any(nil), c.queue[n:]...)
		c.inflight += len(batch)
		c.mu.Unlock()

		c.work(replay, batch)

		c.mu.Lock()
		c.inflight -= len(batch)
		if replay {
			c.replayRequested = false
		}
		if len(c.queue) == 0 {
			c.sendNow = false
			if !replay && c.replayRequested && time.Now().Before(c.spoolCooldown) {
				// The spool is cooling down after an outage; don't hold Flush for it.
				c.replayRequested = false
			}
		}
		c.broadcast()
		c.mu.Unlock()
	}
}

func (c *Client) work(replay bool, batch []map[string]any) {
	defer func() {
		if r := recover(); r != nil { // the worker must never die
			c.notify(Error{Code: CodeDeliveryFailed, Message: fmt.Sprint("worker error: ", r)})
		}
	}()
	if replay {
		c.replaySpool()
	}
	if len(batch) > 0 {
		pending, reason := c.deliver(c.sign(batch))
		c.park(pending, reason)
	}
}

// Flush sends everything queued and waits until it is delivered, dropped or spooled, or until
// ctx is done. It also replays the spool. It reports whether everything was handled.
//
// Without a deadline it waits for the whole retry schedule (about a minute per batch while
// the API is down). In request handlers and serverless functions pass a context with a timeout.
func (c *Client) Flush(ctx context.Context) bool { return c.flush(ctx, true) }

func (c *Client) flush(ctx context.Context, replaySpool bool) bool {
	if ctx == nil {
		ctx = context.Background()
	}
	c.mu.Lock()
	if !c.workerRunning && len(c.queue) == 0 && !(replaySpool && c.spool != nil && !c.disabled) {
		c.mu.Unlock()
		return true
	}
	c.sendNow = true
	if replaySpool && c.spool != nil && !c.disabled {
		c.replayRequested = true
		c.spoolCooldown = time.Time{}
	}
	c.ensureWorker()
	c.signal()
	for len(c.queue) > 0 || c.inflight > 0 || c.sendNow || c.replayRequested {
		ch := c.changed
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
		c.mu.Lock()
	}
	c.mu.Unlock()
	return true
}

// Close refuses new events, sends what is queued (the spool stays on disk for the next
// process) and stops the background goroutine. It returns ctx.Err() if ctx ended first.
//
//	defer func() {
//		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//		defer cancel()
//		client.Close(ctx)
//	}()
func (c *Client) Close(ctx context.Context) error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	drained := c.flush(ctx, false)
	c.mu.Lock()
	c.stopping = true
	c.signal()
	c.mu.Unlock()
	if !drained {
		return ctx.Err()
	}
	return nil
}

func (c *Client) sign(events []map[string]any) []Envelope {
	envelopes := make([]Envelope, 0, len(events))
	for _, event := range events {
		sig, err := SignEvent(event, c.sourceKey)
		if err != nil {
			id, _ := event["id"].(string)
			c.count(func(s *Stats) { s.DroppedInvalid++ })
			c.notify(Error{Code: CodeInvalidEvent, Message: err.Error(), EventID: id})
			continue
		}
		envelopes = append(envelopes, Envelope{Event: event, Sig: sig})
	}
	return envelopes
}

// deliver returns the envelopes to try again later. Everything else is settled.
func (c *Client) deliver(envelopes []Envelope) ([]Envelope, string) {
	if len(envelopes) == 0 {
		return nil, ""
	}
	if c.cfg.Sink != nil {
		return c.deliverSink(envelopes)
	}
	return c.deliverHTTP(envelopes)
}

func (c *Client) sleepBeforeRetry(attempt int) {
	c.count(func(s *Stats) { s.Retries++ })
	base := c.retries[attempt]
	time.Sleep(base + time.Duration(rand.Float64()*0.2*float64(base)))
}

func (c *Client) deliverSink(envelopes []Envelope) (pending []Envelope, reason string) {
	for attempt := 0; ; attempt++ {
		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("sink panicked: %v", r)
				}
			}()
			return c.cfg.Sink(context.Background(), envelopes)
		}()
		if err == nil {
			c.count(func(s *Stats) { s.Accepted += len(envelopes) })
			return nil, ""
		}
		if attempt >= len(c.retries) {
			return envelopes, err.Error()
		}
		c.sleepBeforeRetry(attempt)
	}
}

type outcome struct {
	kind    string // ok, retry, fatal, too_large
	status  int
	results []any
	err     Error
}

func (c *Client) deliverHTTP(envelopes []Envelope) ([]Envelope, string) {
	for attempt := 0; ; attempt++ {
		out := c.post(envelopes)
		switch out.kind {
		case "ok":
			c.applyResults(envelopes, out.results)
			return nil, ""
		case "too_large":
			if len(envelopes) == 1 {
				e := out.err
				if e.ServerCode == "" {
					e.ServerCode = "payload_too_large"
				}
				e.Message = "event is larger than the API accepts"
				c.dropFatal(envelopes, CodeDeliveryFailed, e)
				return nil, ""
			}
			mid := (len(envelopes) + 1) / 2
			left, leftReason := c.deliverHTTP(envelopes[:mid])
			right, rightReason := c.deliverHTTP(envelopes[mid:])
			if rightReason == "" {
				rightReason = leftReason
			}
			return append(left, right...), rightReason
		case "fatal":
			code := CodeDeliveryFailed
			if out.status == 401 || out.status == 403 {
				code = CodeUnauthorized
			}
			c.dropFatal(envelopes, code, out.err)
			return nil, ""
		}
		if attempt >= len(c.retries) {
			return envelopes, out.err.Message
		}
		c.sleepBeforeRetry(attempt)
	}
}

func (c *Client) post(envelopes []Envelope) outcome {
	events := make([]any, len(envelopes))
	for i, e := range envelopes {
		events[i] = map[string]any{"event": e.Event, "sig": e.Sig}
	}
	// The canonical form keeps every string and number exactly as signed.
	body, err := jcs.Canonicalize(map[string]any{"events": events})
	if err != nil {
		return outcome{kind: "fatal", err: Error{Message: err.Error()}}
	}
	req, err := http.NewRequest(http.MethodPost, eventsURL(c.cfg.Endpoint), bytes.NewReader([]byte(body)))
	if err != nil {
		return outcome{kind: "fatal", err: Error{Message: err.Error()}}
	}
	req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "halvorai-ingest-go/"+Version)
	res, err := c.http.Do(req)
	if err != nil {
		return outcome{kind: "retry", err: Error{Message: err.Error()}}
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	status := res.StatusCode
	switch {
	case status == http.StatusRequestEntityTooLarge:
		return outcome{kind: "too_large", status: status, err: readError(res, raw)}
	case fatalStatuses[status]:
		return outcome{kind: "fatal", status: status, err: readError(res, raw)}
	case retryStatuses[status] || status < 200 || status >= 300:
		return outcome{kind: "retry", status: status, err: readError(res, raw)}
	}
	var parsed struct {
		Results []any `json:"results"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return outcome{kind: "retry", status: status, err: Error{Message: "invalid response body"}}
	}
	return outcome{kind: "ok", status: status, results: parsed.Results}
}

// readError reads the API's error body, {"error":{"code","message","details","request_id"}}.
func readError(res *http.Response, raw []byte) Error {
	text := strings.TrimSpace(string(raw))
	if len(text) > 500 {
		text = text[:500]
	}
	if text == "" {
		text = fmt.Sprintf("HTTP %d", res.StatusCode)
	}
	out := Error{Message: text, RequestID: res.Header.Get("request-id")}
	var body struct {
		Error *struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			Details   []any  `json:"details"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Error != nil {
		if body.Error.Message != "" {
			out.Message = body.Error.Message
		}
		out.ServerCode = body.Error.Code
		if body.Error.Details != nil {
			out.Details = body.Error.Details
		}
		if body.Error.RequestID != "" {
			out.RequestID = body.Error.RequestID
		}
	}
	return out
}

// applyResults counts each event by the status the API gave it.
func (c *Client) applyResults(envelopes []Envelope, results []any) {
	byID := map[string]map[string]any{}
	for _, r := range results {
		if m := asMap(r); m != nil {
			if id, ok := m["id"].(string); ok {
				byID[id] = m
			}
		}
	}
	for _, e := range envelopes {
		id, _ := e.Event["id"].(string)
		result := byID[id]
		status, _ := result["status"].(string)
		c.count(func(s *Stats) {
			switch status {
			case "duplicate":
				s.Duplicates++
			case "rejected":
				s.Rejected++
			default:
				s.Accepted++
			}
		})
		if status == "rejected" {
			report := Error{Code: CodeRejected, Message: "server rejected event", EventID: id}
			if server := asMap(result["error"]); server != nil {
				report.ServerCode, _ = server["code"].(string)
				if msg, ok := server["message"].(string); ok && msg != "" {
					report.Message = msg
				}
				report.Details = server["details"]
			}
			c.notify(report)
		}
	}
}

// dropFatal counts a batch the API will never accept as dropped, once, and keeps a copy in dead/.
func (c *Client) dropFatal(envelopes []Envelope, code string, e Error) {
	c.count(func(s *Stats) { s.Dropped += len(envelopes) })
	e.Code = code
	if e.Message == "" {
		e.Message = "delivery failed"
	}
	if len(envelopes) == 1 {
		e.EventID, _ = envelopes[0].Event["id"].(string)
	}
	c.notify(e)
	if c.spool != nil {
		if err := c.spool.deadLetter(envelopes); err != nil {
			c.notify(Error{Code: CodeSpool, Message: "dead-letter write failed: " + err.Error()})
		}
	}
}

// park spools envelopes that could not be delivered now, or drops them loudly without a spool.
func (c *Client) park(pending []Envelope, reason string) {
	if len(pending) == 0 {
		return
	}
	if c.spool != nil {
		evicted, err := c.spool.write(pending)
		if err == nil {
			c.count(func(s *Stats) { s.Spooled += len(pending); s.Dropped += evicted.events })
			if evicted.events > 0 {
				c.notify(Error{Code: CodeSpool, Message: fmt.Sprintf("spool limit reached: evicted %d oldest event(s) in %d file(s)", evicted.events, evicted.files)})
			}
			return
		}
		c.notify(Error{Code: CodeSpool, Message: "spool write failed: " + err.Error()})
	}
	c.count(func(s *Stats) { s.Dropped += len(pending) })
	if reason == "" {
		reason = "delivery failed"
	}
	c.notify(Error{Code: CodeDeliveryFailed, Message: reason})
}

// replaySpool sends spooled files oldest first, one at a time.
func (c *Client) replaySpool() {
	if c.spool == nil || c.disabled {
		return
	}
	for _, name := range c.spool.files() {
		envelopes, corrupt := c.spool.read(name)
		if corrupt > 0 {
			c.notify(Error{Code: CodeSpool, Message: fmt.Sprintf("skipped %d corrupt spool line(s)", corrupt)})
		}
		if len(envelopes) == 0 {
			c.spool.remove(name)
			continue
		}
		before := c.Stats().Dropped
		pending, _ := c.deliver(envelopes)
		c.count(func(s *Stats) { s.Replayed += len(envelopes) - len(pending) - (s.Dropped - before) })
		if len(pending) == 0 {
			c.spool.remove(name)
			continue
		}
		// The API is still unavailable: keep only what was not delivered, then back off.
		if err := c.spool.rewrite(name, pending); err != nil {
			c.notify(Error{Code: CodeSpool, Message: "spool rewrite failed: " + err.Error()})
		}
		cooldown := 32 * time.Second
		if len(c.retries) > 0 {
			cooldown = c.retries[len(c.retries)-1]
		}
		c.mu.Lock()
		c.spoolCooldown = time.Now().Add(cooldown)
		c.mu.Unlock()
		return
	}
}
