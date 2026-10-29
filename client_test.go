package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAPIKey = "hk_test_dddddddddddddddddddddddddddddddd"

func testEvent() Event {
	return Event{
		Type: PaymentSettled,
		Payment: Payment{
			PaymentID: "pi_1",
			Rail:      "stripe",
			Amount:    Amount{Value: "100", Unit: "minor", Currency: "USD"},
			Status:    "settled",
			RailRef:   map[string]any{"payment_intent": "pi_1"},
		},
		Payee: Payee{Type: "merchant", Name: "Shop"},
	}
}

func mustKey(t *testing.T) *JWK {
	t.Helper()
	k, err := GenerateSourceKey("src_local")
	if err != nil {
		t.Fatal(err)
	}
	return &k
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// recorder is a fake API. handle decides the response for each request.
type recorder struct {
	mu       sync.Mutex
	batches  [][]string
	requests []map[string]any
	handle   func(ids []string) (int, string)
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	raw, _ := io.ReadAll(req.Body)
	var body struct {
		Events []struct {
			Event map[string]any `json:"event"`
			Sig   string         `json:"sig"`
		} `json:"events"`
	}
	_ = json.Unmarshal(raw, &body)
	ids := make([]string, len(body.Events))
	for i, e := range body.Events {
		ids[i], _ = e.Event["id"].(string)
	}
	r.mu.Lock()
	r.batches = append(r.batches, ids)
	r.requests = append(r.requests, map[string]any{"auth": req.Header.Get("Authorization"), "path": req.URL.Path})
	r.mu.Unlock()
	status, text := 202, ""
	if r.handle != nil {
		status, text = r.handle(ids)
	}
	if text == "" && status == 202 {
		text = acceptAll(ids)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(text))
}

func (r *recorder) sent() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string(nil), r.batches...)
}

func acceptAll(ids []string) string {
	results := make([]map[string]string, len(ids))
	for i, id := range ids {
		results[i] = map[string]string{"id": id, "status": "accepted"}
	}
	b, _ := json.Marshal(map[string]any{"results": results})
	return string(b)
}

type errorLog struct {
	mu   sync.Mutex
	errs []Error
}

func (l *errorLog) add(e Error) { l.mu.Lock(); l.errs = append(l.errs, e); l.mu.Unlock() }
func (l *errorLog) all() []Error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Error(nil), l.errs...)
}

func newTestClient(t *testing.T, handle func([]string) (int, string), mutate func(*Config)) (*Client, *recorder, *errorLog) {
	t.Helper()
	rec := &recorder{handle: handle}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	log := &errorLog{}
	cfg := Config{
		APIKey:        testAPIKey,
		SourceKey:     mustKey(t),
		Endpoint:      srv.URL,
		OnError:       log.add,
		RetryDelays:   []time.Duration{},
		FlushInterval: 20 * time.Millisecond,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c := NewClient(cfg)
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, rec, log
}

func pendingFiles(t *testing.T, dir string) []string { t.Helper(); return listSpool(dir) }

func deadLines(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	for _, name := range listSpool(filepath.Join(dir, deadDir)) {
		raw, _ := os.ReadFile(filepath.Join(dir, deadDir, name))
		n += strings.Count(string(raw), "\n")
	}
	return n
}

func TestSendsSignedEventsToTheAPI(t *testing.T) {
	c, rec, log := newTestClient(t, nil, nil)
	id := c.Emit(context.Background(), testEvent())
	if !c.Flush(ctxTimeout(t, 5*time.Second)) {
		t.Fatal("flush did not drain")
	}
	if got := rec.sent(); len(got) != 1 || got[0][0] != id {
		t.Fatalf("sent %v, want [[%s]]", got, id)
	}
	if rec.requests[0]["auth"] != "Bearer "+testAPIKey || rec.requests[0]["path"] != "/v1/events" {
		t.Fatalf("bad request: %v", rec.requests[0])
	}
	if s := c.Stats(); s.Accepted != 1 || s.Emitted != 1 || s.Queued != 0 {
		t.Fatalf("stats %+v", s)
	}
	if errs := log.all(); len(errs) != 0 {
		t.Fatalf("unexpected errors %v", errs)
	}
}

func TestEmitNeverWaitsForTheNetwork(t *testing.T) {
	release := make(chan struct{})
	c, _, _ := newTestClient(t, func(ids []string) (int, string) { <-release; return 202, "" }, func(cfg *Config) { cfg.BatchSize = 10 })
	start := time.Now()
	for i := 0; i < 50; i++ {
		c.Emit(context.Background(), testEvent())
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("emit blocked")
	}
	close(release)
	if !c.Flush(ctxTimeout(t, 5*time.Second)) || c.Stats().Accepted != 50 {
		t.Fatalf("stats %+v", c.Stats())
	}
}

func TestSendsInTheBackgroundWithoutFlush(t *testing.T) {
	c, rec, _ := newTestClient(t, nil, nil)
	c.Emit(context.Background(), testEvent())
	deadline := time.Now().Add(2 * time.Second)
	for len(rec.sent()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(rec.sent()) == 0 {
		t.Fatal("nothing sent without flush")
	}
}

func TestRetries503ThenDelivers(t *testing.T) {
	var calls atomic.Int32
	c, _, _ := newTestClient(t, func(ids []string) (int, string) {
		if calls.Add(1) <= 2 {
			return 503, ""
		}
		return 202, ""
	}, func(cfg *Config) {
		cfg.RetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	})
	c.Emit(context.Background(), testEvent())
	c.Flush(ctxTimeout(t, 5*time.Second))
	if s := c.Stats(); s.Retries != 2 || s.Accepted != 1 || s.Dropped != 0 {
		t.Fatalf("stats %+v", s)
	}
}

func Test5xxIsNotCountedAsRejected(t *testing.T) {
	c, _, log := newTestClient(t, func([]string) (int, string) { return 503, "" }, nil)
	c.Emit(context.Background(), testEvent())
	c.Flush(ctxTimeout(t, 5*time.Second))
	if s := c.Stats(); s.Rejected != 0 || s.Dropped != 1 {
		t.Fatalf("stats %+v", s)
	}
	if errs := log.all(); errs[len(errs)-1].Code != CodeDeliveryFailed {
		t.Fatalf("errors %v", errs)
	}
}

func TestNetworkErrorsSpoolTheEvents(t *testing.T) {
	dir := t.TempDir()
	c, _, _ := newTestClient(t, nil, func(cfg *Config) {
		cfg.SpoolDir = dir
		cfg.Endpoint = "http://127.0.0.1:1" // nothing listens here
	})
	c.Emit(context.Background(), testEvent())
	c.flush(ctxTimeout(t, 5*time.Second), false)
	if s := c.Stats(); s.Spooled != 1 || s.Dropped != 0 {
		t.Fatalf("stats %+v", s)
	}
	if len(pendingFiles(t, dir)) != 1 {
		t.Fatal("no spool file")
	}
}

func TestSpooledEventsAreReplayedByTheNextProcess(t *testing.T) {
	dir := t.TempDir()
	key := mustKey(t)
	down, _, _ := newTestClient(t, func([]string) (int, string) { return 503, "" }, func(cfg *Config) { cfg.SpoolDir = dir; cfg.SourceKey = key })
	id := down.Emit(context.Background(), testEvent())
	down.flush(ctxTimeout(t, 5*time.Second), false)
	_ = down.Close(ctxTimeout(t, time.Second))

	up, rec, _ := newTestClient(t, nil, func(cfg *Config) { cfg.SpoolDir = dir; cfg.SourceKey = key })
	if !up.Flush(ctxTimeout(t, 5*time.Second)) {
		t.Fatal("flush did not drain")
	}
	found := false
	for _, batch := range rec.sent() {
		for _, got := range batch {
			found = found || got == id
		}
	}
	if !found || len(pendingFiles(t, dir)) != 0 || up.Stats().Replayed != 1 {
		t.Fatalf("found=%v files=%v stats=%+v", found, pendingFiles(t, dir), up.Stats())
	}
}

func TestFatalErrorsCarryTheServerCodeAndAreDeadLettered(t *testing.T) {
	dir := t.TempDir()
	body := `{"error":{"code":"unknown_source","message":"no such source","request_id":"req_9"}}`
	c, rec, log := newTestClient(t, func([]string) (int, string) { return 401, body }, func(cfg *Config) {
		cfg.SpoolDir = dir
		cfg.RetryDelays = []time.Duration{time.Millisecond}
	})
	id := c.Emit(context.Background(), testEvent())
	c.Flush(ctxTimeout(t, 5*time.Second))
	if len(rec.sent()) != 1 {
		t.Fatalf("fatal error was retried: %v", rec.sent())
	}
	errs := log.all()
	got := errs[len(errs)-1]
	want := Error{Code: CodeUnauthorized, Message: "no such source", ServerCode: "unknown_source", RequestID: "req_9", EventID: id}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if deadLines(t, dir) != 1 || len(pendingFiles(t, dir)) != 0 {
		t.Fatal("batch not dead-lettered")
	}
}

func TestARejectedSpoolFileDoesNotBlockLaterFiles(t *testing.T) {
	dir := t.TempDir()
	key := mustKey(t)
	down, _, _ := newTestClient(t, func([]string) (int, string) { return 503, "" }, func(cfg *Config) { cfg.SpoolDir = dir; cfg.SourceKey = key })
	bad := down.Emit(context.Background(), testEvent())
	down.flush(ctxTimeout(t, 5*time.Second), false)
	good := down.Emit(context.Background(), testEvent())
	down.flush(ctxTimeout(t, 5*time.Second), false)
	_ = down.Close(ctxTimeout(t, time.Second))
	if n := len(pendingFiles(t, dir)); n != 2 {
		t.Fatalf("want 2 spool files, got %d", n)
	}
	up, rec, _ := newTestClient(t, func(ids []string) (int, string) {
		for _, id := range ids {
			if id == bad {
				return 422, `{"error":{"code":"invalid_event"}}`
			}
		}
		return 202, ""
	}, func(cfg *Config) { cfg.SpoolDir = dir; cfg.SourceKey = key })
	up.Flush(ctxTimeout(t, 5*time.Second))
	sentGood := false
	for _, b := range rec.sent() {
		sentGood = sentGood || (len(b) == 1 && b[0] == good)
	}
	if !sentGood || len(pendingFiles(t, dir)) != 0 {
		t.Fatalf("sent %v, files %v", rec.sent(), pendingFiles(t, dir))
	}
	if s := up.Stats(); s.Dropped != 1 || s.Replayed != 1 {
		t.Fatalf("stats %+v", s)
	}
}

func TestABatchThatIsTooLargeIsSplit(t *testing.T) {
	c, rec, _ := newTestClient(t, func(ids []string) (int, string) {
		if len(ids) > 2 {
			return 413, ""
		}
		return 202, ""
	}, nil)
	for i := 0; i < 5; i++ {
		c.Emit(context.Background(), testEvent())
	}
	c.Flush(ctxTimeout(t, 5*time.Second))
	if c.Stats().Accepted != 5 {
		t.Fatalf("stats %+v, sent %v", c.Stats(), rec.sent())
	}
}

func TestASingleOversizedEventIsDroppedNotSpooled(t *testing.T) {
	dir := t.TempDir()
	c, _, log := newTestClient(t, func([]string) (int, string) { return 413, "" }, func(cfg *Config) { cfg.SpoolDir = dir })
	c.Emit(context.Background(), testEvent())
	c.Flush(ctxTimeout(t, 5*time.Second))
	errs := log.all()
	if c.Stats().Dropped != 1 || len(pendingFiles(t, dir)) != 0 || errs[len(errs)-1].ServerCode != "payload_too_large" {
		t.Fatalf("stats %+v errors %v", c.Stats(), errs)
	}
}

func TestPerEventResultsAreCounted(t *testing.T) {
	c, _, log := newTestClient(t, func(ids []string) (int, string) {
		return 202, fmt.Sprintf(`{"results":[{"id":%q,"status":"accepted"},{"id":%q,"status":"duplicate"},{"id":%q,"status":"rejected","error":{"code":"invalid_signature","message":"Signature does not match"}}]}`, ids[0], ids[1], ids[2])
	}, func(cfg *Config) { cfg.BatchSize = 3 })
	for i := 0; i < 3; i++ {
		c.Emit(context.Background(), testEvent())
	}
	c.Flush(ctxTimeout(t, 5*time.Second))
	if s := c.Stats(); s.Accepted != 1 || s.Duplicates != 1 || s.Rejected != 1 {
		t.Fatalf("stats %+v", s)
	}
	errs := log.all()
	if len(errs) != 1 || errs[0].ServerCode != "invalid_signature" {
		t.Fatalf("errors %v", errs)
	}
}

func TestSpoolEvictsTheOldestFilesBeyondItsLimit(t *testing.T) {
	s := &spool{dir: t.TempDir(), maxBytes: 1, maxAge: time.Hour}
	_, _ = s.write([]Envelope{{Event: map[string]any{"id": "evt_a"}, Sig: "s"}})
	ev, err := s.write([]Envelope{{Event: map[string]any{"id": "evt_b"}, Sig: "s"}})
	if err != nil || ev.files < 1 || ev.events < 1 {
		t.Fatalf("eviction %+v %v", ev, err)
	}
}

func TestBadConfigDisablesTheClientOnce(t *testing.T) {
	good := mustKey(t)
	public := good.Public()
	noKid := *good
	noKid.Kid = ""
	wrongCurve := *good
	wrongCurve.Crv = "P-256"
	for name, cfg := range map[string]Config{
		"public key only": {APIKey: testAPIKey, SourceKey: &public},
		"no kid":          {APIKey: testAPIKey, SourceKey: &noKid},
		"wrong curve":     {APIKey: testAPIKey, SourceKey: &wrongCurve},
		"bad API key":     {APIKey: "sk_live_nope", SourceKey: good},
	} {
		t.Run(name, func(t *testing.T) {
			log := &errorLog{}
			cfg.OnError = log.add
			c := NewClient(cfg)
			c.Emit(context.Background(), testEvent())
			c.Emit(context.Background(), testEvent())
			errs := log.all()
			if len(errs) != 1 || errs[0].Code != CodeConfig || c.Stats().DroppedDisabled != 2 {
				t.Fatalf("errors %v stats %+v", errs, c.Stats())
			}
		})
	}
}

func TestInvalidEventsAreDroppedAndReported(t *testing.T) {
	c, rec, log := newTestClient(t, nil, nil)
	bad := testEvent()
	bad.Payment.Amount.Currency = "usd"
	c.Emit(context.Background(), bad)
	c.Emit(context.Background(), map[string]any{"type": "nope"})
	c.Emit(context.Background(), func() {}) // not JSON
	c.Flush(ctxTimeout(t, time.Second))
	errs := log.all()
	if len(rec.sent()) != 0 || c.Stats().DroppedInvalid != 3 || len(errs) != 3 || errs[0].Code != CodeInvalidEvent {
		t.Fatalf("sent %v stats %+v errors %v", rec.sent(), c.Stats(), errs)
	}
}

func TestCloseRefusesNewEvents(t *testing.T) {
	c, rec, _ := newTestClient(t, nil, nil)
	c.Emit(context.Background(), testEvent())
	if err := c.Close(ctxTimeout(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
	c.Emit(context.Background(), testEvent())
	if len(rec.sent()) != 1 || c.Stats().DroppedClosed != 1 {
		t.Fatalf("sent %v stats %+v", rec.sent(), c.Stats())
	}
}

func TestCountersAreExactUnderConcurrentEmits(t *testing.T) {
	var received atomic.Int64
	c := NewClient(Config{SourceKey: mustKey(t), Sink: func(_ context.Context, envs []Envelope) error {
		received.Add(int64(len(envs)))
		return nil
	}})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				c.Emit(context.Background(), testEvent())
			}
		}()
	}
	wg.Wait()
	c.Flush(ctxTimeout(t, 10*time.Second))
	if s := c.Stats(); s.Emitted != 800 || s.Accepted != 800 || received.Load() != 800 {
		t.Fatalf("stats %+v received %d", s, received.Load())
	}
	_ = c.Close(context.Background())
}

func TestSinkErrorsAreRetriedThenSpooled(t *testing.T) {
	dir := t.TempDir()
	var calls atomic.Int32
	c := NewClient(Config{SourceKey: mustKey(t), SpoolDir: dir, RetryDelays: []time.Duration{time.Millisecond}, Sink: func(context.Context, []Envelope) error {
		calls.Add(1)
		return errors.New("down")
	}})
	c.Emit(context.Background(), testEvent())
	c.flush(ctxTimeout(t, 5*time.Second), false)
	if calls.Load() != 2 || c.Stats().Spooled != 1 {
		t.Fatalf("calls %d stats %+v", calls.Load(), c.Stats())
	}
	_ = c.Close(context.Background())
}

func TestFlushHonoursItsContext(t *testing.T) {
	release := make(chan struct{})
	c, _, _ := newTestClient(t, func([]string) (int, string) { <-release; return 202, "" }, nil)
	defer close(release)
	c.Emit(context.Background(), testEvent())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if c.Flush(ctx) {
		t.Fatal("flush reported drained while the API hung")
	}
}

func TestEventsAreBuiltRedactedAndSigned(t *testing.T) {
	var got []Envelope
	key := mustKey(t)
	c := NewClient(Config{SourceKey: key, Sink: func(_ context.Context, envs []Envelope) error { got = append(got, envs...); return nil }})
	ctx := WithAgentContext(context.Background(), AgentContext{
		Agent:       &Agent{ID: "agt_1", Name: "Research agent", Framework: "langgraph"},
		Owner:       &Owner{ID: "own_1", Type: "person", Country: "US"},
		Instruction: &Instruction{ID: "ctx", Text: "from context", Channel: "chat"},
	})
	ctx = WithAgentContext(ctx, AgentContext{Agent: &Agent{ID: "agt_inner"}})
	e := testEvent()
	e.Payment.Description = "card 4242 4242 4242 4242 used"
	e.Payee.Website = "https://shop.example/?card=4242424242424242"
	e.Labels = map[string]string{"4242 4242 4242 4242": "x", "team": "sk_live_abcdef123"}
	e.Evidence = []Evidence{{Kind: "stripe.object", Format: "json", Value: map[string]any{"note": "4242424242424242"}}}
	c.Emit(ctx, e)
	c.Emit(ctx, Event{Type: PaymentSettled, Payment: e.Payment, Payee: Payee{Type: "merchant", Name: "Shop"}, Instruction: &Instruction{ID: "evt_level", Text: "pay"}})
	c.Flush(ctxTimeout(t, 5*time.Second))
	_ = c.Close(context.Background())
	if len(got) != 2 {
		t.Fatalf("got %d envelopes", len(got))
	}
	first := got[0].Event
	text, _ := json.Marshal(first)
	if strings.Contains(string(text), "4242 4242") || strings.Contains(string(text), "4242424242424242") || strings.Contains(string(text), "sk_live_") {
		t.Fatalf("not redacted: %s", text)
	}
	if problems := ValidateEvent(first); problems != nil {
		t.Fatalf("invalid: %v", problems)
	}
	if !VerifyEvent(first, got[0].Sig, key.Public()) {
		t.Fatal("signature does not verify")
	}
	agent := first["agent"].(map[string]any)
	if agent["id"] != "agt_inner" || first["owner"].(map[string]any)["country"] != "US" {
		t.Fatalf("context not applied: %v %v", agent, first["owner"])
	}
	if in := first["instruction"].(map[string]any); in["hash"] != HashInstruction("from context") || in["text"] != nil || in["channel"] != "chat" {
		t.Fatalf("instruction %v", in)
	}
	if in := got[1].Event["instruction"].(map[string]any); in["id"] != "evt_level" || len(in) != 2 {
		t.Fatalf("event-level instruction should replace the context one: %v", in)
	}
	source := first["source"].(map[string]any)
	if source["sdk"] != SDKName || source["id"] != "src_local" || first["environment"] != "test" {
		t.Fatalf("source %v environment %v", source, first["environment"])
	}
}
