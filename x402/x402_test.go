package x402

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.halvorai.com/ingest"
	"go.halvorai.com/ingest/jcs"
)

// The fixtures are the Node.js SDK's (src/x402/fixtures), shared with the Python SDK.

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

type sink struct {
	mu   sync.Mutex
	envs []ingest.Envelope
	errs []ingest.Error
}

func newClient(t *testing.T) (*ingest.Client, *sink) {
	t.Helper()
	key, err := ingest.GenerateSourceKey("src_local")
	if err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	c := ingest.NewClient(ingest.Config{
		SourceKey: &key,
		Sink: func(_ context.Context, envs []ingest.Envelope) error {
			s.mu.Lock()
			s.envs = append(s.envs, envs...)
			s.mu.Unlock()
			return nil
		},
		OnError: func(e ingest.Error) { s.mu.Lock(); s.errs = append(s.errs, e); s.mu.Unlock() },
	})
	return c, s
}

func (s *sink) events(t *testing.T, c *ingest.Client) []map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.Close(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.errs) > 0 {
		t.Fatalf("errors: %v", s.errs)
	}
	out := make([]map[string]any, len(s.envs))
	for i, e := range s.envs {
		if problems := ingest.ValidateEvent(e.Event); problems != nil {
			t.Fatalf("invalid event: %v", problems)
		}
		out[i] = e.Event
	}
	return out
}

func m(v any) map[string]any { return v.(map[string]any) }

func TestMatchesTheNodeSDKForTheSharedFixtures(t *testing.T) {
	required, payload, settled := load(t, "payment-required.json"), load(t, "payment-payload.json"), load(t, "settlement-success.json")
	ctx := context.Background()
	c, s := newClient(t)
	r, err := MapPaymentRequired(ctx, required, AdapterClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	requestedID := c.Emit(ctx, r)
	a, _ := MapPaymentPayload(ctx, payload, AdapterClient, nil, requestedID)
	c.Emit(ctx, a)
	st, _ := MapSettlementResponse(ctx, settled, SettlementContextFrom(payload), AdapterClient)
	c.Emit(ctx, st)
	events := s.events(t, c)
	requested, authorized, settlement := events[0], events[1], events[2]

	accept := m(payload["accepted"])
	auth := m(m(payload["payload"])["authorization"])
	nonce := auth["nonce"].(string)
	if got := m(requested["payment"])["payment_id"]; got != "x402:eip155:84532:requested:"+requested["id"].(string) {
		t.Fatalf("requested payment_id %v", got)
	}
	if fmt.Sprint(m(requested["payment"])["rail_ref"]) != fmt.Sprint(map[string]any{"scheme": "exact", "network": "eip155:84532"}) {
		t.Fatalf("rail_ref %v", m(requested["payment"])["rail_ref"])
	}
	wantPayee := map[string]any{
		"type":         "api_provider",
		"name":         "Access to premium market data",
		"resource_url": "https://api.example.com/premium-data",
		"wallet":       map[string]any{"network": "eip155:84532", "address": accept["payTo"]},
	}
	if fmt.Sprint(requested["payee"]) != fmt.Sprint(wantPayee) || fmt.Sprint(authorized["payee"]) != fmt.Sprint(wantPayee) {
		t.Fatalf("payee %v / %v", requested["payee"], authorized["payee"])
	}
	wantAsset := map[string]any{"network": "eip155:84532", "address": accept["asset"], "symbol": "USDC"}
	if fmt.Sprint(m(m(requested["payment"])["amount"])["asset"]) != fmt.Sprint(wantAsset) {
		t.Fatalf("asset %v", m(m(requested["payment"])["amount"])["asset"])
	}
	want := "x402:eip155:84532:" + nonce
	if m(authorized["payment"])["payment_id"] != want || m(settlement["payment"])["payment_id"] != want {
		t.Fatalf("authorization and settlement must share the nonce id")
	}
	if m(m(settlement["payment"])["rail_ref"])["tx_hash"] != settled["transaction"] {
		t.Fatal("tx_hash missing")
	}
	if fmt.Sprint(m(authorized["related"])) != fmt.Sprint(map[string]any{"previous_event_id": requested["id"]}) {
		t.Fatalf("related %v", authorized["related"])
	}
	wantInstrument := map[string]any{"type": "wallet", "wallet": map[string]any{"network": "eip155:84532", "address": auth["from"]}}
	if fmt.Sprint(authorized["instrument"]) != fmt.Sprint(wantInstrument) {
		t.Fatalf("instrument %v", authorized["instrument"])
	}
}

func TestFailedSettlementHasNoTxHashAndABoundedReason(t *testing.T) {
	failed := load(t, "settlement-failure.json")
	failed["errorReason"] = strings.Repeat("x", 500)
	payload := load(t, "payment-payload.json")
	out, err := MapSettlementResponse(context.Background(), failed, SettlementContextFrom(payload), AdapterClient)
	if err != nil {
		t.Fatal(err)
	}
	payment := m(out["payment"])
	if out["type"] != "payment.failed" || m(payment["rail_ref"])["tx_hash"] != nil || len(payment["failure_reason"].(string)) != 128 {
		t.Fatalf("payment %v", payment)
	}
}

func TestPayeeWithoutAResourceOrPayTo(t *testing.T) {
	bare := map[string]any{"accepts": []any{map[string]any{"scheme": "exact", "network": "eip155:8453", "amount": "1", "asset": "0xabc"}}}
	out, err := MapPaymentRequired(context.Background(), bare, AdapterClient, nil)
	if err != nil || fmt.Sprint(out["payee"]) != fmt.Sprint(map[string]any{"type": "wallet", "name": "x402 payee"}) {
		t.Fatalf("%v %v", out["payee"], err)
	}
}

func TestContextDetailsReachTheEvent(t *testing.T) {
	ctx := ingest.WithAgentContext(context.Background(), ingest.AgentContext{
		Agent: &ingest.Agent{ID: "agt_1", Name: "Research agent", Framework: "langgraph"},
		Owner: &ingest.Owner{ID: "own_1", Type: "person", Country: "US"},
	})
	mapped, _ := MapPaymentPayload(ctx, load(t, "payment-payload.json"), AdapterClient, nil, "")
	if _, has := mapped["agent"]; has {
		t.Fatal("agent should come from the context")
	}
	c, s := newClient(t)
	c.Emit(ctx, mapped)
	event := s.events(t, c)[0]
	if m(event["agent"])["framework"] != "langgraph" || m(event["owner"])["country"] != "US" {
		t.Fatalf("%v %v", event["agent"], event["owner"])
	}
}

func TestPayerWalletIsTheAgentWithoutContext(t *testing.T) {
	payload := load(t, "payment-payload.json")
	mapped, _ := MapPaymentPayload(context.Background(), payload, AdapterClient, nil, "")
	if m(mapped["agent"])["id"] != m(m(payload["payload"])["authorization"])["from"] {
		t.Fatalf("agent %v", mapped["agent"])
	}
}

func TestNeverGuessesAMissingNetworkOrAsset(t *testing.T) {
	for _, missing := range []string{"network", "asset"} {
		required := load(t, "payment-required.json")
		accept := m(required["accepts"].([]any)[0])
		delete(accept, missing)
		if _, err := MapPaymentRequired(context.Background(), required, AdapterClient, nil); err == nil || !strings.Contains(err.Error(), "no "+missing) {
			t.Fatalf("missing %s: %v", missing, err)
		}
	}
}

func TestEveryChallengeGetsItsOwnID(t *testing.T) {
	required := load(t, "payment-required.json")
	a, _ := MapPaymentRequired(context.Background(), required, AdapterClient, nil)
	b, _ := MapPaymentRequired(context.Background(), required, AdapterClient, nil)
	if m(a["payment"])["payment_id"] == m(b["payment"])["payment_id"] {
		t.Fatal("ids repeat")
	}
}

func TestDecodeAcceptsStandardAndURLSafeBase64(t *testing.T) {
	enc, _ := EncodeHeader(map[string]any{"a": "??>>"})
	for _, h := range []string{enc, strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(enc, "="))} {
		v, err := DecodeHeader(h)
		if err != nil || v["a"] != "??>>" {
			t.Fatalf("%q: %v %v", h, v, err)
		}
	}
	if _, err := DecodeHeader("not base64!"); err == nil {
		t.Fatal("bad header accepted")
	}
}

// A fake x402 resource: 402 with a challenge, then 200 with a settlement once paid.
func x402Server(t *testing.T) *httptest.Server {
	required, _ := EncodeHeader(load(t, "payment-required.json"))
	settled, _ := EncodeHeader(load(t, "settlement-success.json"))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderPaymentSignature) == "" {
			w.Header().Set(HeaderPaymentRequired, required)
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		w.Header().Set(HeaderPaymentResponse, settled)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
}

func TestTransportRecordsAPaidRequest(t *testing.T) {
	srv := x402Server(t)
	defer srv.Close()
	c, s := newClient(t)
	httpClient := &http.Client{Transport: NewTransport(c, nil)}
	payload, _ := EncodeHeader(load(t, "payment-payload.json"))

	res, err := httpClient.Get(srv.URL + "/premium-data")
	if err != nil || res.StatusCode != 402 {
		t.Fatalf("%v %v", res, err)
	}
	res.Body.Close()
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/premium-data", nil)
	req.Header.Set(HeaderPaymentSignature, payload)
	res, err = httpClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("%v %v", res, err)
	}
	res.Body.Close()

	events := s.events(t, c)
	types := []string{}
	for _, e := range events {
		types = append(types, e["type"].(string))
	}
	if strings.Join(types, ",") != "payment.requested,payment.authorized,payment.settled" {
		t.Fatalf("types %v", types)
	}
	if m(events[1]["related"])["previous_event_id"] != events[0]["id"] {
		t.Fatalf("authorized event not linked: %v", events[1]["related"])
	}
	if m(events[1]["payment"])["payment_id"] != m(events[2]["payment"])["payment_id"] {
		t.Fatal("authorization and settlement do not join")
	}
}

func TestTransportNeverBreaksTheRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(HeaderPaymentRequired, "%%%")
		w.WriteHeader(http.StatusPaymentRequired)
	}))
	defer srv.Close()
	c, s := newClient(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set(HeaderPaymentSignature, "also not base64")
	res, err := (&http.Client{Transport: NewTransport(c, nil)}).Do(req)
	if err != nil || res.StatusCode != 402 {
		t.Fatalf("%v %v", res, err)
	}
	res.Body.Close()
	_ = c.Close(context.Background())
	if len(s.errs) != 2 || s.errs[0].Code != ingest.CodeInvalidEvent {
		t.Fatalf("errors %v", s.errs)
	}
}

func TestMiddlewareRecordsServerSidePayments(t *testing.T) {
	required, _ := EncodeHeader(load(t, "payment-required.json"))
	settled, _ := EncodeHeader(load(t, "settlement-success.json"))
	payload, _ := EncodeHeader(load(t, "payment-payload.json"))
	paywall := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderPaymentSignature) == "" {
			w.Header().Set(HeaderPaymentRequired, required)
			w.WriteHeader(http.StatusPaymentRequired)
			return
		}
		w.Header().Set(HeaderPaymentResponse, settled)
		_, _ = w.Write([]byte("data"))
	})
	c, s := newClient(t)
	handler := Middleware(c, ServerOptions{Payee: ingest.Payee{Name: "Market data API"}})(paywall)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/premium-data", nil))
	paid := httptest.NewRequest(http.MethodGet, "/premium-data", nil)
	paid.Header.Set(HeaderPaymentSignature, payload)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, paid)
	if rec.Code != 402 || rec2.Code != 200 || rec2.Body.String() != "data" {
		t.Fatalf("responses changed: %d %d %q", rec.Code, rec2.Code, rec2.Body.String())
	}
	events := s.events(t, c)
	if len(events) != 3 {
		t.Fatalf("got %d events", len(events))
	}
	for _, e := range events {
		if m(e["source"])["adapter"] != AdapterServer || m(e["payee"])["name"] != "Market data API" || m(e["payee"])["type"] != "api_provider" {
			t.Fatalf("event %v %v", e["source"], e["payee"])
		}
	}
}
