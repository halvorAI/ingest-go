package stripe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.halvorai.com/ingest"
)

// The fixtures are the Node.js SDK's (src/stripe/fixtures), Stripe test-mode shapes.

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustMap(t *testing.T, name string) map[string]any {
	t.Helper()
	m, err := MapEvent(fixture(t, name))
	if err != nil || m == nil {
		t.Fatalf("%s: %v %v", name, m, err)
	}
	return m
}

func TestMapsEveryFixture(t *testing.T) {
	for _, c := range []struct{ file, apeType, status, adapter string }{
		{"payment_intent.amount_capturable_updated.json", "payment.authorized", "authorized", "stripe"},
		{"payment_intent.succeeded.json", "payment.settled", "settled", "stripe"},
		{"payment_intent.payment_failed.json", "payment.failed", "failed", "stripe"},
		{"charge.refunded.json", "payment.refunded", "refunded", "stripe"},
		{"charge.dispute.created.json", "payment.disputed", "disputed", "stripe"},
		{"issuing_authorization.created.json", "payment.authorized", "authorized", "stripe-issuing"},
		{"issuing_authorization.updated.json", "payment.failed", "failed", "stripe-issuing"},
		{"issuing_transaction.created.json", "payment.settled", "settled", "stripe-issuing"},
		{"issuing_transaction.refund.json", "payment.refunded", "refunded", "stripe-issuing"},
	} {
		m := mustMap(t, c.file)
		payment := m["payment"].(map[string]any)
		adapter := m["source"].(map[string]any)["adapter"]
		if m["type"] != c.apeType || payment["status"] != c.status || adapter != c.adapter {
			t.Errorf("%s: got %v %v %v", c.file, m["type"], payment["status"], adapter)
		}
	}
}

func TestIgnoresUnrelatedTypes(t *testing.T) {
	m, err := MapEvent([]byte(`{"type":"customer.created","data":{"object":{"id":"cus_x"}}}`))
	if m != nil || err != nil {
		t.Fatalf("got %v %v", m, err)
	}
}

func TestUnattributedWhenMetadataIsMissing(t *testing.T) {
	m := mustMap(t, "unattributed.json")
	if m["agent"].(map[string]any)["id"] != "unattributed" || m["owner"].(map[string]any)["id"] != "unattributed" {
		t.Fatalf("%v %v", m["agent"], m["owner"])
	}
}

func TestFailureReasonFromLastPaymentError(t *testing.T) {
	m := mustMap(t, "payment_intent.payment_failed.json")
	if got := m["payment"].(map[string]any)["failure_reason"]; got != "card_declined" {
		t.Fatalf("got %v", got)
	}
}

func TestIssuingMerchantData(t *testing.T) {
	m := mustMap(t, "issuing_authorization.created.json")
	payment := m["payment"].(map[string]any)
	ref := payment["rail_ref"].(map[string]any)
	payee := m["payee"].(map[string]any)
	if payment["rail"] != "card" || ref["authorization_id"] != "iauth_1QxYz2AbCdEfGh" || ref["processor"] != "stripe-issuing" {
		t.Fatalf("payment %v", payment)
	}
	if payee["name"] != "Example Airways" || payee["mcc"] != "4511" || payee["country"] != "US" || payee["id"] != "acq_000123456789" {
		t.Fatalf("payee %v", payee)
	}
	if m["agent"].(map[string]any)["id"] != "agt_travel_12" {
		t.Fatalf("agent %v", m["agent"])
	}
}

func TestEveryFixtureProducesAValidSignedEvent(t *testing.T) {
	files, _ := os.ReadDir("testdata")
	if len(files) < 9 {
		t.Fatalf("only %d fixtures", len(files))
	}
	for _, f := range files {
		t.Run(f.Name(), func(t *testing.T) {
			key, _ := ingest.GenerateSourceKey("src_01STRIPEADAPTERTEST000000001")
			var mu sync.Mutex
			var got []ingest.Envelope
			var errs []ingest.Error
			client := ingest.NewClient(ingest.Config{
				SourceKey: &key,
				Sink: func(_ context.Context, envs []ingest.Envelope) error {
					mu.Lock()
					got = append(got, envs...)
					mu.Unlock()
					return nil
				},
				OnError: func(e ingest.Error) { mu.Lock(); errs = append(errs, e); mu.Unlock() },
			})
			id, ok := Emit(context.Background(), client, fixture(t, f.Name()))
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = client.Close(ctx)
			if !ok || !strings.HasPrefix(id, "evt_") || len(errs) > 0 || len(got) != 1 {
				t.Fatalf("ok=%v id=%s errors=%v envelopes=%d", ok, id, errs, len(got))
			}
			if problems := ingest.ValidateEvent(got[0].Event); problems != nil {
				t.Fatalf("invalid: %v", problems)
			}
			if !ingest.VerifyEvent(got[0].Event, got[0].Sig, key.Public()) {
				t.Fatal("signature does not verify")
			}
		})
	}
}

func TestEmitObjectWithAStripeGoStyleEvent(t *testing.T) {
	key, _ := ingest.GenerateSourceKey("src_local")
	var got []ingest.Envelope
	client := ingest.NewClient(ingest.Config{SourceKey: &key, Sink: func(_ context.Context, envs []ingest.Envelope) error {
		got = append(got, envs...)
		return nil
	}})
	if _, ok := EmitObject(context.Background(), client, "invoice.paid", 0, []byte(`{}`)); ok {
		t.Fatal("unrelated type was emitted")
	}
	object := []byte(`{"id":"pi_3QxAbCdEfGhIjKlM","amount":41200,"currency":"usd","metadata":{"halvor_agent_id":"agt_1"}}`)
	if _, ok := EmitObject(context.Background(), client, "payment_intent.succeeded", 1760000000, object); !ok {
		t.Fatal("not emitted")
	}
	_ = client.Close(context.Background())
	event := got[0].Event
	amount := event["payment"].(map[string]any)["amount"].(map[string]any)
	if amount["value"] != "41200" || amount["currency"] != "USD" || event["occurred_at"] != "2025-10-09T08:53:20.000Z" {
		t.Fatalf("event %v", event)
	}
}

func TestTagMetadata(t *testing.T) {
	ctx := ingest.WithAgentContext(context.Background(), ingest.AgentContext{
		Agent:       &ingest.Agent{ID: "agt_ctx_1", Name: "Ctx"},
		Owner:       &ingest.Owner{ID: "own_ctx_1", Type: "business"},
		Instruction: &ingest.Instruction{ID: "ins_ctx_1", Text: "buy coffee"},
	})
	got := TagMetadata(ctx, map[string]string{"order": "1"}, TagOverrides{})
	want := map[string]string{"order": "1", MetaAgentID: "agt_ctx_1", MetaOwnerID: "own_ctx_1", MetaOwnerType: "business", MetaInstructionID: "ins_ctx_1"}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("got %v", got)
		}
	}
	got = TagMetadata(ctx, nil, TagOverrides{AgentID: "agt_override"})
	if got[MetaAgentID] != "agt_override" || got[MetaOwnerID] != "own_ctx_1" {
		t.Fatalf("got %v", got)
	}
}
