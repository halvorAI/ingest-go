package ingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRedactTextCardNumberBoundaries(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"card 4242424242424242 used", "card [redacted:pan] used"},
		{"card 4242 4242 4242 4242", "card [redacted:pan]"},
		{"card 4242-4242-4242-4242.", "card [redacted:pan]."},
		{"4242424242424242", "[redacted:pan]"},
		// Digits glued to letters or digits are part of a hex string, base64 or an id.
		{"0xab4242424242424242cd", "0xab4242424242424242cd"},
		{"sig 0x4242424242424242ff", "sig 0x4242424242424242ff"},
		{"id_4242424242424242", "id_[redacted:pan]"},
		{"x4242424242424242", "x4242424242424242"},
		{"4242424242424242y", "4242424242424242y"},
		{"42424242424242420", "42424242424242420"},
		// When the longest run touches a letter, a shorter one ending at a separator still counts.
		{"4242 4242 4242 4242 9x", "[redacted:pan] 9x"},
		{"pay 1234 now", "pay 1234 now"},
	} {
		if got := RedactText(c.in); got != c.want {
			t.Errorf("RedactText(%q) = %q, want %q", c.in, got, c.want)
		}
		if got := ContainsPAN(c.in); got != strings.Contains(c.want, "[redacted:pan]") {
			t.Errorf("ContainsPAN(%q) = %v", c.in, got)
		}
	}
}

func TestX402PaymentPayloadEvidenceIsNotRedacted(t *testing.T) {
	var got []Envelope
	key := mustKey(t)
	c := NewClient(Config{SourceKey: key, Sink: func(_ context.Context, envs []Envelope) error { got = append(got, envs...); return nil }})
	// A signature whose hex holds a Luhn-valid 16-digit run between letters.
	sig := "0xab4242424242424242cd" + strings.Repeat("0", 108)
	payload := map[string]any{"payload": map[string]any{"signature": sig, "note": "4242 4242 4242 4242"}}
	e := testEvent()
	e.Evidence = []Evidence{
		{Kind: "x402.payment_payload", Format: "json", Value: payload},
		{Kind: "stripe.object", Format: "json", Value: map[string]any{"note": "4242 4242 4242 4242"}},
	}
	c.Emit(context.Background(), e)
	c.Flush(ctxTimeout(t, 5*time.Second))
	_ = c.Close(context.Background())
	if len(got) != 1 {
		t.Fatalf("got %d envelopes", len(got))
	}
	evidence := got[0].Event["evidence"].([]any)
	signed, _ := json.Marshal(evidence[0])
	if !strings.Contains(string(signed), sig) || !strings.Contains(string(signed), "4242 4242 4242 4242") {
		t.Fatalf("x402 payload changed: %s", signed)
	}
	other, _ := json.Marshal(evidence[1])
	if strings.Contains(string(other), "4242 4242") {
		t.Fatalf("other evidence not redacted: %s", other)
	}
}
