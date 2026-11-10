package ingest

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRedactTextLeavesDigitRunsInsideHexBase64AndIdsAlone(t *testing.T) {
	// 4242424242424242 is Luhn-valid, but glued to letters or digits it is not a card number.
	for _, text := range []string{
		"0x9632e1311996ebcb38d7a4242424242424242b5beb14f513",
		"c2lnbmF0dXJl4242424242424242AAA=",
		"ord_4242424242424242x",
		"x4242424242424242",
	} {
		if got := RedactText(text); got != text {
			t.Errorf("%q became %q", text, got)
		}
		if ContainsPAN(text) {
			t.Errorf("%q reported as holding a card number", text)
		}
	}
}

func TestRedactTextStillRemovesCardNumbers(t *testing.T) {
	for text, want := range map[string]string{
		"4242424242424242":                            "[redacted:pan]",
		"card 4242 4242 4242 4242 used":               "card [redacted:pan] used",
		"card 4242-4242-4242-4242.":                   "card [redacted:pan].",
		"a,4242424242424242,4000056655665556;b":       "a,[redacted:pan],[redacted:pan];b",
		"https://shop.example/?card=4242424242424242": "https://shop.example/?card=[redacted:pan]",
		// The run stops before " 4242x", which is glued to a letter.
		"4242424242424242 4242x": "[redacted:pan] 4242x",
		// Not Luhn-valid, or too short: left alone.
		"4242424242424241":   "4242424242424241",
		"order 123456789012": "order 123456789012",
	} {
		if got := RedactText(text); got != want {
			t.Errorf("%q: got %q, want %q", text, got, want)
		}
	}
}

func TestSignedX402PayloadIsNotRedacted(t *testing.T) {
	var got []Envelope
	c := NewClient(Config{SourceKey: mustKey(t), Sink: func(_ context.Context, envs []Envelope) error { got = append(got, envs...); return nil }})
	payload := map[string]any{
		"accepted": map[string]any{"scheme": "exact", "network": "eip155:84532", "amount": "10000"},
		"payload": map[string]any{
			// A Luhn-valid run inside a hex signature must survive, or the signature no longer verifies.
			"signature":     "0x" + strings.Repeat("ab", 20) + "4242424242424242" + strings.Repeat("cd", 20),
			"authorization": map[string]any{},
		},
	}
	sha := "sha256:" + strings.Repeat("b", 64)
	e := testEvent()
	e.Evidence = []Evidence{{Kind: "x402.payment_payload", Format: "json", Value: payload, SHA256: sha}}
	c.Emit(context.Background(), e)
	c.Flush(ctxTimeout(t, 5*time.Second))
	_ = c.Close(context.Background())
	if len(got) != 1 {
		t.Fatalf("got %d envelopes", len(got))
	}
	ev := got[0].Event["evidence"].([]any)[0].(map[string]any)
	want, _ := json.Marshal(payload)
	have, _ := json.Marshal(ev["value"])
	if !reflect.DeepEqual(want, have) || ev["sha256"] != sha {
		t.Fatalf("payload changed: %s sha256 %v", have, ev["sha256"])
	}
}
