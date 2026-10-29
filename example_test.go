package ingest_test

import (
	"context"
	"fmt"
	"time"

	"go.halvorai.com/ingest"
)

// Offline: no account needed. Events are signed with your own key and handed to Sink.
func Example() {
	key, _ := ingest.GenerateSourceKey("src_local") // keep the private key secret
	client := ingest.NewClient(ingest.Config{
		SourceKey: &key,
		Sink: func(_ context.Context, envelopes []ingest.Envelope) error {
			for _, e := range envelopes {
				ok := ingest.VerifyEvent(e.Event, e.Sig, key.Public())
				fmt.Println(e.Event["type"], e.Event["agent"].(map[string]any)["id"], ok)
			}
			return nil
		},
	})

	ctx := ingest.WithAgentContext(context.Background(), ingest.AgentContext{
		Agent:       &ingest.Agent{ID: "agt_travel_12", Name: "Travel booking agent"},
		Owner:       &ingest.Owner{ID: "own_u_4410", Type: "person", Country: "US"},
		Instruction: &ingest.Instruction{ID: "task_8890", Text: "Book a return flight to Austin under $500"},
	})
	client.Emit(ctx, ingest.Event{
		Type: ingest.PaymentSettled,
		Payment: ingest.Payment{
			PaymentID: "pi_3QxAbCdEfGhIjKlM",
			Rail:      "stripe",
			Amount:    ingest.Amount{Value: "41200", Unit: "minor", Currency: "USD"},
			Status:    "settled",
			RailRef:   map[string]any{"payment_intent": "pi_3QxAbCdEfGhIjKlM"},
		},
		Payee: ingest.Payee{Type: "merchant", Name: "Example Airways"},
	})

	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = client.Close(closeCtx)
	// Output: payment.settled agt_travel_12 true
}

// Production: keys come from HALVOR_API_KEY and HALVOR_SOURCE_KEY.
func ExampleNewClient() {
	client := ingest.NewClient(ingest.Config{
		SpoolDir: "/var/lib/myapp/halvor-spool", // keeps events through an outage
		OnError:  func(err ingest.Error) { fmt.Println(err) },
	})
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = client.Close(ctx) // send what is queued before the process exits
	}()
}
