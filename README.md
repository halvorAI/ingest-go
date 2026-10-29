# HalvorAI Go SDK

Signed, attributed payment events for AI agents. HalvorAI records each payment an agent makes, with the agent, the owner it acted for, the instruction it followed and the network proof that came with it. It is never in the payment path: it cannot slow or block a payment.

> **Developer preview.** The SDK works offline today: build, sign and inspect events with your own sink. Sandbox API keys go to early-access teams. [Request access](https://halvorai.com/?utm_source=github&utm_campaign=ingest_go#early-access).

- Docs: [docs.halvorai.com](https://docs.halvorai.com)
- Event format: [Agent Payment Event (APE) v0.1](https://schema.halvorai.com), open and Apache-2.0
- Go 1.22 or later. No dependencies outside the standard library.
- Events are byte-identical to the [Node.js](https://github.com/halvorAI/ingest-js) and [Python](https://github.com/halvorAI/ingest-python) SDKs.

## Install

```bash
go get go.halvorai.com/ingest
```

## Try it offline

No account needed. Events are signed with your own Ed25519 key and handed to your `Sink` instead of the API.

```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"go.halvorai.com/ingest"
)

func main() {
	key, _ := ingest.GenerateSourceKey("src_local") // private JWK; keep it secret
	halvor := ingest.NewClient(ingest.Config{
		SourceKey: &key,
		Sink: func(_ context.Context, envelopes []ingest.Envelope) error {
			out, _ := json.MarshalIndent(envelopes, "", "  ")
			fmt.Println(string(out))
			return nil
		},
	})

	ctx := ingest.WithAgentContext(context.Background(), ingest.AgentContext{
		Agent:       &ingest.Agent{ID: "agt_travel_12", Name: "Travel booking agent"},
		Owner:       &ingest.Owner{ID: "own_u_4410", Type: "person", Country: "US"},
		Instruction: &ingest.Instruction{ID: "task_8890", Text: "Book a return flight to Austin under $500"},
	})

	halvor.Emit(ctx, ingest.Event{
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
	halvor.Close(closeCtx)
}
```

`Emit` returns the event id at once and never fails. Instruction text is hashed on your machine and never sent. Anyone with the public half of the key (`key.Public()`) can check an envelope with `ingest.VerifyEvent(envelope.Event, envelope.Sig, publicKey)`.

You can also pass a `map[string]any` to `Emit`, in the shape of the [field reference](https://schema.halvorai.com).

## Send to HalvorAI (early access)

With a sandbox key (`hk_test_…`) and a source key registered in the dashboard, set `HALVOR_API_KEY` and `HALVOR_SOURCE_KEY` (the private JWK as JSON) and create the client with no options:

```go
halvor := ingest.NewClient(ingest.Config{
	OnError: func(err ingest.Error) { log.Println(err) },
})
```

A missing or malformed key never breaks your code: the client reports one `config` error and drops events until it is fixed.

## Delivery

- Events are sent every `FlushInterval` (default 1 s), or sooner when a batch of `BatchSize` (100) is full.
- Network errors, 408, 425, 429 and 5xx are retried with backoff (`RetryDelays`, default 1, 2, 4, 8, 16, 32 s). Permanent errors (400, 401, 403, 404, 405, 409, 410, 415, 422) are not retried; the batch is reported through `OnError` with the API's `ServerCode` and `RequestID`.
- Set `SpoolDir` to keep batches that could not be delivered on disk. The next `Flush` or process replays them. Rejected batches go to `<SpoolDir>/dead/`. Limits: `SpoolMaxBytes` (50 MB) and `SpoolMaxAge` (7 days), oldest first. The spool format is shared with the Node.js and Python SDKs.
- `Stats()` returns counts: emitted, accepted, duplicates, rejected, dropped, retries, spooled, replayed, and the dropped reasons.

Go has no exit hook, so **close the client before your process exits**, or queued events are lost:

```go
defer func() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	halvor.Close(ctx)
}()
```

In a serverless handler or a short job, flush before you return; `Flush` reports whether everything was handled:

```go
ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
defer cancel()
halvor.Flush(ctx)
```

## x402

Put the HalvorAI transport under the `http.Client` your agent pays with. Payment requirements, signed payment payloads and settlement responses become events. Headers are only read; nothing in the payment path changes.

```go
import "go.halvorai.com/ingest/x402"

httpClient := &http.Client{Transport: x402.NewTransport(halvor, nil)}
```

Pass your existing transport as the second argument to keep it. Each 402 challenge becomes a `payment.requested` event. The payment that answers it becomes `payment.authorized`, linked to the challenge with `related.previous_event_id`, and the settlement becomes `payment.settled` or `payment.failed` with the same `payment_id`. A challenge without a network or token address is reported as `invalid_event` and not recorded.

Selling over x402? Wrap your handler, inside your x402 payment middleware:

```go
handler = x402.Middleware(halvor, x402.ServerOptions{
	Payee: ingest.Payee{Name: "Market data API"},
})(handler)
```

## Stripe

Map Stripe webhooks after you check their signature. No dependency on stripe-go:

```go
import "go.halvorai.com/ingest/stripe"

// With stripe-go:
event, err := webhook.ConstructEvent(payload, r.Header.Get("Stripe-Signature"), endpointSecret)
if err == nil {
	stripe.EmitObject(r.Context(), halvor, string(event.Type), event.Created, event.Data.Raw)
}

// Or with the raw body:
stripe.Emit(r.Context(), halvor, payload)
```

PaymentIntents, refunds, disputes and Stripe Issuing authorizations and transactions are recorded. To attribute them to an agent, tag the PaymentIntent or Issuing card when you create it:

```go
params.Metadata = stripe.TagMetadata(ctx, params.Metadata, stripe.TagOverrides{})
```

## Develop

```bash
go test -race ./...
go vet ./...
```

The tests run the [ape-schema conformance cases](https://github.com/halvorAI/ape-schema/tree/main/conformance) (40 events and the JCS vectors) and the signing vector shared with the other SDKs.

## Security

Report vulnerabilities privately to hello@halvorai.com.

## License

Apache-2.0
