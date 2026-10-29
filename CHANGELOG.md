# Changelog

## 0.1.0 (developer preview)

- `Client`: validates, redacts, signs (EdDSA, detached JWS over RFC 8785) and delivers Agent Payment Events in batches from a background goroutine. `Emit` never fails, panics or waits for I/O.
- Delivery rules shared with the Node.js and Python SDKs: retries with backoff on network errors, 408, 425, 429 and 5xx; permanent errors dead-lettered and reported once with the API's code and request id; batches that are too large split; per-event results counted.
- Disk spool (`SpoolDir`, 50 MB and 7-day limits) in the same format as the other SDKs, replayed by the next `Flush` or process.
- `WithAgentContext`: attributes payments to an agent, owner and instruction through `context.Context`; instruction text is hashed locally.
- Card numbers, CVCs, API keys and private keys are removed from free-text fields and JSON evidence before signing.
- `ValidateEvent`, `SignEvent`, `VerifyEvent`, `GenerateSourceKey` and the `jcs` package, byte-identical to the Node.js and Python SDKs.
- `x402`: an `http.RoundTripper` for agents and a `net/http` middleware for sellers.
- `stripe`: maps PaymentIntent, refund, dispute and Stripe Issuing webhooks; `TagMetadata` attributes them to an agent. No dependency on stripe-go.
- Passes the ape-schema conformance cases (40/40) and the shared signing vector.
- No dependencies outside the Go standard library. Go 1.22 or later.
