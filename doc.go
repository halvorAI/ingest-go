// Package ingest sends signed, attributed payment events for AI agents to HalvorAI. It is
// never in the payment path: Emit returns at once, never fails and never waits for the network.
//
// Every event is an Agent Payment Event (APE v0.1, https://schema.halvorai.com): the payment,
// the agent that made it, the person or business it acted for, and the instruction it was
// given. The client validates each event, removes card numbers and secrets from free text,
// signs it with your source's Ed25519 key (a detached JWS over the RFC 8785 canonical form)
// and delivers it in batches, with retries and an optional disk spool. Events are
// byte-identical to the HalvorAI Node.js and Python SDKs.
//
// Adapters for x402 (go.halvorai.com/ingest/x402) and Stripe webhooks
// (go.halvorai.com/ingest/stripe) map rail payloads to events for you.
//
// The package has no dependencies outside the Go standard library.
package ingest
