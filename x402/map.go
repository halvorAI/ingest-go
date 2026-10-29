// Package x402 records x402 payments as Agent Payment Events, the same way as the HalvorAI
// Node.js and Python SDKs. It only reads payment headers; nothing in the payment path changes.
//
// Client side, put [Transport] under the http.Client your agent pays with:
//
//	httpClient := &http.Client{Transport: x402.NewTransport(halvor, nil)}
//
// Server side, wrap your handler (inside your x402 payment middleware):
//
//	handler = x402.Middleware(halvor, x402.ServerOptions{Payee: payee})(handler)
//
// Mapping rules (ape-schema docs/MAPPINGS.md §5.1):
//   - payment.requested has payment_id x402:<network>:requested:<event id>, so every 402
//     challenge is its own payment request.
//   - Every later stage uses x402:<network>:<nonce>, never the transaction hash, so
//     authorization, settlement and failure join. The authorized event links to its challenge
//     with related.previous_event_id.
//   - A missing network or asset is never guessed: the event is reported as invalid_event
//     instead of being recorded with a testnet or a zero address.
package x402

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"unicode/utf16"

	"go.halvorai.com/ingest"
	"go.halvorai.com/ingest/jcs"
)

// Header names of the x402 v2 HTTP transport.
const (
	HeaderPaymentRequired  = "PAYMENT-REQUIRED"
	HeaderPaymentSignature = "PAYMENT-SIGNATURE"
	HeaderPaymentResponse  = "PAYMENT-RESPONSE"
)

// Adapter names.
const (
	AdapterClient = "x402-client"
	AdapterServer = "x402-server"
)

// DecodeHeader decodes a base64 (standard or URL-safe, padded or not) JSON payment header.
func DecodeHeader(value string) (map[string]any, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("empty payment header")
	}
	b64 := strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(trimmed), "=")
	raw, err := base64.RawStdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("payment header is not valid base64")
	}
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, errors.New("payment header is not valid JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("payment header is not a JSON object")
	}
	return m, nil
}

// EncodeHeader encodes a value as a base64 JSON payment header (for tests and servers).
func EncodeHeader(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func truncate(s string, n int) string {
	if jcs.UTF16Len(s) <= n {
		return s
	}
	return string(utf16.Decode(utf16.Encode([]rune(s))[:n]))
}

func host(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// attribution sets agent and owner only when the agent context does not; otherwise the client
// fills the full context (name, framework, country, KYC reference) at emit time.
func attribution(ctx context.Context, out map[string]any, payerWallet string) {
	ac, _ := ingest.AgentContextFrom(ctx)
	if ac.Agent == nil {
		id := payerWallet
		if id == "" {
			id = "unattributed"
		}
		out["agent"] = map[string]any{"id": id}
	}
	if ac.Owner == nil {
		out["owner"] = map[string]any{"id": "unattributed", "type": "business"}
	}
}

func asset(accept map[string]any) (map[string]any, error) {
	network := str(accept["network"])
	if network == "" {
		return nil, errors.New("x402 payment requirement has no network; event not recorded")
	}
	address := str(accept["asset"])
	if address == "" {
		return nil, errors.New("x402 payment requirement has no asset; event not recorded")
	}
	out := map[string]any{"network": network, "address": address}
	extra := obj(accept["extra"])
	if name := str(extra["name"]); name != "" {
		out["symbol"] = truncate(name, 16)
	}
	if d, ok := extra["decimals"].(json.Number); ok {
		if n, err := d.Int64(); err == nil {
			out["decimals"] = n
		}
	} else if d, ok := extra["decimals"].(float64); ok && d == float64(int64(d)) {
		out["decimals"] = int64(d)
	}
	return out, nil
}

func amount(accept map[string]any, override string) (map[string]any, error) {
	a, err := asset(accept)
	if err != nil {
		return nil, err
	}
	value := override
	if value == "" {
		value = str(accept["amount"])
	}
	if value == "" {
		value = "0"
	}
	return map[string]any{"value": value, "unit": "atomic", "asset": a}, nil
}

func payeeOf(accept, resource, override map[string]any) map[string]any {
	if override != nil {
		out := make(map[string]any, len(override))
		for k, v := range override {
			out[k] = v
		}
		return out
	}
	u := str(resource["url"])
	name := str(resource["serviceName"])
	if name == "" {
		name = str(resource["description"])
	}
	if name == "" {
		name = host(u)
	}
	payee := map[string]any{"type": "wallet"}
	if u != "" {
		payee["type"] = "api_provider"
		payee["resource_url"] = u
	}
	if name != "" {
		payee["name"] = truncate(name, 256)
	}
	if payTo, network := str(accept["payTo"]), str(accept["network"]); payTo != "" && network != "" {
		payee["wallet"] = map[string]any{"network": network, "address": payTo}
	}
	if payee["name"] == nil && payee["wallet"] == nil {
		payee["name"] = "x402 payee"
	}
	return payee
}

func railRef(accept map[string]any, extra map[string]any) map[string]any {
	ref := map[string]any{}
	if s := str(accept["scheme"]); s != "" {
		ref["scheme"] = s
	}
	if n := str(accept["network"]); n != "" {
		ref["network"] = n
	}
	if flow := str(obj(accept["extra"])["paymentFlow"]); flow != "" {
		ref["payment_flow"] = flow
	}
	for k, v := range extra {
		ref[k] = v
	}
	return ref
}

func description(payment, resource map[string]any) {
	if d := str(resource["description"]); d != "" {
		payment["description"] = truncate(d, 256)
	}
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func evidence(kind string, value map[string]any) []any {
	sha, _ := ingest.EvidenceSHA256(value)
	return []any{map[string]any{"kind": kind, "format": "json", "value": value, "sha256": sha}}
}

// MapPaymentRequired maps a decoded PAYMENT-REQUIRED header (a 402 challenge) to a
// payment.requested event with its own id. It returns nil, nil when there is nothing to map.
// payee replaces the payee read from the challenge (servers pass their own identity).
func MapPaymentRequired(ctx context.Context, required map[string]any, adapter string, payee map[string]any) (map[string]any, error) {
	accepts, _ := required["accepts"].([]any)
	if len(accepts) == 0 {
		return nil, nil
	}
	accept, ok := accepts[0].(map[string]any)
	if !ok {
		return nil, nil
	}
	amt, err := amount(accept, "")
	if err != nil {
		return nil, err
	}
	resource := obj(required["resource"])
	id := ingest.NewEventID()
	payment := map[string]any{
		"payment_id": "x402:" + orUnknown(str(accept["network"])) + ":requested:" + id,
		"rail":       "x402",
		"amount":     amt,
		"status":     "requested",
		"rail_ref":   railRef(accept, nil),
	}
	description(payment, resource)
	out := map[string]any{
		"id":       id,
		"type":     ingest.PaymentRequested,
		"source":   map[string]any{"adapter": adapter},
		"payment":  payment,
		"payee":    payeeOf(accept, resource, payee),
		"evidence": []any{},
	}
	attribution(ctx, out, "")
	return out, nil
}

// MapPaymentPayload maps a decoded PAYMENT-SIGNATURE header to a payment.authorized event.
// previousEventID is the id of the payment.requested event it answers, if known.
func MapPaymentPayload(ctx context.Context, payload map[string]any, adapter string, payee map[string]any, previousEventID string) (map[string]any, error) {
	accept, ok := payload["accepted"].(map[string]any)
	if !ok {
		return nil, nil
	}
	auth := obj(obj(payload["payload"])["authorization"])
	nonce := orUnknown(str(auth["nonce"]))
	payer := str(auth["from"])
	amt, err := amount(accept, str(auth["value"]))
	if err != nil {
		return nil, err
	}
	payment := map[string]any{
		"payment_id": "x402:" + orUnknown(str(accept["network"])) + ":" + nonce,
		"rail":       "x402",
		"amount":     amt,
		"status":     "authorized",
		"rail_ref":   railRef(accept, map[string]any{"nonce": nonce}),
	}
	resource := obj(payload["resource"])
	description(payment, resource)
	out := map[string]any{
		"type":     ingest.PaymentAuthorized,
		"source":   map[string]any{"adapter": adapter},
		"payment":  payment,
		"payee":    payeeOf(accept, resource, payee),
		"evidence": evidence("x402.payment_payload", payload),
	}
	attribution(ctx, out, payer)
	if network := str(accept["network"]); payer != "" && network != "" {
		out["instrument"] = map[string]any{"type": "wallet", "wallet": map[string]any{"network": network, "address": payer}}
	}
	if previousEventID != "" {
		out["related"] = map[string]any{"previous_event_id": previousEventID}
	}
	return out, nil
}

// SettlementContext is what a settlement response alone does not say: the accepted payment
// requirement, the authorization nonce and the resource, taken from the payment payload.
type SettlementContext struct {
	Accept   map[string]any
	Nonce    string
	Resource map[string]any
	Payee    map[string]any
}

// SettlementContextFrom reads the settlement context from a decoded payment payload.
func SettlementContextFrom(payload map[string]any) SettlementContext {
	if payload == nil {
		return SettlementContext{}
	}
	accept, _ := payload["accepted"].(map[string]any)
	resource, _ := payload["resource"].(map[string]any)
	return SettlementContext{
		Accept:   accept,
		Nonce:    str(obj(obj(payload["payload"])["authorization"])["nonce"]),
		Resource: resource,
	}
}

// MapSettlementResponse maps a decoded PAYMENT-RESPONSE header to payment.settled or
// payment.failed.
func MapSettlementResponse(ctx context.Context, settlement map[string]any, sc SettlementContext, adapter string) (map[string]any, error) {
	merged := map[string]any{"scheme": "exact"}
	if sc.Accept != nil {
		for k, v := range sc.Accept {
			merged[k] = v
		}
	} else {
		if n := str(settlement["network"]); n != "" {
			merged["network"] = n
		}
		if a := str(settlement["amount"]); a != "" {
			merged["amount"] = a
		}
	}
	network := str(settlement["network"])
	if network == "" {
		network = orUnknown(str(merged["network"]))
	}
	success := settlement["success"] == true
	payer := str(settlement["payer"])
	extra := map[string]any{}
	if sc.Nonce != "" {
		extra["nonce"] = sc.Nonce
	}
	if tx := str(settlement["transaction"]); tx != "" {
		extra["tx_hash"] = tx
	}
	override := str(settlement["amount"])
	if override == "" {
		override = str(merged["amount"])
	}
	amt, err := amount(merged, override)
	if err != nil {
		return nil, err
	}
	status, eventType := "failed", ingest.PaymentFailed
	if success {
		status, eventType = "settled", ingest.PaymentSettled
	}
	payment := map[string]any{
		"payment_id": "x402:" + network + ":" + orUnknown(sc.Nonce),
		"rail":       "x402",
		"amount":     amt,
		"status":     status,
		"rail_ref":   railRef(merged, extra),
	}
	if !success {
		reason := str(settlement["errorReason"])
		if reason == "" {
			reason = "settlement_failed"
		}
		payment["failure_reason"] = truncate(reason, 128)
	}
	description(payment, sc.Resource)
	out := map[string]any{
		"type":     eventType,
		"source":   map[string]any{"adapter": adapter},
		"payment":  payment,
		"payee":    payeeOf(merged, sc.Resource, sc.Payee),
		"evidence": evidence("x402.settlement", settlement),
	}
	attribution(ctx, out, payer)
	if payer != "" && network != "unknown" {
		out["instrument"] = map[string]any{"type": "wallet", "wallet": map[string]any{"network": network, "address": payer}}
	}
	return out, nil
}
