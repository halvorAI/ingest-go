// Package stripe maps Stripe webhook events to Agent Payment Events, the same way as the
// HalvorAI Node.js SDK.
//
// It has no dependency on stripe-go. Verify the webhook signature first (for example with
// stripe-go's webhook.ConstructEvent), then pass the event to HalvorAI:
//
//	event, err := webhook.ConstructEvent(payload, sigHeader, endpointSecret)
//	if err != nil { ... }
//	stripe.EmitObject(r.Context(), halvor, string(event.Type), event.Created, event.Data.Raw)
//
// Or, with the raw webhook body: stripe.Emit(ctx, halvor, payload).
//
// Handled types: payment_intent.amount_capturable_updated, payment_intent.succeeded,
// payment_intent.payment_failed, charge.refunded, charge.dispute.created,
// issuing_authorization.created, issuing_authorization.updated and issuing_transaction.created.
// Agents and owners are read from metadata.halvor_* (see [TagMetadata]).
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"go.halvorai.com/ingest"
	"go.halvorai.com/ingest/jcs"
)

// HandledTypes are the Stripe event types this package maps.
var HandledTypes = []string{
	"payment_intent.amount_capturable_updated",
	"payment_intent.succeeded",
	"payment_intent.payment_failed",
	"charge.refunded",
	"charge.dispute.created",
	"issuing_authorization.created",
	"issuing_authorization.updated",
	"issuing_transaction.created",
}

// Metadata keys read by the mapper and written by [TagMetadata].
const (
	MetaAgentID       = "halvor_agent_id"
	MetaOwnerID       = "halvor_owner_id"
	MetaOwnerType     = "halvor_owner_type"
	MetaInstructionID = "halvor_instruction_id"
)

// Emit maps a raw Stripe webhook body (already signature-checked) and queues it on client.
// It returns the event id, or false when the type is not one HalvorAI records.
func Emit(ctx context.Context, client *ingest.Client, payload []byte) (string, bool) {
	mapped, err := MapEvent(payload)
	if err != nil {
		client.Notify(ingest.Error{Code: ingest.CodeInvalidEvent, Message: "stripe: " + err.Error()})
		return "", false
	}
	if mapped == nil {
		return "", false
	}
	return client.Emit(ctx, mapped), true
}

// EmitObject is [Emit] for an event that was already decoded, such as stripe-go's
// stripe.Event: pass event.Type, event.Created and event.Data.Raw.
func EmitObject(ctx context.Context, client *ingest.Client, eventType string, created int64, object []byte) (string, bool) {
	mapped, err := MapObject(eventType, created, object)
	if err != nil {
		client.Notify(ingest.Error{Code: ingest.CodeInvalidEvent, Message: "stripe: " + err.Error()})
		return "", false
	}
	if mapped == nil {
		return "", false
	}
	return client.Emit(ctx, mapped), true
}

// MapEvent maps a raw Stripe webhook body to a partial APE event for [ingest.Client.Emit]. It
// returns nil, nil for types HalvorAI does not record.
func MapEvent(payload []byte) (map[string]any, error) {
	v, err := jcs.Parse(payload)
	if err != nil {
		return nil, err
	}
	event, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("webhook body is not an object")
	}
	eventType, _ := event["type"].(string)
	var created int64
	if n, ok := number(event["created"]); ok {
		created = int64(n)
	}
	data, _ := event["data"].(map[string]any)
	object, _ := data["object"].(map[string]any)
	if object == nil {
		if handled(eventType) {
			return nil, errors.New("webhook has no data.object")
		}
		return nil, nil
	}
	return mapObject(eventType, created, object), nil
}

// MapObject maps a decoded event's type, created time (Unix seconds, 0 if unknown) and raw
// data.object JSON.
func MapObject(eventType string, created int64, object []byte) (map[string]any, error) {
	if !handled(eventType) {
		return nil, nil
	}
	v, err := jcs.Parse(object)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("data.object is not an object")
	}
	return mapObject(eventType, created, obj), nil
}

func handled(eventType string) bool {
	for _, t := range HandledTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

func mapObject(eventType string, created int64, obj map[string]any) map[string]any {
	switch eventType {
	case "payment_intent.amount_capturable_updated":
		return mapPaymentIntent(created, obj, ingest.PaymentAuthorized, "authorized")
	case "payment_intent.succeeded":
		return mapPaymentIntent(created, obj, ingest.PaymentSettled, "settled")
	case "payment_intent.payment_failed":
		return mapPaymentIntent(created, obj, ingest.PaymentFailed, "failed")
	case "charge.refunded":
		return mapChargeRefunded(created, obj)
	case "charge.dispute.created":
		return mapDispute(created, obj)
	case "issuing_authorization.created":
		return mapIssuingAuthorization(created, obj, obj["approved"] == false)
	case "issuing_authorization.updated":
		status := str(obj["status"])
		return mapIssuingAuthorization(created, obj, obj["approved"] == false || status == "reversed" || status == "expired")
	case "issuing_transaction.created":
		return mapIssuingTransaction(created, obj)
	}
	return nil
}

// --- helpers -----------------------------------------------------------------------------

func str(v any) string {
	s, _ := v.(string)
	return s
}

func number(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil && !math.IsInf(f, 0)
	case float64:
		return n, true
	}
	return 0, false
}

// truncate cuts s to n UTF-16 code units, like JavaScript's slice.
func truncate(s string, n int) string {
	if jcs.UTF16Len(s) <= n {
		return s
	}
	units := utf16.Encode([]rune(s))
	return string(utf16.Decode(units[:n]))
}

var (
	reCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
	reCountry  = regexp.MustCompile(`(?i)^[A-Z]{2}$`)
	reMCC      = regexp.MustCompile(`^\d{4}$`)
	reHTTP     = regexp.MustCompile(`(?i)^https?://`)
)

func currencyOf(v any) string {
	c := strings.ToUpper(str(v))
	if reCurrency.MatchString(c) {
		return c
	}
	return "USD"
}

func minorAmount(amount float64, currency string) map[string]any {
	return map[string]any{"value": strconv.FormatFloat(math.Trunc(amount), 'f', 0, 64), "unit": "minor", "currency": currency}
}

func amountOf(obj map[string]any, keys ...string) float64 {
	for _, k := range keys {
		if n, ok := number(obj[k]); ok {
			return n
		}
	}
	return 0
}

func metadataOf(obj map[string]any) map[string]string {
	out := map[string]string{}
	meta, _ := obj["metadata"].(map[string]any)
	for k, v := range meta {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func cardMetadata(obj map[string]any) map[string]string {
	card, _ := obj["card"].(map[string]any)
	if card == nil {
		return map[string]string{}
	}
	return metadataOf(card)
}

func occurredAt(created int64) string {
	if created == 0 {
		return ""
	}
	return time.Unix(created, 0).UTC().Format("2006-01-02T15:04:05.000Z")
}

func base(eventType, adapter string, created int64, meta map[string]string, payment, payee, obj map[string]any) map[string]any {
	agentID := meta[MetaAgentID]
	if agentID == "" {
		agentID = "unattributed"
	}
	ownerID := meta[MetaOwnerID]
	if ownerID == "" {
		ownerID = "unattributed"
	}
	ownerType := "business"
	if meta[MetaOwnerType] == "person" {
		ownerType = "person"
	}
	sha, _ := ingest.EvidenceSHA256(obj)
	out := map[string]any{
		"type":     eventType,
		"source":   map[string]any{"adapter": adapter},
		"agent":    map[string]any{"id": agentID},
		"owner":    map[string]any{"id": ownerID, "type": ownerType},
		"payment":  payment,
		"payee":    payee,
		"evidence": []any{map[string]any{"kind": "stripe.object", "format": "json", "value": obj, "sha256": sha}},
	}
	if at := occurredAt(created); at != "" {
		out["occurred_at"] = at
	}
	if id := meta[MetaInstructionID]; id != "" {
		// Webhooks only carry the id; hash a stable local stand-in so the event validates.
		out["instruction"] = map[string]any{"id": id, "hash": ingest.HashInstruction("stripe-meta:" + id)}
	}
	return out
}

func payeeFromConnect(obj map[string]any) map[string]any {
	transfer, _ := obj["transfer_data"].(map[string]any)
	destination := str(transfer["destination"])
	if destination == "" {
		destination = str(obj["on_behalf_of"])
	}
	if destination != "" {
		return map[string]any{"type": "merchant", "id": destination}
	}
	if d := str(obj["description"]); d != "" {
		return map[string]any{"type": "merchant", "name": truncate(d, 256)}
	}
	return map[string]any{"type": "merchant", "name": "Stripe merchant"}
}

func payeeFromMerchantData(obj map[string]any) map[string]any {
	md, _ := obj["merchant_data"].(map[string]any)
	if md == nil {
		return map[string]any{"type": "merchant", "name": "Card merchant"}
	}
	payee := map[string]any{"type": "merchant"}
	if name := str(md["name"]); name != "" {
		payee["name"] = name
	}
	if id := str(md["network_id"]); id != "" {
		payee["id"] = id
	}
	if country := str(md["country"]); reCountry.MatchString(country) {
		payee["country"] = strings.ToUpper(country)
	}
	if mcc := str(md["category_code"]); reMCC.MatchString(mcc) {
		payee["mcc"] = mcc
	}
	if url := str(md["url"]); reHTTP.MatchString(url) {
		payee["website"] = url
	}
	if payee["name"] == nil && payee["id"] == nil {
		payee["name"] = "Card merchant"
	}
	return payee
}

func sharedPaymentToken(obj map[string]any) string {
	meta := metadataOf(obj)
	if t := meta["shared_payment_token"]; t != "" {
		return t
	}
	if t := meta["halvor_shared_payment_token"]; t != "" {
		return t
	}
	return str(obj["shared_payment_token"])
}

func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// --- mappers -----------------------------------------------------------------------------

func mapPaymentIntent(created int64, obj map[string]any, eventType, status string) map[string]any {
	id := orDefault(str(obj["id"]), "pi_unknown")
	railRef := map[string]any{"payment_intent": id}
	payment := map[string]any{
		"payment_id": id,
		"rail":       "stripe",
		"amount":     minorAmount(amountOf(obj, "amount"), currencyOf(obj["currency"])),
		"status":     status,
		"rail_ref":   railRef,
	}
	if d := str(obj["description"]); d != "" {
		payment["description"] = truncate(d, 256)
	}
	if status == "failed" {
		lastErr, _ := obj["last_payment_error"].(map[string]any)
		payment["failure_reason"] = truncate(orDefault(str(lastErr["code"]), "payment_failed"), 128)
	}
	spt := sharedPaymentToken(obj)
	if spt != "" {
		railRef["shared_payment_token"] = spt
	}
	if account := str(obj["on_behalf_of"]); account != "" {
		railRef["account"] = account
	}
	out := base(eventType, "stripe", created, metadataOf(obj), payment, payeeFromConnect(obj), obj)
	if spt != "" {
		out["instrument"] = map[string]any{"type": "stripe_spt"}
	}
	return out
}

func mapChargeRefunded(created int64, obj map[string]any) map[string]any {
	chargeID := orDefault(str(obj["id"]), "ch_unknown")
	pi := str(obj["payment_intent"])
	railRef := map[string]any{"charge": chargeID}
	if pi != "" {
		railRef["payment_intent"] = pi
	}
	payment := map[string]any{
		"payment_id": orDefault(pi, chargeID),
		"rail":       "stripe",
		"amount":     minorAmount(amountOf(obj, "amount_refunded", "amount"), currencyOf(obj["currency"])),
		"status":     "refunded",
		"rail_ref":   railRef,
	}
	if d := str(obj["description"]); d != "" {
		payment["description"] = truncate(d, 256)
	}
	return base(ingest.PaymentRefunded, "stripe", created, metadataOf(obj), payment, payeeFromConnect(obj), obj)
}

func mapDispute(created int64, obj map[string]any) map[string]any {
	disputeID := orDefault(str(obj["id"]), "dp_unknown")
	pi, charge := str(obj["payment_intent"]), str(obj["charge"])
	railRef := map[string]any{"dispute": disputeID}
	if pi != "" {
		railRef["payment_intent"] = pi
	}
	if charge != "" {
		railRef["charge"] = charge
	}
	payment := map[string]any{
		"payment_id": orDefault(pi, orDefault(charge, disputeID)),
		"rail":       "stripe",
		"amount":     minorAmount(amountOf(obj, "amount"), currencyOf(obj["currency"])),
		"status":     "disputed",
		"rail_ref":   railRef,
	}
	if reason := str(obj["reason"]); reason != "" {
		payment["description"] = truncate(reason, 256)
	}
	return base(ingest.PaymentDisputed, "stripe", created, metadataOf(obj), payment, map[string]any{"type": "merchant", "name": "Stripe dispute"}, obj)
}

func issuingMeta(obj map[string]any) map[string]string {
	meta := metadataOf(obj)
	for k, v := range cardMetadata(obj) {
		meta[k] = v
	}
	return meta
}

func merchantDetails(payment, merchant map[string]any) {
	if mcc := str(merchant["mcc"]); mcc != "" {
		payment["category"] = "mcc:" + mcc
	}
	if name := str(merchant["name"]); name != "" {
		payment["description"] = truncate(name, 256)
	}
}

func mapIssuingAuthorization(created int64, obj map[string]any, failed bool) map[string]any {
	id := orDefault(str(obj["id"]), "iauth_unknown")
	merchant := payeeFromMerchantData(obj)
	status, eventType := "authorized", ingest.PaymentAuthorized
	if failed {
		status, eventType = "failed", ingest.PaymentFailed
	}
	payment := map[string]any{
		"payment_id": id,
		"rail":       "card",
		"amount":     minorAmount(amountOf(obj, "amount"), currencyOf(obj["currency"])),
		"status":     status,
		"rail_ref":   map[string]any{"authorization_id": id, "processor": "stripe-issuing"},
	}
	if failed {
		payment["failure_reason"] = "issuing_authorization_declined"
	}
	merchantDetails(payment, merchant)
	out := base(eventType, "stripe-issuing", created, issuingMeta(obj), payment, merchant, obj)
	if card, ok := obj["card"].(map[string]any); ok {
		instrument := map[string]any{"type": "card", "issuer": "Stripe Issuing"}
		if last4 := str(card["last4"]); reMCC.MatchString(last4) {
			instrument["last4"] = last4
		}
		if brand := str(card["brand"]); brand != "" {
			instrument["network"] = strings.ToLower(brand)
		}
		out["instrument"] = instrument
	}
	return out
}

func mapIssuingTransaction(created int64, obj map[string]any) map[string]any {
	id := orDefault(str(obj["id"]), "ipi_unknown")
	refunded := orDefault(str(obj["type"]), "capture") == "refund"
	merchant := payeeFromMerchantData(obj)
	railRef := map[string]any{"transaction_id": id, "processor": "stripe-issuing"}
	if auth := str(obj["authorization"]); auth != "" {
		railRef["authorization_id"] = auth
	}
	status, eventType := "settled", ingest.PaymentSettled
	if refunded {
		status, eventType = "refunded", ingest.PaymentRefunded
	}
	payment := map[string]any{
		"payment_id": id,
		"rail":       "card",
		"amount":     minorAmount(math.Abs(amountOf(obj, "amount")), currencyOf(obj["currency"])),
		"status":     status,
		"rail_ref":   railRef,
	}
	merchantDetails(payment, merchant)
	return base(eventType, "stripe-issuing", created, issuingMeta(obj), payment, merchant, obj)
}

// --- tagging -----------------------------------------------------------------------------

// TagOverrides sets attribution explicitly instead of from the agent context.
type TagOverrides struct {
	AgentID       string
	OwnerID       string
	OwnerType     string
	InstructionID string
}

// TagMetadata returns a copy of metadata with metadata.halvor_* set from the agent context in
// ctx (or overrides). Use it when you create a PaymentIntent or an Issuing card, so webhooks for
// that payment are attributed to the agent:
//
//	params.Metadata = stripe.TagMetadata(ctx, params.Metadata, stripe.TagOverrides{})
func TagMetadata(ctx context.Context, metadata map[string]string, overrides TagOverrides) map[string]string {
	out := make(map[string]string, len(metadata)+4)
	for k, v := range metadata {
		out[k] = v
	}
	ac, _ := ingest.AgentContextFrom(ctx)
	agentID, ownerID, ownerType, instructionID := overrides.AgentID, overrides.OwnerID, overrides.OwnerType, overrides.InstructionID
	if agentID == "" && ac.Agent != nil {
		agentID = ac.Agent.ID
	}
	if ownerID == "" && ac.Owner != nil {
		ownerID = ac.Owner.ID
	}
	if ownerType == "" && ac.Owner != nil {
		ownerType = ac.Owner.Type
	}
	if instructionID == "" && ac.Instruction != nil {
		instructionID = ac.Instruction.ID
	}
	set := func(k, v string) {
		if v != "" {
			out[k] = v
		}
	}
	set(MetaAgentID, agentID)
	set(MetaOwnerID, ownerID)
	set(MetaOwnerType, ownerType)
	set(MetaInstructionID, instructionID)
	return out
}
