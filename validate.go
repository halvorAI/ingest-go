package ingest

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.halvorai.com/ingest/jcs"
)

// Problem is one reason an event does not match APE v0.1.
type Problem struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (p Problem) String() string {
	if p.Path == "" {
		return p.Message
	}
	return p.Path + ": " + p.Message
}

// PANDetected is the Problem message for a card number in a free-text field.
const PANDetected = "pan_detected"

var (
	reCountry  = regexp.MustCompile(`^[A-Z]{2}$`)
	reCAIP2    = regexp.MustCompile(`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`)
	reSHA256   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reAmount   = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	reCurrency = regexp.MustCompile(`^[A-Z]{3}$`)
	reFour     = regexp.MustCompile(`^[0-9]{4}$`)
	reDateTime = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
	reURL      = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://\S+$`)
)

var (
	sourceAdapters = []string{"stripe", "stripe-issuing", "x402-client", "x402-server", "mpp-server", "mcp", "manual", "custom"}
	eventTypes     = []string{"payment.requested", "payment.authorized", "payment.settled", "payment.failed", "payment.refunded", "payment.disputed"}
	statuses       = []string{"requested", "authorized", "settled", "failed", "refunded", "disputed"}
	evidenceKinds  = []string{"ap2.payment_mandate", "ap2.checkout_mandate", "vi.chain", "tap.signature", "x402.payment_payload", "x402.settlement", "mpp.receipt", "stripe.object", "agentic_token.metadata", "kya.attestation"}
	railRefKeys    = map[string][]string{
		"stripe":        {"account", "payment_intent", "charge", "refund", "dispute", "shared_payment_token"},
		"card":          {"authorization_id", "transaction_id", "network_transaction_id", "processor"},
		"x402":          {"scheme", "network", "nonce", "tx_hash", "facilitator", "payment_flow"},
		"mpp":           {"method", "challenge_id", "payment_intent", "tx_hash"},
		"stablecoin":    {"network", "tx_hash", "log_index"},
		"bank_transfer": {"scheme", "end_to_end_id", "pisp"},
	}
)

// ValidateEvent checks a complete event (a decoded JSON object) against APE v0.1 and the
// card-number rule. It returns nil when the event is valid. It accepts and rejects exactly what
// the published schema at https://schema.halvorai.com/ape/v0.1.json does, as the Node.js and
// Python SDKs do.
func ValidateEvent(event map[string]any) []Problem {
	v := &validator{}
	v.event(event)
	return v.problems
}

type validator struct{ problems []Problem }

func (v *validator) add(path, format string, args ...any) {
	v.problems = append(v.problems, Problem{Path: path, Message: fmt.Sprintf(format, args...)})
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// object checks that value is an object with no keys outside allowed and no nulls, and that the
// required keys are present. It returns nil if value is not an object.
func (v *validator) object(path string, value any, required, optional []string) map[string]any {
	obj, ok := value.(map[string]any)
	if !ok {
		v.add(path, "expected an object")
		return nil
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, ok := obj[k]; !ok {
			v.add(join(path, k), "is required")
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowed[k] {
			v.add(join(path, k), "is not an APE v0.1 field")
		} else if obj[k] == nil {
			v.add(join(path, k), "null is not allowed; leave the field out")
		}
	}
	return obj
}

// present returns the value at key if it is set and not null (nulls are reported by object).
func present(obj map[string]any, key string) (any, bool) {
	value, ok := obj[key]
	return value, ok && value != nil
}

func (v *validator) str(obj map[string]any, path, key string, max int, check func(string) bool, what string) (string, bool) {
	value, ok := present(obj, key)
	if !ok {
		return "", false
	}
	s, isStr := value.(string)
	p := join(path, key)
	switch {
	case !isStr:
		v.add(p, "expected a string")
		return "", false
	case max > 0 && jcs.UTF16Len(s) > max:
		v.add(p, "must be at most %d characters", max)
		return "", false
	case check != nil && !check(s):
		v.add(p, "must be %s", what)
		return "", false
	}
	return s, true
}

func (v *validator) maxStr(obj map[string]any, path, key string, max int) (string, bool) {
	return v.str(obj, path, key, max, nil, "")
}

func (v *validator) pattern(obj map[string]any, path, key string, re *regexp.Regexp, what string) (string, bool) {
	return v.str(obj, path, key, 0, re.MatchString, what)
}

func (v *validator) enum(obj map[string]any, path, key string, values []string) (string, bool) {
	return v.str(obj, path, key, 0, func(s string) bool {
		for _, allowed := range values {
			if s == allowed {
				return true
			}
		}
		return false
	}, "one of "+strings.Join(values, ", "))
}

func isDateTime(s string) bool {
	if !reDateTime.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}

func (v *validator) dateTime(obj map[string]any, path, key string) {
	v.str(obj, path, key, 0, isDateTime, "an RFC 3339 date-time with an offset")
}

func (v *validator) url(obj map[string]any, path, key string) (string, bool) {
	return v.str(obj, path, key, 0, reURL.MatchString, "a URL")
}

// integer reports whether value is a JSON integer, returning it.
func integer(value any) (float64, bool) {
	var f float64
	switch n := value.(type) {
	case json.Number:
		var err error
		if f, err = n.Float64(); err != nil {
			return 0, false
		}
	case float64:
		f = n
	case float32:
		f = float64(n)
	default:
		rv := reflect.ValueOf(value)
		switch rv.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			return float64(rv.Int()), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			return float64(rv.Uint()), true
		}
		return 0, false
	}
	return f, !math.IsInf(f, 0) && f == math.Trunc(f)
}

func (v *validator) event(event map[string]any) {
	obj := v.object("", event,
		[]string{"ape_version", "id", "type", "occurred_at", "environment", "source", "agent", "owner", "payment", "payee"},
		[]string{"instruction", "instrument", "evidence", "related", "labels"})
	if obj == nil {
		return
	}
	v.str(obj, "", "ape_version", 0, func(s string) bool { return s == APEVersion }, `"0.1"`)
	if id, ok := v.maxStr(obj, "", "id", 128); ok && jcs.UTF16Len(id) < 8 {
		v.add("id", "must be at least 8 characters")
	}
	v.enum(obj, "", "type", eventTypes)
	v.dateTime(obj, "", "occurred_at")
	v.enum(obj, "", "environment", []string{"test", "live"})

	if source, ok := present(obj, "source"); ok {
		if s := v.object("source", source, []string{"id", "sdk", "adapter"}, nil); s != nil {
			v.maxStr(s, "source", "id", 64)
			v.maxStr(s, "source", "sdk", 64)
			v.enum(s, "source", "adapter", sourceAdapters)
		}
	}
	free := []freeText{}
	if agent, ok := present(obj, "agent"); ok {
		if a := v.object("agent", agent, []string{"id"}, []string{"name", "framework", "version", "key_thumbprint", "kya"}); a != nil {
			v.maxStr(a, "agent", "id", 128)
			if name, ok := v.maxStr(a, "agent", "name", 128); ok {
				free = append(free, freeText{"agent.name", name})
			}
			v.maxStr(a, "agent", "framework", 64)
			v.maxStr(a, "agent", "version", 64)
			v.maxStr(a, "agent", "key_thumbprint", 64)
			if kya, ok := present(a, "kya"); ok {
				if k := v.object("agent.kya", kya, []string{"provider", "subject"}, []string{"assurance", "verified_at"}); k != nil {
					v.maxStr(k, "agent.kya", "provider", 64)
					v.maxStr(k, "agent.kya", "subject", 256)
					v.maxStr(k, "agent.kya", "assurance", 64)
					v.dateTime(k, "agent.kya", "verified_at")
				}
			}
		}
	}
	if owner, ok := present(obj, "owner"); ok {
		if o := v.object("owner", owner, []string{"id", "type"}, []string{"display_name", "country", "kyc_ref"}); o != nil {
			v.maxStr(o, "owner", "id", 128)
			v.enum(o, "owner", "type", []string{"person", "business"})
			if name, ok := v.maxStr(o, "owner", "display_name", 128); ok {
				free = append(free, freeText{"owner.display_name", name})
			}
			v.pattern(o, "owner", "country", reCountry, "an ISO 3166-1 alpha-2 code")
			v.maxStr(o, "owner", "kyc_ref", 128)
		}
	}
	if instruction, ok := present(obj, "instruction"); ok {
		if in := v.object("instruction", instruction, []string{"id", "hash"}, []string{"summary", "channel", "issued_at", "tool_call_id"}); in != nil {
			v.maxStr(in, "instruction", "id", 128)
			v.pattern(in, "instruction", "hash", reSHA256, "sha256: and 64 lowercase hex digits")
			if summary, ok := v.maxStr(in, "instruction", "summary", 500); ok {
				free = append(free, freeText{"instruction.summary", summary})
			}
			v.enum(in, "instruction", "channel", []string{"chat", "api", "schedule", "email", "agent", "other"})
			v.dateTime(in, "instruction", "issued_at")
			v.maxStr(in, "instruction", "tool_call_id", 128)
		}
	}
	if payment, ok := present(obj, "payment"); ok {
		free = append(free, v.payment(payment)...)
	}
	if payee, ok := present(obj, "payee"); ok {
		free = append(free, v.payee(payee)...)
	}
	if instrument, ok := present(obj, "instrument"); ok {
		if in := v.object("instrument", instrument, []string{"type"}, []string{"network", "last4", "par", "token_ref", "wallet", "issuer"}); in != nil {
			v.enum(in, "instrument", "type", []string{"card", "agentic_token", "stripe_spt", "wallet", "bank_account"})
			v.maxStr(in, "instrument", "network", 32)
			v.pattern(in, "instrument", "last4", reFour, "4 digits")
			v.maxStr(in, "instrument", "par", 64)
			v.maxStr(in, "instrument", "token_ref", 128)
			if w, ok := present(in, "wallet"); ok {
				v.wallet("instrument.wallet", w)
			}
			v.maxStr(in, "instrument", "issuer", 128)
		}
	}
	if evidence, ok := present(obj, "evidence"); ok {
		v.evidence(evidence)
	}
	if related, ok := present(obj, "related"); ok {
		if r := v.object("related", related, nil, []string{"previous_event_id", "corrects_event_id", "session_id"}); r != nil {
			v.maxStr(r, "related", "previous_event_id", 128)
			v.maxStr(r, "related", "corrects_event_id", 128)
			v.maxStr(r, "related", "session_id", 128)
		}
	}
	if labels, ok := present(obj, "labels"); ok {
		free = append(free, v.labels(labels)...)
	}
	for _, f := range free {
		if ContainsPAN(f.text) {
			v.add(f.path, PANDetected)
		}
	}
}

type freeText struct{ path, text string }

func (v *validator) wallet(path string, value any) {
	if w := v.object(path, value, []string{"network", "address"}, nil); w != nil {
		v.pattern(w, path, "network", reCAIP2, "a CAIP-2 chain id")
		v.maxStr(w, path, "address", 128)
	}
}

func (v *validator) payment(value any) []freeText {
	rail := ""
	if obj, ok := value.(map[string]any); ok {
		rail, _ = obj["rail"].(string)
	}
	refKeys, knownRail := railRefKeys[rail]
	p := v.object("payment", value,
		[]string{"payment_id", "rail", "amount", "status", "rail_ref"},
		[]string{"failure_reason", "description", "category"})
	if p == nil {
		return nil
	}
	free := []freeText{}
	v.maxStr(p, "payment", "payment_id", 256)
	if _, ok := present(p, "rail"); ok && !knownRail {
		v.add("payment.rail", "must be one of stripe, card, x402, mpp, stablecoin, bank_transfer")
	}
	if amount, ok := present(p, "amount"); ok {
		v.amount(amount)
	}
	status, _ := v.enum(p, "payment", "status", statuses)
	reason, hasReason := v.maxStr(p, "payment", "failure_reason", 128)
	if hasReason {
		free = append(free, freeText{"payment.failure_reason", reason})
	}
	if status == "failed" {
		if _, ok := p["failure_reason"]; !ok {
			v.add("payment.failure_reason", "failure_reason is required when status is failed")
		}
	}
	if description, ok := v.maxStr(p, "payment", "description", 256); ok {
		free = append(free, freeText{"payment.description", description})
	}
	if category, ok := v.maxStr(p, "payment", "category", 64); ok {
		free = append(free, freeText{"payment.category", category})
	}
	if ref, ok := present(p, "rail_ref"); ok && knownRail {
		if r := v.object("payment.rail_ref", ref, nil, refKeys); r != nil {
			for k, item := range r {
				if item == nil {
					continue
				}
				_, isStr := item.(string)
				_, isInt := integer(item)
				if !isStr && !isInt {
					v.add("payment.rail_ref."+k, "must be a string or an integer")
				}
			}
		}
	}
	return free
}

func (v *validator) asset(path string, value any) {
	a := v.object(path, value, []string{"network", "address"}, []string{"symbol", "decimals"})
	if a == nil {
		return
	}
	v.pattern(a, path, "network", reCAIP2, "a CAIP-2 chain id")
	v.maxStr(a, path, "address", 128)
	v.maxStr(a, path, "symbol", 16)
	if d, ok := present(a, "decimals"); ok {
		if n, isInt := integer(d); !isInt || n < 0 || n > 36 {
			v.add(path+".decimals", "must be an integer from 0 to 36")
		}
	}
}

func (v *validator) amount(value any) {
	unit := ""
	if obj, ok := value.(map[string]any); ok {
		unit, _ = obj["unit"].(string)
	}
	var a map[string]any
	switch unit {
	case "minor":
		a = v.object("payment.amount", value, []string{"value", "unit", "currency"}, []string{"asset"})
	case "atomic":
		a = v.object("payment.amount", value, []string{"value", "unit", "asset"}, []string{"currency"})
	default:
		if _, ok := value.(map[string]any); !ok {
			v.add("payment.amount", "expected an object")
		} else {
			v.add("payment.amount.unit", `must be "minor" or "atomic"`)
		}
		return
	}
	if a == nil {
		return
	}
	v.pattern(a, "payment.amount", "value", reAmount, "a non-negative integer string")
	v.pattern(a, "payment.amount", "currency", reCurrency, "an ISO 4217 code")
	if asset, ok := present(a, "asset"); ok {
		v.asset("payment.amount.asset", asset)
	}
}

func (v *validator) payee(value any) []freeText {
	p := v.object("payee", value, []string{"type"}, []string{"name", "id", "website", "country", "mcc", "wallet", "resource_url"})
	if p == nil {
		return nil
	}
	free := []freeText{}
	v.enum(p, "payee", "type", []string{"merchant", "api_provider", "wallet", "business", "person"})
	if name, ok := v.maxStr(p, "payee", "name", 256); ok {
		free = append(free, freeText{"payee.name", name})
	}
	v.maxStr(p, "payee", "id", 128)
	if website, ok := v.url(p, "payee", "website"); ok {
		free = append(free, freeText{"payee.website", website})
	}
	v.pattern(p, "payee", "country", reCountry, "an ISO 3166-1 alpha-2 code")
	v.pattern(p, "payee", "mcc", reFour, "4 digits")
	if w, ok := present(p, "wallet"); ok {
		v.wallet("payee.wallet", w)
	}
	if resource, ok := v.url(p, "payee", "resource_url"); ok {
		free = append(free, freeText{"payee.resource_url", resource})
	}
	_, hasName := present(p, "name")
	_, hasWallet := present(p, "wallet")
	_, hasID := present(p, "id")
	if !hasName && !hasWallet && !hasID {
		v.add("payee", "payee needs at least one of name, wallet or id")
	}
	return free
}

func (v *validator) evidence(value any) {
	items, ok := value.([]any)
	if !ok {
		v.add("evidence", "expected an array")
		return
	}
	if len(items) > 16 {
		v.add("evidence", "at most 16 items")
	}
	for i, item := range items {
		path := fmt.Sprintf("evidence.%d", i)
		e := v.object(path, item, []string{"kind", "format", "sha256"}, []string{"value", "uri", "captured_at"})
		if e == nil {
			continue
		}
		v.enum(e, path, "kind", evidenceKinds)
		v.enum(e, path, "format", []string{"sd-jwt", "kb-sd-jwt", "jws", "http-signature", "json"})
		_, hasValue := present(e, "value")
		if hasValue {
			switch e["value"].(type) {
			case string, map[string]any:
			default:
				v.add(path+".value", "must be a string or an object")
			}
		}
		_, hasURI := present(e, "uri")
		v.url(e, path, "uri")
		v.pattern(e, path, "sha256", reSHA256, "sha256: and 64 lowercase hex digits")
		v.dateTime(e, path, "captured_at")
		if hasValue == hasURI {
			v.add(path, "evidence needs exactly one of value or uri")
		}
	}
}

func (v *validator) labels(value any) []freeText {
	labels, ok := value.(map[string]any)
	if !ok {
		v.add("labels", "expected an object")
		return nil
	}
	if len(labels) > 20 {
		v.add("labels", "at most 20 labels")
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	free := []freeText{}
	for _, k := range keys {
		path := "labels." + k
		if jcs.UTF16Len(k) > 64 {
			v.add(path, "label keys must be at most 64 characters")
		}
		free = append(free, freeText{path, k})
		s, isStr := labels[k].(string)
		switch {
		case labels[k] == nil:
			v.add(path, "null is not allowed; leave the field out")
		case !isStr:
			v.add(path, "label values must be strings")
		case jcs.UTF16Len(s) > 256:
			v.add(path, "label values must be at most 256 characters")
		default:
			free = append(free, freeText{path, s})
		}
	}
	return free
}
