package x402

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"

	"go.halvorai.com/ingest"
)

// maxPendingChallenges bounds the challenges remembered while waiting for their payment.
const maxPendingChallenges = 1000

func report(client *ingest.Client, err error, what string) {
	msg := what + " failed"
	if err != nil && err.Error() != "" {
		msg = err.Error()
	}
	client.Notify(ingest.Error{Code: ingest.CodeInvalidEvent, Message: msg})
}

func urlKey(r *http.Request) string {
	u := *r.URL
	u.Fragment = ""
	return u.String()
}

// Transport is an http.RoundTripper that records x402 payments made through it. It reads the
// headers only; requests and responses pass through unchanged, and no error from HalvorAI ever
// reaches the caller.
//
// The agent context comes from each request's context (see ingest.WithAgentContext).
type Transport struct {
	// Base sends the requests (http.DefaultTransport when nil).
	Base   http.RoundTripper
	client *ingest.Client

	mu        sync.Mutex
	requested map[string]string // URL -> payment.requested event id, oldest first in order
	order     []string
}

// NewTransport returns a Transport that records payments on client. base may be nil.
func NewTransport(client *ingest.Client, base http.RoundTripper) *Transport {
	return &Transport{Base: base, client: client, requested: map[string]string{}}
}

func (t *Transport) base() http.RoundTripper {
	if t.Base != nil {
		return t.Base
	}
	return http.DefaultTransport
}

func (t *Transport) remember(key, eventID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.requested[key]; !ok {
		t.order = append(t.order, key)
	}
	t.requested[key] = eventID
	for len(t.requested) > maxPendingChallenges && len(t.order) > 0 {
		oldest := t.order[0]
		t.order = t.order[1:]
		delete(t.requested, oldest)
	}
}

func (t *Transport) take(key string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	id, ok := t.requested[key]
	if ok {
		delete(t.requested, key)
		for i, k := range t.order {
			if k == key {
				t.order = append(t.order[:i], t.order[i+1:]...)
				break
			}
		}
	}
	return id
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	key := urlKey(req)
	var payload map[string]any
	if sig := req.Header.Get(HeaderPaymentSignature); sig != "" {
		var err error
		if payload, err = DecodeHeader(sig); err != nil {
			report(t.client, err, "PAYMENT-SIGNATURE decode")
		} else if mapped, err := MapPaymentPayload(ctx, payload, AdapterClient, nil, t.take(key)); err != nil {
			report(t.client, err, "PAYMENT-SIGNATURE mapping")
		} else if mapped != nil {
			t.client.Emit(ctx, mapped)
		}
	}

	res, err := t.base().RoundTrip(req)
	if err != nil || res == nil {
		return res, err
	}

	if res.StatusCode == http.StatusPaymentRequired {
		if header := res.Header.Get(HeaderPaymentRequired); header != "" {
			required, err := DecodeHeader(header)
			if err != nil {
				report(t.client, err, "PAYMENT-REQUIRED decode")
			} else if mapped, err := MapPaymentRequired(ctx, required, AdapterClient, nil); err != nil {
				report(t.client, err, "PAYMENT-REQUIRED mapping")
			} else if mapped != nil {
				t.remember(key, t.client.Emit(ctx, mapped))
			}
		}
	}
	if header := res.Header.Get(HeaderPaymentResponse); header != "" {
		settlement, err := DecodeHeader(header)
		if err != nil {
			report(t.client, err, "PAYMENT-RESPONSE decode")
		} else if mapped, err := MapSettlementResponse(ctx, settlement, SettlementContextFrom(payload), AdapterClient); err != nil {
			report(t.client, err, "PAYMENT-RESPONSE mapping")
		} else if mapped != nil {
			t.client.Emit(ctx, mapped)
		}
	}
	return res, nil
}

// ServerOptions configures [Middleware].
type ServerOptions struct {
	// Payee is your identity as the seller: Type defaults to api_provider and, without a name,
	// id or wallet, Name to "x402 resource server".
	Payee ingest.Payee
}

func (o ServerOptions) payee() map[string]any {
	p := o.Payee
	if p.Type == "" {
		p.Type = "api_provider"
	}
	if p.Name == "" && p.ID == "" && p.Wallet == nil {
		p.Name = "x402 resource server"
	}
	out := map[string]any{"type": p.Type}
	set := func(k, v string) {
		if v != "" {
			out[k] = v
		}
	}
	set("name", p.Name)
	set("id", p.ID)
	set("website", p.Website)
	set("country", p.Country)
	set("mcc", p.MCC)
	set("resource_url", p.ResourceURL)
	if p.Wallet != nil {
		out["wallet"] = map[string]any{"network": p.Wallet.Network, "address": p.Wallet.Address}
	}
	return out
}

// Middleware records x402 payments received by a net/http server. Put it inside your x402
// payment middleware so it sees the PAYMENT-REQUIRED and PAYMENT-RESPONSE headers that
// middleware sets. Server-side events are not linked to their challenge, because a 402 and the
// paid retry are separate requests that may come from different clients.
func Middleware(client *ingest.Client, opts ServerOptions) func(http.Handler) http.Handler {
	payee := opts.payee()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			var payload map[string]any
			if sig := r.Header.Get(HeaderPaymentSignature); sig != "" {
				var err error
				if payload, err = DecodeHeader(sig); err != nil {
					report(client, err, "PAYMENT-SIGNATURE decode")
				} else if mapped, err := MapPaymentPayload(ctx, payload, AdapterServer, payee, ""); err != nil {
					report(client, err, "PAYMENT-SIGNATURE mapping")
				} else if mapped != nil {
					client.Emit(ctx, mapped)
				}
			}
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			observeResponse(ctx, client, rec.status, rec.header(), payee, payload)
		})
	}
}

func observeResponse(ctx context.Context, client *ingest.Client, status int, headers http.Header, payee map[string]any, payload map[string]any) {
	if status == http.StatusPaymentRequired {
		if header := headers.Get(HeaderPaymentRequired); header != "" {
			required, err := DecodeHeader(header)
			if err != nil {
				report(client, err, "PAYMENT-REQUIRED decode")
			} else if mapped, err := MapPaymentRequired(ctx, required, AdapterServer, payee); err != nil {
				report(client, err, "PAYMENT-REQUIRED mapping")
			} else if mapped != nil {
				client.Emit(ctx, mapped)
			}
		}
	}
	if header := headers.Get(HeaderPaymentResponse); header != "" {
		settlement, err := DecodeHeader(header)
		if err != nil {
			report(client, err, "PAYMENT-RESPONSE decode")
			return
		}
		sc := SettlementContextFrom(payload)
		sc.Payee = payee
		if mapped, err := MapSettlementResponse(ctx, settlement, sc, AdapterServer); err != nil {
			report(client, err, "PAYMENT-RESPONSE mapping")
		} else if mapped != nil {
			client.Emit(ctx, mapped)
		}
	}
}

// statusRecorder remembers the status and the headers as they were when the response started.
type statusRecorder struct {
	http.ResponseWriter
	status   int
	snapshot http.Header
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.snapshot == nil {
		s.status = code
		s.snapshot = s.ResponseWriter.Header().Clone()
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.snapshot == nil {
		s.snapshot = s.ResponseWriter.Header().Clone()
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) header() http.Header {
	if s.snapshot != nil {
		return s.snapshot
	}
	return s.ResponseWriter.Header()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// Flush passes through to the underlying writer when it supports flushing.
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		if s.snapshot == nil {
			s.snapshot = s.ResponseWriter.Header().Clone()
		}
		f.Flush()
	}
}

// Hijack passes through for WebSocket upgrades.
func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := s.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("x402: the response writer does not support hijacking")
}
