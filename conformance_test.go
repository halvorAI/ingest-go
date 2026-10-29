package ingest

import (
	"os"
	"strings"
	"testing"

	"go.halvorai.com/ingest/jcs"
)

func parseFile(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v, err := jcs.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func verdict(event map[string]any) (string, []Problem) {
	problems := ValidateEvent(event)
	if len(problems) == 0 {
		return "valid", nil
	}
	for _, p := range problems {
		if p.Message == PANDetected {
			return "pan", problems
		}
	}
	return "schema", problems
}

// The ape-schema conformance cases: the same verdicts as every other APE implementation.
// testdata/conformance is copied from https://github.com/halvorAI/ape-schema/tree/main/conformance.
func TestConformanceEvents(t *testing.T) {
	data := parseFile(t, "testdata/conformance/events.json")
	cases := data["cases"].([]any)
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	for _, raw := range cases {
		c := raw.(map[string]any)
		name := c["name"].(string)
		t.Run(name, func(t *testing.T) {
			want := "valid"
			if c["expect"] != "valid" {
				want = c["rule"].(string)
			}
			event, _ := c["event"].(map[string]any)
			got, problems := verdict(event)
			if got != want {
				t.Errorf("got %s, want %s: %v", got, want, problems)
			}
		})
	}
}

// The cross-language signing vector shared with the Node.js and Python SDKs.
func TestSignVector(t *testing.T) {
	vector := parseFile(t, "testdata/sign-vector.json")
	event := vector["event"].(map[string]any)
	canonical, err := jcs.Canonicalize(event)
	if err != nil || canonical != vector["canonical_jcs"] {
		t.Fatalf("canonical form differs: %v", err)
	}
	jwk := func(m any) JWK {
		k := m.(map[string]any)
		get := func(s string) string { v, _ := k[s].(string); return v }
		return JWK{Kty: get("kty"), Crv: get("crv"), X: get("x"), D: get("d"), Kid: get("kid")}
	}
	sig, err := SignEvent(event, jwk(vector["private_jwk"]))
	if err != nil || sig != vector["sig"] {
		t.Fatalf("signature differs: %v\n got %s\nwant %s", err, sig, vector["sig"])
	}
	if !VerifyEvent(event, sig, jwk(vector["public_jwk"])) {
		t.Fatal("vector signature does not verify")
	}
	event["id"] = "evt_tampered000000000000000"
	if VerifyEvent(event, sig, jwk(vector["public_jwk"])) {
		t.Fatal("tampered event verified")
	}
	if VerifyEvent(event, strings.Replace(sig, "..", ".x.", 1), jwk(vector["public_jwk"])) {
		t.Fatal("attached payload accepted")
	}
}
