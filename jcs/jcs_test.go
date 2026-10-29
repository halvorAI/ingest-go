package jcs

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"testing"
)

func load(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

// The ape-schema vectors (https://github.com/halvorAI/ape-schema/tree/main/conformance).
func TestConformanceVectors(t *testing.T) {
	var vectors struct {
		Numbers []struct{ Bits, Expected string }
		Objects []struct{ JSON, Expected string }
	}
	load(t, "jcs-vectors.json", &vectors)
	for _, v := range vectors.Numbers {
		raw, err := hex.DecodeString(v.Bits)
		if err != nil {
			t.Fatal(err)
		}
		got, err := FormatNumber(math.Float64frombits(binary.BigEndian.Uint64(raw)))
		if err != nil || got != v.Expected {
			t.Errorf("number %s: got %q (%v), want %q", v.Bits, got, err, v.Expected)
		}
	}
	for i, v := range vectors.Objects {
		got, err := Transform([]byte(v.JSON))
		if err != nil || got != v.Expected {
			t.Errorf("object %d: got %q (%v), want %q", i, got, err, v.Expected)
		}
	}
}

// Random values canonicalized by the TypeScript SDK's algorithm (testdata/differential.json).
func TestMatchesTypeScript(t *testing.T) {
	var data struct {
		Cases []struct{ JSON, Expected string }
	}
	load(t, "differential.json", &data)
	for i, c := range data.Cases {
		got, err := Transform([]byte(c.JSON))
		if err != nil || got != c.Expected {
			t.Fatalf("case %d %s: got %q (%v), want %q", i, c.JSON, got, err, c.Expected)
		}
	}
}

func TestGoValues(t *testing.T) {
	type inner struct {
		B int    `json:"b"`
		A string `json:"a,omitempty"`
	}
	got, err := Canonicalize(map[string]any{"z": []any{1, 2.5, int64(-3)}, "a": inner{B: 1}, "€": nil})
	want := `{"a":{"b":1},"z":[1,2.5,-3],"€":null}`
	if err != nil || got != want {
		t.Fatalf("got %q (%v), want %q", got, err, want)
	}
	if _, err := Canonicalize(math.NaN()); err == nil {
		t.Fatal("NaN must be rejected")
	}
}

func TestParseRejectsBadJSON(t *testing.T) {
	for _, bad := range []string{`{`, `[1,]`, `01`, `"\x01"`, `{"a" 1}`, `1 2`, `"\q"`, `tru`} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}
