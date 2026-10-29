package ingest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"go.halvorai.com/ingest/jcs"
)

// APEVersion is the Agent Payment Event schema version this SDK writes.
const APEVersion = "0.1"

const headerTyp = "ape+jws"

// JWK is an Ed25519 key in JSON Web Key form (RFC 8037). A source key has all fields; its
// public half (the one you register with HalvorAI) has no D.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// Public returns the key without its private part.
func (k JWK) Public() JWK {
	k.D = ""
	return k
}

// ParseJWK reads a JWK from JSON, such as the HALVOR_SOURCE_KEY environment variable.
func ParseJWK(data string) (JWK, error) {
	var k JWK
	if err := json.Unmarshal([]byte(data), &k); err != nil {
		return JWK{}, err
	}
	return k, nil
}

var b64 = base64.RawURLEncoding

func (k JWK) privateKey() (ed25519.PrivateKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, errors.New("source key must be an Ed25519 JWK (kty OKP, crv Ed25519)")
	}
	seed, err := b64.DecodeString(k.D)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("source key has no valid private part (d)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func (k JWK) publicKey() (ed25519.PublicKey, error) {
	if k.Kty != "OKP" || k.Crv != "Ed25519" {
		return nil, errors.New("key must be an Ed25519 JWK (kty OKP, crv Ed25519)")
	}
	x, err := b64.DecodeString(k.X)
	if err != nil || len(x) != ed25519.PublicKeySize {
		return nil, errors.New("key has no valid public part (x)")
	}
	return ed25519.PublicKey(x), nil
}

// GenerateSourceKey makes a new Ed25519 source key. kid is the source id; use the src_ id
// HalvorAI returned when you registered the public key, or "src_local" for offline use.
func GenerateSourceKey(kid string) (JWK, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return JWK{}, err
	}
	return JWK{Kty: "OKP", Crv: "Ed25519", X: b64.EncodeToString(pub), D: b64.EncodeToString(priv.Seed()), Kid: kid}, nil
}

func sourceID(event map[string]any) (string, error) {
	source, _ := event["source"].(map[string]any)
	id, _ := source["id"].(string)
	if id == "" {
		return "", errors.New("event.source.id is required to sign an event")
	}
	return id, nil
}

// protectedHeader is the JWS header, byte-identical to the Node.js SDK's.
func protectedHeader(kid string) string {
	return b64.EncodeToString([]byte(`{"alg":"EdDSA","kid":` + jcs.Quote(kid) + `,"typ":"ape+jws","ape":"0.1"}`))
}

// SignEvent signs the canonical (JCS) form of an event and returns a compact JWS with a
// detached payload: "<header>..<signature>". The header kid is event.source.id.
func SignEvent(event map[string]any, key JWK) (string, error) {
	priv, err := key.privateKey()
	if err != nil {
		return "", err
	}
	kid, err := sourceID(event)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Canonicalize(event)
	if err != nil {
		return "", err
	}
	header := protectedHeader(kid)
	input := header + "." + b64.EncodeToString([]byte(canonical))
	return header + ".." + b64.EncodeToString(ed25519.Sign(priv, []byte(input))), nil
}

// VerifyEvent reports whether sig is a valid detached APE JWS over exactly this event, made
// with the private half of key. It never panics.
func VerifyEvent(event map[string]any, sig string, key JWK) bool {
	pub, err := key.publicKey()
	if err != nil {
		return false
	}
	parts := strings.Split(sig, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] != "" || parts[2] == "" {
		return false
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return false
	}
	kid, err := sourceID(event)
	if err != nil || header["alg"] != "EdDSA" || header["typ"] != headerTyp || header["ape"] != APEVersion || header["kid"] != kid {
		return false
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return false
	}
	canonical, err := jcs.Canonicalize(event)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(parts[0]+"."+b64.EncodeToString([]byte(canonical))), signature)
}
