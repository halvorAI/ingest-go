package ingest

import (
	"regexp"
	"strings"
)

var (
	reSecretKey  = regexp.MustCompile(`\b(?:sk_live_|sk_test_|rk_live_|whsec_|hk_live_|hk_test_)[0-9A-Za-z]+\b`)
	rePEMPrivate = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reJWKD       = regexp.MustCompile(`"d"\s*:\s*"[^"]*"`)
	reCVC        = regexp.MustCompile(`(?i)\b(cvc|cvv2?|security code)("\s*:\s*"|\s*[:=]\s*|\s+)(\d{3,4})(")?`)
	rePANRun     = regexp.MustCompile(`\d(?:[ -]?\d)*`)
)

// RedactPattern is an extra pattern for [Config.RedactPatterns]. Matches are replaced with
// "[redacted:<Label>]", or "[redacted]" when Label is empty.
type RedactPattern struct {
	Pattern *regexp.Regexp
	Label   string
}

func luhnValid(digits string) bool {
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

func panDigits(run string) (string, bool) {
	digits := strings.NewReplacer(" ", "", "-", "").Replace(run)
	return digits, len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits)
}

// ContainsPAN reports whether text holds a card number: a Luhn-valid run of 13 to 19 digits,
// with single spaces or dashes allowed between digits. This is the APE card-number rule.
func ContainsPAN(text string) bool {
	for _, run := range rePANRun.FindAllString(text, -1) {
		if _, ok := panDigits(run); ok {
			return true
		}
	}
	return false
}

// RedactText removes card numbers, CVCs, API and secret keys and private keys from free text.
func RedactText(text string, extra ...RedactPattern) string {
	out := rePEMPrivate.ReplaceAllString(text, "[redacted:private-key]")
	out = reSecretKey.ReplaceAllString(out, "[redacted:secret-key]")
	out = reJWKD.ReplaceAllString(out, `"d":"[redacted:private-key]"`)
	out = rePANRun.ReplaceAllStringFunc(out, func(run string) string {
		if _, ok := panDigits(run); ok {
			return "[redacted:pan]"
		}
		return run
	})
	out = reCVC.ReplaceAllString(out, "${1}${2}[redacted:cvc]${4}")
	for _, p := range extra {
		if p.Pattern == nil {
			continue
		}
		replacement := "[redacted]"
		if p.Label != "" {
			replacement = "[redacted:" + p.Label + "]"
		}
		out = p.Pattern.ReplaceAllLiteralString(out, replacement)
	}
	return out
}

const maxRedactDepth = 64

// RedactDeep returns a copy of a decoded JSON value with [RedactText] applied to every string,
// and the private part of any JWK replaced.
func RedactDeep(value any, extra ...RedactPattern) any {
	return redactDeep(value, extra, 0)
}

func redactDeep(value any, extra []RedactPattern, depth int) any {
	if depth > maxRedactDepth {
		return nil
	}
	switch v := value.(type) {
	case string:
		return RedactText(v, extra...)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactDeep(item, extra, depth+1)
		}
		return out
	case map[string]any:
		_, kty := v["kty"].(string)
		_, d := v["d"].(string)
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = redactDeep(item, extra, depth+1)
		}
		if kty && d {
			out["d"] = "[redacted:private-key]"
		}
		return out
	default:
		return value
	}
}
