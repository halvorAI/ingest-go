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
// with single spaces or dashes allowed between digits. This is the APE card-number rule. Digits
// glued to letters or other digits (hex signatures, base64, ids) are not a card number.
func ContainsPAN(text string) bool {
	found := false
	scanPANRuns(text, func(_, _ int, run string) bool {
		if _, ok := panDigits(run); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

func isASCIIAlnum(b byte) bool {
	return isASCIIDigit(b) || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// scanPANRuns calls fn for each candidate card-number run, left to right, as the Node.js and
// Python SDKs find them with /(?<![0-9A-Za-z])\d(?:[ -]?\d)*(?![0-9A-Za-z])/: a run must not
// touch an ASCII letter or digit on either side; when the longest run does, shorter runs ending
// at a digit followed by a space or dash are tried. fn returns false to stop.
func scanPANRuns(text string, fn func(start, end int, run string) bool) {
	for i := 0; i < len(text); {
		if !isASCIIDigit(text[i]) || (i > 0 && isASCIIAlnum(text[i-1])) {
			i++
			continue
		}
		// Possible ends (exclusive) of \d(?:[ -]?\d)* starting at i, shortest first.
		ends := []int{i + 1}
		for j := i + 1; ; {
			if j < len(text) && isASCIIDigit(text[j]) {
				j++
			} else if j+1 < len(text) && (text[j] == ' ' || text[j] == '-') && isASCIIDigit(text[j+1]) {
				j += 2
			} else {
				break
			}
			ends = append(ends, j)
		}
		matched := -1
		for k := len(ends) - 1; k >= 0; k-- {
			if e := ends[k]; e == len(text) || !isASCIIAlnum(text[e]) {
				matched = e
				break
			}
		}
		if matched < 0 {
			i++
			continue
		}
		if !fn(i, matched, text[i:matched]) {
			return
		}
		i = matched
	}
}

func redactPANs(text string) string {
	var b strings.Builder
	last := 0
	scanPANRuns(text, func(start, end int, run string) bool {
		if _, ok := panDigits(run); ok {
			b.WriteString(text[last:start])
			b.WriteString("[redacted:pan]")
			last = end
		}
		return true
	})
	if last == 0 {
		return text
	}
	b.WriteString(text[last:])
	return b.String()
}

// RedactText removes card numbers, CVCs, API and secret keys and private keys from free text.
func RedactText(text string, extra ...RedactPattern) string {
	out := rePEMPrivate.ReplaceAllString(text, "[redacted:private-key]")
	out = reSecretKey.ReplaceAllString(out, "[redacted:secret-key]")
	out = reJWKD.ReplaceAllString(out, `"d":"[redacted:private-key]"`)
	out = redactPANs(out)
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
