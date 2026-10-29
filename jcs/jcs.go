// Package jcs implements the JSON Canonicalization Scheme (RFC 8785) with the same output as
// the HalvorAI Node.js and Python SDKs, byte for byte.
//
// Numbers are written the way ECMAScript writes them, object members are sorted by their UTF-16
// code units, and strings are escaped like JSON.stringify: a lone UTF-16 surrogate (which a Go
// string can only hold in its WTF-8 form, as produced by [Parse]) is written as a lowercase
// \udXXX escape instead of being rejected.
package jcs

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize returns the JCS form of v.
//
// v may be a decoded JSON value (nil, bool, string, float64, json.Number, []any,
// map[string]any), any Go integer or float, or any other value encoding/json can marshal
// (structs are marshalled first, so their json tags apply).
func Canonicalize(v any) (string, error) {
	var b strings.Builder
	if err := write(&b, v, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// Transform canonicalizes JSON text. Lone surrogates and number spellings in the input are
// kept exactly as a JavaScript engine would read them.
func Transform(data []byte) (string, error) {
	v, err := Parse(data)
	if err != nil {
		return "", err
	}
	return Canonicalize(v)
}

const maxDepth = 1000

func write(b *strings.Builder, v any, depth int) error {
	if depth > maxDepth {
		return errors.New("jcs: value is nested too deeply")
	}
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeString(b, x)
	case json.Number:
		f, err := strconv.ParseFloat(string(x), 64)
		if err != nil && !isRangeErr(err) {
			return fmt.Errorf("jcs: invalid number %q", string(x))
		}
		return writeNumber(b, f)
	case float64:
		return writeNumber(b, x)
	case float32:
		return writeNumber(b, float64(x))
	case int:
		return writeNumber(b, float64(x))
	case int8:
		return writeNumber(b, float64(x))
	case int16:
		return writeNumber(b, float64(x))
	case int32:
		return writeNumber(b, float64(x))
	case int64:
		return writeNumber(b, float64(x))
	case uint:
		return writeNumber(b, float64(x))
	case uint8:
		return writeNumber(b, float64(x))
	case uint16:
		return writeNumber(b, float64(x))
	case uint32:
		return writeNumber(b, float64(x))
	case uint64:
		return writeNumber(b, float64(x))
	case []any:
		b.WriteByte('[')
		for i, item := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, item, depth+1); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortUTF16(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, x[k], depth+1); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		rv := reflect.ValueOf(v)
		if (rv.Kind() == reflect.Pointer || rv.Kind() == reflect.Map || rv.Kind() == reflect.Slice) && rv.IsNil() {
			b.WriteString("null")
			return nil
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("jcs: %w", err)
		}
		parsed, err := Parse(raw)
		if err != nil {
			return err
		}
		return write(b, parsed, depth+1)
	}
	return nil
}

func isRangeErr(err error) bool {
	var ne *strconv.NumError
	return errors.As(err, &ne) && errors.Is(ne.Err, strconv.ErrRange)
}

// FormatNumber writes a float64 the way ECMAScript Number::toString does.
func FormatNumber(f float64) (string, error) {
	var b strings.Builder
	if err := writeNumber(&b, f); err != nil {
		return "", err
	}
	return b.String(), nil
}

func writeNumber(b *strings.Builder, f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.New("jcs: numbers must be finite")
	}
	if f == 0 {
		b.WriteByte('0') // also -0
		return nil
	}
	if f < 0 {
		b.WriteByte('-')
		f = -f
	}
	// Shortest round-trip digits, as "d.ddde±x".
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mant, expPart, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	exp, _ := strconv.Atoi(expPart)
	k := len(digits)
	n := exp + 1 // position of the decimal point relative to the digits
	switch {
	case k <= n && n <= 21:
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", n-k))
	case 0 < n && n <= 21:
		b.WriteString(digits[:n])
		b.WriteByte('.')
		b.WriteString(digits[n:])
	case -6 < n && n <= 0:
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -n))
		b.WriteString(digits)
	default:
		b.WriteByte(digits[0])
		if k > 1 {
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		if n-1 >= 0 {
			b.WriteByte('+')
		}
		b.WriteString(strconv.Itoa(n - 1))
	}
	return nil
}

const hexDigits = "0123456789abcdef"

// Quote returns s as a JSON string literal, escaped exactly like JavaScript's JSON.stringify.
func Quote(s string) string {
	var b strings.Builder
	writeString(&b, s)
	return b.String()
}

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if c < 0x20 {
					b.WriteString(`\u00`)
					b.WriteByte(hexDigits[c>>4])
					b.WriteByte(hexDigits[c&0xF])
				} else {
					b.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			if hi, ok := surrogateAt(s, i); ok {
				// A WTF-8 surrogate pair is one character to JavaScript.
				if hi >= 0xD800 && hi <= 0xDBFF {
					if lo, ok := surrogateAt(s, i+3); ok && lo >= 0xDC00 {
						b.WriteRune(utf16.DecodeRune(rune(hi), rune(lo)))
						i += 6
						continue
					}
				}
				b.WriteString(`\u`)
				b.WriteByte(hexDigits[hi>>12&0xF])
				b.WriteByte(hexDigits[hi>>8&0xF])
				b.WriteByte(hexDigits[hi>>4&0xF])
				b.WriteByte(hexDigits[hi&0xF])
				i += 3
				continue
			}
			b.WriteRune(utf8.RuneError) // invalid UTF-8, as encoding/json does
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	b.WriteByte('"')
}

// surrogateAt reports the UTF-16 surrogate encoded in WTF-8 at s[i:i+3], if there is one.
func surrogateAt(s string, i int) (uint16, bool) {
	if i+3 > len(s) || s[i] != 0xED || s[i+1] < 0xA0 || s[i+1] > 0xBF || s[i+2] < 0x80 || s[i+2] > 0xBF {
		return 0, false
	}
	return 0xD000 | uint16(s[i+1]&0x3F)<<6 | uint16(s[i+2]&0x3F), true
}

// utf16Units returns the UTF-16 code units JavaScript would see for s.
func utf16Units(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		if u, ok := surrogateAt(s, i); ok {
			units = append(units, u)
			i += 3
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r >= 0x10000 {
			hi, lo := utf16.EncodeRune(r)
			units = append(units, uint16(hi), uint16(lo))
		} else {
			units = append(units, uint16(r))
		}
		i += size
	}
	return units
}

// UTF16Len is the length JavaScript reports for s (`s.length`), used for APE max-length checks.
func UTF16Len(s string) int { return len(utf16Units(s)) }

func sortUTF16(keys []string) {
	units := make(map[string][]uint16, len(keys))
	for _, k := range keys {
		units[k] = utf16Units(k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := units[keys[i]], units[keys[j]]
		for n := 0; n < len(a) && n < len(b); n++ {
			if a[n] != b[n] {
				return a[n] < b[n]
			}
		}
		return len(a) < len(b)
	})
}
