package jcs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Parse decodes JSON text the way JavaScript's JSON.parse does, so that canonicalizing the
// result gives the same bytes as the Node.js SDK.
//
// It differs from encoding/json in two ways: numbers come back as json.Number, and a \u escape
// for a lone UTF-16 surrogate is kept (encoded as WTF-8) instead of being replaced with U+FFFD.
// As in JSON.parse, a repeated object key keeps its last value.
func Parse(data []byte) (any, error) {
	p := &parser{s: data}
	p.skipSpace()
	v, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i != len(p.s) {
		return nil, p.errorf("unexpected data after the value")
	}
	return v, nil
}

type parser struct {
	s []byte
	i int
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("jcs: invalid JSON at offset %d: %s", p.i, fmt.Sprintf(format, args...))
}

func (p *parser) skipSpace() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, p.errorf("nested too deeply")
	}
	if p.i >= len(p.s) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		return p.str()
	case c == 't':
		return true, p.literal("true")
	case c == 'f':
		return false, p.literal("false")
	case c == 'n':
		return nil, p.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errorf("unexpected character %q", c)
	}
}

func (p *parser) literal(word string) error {
	if !strings.HasPrefix(string(p.s[p.i:min(len(p.s), p.i+len(word))]), word) {
		return p.errorf("expected %s", word)
	}
	p.i += len(word)
	return nil
}

func (p *parser) object(depth int) (any, error) {
	p.i++ // {
	out := map[string]any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return out, nil
	}
	for {
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errorf("expected a string key")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errorf("expected ':'")
		}
		p.i++
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out[key] = v
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.errorf("unexpected end of input")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == '}' {
			p.i++
			return out, nil
		}
		return nil, p.errorf("expected ',' or '}'")
	}
}

func (p *parser) array(depth int) (any, error) {
	p.i++ // [
	out := []any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return out, nil
	}
	for {
		p.skipSpace()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.errorf("unexpected end of input")
		}
		if p.s[p.i] == ',' {
			p.i++
			continue
		}
		if p.s[p.i] == ']' {
			p.i++
			return out, nil
		}
		return nil, p.errorf("expected ',' or ']'")
	}
}

func (p *parser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return nil, p.errorf("invalid number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return nil, p.errorf("invalid number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return nil, p.errorf("invalid number")
		}
	}
	return json.Number(p.s[start:p.i]), nil
}

func (p *parser) hex4() (uint16, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errorf("short \\u escape")
	}
	v, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, p.errorf("invalid \\u escape")
	}
	p.i += 4
	return uint16(v), nil
}

// appendWTF8 writes a lone surrogate the way Go would if surrogates were allowed in UTF-8.
func appendWTF8(b *strings.Builder, u uint16) {
	b.WriteByte(0xED)
	b.WriteByte(0x80 | byte(u>>6&0x3F))
	b.WriteByte(0x80 | byte(u&0x3F))
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.errorf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.errorf("control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", p.errorf("unterminated escape")
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				b.WriteByte(e)
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				u, err := p.hex4()
				if err != nil {
					return "", err
				}
				switch {
				case u >= 0xD800 && u <= 0xDBFF:
					// A high surrogate: combine it with a following \u low surrogate if there is one.
					if p.i+6 <= len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
						save := p.i
						p.i += 2
						lo, err := p.hex4()
						if err == nil && lo >= 0xDC00 && lo <= 0xDFFF {
							b.WriteRune(utf16.DecodeRune(rune(u), rune(lo)))
							continue
						}
						p.i = save
					}
					appendWTF8(&b, u)
				case u >= 0xDC00 && u <= 0xDFFF:
					appendWTF8(&b, u)
				default:
					b.WriteRune(rune(u))
				}
			default:
				return "", p.errorf("invalid escape \\%c", e)
			}
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			if r == utf8.RuneError && size == 1 {
				return "", p.errorf("invalid UTF-8")
			}
			b.Write(p.s[p.i : p.i+size])
			p.i += size
		}
	}
}
