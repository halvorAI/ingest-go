package ingest

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"

	"go.halvorai.com/ingest/jcs"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewEventID returns a new event id: "evt_" and a 26-character ULID (time-ordered).
func NewEventID() string {
	var b [26]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 9; i >= 0; i-- {
		b[i] = crockford[ms&31]
		ms >>= 5
	}
	var r [10]byte
	_, _ = rand.Read(r[:])
	hi := binary.BigEndian.Uint16(r[:2])
	lo := binary.BigEndian.Uint64(r[2:])
	// 80 random bits as 16 characters.
	for i := 25; i >= 10; i-- {
		b[i] = crockford[lo&31]
		lo = lo>>5 | uint64(hi&31)<<59
		hi >>= 5
	}
	return "evt_" + string(b[:])
}

// NowUTC is the current time in the only format APE uses: RFC 3339, UTC, milliseconds.
func NowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
}

// HashInstruction returns the APE instruction digest: "sha256:" and the hex SHA-256 of the
// UTF-8 text. The text itself never leaves your process.
func HashInstruction(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// EvidenceSHA256 is the digest stored in evidence[].sha256: UTF-8 bytes for a string, the
// canonical (JCS) form for anything else.
func EvidenceSHA256(value any) (string, error) {
	text, ok := value.(string)
	if !ok {
		var err error
		if text, err = jcs.Canonicalize(value); err != nil {
			return "", err
		}
	}
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
