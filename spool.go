package ingest

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"go.halvorai.com/ingest/jcs"
)

// Disk spool for events that could not be delivered yet. The layout and limits are the same as
// the Node.js and Python SDKs: JSON Lines, one signed envelope per line, files named so that
// lexical order is age order. Batches the API will never accept go to dead/ and are never
// replayed.

const (
	spoolPrefix = "halvor-spool-"
	spoolSuffix = ".jsonl"
	deadDir     = "dead"
	// DefaultSpoolMaxBytes is the spool's default size limit.
	DefaultSpoolMaxBytes = 50 * 1024 * 1024
	// DefaultSpoolMaxAge is the spool's default age limit.
	DefaultSpoolMaxAge = 7 * 24 * time.Hour
)

type spool struct {
	dir      string
	maxBytes int64
	maxAge   time.Duration
}

type eviction struct{ files, events int }

func spoolFileName() string {
	var r [4]byte
	_, _ = rand.Read(r[:])
	return fmt.Sprintf("%s%015d-%s%s", spoolPrefix, time.Now().UnixMilli(), hex.EncodeToString(r[:]), spoolSuffix)
}

func serializeEnvelopes(envelopes []Envelope) (string, error) {
	var b strings.Builder
	for _, e := range envelopes {
		line, err := jcs.Canonicalize(map[string]any{"event": e.Event, "sig": e.Sig})
		if err != nil {
			return "", err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func atomicWrite(dir, name, body string) error {
	tmp, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(body); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, name)); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

func listSpool(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if !e.IsDir() && strings.HasPrefix(n, spoolPrefix) && strings.HasSuffix(n, spoolSuffix) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// files returns pending file names, oldest first.
func (s *spool) files() []string { return listSpool(s.dir) }

func (s *spool) write(envelopes []Envelope) (eviction, error) {
	if len(envelopes) == 0 {
		return eviction{}, nil
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return eviction{}, err
	}
	body, err := serializeEnvelopes(envelopes)
	if err != nil {
		return eviction{}, err
	}
	if err := atomicWrite(s.dir, spoolFileName(), body); err != nil {
		return eviction{}, err
	}
	return s.evict(s.dir), nil
}

// read returns a file's envelopes and how many lines could not be read.
func (s *spool) read(name string) ([]Envelope, int) {
	raw, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return nil, 0
	}
	var out []Envelope
	corrupt := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := jcs.Parse([]byte(line))
		obj, _ := v.(map[string]any)
		event, okEvent := obj["event"].(map[string]any)
		sig, okSig := obj["sig"].(string)
		if err != nil || !okEvent || !okSig {
			corrupt++
			continue
		}
		out = append(out, Envelope{Event: event, Sig: sig})
	}
	return out, corrupt
}

// rewrite keeps only envelopes in the file, in its place in the order.
func (s *spool) rewrite(name string, envelopes []Envelope) error {
	if len(envelopes) == 0 {
		s.remove(name)
		return nil
	}
	body, err := serializeEnvelopes(envelopes)
	if err != nil {
		return err
	}
	return atomicWrite(s.dir, name, body)
}

func (s *spool) remove(name string) { _ = os.Remove(filepath.Join(s.dir, name)) }

func (s *spool) deadLetter(envelopes []Envelope) error {
	if len(envelopes) == 0 {
		return nil
	}
	dir := filepath.Join(s.dir, deadDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body, err := serializeEnvelopes(envelopes)
	if err != nil {
		return err
	}
	if err := atomicWrite(dir, spoolFileName(), body); err != nil {
		return err
	}
	s.evict(dir)
	return nil
}

// evict deletes the oldest files until the folder is under the size limit and none is too old.
func (s *spool) evict(dir string) eviction {
	type entry struct {
		name  string
		size  int64
		mtime time.Time
	}
	var entries []entry
	var total int64
	for _, name := range listSpool(dir) {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		entries = append(entries, entry{name, info.Size(), info.ModTime()})
		total += info.Size()
	}
	var result eviction
	now := time.Now()
	for _, e := range entries {
		tooOld := now.Sub(e.mtime) > s.maxAge
		if !tooOld && total <= s.maxBytes {
			continue
		}
		path := filepath.Join(dir, e.name)
		raw, err := os.ReadFile(path)
		if err != nil || os.Remove(path) != nil {
			continue
		}
		result.files++
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.TrimSpace(line) != "" {
				result.events++
			}
		}
		total -= e.size
	}
	return result
}
