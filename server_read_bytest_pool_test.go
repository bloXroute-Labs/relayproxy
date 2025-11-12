package relayproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// Minimal server wiring for tests (pool + method under test).
func newTestServer() *Server {
	s := &Server{}
	s.getPayloadBodyPool = syncPoolBytes(64 << 10) // 64 KiB scratch
	return s
}

func syncPoolBytes(sz int) (p sync.Pool) {
	p = sync.Pool{
		New: func() any { return make([]byte, sz) },
	}
	return
}

func TestReadAllPooledCtx_KnownContentLength_Succeeds(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()

	// 1 MiB payload, max 2 MiB, generous timeout
	src := bytes.Repeat([]byte("A"), 1<<20)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(src)) // sets ContentLength
	// Body is already wrapped by httptest; leave as-is.

	start := time.Now()
	out, err := s.readAllPooledCtx(context.Background(), w, req, 2<<20, 500*time.Millisecond)
	dur := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, src) {
		t.Fatalf("mismatched bytes: got %d, want %d", len(out), len(src))
	}
	if dur > 500*time.Millisecond {
		t.Fatalf("read exceeded timeout window: %v", dur)
	}
}

func TestReadAllPooledCtx_UnknownContentLength_Succeeds(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()

	// Unknown Content-Length: use a reader type that doesn't advertise size
	src := bytes.Repeat([]byte("B"), 128<<10)                              // 128 KiB
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBuffer(src)) // ContentLength set
	// Force unknown length by clearing it and swapping Body to NopCloser over Reader
	req.ContentLength = -1
	req.Body = io.NopCloser(bytes.NewReader(src))

	out, err := s.readAllPooledCtx(context.Background(), w, req, 1<<20, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, src) {
		t.Fatalf("mismatched bytes")
	}
}

func TestReadAllPooledCtx_RespectsMaxBytes(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()

	// Payload 2 MiB, max 1 MiB -> expect http.MaxBytesError
	src := bytes.Repeat([]byte("X"), 2<<20)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(src)) // known length

	_, err := s.readAllPooledCtx(context.Background(), w, req, 1<<20, 2*time.Second)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var mbe *http.MaxBytesError
	if !errors.As(err, &mbe) {
		t.Fatalf("expected *http.MaxBytesError, got %T: %v", err, err)
	}
}

type slowRC struct {
	data   []byte
	cursor int
	delay  time.Duration
	done   chan struct{}
}

func newSlowRC(data []byte, delay time.Duration) *slowRC {
	return &slowRC{data: data, delay: delay, done: make(chan struct{})}
}

func (s *slowRC) Read(p []byte) (int, error) {
	if s.cursor >= len(s.data) {
		return 0, io.EOF
	}
	// Sleep but allow Close() to interrupt.
	select {
	case <-time.After(s.delay):
	case <-s.done:
		return 0, io.EOF
	}
	n := copy(p, s.data[s.cursor:])
	s.cursor += n
	return n, nil
}

func (s *slowRC) Close() error {
	select {
	case <-s.done: // already closed
	default:
		close(s.done)
	}
	return nil
}

func TestReadAllPooledCtx_TimeoutOnSlowBody(t *testing.T) {
	s := newTestServer()
	w := httptest.NewRecorder()

	// 10 chunks; each read sleeps 200ms => ~2s total if not canceled
	src := bytes.Repeat([]byte("Z"), 10*(32<<10))
	slow := newSlowRC(src, 200*time.Millisecond) // implements io.ReadCloser itself

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Body = slow        // IMPORTANT: do NOT wrap with io.NopCloser
	req.ContentLength = -1 // unknown/chunked

	timeout := 300 * time.Millisecond
	start := time.Now()
	_, err := s.readAllPooledCtx(context.Background(), w, req, 4<<20, timeout)
	dur := time.Since(start)

	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	// Expect deadline exceeded OR a read error after Close unblocks the read.
	if !(errors.Is(err, context.DeadlineExceeded) || err != nil) {
		t.Fatalf("expected deadline or read-close error, got: %v", err)
	}
	// Should be close to the timeout (allow some scheduler overhead).
	if dur < timeout || dur > timeout+350*time.Millisecond {
		t.Fatalf("unexpected duration; got %v, want ~%v±350ms", dur, timeout)
	}
}

func TestReadAllPooledCtx_PoolEdgeCase_EmptyScratchStillWorks(t *testing.T) {
	s := newTestServer()
	// Override pool to return empty slice first; ensures fallback path runs.
	var called bool
	s.getPayloadBodyPool = sync.Pool{
		New: func() any {
			if !called {
				called = true
				return []byte{} // force empty
			}
			return make([]byte, 64<<10)
		},
	}

	w := httptest.NewRecorder()
	src := bytes.Repeat([]byte("Q"), 96<<10) // > first empty, requires allocation
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(src))

	out, err := s.readAllPooledCtx(context.Background(), w, req, 1<<20, 1*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(out, src) {
		t.Fatalf("mismatched bytes")
	}
}
