package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCopyRunnerOutputDrainsSourceAfterResponseLimit(t *testing.T) {
	const limit = int64(64)
	source := &countingReader{Reader: strings.NewReader(strings.Repeat("x", 256))}
	var output bytes.Buffer
	err := copyRunnerOutput(&output, source, limit)
	if !errors.Is(err, errRunnerOutputTruncated) {
		t.Fatalf("copy error=%v", err)
	}
	if output.Len() != int(limit) {
		t.Fatalf("forwarded bytes=%d want=%d", output.Len(), limit)
	}
	if source.read != 256 {
		t.Fatalf("source was not fully drained: read=%d", source.read)
	}
}

type countingReader struct {
	io.Reader
	read int
}

func (r *countingReader) Read(buffer []byte) (int, error) {
	count, err := r.Reader.Read(buffer)
	r.read += count
	return count, err
}

func TestRunnerAuthorizedUsesExactToken(t *testing.T) {
	if !runnerAuthorized("secret", " secret ") {
		t.Fatal("trimmed matching token was rejected")
	}
	if runnerAuthorized("secret", "different") || runnerAuthorized("secret", "") {
		t.Fatal("invalid runner token was accepted")
	}
}
