/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package netstring

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestMarshal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "empty string",
			in:   "",
			want: "0:,",
		},
		{
			name: "ascii",
			in:   "hello",
			want: "5:hello,",
		},
		{
			name: "unicode bytes length",
			in:   "€",
			want: "3:€,",
		},
		{
			name: "contains colon and comma",
			in:   "a:b,c",
			want: "5:a:b,c,",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := Marshal(tt.in)
			if string(got) != tt.want {
				t.Fatalf("Marshal(%q) = %q, want %q", tt.in, string(got), tt.want)
			}
		})
	}
}

func TestNewScannerAndSplit_ValidSingleToken(t *testing.T) {
	t.Parallel()

	input := "5:hello,"
	s := NewScanner(strings.NewReader(input))

	if !s.Scan() {
		t.Fatalf("expected first Scan() to succeed, err=%v", s.Err())
	}
	if got := string(s.Bytes()); got != "hello" {
		t.Fatalf("token = %q, want %q", got, "hello")
	}

	if s.Scan() {
		t.Fatalf("expected no more tokens")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("unexpected scanner err: %v", err)
	}
}

func TestNewScannerAndSplit_ValidMultipleTokens(t *testing.T) {
	t.Parallel()

	input := "5:hello,0:,4:test,3:abc,"
	s := NewScanner(strings.NewReader(input))

	var got []string
	for s.Scan() {
		got = append(got, string(s.Bytes()))
	}

	if err := s.Err(); err != nil {
		t.Fatalf("unexpected scanner err: %v", err)
	}

	want := []string{"hello", "", "test", "abc"}
	if len(got) != len(want) {
		t.Fatalf("token count = %d, want %d; got=%v", len(got), len(want), got)
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("token[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSplitNetstring_ValidCases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		data        string
		atEOF       bool
		wantAdvance int
		wantToken   string
	}{
		{
			name:        "empty payload",
			data:        "0:,",
			atEOF:       true,
			wantAdvance: 3,
			wantToken:   "",
		},
		{
			name:        "simple payload",
			data:        "5:hello,",
			atEOF:       true,
			wantAdvance: 8,
			wantToken:   "hello",
		},
		{
			name:        "payload followed by extra bytes",
			data:        "4:test,TRAIL",
			atEOF:       false,
			wantAdvance: 7,
			wantToken:   "test",
		},
		{
			name:        "payload with punctuation",
			data:        "5:a:b,c,",
			atEOF:       true,
			wantAdvance: 8,
			wantToken:   "a:b,c",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adv, tok, err := splitNetstring([]byte(tt.data), tt.atEOF)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if adv != tt.wantAdvance {
				t.Fatalf("advance = %d, want %d", adv, tt.wantAdvance)
			}
			if string(tok) != tt.wantToken {
				t.Fatalf("token = %q, want %q", string(tok), tt.wantToken)
			}
		})
	}
}

func TestSplitNetstring_IncompleteNeedMoreData_NotEOF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		data  string
		atEOF bool
	}{
		{
			name:  "no data",
			data:  "",
			atEOF: false,
		},
		{
			name:  "missing colon yet",
			data:  "12",
			atEOF: false,
		},
		{
			name:  "missing payload bytes",
			data:  "5:hel",
			atEOF: false,
		},
		{
			name:  "missing comma terminator yet",
			data:  "5:hello",
			atEOF: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adv, tok, err := splitNetstring([]byte(tt.data), tt.atEOF)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if adv != 0 {
				t.Fatalf("advance = %d, want 0", adv)
			}
			if tok != nil {
				t.Fatalf("token = %v, want nil", tok)
			}
		})
	}
}

func TestSplitNetstring_ErrorCasesAtEOF(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name:    "missing colon",
			data:    "123",
			wantErr: "netstring: missing colon",
		},
		{
			name:    "empty length",
			data:    ":abc,",
			wantErr: "netstring: empty length",
		},
		{
			name:    "leading zero",
			data:    "01:a,",
			wantErr: "netstring: leading zero in length",
		},
		{
			name:    "double zero length",
			data:    "00:,",
			wantErr: "netstring: leading zero in length",
		},
		{
			name:    "invalid length character alpha",
			data:    "a:abc,",
			wantErr: "netstring: invalid length character",
		},
		{
			name:    "invalid length character sign",
			data:    "-1:a,",
			wantErr: "netstring: invalid length character",
		},
		{
			name:    "unexpected eof before full payload",
			data:    "5:hell,",
			wantErr: "netstring: unexpected EOF",
		},
		{
			name:    "unexpected eof missing comma",
			data:    "5:hello",
			wantErr: "netstring: unexpected EOF",
		},
		{
			name:    "missing comma terminator",
			data:    "5:hellox",
			wantErr: "netstring: missing comma terminator",
		},
		{
			name:    "trailing garbage where comma expected",
			data:    "0:;",
			wantErr: "netstring: missing comma terminator",
		},
		{
			name:    "very large declared length over available bytes",
			data:    "999999999:x,",
			wantErr: "netstring: unexpected EOF",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			adv, tok, err := splitNetstring([]byte(tt.data), true)
			if err == nil {
				t.Fatalf("expected error, got nil (advance=%d token=%q)", adv, string(tok))
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("err = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestScanner_ErrorPropagation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "invalid leading zero",
			input:   "01:a,",
			wantErr: "netstring: leading zero in length",
		},
		{
			name:    "missing comma",
			input:   "1:ax",
			wantErr: "netstring: missing comma terminator",
		},
		{
			name:    "missing colon at eof",
			input:   "123",
			wantErr: "netstring: missing colon",
		},
		{
			name:    "truncated",
			input:   "4:ab,",
			wantErr: "netstring: unexpected EOF",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := NewScanner(strings.NewReader(tt.input))
			for s.Scan() {
			}
			if err := s.Err(); err == nil {
				t.Fatalf("expected scanner error, got nil")
			} else if err.Error() != tt.wantErr {
				t.Fatalf("scanner err = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestScanner_BufferLimit_DefaultTooSmallForLargeToken(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("a", bufio.MaxScanTokenSize+1)
	input := string(Marshal(large))

	s := NewScanner(strings.NewReader(input))
	if s.Scan() {
		t.Fatalf("expected Scan() to fail due to token too long")
	}
	if err := s.Err(); err == nil {
		t.Fatalf("expected scanner error, got nil")
	}
}

func TestScanner_BufferLimit_WithCustomBufferSucceeds(t *testing.T) {
	t.Parallel()

	large := strings.Repeat("b", bufio.MaxScanTokenSize+1)
	input := string(Marshal(large))

	s := NewScanner(strings.NewReader(input))

	// Increase maximum token size so scanner can hold full netstring token.
	buf := make([]byte, 0, 64*1024)
	s.Buffer(buf, len(input)+16)

	if !s.Scan() {
		t.Fatalf("expected Scan() to succeed, err=%v", s.Err())
	}
	if got := string(s.Bytes()); got != large {
		t.Fatalf("decoded payload length = %d, want %d", len(got), len(large))
	}
	if s.Scan() {
		t.Fatalf("expected exactly one token")
	}
	if err := s.Err(); err != nil {
		t.Fatalf("unexpected scanner err: %v", err)
	}
}

func TestRoundTrip_MarshalThenScan(t *testing.T) {
	t.Parallel()

	payloads := []string{
		"",
		"x",
		"hello",
		"a:b,c",
		"€漢字🙂",
	}

	var stream bytes.Buffer
	for _, p := range payloads {
		stream.Write(Marshal(p))
	}

	s := NewScanner(bytes.NewReader(stream.Bytes()))

	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}
	if err := s.Err(); err != nil {
		t.Fatalf("unexpected scanner err: %v", err)
	}

	if len(got) != len(payloads) {
		t.Fatalf("decoded count = %d, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if got[i] != payloads[i] {
			t.Fatalf("decoded[%d] = %q, want %q", i, got[i], payloads[i])
		}
	}
}

type chunkedReader struct {
	data      []byte
	chunkSize int
	offset    int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := r.chunkSize
	if n > len(r.data)-r.offset {
		n = len(r.data) - r.offset
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}

func TestScanner_StreamedChunkedInput(t *testing.T) {
	t.Parallel()

	payloads := []string{
		"hello",
		"",
		"abc",
		"€",
	}

	var stream bytes.Buffer
	for _, p := range payloads {
		stream.Write(Marshal(p))
	}

	r := &chunkedReader{
		data:      stream.Bytes(),
		chunkSize: 1,
	}
	s := NewScanner(r)

	var got []string
	for s.Scan() {
		got = append(got, s.Text())
	}

	if err := s.Err(); err != nil {
		t.Fatalf("unexpected scanner err: %v", err)
	}

	if len(got) != len(payloads) {
		t.Fatalf("decoded count = %d, want %d", len(got), len(payloads))
	}
	for i := range payloads {
		if got[i] != payloads[i] {
			t.Fatalf("decoded[%d] = %q, want %q", i, got[i], payloads[i])
		}
	}
}
