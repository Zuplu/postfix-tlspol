/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package netstring

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
)

type Scanner struct {
	*bufio.Scanner
}

func NewScanner(r io.Reader) *Scanner {
	s := &Scanner{
		Scanner: bufio.NewScanner(r),
	}
	s.Scanner.Split(splitNetstring)
	return s
}

// Read decodes one netstring without reading beyond its terminating comma.
// The payload limit excludes the netstring length prefix and delimiters.
func Read(r *bufio.Reader, maxPayload int) ([]byte, error) {
	length := 0
	digits := 0
	maxInt := int(^uint(0) >> 1)
	for {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && digits != 0 {
				return nil, errors.New("netstring: unexpected EOF")
			}
			return nil, err
		}
		if b == ':' {
			if digits == 0 {
				return nil, errors.New("netstring: empty length")
			}
			break
		}
		if digits == 1 && length == 0 {
			return nil, errors.New("netstring: leading zero in length")
		}
		if b < '0' || b > '9' {
			return nil, errors.New("netstring: invalid length character")
		}
		digit := int(b - '0')
		if length > (maxInt-digit)/10 {
			return nil, errors.New("netstring: invalid length")
		}
		length = length*10 + digit
		digits++
		if length > maxPayload {
			return nil, errors.New("netstring: payload too large")
		}
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("netstring: unexpected EOF")
		}
		return nil, err
	}
	terminator, err := r.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("netstring: unexpected EOF")
		}
		return nil, err
	}
	if terminator != ',' {
		return nil, errors.New("netstring: missing comma terminator")
	}
	return payload, nil
}

func splitNetstring(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) == 0 {
		return 0, nil, nil
	}
	colonPos := bytes.IndexByte(data, ':')
	if colonPos == -1 {
		if atEOF {
			return 0, nil, errors.New("netstring: missing colon")
		}
		return 0, nil, nil
	}
	lengthBytes := data[:colonPos]
	if len(lengthBytes) == 0 {
		return 0, nil, errors.New("netstring: empty length")
	}
	if len(lengthBytes) > 1 && lengthBytes[0] == '0' {
		return 0, nil, errors.New("netstring: leading zero in length")
	}
	length := 0
	maxInt := int(^uint(0) >> 1)
	for _, c := range lengthBytes {
		if c < '0' || c > '9' {
			return 0, nil, errors.New("netstring: invalid length character")
		}
		digit := int(c - '0')
		if length > (maxInt-digit)/10 {
			return 0, nil, errors.New("netstring: invalid length")
		}
		length = length*10 + digit
	}
	payloadStart := colonPos + 1
	if length >= len(data)-payloadStart {
		if atEOF {
			return 0, nil, errors.New("netstring: unexpected EOF")
		}
		return 0, nil, nil
	}
	commaPos := payloadStart + length
	if data[commaPos] != ',' {
		return 0, nil, errors.New("netstring: missing comma terminator")
	}
	return commaPos + 1, data[colonPos+1 : commaPos], nil
}

func Marshal(s string) []byte {
	return []byte(strconv.Itoa(len(s)) + ":" + s + ",")
}
