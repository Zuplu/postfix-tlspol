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
