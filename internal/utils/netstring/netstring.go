/*
 * MIT License
 * Copyright (c) 2024-2025 Zuplu
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

	lengthStr := data[:colonPos]
	if len(lengthStr) == 0 {
		return 0, nil, errors.New("netstring: empty length")
	}
	if len(lengthStr) > 1 && lengthStr[0] == '0' {
		return 0, nil, errors.New("netstring: leading zero in length")
	}
	for _, c := range lengthStr {
		if c < '0' || c > '9' {
			return 0, nil, errors.New("netstring: invalid length character")
		}
	}

	length, err := strconv.Atoi(string(lengthStr))
	if err != nil {
		return 0, nil, errors.New("netstring: invalid length")
	}
	if length < 0 {
		return 0, nil, errors.New("netstring: negative length")
	}

	commaPos := colonPos + 1 + length
	if commaPos >= len(data) {
		if atEOF {
			return 0, nil, errors.New("netstring: unexpected EOF")
		}
		return 0, nil, nil
	}

	if data[commaPos] != ',' {
		return 0, nil, errors.New("netstring: missing comma terminator")
	}

	return commaPos + 1, data[colonPos+1 : commaPos], nil
}
