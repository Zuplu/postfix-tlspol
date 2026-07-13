/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"errors"
	"io"
	"testing"
)

func TestCliCommandsReturnWriteErrors(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func() error
	}{
		{name: "query", run: func() error {
			return cliQuery(&partialWriteConn{writeErr: io.ErrClosedPipe}, "example.com")
		}},
		{name: "export", run: func() error {
			return cliDump(&partialWriteConn{writeErr: io.ErrClosedPipe}, true)
		}},
		{name: "purge", run: func() error {
			return cliPurge(&partialWriteConn{writeErr: io.ErrClosedPipe})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.run(); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("command error = %v, want closed pipe", err)
			}
		})
	}
}

func TestRecordCliErrorPreservesFirstFailure(t *testing.T) {
	original := cliErr
	cliErr = nil
	t.Cleanup(func() { cliErr = original })
	first := errors.New("first")
	recordCliError(first)
	recordCliError(errors.New("second"))
	recordCliError(nil)
	if !errors.Is(cliErr, first) {
		t.Fatalf("recorded CLI error = %v, want first failure", cliErr)
	}
}
