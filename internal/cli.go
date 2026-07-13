/*
 * MIT License
 * Copyright (c) 2024-2026 Zuplu
 */

package tlspol

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/Zuplu/postfix-tlspol/internal/utils/netstring"
	"github.com/Zuplu/postfix-tlspol/internal/utils/valid"
)

type dialTarget struct {
	network string
	address string
}

var cliErr error

func recordCliError(err error) {
	if cliErr == nil && err != nil {
		cliErr = err
	}
}

func appendDialTarget(targets []dialTarget, seen map[string]struct{}, network string, address string) []dialTarget {
	address = strings.TrimSpace(address)
	if address == "" {
		return targets
	}
	key := network + "|" + address
	if _, exists := seen[key]; exists {
		return targets
	}
	seen[key] = struct{}{}
	return append(targets, dialTarget{
		network: network,
		address: address,
	})
}

func dialConfiguredOrDetectedSocketmap() (net.Conn, string, error) {
	seen := make(map[string]struct{})
	targets := make([]dialTarget, 0, 4)

	if strings.HasPrefix(config.Server.Address, "unix:") {
		targets = appendDialTarget(targets, seen, "unix", config.Server.Address[5:])
	} else {
		targets = appendDialTarget(targets, seen, "tcp", config.Server.Address)
	}

	// Probe known defaults so CLI works with systemd socket activation
	// even when server.address does not match the active listener(s).
	targets = appendDialTarget(targets, seen, "unix", "/run/postfix-tlspol/tlspol.sock")
	targets = appendDialTarget(targets, seen, "tcp", "127.0.0.1:8642")
	targets = appendDialTarget(targets, seen, "tcp", "localhost:8642")

	var (
		lastErr  error
		attempts []string
	)
	for _, t := range targets {
		attempts = append(attempts, t.network+":"+t.address)
		conn, err := net.DialTimeout(t.network, t.address, 750*time.Millisecond)
		if err == nil {
			return conn, t.network + ":" + t.address, nil
		}
		lastErr = err
	}

	return nil, strings.Join(attempts, ", "), fmt.Errorf("all connection attempts failed (last error: %w)", lastErr)
}

func flagCliConnFunc(f *flag.Flag) {
	var value string
	switch (*f).Name {
	case "query":
		cliConnMode = true
		value = (*f).Value.String()
		if len(value) == 0 || !valid.IsDNSName(value) {
			recordCliError(fmt.Errorf("invalid domain %q", value))
			return
		}
	case "dump", "export", "purge":
		cliConnMode = true
	default:
		return
	}
	conn, dialedEndpoint, err := dialConfiguredOrDetectedSocketmap()
	if err != nil {
		recordCliError(fmt.Errorf("connect to socketmap instance using %s: %w", dialedEndpoint, err))
		return
	}
	defer conn.Close()
	slog.Debug("Connected to socketmap instance", "endpoint", dialedEndpoint)
	switch (*f).Name {
	case "query":
		recordCliError(cliQuery(conn, value))
	case "dump":
		recordCliError(cliDump(conn, false))
	case "export":
		recordCliError(cliDump(conn, true))
	case "purge":
		recordCliError(cliPurge(conn))
	}
}

func cliQuery(conn net.Conn, value string) error {
	if err := writeConnection(conn, netstring.Marshal("JSON "+value)); err != nil {
		return fmt.Errorf("query domain %q: %w", value, err)
	}
	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("read query response for %q: %w", value, err)
	}
	var result Result
	if err := json.Unmarshal(raw, &result); err != nil {
		return fmt.Errorf("decode query response for %q: %w", value, err)
	}
	o, err := os.Stdout.Stat()
	if err == nil && o.Mode()&os.ModeCharDevice != 0 {
		var buf io.WriteCloser
		var jq *exec.Cmd
		if _, lookErr := exec.LookPath("jq"); lookErr == nil {
			jq = exec.Command("jq")
			buf, err = jq.StdinPipe()
			if err == nil {
				jq.Stdout = os.Stdout
				jq.Stderr = os.Stderr
				err = jq.Start()
			}
		}
		if err != nil && buf != nil {
			_ = buf.Close()
		}
		if err != nil || buf == nil {
			jq = nil
			buf = nopWriteCloser{Writer: os.Stdout}
		}
		enc := json.NewEncoder(buf)
		enc.SetIndent("", "  ")
		err = enc.Encode(result)
		closeErr := buf.Close()
		if err == nil {
			err = closeErr
		}
		if jq != nil {
			waitErr := jq.Wait()
			if err == nil {
				err = waitErr
			}
		}
	} else {
		enc := json.NewEncoder(os.Stdout)
		err = enc.Encode(result)
	}
	if err != nil {
		return fmt.Errorf("write query result for %q: %w", value, err)
	}
	return nil
}

type nopWriteCloser struct {
	io.Writer
}

func (w nopWriteCloser) Close() error { return nil }

func cliDump(conn net.Conn, export bool) error {
	command := "DUMP"
	if export {
		command = "EXPORT"
	} else {
	}
	if err := writeConnection(conn, netstring.Marshal(command)); err != nil {
		return fmt.Errorf("request cached policies with %s: %w", command, err)
	}
	if !export {
		o, err := os.Stdout.Stat()
		if err == nil && o.Mode()&os.ModeCharDevice != 0 {
			if _, err := exec.LookPath("less"); err == nil {
				less := exec.Command("less")
				less.Env = append(os.Environ(), "LESS=-S --use-color --prompt=postfix-tlspol\\ in-memory\\ cache")
				less.Stdin = conn
				less.Stdout = os.Stdout
				less.Stderr = os.Stderr
				if err := less.Run(); err != nil {
					return fmt.Errorf("display cached policies: %w", err)
				}
				return nil
			}
		}
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return fmt.Errorf("read cached policies: %w", err)
	}
	return nil
}

func cliPurge(conn net.Conn) error {
	if err := writeConnection(conn, netstring.Marshal("PURGE")); err != nil {
		return fmt.Errorf("request cache purge: %w", err)
	}
	if _, err := io.Copy(os.Stdout, conn); err != nil {
		return fmt.Errorf("read cache purge result: %w", err)
	}
	return nil
}
