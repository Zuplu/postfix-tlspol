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
			slog.Error("Invalid domain", "domain", value)
			return
		}
	case "dump", "export", "purge":
		cliConnMode = true
	default:
		return
	}
	conn, dialedEndpoint, err := dialConfiguredOrDetectedSocketmap()
	if err != nil {
		slog.Error("Could not connect to socketmap instance. Is postfix-tlspol running?", "error", err, "attempted_endpoints", dialedEndpoint)
		return
	}
	defer conn.Close()
	slog.Debug("Connected to socketmap instance", "endpoint", dialedEndpoint)
	switch (*f).Name {
	case "query":
		cliQuery(f, &conn, &value)
	case "dump":
		cliDump(f, &conn, false)
	case "export":
		cliDump(f, &conn, true)
	case "purge":
		cliPurge(f, &conn)
	}
}

func cliQuery(f *flag.Flag, conn *net.Conn, value *string) {
	(*conn).Write(netstring.Marshal("JSON " + *value))
	raw, err := bufio.NewReader(*conn).ReadBytes('\n')
	if err != nil {
		slog.Error("Could not query domain", "domain", *value, "error", err)
		return
	}
	result := new(Result)
	err = json.Unmarshal(raw, &result)
	if err != nil {
		slog.Error("Could not query domain %q. (%v)", "domain", *value, "error", err)
		return
	}
	o, err := os.Stdout.Stat()
	if err == nil && o.Mode()&os.ModeCharDevice != 0 {
		var buf io.WriteCloser
		if _, err := exec.LookPath("jq"); err == nil {
			jq := exec.Command("jq")
			buf, _ = jq.StdinPipe()
			jq.Stdout = os.Stdout
			jq.Stderr = os.Stderr
			defer jq.Run()
		} else {
			buf = os.Stdout
		}
		enc := json.NewEncoder(buf)
		enc.SetIndent("", "  ")
		err = enc.Encode(result)
		defer buf.Close()
	} else {
		enc := json.NewEncoder(os.Stdout)
		err = enc.Encode(result)
	}
	if err != nil {
		slog.Error("Could not query domain", "domain", *value, "error", err)
		return
	}
	return
}

func cliDump(f *flag.Flag, conn *net.Conn, export bool) {
	if export {
		(*conn).Write(netstring.Marshal("EXPORT"))
	} else {
		(*conn).Write(netstring.Marshal("DUMP"))
		o, err := os.Stdout.Stat()
		if err == nil && o.Mode()&os.ModeCharDevice != 0 {
			if _, err := exec.LookPath("less"); err == nil {
				less := exec.Command("less")
				less.Env = append(os.Environ(), "LESS=-S --use-color --prompt=postfix-tlspol\\ in-memory\\ cache")
				less.Stdin = *conn
				less.Stdout = os.Stdout
				less.Stderr = os.Stderr
				less.Run()
				return
			}
		}
	}
	io.Copy(os.Stdout, *conn)
}

func cliPurge(f *flag.Flag, conn *net.Conn) {
	(*conn).Write(netstring.Marshal("PURGE"))
	io.Copy(os.Stdout, *conn)
}
