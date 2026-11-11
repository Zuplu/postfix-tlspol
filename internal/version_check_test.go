/*
 * MIT License
 * Copyright (c) 2026 Zuplu
 */

package tlspol

import (
	"bytes"
	"context"
	"encoding/base32"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"codeberg.org/miekg/dns"
)

type versionCheckTransport func(*http.Request) (*http.Response, error)

func (f versionCheckTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestInstanceIDPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache.db.instance-id")
	var workers sync.WaitGroup
	ids := make(chan string, 8)
	for range 8 {
		workers.Go(func() {
			id, err := loadInstanceID(path)
			if err != nil {
				t.Error(err)
				return
			}
			ids <- id
		})
	}
	workers.Wait()
	close(ids)
	first := ""
	for id := range ids {
		if !validInstanceID(id) || first != "" && id != first {
			t.Fatal("concurrent starts did not share a valid persistent identity")
		}
		first = id
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("identity permissions: %v, %v", info, err)
	}
	link := path + ".link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadInstanceID(link); err == nil {
		t.Fatal("followed an identity symlink")
	}
}

func TestInstanceIDIsUUIDv7(t *testing.T) {
	now := time.UnixMilli(1794440000123)
	id, err := newInstanceID(now)
	if err != nil || !validInstanceID(id) {
		t.Fatalf("invalid UUIDv7 encoding: %v", err)
	}
	data, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(id))
	if err != nil {
		t.Fatal(err)
	}
	var milliseconds int64
	for _, b := range data[:6] {
		milliseconds = milliseconds<<8 | int64(b)
	}
	if milliseconds != now.UnixMilli() {
		t.Fatal("UUIDv7 timestamp differs")
	}
	if validInstanceID(strings.ToUpper(id)) || validInstanceID(id+"=") {
		t.Fatal("accepted non-canonical encoding")
	}
}

func TestVersionCheckRequestPrivacy(t *testing.T) {
	id, err := newInstanceID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: versionCheckTransport(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.RawQuery != "" || request.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatal("version check did not use a DNS wire-format POST")
		}
		data, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		query := &dns.Msg{Data: data}
		if err := query.Unpack(); err != nil {
			t.Fatal(err)
		}
		question := dnsQuestion(query)
		if query.ID != 0 || !query.RecursionDesired || query.CheckingDisabled || query.Security || question.Name != id+".tlspol.zuplu.net." || question.Qtype != dns.TypeTXT {
			t.Fatal("unexpected version-check DNS question or flags")
		}
		if len(query.Pseudo) != 1 {
			t.Fatal("unexpected extra DNS metadata")
		}
		subnet, ok := query.Pseudo[0].(*dns.SUBNET)
		if !ok || subnet.Family != 1 || subnet.Netmask != 0 || subnet.Scope != 0 {
			t.Fatal("client-subnet forwarding was not disabled")
		}
		reply := dns.NewMsg(question.Name, dns.TypeTXT)
		setDNSReply(reply, query)
		reply.Answer = []dns.RR{dnsTXT(question.Name, 0, "v=tlspol1;", "latest=1.16.0")}
		if err := reply.Pack(); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/dns-message"}}, Body: io.NopCloser(bytes.NewReader(reply.Data))}, nil
	})}
	latest, err := queryLatestVersion(t.Context(), client, versionCheckResolvers[0], id)
	if err != nil || latest != "1.16.0" {
		t.Fatalf("version response = %q, %v", latest, err)
	}
}

func TestVersionCheckRetryBoundAndCancellation(t *testing.T) {
	id, _ := newInstanceID(time.Now())
	attempts := 0
	client := &http.Client{Transport: versionCheckTransport(func(request *http.Request) (*http.Response, error) {
		attempts++
		if !slices.Contains(versionCheckResolvers[:], request.URL.String()) {
			t.Fatal("unexpected DoH provider")
		}
		return &http.Response{StatusCode: 503, Body: http.NoBody}, nil
	})}
	runVersionCheckCycle(t.Context(), client, id, "1.15.0", 0)
	if attempts != 4 {
		t.Fatalf("attempts = %d, want initial attempt plus three retries", attempts)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	runVersionCheckCycle(ctx, client, id, "1.15.0", time.Hour)
	if attempts != 4 {
		t.Fatal("cancelled check sent a request")
	}
}

func TestVersionReplyAndComparison(t *testing.T) {
	for _, value := range []string{"v=tlspol1;latest=1.16.0"} {
		if _, err := parseVersionReply(value); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []string{"1.16.0", "v=tlspol1", "v=tlspol1;latest=1.16.0-rc.1", "v=tlspol1;latest=01.2.3", "v=tlspol1;latest=1.2.3;latest=1.2.4"} {
		if _, err := parseVersionReply(value); err == nil {
			t.Fatalf("accepted malformed version record %q", value)
		}
	}
	for _, item := range []struct {
		current, latest string
		newer           bool
	}{{"1.15.0", "1.16.0", true}, {"1.9.0", "1.10.0", true}, {"1.10.0", "1.9.9", false}, {"v1.16.0-dev", "1.16.0", true}, {"1.16.0-dev+abc", "1.15.0", false}, {"1.16.0+abc", "1.16.0", false}, {"1.16.0", "1.16.0", false}, {"1.17.0", "1.16.0", false}, {"undefined", "1.16.0", false}} {
		if newerStableVersion(item.current, item.latest) != item.newer {
			t.Errorf("unexpected comparison: %s -> %s", item.current, item.latest)
		}
	}
}

func TestVersionCheckOptOut(t *testing.T) {
	initializeTestDefaultConfig(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("server:\n  version-check: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil || cfg.Server.VersionCheck {
		t.Fatalf("YAML opt-out was not applied: %v", err)
	}
	old := config
	t.Cleanup(func() { config = old })
	config = cfg
	config.Server.VersionCheck = true
	t.Setenv("TLSPOL_VERSION_CHECK", "0")
	if err := readEnv(); err != nil || config.Server.VersionCheck {
		t.Fatalf("environment opt-out was not applied: %v", err)
	}
}
