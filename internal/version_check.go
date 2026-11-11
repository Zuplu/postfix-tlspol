/*
 * MIT License
 * Copyright (c) 2026 Zuplu
 */

package tlspol

import (
	"bytes"
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"uuid"

	"codeberg.org/miekg/dns"
	"golang.org/x/sys/unix"
)

const (
	versionCheckDomain   = "tlspol.zuplu.net."
	versionCheckInterval = 24 * time.Hour
	versionCheckRetry    = 30 * time.Minute
	versionCheckRetries  = 3
)

var versionCheckResolvers = [...]string{
	"https://cloudflare-dns.com/dns-query",
	"https://dns.google/dns-query",
	"https://dns.quad9.net/dns-query",
}

// Encode UUIDv7 as a lowercase, unpadded DNS label.
func newInstanceID() string {
	id := uuid.NewV7()
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(id[:]))
}

func validInstanceID(value string) bool {
	if len(value) != 26 || value != strings.ToLower(value) {
		return false
	}
	encoding := base32.StdEncoding.WithPadding(base32.NoPadding)
	data, err := encoding.DecodeString(strings.ToUpper(value))
	return err == nil && len(data) == 16 && data[6]>>4 == 7 && data[8]&0xc0 == 0x80 && strings.ToLower(encoding.EncodeToString(data)) == value
}

func readInstanceID(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 64 {
		return "", fmt.Errorf("instance ID must be a small regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, 65))
	if err != nil {
		return "", err
	}
	id := strings.TrimSpace(string(data))
	if !validInstanceID(id) {
		return "", fmt.Errorf("instance ID file is not a canonical Base32 UUIDv7")
	}
	return id, nil
}

func loadInstanceID(path string) (string, error) {
	if id, err := readInstanceID(path); !errors.Is(err, os.ErrNotExist) {
		return id, err
	}
	id := newInstanceID()
	file, err := os.CreateTemp(filepath.Dir(path), ".postfix-tlspol-instance-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := io.WriteString(file, id+"\n"); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	// Atomic, no-replace publication: concurrent starts reuse the winning ID.
	if err := os.Link(file.Name(), path); err != nil {
		if errors.Is(err, os.ErrExist) {
			return readInstanceID(path)
		}
		return "", err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return "", err
	}
	return id, nil
}

func newVersionCheckClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 8 * time.Second,
			IdleConnTimeout:       30 * time.Second,
			MaxIdleConns:          3,
			MaxIdleConnsPerHost:   1,
		},
	}
}

func queryLatestVersion(ctx context.Context, client *http.Client, endpoint, id string) (string, error) {
	// The persistent label is validated once when loaded and reused unchanged.
	name := id + "." + versionCheckDomain
	query := dns.NewMsg(name, dns.TypeTXT)
	query.ID = 0 // RFC 8484: no DNS transaction identifier is needed over HTTPS.
	query.UDPSize = 1232
	// RFC 7871 /0 explicitly requests that no client subnet be forwarded.
	query.Pseudo = []dns.RR{&dns.SUBNET{Family: 1, Netmask: 0, Scope: 0}}
	if err := query.Pack(); err != nil {
		return "", fmt.Errorf("encode version query: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(query.Data))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/dns-message")
	request.Header.Set("Accept", "application/dns-message")
	request.Header.Set("User-Agent", "postfix-tlspol-version-check")
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("DoH returned HTTP %d", response.StatusCode)
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		return "", fmt.Errorf("DoH returned an unexpected content type")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 65536))
	if err != nil || len(data) > 65535 {
		return "", fmt.Errorf("could not read a bounded DNS response")
	}
	reply := &dns.Msg{Data: data}
	if err := reply.Unpack(); err != nil {
		return "", fmt.Errorf("could not decode the version reply")
	}
	if !reply.Response || reply.ID != query.ID || reply.Opcode != 0 || reply.Truncated || reply.Rcode != dns.RcodeSuccess || len(reply.Question) != 1 {
		return "", fmt.Errorf("invalid or unsuccessful DNS response")
	}
	question := reply.Question[0]
	if !strings.EqualFold(question.Header().Name, name) || question.Header().Class != dns.ClassINET || dns.RRToType(question) != dns.TypeTXT {
		return "", fmt.Errorf("DNS response question mismatch")
	}
	for _, record := range reply.Answer {
		if txt, ok := record.(*dns.TXT); ok && strings.EqualFold(txt.Hdr.Name, name) {
			return parseVersionReply(strings.Join(txt.Txt, ""))
		}
	}
	return "", fmt.Errorf("DNS response has no version TXT record")
}

func parseStableVersion(value string) ([3]uint64, bool) {
	var result [3]uint64
	parts := strings.Split(value, ".")
	if len(parts) != 3 || len(value) > 64 {
		return result, false
	}
	for i, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return result, false
		}
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return result, false
		}
		result[i] = value
	}
	return result, true
}

func parseVersionReply(value string) (string, error) {
	fields := strings.Split(value, ";")
	if len(value) > 256 || strings.TrimSpace(fields[0]) != "v=tlspol1" {
		return "", fmt.Errorf("unrecognized version protocol")
	}
	latest := ""
	for _, field := range fields[1:] {
		key, value, found := strings.Cut(strings.TrimSpace(field), "=")
		if !found || key != "latest" {
			continue
		}
		if _, valid := parseStableVersion(value); !valid || latest != "" {
			return "", fmt.Errorf("invalid or duplicate stable version")
		}
		latest = value
	}
	if latest == "" {
		return "", fmt.Errorf("version reply has no stable version")
	}
	return latest, nil
}

func newerStableVersion(current, latest string) bool {
	current, _, _ = strings.Cut(strings.TrimPrefix(current, "v"), "+")
	base, _, prerelease := strings.Cut(current, "-")
	have, valid := parseStableVersion(base)
	want, latestValid := parseStableVersion(latest)
	if !valid || !latestValid {
		return false
	}
	for i := range have {
		if want[i] != have[i] {
			return want[i] > have[i]
		}
	}
	return prerelease
}

func runVersionChecks(ctx context.Context, cacheFile, current string) {
	id, err := loadInstanceID(cacheFile + ".instance-id")
	if err != nil {
		slog.Warn("Version checking unavailable; service continues normally", "error", err)
		return
	}
	slog.Info("Version checking and the pseudonymous active installations count are enabled", "disable", "TLSPOL_VERSION_CHECK=0")
	client := newVersionCheckClient()
	defer client.CloseIdleConnections()
	daily := time.NewTicker(versionCheckInterval)
	defer daily.Stop()
	for {
		runVersionCheckCycle(ctx, client, id, current, versionCheckRetry)
		select {
		case <-ctx.Done():
			return
		case <-daily.C:
		}
	}
}

func runVersionCheckCycle(ctx context.Context, client *http.Client, id, current string, retryDelay time.Duration) {
	for attempt := 0; attempt <= versionCheckRetries; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}
		endpoint := versionCheckResolvers[rand.IntN(len(versionCheckResolvers))]
		latest, err := queryLatestVersion(ctx, client, endpoint, id)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.Warn("Version check failed; mail policy service is unaffected", "attempt", attempt+1, "max-attempts", versionCheckRetries+1, "error", err)
			continue
		}
		if newerStableVersion(current, latest) {
			slog.Warn("A newer stable postfix-tlspol version is available", "current", current, "latest", latest, "url", "https://github.com/Zuplu/postfix-tlspol/releases/latest")
		} else {
			slog.Info("postfix-tlspol version check completed", "current", current, "latest", latest)
		}
		break
	}
}
