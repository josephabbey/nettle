package services

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
)

func TestWebServiceStateUpdatesFromBus(t *testing.T) {
	svc, baseURL, cleanup := startTestWebService(t)
	defer cleanup()

	state := fetchTestState(t, baseURL)
	if got, want := len(state.DNSRecords), 1; got != want {
		t.Fatalf("initial dns records = %d, want %d", got, want)
	}
	if got, want := len(state.Leases), 0; got != want {
		t.Fatalf("initial leases = %d, want %d", got, want)
	}

	leaseAddr := netip.MustParseAddr("192.168.0.45")
	if err := svc.bus.Publish(context.Background(), domain.DNSRecordUpserted{
		Record: domain.DNSRecord{
			Name:  "printer",
			Addr:  &leaseAddr,
			CNAME: "",
		},
	}); err != nil {
		t.Fatalf("publish dns record: %v", err)
	}
	if err := svc.bus.Publish(context.Background(), domain.DHCPLeaseAssigned{
		Lease: domain.Lease{
			Hostname:     "printer",
			HardwareAddr: "aa:bb:cc:dd:ee:ff",
			Address:      leaseAddr,
			Interface:    "eth0",
			LeaseUntil:   time.Now().Add(time.Hour).UTC(),
		},
	}); err != nil {
		t.Fatalf("publish lease: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		state = fetchTestState(t, baseURL)
		return len(state.Leases) == 1 && len(state.DNSRecords) >= 2
	})

	if state.Leases[0].Hostname != "printer" {
		t.Fatalf("lease hostname = %q, want printer", state.Leases[0].Hostname)
	}
}

func TestWebServiceSSELiveUpdates(t *testing.T) {
	svc, baseURL, cleanup := startTestWebService(t)
	defer cleanup()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/events", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("open sse stream: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	if got := readSSEEventName(t, reader); got != "snapshot" {
		t.Fatalf("first sse event = %q, want snapshot", got)
	}

	leaseAddr := netip.MustParseAddr("192.168.0.99")
	if err := svc.bus.Publish(context.Background(), domain.DHCPLeaseAssigned{
		Lease: domain.Lease{
			Hostname:     "tablet",
			HardwareAddr: "11:22:33:44:55:66",
			Address:      leaseAddr,
			Interface:    "wlan0",
			LeaseUntil:   time.Now().Add(2 * time.Hour).UTC(),
		},
	}); err != nil {
		t.Fatalf("publish lease: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return readSSEEventName(t, reader) == "lease"
	})
}

func startTestWebService(t *testing.T) (*WebService, string, func()) {
	t.Helper()

	cfg := &config.Config{
		Web: config.WebConfig{Addr: "127.0.0.1:0"},
		Hosts: []config.HostRecord{
			{
				Names: []string{"alpha"},
				IP:    addrPtrForTest("192.168.0.10"),
			},
		},
	}
	hub := bus.NewHub()
	svc := NewWeb(cfg, hub, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	if err := svc.Start(ctx); err != nil {
		cancel()
		t.Fatalf("start web service: %v", err)
	}

	waitFor(t, 3*time.Second, func() bool {
		return svc.Addr() != ""
	})

	cleanup := func() {
		cancel()
		_ = svc.Stop(context.Background())
	}

	return svc, "http://" + svc.Addr(), cleanup
}

func fetchTestState(t *testing.T, baseURL string) webState {
	t.Helper()

	resp, err := http.Get(baseURL + "/api/state")
	if err != nil {
		t.Fatalf("fetch state: %v", err)
	}
	defer resp.Body.Close()

	var state webState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	return state
}

func readSSEEventName(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for sse event")
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read sse line: %v", err)
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ":") {
			continue
		}
		if strings.HasPrefix(line, "event:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		}
	}
}

func waitFor(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for condition")
}

func addrPtrForTest(value string) *netip.Addr {
	addr := netip.MustParseAddr(value)
	return &addr
}
