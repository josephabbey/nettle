package services

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
)

const (
	vethSrvName  = "nettle-srv"
	vethCliName  = "nettle-cli"
	vethSrvIP    = "172.16.0.1"
	vethCliIP    = "172.16.0.2"
	vethPrefix   = "172.16.0.0/24"
	vethPoolEnd  = "172.16.0.200"
	netnsName    = "nettle-test"
)

func TestUDPResponsePath(t *testing.T) {
	prereq(t)
	setupNetNS(t)
	defer teardownNetNS(t)

	serverPort := 10667

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: serverPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	responseCh := make(chan struct{}, 1)
	go func() {
		buf := make([]byte, 4096)
		n, addr, err := listener.ReadFrom(buf)
		if err != nil {
			t.Logf("echo server read error: %v", err)
			return
		}
		t.Logf("echo server received %d bytes from %s", n, addr)
		_, err = listener.WriteTo([]byte("pong"), addr)
		if err != nil {
			t.Logf("echo server write error: %v", err)
			return
		}
		t.Logf("echo server sent pong to %s", addr)
		responseCh <- struct{}{}
	}()

	var clientOut, clientErr bytes.Buffer
	clientCmd := exec.Command("ip", "netns", "exec", netnsName,
		"bash", "-c",
		fmt.Sprintf("echo 'ping' > /dev/udp/%s/%d && timeout 2 cat < /dev/udp/%s/%d", vethSrvIP, serverPort, vethSrvIP, serverPort),
	)
	clientCmd.Stdout = &clientOut
	clientCmd.Stderr = &clientErr

	t.Logf("running UDP echo test from netns to %s:%d", vethSrvIP, serverPort)
	if err := clientCmd.Run(); err != nil {
		t.Logf("echo client: %v\nstdout=%s\nstderr=%s", err, clientOut.String(), clientErr.String())
	}

	select {
	case <-responseCh:
		t.Log("UDP echo test PASSED: response received from server namespace")
	case <-time.After(5 * time.Second):
		t.Fatal("UDP echo test FAILED: no response from server namespace")
	}
}

func TestDHCPPerfdhcpSingleExchange(t *testing.T) {
	prereq(t)

	srvIP := netip.MustParseAddr(vethSrvIP)
	prefix := netip.MustParsePrefix(vethPrefix)
	poolEnd := netip.MustParseAddr(vethPoolEnd)

	cfg := dhcpTestConfig(vethSrvName, prefix, srvIP, poolEnd)
	svc, cleanup := startTestDHCPService(t, cfg)
	defer cleanup()

	result := runPerfdhcp(t, vethSrvIP,
		"-n", "1",
	)

	if result.discoverSent == 0 {
		t.Fatal("perfdhcp did not send any DISCOVER packets")
	}
	if result.discoverReceived == 0 {
		t.Fatal("perfdhcp did not receive any OFFER packets (0/1)")
	}
	if result.requestSent == 0 {
		t.Fatal("perfdhcp did not send any REQUEST packets")
	}
	if result.requestReceived == 0 {
		t.Fatal("perfdhcp did not receive any ACK packets (0/1)")
	}
	if result.drops > 0 {
		t.Fatalf("perfdhcp reported %d drops, want 0", result.drops)
	}
	if len(result.leases) == 0 {
		t.Fatal("perfdhcp did not receive any leases")
	}

	lease := result.leases[0]
	t.Logf("acquired lease: %s", lease)

	count := countActiveLeases(svc)
	if count == 0 {
		t.Fatal("DHCPService has no active leases after perfdhcp exchange")
	}
	t.Logf("active leases in pool: %d", count)
}

func TestDHCPPerfdhcpRate(t *testing.T) {
	prereq(t)

	srvIP := netip.MustParseAddr(vethSrvIP)
	prefix := netip.MustParsePrefix(vethPrefix)
	poolEnd := netip.MustParseAddr(vethPoolEnd)

	cfg := dhcpTestConfig(vethSrvName, prefix, srvIP, poolEnd)
	svc, cleanup := startTestDHCPService(t, cfg)
	defer cleanup()

	rate := 50
	numRequests := 100
	result := runPerfdhcp(t, vethSrvIP,
		"-r", strconv.Itoa(rate),
		"-n", strconv.Itoa(numRequests),
		"-R", "20",
		"-p", "5",
	)

	t.Logf("perfdhcp rate test: %d/%d DORA exchanges at %d req/s",
		result.discoverReceived, numRequests, rate)

	t.Logf("active leases after rate test: %d", countActiveLeases(svc))

	if result.discoverSent == 0 {
		t.Fatal("perfdhcp did not send any packets")
	}
	if result.dropsRatio > 10 {
		t.Fatalf("perfdhcp drop ratio %.1f%% exceeds 10%% threshold", result.dropsRatio)
	}
	if len(result.leases) == 0 {
		t.Fatal("perfdhcp did not acquire any leases")
	}

	t.Logf("acquired %d unique leases", len(result.leases))
	t.Logf("drops: %d (%.1f%%)", result.drops, result.dropsRatio)

	if result.avgDelayDiscover > 0 {
		t.Logf("avg DISCOVER-OFFER delay: %.2f ms", result.avgDelayDiscover)
	}
	if result.avgDelayRequest > 0 {
		t.Logf("avg REQUEST-ACK delay: %.2f ms", result.avgDelayRequest)
	}
}

func TestDHCPPerfdhcpMultipleClients(t *testing.T) {
	prereq(t)

	srvIP := netip.MustParseAddr(vethSrvIP)
	prefix := netip.MustParsePrefix(vethPrefix)
	poolEnd := netip.MustParseAddr(vethPoolEnd)

	cfg := dhcpTestConfig(vethSrvName, prefix, srvIP, poolEnd)
	_, cleanup := startTestDHCPService(t, cfg)
	defer cleanup()

	numClients := 50
	result := runPerfdhcp(t, vethSrvIP,
		"-n", strconv.Itoa(numClients),
		"-R", strconv.Itoa(numClients),
		"-b", "mac=00:0c:01:02:00:00",
	)

	if result.discoverReceived == 0 {
		t.Fatal("perfdhcp did not receive any OFFERs")
	}
	if result.requestReceived == 0 {
		t.Fatal("perfdhcp did not receive any ACKs")
	}
	if result.dropsRatio > 5 {
		t.Fatalf("perfdhcp drop ratio %.1f%% exceeds 5%%", result.dropsRatio)
	}

	t.Logf("simulated %d unique clients, acquired %d leases",
		numClients, len(result.leases))
}

func TestDHCPPerfdhcpAvalanche(t *testing.T) {
	prereq(t)

	srvIP := netip.MustParseAddr(vethSrvIP)
	prefix := netip.MustParsePrefix(vethPrefix)
	poolEnd := netip.MustParseAddr(vethPoolEnd)

	cfg := dhcpTestConfig(vethSrvName, prefix, srvIP, poolEnd)
	_, cleanup := startTestDHCPService(t, cfg)
	defer cleanup()

	numClients := 100
	result := runPerfdhcp(t, vethSrvIP,
		"--scenario", "avalanche",
		"-R", strconv.Itoa(numClients),
		"-b", "mac=00:0c:01:02:00:00",
		"-p", "10",
	)

	if result.discoverReceived == 0 {
		t.Fatal("perfdhcp avalanche did not receive any OFFERs")
	}
	if result.requestReceived == 0 {
		t.Fatal("perfdhcp avalanche did not receive any ACKs")
	}

	t.Logf("avalanche: %d clients, %d DORA exchanges completed, %d drops",
		numClients, result.discoverReceived, result.drops)
}

func TestDHCPPerfdhcpRenew(t *testing.T) {
	prereq(t)

	srvIP := netip.MustParseAddr(vethSrvIP)
	prefix := netip.MustParsePrefix(vethPrefix)
	poolEnd := netip.MustParseAddr(vethPoolEnd)

	cfg := dhcpTestConfig(vethSrvName, prefix, srvIP, poolEnd)
	_, cleanup := startTestDHCPService(t, cfg)
	defer cleanup()

	result := runPerfdhcp(t, vethSrvIP,
		"-n", "20",
		"-r", "10",
		"-R", "5",
		"-f", "5",
		"-p", "10",
	)

	if result.discoverReceived == 0 {
		t.Fatal("perfdhcp did not receive any OFFERs")
	}
	if result.requestReceived == 0 {
		t.Fatal("perfdhcp did not receive any ACKs")
	}

	t.Logf("renew test: %d discover-received, %d request-received, %d drops",
		result.discoverReceived, result.requestReceived, result.drops)
}

type perfdhcpResult struct {
	rate             float64
	discoverSent     int
	discoverReceived int
	requestSent      int
	requestReceived  int
	drops            int
	dropsRatio       float64
	avgDelayDiscover float64
	avgDelayRequest  float64
	leases           []string
}

func prereq(t *testing.T) {
	t.Helper()

	if os.Geteuid() != 0 {
		t.Skip("SKIP: requires root for namespace/veth setup")
	}

	for _, cmd := range []string{"perfdhcp", "ip"} {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Skipf("SKIP: %s not found in PATH", cmd)
		}
	}
}

func dhcpTestConfig(ifname string, prefix netip.Prefix, gateway netip.Addr, poolEnd netip.Addr) *config.Config {
	poolStart := prefix.Addr().Next()

	dns := netip.MustParseAddr(vethSrvIP)
	return &config.Config{
		Global: config.GlobalConfig{TLD: "nettle.test"},
		DHCP: config.DHCPConfig{
			Gateway: &gateway,
			DNS:     []netip.Addr{dns},
			Main: config.Assignment{
				Range: &config.AddressRange{
					Start: poolStart,
					End:   poolEnd,
				},
				Interface: ifname,
				Lease:     10 * time.Minute,
			},
		},
		Web: config.WebConfig{Addr: "127.0.0.1:0"},
	}
}

func startTestDHCPService(t *testing.T, cfg *config.Config) (*DHCPService, func()) {
	t.Helper()

	setupNetNS(t)

	hub := bus.NewHub()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := NewDHCP(cfg, hub, logger)

	svc.mu.Lock()
	svc.started = true
	svc.ctx, svc.cancel = context.WithCancel(context.Background())
	svc.mu.Unlock()

	pools, err := svc.buildPools()
	if err != nil {
		teardownNetNS(t)
		t.Fatalf("build pools: %v", err)
	}
	if len(pools) == 0 {
		teardownNetNS(t)
		t.Fatal("no DHCP pools configured")
	}

	svc.mu.Lock()
	svc.pools = pools
	svc.mu.Unlock()

	if svc.bus != nil {
		events, unsubscribe := svc.bus.Subscribe(32)
		svc.unsubscribe = unsubscribe
		go svc.consumeEvents(events)
	}

	for _, pool := range svc.pools {
		ifname := pool.assign.Interface
		conn, err := server4.NewIPv4UDPConn(ifname, &net.UDPAddr{IP: net.IPv4zero, Port: dhcpv4.ServerPort})
		if err != nil {
			svc.Stop(context.Background())
			teardownNetNS(t)
			t.Fatalf("create udp conn: %v", err)
		}
		handler := wrapHandler(pool.handler)
		server, err := server4.NewServer("", nil, handler, server4.WithConn(conn))
		if err != nil {
			conn.Close()
			svc.Stop(context.Background())
			teardownNetNS(t)
			t.Fatalf("create server: %v", err)
		}
		svc.mu.Lock()
		svc.servers = append(svc.servers, server)
		svc.mu.Unlock()

		go func(name string, srv *server4.Server) {
			if err := srv.Serve(); err != nil {
				logger.Error("dhcp server stopped", "pool", name, "error", err)
			}
		}(pool.name, server)

		t.Logf("dhcp server pool=%s addr=%s", pool.name, conn.LocalAddr())
	}

	time.Sleep(100 * time.Millisecond)

	cleanup := func() {
		cancel := svc.cancel
		if cancel != nil {
			cancel()
		}
		_ = svc.Stop(context.Background())
		hub.Close()
		teardownNetNS(t)
	}

	return svc, cleanup
}

type logPacketConn struct {
	net.PacketConn
}

func (c *logPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if err != nil {
		slog.Error("dhcp write failed", "addr", addr, "error", err, "bytes", n)
	} else {
		slog.Debug("dhcp write OK", "addr", addr, "bytes", n)
	}
	return n, err
}

func wrapHandler(next func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4)) func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	return func(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
		defer func() {
			if r := recover(); r != nil {
				slog.Error("dhcp handler panic", "peer", peer, "recover", r)
			}
		}()
		lc := &logPacketConn{PacketConn: conn}
		next(lc, peer, m)
	}
}

func setupNetNS(t *testing.T) {
	t.Helper()

	exec.Command("ip", "netns", "delete", netnsName).Run()
	exec.Command("ip", "link", "delete", vethSrvName).Run()
	execIP(t, "netns", "add", netnsName)
	execIP(t, "link", "add", vethSrvName, "type", "veth", "peer", "name", vethCliName)
	execIP(t, "link", "set", vethCliName, "netns", netnsName)
	execIP(t, "addr", "add", vethSrvIP+"/24", "dev", vethSrvName)
	execIP(t, "link", "set", vethSrvName, "up")
	execIPNS(t, netnsName, "addr", "add", vethCliIP+"/24", "dev", vethCliName)
	execIPNS(t, netnsName, "link", "set", "lo", "up")
	execIPNS(t, netnsName, "link", "set", vethCliName, "up")
	execIPNS(t, netnsName, "route", "add", "default", "via", vethSrvIP)
}

func teardownNetNS(t *testing.T) {
	t.Helper()

	exec.Command("ip", "link", "delete", vethSrvName).Run()
	exec.Command("ip", "netns", "delete", netnsName).Run()
}

func execIP(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("ip", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v\n%s", strings.Join(args, " "), err, string(output))
	}
}

func execIPNS(t *testing.T, ns string, args ...string) {
	t.Helper()
	allArgs := append([]string{"netns", "exec", ns, "ip"}, args...)
	cmd := exec.Command("ip", allArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ip netns exec %s ip %s: %v\n%s", ns, strings.Join(args, " "), err, string(output))
	}
}

func runPerfdhcp(t *testing.T, serverIP string, extraArgs ...string) perfdhcpResult {
	t.Helper()

	args := []string{
		"-4",
		"-l", vethCliName,
		"-x", "l",
	}
	args = append(args, extraArgs...)
	args = append(args, serverIP)

	nsArgs := append([]string{"netns", "exec", netnsName, "perfdhcp"}, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ip", nsArgs...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	t.Logf("running: perfdhcp %s", strings.Join(args, " "))

	err := cmd.Run()
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	for _, line := range strings.Split(stderrStr, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			t.Logf("perfdhcp stderr: %s", line)
		}
	}

	for _, line := range strings.Split(stdoutStr, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			t.Logf("perfdhcp stdout: %s", line)
		}
	}

	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("perfdhcp timed out: %v", ctx.Err())
		}
		t.Logf("perfdhcp finished with non-zero exit: %v", err)
	}

	return parsePerfdhcpOutput(t, stdoutStr)
}

func parsePerfdhcpOutput(t *testing.T, output string) perfdhcpResult {
	t.Helper()

	var result perfdhcpResult
	scanner := bufio.NewScanner(strings.NewReader(output))

	inDiscover := false
	inRequest := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case line == "***Statistics for: DISCOVER-OFFER***":
			inDiscover = true
			inRequest = false
		case line == "***Statistics for: REQUEST-ACK***":
			inDiscover = false
			inRequest = true
		case strings.HasPrefix(line, "***"):
			inDiscover = false
			inRequest = false
		}

		if strings.HasPrefix(line, "Rate:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result.rate, _ = strconv.ParseFloat(parts[1], 64)
			}
		}

		if strings.HasPrefix(line, "sent packets:") {
			val := extractInt(line)
			if inDiscover {
				result.discoverSent = val
			} else if inRequest {
				result.requestSent = val
			}
		}

		if strings.HasPrefix(line, "received packets:") {
			val := extractInt(line)
			if inDiscover {
				result.discoverReceived = val
			} else if inRequest {
				result.requestReceived = val
			}
		}

		if strings.HasPrefix(line, "drops:") && !strings.HasPrefix(line, "drops ratio:") && !strings.Contains(line, "%") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				result.drops, _ = strconv.Atoi(parts[1])
			}
		}

		if strings.HasPrefix(line, "drops ratio:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				val := strings.TrimSuffix(parts[2], "%")
				result.dropsRatio, _ = strconv.ParseFloat(val, 64)
			}
		}

		if strings.HasPrefix(line, "avg delay:") && strings.Contains(line, "ms") && !strings.Contains(line, "n/a") {
			parts := strings.Fields(line)
			for _, p := range parts {
				if strings.HasSuffix(p, "ms") {
					val := strings.TrimSuffix(p, "ms")
					if f, err := strconv.ParseFloat(val, 64); err == nil {
						if inDiscover {
							result.avgDelayDiscover = f
						} else if inRequest {
							result.avgDelayRequest = f
						}
					}
				}
			}
		}

		if strings.HasPrefix(line, "Lease:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addr := strings.TrimRight(parts[1], ",")
				result.leases = append(result.leases, addr)
			}
		}
	}

	return result
}

func extractInt(line string) int {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		n, err := strconv.Atoi(parts[len(parts)-1])
		if err == nil {
			return n
		}
	}
	return 0
}

func countActiveLeases(svc *DHCPService) int {
	if svc == nil {
		return 0
	}

	svc.mu.Lock()
	defer svc.mu.Unlock()

	count := 0
	for _, pool := range svc.pools {
		pool.leasesMu.RLock()
		count += len(pool.leases)
		pool.leasesMu.RUnlock()
	}
	return count
}
