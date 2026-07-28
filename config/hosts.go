package config

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type StaticHost struct {
	Hostname     string
	HardwareAddr string
	Address      netip.Addr
}

func ReadHostsFile(path string) ([]HostRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("hosts file %q: %w", path, err)
	}
	defer f.Close()

	var records []HostRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		addr, err := netip.ParseAddr(fields[0])
		if err != nil {
			continue
		}

		record := HostRecord{
			Names: fields[1:],
			IP:    &addr,
		}
		records = append(records, record)
	}

	return records, scanner.Err()
}

func ReadEthersFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]string{}, nil
		}
		return nil, fmt.Errorf("ethers file %q: %w", path, err)
	}
	defer f.Close()

	ethers := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		hostname := strings.TrimSpace(fields[1])
		ethers[hostname] = strings.TrimSpace(strings.ToLower(fields[0]))
	}

	return ethers, scanner.Err()
}

func DeriveStaticHosts(hosts []HostRecord, ethers map[string]string) []StaticHost {
	hostnameMAC := map[string]string{}
	for hostname, mac := range ethers {
		hostnameMAC[hostname] = mac
	}

	var statics []StaticHost
	for _, host := range hosts {
		if host.IP == nil {
			continue
		}

		firstWord := ""
		for _, name := range host.Names {
			n := strings.TrimSpace(name)
			if n == "" {
				continue
			}
			if !strings.Contains(n, ".") {
				firstWord = n
				break
			}
		}

		mac := ""
		if firstWord != "" {
			mac = hostnameMAC[firstWord]
		}

		hostname := firstWord
		if hostname == "" {
			hostname = host.Names[0]
		}

		statics = append(statics, StaticHost{
			Hostname:     hostname,
			HardwareAddr: mac,
			Address:      *host.IP,
		})
	}

	return statics
}
