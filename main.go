package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/logging"
	"github.com/josephabbey/nettle/services"
)

func main() {
	if err := run(); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath = flag.String("config", "test/Nettlefile", "path to the Nettle config")
		validate   = flag.Bool("validate", false, "validate config and exit")
		logLevel   = flag.String("log-level", "", "override log level from config")
		logFormat  = flag.String("log-format", "", "override log format from config")
	)
	flag.Parse()

	file, err := os.Open(*configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	cfg, err := config.Parse(*configPath, file)
	if err != nil {
		return err
	}

	hostsFileRecords, err := config.ReadHostsFile(cfg.Global.HostsFile)
	if err != nil {
		return err
	}
	cfg.Hosts = append(cfg.Hosts, hostsFileRecords...)

	ethers, err := config.ReadEthersFile(cfg.Global.EthersFile)
	if err != nil {
		return err
	}
	cfg.StaticHosts = config.DeriveStaticHosts(cfg.Hosts, ethers)

	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	if *logFormat != "" {
		cfg.Logging.Format = *logFormat
	}

	logger, err := logging.Setup(logging.Config{
		Level:  cfg.Logging.Level,
		Format: cfg.Logging.Format,
	})
	if err != nil {
		return err
	}
	slog.SetDefault(logger)

	if err := cfg.Validate(); err != nil {
		logger.Error("config validation failed", "error", err)
		return err
	}
	if *validate {
		logger.Info("config validated")
		return nil
	}

	hub := bus.NewHub()
	defer hub.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	dns := services.NewDNS(cfg, hub, logger)
	vpn := services.NewVPN(cfg, hub, logger)
	connect := services.NewConnect(cfg, hub, logger)
	connect.SetDNS(dns)
	web := services.NewWeb(cfg, hub, logger)
	web.SetVPN(vpn)
	web.SetConnect(connect)

	runtime := []services.Service{
		dns,
		services.NewDHCP(cfg, hub, logger),
		vpn,
		connect,
		web,
	}

	started := 0
	for _, svc := range runtime {
		if err := svc.Start(ctx); err != nil {
			for i := started - 1; i >= 0; i-- {
				_ = runtime[i].Stop(context.Background())
			}
			return err
		}
		started++
	}

	logger.Info("nettle started", "config", *configPath)
	<-ctx.Done()
	logger.Info("shutdown requested")

	for i := len(runtime) - 1; i >= 0; i-- {
		_ = runtime[i].Stop(context.Background())
	}
	return nil
}
