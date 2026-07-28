package services

import (
	"context"
	"log/slog"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
)

type VPNService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger
}

func NewVPN(cfg *config.Config, b bus.Bus, logger *slog.Logger) *VPNService {
	if logger == nil {
		logger = slog.Default()
	}
	return &VPNService{
		cfg: cfg,
		bus: b,
		log: logger.With("component", "vpn"),
	}
}

func (s *VPNService) Start(ctx context.Context) error {
	s.log.Info("vpn service started", "assigned", s.cfg.VPN.Assign != nil)
	return nil
}

func (s *VPNService) Stop(ctx context.Context) error {
	s.log.Info("vpn service stopped")
	return nil
}
