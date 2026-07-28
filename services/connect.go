package services

import (
	"context"
	"log/slog"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
)

type ConnectService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger
}

func NewConnect(cfg *config.Config, b bus.Bus, logger *slog.Logger) *ConnectService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ConnectService{
		cfg: cfg,
		bus: b,
		log: logger.With("component", "connect"),
	}
}

func (s *ConnectService) Start(ctx context.Context) error {
	s.log.Info("connect service started", "glue", len(s.cfg.Glue))
	return nil
}

func (s *ConnectService) Stop(ctx context.Context) error {
	s.log.Info("connect service stopped")
	return nil
}
