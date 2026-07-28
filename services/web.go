package services

import (
	"context"
	"log/slog"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
)

type WebService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger
}

func NewWeb(cfg *config.Config, b bus.Bus, logger *slog.Logger) *WebService {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebService{
		cfg: cfg,
		bus: b,
		log: logger.With("component", "web"),
	}
}

func (s *WebService) Start(ctx context.Context) error {
	s.log.Info("web service started")
	return nil
}

func (s *WebService) Stop(ctx context.Context) error {
	s.log.Info("web service stopped")
	return nil
}
