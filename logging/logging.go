package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Config struct {
	Level  string
	Format string
}

func Setup(cfg Config) (*slog.Logger, error) {
	handler, err := handlerFor(os.Stderr, cfg)
	if err != nil {
		return nil, err
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger, nil
}

func Component(base *slog.Logger, component string) *slog.Logger {
	if base == nil {
		base = slog.Default()
	}
	return base.With("component", component)
}

func SinkLogger(w io.Writer, cfg Config) (*slog.Logger, error) {
	handler, err := handlerFor(w, cfg)
	if err != nil {
		return nil, err
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger, nil
}

func handlerFor(w io.Writer, cfg Config) (slog.Handler, error) {
	level := new(slog.LevelVar)
	if strings.TrimSpace(cfg.Level) == "" {
		level.Set(slog.LevelInfo)
	} else if err := level.UnmarshalText([]byte(strings.TrimSpace(cfg.Level))); err != nil {
		return nil, err
	}
	opts := &slog.HandlerOptions{Level: level}
	switch strings.ToLower(strings.TrimSpace(cfg.Format)) {
	case "", "text":
		return slog.NewTextHandler(w, opts), nil
	case "json":
		return slog.NewJSONHandler(w, opts), nil
	default:
		return nil, fmt.Errorf("log format %q is not supported", cfg.Format)
	}
}
