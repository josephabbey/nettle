package logging

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestSinkLoggerInstallsDefault(t *testing.T) {
	var buf bytes.Buffer
	logger, err := SinkLogger(&buf, Config{Level: "debug", Format: "text"})
	if err != nil {
		t.Fatalf("sink logger: %v", err)
	}
	if slog.Default() != logger {
		t.Fatalf("default logger was not installed")
	}

	logger.Info("hello", "component", "test")
	if buf.Len() == 0 {
		t.Fatal("expected log output")
	}
}
