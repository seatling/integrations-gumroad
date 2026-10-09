package gumroad_test

import (
	"encoding/hex"
	"net/url"
	"testing"

	gumroad "github.com/seatling/integrations-gumroad"
)

func TestGenerateWebhookSecret(t *testing.T) {
	t.Run("default 32 bytes produces 64 hex chars", func(t *testing.T) {
		secret, err := gumroad.GenerateWebhookSecret(0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secret) != 64 {
			t.Fatalf("expected 64 characters, got %d: %s", len(secret), secret)
		}
		decoded, err := hex.DecodeString(secret)
		if err != nil {
			t.Fatalf("invalid hex: %v", err)
		}
		if len(decoded) != 32 {
			t.Fatalf("expected 32 decoded bytes, got %d", len(decoded))
		}
	})

	t.Run("custom length 16 bytes produces 32 hex chars", func(t *testing.T) {
		secret, err := gumroad.GenerateWebhookSecret(16)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(secret) != 32 {
			t.Fatalf("expected 32 characters, got %d: %s", len(secret), secret)
		}
	})
}

func TestBuildPingURL(t *testing.T) {
	t.Run("appends passcode to existing query parameters", func(t *testing.T) {
		endpoint := "https://api.seatling.app/v1/webhooks/gumroad?env=prod"
		secret := "abcdef123456"

		resURL, err := gumroad.BuildPingURL(endpoint, secret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		parsed, err := url.Parse(resURL)
		if err != nil {
			t.Fatalf("failed to parse result: %v", err)
		}

		if parsed.Query().Get("passcode") != secret {
			t.Fatalf("expected passcode %s, got %s", secret, parsed.Query().Get("passcode"))
		}
		if parsed.Query().Get("env") != "prod" {
			t.Fatalf("expected preserved query param env=prod, got %s", parsed.Query().Get("env"))
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		_, err := gumroad.BuildPingURL("", "secret")
		if err == nil {
			t.Fatal("expected error on empty url")
		}

		_, err = gumroad.BuildPingURL("https://example.com", "   ")
		if err == nil {
			t.Fatal("expected error on empty secret")
		}

		_, err = gumroad.BuildPingURL("http://::invalid-url", "secret")
		if err == nil {
			t.Fatal("expected error on invalid url")
		}
	})
}

func TestGeneratePingURL(t *testing.T) {
	t.Run("generates valid ping url with 64 hex char passcode", func(t *testing.T) {
		endpoint := "https://api.seatling.app/v1/webhooks/gumroad"
		pingURL, secret, err := gumroad.GeneratePingURL(endpoint, 32)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if len(secret) != 64 {
			t.Fatalf("expected 64 char secret, got %d: %s", len(secret), secret)
		}

		parsed, err := url.Parse(pingURL)
		if err != nil {
			t.Fatalf("failed to parse ping url: %v", err)
		}

		if parsed.Query().Get("passcode") != secret {
			t.Fatalf("expected passcode query to match generated secret")
		}
	})

	t.Run("propagates error on invalid endpoint", func(t *testing.T) {
		_, _, err := gumroad.GeneratePingURL("http://::invalid-url", 32)
		if err == nil {
			t.Fatal("expected error on invalid url")
		}
	})
}
