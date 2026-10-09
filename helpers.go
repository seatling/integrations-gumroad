package gumroad

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const (
	// DefaultSecretByteLength is 32 bytes, producing a 64-character hex string.
	DefaultSecretByteLength = 32
)

// GenerateWebhookSecret generates a cryptographically secure random hexadecimal string.
// If byteLength <= 0, DefaultSecretByteLength (32 bytes = 64 hex characters) is used.
func GenerateWebhookSecret(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = DefaultSecretByteLength
	}

	buf := make([]byte, byteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}

	return hex.EncodeToString(buf), nil
}

// BuildPingURL constructs a secure Gumroad Ping webhook URL appending the secret passcode.
// The secret is set as the "passcode" query parameter, which is natively validated by ParseWebhook.
func BuildPingURL(endpointURL string, secret string) (string, error) {
	cleanURL := strings.TrimSpace(endpointURL)
	if cleanURL == "" {
		return "", fmt.Errorf("endpoint url cannot be empty")
	}

	cleanSecret := strings.TrimSpace(secret)
	if cleanSecret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	parsed, err := url.Parse(cleanURL)
	if err != nil {
		return "", fmt.Errorf("invalid endpoint url: %w", err)
	}

	q := parsed.Query()
	q.Set("passcode", cleanSecret)
	parsed.RawQuery = q.Encode()

	return parsed.String(), nil
}

// GeneratePingURL combines secret generation and URL creation into a single helper.
// It generates a 64-character hex secret and appends it to the base endpoint URL.
func GeneratePingURL(endpointURL string, byteLength int) (pingURL string, secretHex string, err error) {
	secret, err := GenerateWebhookSecret(byteLength)
	if err != nil {
		return "", "", err
	}

	fullURL, err := BuildPingURL(endpointURL, secret)
	if err != nil {
		return "", "", err
	}

	return fullURL, secret, nil
}
