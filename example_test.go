package gumroad_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	gumroad "github.com/seatling/integrations-gumroad"
	integrations "github.com/seatling/integrations-shared"
)

// ExampleGeneratePingURL demonstrates generating a 64-character hex secret and configuring a Gumroad Ping URL.
func ExampleGeneratePingURL() {
	endpoint := "https://api.seatling.app/v1/webhooks/gumroad"

	// 1. Generate the Ping URL with a 32-byte (64 hex characters) secure passcode
	pingURL, secret, err := gumroad.GeneratePingURL(endpoint, 32)
	if err != nil {
		log.Fatalf("failed generating ping URL: %v", err)
	}

	// 2. Secret is stored in your secret manager / database
	_ = secret

	// 3. The pingURL is provided to Gumroad settings (or resource_subscriptions)
	fmt.Printf("Base URL: %s\n", strings.Split(pingURL, "?")[0])
	fmt.Printf("Has passcode query: %v\n", strings.Contains(pingURL, "passcode="))

	// Output:
	// Base URL: https://api.seatling.app/v1/webhooks/gumroad
	// Has passcode query: true
}

// ExampleBuildPingURL demonstrates appending a known secret to a base webhook destination.
func ExampleBuildPingURL() {
	endpoint := "https://api.seatling.app/v1/webhooks/gumroad"
	secretHex := "4a8e9b1c7d2f3e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80"

	pingURL, err := gumroad.BuildPingURL(endpoint, secretHex)
	if err != nil {
		log.Fatalf("failed building ping URL: %v", err)
	}

	fmt.Println(pingURL)

	// Output:
	// https://api.seatling.app/v1/webhooks/gumroad?passcode=4a8e9b1c7d2f3e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80
}

// ExampleClient_ParseWebhook demonstrates parsing an incoming Gumroad Ping with passcode verification.
func ExampleClient_ParseWebhook() {
	client := gumroad.New()
	secretHex := "4a8e9b1c7d2f3e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80"

	// Simulate incoming Gumroad Ping POST request
	form := url.Values{}
	form.Set("sale_id", "sale_example_123")
	form.Set("email", "customer@example.com")
	form.Set("product_name", "Seatling Desktop")
	form.Set("price", "4900")
	form.Set("currency", "USD")

	req := httptest.NewRequest(http.MethodPost, "/webhooks/gumroad?passcode="+secretHex, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	event, err := client.ParseWebhook(req, secretHex)
	if err != nil {
		log.Fatalf("webhook parsing failed: %v", err)
	}

	fmt.Printf("Event: %s, Sale: %s, Customer: %s\n", event.EventType, event.Order.ID, event.Order.Customer.Email)
	fmt.Printf("Provider: %s\n", event.Provider)

	// Output:
	// Event: order.created, Sale: sale_example_123, Customer: customer@example.com
	// Provider: gumroad
}

// Example_completeWebhookHandler demonstrates an HTTP handler receiving Gumroad Pings with secret validation.
func Example_completeWebhookHandler() {
	client := gumroad.New()
	configuredSecret := "4a8e9b1c7d2f3e4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f80"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		event, err := client.ParseWebhook(r, configuredSecret)
		if err != nil {
			http.Error(w, "Unauthorized or invalid payload", http.StatusUnauthorized)
			return
		}

		if event.EventType == integrations.EventTypeOrderCreated {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprintf(w, "Order processed: %s", event.Order.ID)
		}
	})

	// Test request
	form := url.Values{"sale_id": {"sale_test_888"}, "email": {"alice@seatling.app"}}
	req := httptest.NewRequest(http.MethodPost, "/webhooks?passcode="+configuredSecret, strings.NewReader(form.Encode()))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	fmt.Println(rec.Body.String())

	// Output:
	// Order processed: sale_test_888
}
