package gumroad_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	gumroad "github.com/seatling/integrations-gumroad"
	integrations "github.com/seatling/integrations-shared"
)

func getIntegrationToken(t *testing.T) string {
	token := strings.TrimSpace(os.Getenv("GUMROAD_ACCESS_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("GUMROAD_TOKEN"))
	}
	if token == "" {
		t.Fatalf("skipping live Gumroad integration test: GUMROAD_ACCESS_TOKEN is not set")
	}
	return token
}

func TestIntegration_GetUser(t *testing.T) {
	token := getIntegrationToken(t)

	client := gumroad.New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	user, err := client.GetUser(ctx, token)
	if err != nil {
		t.Fatalf("GetUser live call failed: %v", err)
	}

	if user == nil {
		t.Fatal("expected non-nil user")
	}
	if user.Provider != integrations.ProviderGumroad {
		t.Fatalf("expected provider %v, got %v", integrations.ProviderGumroad, user.Provider)
	}
	if user.Email == "" && user.ID == "" {
		t.Fatalf("expected user Email or ID to be populated, got: %+v", user)
	}
	t.Logf("Successfully fetched live Gumroad user: email=%s, id=%s, name=%s", user.Email, user.ID, user.Name)
}

func TestIntegration_ListAndGetProducts(t *testing.T) {
	token := getIntegrationToken(t)

	client := gumroad.New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	products, err := client.ListProducts(ctx, token)
	if err != nil {
		t.Fatalf("ListProducts live call failed: %v", err)
	}

	t.Logf("Successfully fetched %d live Gumroad products", len(products))

	if len(products) == 0 {
		t.Fatal("expected at least one product")
	}

	firstProduct := products[0]
	if firstProduct.ID == "" {
		t.Fatal("expected product to have non-empty ID")
	}

	fetched, err := client.GetProduct(ctx, token, firstProduct.ID)
	if err != nil {
		t.Fatalf("GetProduct live call failed for ID %s: %v", firstProduct.ID, err)
	}
	if fetched.ID != firstProduct.ID {
		t.Fatalf("expected product ID %s, got %s", firstProduct.ID, fetched.ID)
	}
	t.Logf("Successfully fetched live Gumroad product by ID: id=%s, name=%s, price=%d %s",
		fetched.ID, fetched.Name, fetched.PriceCents, fetched.Currency)
}

func TestIntegration_WebhookSubscriptions(t *testing.T) {
	token := getIntegrationToken(t)

	client := gumroad.New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	subs, err := client.ListWebhookSubscriptions(ctx, token)
	if err != nil {
		t.Fatalf("ListWebhookSubscriptions live call failed: %v", err)
	}

	t.Logf("Successfully listed %d live Gumroad webhook subscriptions", len(subs))
}

func TestIntegration_VerifyLicense(t *testing.T) {
	token := getIntegrationToken(t)
	_ = token // token confirmed available

	productID := strings.TrimSpace(os.Getenv("GUMROAD_PRODUCT_ID"))
	licenseKey := strings.TrimSpace(os.Getenv("GUMROAD_LICENSE_KEY"))

	if productID == "" || licenseKey == "" {
		t.Fatalf("skipping live VerifyLicense integration test: GUMROAD_PRODUCT_ID and/or GUMROAD_LICENSE_KEY not set")
	}

	client := gumroad.New()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := client.VerifyLicense(ctx, integrations.LicenseVerificationRequest{
		ProductID:  productID,
		LicenseKey: licenseKey,
	})
	if err != nil {
		t.Fatalf("VerifyLicense live call failed: %v", err)
	}

	if result == nil {
		t.Fatal("expected non-nil LicenseVerificationResult")
	}
	if result.Provider != integrations.ProviderGumroad {
		t.Fatalf("expected provider %v, got %v", integrations.ProviderGumroad, result.Provider)
	}
	if !result.Valid {
		t.Fatalf("expected license to be valid, got invalid: status=%s, message=%s", result.Status, result.Message)
	}

	t.Logf("Successfully verified live license: valid=%v, status=%s, uses=%d, message=%s",
		result.Valid, result.Status, result.UsesCount, result.Message)
}
