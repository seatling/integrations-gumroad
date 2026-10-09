package gumroad

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	integrations "github.com/seatling/integrations-shared"
)

func TestNew_Defaults(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("expected non-nil client")
	}
	if c.Provider() != integrations.ProviderGumroad {
		t.Fatalf("expected provider %v, got %v", integrations.ProviderGumroad, c.Provider())
	}
	if c.baseURL != DefaultBaseURL {
		t.Fatalf("expected default baseURL %q, got %q", DefaultBaseURL, c.baseURL)
	}
	if c.httpClient == nil {
		t.Fatal("expected non-nil httpClient")
	}
}

func TestOptions(t *testing.T) {
	customClient := &http.Client{Timeout: 5 * time.Second}
	c := New(
		WithHTTPClient(customClient),
		WithBaseURL("https://custom.api.gumroad.com/v2/"),
		WithAccessToken("  test_token_123  "),
		nil,
	)

	if c.httpClient != customClient {
		t.Fatal("expected custom httpClient")
	}
	if c.baseURL != "https://custom.api.gumroad.com/v2" {
		t.Fatalf("expected trimmed baseURL, got %q", c.baseURL)
	}
	if c.accessToken != "test_token_123" {
		t.Fatalf("expected trimmed accessToken, got %q", c.accessToken)
	}

	// Nil httpClient shouldn't override
	c2 := New(WithHTTPClient(nil), WithBaseURL(""))
	if c2.httpClient == nil {
		t.Fatal("expected default httpClient not overwritten by nil")
	}
	if c2.baseURL != DefaultBaseURL {
		t.Fatalf("expected default baseURL, got %q", c2.baseURL)
	}
}

func TestGetUser(t *testing.T) {
	t.Run("success with user_id and profile_url", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET, got %s", r.Method)
			}
			if r.URL.Path != "/user" {
				t.Fatalf("expected /user, got %s", r.URL.Path)
			}
			if r.Header.Get("Authorization") != "Bearer valid_token" {
				t.Fatalf("unexpected Authorization header: %s", r.Header.Get("Authorization"))
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"user": {
					"user_id": "usr_abc",
					"name": "Jane Creator",
					"email": "jane@example.com",
					"profile_url": "https://jane.gumroad.com",
					"currency": "usd",
					"custom_domain": "https://shop.jane.com",
					"subscribed_to_email": true
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		u, err := c.GetUser(context.Background(), "valid_token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ID != "usr_abc" {
			t.Fatalf("expected ID usr_abc, got %s", u.ID)
		}
		if u.Email != "jane@example.com" {
			t.Fatalf("expected email jane@example.com, got %s", u.Email)
		}
		if u.Provider != integrations.ProviderGumroad {
			t.Fatalf("expected provider gumroad, got %s", u.Provider)
		}
		if !u.SubscribedToEmail {
			t.Fatal("expected subscribed_to_email true")
		}
	})

	t.Run("fallback to id and url", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"user": {
					"id": "usr_id_fallback",
					"name": "Fallback Creator",
					"email": "fb@example.com",
					"url": "https://fb.gumroad.com"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL), WithAccessToken("default_token"))
		u, err := c.GetUser(context.Background(), "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ID != "usr_id_fallback" {
			t.Fatalf("expected fallback ID, got %s", u.ID)
		}
		if u.ProfileURL != "https://fb.gumroad.com" {
			t.Fatalf("expected fallback profile URL, got %s", u.ProfileURL)
		}
	})

	t.Run("missing access token", func(t *testing.T) {
		c := New()
		_, err := c.GetUser(context.Background(), "")
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}
	})

	t.Run("api unauthorized error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success": false, "message": "Invalid token"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetUser(context.Background(), "bad_token")
		if !errors.Is(err, integrations.ErrUnauthorized) {
			t.Fatalf("expected ErrUnauthorized, got %v", err)
		}
	})

	t.Run("api rate limited error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"success": false, "message": "Too many requests"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetUser(context.Background(), "token")
		if !errors.Is(err, integrations.ErrRateLimited) {
			t.Fatalf("expected ErrRateLimited, got %v", err)
		}
		var apiErr *integrations.APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			t.Fatal("expected retryable error for 429")
		}
	})

	t.Run("malformed json response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`invalid-json`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetUser(context.Background(), "token")
		if err == nil {
			t.Fatal("expected unmarshal error")
		}
	})
}

func TestListProducts(t *testing.T) {
	t.Run("success with variants and url fallbacks", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/products" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"products": [
					{
						"id": "prod_1",
						"name": "Software Pro",
						"description": "Desktop app license",
						"short_url": "https://gum.co/swpro",
						"price": 2900,
						"currency": "usd",
						"formatted_price": "$29",
						"published": true,
						"variants": [
							{
								"id": "var_1",
								"name": "1 Device",
								"price_difference": 0
							},
							{
								"id": "var_2",
								"title": "5 Devices",
								"price_difference": 3000
							}
						]
					},
					{
						"id": "prod_2",
						"name": "Fallback Link Product",
						"preview_url": "https://preview.gumroad.com/p2",
						"price": 1000,
						"currency": "usd",
						"published": false
					}
				]
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		products, err := c.ListProducts(context.Background(), "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(products) != 2 {
			t.Fatalf("expected 2 products, got %d", len(products))
		}

		p1 := products[0]
		if p1.ID != "prod_1" || p1.PriceCents != 2900 || p1.URL != "https://gum.co/swpro" {
			t.Fatalf("unexpected product 1: %+v", p1)
		}
		if len(p1.Variants) != 2 {
			t.Fatalf("expected 2 variants, got %d", len(p1.Variants))
		}
		if p1.Variants[1].PriceCents != 5900 || p1.Variants[1].Name != "5 Devices" {
			t.Fatalf("unexpected variant 2: %+v", p1.Variants[1])
		}

		p2 := products[1]
		if p2.URL != "https://preview.gumroad.com/p2" {
			t.Fatalf("expected preview_url fallback, got %s", p2.URL)
		}
	})

	t.Run("missing access token", func(t *testing.T) {
		c := New()
		_, err := c.ListProducts(context.Background(), "")
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.ListProducts(context.Background(), "token")
		if err == nil {
			t.Fatal("expected error on malformed json")
		}
	})
}

func TestGetProduct(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/products/prod_123" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"product": {
					"id": "prod_123",
					"name": "Single Product",
					"custom_permalink": "https://gumroad.com/l/single",
					"price": 500,
					"currency": "usd",
					"published": true
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		p, err := c.GetProduct(context.Background(), "token", "prod_123")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.ID != "prod_123" || p.Name != "Single Product" || p.URL != "https://gumroad.com/l/single" {
			t.Fatalf("unexpected product: %+v", p)
		}
	})

	t.Run("missing product id", func(t *testing.T) {
		c := New()
		_, err := c.GetProduct(context.Background(), "token", "  ")
		if !errors.Is(err, integrations.ErrInvalidParameter) {
			t.Fatalf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("missing access token", func(t *testing.T) {
		c := New()
		_, err := c.GetProduct(context.Background(), "", "prod_1")
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}
	})

	t.Run("not found", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success": false, "message": "Product not found"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetProduct(context.Background(), "token", "missing")
		if !errors.Is(err, integrations.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("malformed json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetProduct(context.Background(), "token", "prod_1")
		if err == nil {
			t.Fatal("expected error on malformed json")
		}
	})
}

func TestVerifyLicense(t *testing.T) {
	t.Run("valid active license", func(t *testing.T) {
		inc := true
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/licenses/verify" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			_ = r.ParseForm()
			if r.Form.Get("license_key") != "KEY-12345" || r.Form.Get("product_id") != "prod_99" || r.Form.Get("increment_uses_count") != "true" {
				t.Fatalf("unexpected form params: %v", r.Form)
			}

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 1,
				"purchase": {
					"seller_id": "usr_seller",
					"product_id": "prod_99",
					"product_name": "Software Suite",
					"email": "buyer@example.com",
					"full_name": "Buyer Name",
					"price": 4900,
					"currency": "usd",
					"sale_id": "sale_123",
					"refunded": false,
					"chargebacked": false,
					"disputed": false,
					"subscription_id": "sub_99"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey:         "KEY-12345",
			ProductID:          "prod_99",
			IncrementUsesCount: &inc,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Valid {
			t.Fatal("expected valid license")
		}
		if res.Status != "active" {
			t.Fatalf("expected status active, got %s", res.Status)
		}
		if res.UsesCount != 1 || res.OrderID != "sale_123" || res.CustomerEmail != "buyer@example.com" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("permalink fallback", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			if r.Form.Get("product_permalink") != "permalink_xyz" {
				t.Fatalf("expected permalink_xyz, got %s", r.Form.Get("product_permalink"))
			}
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 2,
				"purchase": {
					"product_id": "prod_from_purchase",
					"sale_id": "sale_456"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey:       "KEY-PERM",
			ProductPermalink: "permalink_xyz",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !res.Valid || res.ProductID != "prod_from_purchase" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})

	t.Run("refunded license", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 1,
				"purchase": {
					"sale_id": "sale_ref",
					"refunded": true
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-REF",
			ProductID:  "prod_1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected refunded license to be invalid")
		}
		if res.Status != "refunded" {
			t.Fatalf("expected status refunded, got %s", res.Status)
		}
	})

	t.Run("disputed license", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 1,
				"purchase": {
					"sale_id": "sale_disp",
					"chargebacked": true
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-DISP",
			ProductID:  "prod_1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected disputed license to be invalid")
		}
		if res.Status != "disputed" {
			t.Fatalf("expected status disputed, got %s", res.Status)
		}
	})

	t.Run("cancelled subscription", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 1,
				"purchase": {
					"sale_id": "sale_canc",
					"subscription_cancelled_at": "2026-03-01T00:00:00Z"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-CANC",
			ProductID:  "prod_1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected cancelled license to be invalid")
		}
		if res.Status != "cancelled" {
			t.Fatalf("expected status cancelled, got %s", res.Status)
		}
	})

	t.Run("failed subscription", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{
				"success": true,
				"uses": 1,
				"purchase": {
					"sale_id": "sale_failed",
					"subscription_failed_at": "2026-03-01T00:00:00Z"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-FAILED",
			ProductID:  "prod_1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected failed license to be invalid")
		}
		if res.Status != "failed" {
			t.Fatalf("expected status failed, got %s", res.Status)
		}
	})

	t.Run("404 not found from gumroad", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success": false, "message": "That license does not exist for the provided product."}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		res, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-NONEXISTENT",
			ProductID:  "prod_1",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if res.Valid {
			t.Fatal("expected invalid license")
		}
		if res.Status != "invalid" {
			t.Fatalf("expected status invalid, got %s", res.Status)
		}
		if !strings.Contains(res.Message, "That license does not exist") {
			t.Fatalf("unexpected message: %s", res.Message)
		}
	})

	t.Run("validation errors", func(t *testing.T) {
		c := New()
		_, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "",
			ProductID:  "prod_1",
		})
		if !errors.Is(err, integrations.ErrInvalidParameter) {
			t.Fatalf("expected ErrInvalidParameter, got %v", err)
		}

		_, err = c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-123",
		})
		if !errors.Is(err, integrations.ErrInvalidParameter) {
			t.Fatalf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("malformed response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-123",
			ProductID:  "prod_1",
		})
		if err == nil {
			t.Fatal("expected unmarshal error")
		}
	})
}

func TestWebhookSubscriptions(t *testing.T) {
	t.Run("create success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != "/resource_subscriptions" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			_ = r.ParseForm()
			if r.Form.Get("post_url") != "https://example.com/hook" || r.Form.Get("resource_name") != "refund" {
				t.Fatalf("unexpected form params: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"resource_subscription": {
					"id": "sub_hook_1",
					"resource_name": "refund",
					"post_url": "https://example.com/hook"
				}
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		sub, err := c.CreateWebhookSubscription(context.Background(), "token", integrations.CreateWebhookSubscriptionRequest{
			TargetURL: "https://example.com/hook",
			Events:    []string{"refund"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sub.ID != "sub_hook_1" || sub.TargetURL != "https://example.com/hook" || len(sub.Events) != 1 || sub.Events[0] != "refund" {
			t.Fatalf("unexpected subscription: %+v", sub)
		}
	})

	t.Run("create validation errors", func(t *testing.T) {
		c := New()
		_, err := c.CreateWebhookSubscription(context.Background(), "", integrations.CreateWebhookSubscriptionRequest{
			TargetURL: "https://example.com",
		})
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}

		_, err = c.CreateWebhookSubscription(context.Background(), "token", integrations.CreateWebhookSubscriptionRequest{})
		if !errors.Is(err, integrations.ErrInvalidParameter) {
			t.Fatalf("expected ErrInvalidParameter, got %v", err)
		}
	})

	t.Run("list success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/resource_subscriptions" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"success": true,
				"resource_subscriptions": [
					{
						"id": "sub_hook_1",
						"resource_name": "sale",
						"post_url": "https://example.com/hook"
					}
				]
			}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		subs, err := c.ListWebhookSubscriptions(context.Background(), "token")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(subs) != 1 || subs[0].ID != "sub_hook_1" {
			t.Fatalf("unexpected subscriptions: %+v", subs)
		}
	})

	t.Run("list missing token", func(t *testing.T) {
		c := New()
		_, err := c.ListWebhookSubscriptions(context.Background(), "")
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}
	})

	t.Run("delete success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodDelete || r.URL.Path != "/resource_subscriptions/sub_hook_1" {
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success": true, "message": "deleted"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		err := c.DeleteWebhookSubscription(context.Background(), "token", "sub_hook_1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("delete validation errors", func(t *testing.T) {
		c := New()
		err := c.DeleteWebhookSubscription(context.Background(), "", "sub_1")
		if !errors.Is(err, integrations.ErrMissingAccessToken) {
			t.Fatalf("expected ErrMissingAccessToken, got %v", err)
		}

		err = c.DeleteWebhookSubscription(context.Background(), "token", "")
		if !errors.Is(err, integrations.ErrInvalidParameter) {
			t.Fatalf("expected ErrInvalidParameter, got %v", err)
		}
	})
}

func TestWebhooks(t *testing.T) {
	c := New()

	t.Run("url-encoded sale ping", func(t *testing.T) {
		form := url.Values{}
		form.Set("sale_id", "sale_001")
		form.Set("seller_id", "usr_seller")
		form.Set("product_id", "prod_100")
		form.Set("product_name", "Awesome Toolkit")
		form.Set("email", "buyer@example.com")
		form.Set("full_name", "Buyer Person")
		form.Set("price", "2500")
		form.Set("currency", "USD")
		form.Set("license_key", "LIC-XYZ-123")
		form.Set("variants", "Pro Tier")
		form.Set("ip_country", "US")

		req := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		evt, err := c.ParseWebhook(req, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventType != integrations.EventTypeOrderCreated {
			t.Fatalf("expected event type order.created, got %s", evt.EventType)
		}
		if evt.EventID != "sale_001" || evt.ProductID != "prod_100" || evt.LicenseKey != "LIC-XYZ-123" {
			t.Fatalf("unexpected event: %+v", evt)
		}
		if evt.Order == nil || evt.Order.PriceCents != 2500 || evt.Order.VariantName != "Pro Tier" {
			t.Fatalf("unexpected order: %+v", evt.Order)
		}
		if evt.Order.Customer.Email != "buyer@example.com" || evt.Order.Customer.Country != "US" {
			t.Fatalf("unexpected customer: %+v", evt.Order.Customer)
		}

		// Verify body is restored and readable
		bodyRestored, _ := io.ReadAll(req.Body)
		if len(bodyRestored) == 0 {
			t.Fatal("expected request body to be restored")
		}
	})

	t.Run("event types deduction", func(t *testing.T) {
		tests := []struct {
			name     string
			params   map[string]string
			expected integrations.EventType
		}{
			{
				name:     "refund boolean",
				params:   map[string]string{"sale_id": "s1", "refunded": "true"},
				expected: integrations.EventTypeOrderRefunded,
			},
			{
				name:     "refund resource_name",
				params:   map[string]string{"sale_id": "s2", "resource_name": "refund"},
				expected: integrations.EventTypeOrderRefunded,
			},
			{
				name:     "dispute",
				params:   map[string]string{"sale_id": "s3", "resource_name": "dispute"},
				expected: integrations.EventTypeOrderDisputed,
			},
			{
				name:     "cancellation",
				params:   map[string]string{"sale_id": "s4", "resource_name": "cancellation"},
				expected: integrations.EventTypeSubscriptionCancelled,
			},
			{
				name:     "subscription_updated",
				params:   map[string]string{"sale_id": "s5", "resource_name": "subscription_updated"},
				expected: integrations.EventTypeSubscriptionUpdated,
			},
			{
				name:     "subscription_ended",
				params:   map[string]string{"sale_id": "s6", "resource_name": "subscription_ended"},
				expected: integrations.EventTypeSubscriptionExpired,
			},
			{
				name:     "subscription_restarted",
				params:   map[string]string{"sale_id": "s7", "resource_name": "subscription_restarted"},
				expected: integrations.EventTypeSubscriptionResumed,
			},
			{
				name:     "license_key_created",
				params:   map[string]string{"sale_id": "s8", "resource_name": "license_key_created"},
				expected: integrations.EventTypeLicenseKeyCreated,
			},
			{
				name:     "license_key_updated",
				params:   map[string]string{"sale_id": "s9", "resource_name": "license_key_updated"},
				expected: integrations.EventTypeLicenseKeyUpdated,
			},
			{
				name:     "subscription_created",
				params:   map[string]string{"sale_id": "s10", "subscription_id": "sub_10"},
				expected: integrations.EventTypeSubscriptionCreated,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				form := url.Values{}
				for k, v := range tt.params {
					form.Set(k, v)
				}
				evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if evt.EventType != tt.expected {
					t.Fatalf("expected event %v, got %v", tt.expected, evt.EventType)
				}
			})
		}
	})

	t.Run("json payload", func(t *testing.T) {
		jsonData := map[string]any{
			"sale_id":         "json_sale_1",
			"seller_id":       "seller_json",
			"product_id":      "prod_json",
			"email":           "json@example.com",
			"price":           3000,
			"subscription_id": "sub_json_1",
			"created_at":      "2026-05-01T12:00:00Z",
		}
		payload, err := json.Marshal(jsonData)
		if err != nil {
			t.Fatalf("failed to marshal json: %v", err)
		}

		evt, err := c.ParseWebhookPayload(payload, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "json_sale_1" || evt.CustomerEmail != "json@example.com" {
			t.Fatalf("unexpected event: %+v", evt)
		}
		if evt.Subscription == nil || evt.Subscription.ID != "sub_json_1" {
			t.Fatalf("expected subscription populated: %+v", evt.Subscription)
		}
	})

	t.Run("secret verification modes", func(t *testing.T) {
		secret := "my_webhook_secret_key"
		form := url.Values{"sale_id": {"sale_sec"}}
		body := []byte(form.Encode())

		// Query param
		req1 := httptest.NewRequest(http.MethodPost, "/webhook?passcode="+secret, bytes.NewReader(body))
		evt, err := c.ParseWebhook(req1, secret)
		if err != nil || evt == nil {
			t.Fatalf("expected query passcode verification success, err: %v", err)
		}

		// X-Gumroad-Secret Header
		req2 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		req2.Header.Set("X-Gumroad-Secret", secret)
		evt, err = c.ParseWebhook(req2, secret)
		if err != nil || evt == nil {
			t.Fatalf("expected X-Gumroad-Secret verification success, err: %v", err)
		}

		// Authorization Bearer Header
		req3 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		req3.Header.Set("Authorization", "Bearer "+secret)
		evt, err = c.ParseWebhook(req3, secret)
		if err != nil || evt == nil {
			t.Fatalf("expected Bearer token verification success, err: %v", err)
		}

		// HMAC-SHA256 Signature Header
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sig := hex.EncodeToString(mac.Sum(nil))

		req4 := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		req4.Header.Set("X-Gumroad-Signature", sig)
		evt, err = c.ParseWebhook(req4, secret)
		if err != nil || evt == nil {
			t.Fatalf("expected HMAC signature verification success, err: %v", err)
		}

		// In Form Body
		formWithSecret := url.Values{"sale_id": {"sale_sec"}, "token": {secret}}
		req5 := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader(formWithSecret.Encode()))
		evt, err = c.ParseWebhook(req5, secret)
		if err != nil || evt == nil {
			t.Fatalf("expected form token verification success, err: %v", err)
		}

		// Invalid secret
		reqInvalid := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		_, err = c.ParseWebhook(reqInvalid, secret)
		if !errors.Is(err, integrations.ErrWebhookVerificationFailed) {
			t.Fatalf("expected ErrWebhookVerificationFailed, got %v", err)
		}
	})

	t.Run("invalid payload errors", func(t *testing.T) {
		_, err := c.ParseWebhook(nil, "")
		if !errors.Is(err, integrations.ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload, got %v", err)
		}

		_, err = c.ParseWebhookPayload(nil, nil, "")
		if !errors.Is(err, integrations.ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload, got %v", err)
		}

		_, err = c.ParseWebhookPayload([]byte("   "), nil, "")
		if !errors.Is(err, integrations.ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload on whitespace, got %v", err)
		}

		_, err = c.ParseWebhookPayload([]byte("{bad-json"), nil, "")
		if !errors.Is(err, integrations.ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload on bad json, got %v", err)
		}
	})

	t.Run("additional payload parsing branches", func(t *testing.T) {
		// Multi-value query param and order_number parsing
		form := url.Values{}
		form.Add("multi", "val1") // non-spec: must be discarded
		form.Add("multi", "val2")
		form.Set("order_number", "ord_999")
		form.Set("sale_timestamp", "2026-06-01T15:00:00Z")
		form.Set("price", "49.99")
		form.Set("variants", "Single Seat")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "ord_999" || evt.Order.VariantName != "Single Seat" || evt.Order.PriceCents != 49 {
			t.Fatalf("unexpected event: %+v", evt)
		}
		if _, exists := evt.RawPayload["multi"]; exists {
			t.Fatal("expected non-spec key 'multi' to be filtered out of RawPayload")
		}

		// Fallback to "order_number" field and float numeric price in JSON
		jsonBytes := []byte(`{"order_number": "id_123", "price": 19.99, "unknown_field": "drop_me"}`)
		evtJSON, err := c.ParseWebhookPayload(jsonBytes, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtJSON.EventID != "id_123" || evtJSON.Order.PriceCents != 19 {
			t.Fatalf("unexpected event: %+v", evtJSON)
		}
		if _, exists := evtJSON.RawPayload["unknown_field"]; exists {
			t.Fatal("expected non-spec key 'unknown_field' to be filtered out of RawPayload")
		}

		// Generated fallback event ID when no id is present
		noIDBytes := []byte(`{"product_name": "No ID Tool"}`)
		evtNoID, err := c.ParseWebhookPayload(noIDBytes, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(evtNoID.EventID, "evt_") {
			t.Fatalf("expected generated evt_ prefix, got %s", evtNoID.EventID)
		}

		// Invalid urlencoded query
		_, err = c.ParseWebhookPayload([]byte("%ZZ%invalid"), nil, "")
		if !errors.Is(err, integrations.ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload on unparsable query, got %v", err)
		}
	})

	t.Run("gumroad_ping_test_event", func(t *testing.T) {
		// Gumroad "Send test ping to URL" sends test=true with previous transaction data
		form := url.Values{}
		form.Set("test", "true")
		form.Set("sale_id", "test_sale_123")
		form.Set("seller_id", "usr_seller_abc")
		form.Set("product_id", "prod_xyz==")
		form.Set("product_name", "Test Ping Product")
		form.Set("email", "tester@example.com")
		form.Set("price", "1000")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "test_sale_123" {
			t.Fatalf("expected EventID test_sale_123, got %s", evt.EventID)
		}
		if evt.RawPayload["test"] != "true" {
			t.Fatalf("expected test flag true in RawPayload, got %v", evt.RawPayload["test"])
		}
		if evt.Order == nil || evt.Order.RawData["test"] != "true" {
			t.Fatalf("expected test flag true in Order.RawData, got %v", evt.Order.RawData["test"])
		}
	})

	t.Run("product_identifier_fallbacks", func(t *testing.T) {
		// 1. Fallback to short_product_id
		form1 := url.Values{"sale_id": {"s1"}, "short_product_id": {"short_prod_123"}}
		evt1, err := c.ParseWebhookPayload([]byte(form1.Encode()), nil, "")
		if err != nil || evt1.ProductID != "short_prod_123" || evt1.Order.ProductID != "short_prod_123" {
			t.Fatalf("expected short_product_id fallback 'short_prod_123', got %s, err: %v", evt1.ProductID, err)
		}

		// 2. Fallback to product_permalink
		form2 := url.Values{"sale_id": {"s2"}, "product_permalink": {"https://gumroad.com/l/course-2"}}
		evt2, err := c.ParseWebhookPayload([]byte(form2.Encode()), nil, "")
		if err != nil || evt2.ProductID != "https://gumroad.com/l/course-2" {
			t.Fatalf("expected product_permalink fallback, got %s, err: %v", evt2.ProductID, err)
		}

		// 3. Base64 product_id with trailing ==
		form3 := url.Values{"sale_id": {"s3"}, "product_id": {"kL3yQ=="}}
		evt3, err := c.ParseWebhookPayload([]byte(form3.Encode()), nil, "")
		if err != nil || evt3.ProductID != "kL3yQ==" {
			t.Fatalf("expected base64 product_id 'kL3yQ==', got %s, err: %v", evt3.ProductID, err)
		}

		// 4. Non-spec permalink field is ignored and not retained
		form4 := url.Values{"sale_id": {"s4"}, "permalink": {"custom_link"}}
		evt4, err := c.ParseWebhookPayload([]byte(form4.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt4.ProductID != "" {
			t.Fatalf("expected non-spec permalink to not set ProductID, got %s", evt4.ProductID)
		}
		if _, exists := evt4.RawPayload["permalink"]; exists {
			t.Fatal("expected non-spec 'permalink' to be filtered out of RawPayload")
		}
	})

	t.Run("customer_id_and_ip_country_handling", func(t *testing.T) {
		// With purchaser_id and ip_country; non-spec ip_address must not be retained
		form1 := url.Values{
			"sale_id":      {"s_cust_1"},
			"email":        {"buyer@example.com"},
			"purchaser_id": {"usr_buyer_999"},
			"ip_country":   {"DE"},
			"ip_address":   {"192.0.2.1"},
		}
		evt1, err := c.ParseWebhookPayload([]byte(form1.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt1.Order.Customer.ID != "usr_buyer_999" {
			t.Fatalf("expected Customer.ID usr_buyer_999, got %s", evt1.Order.Customer.ID)
		}
		if evt1.Order.Customer.Email != "buyer@example.com" {
			t.Fatalf("expected Customer.Email buyer@example.com, got %s", evt1.Order.Customer.Email)
		}
		if evt1.Order.Customer.Country != "DE" {
			t.Fatalf("expected Customer.Country DE, got %s", evt1.Order.Customer.Country)
		}
		// Gumroad Ping does not send IP address, so IPAddress must be empty
		if evt1.Order.Customer.IPAddress != "" {
			t.Fatalf("expected Customer.IPAddress to be empty, got %s", evt1.Order.Customer.IPAddress)
		}
		// Non-spec ip_address must be filtered out
		if _, exists := evt1.RawPayload["ip_address"]; exists {
			t.Fatal("expected non-spec ip_address to be filtered from RawPayload")
		}

		// Fallback to email when purchaser_id is absent; non-spec "ip" must not be retained
		form2 := url.Values{
			"sale_id": {"s_cust_2"},
			"email":   {"solo@example.com"},
			"ip":      {"198.51.100.42"},
		}
		evt2, err := c.ParseWebhookPayload([]byte(form2.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt2.Order.Customer.ID != "solo@example.com" {
			t.Fatalf("expected Customer.ID fallback to email, got %s", evt2.Order.Customer.ID)
		}
		if evt2.Order.Customer.IPAddress != "" {
			t.Fatalf("expected Customer.IPAddress to be empty, got %s", evt2.Order.Customer.IPAddress)
		}
		if _, exists := evt2.RawPayload["ip"]; exists {
			t.Fatal("expected non-spec ip to be filtered from RawPayload")
		}
	})

	t.Run("custom_fields_and_url_parameters", func(t *testing.T) {
		// URL-encoded form data with custom_fields[...] and url_params[...]
		form := url.Values{}
		form.Set("sale_id", "s_cf_1")
		form.Set("custom_fields[Discord ID]", "Dev#1337")
		form.Set("custom_fields[Organization]", "Acme Inc")
		form.Set("url_params[utm_source]", "twitter")
		form.Set("url_params[affiliate]", "partner_42")
		form.Set("offer_code", "BLACKFRIDAY")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.Order.CustomFields == nil {
			t.Fatal("expected non-nil CustomFields")
		}
		if evt.Order.CustomFields["Discord ID"] != "Dev#1337" {
			t.Fatalf("expected Discord ID Dev#1337, got %s", evt.Order.CustomFields["Discord ID"])
		}
		if evt.Order.CustomFields["Organization"] != "Acme Inc" {
			t.Fatalf("expected Organization Acme Inc, got %s", evt.Order.CustomFields["Organization"])
		}
		if evt.Order.CustomFields["utm_source"] != "twitter" {
			t.Fatalf("expected utm_source twitter, got %s", evt.Order.CustomFields["utm_source"])
		}
		if evt.Order.CustomFields["affiliate"] != "partner_42" {
			t.Fatalf("expected affiliate partner_42, got %s", evt.Order.CustomFields["affiliate"])
		}
		if evt.Order.CustomFields["offer_code"] != "BLACKFRIDAY" {
			t.Fatalf("expected offer_code BLACKFRIDAY, got %s", evt.Order.CustomFields["offer_code"])
		}

		// JSON nested maps for custom_fields and url_params, offer_code parameter
		jsonBody := []byte(`{
			"sale_id": "s_cf_2",
			"custom_fields": {
				"GitHub User": "octocat",
				"Licensee": "Alice"
			},
			"url_params": {
				"campaign": "winter_sale"
			},
			"offer_code": "HOLIDAY10",
			"discount_code": "OLDDISCOUNT"
		}`)
		evtJSON, err := c.ParseWebhookPayload(jsonBody, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtJSON.Order.CustomFields["GitHub User"] != "octocat" {
			t.Fatalf("expected GitHub User octocat, got %s", evtJSON.Order.CustomFields["GitHub User"])
		}
		if evtJSON.Order.CustomFields["Licensee"] != "Alice" {
			t.Fatalf("expected Licensee Alice, got %s", evtJSON.Order.CustomFields["Licensee"])
		}
		if evtJSON.Order.CustomFields["campaign"] != "winter_sale" {
			t.Fatalf("expected campaign winter_sale, got %s", evtJSON.Order.CustomFields["campaign"])
		}
		if evtJSON.Order.CustomFields["offer_code"] != "HOLIDAY10" {
			t.Fatalf("expected offer_code HOLIDAY10, got %s", evtJSON.Order.CustomFields["offer_code"])
		}
		if _, exists := evtJSON.RawPayload["discount_code"]; exists {
			t.Fatal("expected non-spec discount_code to be filtered out of RawPayload")
		}
	})

	t.Run("complex_variant_structures", func(t *testing.T) {
		// Form-encoded indexed variants: variants[Plan]=Pro&variants[Seats]=5
		form := url.Values{}
		form.Set("sale_id", "s_var_1")
		form.Set("variants[Plan]", "Pro")
		form.Set("variants[Seats]", "5")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(evt.Order.VariantName, "Plan: Pro") || !strings.Contains(evt.Order.VariantName, "Seats: 5") {
			t.Fatalf("expected VariantName to contain Plan: Pro and Seats: 5, got %s", evt.Order.VariantName)
		}

		// JSON map variants
		jsonMap := []byte(`{
			"sale_id": "s_var_2",
			"variants": {
				"Color": "Dark Mode",
				"Size": "Large"
			}
		}`)
		evtMap, err := c.ParseWebhookPayload(jsonMap, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(evtMap.Order.VariantName, "Color: Dark Mode") {
			t.Fatalf("expected VariantName to contain Color: Dark Mode, got %s", evtMap.Order.VariantName)
		}

		// JSON slice variants
		jsonSlice := []byte(`{
			"sale_id": "s_var_3",
			"variants": ["Tier: Enterprise", "Location: US-East"]
		}`)
		evtSlice, err := c.ParseWebhookPayload(jsonSlice, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(evtSlice.Order.VariantName, "Tier: Enterprise") {
			t.Fatalf("expected VariantName to contain Tier: Enterprise, got %s", evtSlice.Order.VariantName)
		}
	})

	t.Run("financial_edge_cases_and_currency_symbols", func(t *testing.T) {
		tests := []struct {
			name          string
			form          url.Values
			expectedPrice int
			expectedRef   int
		}{
			{
				name: "dollar sign in price and non-spec tax/discount ignored",
				form: url.Values{
					"sale_id":        {"f1"},
					"price":          {"$49.99"},
					"tax_cents":      {"350"},
					"discount_cents": {"500"},
				},
				expectedPrice: 49,
				expectedRef:   0,
			},
			{
				name: "euro sign in price and non-spec tax ignored",
				form: url.Values{
					"sale_id": {"f2"},
					"price":   {"€2900"},
					"tax":     {"250"},
				},
				expectedPrice: 2900,
				expectedRef:   0,
			},
			{
				name: "pound sign and refunded=true defaults to full price",
				form: url.Values{
					"sale_id":  {"f3"},
					"price":    {"£15"},
					"refunded": {"true"},
				},
				expectedPrice: 15,
				expectedRef:   15,
			},
			{
				name: "zero price free product",
				form: url.Values{
					"sale_id": {"f4"},
					"price":   {"0"},
				},
				expectedPrice: 0,
				expectedRef:   0,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				evt, err := c.ParseWebhookPayload([]byte(tt.form.Encode()), nil, "")
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if evt.Order.PriceCents != tt.expectedPrice {
					t.Fatalf("expected price %d, got %d", tt.expectedPrice, evt.Order.PriceCents)
				}
				if evt.Order.TaxCents != 0 {
					t.Fatalf("expected tax 0 (not in spec), got %d", evt.Order.TaxCents)
				}
				if evt.Order.DiscountCents != 0 {
					t.Fatalf("expected discount 0 (not in spec), got %d", evt.Order.DiscountCents)
				}
				if evt.Order.RefundedAmountCents != tt.expectedRef {
					t.Fatalf("expected refund %d, got %d", tt.expectedRef, evt.Order.RefundedAmountCents)
				}
				if _, exists := evt.RawPayload["tax_cents"]; exists {
					t.Fatal("expected tax_cents to be filtered out of RawPayload")
				}
				if _, exists := evt.RawPayload["discount_cents"]; exists {
					t.Fatal("expected discount_cents to be filtered out of RawPayload")
				}
			})
		}
	})

	t.Run("subscription_extended_lifecycle_statuses", func(t *testing.T) {
		// 1. Subscription cancellation via resource_name
		formCanc := url.Values{
			"sale_id":         {"s_sub_canc"},
			"subscription_id": {"sub_canc_99"},
			"resource_name":   {"cancellation"},
		}
		evtCanc, err := c.ParseWebhookPayload([]byte(formCanc.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtCanc.EventType != integrations.EventTypeSubscriptionCancelled {
			t.Fatalf("expected subscription.cancelled, got %s", evtCanc.EventType)
		}
		if evtCanc.Subscription == nil || evtCanc.Subscription.Status != integrations.SubscriptionStatusCancelled {
			t.Fatalf("expected SubscriptionStatusCancelled, got %+v", evtCanc.Subscription)
		}

		// 2. Subscription ended -> expired
		formEnd := url.Values{
			"sale_id":         {"s_sub_end"},
			"subscription_id": {"sub_end_99"},
			"resource_name":   {"subscription_ended"},
		}
		evtEnd, err := c.ParseWebhookPayload([]byte(formEnd.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtEnd.EventType != integrations.EventTypeSubscriptionExpired {
			t.Fatalf("expected subscription.expired, got %s", evtEnd.EventType)
		}
		if evtEnd.Subscription.Status != integrations.SubscriptionStatusExpired {
			t.Fatalf("expected SubscriptionStatusExpired, got %s", evtEnd.Subscription.Status)
		}

		// 3. Subscription paused via resource_name
		formPause := url.Values{
			"sale_id":         {"s_sub_pause"},
			"subscription_id": {"sub_pause_99"},
			"resource_name":   {"subscription_paused"},
		}
		evtPause, err := c.ParseWebhookPayload([]byte(formPause.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtPause.EventType != integrations.EventTypeSubscriptionPaused {
			t.Fatalf("expected subscription.paused, got %s", evtPause.EventType)
		}
		if evtPause.Subscription.Status != integrations.SubscriptionStatusPaused {
			t.Fatalf("expected SubscriptionStatusPaused, got %s", evtPause.Subscription.Status)
		}

		// 4. Order cancelled via resource_name
		formOrdCanc := url.Values{
			"sale_id":       {"s_ord_canc"},
			"resource_name": {"order_cancelled"},
		}
		evtOrdCanc, err := c.ParseWebhookPayload([]byte(formOrdCanc.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtOrdCanc.EventType != integrations.EventTypeOrderCancelled {
			t.Fatalf("expected order.cancelled, got %s", evtOrdCanc.EventType)
		}
	})

	t.Run("timestamp_formats_resilience", func(t *testing.T) {
		// RFC3339 with timezone offset in sale_timestamp
		form1 := url.Values{"sale_id": {"ts1"}, "sale_timestamp": {"2026-08-15T14:30:00+02:00"}}
		evt1, err := c.ParseWebhookPayload([]byte(form1.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt1.OccurredAt.Hour() != 12 { // 14:30+02:00 = 12:30 UTC
			t.Fatalf("expected UTC hour 12, got %d", evt1.OccurredAt.Hour())
		}

		// Space-separated UTC timestamp in sale_timestamp
		form2 := url.Values{"sale_id": {"ts2"}, "sale_timestamp": {"2026-08-15 12:30:00 UTC"}}
		evt2, err := c.ParseWebhookPayload([]byte(form2.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt2.OccurredAt.Year() != 2026 || evt2.OccurredAt.Month() != 8 {
			t.Fatalf("expected August 2026, got %v", evt2.OccurredAt)
		}

		// Unix timestamp string in sale_timestamp
		form3 := url.Values{"sale_id": {"ts3"}, "sale_timestamp": {"1778100000"}}
		evt3, err := c.ParseWebhookPayload([]byte(form3.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt3.OccurredAt.Unix() != 1778100000 {
			t.Fatalf("expected unix timestamp 1778100000, got %d", evt3.OccurredAt.Unix())
		}

		// Numeric Unix timestamp in JSON sale_timestamp
		jsonTS := []byte(`{"sale_id": "ts4", "sale_timestamp": 1778100000}`)
		evt4, err := c.ParseWebhookPayload(jsonTS, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt4.OccurredAt.Unix() != 1778100000 {
			t.Fatalf("expected unix timestamp 1778100000 in json, got %d", evt4.OccurredAt.Unix())
		}

		// Millisecond Unix timestamp in JSON sale_timestamp
		jsonMS := []byte(`{"sale_id": "ts5", "sale_timestamp": 1778100000000}`)
		evt5, err := c.ParseWebhookPayload(jsonMS, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt5.OccurredAt.Unix() != 1778100000 {
			t.Fatalf("expected ms unix timestamp converted to seconds, got %d", evt5.OccurredAt.Unix())
		}

		// Non-spec created_at is filtered out
		jsonNonSpec := []byte(`{"sale_id": "ts6", "created_at": "2026-08-15T12:00:00Z"}`)
		evt6, err := c.ParseWebhookPayload(jsonNonSpec, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, exists := evt6.RawPayload["created_at"]; exists {
			t.Fatal("expected non-spec created_at to be filtered out of RawPayload")
		}
	})

	t.Run("secret_verification_edge_cases", func(t *testing.T) {
		secret := "super_secret_webhook_key_456"
		form := url.Values{"sale_id": {"sale_sec_edge"}}
		body := []byte(form.Encode())

		// 1. HMAC signature with "sha256=" prefix
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		sigHex := hex.EncodeToString(mac.Sum(nil))

		reqPrefixed := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		reqPrefixed.Header.Set("X-Gumroad-Signature", "sha256="+sigHex)
		evt1, err := c.ParseWebhook(reqPrefixed, secret)
		if err != nil || evt1 == nil {
			t.Fatalf("expected sha256= prefixed signature to pass, err: %v", err)
		}

		// 2. HMAC signature in uppercase
		reqUpper := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		reqUpper.Header.Set("X-Gumroad-Signature", strings.ToUpper(sigHex))
		evt2, err := c.ParseWebhook(reqUpper, secret)
		if err != nil || evt2 == nil {
			t.Fatalf("expected uppercase signature to pass, err: %v", err)
		}

		// 3. Secret inside JSON payload (verified then dropped from RawPayload)
		jsonWithSecret := []byte(`{"sale_id": "s_sec_json", "passcode": "` + secret + `"}`)
		evtJSON, err := c.ParseWebhookPayload(jsonWithSecret, nil, secret)
		if err != nil || evtJSON == nil {
			t.Fatalf("expected passcode inside JSON body to pass, err: %v", err)
		}
		if _, exists := evtJSON.RawPayload["passcode"]; exists {
			t.Fatal("expected passcode to not be retained in RawPayload")
		}

		// 4. Token inside JSON payload (verified then dropped from RawPayload)
		jsonWithToken := []byte(`{"sale_id": "s_sec_token", "token": "` + secret + `"}`)
		evtToken, err := c.ParseWebhookPayload(jsonWithToken, nil, secret)
		if err != nil || evtToken == nil {
			t.Fatalf("expected token inside JSON body to pass, err: %v", err)
		}
		if _, exists := evtToken.RawPayload["token"]; exists {
			t.Fatal("expected token to not be retained in RawPayload")
		}

		// 5. Secret configured with surrounding whitespace
		reqWhitespaceSec := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(body))
		reqWhitespaceSec.Header.Set("X-Gumroad-Secret", secret)
		evtSpace, err := c.ParseWebhook(reqWhitespaceSec, "  "+secret+"  ")
		if err != nil || evtSpace == nil {
			t.Fatalf("expected secret with trimmed whitespace to pass, err: %v", err)
		}

		// 6. Tampered payload with valid-looking signature fails
		reqTampered := httptest.NewRequest(http.MethodPost, "/webhook", strings.NewReader("tampered=true"))
		reqTampered.Header.Set("X-Gumroad-Signature", sigHex)
		_, err = c.ParseWebhook(reqTampered, secret)
		if !errors.Is(err, integrations.ErrWebhookVerificationFailed) {
			t.Fatalf("expected ErrWebhookVerificationFailed for tampered payload, got %v", err)
		}
	})

	t.Run("utf8_bom_and_boundary_payloads", func(t *testing.T) {
		// UTF-8 BOM prefix on URL-encoded data
		bomURLEncoded := append([]byte("\xef\xbb\xbf"), []byte("sale_id=sale_bom_form&product_name=BOM+Tool")...)
		evtBOMForm, err := c.ParseWebhookPayload(bomURLEncoded, nil, "")
		if err != nil {
			t.Fatalf("unexpected error with BOM urlencoded: %v", err)
		}
		if evtBOMForm.EventID != "sale_bom_form" || evtBOMForm.Order.ProductName != "BOM Tool" {
			t.Fatalf("unexpected event: %+v", evtBOMForm)
		}

		// UTF-8 BOM prefix on JSON data
		bomJSON := append([]byte("\xef\xbb\xbf"), []byte(`{"sale_id": "sale_bom_json", "price": 1500}`)...)
		evtBOMJSON, err := c.ParseWebhookPayload(bomJSON, nil, "")
		if err != nil {
			t.Fatalf("unexpected error with BOM JSON: %v", err)
		}
		if evtBOMJSON.EventID != "sale_bom_json" || evtBOMJSON.Order.PriceCents != 1500 {
			t.Fatalf("unexpected event: %+v", evtBOMJSON)
		}

		// Boolean truthy representations ("yes", "1", "t") on spec boolean refunded
		formBool := url.Values{
			"sale_id":  {"s_bool"},
			"refunded": {"yes"},
		}
		evtBool, err := c.ParseWebhookPayload([]byte(formBool.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !evtBool.Order.Refunded {
			t.Fatalf("expected truthy booleans, got refunded=%v", evtBool.Order.Refunded)
		}

		// Null values in JSON handled gracefully
		nullJSON := []byte(`{"sale_id": null, "order_number": "ord_from_null", "email": null, "price": null}`)
		evtNull, err := c.ParseWebhookPayload(nullJSON, nil, "")
		if err != nil {
			t.Fatalf("unexpected error on null json: %v", err)
		}
		if evtNull.EventID != "ord_from_null" {
			t.Fatalf("expected EventID ord_from_null, got %s", evtNull.EventID)
		}
	})

	t.Run("strict_non_spec_field_exclusion", func(t *testing.T) {
		form := url.Values{}
		// Official fields
		form.Set("sale_id", "sale_strict_1")
		form.Set("email", "strict@example.com")
		form.Set("ip_country", "US")
		form.Set("price", "4200")
		form.Set("custom_fields[user_name]", "alice")
		// Non-spec fields that must NEVER be retained
		form.Set("ip_address", "192.168.1.1")
		form.Set("ip", "10.0.0.1")
		form.Set("tax_cents", "420")
		form.Set("tax", "420")
		form.Set("discount_cents", "200")
		form.Set("discount_code", "SAVE")
		form.Set("created_at", "2026-01-01T00:00:00Z")
		form.Set("order_date", "2026-01-01T00:00:00Z")
		form.Set("timestamp", "1700000000")
		form.Set("secret", "topsecret")
		form.Set("token", "mytoken")
		form.Set("passcode", "1234")
		form.Set("key", "secretkey")
		form.Set("order_id", "order_123")
		form.Set("id", "id_999")
		form.Set("permalink", "custom-link")
		form.Set("short_url", "https://gum.co/short")
		form.Set("random_injected_field", "malicious_or_noise")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Ensure official fields are retained
		if evt.RawPayload["sale_id"] != "sale_strict_1" {
			t.Fatal("expected sale_id to be retained")
		}
		if evt.RawPayload["email"] != "strict@example.com" {
			t.Fatal("expected email to be retained")
		}
		if evt.RawPayload["ip_country"] != "US" {
			t.Fatal("expected ip_country to be retained")
		}
		if evt.RawPayload["price"] != "4200" {
			t.Fatal("expected price to be retained")
		}
		if evt.RawPayload["custom_fields[user_name]"] != "alice" {
			t.Fatal("expected custom_fields[user_name] to be retained")
		}

		// Ensure none of the non-spec fields are retained
		forbiddenKeys := []string{
			"ip_address", "ip", "tax_cents", "tax", "discount_cents", "discount_code",
			"created_at", "order_date", "timestamp", "secret", "token", "passcode", "key",
			"order_id", "id", "permalink", "short_url", "random_injected_field",
		}
		for _, key := range forbiddenKeys {
			if _, exists := evt.RawPayload[key]; exists {
				t.Fatalf("forbidden non-spec key %q was retained in RawPayload", key)
			}
			if _, exists := evt.Order.RawData[key]; exists {
				t.Fatalf("forbidden non-spec key %q was retained in Order.RawData", key)
			}
		}

		// Verify model field guarantees
		if evt.Order.Customer.IPAddress != "" {
			t.Fatalf("Customer.IPAddress must be empty, got %q", evt.Order.Customer.IPAddress)
		}
		if evt.Order.TaxCents != 0 {
			t.Fatalf("Order.TaxCents must be 0, got %d", evt.Order.TaxCents)
		}
		if evt.Order.DiscountCents != 0 {
			t.Fatalf("Order.DiscountCents must be 0, got %d", evt.Order.DiscountCents)
		}
	})

	t.Run("gumroad_ping_official_spec_dictionary_strings", func(t *testing.T) {
		// Tests the EXACT dictionary string examples documented at https://gumroad.com/ping:
		// variants: "{'size' : 'large', 'color' : 'red'}"
		// custom_fields: "{'name' : 'john smith', 'spouse name' : 'jane smith'}"
		// url_params: "{'source_url' : 'https%3A%2F%2Fgumroad.com%2Fwidgets', 'campaignid' : 'c123', 'userid' : '456', 'version' : '1.4.5'}"
		form := url.Values{}
		form.Set("sale_id", "sale_ping_official_1")
		form.Set("product_name", "Official Ping Spec Product")
		form.Set("email", "buyer@example.com")
		form.Set("price", "4200")
		form.Set("variants", "{'size' : 'large', 'color' : 'red'}")
		form.Set("custom_fields", "{'name' : 'john smith', 'spouse name' : 'jane smith'}")
		form.Set("url_params", "{'source_url' : 'https%3A%2F%2Fgumroad.com%2Fwidgets', 'campaignid' : 'c123', 'userid' : '456', 'version' : '1.4.5'}")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error parsing official spec ping: %v", err)
		}

		// Verify variants dictionary parsing
		if !strings.Contains(evt.Order.VariantName, "size: large") || !strings.Contains(evt.Order.VariantName, "color: red") {
			t.Fatalf("expected parsed variant string, got: %s", evt.Order.VariantName)
		}

		// Verify custom_fields dictionary parsing
		if evt.Order.CustomFields["name"] != "john smith" {
			t.Fatalf("expected custom field 'name' to be 'john smith', got: %s", evt.Order.CustomFields["name"])
		}
		if evt.Order.CustomFields["spouse name"] != "jane smith" {
			t.Fatalf("expected custom field 'spouse name' to be 'jane smith', got: %s", evt.Order.CustomFields["spouse name"])
		}

		// Verify url_params dictionary parsing
		if evt.Order.CustomFields["source_url"] != "https%3A%2F%2Fgumroad.com%2Fwidgets" {
			t.Fatalf("expected url_param 'source_url', got: %s", evt.Order.CustomFields["source_url"])
		}
		if evt.Order.CustomFields["campaignid"] != "c123" {
			t.Fatalf("expected url_param 'campaignid', got: %s", evt.Order.CustomFields["campaignid"])
		}
		if evt.Order.CustomFields["userid"] != "456" {
			t.Fatalf("expected url_param 'userid', got: %s", evt.Order.CustomFields["userid"])
		}
		if evt.Order.CustomFields["version"] != "1.4.5" {
			t.Fatalf("expected url_param 'version', got: %s", evt.Order.CustomFields["version"])
		}

		// Edge case: unquoted scanner fallback, empty dictionary, and non-dict string
		formFallback := url.Values{}
		formFallback.Set("sale_id", "sale_dict_fallback")
		formFallback.Set("custom_fields", "{theme: retro, mode: compact}")
		formFallback.Set("variants", "{}")
		formFallback.Set("url_params", "not a dict")
		evtFallback, err := c.ParseWebhookPayload([]byte(formFallback.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtFallback.Order.CustomFields["theme"] != "retro" || evtFallback.Order.CustomFields["mode"] != "compact" {
			t.Fatalf("expected scanner fallback to parse, got: %+v", evtFallback.Order.CustomFields)
		}
	})

	t.Run("gumroad_ping_short_product_id_resolution", func(t *testing.T) {
		// Gumroad table specifies: short_product_id: "Unique identifier for the product"
		form := url.Values{}
		form.Set("sale_id", "sale_sp_1")
		form.Set("short_product_id", "sProd99")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.ProductID != "sProd99" || evt.Order.ProductID != "sProd99" {
			t.Fatalf("expected ProductID sProd99 from short_product_id, got %s", evt.ProductID)
		}
	})

	t.Run("gumroad_ping_deduplication_sale_vs_refund", func(t *testing.T) {
		// Gumroad spec explicitly specifies:
		// "Delivery is at least once. The same ping can arrive more than once, so deduplicate.
		// Ordering is not guaranteed. A refund ping can reach you before the sale ping it refers to.
		// Deduplicate on sale_id together with resource_name, not on sale_id alone.
		// A refund carries the same sale_id as the sale it reverses."
		saleID := "sale_tx_888"

		// 1. Initial Sale Ping
		saleForm := url.Values{
			"sale_id":       {saleID},
			"resource_name": {"sale"},
			"price":         {"2500"},
			"email":         {"buyer@example.com"},
		}
		saleEvt, err := c.ParseWebhookPayload([]byte(saleForm.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 2. Refund Ping (carries the EXACT SAME sale_id per spec)
		refundForm := url.Values{
			"sale_id":       {saleID},
			"resource_name": {"refund"},
			"refunded":      {"true"},
			"email":         {"buyer@example.com"},
		}
		refundEvt, err := c.ParseWebhookPayload([]byte(refundForm.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both must retain the original sale_id in Order.ID
		if saleEvt.Order.ID != saleID || refundEvt.Order.ID != saleID {
			t.Fatalf("expected both events to track sale_id %s, got sale=%s, refund=%s", saleID, saleEvt.Order.ID, refundEvt.Order.ID)
		}

		// But their deduplication EventIDs must be distinct so consumers don't drop the refund
		if saleEvt.EventID != saleID {
			t.Fatalf("expected sale EventID to be %s, got %s", saleID, saleEvt.EventID)
		}
		if refundEvt.EventID != saleID+":refund" {
			t.Fatalf("expected refund EventID to be %s:refund, got %s", saleID, refundEvt.EventID)
		}
		if saleEvt.EventID == refundEvt.EventID {
			t.Fatal("sale and refund EventIDs must not collide to allow proper at-least-once deduplication")
		}
	})

	t.Run("gumroad_ping_extended_table_parameters", func(t *testing.T) {
		// Validates presence and retention of all table fields from the spec:
		// retry_count, is_preorder_authorization, is_recurring_charge, recurrence,
		// is_gift_receiver_purchase, gifter_email, gift_price, shipping_rate,
		// shipping_information, discover_fee_charged, can_contact, referrer,
		// gumroad_fee, card, affiliate, affiliate_credit_amount_cents, quantity
		form := url.Values{}
		form.Set("sale_id", "sale_full_table")
		form.Set("email", "recipient@example.com")
		form.Set("price", "5000")
		form.Set("recurrence", "monthly")
		form.Set("is_recurring_charge", "true")
		form.Set("is_preorder_authorization", "false")
		form.Set("retry_count", "2")
		form.Set("is_gift_receiver_purchase", "true")
		form.Set("gifter_email", "gifter@example.com")
		form.Set("gift_price", "5000")
		form.Set("shipping_rate", "750")
		form.Set("shipping_information", "{'address': '123 Market St', 'city': 'SF'}")
		form.Set("discover_fee_charged", "true")
		form.Set("can_contact", "true")
		form.Set("referrer", "https://partner.com")
		form.Set("gumroad_fee", "450")
		form.Set("card", "{'type': 'mastercard', 'last4': '5555'}")
		form.Set("affiliate", "affiliate@example.com")
		form.Set("affiliate_credit_amount_cents", "500")
		form.Set("quantity", "2")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify fields in RawPayload
		raw := evt.RawPayload
		if raw["retry_count"] != "2" {
			t.Fatalf("expected retry_count 2, got %v", raw["retry_count"])
		}
		if raw["recurrence"] != "monthly" {
			t.Fatalf("expected recurrence monthly, got %v", raw["recurrence"])
		}
		if raw["is_recurring_charge"] != "true" {
			t.Fatalf("expected is_recurring_charge true, got %v", raw["is_recurring_charge"])
		}
		if raw["is_preorder_authorization"] != "false" {
			t.Fatalf("expected is_preorder_authorization false, got %v", raw["is_preorder_authorization"])
		}
		if raw["is_gift_receiver_purchase"] != "true" {
			t.Fatalf("expected is_gift_receiver_purchase true, got %v", raw["is_gift_receiver_purchase"])
		}
		if raw["gifter_email"] != "gifter@example.com" {
			t.Fatalf("expected gifter_email gifter@example.com, got %v", raw["gifter_email"])
		}
		if raw["shipping_rate"] != "750" {
			t.Fatalf("expected shipping_rate 750, got %v", raw["shipping_rate"])
		}
		if raw["discover_fee_charged"] != "true" {
			t.Fatalf("expected discover_fee_charged true, got %v", raw["discover_fee_charged"])
		}
		if raw["gumroad_fee"] != "450" {
			t.Fatalf("expected gumroad_fee 450, got %v", raw["gumroad_fee"])
		}
		if raw["affiliate"] != "affiliate@example.com" {
			t.Fatalf("expected affiliate affiliate@example.com, got %v", raw["affiliate"])
		}
		if raw["affiliate_credit_amount_cents"] != "500" {
			t.Fatalf("expected affiliate_credit_amount_cents 500, got %v", raw["affiliate_credit_amount_cents"])
		}
		if raw["quantity"] != "2" {
			t.Fatalf("expected quantity 2, got %v", raw["quantity"])
		}
	})

	t.Run("gumroad_ping_absent_fields_and_spec_defaults", func(t *testing.T) {
		// Gumroad Ping spec explicitly only includes ip_country (country of the buyer's IP address),
		// and NOT the buyer's IP address (ip_address / ip).
		// Also, prices are defined in USD cents ("The price paid, in USD cents"), omitting currency.
		// When refunded=true arrives without refunded_amount_cents, full price is assumed refunded.
		form := url.Values{}
		form.Set("sale_id", "sale_spec_absent_test")
		form.Set("email", "buyer@example.de")
		form.Set("ip_country", "DE")
		form.Set("price", "3500")
		form.Set("refunded", "true")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// 1. IP country is populated, but IP address is empty (not sent by Gumroad Ping)
		if evt.Order.Customer.Country != "DE" {
			t.Fatalf("expected Customer.Country DE, got %s", evt.Order.Customer.Country)
		}
		if evt.Order.Customer.IPAddress != "" {
			t.Fatalf("expected Customer.IPAddress to be empty, got %s", evt.Order.Customer.IPAddress)
		}

		// 2. Currency defaults to "usd" per spec ("The price paid, in USD cents")
		if evt.Order.Currency != "usd" {
			t.Fatalf("expected Currency to default to usd, got %s", evt.Order.Currency)
		}

		// 3. Refunded amount defaults to full price when refunded_amount_cents is absent in ping
		if !evt.Order.Refunded {
			t.Fatal("expected Order.Refunded to be true")
		}
		if evt.Order.RefundedAmountCents != 3500 {
			t.Fatalf("expected RefundedAmountCents to default to full price 3500, got %d", evt.Order.RefundedAmountCents)
		}
	})
}

type failingRoundTripper struct{}

func (f *failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("simulated network failure")
}

func TestDoRequest_EdgeCases(t *testing.T) {
	t.Run("nil context handled gracefully", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"success": true, "user": {"id": "u1"}}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		// Passing nil context explicitly to test fallback to context.Background()
		var nilCtx context.Context
		_, err := c.GetUser(nilCtx, "token") //nolint:staticcheck // intentionally testing nil context fallback
		if err != nil {
			t.Fatalf("expected nil context to be handled safely, got %v", err)
		}
	})

	t.Run("network error propagation", func(t *testing.T) {
		c := New(WithHTTPClient(&http.Client{Transport: &failingRoundTripper{}}))
		_, err := c.GetUser(context.Background(), "token")
		if err == nil || !strings.Contains(err.Error(), "simulated network failure") {
			t.Fatalf("expected network failure, got %v", err)
		}
	})

	t.Run("api error using error field", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"success": false, "error": "custom error message"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.GetUser(context.Background(), "token")
		if err == nil || !strings.Contains(err.Error(), "custom error message") {
			t.Fatalf("expected custom error message in API error, got %v", err)
		}
	})

	t.Run("verify license upstream 500 error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"success": false, "message": "internal error"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.VerifyLicense(context.Background(), integrations.LicenseVerificationRequest{
			LicenseKey: "KEY-123",
			ProductID:  "prod_1",
		})
		if err == nil {
			t.Fatal("expected 500 API error")
		}
	})

	t.Run("create webhook subscription malformed response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.CreateWebhookSubscription(context.Background(), "token", integrations.CreateWebhookSubscriptionRequest{
			TargetURL: "https://example.com/hook",
		})
		if err == nil {
			t.Fatal("expected malformed json error")
		}
	})

	t.Run("list webhook subscriptions malformed response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		_, err := c.ListWebhookSubscriptions(context.Background(), "token")
		if err == nil {
			t.Fatal("expected malformed json error")
		}
	})

	t.Run("delete webhook subscription upstream error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success": false, "message": "Subscription not found"}`))
		}))
		defer ts.Close()

		c := New(WithBaseURL(ts.URL))
		err := c.DeleteWebhookSubscription(context.Background(), "token", "sub_404")
		if !errors.Is(err, integrations.ErrNotFound) {
			t.Fatalf("expected ErrNotFound, got %v", err)
		}
	})
}
