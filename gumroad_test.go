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
				params:   map[string]string{"sale_id": "s3", "disputed": "true"},
				expected: integrations.EventTypeOrderDisputed,
			},
			{
				name:     "cancellation",
				params:   map[string]string{"sale_id": "s4", "subscription_cancelled_at": "2026-01-01T00:00:00Z"},
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
		// Multi-value query param and order_date parsing
		form := url.Values{}
		form.Add("multi", "val1")
		form.Add("multi", "val2")
		form.Set("order_number", "ord_999")
		form.Set("order_date", "2026-06-01T15:00:00Z")
		form.Set("price", "49.99")
		form.Set("variant", "Single Seat")

		evt, err := c.ParseWebhookPayload([]byte(form.Encode()), nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evt.EventID != "ord_999" || evt.Order.VariantName != "Single Seat" || evt.Order.PriceCents != 49 {
			t.Fatalf("unexpected event: %+v", evt)
		}

		// Fallback to "id" field and float numeric price in JSON
		jsonBytes := []byte(`{"id": "id_123", "price": 19.99}`)
		evtJSON, err := c.ParseWebhookPayload(jsonBytes, nil, "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if evtJSON.EventID != "id_123" || evtJSON.Order.PriceCents != 19 {
			t.Fatalf("unexpected event: %+v", evtJSON)
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
