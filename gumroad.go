package gumroad

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	integrations "github.com/seatling/integrations-shared"
)

const (
	// DefaultBaseURL is the production Gumroad REST API base URL.
	DefaultBaseURL = "https://api.gumroad.com/v2"

	// DefaultTimeout is the standard timeout applied to outbound HTTP calls.
	DefaultTimeout = 30 * time.Second

	// MaxBodySize defines the maximum allowed response body size (2MB) to prevent memory exhaustion.
	MaxBodySize = 2 * 1024 * 1024
)

// Compile-time interface adherence assertions.
var (
	_ integrations.Integration    = (*Client)(nil)
	_ integrations.ProviderClient = (*Client)(nil)
	_ integrations.WebhookParser  = (*Client)(nil)
)

// Client is the production-ready Gumroad API client and webhook parser.
type Client struct {
	httpClient  integrations.HTTPClient
	baseURL     string
	accessToken string
}

// Option represents a functional configuration option for Client.
type Option func(*Client)

// WithHTTPClient configures a custom HTTPClient for outbound requests.
func WithHTTPClient(client integrations.HTTPClient) Option {
	return func(c *Client) {
		if client != nil {
			c.httpClient = client
		}
	}
}

// WithBaseURL overrides the default Gumroad API base URL (useful for integration testing and mocks).
func WithBaseURL(rawURL string) Option {
	return func(c *Client) {
		trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
		if trimmed != "" {
			c.baseURL = trimmed
		}
	}
}

// WithAccessToken sets an optional default access token for the client.
func WithAccessToken(token string) Option {
	return func(c *Client) {
		c.accessToken = strings.TrimSpace(token)
	}
}

// New constructs and returns a fully initialized Gumroad Client.
func New(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{
			Timeout: DefaultTimeout,
		},
		baseURL: DefaultBaseURL,
	}

	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}

	return c
}

// Provider returns integrations.ProviderGumroad.
func (c *Client) Provider() integrations.Provider {
	return integrations.ProviderGumroad
}

// resolveToken returns the provided token or falls back to the client default.
func (c *Client) resolveToken(token string) string {
	t := strings.TrimSpace(token)
	if t != "" {
		return t
	}
	return c.accessToken
}

// doRequest performs an HTTP request with context propagation, timeout boundaries, and error unmarshaling.
func (c *Client) doRequest(ctx context.Context, method, endpoint string, token string, body io.Reader, contentType string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	fullURL := c.baseURL + endpoint
	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "seatling-integrations-gumroad")

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("failed reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var errPayload struct {
			Success bool   `json:"success"`
			Message string `json:"message"`
			Error   string `json:"error"`
		}
		msg := http.StatusText(resp.StatusCode)
		if jsonErr := json.Unmarshal(respBody, &errPayload); jsonErr == nil {
			if errPayload.Message != "" {
				msg = errPayload.Message
			} else if errPayload.Error != "" {
				msg = errPayload.Error
			}
		}
		return respBody, integrations.NewAPIError(integrations.ProviderGumroad, resp.StatusCode, msg, string(respBody))
	}

	return respBody, nil
}

// GetUser retrieves the authenticated Gumroad merchant/creator account details.
func (c *Client) GetUser(ctx context.Context, accessToken string) (*integrations.User, error) {
	token := c.resolveToken(accessToken)
	if token == "" {
		return nil, integrations.ErrMissingAccessToken
	}

	respBytes, err := c.doRequest(ctx, http.MethodGet, "/user", token, nil, "")
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success bool `json:"success"`
		User    struct {
			ID                string `json:"id"`
			UserID            string `json:"user_id"`
			Name              string `json:"name"`
			Email             string `json:"email"`
			ProfileURL        string `json:"profile_url"`
			URL               string `json:"url"`
			Currency          string `json:"currency"`
			CustomDomain      string `json:"custom_domain"`
			SubscribedToEmail bool   `json:"subscribed_to_email"`
		} `json:"user"`
	}

	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse gumroad user response: %w", err)
	}

	var rawMap map[string]any
	_ = json.Unmarshal(respBytes, &rawMap)

	userID := envelope.User.UserID
	if userID == "" {
		userID = envelope.User.ID
	}

	profileURL := envelope.User.ProfileURL
	if profileURL == "" {
		profileURL = envelope.User.URL
	}

	user := &integrations.User{
		ID:                userID,
		Provider:          integrations.ProviderGumroad,
		Name:              envelope.User.Name,
		Email:             envelope.User.Email,
		ProfileURL:        profileURL,
		Currency:          envelope.User.Currency,
		CustomDomain:      envelope.User.CustomDomain,
		SubscribedToEmail: envelope.User.SubscribedToEmail,
		RawData:           rawMap,
	}

	return user, nil
}

// ListProducts retrieves the creator's product catalog.
func (c *Client) ListProducts(ctx context.Context, accessToken string) ([]integrations.Product, error) {
	token := c.resolveToken(accessToken)
	if token == "" {
		return nil, integrations.ErrMissingAccessToken
	}

	respBytes, err := c.doRequest(ctx, http.MethodGet, "/products", token, nil, "")
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success  bool             `json:"success"`
		Products []gumroadProduct `json:"products"`
	}

	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse gumroad products response: %w", err)
	}

	var rawEnvelope struct {
		Products []map[string]any `json:"products"`
	}
	_ = json.Unmarshal(respBytes, &rawEnvelope)

	products := make([]integrations.Product, 0, len(envelope.Products))
	for i, gp := range envelope.Products {
		var raw map[string]any
		if i < len(rawEnvelope.Products) {
			raw = rawEnvelope.Products[i]
		}
		products = append(products, mapGumroadProduct(gp, raw))
	}

	return products, nil
}

// GetProduct retrieves a single product by its ID or permalink.
func (c *Client) GetProduct(ctx context.Context, accessToken string, productID string) (*integrations.Product, error) {
	token := c.resolveToken(accessToken)
	if token == "" {
		return nil, integrations.ErrMissingAccessToken
	}

	cleanID := strings.TrimSpace(productID)
	if cleanID == "" {
		return nil, integrations.ErrInvalidParameter
	}

	respBytes, err := c.doRequest(ctx, http.MethodGet, "/products/"+url.PathEscape(cleanID), token, nil, "")
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success bool           `json:"success"`
		Product gumroadProduct `json:"product"`
	}

	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse gumroad product response: %w", err)
	}

	var rawEnvelope struct {
		Product map[string]any `json:"product"`
	}
	_ = json.Unmarshal(respBytes, &rawEnvelope)

	prod := mapGumroadProduct(envelope.Product, rawEnvelope.Product)
	return &prod, nil
}

// VerifyLicense verifies a license key directly with the Gumroad API.
func (c *Client) VerifyLicense(ctx context.Context, req integrations.LicenseVerificationRequest) (*integrations.LicenseVerificationResult, error) {
	licenseKey := strings.TrimSpace(req.LicenseKey)
	if licenseKey == "" {
		return nil, fmt.Errorf("%w: license_key is required", integrations.ErrInvalidParameter)
	}

	productID := strings.TrimSpace(req.ProductID)
	permalink := strings.TrimSpace(req.ProductPermalink)
	if productID == "" && permalink == "" {
		return nil, fmt.Errorf("%w: product_id or product_permalink is required", integrations.ErrInvalidParameter)
	}

	form := url.Values{}
	form.Set("license_key", licenseKey)
	if productID != "" {
		form.Set("product_id", productID)
	} else {
		form.Set("product_permalink", permalink)
	}

	if req.IncrementUsesCount != nil {
		form.Set("increment_uses_count", strconv.FormatBool(*req.IncrementUsesCount))
	}

	encodedBody := form.Encode()
	respBytes, err := c.doRequest(ctx, http.MethodPost, "/licenses/verify", "", strings.NewReader(encodedBody), "application/x-www-form-urlencoded")
	if err != nil {
		// Gumroad returns 404 if the license does not exist for the product.
		var apiErr *integrations.APIError
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "resource not found") {
			var errPayload struct {
				Success bool   `json:"success"`
				Message string `json:"message"`
			}
			msg := "license verification failed: license not found"
			if len(respBytes) > 0 && json.Unmarshal(respBytes, &errPayload) == nil && errPayload.Message != "" {
				msg = errPayload.Message
			}

			var rawMap map[string]any
			if len(respBytes) > 0 {
				_ = json.Unmarshal(respBytes, &rawMap)
			}

			return &integrations.LicenseVerificationResult{
				Valid:      false,
				Provider:   integrations.ProviderGumroad,
				LicenseKey: licenseKey,
				ProductID:  productID,
				Status:     "invalid",
				Message:    msg,
				RawData:    rawMap,
			}, nil
		}
		_ = apiErr
		return nil, err
	}

	var verifyResp struct {
		Success  bool            `json:"success"`
		Uses     int             `json:"uses"`
		Message  string          `json:"message"`
		Purchase gumroadPurchase `json:"purchase"`
	}

	if err := json.Unmarshal(respBytes, &verifyResp); err != nil {
		return nil, fmt.Errorf("failed to parse license verification response: %w", err)
	}

	var rawMap map[string]any
	_ = json.Unmarshal(respBytes, &rawMap)

	p := verifyResp.Purchase
	isCancelled := p.SubscriptionCancelledAt != nil && !p.SubscriptionCancelledAt.IsZero()
	isFailed := p.SubscriptionFailedAt != nil && !p.SubscriptionFailedAt.IsZero()

	isValid := verifyResp.Success && !p.Refunded && !p.Chargebacked && !p.Disputed && !isCancelled && !isFailed

	status := "active"
	switch {
	case !verifyResp.Success:
		status = "invalid"
	case p.Refunded:
		status = "refunded"
	case p.Chargebacked || p.Disputed:
		status = "disputed"
	case isCancelled:
		status = "cancelled"
	case isFailed:
		status = "failed"
	}

	resPID := p.ProductID
	if resPID == "" {
		resPID = productID
	}

	result := &integrations.LicenseVerificationResult{
		Valid:          isValid,
		Provider:       integrations.ProviderGumroad,
		LicenseKey:     licenseKey,
		ProductID:      resPID,
		UsesCount:      verifyResp.Uses,
		Status:         status,
		CustomerEmail:  p.Email,
		CustomerName:   p.FullName,
		OrderID:        p.SaleID,
		SubscriptionID: p.SubscriptionID,
		Message:        verifyResp.Message,
		RawData:        rawMap,
	}

	return result, nil
}

// CreateWebhookSubscription registers a webhook listener with Gumroad.
func (c *Client) CreateWebhookSubscription(ctx context.Context, accessToken string, req integrations.CreateWebhookSubscriptionRequest) (*integrations.WebhookSubscription, error) {
	token := c.resolveToken(accessToken)
	if token == "" {
		return nil, integrations.ErrMissingAccessToken
	}

	targetURL := strings.TrimSpace(req.TargetURL)
	if targetURL == "" {
		return nil, fmt.Errorf("%w: target_url is required", integrations.ErrInvalidParameter)
	}

	resourceName := "sale"
	if len(req.Events) > 0 && strings.TrimSpace(req.Events[0]) != "" {
		resourceName = strings.TrimSpace(req.Events[0])
	}

	form := url.Values{}
	form.Set("post_url", targetURL)
	form.Set("resource_name", resourceName)

	respBytes, err := c.doRequest(ctx, http.MethodPut, "/resource_subscriptions", token, strings.NewReader(form.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success              bool `json:"success"`
		ResourceSubscription struct {
			ID           string `json:"id"`
			ResourceName string `json:"resource_name"`
			PostURL      string `json:"post_url"`
		} `json:"resource_subscription"`
	}

	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse resource_subscription response: %w", err)
	}

	var rawMap map[string]any
	_ = json.Unmarshal(respBytes, &rawMap)

	now := time.Now().UTC()
	sub := &integrations.WebhookSubscription{
		ID:        envelope.ResourceSubscription.ID,
		Provider:  integrations.ProviderGumroad,
		TargetURL: envelope.ResourceSubscription.PostURL,
		Events:    []string{envelope.ResourceSubscription.ResourceName},
		CreatedAt: &now,
		RawData:   rawMap,
	}

	return sub, nil
}

// ListWebhookSubscriptions lists registered webhooks with Gumroad.
func (c *Client) ListWebhookSubscriptions(ctx context.Context, accessToken string) ([]integrations.WebhookSubscription, error) {
	token := c.resolveToken(accessToken)
	if token == "" {
		return nil, integrations.ErrMissingAccessToken
	}

	respBytes, err := c.doRequest(ctx, http.MethodGet, "/resource_subscriptions", token, nil, "")
	if err != nil {
		return nil, err
	}

	var envelope struct {
		Success               bool `json:"success"`
		ResourceSubscriptions []struct {
			ID           string `json:"id"`
			ResourceName string `json:"resource_name"`
			PostURL      string `json:"post_url"`
		} `json:"resource_subscriptions"`
	}

	if err := json.Unmarshal(respBytes, &envelope); err != nil {
		return nil, fmt.Errorf("failed to parse resource_subscriptions response: %w", err)
	}

	var rawEnvelope struct {
		ResourceSubscriptions []map[string]any `json:"resource_subscriptions"`
	}
	_ = json.Unmarshal(respBytes, &rawEnvelope)

	subs := make([]integrations.WebhookSubscription, 0, len(envelope.ResourceSubscriptions))
	for i, item := range envelope.ResourceSubscriptions {
		var raw map[string]any
		if i < len(rawEnvelope.ResourceSubscriptions) {
			raw = rawEnvelope.ResourceSubscriptions[i]
		}
		subs = append(subs, integrations.WebhookSubscription{
			ID:        item.ID,
			Provider:  integrations.ProviderGumroad,
			TargetURL: item.PostURL,
			Events:    []string{item.ResourceName},
			RawData:   raw,
		})
	}

	return subs, nil
}

// DeleteWebhookSubscription unregisters a webhook listener with Gumroad.
func (c *Client) DeleteWebhookSubscription(ctx context.Context, accessToken string, subscriptionID string) error {
	token := c.resolveToken(accessToken)
	if token == "" {
		return integrations.ErrMissingAccessToken
	}

	cleanID := strings.TrimSpace(subscriptionID)
	if cleanID == "" {
		return integrations.ErrInvalidParameter
	}

	_, err := c.doRequest(ctx, http.MethodDelete, "/resource_subscriptions/"+url.PathEscape(cleanID), token, nil, "")
	return err
}

// ParseWebhook parses and validates an incoming HTTP webhook request into a NormalizedWebhookEvent.
func (c *Client) ParseWebhook(r *http.Request, secret string) (*integrations.NormalizedWebhookEvent, error) {
	if r == nil {
		return nil, integrations.ErrInvalidPayload
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBodySize))
	if err != nil {
		return nil, fmt.Errorf("%w: error reading webhook body: %v", integrations.ErrInvalidPayload, err)
	}
	// Restore body for downstream handlers
	r.Body = io.NopCloser(bytes.NewReader(body))

	// Verify secret against query param, headers, or body
	if secret != "" {
		if !verifySecret(r.URL, r.Header, body, secret) {
			return nil, integrations.ErrWebhookVerificationFailed
		}
	}

	return c.ParseWebhookPayload(body, r.Header, "")
}

// ParseWebhookPayload parses and validates raw payload bytes and headers into a NormalizedWebhookEvent.
func (c *Client) ParseWebhookPayload(payload []byte, headers http.Header, secret string) (*integrations.NormalizedWebhookEvent, error) {
	if len(payload) == 0 {
		return nil, integrations.ErrInvalidPayload
	}

	if secret != "" {
		if !verifySecret(nil, headers, payload, secret) {
			return nil, integrations.ErrWebhookVerificationFailed
		}
	}

	trimmed := bytes.TrimSpace(payload)
	trimmed = bytes.TrimPrefix(trimmed, []byte("\xef\xbb\xbf"))
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) == 0 {
		return nil, integrations.ErrInvalidPayload
	}

	valuesMap := make(map[string]any)

	// Check if JSON or form urlencoded
	if trimmed[0] == '{' {
		if err := json.Unmarshal(trimmed, &valuesMap); err != nil {
			return nil, fmt.Errorf("%w: invalid json payload: %v", integrations.ErrInvalidPayload, err)
		}
	} else {
		vals, err := url.ParseQuery(string(trimmed))
		if err != nil {
			return nil, fmt.Errorf("%w: invalid urlencoded payload: %v", integrations.ErrInvalidPayload, err)
		}
		if len(vals) == 0 {
			return nil, integrations.ErrInvalidPayload
		}
		for k, v := range vals {
			if len(v) == 1 {
				valuesMap[k] = v[0]
			} else if len(v) > 1 {
				valuesMap[k] = v
			}
		}
	}

	return normalizeGumroadWebhook(valuesMap)
}

// verifySecret validates the provided secret token against request query params, headers, or payload.
func verifySecret(reqURL *url.URL, headers http.Header, payload []byte, secret string) bool {
	cleanSecret := strings.TrimSpace(secret)
	if cleanSecret == "" {
		return false
	}
	secBytes := []byte(cleanSecret)

	// 1. Query parameter
	if reqURL != nil {
		q := reqURL.Query()
		for _, param := range []string{"secret", "token", "passcode", "key"} {
			if val := q.Get(param); val != "" {
				if subtle.ConstantTimeCompare([]byte(val), secBytes) == 1 {
					return true
				}
			}
		}
	}

	// 2. HTTP headers
	if headers != nil {
		for _, hdr := range []string{"X-Gumroad-Secret", "X-Webhook-Secret", "X-Secret"} {
			if val := headers.Get(hdr); val != "" {
				if subtle.ConstantTimeCompare([]byte(val), secBytes) == 1 {
					return true
				}
			}
		}

		if auth := headers.Get("Authorization"); auth != "" {
			parts := strings.SplitN(auth, " ", 2)
			token := auth
			if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
				token = parts[1]
			}
			if subtle.ConstantTimeCompare([]byte(token), secBytes) == 1 {
				return true
			}
		}

		// 3. HMAC-SHA256 signature header if provided
		if sig := headers.Get("X-Gumroad-Signature"); sig != "" {
			cleanSig := strings.TrimSpace(sig)
			cleanSig = strings.TrimPrefix(cleanSig, "sha256=")
			cleanSig = strings.TrimPrefix(cleanSig, "SHA256=")
			mac := hmac.New(sha256.New, secBytes)
			mac.Write(payload)
			expectedMAC := hex.EncodeToString(mac.Sum(nil))
			if subtle.ConstantTimeCompare([]byte(strings.ToLower(cleanSig)), []byte(strings.ToLower(expectedMAC))) == 1 {
				return true
			}
		}
	}

	// 4. In form / url-encoded or JSON payload
	trimmed := bytes.TrimSpace(payload)
	trimmed = bytes.TrimPrefix(trimmed, []byte("\xef\xbb\xbf"))
	trimmed = bytes.TrimSpace(trimmed)
	if len(trimmed) > 0 {
		if trimmed[0] == '{' {
			var jMap map[string]any
			if json.Unmarshal(trimmed, &jMap) == nil {
				for _, param := range []string{"secret", "token", "passcode", "key"} {
					if val, ok := jMap[param]; ok && val != nil {
						if subtle.ConstantTimeCompare([]byte(fmt.Sprintf("%v", val)), secBytes) == 1 {
							return true
						}
					}
				}
			}
		} else {
			if vals, err := url.ParseQuery(string(trimmed)); err == nil {
				for _, param := range []string{"secret", "token", "passcode", "key"} {
					if val := vals.Get(param); val != "" {
						if subtle.ConstantTimeCompare([]byte(val), secBytes) == 1 {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// parseDictString extracts key-value pairs from a dictionary string formatted like "{'size' : 'large', 'color' : 'red'}"
// as documented in Gumroad's Ping specification (https://gumroad.com/ping).
func parseDictString(s string) map[string]string {
	trimmed := strings.TrimSpace(s)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return nil
	}

	result := make(map[string]string)
	// Try unmarshaling after standardizing single quotes to double quotes
	replaced := strings.ReplaceAll(trimmed, "'", "\"")
	var jMap map[string]any
	if err := json.Unmarshal([]byte(replaced), &jMap); err == nil {
		for k, v := range jMap {
			if v != nil {
				result[k] = fmt.Sprintf("%v", v)
			}
		}
		return result
	}

	// Scanner fallback for unquoted or malformed key-value pairs
	inner := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
	if inner == "" {
		return result
	}

	for _, part := range strings.Split(inner, ",") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			k := strings.Trim(strings.TrimSpace(kv[0]), `'" `)
			v := strings.Trim(strings.TrimSpace(kv[1]), `'" `)
			if k != "" {
				result[k] = v
			}
		}
	}

	return result
}

// officialPingFields defines the complete, strict set of 39 parameters documented in the
// official Gumroad Ping specification (https://gumroad.com/ping).
var officialPingFields = map[string]struct{}{
	"sale_id":                       {},
	"sale_timestamp":                {},
	"order_number":                  {},
	"seller_id":                     {},
	"product_id":                    {},
	"product_permalink":             {},
	"short_product_id":              {},
	"product_name":                  {},
	"email":                         {},
	"url_params":                    {},
	"full_name":                     {},
	"purchaser_id":                  {},
	"subscription_id":               {},
	"ip_country":                    {},
	"price":                         {},
	"recurrence":                    {},
	"variants":                      {},
	"offer_code":                    {},
	"test":                          {},
	"custom_fields":                 {},
	"shipping_information":          {},
	"is_recurring_charge":           {},
	"is_preorder_authorization":     {},
	"license_key":                   {},
	"quantity":                      {},
	"shipping_rate":                 {},
	"affiliate":                     {},
	"affiliate_credit_amount_cents": {},
	"is_gift_receiver_purchase":     {},
	"gifter_email":                  {},
	"gift_price":                    {},
	"refunded":                      {},
	"discover_fee_charged":          {},
	"can_contact":                   {},
	"referrer":                      {},
	"gumroad_fee":                   {},
	"card":                          {},
	"resource_name":                 {},
	"retry_count":                   {},
}

// isOfficialPingKey reports whether key is one of the 39 official Gumroad Ping parameters
// or a bracket-indexed subkey of an official dictionary parameter (e.g. custom_fields[...]).
func isOfficialPingKey(key string) bool {
	if _, ok := officialPingFields[key]; ok {
		return true
	}
	for _, prefix := range []string{
		"custom_fields[",
		"url_params[",
		"variants[",
		"shipping_information[",
		"card[",
	} {
		if strings.HasPrefix(key, prefix) && strings.HasSuffix(key, "]") {
			return true
		}
	}
	return false
}

// filterOfficialPingFields strips any parameters that are not part of the official Gumroad Ping definition.
func filterOfficialPingFields(raw map[string]any) map[string]any {
	filtered := make(map[string]any, len(raw))
	for k, v := range raw {
		if isOfficialPingKey(k) {
			filtered[k] = v
		}
	}
	return filtered
}

// normalizeGumroadWebhook converts the parsed Gumroad payload into a standard NormalizedWebhookEvent.
// It filters incoming parameters to strictly retain only fields defined in the official Gumroad Ping specification.
func normalizeGumroadWebhook(raw map[string]any) (*integrations.NormalizedWebhookEvent, error) {
	// Filter raw map so no non-spec fields are retained in NormalizedWebhookEvent.RawPayload or Order.RawData.
	raw = filterOfficialPingFields(raw)

	getString := func(key string) string {
		if v, ok := raw[key]; ok && v != nil {
			return strings.TrimSpace(fmt.Sprintf("%v", v))
		}
		return ""
	}

	getBool := func(key string) bool {
		if v, ok := raw[key]; ok && v != nil {
			switch b := v.(type) {
			case bool:
				return b
			case int:
				return b == 1
			case float64:
				return b == 1
			case string:
				s := strings.TrimSpace(strings.ToLower(b))
				return s == "true" || s == "1" || s == "yes" || s == "t"
			}
		}
		return false
	}

	getInt := func(key string) int {
		if v, ok := raw[key]; ok && v != nil {
			switch n := v.(type) {
			case float64:
				return int(n)
			case int:
				return n
			case string:
				s := strings.TrimSpace(n)
				s = strings.TrimPrefix(s, "$")
				s = strings.TrimPrefix(s, "€")
				s = strings.TrimPrefix(s, "£")
				if i, err := strconv.Atoi(s); err == nil {
					return i
				}
				if f, err := strconv.ParseFloat(s, 64); err == nil {
					return int(f)
				}
			}
		}
		return 0
	}

	parseTimestamp := func(keys ...string) (time.Time, bool) {
		layouts := []string{
			"2006-01-02 15:04:05 MST",
			"2006-01-02 15:04:05 UTC",
			time.RFC3339,
			time.RFC3339Nano,
			"2006-01-02T15:04:05-0700",
			"2006-01-02 15:04:05",
			"2006-01-02",
		}
		for _, key := range keys {
			val, ok := raw[key]
			if !ok || val == nil {
				continue
			}
			switch v := val.(type) {
			case float64:
				if v > 0 {
					sec := int64(v)
					if sec > 1e11 {
						return time.UnixMilli(sec).UTC(), true
					}
					return time.Unix(sec, 0).UTC(), true
				}
			case int:
				if v > 0 {
					return time.Unix(int64(v), 0).UTC(), true
				}
			case string:
				s := strings.TrimSpace(v)
				if s == "" {
					continue
				}
				if sec, err := strconv.ParseInt(s, 10, 64); err == nil && sec > 0 {
					if sec > 1e11 {
						return time.UnixMilli(sec).UTC(), true
					}
					return time.Unix(sec, 0).UTC(), true
				}
				for _, layout := range layouts {
					if t, err := time.Parse(layout, s); err == nil {
						return t.UTC(), true
					}
				}
			}
		}
		return time.Time{}, false
	}

	saleID := getString("sale_id")
	if saleID == "" {
		saleID = getString("order_number")
	}

	productID := getString("product_id")
	if productID == "" {
		productID = getString("short_product_id")
	}
	if productID == "" {
		productID = getString("product_permalink")
	}

	sellerID := getString("seller_id")
	email := getString("email")
	fullName := getString("full_name")
	priceCents := getInt("price")
	licenseKey := getString("license_key")
	subscriptionID := getString("subscription_id")
	resourceName := strings.ToLower(getString("resource_name"))

	customerID := getString("purchaser_id")
	if customerID == "" {
		customerID = email
	}

	refunded := getBool("refunded")
	refundedAmountCents := 0
	if refunded || resourceName == "refund" {
		refunded = true
		// Gumroad Ping does not send refunded_amount_cents; it sends refunded=true for the reversed sale
		refundedAmountCents = priceCents
	}
	disputed := resourceName == "dispute"
	cancelled := resourceName == "cancellation"

	// Determine normalized event type
	var eventType integrations.EventType
	switch {
	case resourceName == "refund" || refunded:
		eventType = integrations.EventTypeOrderRefunded
	case resourceName == "dispute" || disputed:
		eventType = integrations.EventTypeOrderDisputed
	case resourceName == "order_cancelled" || resourceName == "order.cancelled":
		eventType = integrations.EventTypeOrderCancelled
	case resourceName == "cancellation" || cancelled:
		eventType = integrations.EventTypeSubscriptionCancelled
	case resourceName == "subscription_paused":
		eventType = integrations.EventTypeSubscriptionPaused
	case resourceName == "subscription_updated":
		eventType = integrations.EventTypeSubscriptionUpdated
	case resourceName == "subscription_ended":
		eventType = integrations.EventTypeSubscriptionExpired
	case resourceName == "subscription_restarted":
		eventType = integrations.EventTypeSubscriptionResumed
	case resourceName == "license_key_created":
		eventType = integrations.EventTypeLicenseKeyCreated
	case resourceName == "license_key_updated":
		eventType = integrations.EventTypeLicenseKeyUpdated
	case subscriptionID != "":
		eventType = integrations.EventTypeSubscriptionCreated
	default:
		eventType = integrations.EventTypeOrderCreated
	}

	occurredAt := time.Now().UTC()
	if t, ok := parseTimestamp("sale_timestamp"); ok {
		occurredAt = t
	}

	var variantName string
	if vm, ok := raw["variants"].(map[string]any); ok {
		var parts []string
		for k, v := range vm {
			parts = append(parts, fmt.Sprintf("%s: %v", k, v))
		}
		variantName = strings.Join(parts, ", ")
	} else if vs, ok := raw["variants"].([]any); ok {
		var parts []string
		for _, v := range vs {
			parts = append(parts, fmt.Sprintf("%v", v))
		}
		variantName = strings.Join(parts, ", ")
	} else if s := getString("variants"); s != "" {
		if dict := parseDictString(s); len(dict) > 0 {
			var parts []string
			for k, v := range dict {
				parts = append(parts, fmt.Sprintf("%s: %v", k, v))
			}
			variantName = strings.Join(parts, ", ")
		} else {
			variantName = s
		}
	}

	if variantName == "" {
		var parts []string
		for k, v := range raw {
			if strings.HasPrefix(k, "variants[") && strings.HasSuffix(k, "]") {
				tier := strings.TrimSuffix(strings.TrimPrefix(k, "variants["), "]")
				parts = append(parts, fmt.Sprintf("%s: %v", tier, v))
			}
		}
		if len(parts) > 0 {
			variantName = strings.Join(parts, ", ")
		}
	}

	customFields := make(map[string]string)
	for k, v := range raw {
		if strings.HasPrefix(k, "custom_fields[") && strings.HasSuffix(k, "]") {
			fieldName := strings.TrimSuffix(strings.TrimPrefix(k, "custom_fields["), "]")
			if fieldName != "" && v != nil {
				customFields[fieldName] = fmt.Sprintf("%v", v)
			}
		} else if strings.HasPrefix(k, "url_params[") && strings.HasSuffix(k, "]") {
			paramName := strings.TrimSuffix(strings.TrimPrefix(k, "url_params["), "]")
			if paramName != "" && v != nil {
				customFields[paramName] = fmt.Sprintf("%v", v)
			}
		}
	}
	if cf, ok := raw["custom_fields"].(map[string]any); ok {
		for k, v := range cf {
			if v != nil {
				customFields[k] = fmt.Sprintf("%v", v)
			}
		}
	} else if cfStr := getString("custom_fields"); cfStr != "" {
		for k, v := range parseDictString(cfStr) {
			customFields[k] = v
		}
	}
	if up, ok := raw["url_params"].(map[string]any); ok {
		for k, v := range up {
			if v != nil {
				customFields[k] = fmt.Sprintf("%v", v)
			}
		}
	} else if upStr := getString("url_params"); upStr != "" {
		for k, v := range parseDictString(upStr) {
			customFields[k] = v
		}
	}
	if offerCode := getString("offer_code"); offerCode != "" {
		customFields["offer_code"] = offerCode
	}
	var orderCustomFields map[string]string
	if len(customFields) > 0 {
		orderCustomFields = customFields
	}

	order := &integrations.Order{
		ID:          saleID,
		Provider:    integrations.ProviderGumroad,
		ProductID:   productID,
		ProductName: getString("product_name"),
		VariantID:   "",
		VariantName: variantName,
		Customer: integrations.Customer{
			ID:        customerID,
			Email:     email,
			Name:      fullName,
			Country:   getString("ip_country"),
			IPAddress: "",
		},
		LicenseKey:          licenseKey,
		PriceCents:          priceCents,
		Currency:            "usd",
		TaxCents:            0,
		DiscountCents:       0,
		Refunded:            refunded,
		RefundedAmountCents: refundedAmountCents,
		Disputed:            disputed,
		SubscriptionID:      subscriptionID,
		OrderDate:           occurredAt,
		CustomFields:        orderCustomFields,
		RawData:             raw,
	}

	var sub *integrations.Subscription
	if subscriptionID != "" {
		subStatus := integrations.SubscriptionStatusActive
		switch {
		case cancelled:
			subStatus = integrations.SubscriptionStatusCancelled
		case resourceName == "subscription_ended":
			subStatus = integrations.SubscriptionStatusExpired
		case resourceName == "subscription_paused":
			subStatus = integrations.SubscriptionStatusPaused
		}
		sub = &integrations.Subscription{
			ID:            subscriptionID,
			Provider:      integrations.ProviderGumroad,
			ProductID:     productID,
			CustomerID:    customerID,
			CustomerEmail: email,
			Status:        subStatus,
			LicenseKey:    licenseKey,
			CancelledAt:   nil,
			CreatedAt:     occurredAt,
			RawData:       raw,
		}
	}

	// Per Gumroad specification (https://gumroad.com/ping):
	// "Deduplicate on sale_id together with resource_name, not on sale_id alone.
	// A refund carries the same sale_id as the sale it reverses."
	eventID := saleID
	if resourceName != "" && resourceName != "sale" {
		eventID = fmt.Sprintf("%s:%s", saleID, resourceName)
	} else if refunded {
		eventID = fmt.Sprintf("%s:refund", saleID)
	} else if disputed {
		eventID = fmt.Sprintf("%s:dispute", saleID)
	}
	if eventID == "" {
		eventID = fmt.Sprintf("evt_%d", occurredAt.UnixNano())
	}

	event := &integrations.NormalizedWebhookEvent{
		EventID:       eventID,
		Provider:      integrations.ProviderGumroad,
		EventType:     eventType,
		OccurredAt:    occurredAt,
		SellerID:      sellerID,
		ProductID:     productID,
		CustomerEmail: email,
		LicenseKey:    licenseKey,
		Order:         order,
		Subscription:  sub,
		RawPayload:    raw,
	}

	return event, nil
}

// gumroadProduct is the internal unmarshaling model for Gumroad product API responses.
type gumroadProduct struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	PreviewURL      string           `json:"preview_url"`
	ShortURL        string           `json:"short_url"`
	CustomPermalink string           `json:"custom_permalink"`
	Price           int              `json:"price"`
	Currency        string           `json:"currency"`
	FormattedPrice  string           `json:"formatted_price"`
	Published       bool             `json:"published"`
	Variants        []gumroadVariant `json:"variants"`
}

type gumroadVariant struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Title           string `json:"title"`
	PriceDifference int    `json:"price_difference"`
}

func mapGumroadProduct(gp gumroadProduct, raw map[string]any) integrations.Product {
	targetURL := gp.ShortURL
	if targetURL == "" {
		targetURL = gp.PreviewURL
	}
	if targetURL == "" {
		targetURL = gp.CustomPermalink
	}

	variants := make([]integrations.Variant, 0, len(gp.Variants))
	for _, v := range gp.Variants {
		vName := v.Name
		if vName == "" {
			vName = v.Title
		}
		variants = append(variants, integrations.Variant{
			ID:         v.ID,
			ProductID:  gp.ID,
			Name:       vName,
			PriceCents: gp.Price + v.PriceDifference,
			Currency:   gp.Currency,
		})
	}

	return integrations.Product{
		ID:             gp.ID,
		Provider:       integrations.ProviderGumroad,
		Name:           gp.Name,
		Description:    gp.Description,
		URL:            targetURL,
		PriceCents:     gp.Price,
		Currency:       gp.Currency,
		FormattedPrice: gp.FormattedPrice,
		Published:      gp.Published,
		Variants:       variants,
		RawData:        raw,
	}
}

// gumroadPurchase represents the purchase sub-object returned by /licenses/verify.
type gumroadPurchase struct {
	SellerID                string     `json:"seller_id"`
	ProductID               string     `json:"product_id"`
	ProductName             string     `json:"product_name"`
	Email                   string     `json:"email"`
	FullName                string     `json:"full_name"`
	Price                   int        `json:"price"`
	Currency                string     `json:"currency"`
	SaleID                  string     `json:"sale_id"`
	Refunded                bool       `json:"refunded"`
	Chargebacked            bool       `json:"chargebacked"`
	Disputed                bool       `json:"disputed"`
	SubscriptionID          string     `json:"subscription_id"`
	SubscriptionCancelledAt *time.Time `json:"subscription_cancelled_at"`
	SubscriptionFailedAt    *time.Time `json:"subscription_failed_at"`
}
