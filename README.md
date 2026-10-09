# Seatling Gumroad Integration (`integrations-gumroad`)

`github.com/seatling/integrations-gumroad` is the sole, canonical Go integration library for [Gumroad](https://gumroad.com) in the Seatling ecosystem. It implements the contracts and models defined in `github.com/seatling/integrations-shared`.

---

## 1. Architectural Role & Boundary

This repository provides the concrete implementation of:
- `integrations.ProviderClient`: Complete REST API operations against Gumroad API v2 (`/v2/user`, `/v2/products`, `/v2/licenses/verify`, `/v2/resource_subscriptions`).
- `integrations.WebhookParser`: Form-encoded and JSON webhook payload parsing, event normalization, and secret verification.
- `integrations.Integration`: Combined provider client and webhook parser.

### Key Guarantees:
- **Zero Third-Party Dependencies**: Built 100% on the Go standard library and `github.com/seatling/integrations-shared`.
- **Production-Hardened Defaults**: Configured with timeouts, bounded response stream reading (DOS protection), and secure secret comparison (`subtle.ConstantTimeCompare`).
- **Normalized Outputs**: Translates Gumroad-specific payloads and responses into canonical Seatling models (`User`, `Product`, `Order`, `Subscription`, `LicenseVerificationResult`, `NormalizedWebhookEvent`).

---

## 2. Installation

```bash
go get github.com/seatling/integrations-gumroad@latest
```

---

## 3. Usage

### Initializing the Client

```go
package main

import (
    "context"
    "fmt"
    "log"

    gumroad "github.com/seatling/integrations-gumroad"
    integrations "github.com/seatling/integrations-shared"
)

func main() {
    client := gumroad.New(
        gumroad.WithAccessToken("your-gumroad-access-token"),
    )

    ctx := context.Background()

    // 1. Get creator profile
    user, err := client.GetUser(ctx, "")
    if err != nil {
        log.Fatalf("failed to get user: %v", err)
    }
    fmt.Printf("Connected Gumroad user: %s (%s)\n", user.Name, user.Email)

    // 2. List products
    products, err := client.ListProducts(ctx, "")
    if err != nil {
        log.Fatalf("failed to list products: %v", err)
    }
    fmt.Printf("Found %d products\n", len(products))

    // 3. Verify license key
    result, err := client.VerifyLicense(ctx, integrations.LicenseVerificationRequest{
        ProductID:  "YOUR_PRODUCT_ID",
        LicenseKey: "BUYER_LICENSE_KEY",
    })
    if err != nil {
        log.Fatalf("verification error: %v", err)
    }
    fmt.Printf("License valid: %v (status: %s)\n", result.Valid, result.Status)
}
```

### Parsing Webhooks (Gumroad Ping)

```go
func handleGumroadWebhook(w http.ResponseWriter, r *http.Request) {
    client := gumroad.New()

    event, err := client.ParseWebhook(r, "your_webhook_passcode_or_secret")
    if err != nil {
        http.Error(w, err.Error(), http.StatusBadRequest)
        return
    }

    switch event.EventType {
    case integrations.EventTypeOrderCreated:
        fmt.Printf("New order: %s, amount: %d cents\n", event.Order.ID, event.Order.PriceCents)
    case integrations.EventTypeOrderRefunded:
        fmt.Printf("Order refunded: %s\n", event.Order.ID)
    case integrations.EventTypeSubscriptionCancelled:
        fmt.Printf("Subscription cancelled: %s\n", event.Subscription.ID)
    }

    w.WriteHeader(http.StatusOK)
}
```

---

## 4. Testing

### Mock Unit Tests
Run complete mock unit test suite:
```bash
go test -v -cover ./...
```

### Live API Integration Tests
Integration tests run against the live Gumroad API when `GUMROAD_ACCESS_TOKEN` is supplied:
```bash
GUMROAD_ACCESS_TOKEN="your_token" go test -v -run TestIntegration ./...
```
Optional environment variables for license verification live tests:
- `GUMROAD_PRODUCT_ID`
- `GUMROAD_LICENSE_KEY`

---

## 5. License

This project is licensed under the **Business Source License 1.1 (BUSL-1.1)**. See the [LICENSE](./LICENSE) file for complete terms and parameters.

> [!NOTE]
> Non-production use (such as local development, testing, and evaluation) is freely permitted. Production use or commercial distribution within platforms providing substantially similar licensing and checkout services to Seatling may require a separate commercial arrangement. If you have questions about whether your intended use case is covered, feel free to reach out to the team.


