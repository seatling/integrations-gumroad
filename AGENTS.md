# Seatling Gumroad Integration: AI Agent Guidebook (`AGENTS.md`)

Welcome, Agent. This document defines the engineering standards, architectural boundaries, and tactical instructions for `github.com/seatling/integrations-gumroad`. All AI coding agents working in this repository must adhere to these conventions.

---

## 1. Overview & Architectural Role

`github.com/seatling/integrations-gumroad` is the sole, canonical Go integration module for Gumroad in the Seatling ecosystem.

### Key Boundaries:
- **Implements Canonical Shared Interfaces**: Implements `integrations.Integration` (`ProviderClient` and `WebhookParser`) defined in `github.com/seatling/integrations-shared`.
- **Zero Third-Party Dependencies**: Restricted strictly to the Go standard library (100% stdlib) and `github.com/seatling/integrations-shared`.
- **Normalized Outputs**: Returns normalized models from `integrations-shared` (`User`, `Product`, `Order`, `Subscription`, `LicenseVerificationResult`, `NormalizedWebhookEvent`).
- **High Test Coverage**: Comprehensive mock unit tests (>95% statement coverage) plus optional live Gumroad API integration tests.

---

## 2. Setup Commands

- **Verify Go environment**: Go 1.26+ required
  ```bash
  go version
  ```
- **Download and verify module**:
  ```bash
  go mod download
  go mod verify
  ```

---

## 3. Build, Test & Lint Commands

All verification in this repository uses the canonical shell scripts [`test.sh`](./test.sh) and [`lint.sh`](./lint.sh):

### Primary Verification Commands

| Command | Purpose |
| :--- | :--- |
| `go test -v -cover -timeout 10s ./...` | Full unit test suite execution with statement coverage |
| `go vet ./...` | Go standard static analysis |
| `gofmt -s -w .` | Standard Go formatting |
| `GUMROAD_ACCESS_TOKEN="<token>" go test -v -run TestIntegration ./...` | Live Gumroad API integration test run |

---

## 4. Architectural Invariants & Rules

### Rule 1: Zero External Dependencies
- `go.mod` must only declare `module github.com/seatling/integrations-gumroad` and require `github.com/seatling/integrations-shared`.
- Never add third-party dependencies (`github.com/...`).

### Rule 2: Sole Provider Responsibility
- All Gumroad REST endpoints (`/user`, `/products`, `/licenses/verify`, `/resource_subscriptions`) and webhook parsing reside here.
- Do not implement more interfaces or endpoints than required by `integrations-shared`.

### Rule 3: Error Taxonomy
- Always return typed errors from `integrations-shared`:
  - `ErrMissingAccessToken`
  - `ErrInvalidParameter`
  - `ErrUnauthorized`
  - `ErrNotFound`
  - `ErrRateLimited`
  - `ErrWebhookVerificationFailed`
  - `ErrInvalidPayload`
  - `*integrations.APIError`

### Rule 4: Licensing
- This repository is licensed under the **Business Source License 1.1 (BUSL-1.1)**. Do not apply or reference permissive open-source licenses (such as MIT) in this module.

