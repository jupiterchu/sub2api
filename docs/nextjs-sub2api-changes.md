# NextJS integration custom changes

Scope
- Base commit: 4d570de31dbc80840ccbc1a11f06a7a4e448b58b (Add NextJS balance sync and usage webhook)
- Additional patch: finite balance check + 4 dp rounding in internal balance sync (added after the base commit)
- Purpose: track local custom changes for easier upstream merges

Files added
- backend/internal/custom/internal_handler.go
  - Internal balance sync endpoint: POST /api/internal/balance/sync
  - Header: X-Internal-Secret
  - Body: { user_id, balance_points | balance_usd | balance }
  - Conversion: balance_points -> USD using nextjs.points_to_usd (default 10000)
  - Validation: reject NaN/Inf, allow negative values
  - Rounding: 4 decimal places (USD)
  - Persists via UserService.SetBalance and invalidates billing cache
- backend/internal/custom/service/nextjs_service.go
  - HTTP client to NextJS BFF with retries, timeout, internal secret header
  - Webhook request/response structs
- backend/internal/custom/service/usage_hook.go
  - Implements UsageRecordedHook
  - Sends usage webhook after billing success
  - Sends userId, omits apiKey (empty string), optional sub2api_balance_usd
- backend/internal/custom/wire.go
  - Wire providers for NextJS service, usage hook, internal handler

Files modified
- backend/internal/config/config.go
  - Adds NextJSConfig: enabled, base_url, internal_secret, timeout_seconds, retry_count, retry_delay_seconds, points_to_usd
  - Defaults + validation when nextjs.enabled = true
- backend/internal/service/gateway_service.go
  - Adds UsageRecordedHook + SetUsageRecordedHook
  - Triggers hook only when billing succeeds (in both RecordUsage and RecordUsageWithLongContext)
- backend/internal/service/openai_gateway_service.go
  - Same as gateway_service.go
- backend/internal/handler/wire.go
  - Uses ProvideGatewayHandler / ProvideOpenAIGatewayHandler to wire usage hook
- backend/cmd/server/wire.go, backend/cmd/server/wire_gen.go
  - Adds custom.ProviderSet (NextJS integration)
- backend/internal/server/router.go, backend/internal/server/http.go
  - Injects InternalHandler and registers internal routes
- backend/internal/service/user_service.go
  - Adds SetBalance method (invalidates auth cache)
- backend/internal/repository/user_repo.go
  - Adds SetBalance persistence helper
- backend/internal/server/api_contract_test.go
  - Adds SetBalance stub for tests
- backend/internal/service/admin_service_delete_test.go
  - Adds SetBalance stub for tests

Runtime behavior summary
- Internal balance sync endpoint
  - POST /api/internal/balance/sync
  - Requires X-Internal-Secret header
  - Accepts one of: balance_points, balance_usd, balance
  - Converts points to USD using nextjs.points_to_usd
  - Rejects NaN/Inf, allows negative values
  - Rounds to 4 decimal places before writing
  - Persists using UserService.SetBalance
  - Invalidates billing cache (and auth cache via UserService)

- Usage webhook to NextJS
  - Target: /api/internal/webhooks/usage on NextJS base_url
  - Trigger: only after billing succeeds (deduct balance or increment subscription)
  - Not sent when cost == 0
  - apiKey is omitted (empty string), userId is sent
  - sub2api_balance_usd is sent only if apiKey.User is preloaded

Config keys (new)
- nextjs.enabled
- nextjs.base_url
- nextjs.internal_secret
- nextjs.timeout_seconds
- nextjs.retry_count
- nextjs.retry_delay_seconds
- nextjs.points_to_usd

Merge checklist (for future upstream updates)
- Custom package preserved: backend/internal/custom/*
- custom.ProviderSet included in backend/cmd/server/wire.go
- Internal routes registered in backend/internal/server/router.go
- UsageRecordedHook wiring in backend/internal/handler/wire.go
- UsageRecordedHook triggers after billing success in gateway services (both RecordUsage and RecordUsageWithLongContext)
- UserService.SetBalance + UserRepository.SetBalance still present
- nextjs config defaults + validation in backend/internal/config/config.go

Examples
- Internal balance sync request
  - POST /api/internal/balance/sync
  - Header: X-Internal-Secret: <secret>
  - Body (points):
    {
      "user_id": 123,
      "balance_points": 105000
    }
  - Body (USD):
    {
      "user_id": 123,
      "balance_usd": -3.25
    }
  - Response:
    {
      "user_id": 123,
      "balance": -3.25
    }

- Usage webhook payload (sub2api -> NextJS)
  - POST /api/internal/webhooks/usage
  - Header: X-Internal-Secret: <secret>
  - Body (example):
    {
      "event": "usage",
      "userId": 123,
      "model": "gpt-4o-mini",
      "inputTokens": 100,
      "outputTokens": 200,
      "cacheReadTokens": 0,
      "cacheWriteTokens": 0,
      "cost": 0.003,
      "totalCost": 0.003,
      "rateMultiplier": 1,
      "timestamp": 1700000000000,
      "sub2api_balance_usd": -3.25
    }

Config example (YAML)
nextjs:
  enabled: true
  base_url: http://localhost:3000
  internal_secret: "your-internal-secret"
  timeout_seconds: 10
  retry_count: 2
  retry_delay_seconds: 1
  points_to_usd: 10000

Merge hotspots (likely conflicts)
- backend/cmd/server/wire.go
- backend/cmd/server/wire_gen.go
- backend/internal/handler/wire.go
- backend/internal/server/router.go
- backend/internal/service/gateway_service.go
- backend/internal/service/openai_gateway_service.go
- backend/internal/config/config.go

Design notes (intent)
- Usage webhook is sent only after billing success, to keep NextJS and sub2api aligned.
- apiKey is omitted in webhook payload; NextJS uses userId as the identity key.
- Internal balance sync allows negative values; only NaN/Inf are rejected.

Bug fixes
- RecordUsageWithLongContext (used by Gemini via Antigravity mixed_scheduling) was missing the UsageRecordedHook call.
  - Fixed: Added billingSucceeded tracking and hook invocation to match RecordUsage behavior.
  - This ensures Gemini usage via Antigravity channel also triggers the NextJS webhook.
