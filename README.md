# Attendance Webhook Server

A standalone Express server that processes attendance/access events for fitness254 tenants.

Currently supported providers:
- ZKTeco (`POST /webhook/:tenant`)
- HikCentral push events (`POST /webhook/:tenant/hikcentral`)

## Architecture

This server implements the database trigger pattern:
1. **Webhook Server** - Validates HMAC signatures and inserts raw events
2. **Database Triggers** - Handle member enrichment and Supabase Realtime broadcasts
3. **Frontend** - Receives real-time updates via Supabase Realtime

## Quick Start

1. **Configure Environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your Supabase credentials
   ```

2. **Build**:
   ```bash
   pnpm run build
   ```

3. **Run Server**:
   ```bash
   pnpm run start
   ```


## API Endpoints

### `POST /webhook/:tenant`
Process ZKTeco attendance events for a specific gym tenant.

**Parameters:**
- `tenant` - Gym subdomain (e.g., `testgym`)
- Query `branch_id` - Branch/location identifier (required)

**Headers:**
- `x-signature` - HMAC-SHA256 signature of request body
- `Content-Type: application/json`

**Request Body:**
```json
{
  "data": [
    {
      "eventTime": "2025-01-15 10:30:15",
      "event_iso": "2025-01-15T10:30:15Z",
      "event_id": "evt_1001_1736937015",
      "pin": "1001",
      "areaName": "Main Gym",
      "cardNo": "12345678",
      "devSn": "0564140100195",
      "verify_mode": "face",
      "result": "pass",
      "devName": "SpeedFace V5L"
    }
  ]
}
```

**Response:**
```json
{
  "ok": true,
  "tenant": "testgym",
  "received": 1,
  "processed": 1,
  "duplicates": 0,
  "skipped_unknown": 0,
  "skipped_repeats": 0,
  "errors": 0
}
```

Repeat scans by the same member within `REPEAT_SCAN_WINDOW_MINUTES` (default 10) of an already stored or earlier event are dropped and counted in `skipped_repeats`. Set it to `0` to disable.

Events whose `pin` does not match a `members.turnstile_id` with a linked `user_id` are dropped before insert (they would otherwise show as "Unknown" in the app) and counted in `skipped_unknown`. The same applies to HikCentral events.

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-01-15T10:30:15.000Z"
}
```

### `POST /webhook/:tenant/hikcentral`
Process HikCentral access control push events for a specific gym tenant.

**Parameters:**
- `tenant` - Gym subdomain (e.g., `testgym`); must exist as `gyms.subdomain` (no extra DB column required for Hik)
- Query `branch_id` - Branch/location identifier (required)

**Authentication:** None. HikCentral event push is accepted when the tenant resolves to a gym row. Protect this URL at the network edge (VPN, firewall, or reverse proxy) if needed.

**Request Body (example):**
```json
{
  "method": "OnEventNotify",
  "params": {
    "sendTime": "2026-04-10T17:00:00.000+08:00",
    "ability": "event_acs",
    "events": [
      {
        "eventId": "c929d9f873eb48439bd2c59df358bbeb",
        "srcName": "Main Entrance Door",
        "srcIndex": "1",
        "eventType": 196893,
        "happenTime": "2026-04-10T17:00:00.000+08:00",
        "data": {
          "personId": "1149",
          "personCode": "3536895491",
          "personName": "John Doe",
          "cardNo": "234324",
          "checkInAndOutType": 1,
          "readerName": "Cardreader 01",
          "readerIndexCode": "3"
        }
      }
    ]
  }
}
```

**Response (example):**
```json
{
  "ok": true,
  "tenant": "testgym",
  "provider": "hikcentral",
  "received": 1,
  "processed": 1,
  "duplicates": 0,
  "skipped_unknown": 0,
  "skipped_repeats": 0,
  "errors": 0
}
```

**Notes:**
- The service returns HTTP 200 for accepted requests (required by HikCentral push retries/ack flow).
- Default successful access event types accepted: `196893,198914,196883,197127`.
- Unsupported event types are skipped and reported in `error_details`.
- `device_name` is set from `data.readerName` when present, otherwise the door `srcName`. `area_name` is the door `srcName`.
- `turnstile_id` is set from `data.personCode` (same idea as ZK `pin`), then `readerIndexCode`, then `srcIndex` if `personCode` is missing.
- `checkInAndOutType` may be `0` on some deployments; direction semantics are not stored in `attendance_events` today (only logged at debug). Extend the schema or triggers if you need check-in vs check-out in the app.
- Payloads may include top-level `isHistory`; live vs replay handling is not special-cased unless you add it.

## Environment Variables

```bash
# Server Configuration
NODE_ENV=development
LOG_LEVEL=info
PORT=3001

# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key

# Optional HikCentral event type allow-list (comma-separated integers)
# Defaults: 196893,198914,196883,197127
HIK_SUCCESS_EVENT_TYPES=196893,198914,196883,197127

# Optional: drop repeat scans by the same member within this many minutes (0 disables)
REPEAT_SCAN_WINDOW_MINUTES=10
```

## Tenant configuration

- **ZKTeco** (`POST /webhook/:tenant`): requires `zk_webhook_secret` on the gym row for HMAC verification.
- **HikCentral** (`POST /webhook/:tenant/hikcentral`): only requires a matching `gyms.subdomain` for `:tenant`; no webhook secret column.

## Testing

The mock ZK server (`mock-zk-server.js`) sends test events to the webhook server:

Add this to the env file:

```bash
# Configure test environment
TARGET_URL=http://localhost:PORT/webhook/testgym
PUSH_HMAC_SECRET=test-secret-123
PUSH_INTERVAL_MS=5000

# Start mock server
node mock-zk-server.js
```
