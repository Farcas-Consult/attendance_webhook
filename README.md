# ZK Attendance Webhook Server

A standalone Express server that processes ZK device attendance webhooks for fitness254 tenants

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
Process ZK attendance events for a specific gym tenant.

**Parameters:**
- `tenant` - Gym subdomain (e.g., `testgym`)

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
  "errors": 0
}
```

### `GET /health`
Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-01-15T10:30:15.000Z"
}
```

## Environment Variables

```bash
# Server Configuration
NODE_ENV=development
LOG_LEVEL=info
PORT=3001

# Supabase Configuration
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_KEY=your-service-role-key
```

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
