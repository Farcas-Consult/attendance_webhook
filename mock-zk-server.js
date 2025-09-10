import http from 'http';
import https from 'https';
import crypto from 'crypto';

// Mock transaction data
let mockTransactions = [
  {
    eventTime: "2025-01-15 10:30:15",
    event_iso: "2025-01-15T10:30:15Z",
    event_id: "evt_1001_1736937015",
    pin: "1001",
    areaName: "Main Gym",
    cardNo: "12345678",
    devSn: "0564140100195",
    verify_mode: "face",
    verifyModeName: "face",
    result: "granted",
    eventName: "access granted",
    eventPointName: "192.168.1.100-1",
    readerName: "Front Turnstile",
    devName: "SpeedFace V5L"
  },
  {
    eventTime: "2025-01-15 10:32:20",
    event_iso: "2025-01-15T10:32:20Z",
    event_id: "evt_1002_1736937140",
    pin: "1002",
    areaName: "Main Gym",
    cardNo: "87654321",
    devSn: "0564140100195",
    verify_mode: "card",
    verifyModeName: "card",
    result: "granted",
    eventName: "access granted",
    eventPointName: "192.168.1.100-1",
    readerName: "Front Turnstile",
    devName: "SpeedFace V5L"
  },
  {
    eventTime: "2025-01-15 10:35:05",
    event_iso: "2025-01-15T10:35:05Z",
    event_id: "evt_1003_1736937305",
    pin: "1003",
    areaName: "Free Weights",
    cardNo: "11223344",
    devSn: "0564140100195",
    verify_mode: "fingerprint",
    verifyModeName: "fingerprint",
    result: "granted",
    eventName: "access granted",
    eventPointName: "192.168.1.100-2",
    readerName: "Side Gate",
    devName: "SpeedFace V5L"
  },
  {
    eventTime: "2025-01-15 10:36:40",
    event_iso: "2025-01-15T10:36:40Z",
    event_id: "evt_1004_1736937400",
    pin: "1004",
    areaName: "Main Gym",
    cardNo: "99887766",
    devSn: "0564140100195",
    verify_mode: "face",
    verifyModeName: "face",
    result: "denied",
    eventName: "access denied",
    eventPointName: "192.168.1.100-1",
    readerName: "Front Turnstile",
    devName: "SpeedFace V5L"
  }
];

const TARGET_URL = process.env.TARGET_URL || 'http://localhost:3005/webhook/demo';
const PUSH_HMAC_SECRET = process.env.PUSH_HMAC_SECRET || 'demowebhook';
const PUSH_INTERVAL_MS = Number(process.env.PUSH_INTERVAL_MS || 10000);

function chooseRandomSubset(items) {
  const max = items.length;
  const count = Math.max(1, Math.floor(Math.random() * max) + 1);
  const indices = Array.from({ length: max }, (_, i) => i);
  for (let i = indices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [indices[i], indices[j]] = [indices[j], indices[i]];
  }
  const picked = indices.slice(0, count).map(i => items[i]);
  return picked;
}

function sendEvents(events) {
  const payload = JSON.stringify({ data: events });
  const signature = crypto.createHmac('sha256', PUSH_HMAC_SECRET).update(payload).digest('hex');
  const parsed = new URL(TARGET_URL);
  const isHttps = parsed.protocol === 'https:';
  const client = isHttps ? https : http;

  const options = {
    hostname: parsed.hostname,
    port: parsed.port || (isHttps ? 443 : 80),
    path: parsed.pathname + parsed.search,
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload),
      'x-signature': signature
    }
  };

  const req = client.request(options, res => {
    let resp = '';
    res.on('data', chunk => resp += chunk);
    res.on('end', () => {
      console.log(`📨 Pushed ${events.length} event(s) → ${TARGET_URL} (status ${res.statusCode})`);
    });
  });
  req.on('error', err => {
    console.error('❌ Push failed:', err.message);
  });
  req.write(payload);
  req.end();
}

console.log('🎭 Mock ZK pusher starting...');
console.log(`➡️  Target: ${TARGET_URL}`);
console.log(`⏱️  Interval: ${PUSH_INTERVAL_MS}ms`);

const timer = setInterval(() => {
  const batch = chooseRandomSubset(mockTransactions);
  sendEvents(batch);
}, PUSH_INTERVAL_MS);

process.on('SIGINT', () => {
  clearInterval(timer);
  console.log('\n🛑 Stopped mock pusher.');
  process.exit(0);
});
