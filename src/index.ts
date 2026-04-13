import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import pino from 'pino';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

// Logger setup
const logger = pino({
  level: process.env['LOG_LEVEL'] || 'info',
  ...(process.env['NODE_ENV'] !== 'production' && {
    transport: { target: 'pino-pretty', options: { colorize: true } },
  }),
});

// Environment variables
const PORT = Number(process.env['PORT'] || 3001);
const SUPABASE_URL = mustGet('SUPABASE_URL');
const SUPABASE_SERVICE_KEY = mustGet('SUPABASE_SERVICE_KEY');

// Supabase client with optimized configuration
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false },
  db: {
    schema: 'public'
  },
  global: {
    headers: {
      'x-application-name': 'attendance-webhook'
    }
  }
});

function mustGet(key: string): string {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing required environment variable: ${key}`);
  }
  return value;
}

// ZK Event interfaces 
interface ZKEvent {
  eventTime: string;
  pin: string;
  areaName: string;
  cardNo: string;
  devSn: string;
  verifyModeName: string;
  eventName: string;
  eventPointName: string;
  readerName: string;
  devName: string;
  event_id: string;
  verify_mode: 'face' | 'fingerprint' | 'finger' | 'card' | 'multi';
  result: 'granted' | 'denied' | 'pass' | 'fail';
  event_iso: string;
}

interface ZKWebhookPayload {
  data: ZKEvent[];
}

interface HikEventData {
  personId?: string;
  personCode?: string;
  personName?: string;
  cardNo?: string;
  checkInAndOutType?: number;
  picUri?: string;
  readerName?: string;
  readerIndexCode?: string;
}

interface HikEvent {
  eventId: string;
  srcName?: string;
  srcIndex?: string;
  srcType?: string;
  eventType: number;
  happenTime: string;
  data?: HikEventData;
}

interface HikWebhookPayload {
  method: string;
  params: {
    sendTime?: string;
    ability?: string;
    events: HikEvent[];
  };
  isHistory?: number;
}

type Provider = 'zk' | 'hikcentral';
type GymSecretColumn = 'zk_webhook_secret';

interface AttendanceEventInsert {
  event_id: string;
  turnstile_id: number | null;
  event_time: string;
  result: 'pass' | 'fail';
  verify_mode: 'face' | 'finger' | 'card' | 'multi';
  device_name: string | null;
  area_name: string | null;
  branch_id: string;
}

interface ProcessedEventResult {
  event_id: string;
  status: 'processed' | 'duplicate';
  message?: string;
  db_id?: number;
}

interface EventProcessingResult {
  processedEvents: ProcessedEventResult[];
  errors: string[];
}

interface GymSecretRecord {
  gym_id: string;
  zk_webhook_secret?: string | null;
}

const DEFAULT_HIK_SUCCESS_EVENT_TYPES = [196893, 198914, 196883, 197127];
const HIK_SUCCESS_EVENT_TYPES = parseIntegerList(
  process.env['HIK_SUCCESS_EVENT_TYPES'],
  DEFAULT_HIK_SUCCESS_EVENT_TYPES
);

const HIK_VERIFY_MODE_BY_EVENT_TYPE: Record<number, AttendanceEventInsert['verify_mode']> = {
  196893: 'face',
  198914: 'card',
  196883: 'multi',
  197127: 'finger',
};

// HMAC verification function 
function verifyHmacSignature(body: string, signature: string, secret: string): boolean {
  try {
    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(body)
      .digest('hex');
      
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature, 'hex'),
      Buffer.from(signature, 'hex')
    );
  } catch (error) {
    logger.error({ error }, 'HMAC verification error');
    return false;
  }
}

function parseIntegerList(value: string | undefined, fallback: number[]): number[] {
  if (!value) {
    return fallback;
  }

  const parsed = value
    .split(',')
    .map((entry) => Number.parseInt(entry.trim(), 10))
    .filter((entry) => Number.isFinite(entry));

  return parsed.length > 0 ? parsed : fallback;
}

function toSafeInteger(value: string | number | undefined): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.trunc(value);
  }

  if (typeof value !== 'string' || value.trim() === '') {
    return null;
  }

  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

// Validate ZK event data 
function validateZKEvent(event: ZKEvent): boolean {
  return !!(
    event.event_id &&
    event.pin &&
    event.event_iso &&
    event.result &&
    event.verify_mode &&
    ['granted', 'denied', 'pass', 'fail'].includes(event.result) &&
    ['face', 'fingerprint', 'finger', 'card', 'multi'].includes(event.verify_mode)
  );
}

// Map ZK values to database values
function mapZKToDatabase(event: ZKEvent, branchId: string): AttendanceEventInsert {
  return {
    event_id: event.event_id,
    turnstile_id: toSafeInteger(event.pin),
    event_time: event.event_iso,
    result: (event.result === 'granted' || event.result === 'pass') ? 'pass' : 'fail',
    verify_mode: (event.verify_mode === 'fingerprint' || event.verify_mode === 'finger') ? 'finger' : event.verify_mode,
    device_name: event.devName || null,
    area_name: event.areaName || null,
    branch_id: branchId
  };
}

function validateHikEvent(event: HikEvent): boolean {
  return !!(
    event.eventId &&
    event.happenTime &&
    Number.isFinite(event.eventType) &&
    HIK_SUCCESS_EVENT_TYPES.includes(event.eventType)
  );
}

function mapHikToDatabase(event: HikEvent, branchId: string): AttendanceEventInsert {
  const verifyMode = HIK_VERIFY_MODE_BY_EVENT_TYPE[event.eventType] || 'card';
  // Site convention: map member `personCode` into `turnstile_id` (same role as ZK `pin`).
  const turnstileId =
    toSafeInteger(event.data?.personCode) ??
    toSafeInteger(event.data?.readerIndexCode) ??
    toSafeInteger(event.srcIndex);

  const doorName = event.srcName?.trim() || null;
  const readerName = event.data?.readerName?.trim() || null;
  // Door vs reader: matches typical Hik payloads (door in srcName, reader in data.readerName).
  const device_name = readerName || doorName;
  const area_name = doorName;

  return {
    event_id: event.eventId,
    turnstile_id: turnstileId,
    event_time: event.happenTime,
    result: 'pass',
    verify_mode: verifyMode,
    device_name,
    area_name,
    branch_id: branchId
  };
}

function getRawBody(body: unknown): string {
  if (Buffer.isBuffer(body)) {
    return body.toString('utf8');
  }
  if (typeof body === 'string') {
    return body;
  }
  return '';
}

function getBranchId(branchId: string | undefined): string | null {
  if (!branchId || branchId.trim() === '') {
    return null;
  }
  return branchId.trim();
}

async function getGymProviderSecret(
  tenant: string,
  secretColumn: GymSecretColumn
): Promise<{ gymId: string; secret: string } | null> {
  const { data, error } = await supabase
    .from('gyms')
    .select(`gym_id, ${secretColumn}`)
    .eq('subdomain', tenant)
    .single();

  if (error || !data) {
    logger.error({ tenant, error }, 'Gym not found');
    return null;
  }

  const gym = data as GymSecretRecord;
  const secret = gym[secretColumn];
  if (!secret) {
    logger.error({ tenant, secretColumn }, 'No provider webhook secret configured');
    return null;
  }

  return { gymId: gym.gym_id, secret };
}

/** Resolve tenant for HikCentral: no webhook secret column required; Hik push does not send auth. */
async function getGymBySubdomain(tenant: string): Promise<{ gymId: string } | null> {
  const { data, error } = await supabase
    .from('gyms')
    .select('gym_id')
    .eq('subdomain', tenant)
    .single();

  if (error || !data) {
    logger.error({ tenant, error }, 'Gym not found');
    return null;
  }

  return { gymId: (data as { gym_id: string }).gym_id };
}

// Fallback function for individual event processing
async function processEventsIndividually(
  validEvents: AttendanceEventInsert[], 
  gym_schema: string, 
  processedEvents: ProcessedEventResult[], 
  errors: string[]
) {
  for (const event of validEvents) {
    try {
      const { data: newEvent, error: insertError } = await supabase
        .schema(gym_schema)
        .from('attendance_events')
        .insert(event)
        .select('id')
        .single();

      if (insertError) {
        // Handle unique constraint violation (duplicate event)
        if (insertError.code === '23505') {
          logger.debug({ event_id: event.event_id }, 'Event already processed (duplicate)');
          processedEvents.push({
            event_id: event.event_id,
            status: 'duplicate',
            message: 'Event already processed'
          });
          continue;
        }
        
        // Handle other database errors
        logger.error({ event_id: event.event_id, insertError }, 'Error inserting attendance event');
        errors.push(`Failed to store event: ${event.event_id}`);
        continue;
      }

      if (!newEvent) {
        logger.error({ event_id: event.event_id }, 'No data returned from insert');
        errors.push(`Failed to store event: ${event.event_id}`);
        continue;
      }

      processedEvents.push({
        event_id: event.event_id,
        status: 'processed',
        db_id: newEvent.id
      });

    } catch (error) {
      logger.error({ event_id: event.event_id, error: String(error) }, 'Error processing event');
      errors.push(`Error processing event ${event.event_id}: ${error}`);
    }
  }
}

async function insertAttendanceEvents(
  validEvents: AttendanceEventInsert[],
  gymSchema: string
): Promise<EventProcessingResult> {
  const processedEvents: ProcessedEventResult[] = [];
  const errors: string[] = [];

  if (validEvents.length === 0) {
    return { processedEvents, errors };
  }

  try {
    const { data: newEvents, error: insertError } = await supabase
      .schema(gymSchema)
      .from('attendance_events')
      .insert(validEvents)
      .select('id, event_id');

    if (insertError) {
      logger.warn({ insertError }, 'Batch insert failed, falling back to individual inserts');
      await processEventsIndividually(validEvents, gymSchema, processedEvents, errors);
      return { processedEvents, errors };
    }

    if (newEvents) {
      for (const newEvent of newEvents) {
        processedEvents.push({
          event_id: newEvent.event_id,
          status: 'processed',
          db_id: newEvent.id
        });
      }
      logger.debug({ count: newEvents.length }, 'Successfully batch inserted events');
    }
  } catch (error) {
    logger.error({ error: String(error) }, 'Error in batch processing, falling back to individual inserts');
    await processEventsIndividually(validEvents, gymSchema, processedEvents, errors);
  }

  return { processedEvents, errors };
}

function buildWebhookResponse(
  tenant: string,
  received: number,
  processingResult: EventProcessingResult,
  provider: Provider
) {
  return {
    ok: true,
    tenant,
    provider,
    received,
    processed: processingResult.processedEvents.filter((event) => event.status === 'processed').length,
    duplicates: processingResult.processedEvents.filter((event) => event.status === 'duplicate').length,
    errors: processingResult.errors.length,
    error_details: processingResult.errors.length > 0 ? processingResult.errors : undefined
  };
}

// Create Express app
const app = express();

// Middleware to parse raw body for HMAC verification
app.use('/webhook/:tenant', express.raw({ type: 'application/json', limit: '10mb' }));

// Health check endpoint
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ZKTeco webhook endpoint (backward compatible route)
app.post('/webhook/:tenant', async (req, res) => {
  const tenant = req.params.tenant;
  const branchId = getBranchId(req.query.branch_id as string | undefined);
  const body = getRawBody(req.body);
  
  logger.info({ tenant, branchId, bodyLength: body.length }, 'Received webhook request');

  try {
    // Validate branch_id is provided
    if (!branchId) {
      logger.error({ tenant }, 'Missing required branch_id query parameter');
      return res.status(400).json({ error: 'Missing required query parameter: branch_id' });
    }

    // Verify HMAC signature
    const signature = req.headers['x-signature'] as string;
    if (!signature) {
      logger.error('Missing HMAC signature header');
      return res.status(401).json({ error: 'Missing signature header' });
    }

    const gymConfig = await getGymProviderSecret(tenant, 'zk_webhook_secret');
    if (!gymConfig) {
      return res.status(401).json({ error: 'Invalid tenant or webhook secret not configured' });
    }

    // Verify HMAC signature
    if (!verifyHmacSignature(body, signature, gymConfig.secret)) {
      logger.error({ tenant }, 'Invalid HMAC signature');
      return res.status(401).json({ error: 'Invalid signature' });
    }

    // Parse JSON payload
    let payload: ZKWebhookPayload;
    try {
      payload = JSON.parse(body);
    } catch (error) {
      logger.error({ error: String(error) }, 'Invalid JSON payload');
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

    if (!payload.data || !Array.isArray(payload.data)) {
      return res.status(400).json({ error: 'Invalid payload structure' });
    }

    const gymSchema = `gym_${tenant}`;

    // Validate and prepare events for batch processing
    const validEvents: AttendanceEventInsert[] = [];
    for (const event of payload.data) {
      if (!validateZKEvent(event)) {
        logger.warn({ event_id: event.event_id }, 'Invalid event data');
        continue;
      }
      validEvents.push(mapZKToDatabase(event, branchId));
    }

    const processingResult = await insertAttendanceEvents(validEvents, gymSchema);
    const response = buildWebhookResponse(tenant, payload.data.length, processingResult, 'zk');

    logger.info(response, 'Webhook processing completed');
    return res.json(response);

  } catch (error) {
    logger.error({ tenant, error }, 'Webhook processing error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// HikCentral webhook endpoint
app.post('/webhook/:tenant/hikcentral', async (req, res) => {
  const tenant = req.params.tenant;
  const branchId = getBranchId(req.query.branch_id as string | undefined);
  const body = getRawBody(req.body);

  logger.info({ tenant, branchId, bodyLength: body.length }, 'Received HikCentral webhook request');

  try {
    if (!branchId) {
      logger.error({ tenant }, 'Missing required branch_id query parameter');
      return res.status(400).json({ error: 'Missing required query parameter: branch_id' });
    }

    const gym = await getGymBySubdomain(tenant);
    if (!gym) {
      return res.status(401).json({ error: 'Invalid tenant' });
    }

    let payload: HikWebhookPayload;
    try {
      payload = JSON.parse(body);
    } catch (error) {
      logger.error({ error: String(error) }, 'Invalid HikCentral JSON payload');
      return res.status(400).json({ error: 'Invalid JSON payload' });
    }

    if (
      payload.method !== 'OnEventNotify' ||
      !payload.params ||
      !Array.isArray(payload.params.events)
    ) {
      return res.status(400).json({ error: 'Invalid HikCentral payload structure' });
    }

    const gymSchema = `gym_${tenant}`;
    const validEvents: AttendanceEventInsert[] = [];
    const skippedEventIds: string[] = [];

    for (const event of payload.params.events) {
      if (!validateHikEvent(event)) {
        skippedEventIds.push(event.eventId || 'unknown');
        continue;
      }

      if (event.data?.checkInAndOutType !== undefined) {
        logger.debug(
          { eventId: event.eventId, checkInAndOutType: event.data.checkInAndOutType },
          'HikCentral event includes check in/out marker'
        );
      }

      validEvents.push(mapHikToDatabase(event, branchId));
    }

    const processingResult = await insertAttendanceEvents(validEvents, gymSchema);
    for (const skipped of skippedEventIds) {
      processingResult.errors.push(`Skipped unsupported or invalid HikCentral event: ${skipped}`);
    }

    const response = buildWebhookResponse(
      tenant,
      payload.params.events.length,
      processingResult,
      'hikcentral'
    );
    logger.info(response, 'HikCentral webhook processing completed');
    return res.json(response);
  } catch (error) {
    logger.error({ tenant, error }, 'HikCentral webhook processing error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, () => {
  logger.info({ port: PORT }, 'Webhook server started');
  logger.info('Endpoints:');
  logger.info(`  POST /webhook/:tenant - Process ZK events for tenant`);
  logger.info(`  POST /webhook/:tenant/hikcentral - Process HikCentral access events for tenant`);
  logger.info(`  GET /health - Health check`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('Shutting down webhook server...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  logger.info('Shutting down webhook server...');
  process.exit(0);
});