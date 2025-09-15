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

// Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: { persistSession: false }
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
function mapZKToDatabase(event: ZKEvent) {
  return {
    event_id: event.event_id,
    turnstile_id: parseInt(event.pin),
    event_time: event.event_iso,
    result: (event.result === 'granted' || event.result === 'pass') ? 'pass' : 'fail',
    verify_mode: (event.verify_mode === 'fingerprint' || event.verify_mode === 'finger') ? 'finger' : event.verify_mode,
    device_name: event.devName,
    area_name: event.areaName
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

// Main webhook endpoint
app.post('/webhook/:tenant', async (req, res) => {
  const tenant = req.params.tenant;
  const body = req.body.toString('utf8');

  console.log('Received webhook request', tenant, body);
  
  logger.info({ tenant }, 'Received webhook request');

  try {
    // Verify HMAC signature
    const signature = req.headers['x-signature'] as string;
    if (!signature) {
      logger.error('Missing HMAC signature header');
      return res.status(401).json({ error: 'Missing signature header' });
    }

    // Get gym's webhook secret from database
    const { data: gym, error: gymError } = await supabase
      .from('gyms')
      .select('gym_id, zk_webhook_secret')
      .eq('subdomain', tenant)
      .single();

    if (gymError || !gym) {
      logger.error({ tenant, error: gymError }, 'Gym not found');
      return res.status(401).json({ error: 'Invalid tenant' });
    }

    if (!gym.zk_webhook_secret) {
      logger.error({ tenant }, 'No webhook secret configured');
      return res.status(401).json({ error: 'Webhook secret not configured' });
    }

    // Verify HMAC signature
    if (!verifyHmacSignature(body, signature, gym.zk_webhook_secret)) {
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

    const gym_schema = `gym_${tenant}`;
    const processedEvents: Array<{ event_id: string; status: string; message?: string; db_id?: number }> = [];
    const errors: string[] = [];

    // Process each event
    for (const event of payload.data) {
      try {
        // Validate event data
        if (!validateZKEvent(event)) {
          logger.warn({ event_id: event.event_id }, 'Invalid event data');
          errors.push(`Invalid event data for event_id: ${event.event_id}`);
          continue;
        }

        // Check if event already exists (idempotency)
        const { data: existingEvent } = await supabase
          .schema(gym_schema)
          .from('attendance_events')
          .select('id')
          .eq('event_id', event.event_id)
          .single();

        if (existingEvent) {
          logger.debug({ event_id: event.event_id }, 'Event already processed');
          processedEvents.push({
            event_id: event.event_id,
            status: 'duplicate',
            message: 'Event already processed'
          });
          continue;
        }

        // Store raw attendance event (database trigger will handle the rest)
        const { data: newEvent, error: insertError } = await supabase
          .schema(gym_schema)
          .from('attendance_events')
          .insert(mapZKToDatabase(event))
          .select('id')
          .single();

        if (insertError || !newEvent) {
          logger.error({ event_id: event.event_id, insertError }, 'Error inserting attendance event');
          errors.push(`Failed to store event: ${event.event_id}`);
          continue;
        }

        processedEvents.push({
          event_id: event.event_id,
          status: 'processed',
          db_id: newEvent.id
        });

        logger.debug({ 
          event_id: event.event_id, 
          turnstile_id: event.pin,
          db_id: newEvent.id 
        }, 'Successfully inserted attendance event');

      } catch (error) {
        logger.error({ event_id: event.event_id, error: String(error) }, 'Error processing event');
        errors.push(`Error processing event ${event.event_id}: ${error}`);
      }
    }

    // Return response
    const response = {
      ok: true,
      tenant,
      received: payload.data.length,
      processed: processedEvents.filter(e => e.status === 'processed').length,
      duplicates: processedEvents.filter(e => e.status === 'duplicate').length,
      errors: errors.length,
      error_details: errors.length > 0 ? errors : undefined
    };

    logger.info(response, 'Webhook processing completed');
    return res.json(response);

  } catch (error) {
    logger.error({ tenant, error }, 'Webhook processing error');
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Start server
app.listen(PORT, () => {
  logger.info({ port: PORT }, 'Webhook server started');
  logger.info('Endpoints:');
  logger.info(`  POST /webhook/:tenant - Process ZK events for tenant`);
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