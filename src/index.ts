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
function mapZKToDatabase(event: ZKEvent, branchId: string) {
  return {
    event_id: event.event_id,
    turnstile_id: parseInt(event.pin),
    event_time: event.event_iso,
    result: (event.result === 'granted' || event.result === 'pass') ? 'pass' : 'fail',
    verify_mode: (event.verify_mode === 'fingerprint' || event.verify_mode === 'finger') ? 'finger' : event.verify_mode,
    device_name: event.devName,
    area_name: event.areaName,
    branch_id: branchId
  };
}

// Fallback function for individual event processing
async function processEventsIndividually(
  validEvents: any[], 
  gym_schema: string, 
  processedEvents: any[], 
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
  const branchId = req.query.branch_id as string | undefined;
  const body = req.body.toString('utf8');
  
  logger.info({ tenant, branchId, bodyLength: body.length }, 'Received webhook request');

  try {
    // Validate branch_id is provided
    if (!branchId || branchId.trim() === '') {
      logger.error({ tenant }, 'Missing required branch_id query parameter');
      return res.status(400).json({ error: 'Missing required query parameter: branch_id' });
    }

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

    // Validate and prepare events for batch processing
    const validEvents = [];
    for (const event of payload.data) {
      if (!validateZKEvent(event)) {
        logger.warn({ event_id: event.event_id }, 'Invalid event data');
        errors.push(`Invalid event data for event_id: ${event.event_id}`);
        continue;
      }
      validEvents.push(mapZKToDatabase(event, branchId));
    }

    // Batch insert all valid events
    if (validEvents.length > 0) {
      try {
        const { data: newEvents, error: insertError } = await supabase
          .schema(gym_schema)
          .from('attendance_events')
          .insert(validEvents)
          .select('id, event_id');

        if (insertError) {
          // If batch insert fails, fall back to individual inserts
          logger.warn({ insertError }, 'Batch insert failed, falling back to individual inserts');
          await processEventsIndividually(validEvents, gym_schema, processedEvents, errors);
        } else if (newEvents) {
          // All events inserted successfully
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
        await processEventsIndividually(validEvents, gym_schema, processedEvents, errors);
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