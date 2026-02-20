const engine = require('../engine');
const policy = require('../policy');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Non-blocking Hash-Chained Audit Queue
const auditStream = fs.createWriteStream(path.join(process.cwd(), 'civicshield-audit.log'), { flags: 'a' });
const auditQueue = [];
let isFlushingAudit = false;
let lastAuditHash = crypto.createHash('sha256').update('CIVICSHIELD_GENESIS_BLOCK').digest('hex');

auditStream.on('error', (err) => {
  console.error('[CRITICAL] Audit stream failure:', err.message);
});

async function flushAuditQueue() {
  if (isFlushingAudit || auditQueue.length === 0) return;
  isFlushingAudit = true;

  while (auditQueue.length > 0) {
    const entry = auditQueue.shift();
    const payloadStr = JSON.stringify(entry);
    const entryHash = crypto.createHash('sha256').update(lastAuditHash + payloadStr).digest('hex');
    
    const chainedEntry = {
      ...entry,
      previousHash: lastAuditHash,
      hash: entryHash
    };
    
    lastAuditHash = entryHash;
    const logLine = JSON.stringify(chainedEntry) + '\n';

    if (auditStream && !auditStream.destroyed) {
      const canWrite = auditStream.write(logLine);
      if (!canWrite) {
        await new Promise(resolve => auditStream.once('drain', resolve));
      }
    } else {
      console.error('[CRITICAL] Audit stream broken. Dropped log:', logLine.trim());
    }
  }
  
  isFlushingAudit = false;
}

const logAudit = (action, ip, details) => {
  auditQueue.push({ timestamp: new Date().toISOString(), action, ip, details });
  setImmediate(flushAuditQueue);
};

const adminRateLimits = new Map();
const ADMIN_BUCKET_CAPACITY = 60;
const ADMIN_REFILL_RATE = 1; 

const usedNonces = new Map();
const NONCE_TTL_MS = 60000;
const MAX_NONCE_CACHE = 100000; 

setInterval(() => {
  const now = Date.now();
  for (const [nonce, timestamp] of usedNonces.entries()) {
    if (now - timestamp > NONCE_TTL_MS) usedNonces.delete(nonce);
  }
  for (const [ip, bucket] of adminRateLimits.entries()) {
    if (now - bucket.last > (ADMIN_BUCKET_CAPACITY / ADMIN_REFILL_RATE) * 1000) {
      adminRateLimits.delete(ip);
    }
  }
}, 30000).unref();

const IPV4_REGEX = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)){3}$/;

module.exports = async function adminRoutes(fastify) {
  
  // Capture Raw Buffer for Cryptographically Perfect HMAC
  fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
    req.rawBody = body;
    if (body.length === 0) {
      return done(null, {});
    }
    try {
      const json = JSON.parse(body.toString('utf8'));
      done(null, json);
    } catch (err) {
      err.statusCode = 400;
      done(err, undefined);
    }
  });

  fastify.addHook('onRequest', async (request, reply) => {
    const now = Date.now();
    const ip = request.ip;

    let bucket = adminRateLimits.get(ip);
    if (!bucket) {
      bucket = { tokens: ADMIN_BUCKET_CAPACITY, last: now };
      adminRateLimits.set(ip, bucket);
    }

    const deltaSec = (now - bucket.last) / 1000;
    if (deltaSec > 0) {
      bucket.tokens = Math.min(ADMIN_BUCKET_CAPACITY, bucket.tokens + deltaSec * ADMIN_REFILL_RATE);
      bucket.last = now;
    }

    bucket.tokens -= 1;
    if (bucket.tokens < 0) {
      logAudit('RATE_LIMIT_EXCEEDED', ip, { path: request.url });
      return reply.code(429).send({ error: 'Too Many Requests', message: 'Control plane rate limit exceeded' });
    }
  });

  fastify.addHook('preHandler', async (request, reply) => {
    const now = Date.now();
    const ip = request.ip;
    
    const reqTimestamp = parseInt(request.headers['x-admin-timestamp'], 10);
    const reqNonce = request.headers['x-admin-nonce'];
    const reqSignature = request.headers['x-admin-signature'];
    const expectedKey = process.env.ADMIN_KEY || '';

    try {
      if (Buffer.from(expectedKey, 'base64').length < 32) {
        logAudit('SYSTEM_ERROR', ip, { reason: 'ADMIN_KEY entropy < 256-bit base64' });
        return reply.code(500).send({ error: 'Internal Server Error', message: 'Control plane misconfigured' });
      }
    } catch (e) {
      logAudit('SYSTEM_ERROR', ip, { reason: 'ADMIN_KEY is not valid base64' });
      return reply.code(500).send({ error: 'Internal Server Error', message: 'Control plane misconfigured' });
    }

    if (!reqTimestamp || !reqNonce || !reqSignature || isNaN(reqTimestamp)) {
      logAudit('AUTH_FAILURE', ip, { reason: 'Missing cryptographic headers' });
      return reply.code(401).send({ error: 'Unauthorized', message: 'Missing required security headers' });
    }

    if (Math.abs(now - reqTimestamp) > NONCE_TTL_MS) {
      logAudit('REPLAY_REJECTION', ip, { reason: 'Timestamp expired', delta: now - reqTimestamp });
      return reply.code(401).send({ error: 'Unauthorized', message: 'Request window expired' });
    }

    if (usedNonces.has(reqNonce)) {
      logAudit('REPLAY_REJECTION', ip, { reason: 'Nonce reused', nonce: reqNonce });
      return reply.code(401).send({ error: 'Unauthorized', message: 'Cryptographic nonce already used' });
    }

    if (usedNonces.size >= MAX_NONCE_CACHE) {
      logAudit('SYSTEM_PROTECTION', ip, { reason: 'Nonce cache capacity reached' });
      return reply.code(429).send({ error: 'Too Many Requests', message: 'Security subsystem overloaded' });
    }

    // Raw Buffer HMAC computation to prevent JSON serialization attacks
    const prefixBuffer = Buffer.from(`${reqTimestamp}:${reqNonce}:${request.method}:${request.url}:`, 'utf8');
    const rawBodyBuffer = request.raw.rawBody || Buffer.alloc(0);
    const hmacPayload = Buffer.concat([prefixBuffer, rawBodyBuffer]);
    
    const expectedSignature = crypto.createHmac('sha256', Buffer.from(expectedKey, 'base64')).update(hmacPayload).digest('hex');

    if (reqSignature.length !== expectedSignature.length || !crypto.timingSafeEqual(Buffer.from(reqSignature), Buffer.from(expectedSignature))) {
      logAudit('AUTH_FAILURE', ip, { reason: 'HMAC signature mismatch' });
      return reply.code(401).send({ error: 'Unauthorized', message: 'Invalid cryptographic signature' });
    }

    usedNonces.set(reqNonce, now);
  });

  fastify.get('/policy', async (request, reply) => {
    try {
      const snapshot = policy.getSafeSnapshot();
      return reply.code(200).send(snapshot);
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.post('/policy', {
    bodyLimit: 1048576,
    schema: {
      body: {
        type: 'object',
        additionalProperties: false,
        properties: {
          bucketSize: { type: 'integer' },
          refillRate: { type: 'integer' },
          queueTolerance: { type: 'integer' },
          staleTTLMs: { type: 'integer' },
          cleanupBatchSize: { type: 'integer' },
          cleanupIntervalMs: { type: 'integer' },
          queueDrainRate: { type: 'integer' },
          maxQueueEstimate: { type: 'integer' },
          maxTrackedIPs: { type: 'integer' },
          maxGlobalRPS: { type: 'integer' },
          rpsLimits: {
            type: 'object',
            additionalProperties: false,
            properties: {
              elevated: { type: 'integer' },
              surge: { type: 'integer' },
              critical: { type: 'integer' },
              emergency: { type: 'integer' }
            }
          }
        }
      }
    }
  }, async (request, reply) => {
    try {
      const result = policy.updatePolicy(request.body);
      
      if (!result.success) {
        logAudit('POLICY_UPDATE_FAILED', request.ip, { errors: result.errors });
        return reply.code(400).send({ error: 'Bad Request', details: result.errors });
      }

      logAudit('POLICY_UPDATED', request.ip, { newVersion: result.version });
      return reply.code(200).send({ success: true, version: result.version, timestamp: new Date().toISOString() });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.post('/policy/reset', async (request, reply) => {
    try {
      const result = policy.resetToDefault();
      logAudit('POLICY_RESET', request.ip, { newVersion: result.version });
      return reply.code(200).send({ success: true, version: result.version, timestamp: new Date().toISOString() });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.post('/trust/:ip', async (request, reply) => {
    try {
      const { ip } = request.params;
      if (!IPV4_REGEX.test(ip)) {
        return reply.code(400).send({ error: 'Bad Request', message: 'Invalid IPv4 format' });
      }

      if (typeof engine.trustIP === 'function') engine.trustIP(ip);
      
      logAudit('IP_TRUSTED', request.ip, { targetIp: ip });
      return reply.code(200).send({ success: true, ip, action: 'trusted', timestamp: new Date().toISOString() });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.delete('/trust/:ip', async (request, reply) => {
    try {
      const { ip } = request.params;
      if (!IPV4_REGEX.test(ip)) {
        return reply.code(400).send({ error: 'Bad Request', message: 'Invalid IPv4 format' });
      }

      if (typeof engine.untrustIP === 'function') engine.untrustIP(ip);
      
      logAudit('IP_UNTRUSTED', request.ip, { targetIp: ip });
      return reply.code(200).send({ success: true, ip, action: 'untrusted', timestamp: new Date().toISOString() });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.get('/engine/metrics', async (request, reply) => {
    try {
      const metrics = engine.getMetrics();
      return reply.code(200).send({
        currentRPS: metrics.currentRPS,
        avgRPS10s: metrics.avgRPS10s,
        mode: metrics.mode,
        operationalMode: metrics.operationalMode,
        queueSizeEstimate: metrics.queueSizeEstimate,
        trackedIPs: metrics.tokenBucketStats ? metrics.tokenBucketStats.totalTrackedIPs : 0,
        trustedIPsCount: metrics.trustedIPsCount || 0,
        timestamp: new Date().toISOString()
      });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });

  fastify.post('/engine/mode', {
    bodyLimit: 1048576,
    schema: {
      body: {
        type: 'object',
        required: ['mode'],
        additionalProperties: false,
        properties: {
          mode: { type: 'string', enum: ['ENFORCING', 'MONITOR'] }
        }
      }
    }
  }, async (request, reply) => {
    try {
      const { mode } = request.body;
      
      if (typeof engine.setOperationalMode === 'function') {
        engine.setOperationalMode(mode);
      }

      logAudit('ENGINE_MODE_CHANGED', request.ip, { newMode: mode });
      return reply.code(200).send({ success: true, mode, timestamp: new Date().toISOString() });
    } catch (err) {
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
  });
};
