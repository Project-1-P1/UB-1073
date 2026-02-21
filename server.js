/**
 * CivicShield Server Infrastructure
 * Enterprise-grade server configuration for high concurrency,
 * resilience, load shedding, and production observability.
 */
require('dotenv').config();

const fastify = require('fastify');
const helmet = require('@fastify/helmet');
const cors = require('@fastify/cors');
const crypto = require('crypto');
const { monitorEventLoopDelay } = require('perf_hooks');

// 1. Startup Safety & Configuration Validation
const REQUIRED_ENV = ['NODE_ENV', 'METRICS_KEY'];

for (const envVar of REQUIRED_ENV) {
  if (!process.env[envVar]) {
    console.error(`[FATAL] Startup aborted. Missing required environment variable: ${envVar}`);
    process.exit(1);
  }
}

// 2. Framework Initialization & Security Hardening
const app = fastify({
  logger: {
    level: process.env.LOG_LEVEL || 'info',
    formatters: {
      level: (label) => ({ level: label.toUpperCase() }),
    },
    redact: ['req.headers.authorization', 'req.headers.cookie']
  },
  trustProxy: true,
  bodyLimit: 1048576, // 1MB strict limit
  connectionTimeout: 5000,
  keepAliveTimeout: 5000,
  maxParamLength: 2048,
  genReqId: () => crypto.randomUUID(),
});

// 3. Resilience Monitors & Engine State
const eldHistogram = monitorEventLoopDelay({ resolution: 20 });
eldHistogram.enable();

// Tightened 5-second window for highly accurate burst detection
setInterval(() => {
  eldHistogram.reset();
}, 5000).unref();

const ENGINE_TIMEOUT_MS = parseInt(process.env.ENGINE_TIMEOUT_MS, 10) || 250;
const MAX_ENGINE_FAILURES = parseInt(process.env.MAX_ENGINE_FAILURES, 10) || 5;
const RECOVERY_TIMEOUT_MS = parseInt(process.env.RECOVERY_TIMEOUT_MS, 10) || 60000;
const MAX_CONCURRENT_REQUESTS = parseInt(process.env.MAX_CONCURRENT_REQUESTS, 10) || 5000;

let activeRequests = 0;

const engineState = {
  status: 'HEALTHY', // HEALTHY | DEGRADED | HALF_OPEN
  mode: 'ENFORCING',
  consecutiveFailures: 0,
  lastFailureTime: null,
};

// 4. Engine & Policy Integration
const engine = require('./engine');
const policy = require('./policy');

// ✅ CHANGED: Fixed route imports for flat directory structure
const adminRoutes = require('./admin');
const serviceRoutes = require('./service');

try {
  engine.bindPolicy(policy);
} catch (err) {
  app.log.error({ err }, '[FATAL] Failed to bind policy to engine');
  process.exit(1);
}

app.register(helmet, { global: true });

// 🔥 EXACT FIX APPLIED HERE
app.register(cors, {
  origin: true, // allow all origins for demo
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-metrics-key'],
});

// Helper: Hardware/Process Overload Guard
const isSystemOverloaded = () => {
  const mem = process.memoryUsage();
  const heapRatio = mem.heapUsed / mem.heapTotal;
  const eventLoopLagMs = eldHistogram.percentile(99) / 1e6;
  return heapRatio > 0.85 || eventLoopLagMs > 150 || activeRequests >= MAX_CONCURRENT_REQUESTS;
};

// 5. Explicitly Named Hooks for Concurrency Tracking
const requestCounterHook = async () => {
  activeRequests++;
};

const responseCounterHook = async () => {
  // Clamped to prevent negative counts during catastrophic socket drops
  activeRequests = Math.max(activeRequests - 1, 0);
};

// 6. Traffic Orchestration & Protection Hook
/**
 * ARCHITECTURE PRIORITY:
 * Hardware Protection (Load Shedding - 503): Drop traffic if memory/CPU/concurrency is exhausted.
 * Subsystem Protection (Circuit Breaker - Pass-through): If hardware is fine but engine is failing,
 * bypass the engine to maintain partial system availability.
 */
const engineOrchestrationHook = async (request, reply) => {
  if (['/health', '/ready', '/metrics'].includes(request.routeOptions.url)) return;

  // PRIORITY 1: Hardware Load Shedding
  if (isSystemOverloaded()) {
    app.log.warn({ reqId: request.id, activeRequests }, 'Load shedding active. System overloaded.');
    return reply.code(503).send({
      error: 'Service Unavailable',
      message: 'System is currently at maximum capacity. Please try again later.'
    });
  }

  // PRIORITY 2: Circuit Breaker Recovery & Bypass
  if (engineState.status === 'DEGRADED') {
    const timeSinceFailure = Date.now() - engineState.lastFailureTime;
    if (timeSinceFailure > RECOVERY_TIMEOUT_MS) {
      engineState.status = 'HALF_OPEN';
      app.log.info('Circuit breaker HALF_OPEN. Testing recovery.');
    } else {
      return; // Fast pass-through mode while fully degraded
    }
  }

  const abortController = new AbortController();
  const requestPayload = {
    id: request.id,
    ip: request.ip,
    headers: request.headers,
    url: request.url,
    method: request.method,
    timestamp: Date.now(),
    signal: abortController.signal // Engine MUST check signal.aborted cooperatively
  };

  let timeoutId;
  try {
    const enginePromise = engine.handleRequest(requestPayload);
    const timeoutPromise = new Promise((_, reject) => {
      timeoutId = setTimeout(() => {
        abortController.abort();
        reject(new Error('ENGINE_TIMEOUT'));
      }, ENGINE_TIMEOUT_MS);
    });

    const decision = await Promise.race([enginePromise, timeoutPromise]);  
    clearTimeout(timeoutId);   

    // Healing phase  
    if (engineState.status === 'HALF_OPEN') {  
      engineState.status = 'HEALTHY';  
      engineState.consecutiveFailures = 0;  
      app.log.info('Circuit breaker CLOSED. Engine recovered.');  
    } else if (engineState.consecutiveFailures > 0) {  
      engineState.consecutiveFailures = 0;  
    }  

    switch (decision.action) {  
      case 'THROTTLE':  
        return reply.code(429).send({ error: 'Too Many Requests', retryAfter: decision.retryAfter || 60 });  
      case 'QUEUE':  
        return reply.code(202).send({ status: 'Accepted', queueId: decision.queueId });  
      case 'ALLOW':  
      case 'BYPASS':  
      default:  
        break; // Continue to route execution  
    }  
  } catch (err) {
    clearTimeout(timeoutId);
    engineState.consecutiveFailures += 1;  
    engineState.lastFailureTime = Date.now();  
      
    app.log.error({ err: err.message, reqId: request.id }, 'Engine execution error or timeout');  

    if (engineState.consecutiveFailures >= MAX_ENGINE_FAILURES && engineState.status !== 'DEGRADED') {  
      engineState.status = 'DEGRADED';  
      app.log.fatal('Circuit breaker OPEN. System switched to DEGRADED pass-through mode.');  
    }  
  }
};

// Register Hooks Explicitly in Order
app.addHook('onRequest', requestCounterHook);
app.addHook('onRequest', engineOrchestrationHook);
app.addHook('onResponse', responseCounterHook);

// 7. PreHandler Hardening
app.addHook('preHandler', async (request, reply) => {
  if (request.url.length > 2048) {
    return reply.code(414).send({ error: 'URI Too Long' });
  }
  if (Object.keys(request.headers).length > 50) {
    return reply.code(431).send({ error: 'Request Header Fields Too Large' });
  }
  const contentType = request.headers['content-type'];
  if (request.method === 'POST' && contentType && !contentType.includes('application/json')) {
    return reply.code(415).send({ error: 'Unsupported Media Type' });
  }
});

// 8. Production Observability Routes
app.get('/health', async () => ({ status: 'OK', uptime: process.uptime() }));

app.get('/ready', async (request, reply) => {
  const isReady = engineState.status !== 'OFFLINE' && !isSystemOverloaded();
  if (!isReady) {
    return reply.code(503).send({ status: 'UNAVAILABLE', component: 'infrastructure' });
  }
  return { status: 'READY' };
});

app.get('/metrics', async (request, reply) => {
  if (request.headers['x-metrics-key'] !== process.env.METRICS_KEY) {
    return reply.code(401).send({ error: 'Unauthorized' });
  }
  const mem = process.memoryUsage();
  const metrics = typeof engine.getMetrics === 'function' ? engine.getMetrics() : {};
  
  if (metrics.mode) {
    engineState.mode = metrics.mode;
  }
  
  return {
    system: {
      activeRequests,
      heapUsagePercent: ((mem.heapUsed / mem.heapTotal) * 100).toFixed(2),
      eventLoopLagP99Ms: (eldHistogram.percentile(99) / 1e6).toFixed(2),
    },
    engine: {
      rps: metrics.currentRPS || 0,
      mode: engineState.mode,
      circuitBreakerStatus: engineState.status,
      queueSize: metrics.queueSize || 0,
    },
    timestamp: new Date().toISOString()
  };
});

// Route Mounting
app.register(adminRoutes, { prefix: '/admin' });
app.register(serviceRoutes, { prefix: '/service' });

// Global Error Handling
app.setErrorHandler((error, request, reply) => {
  if (error.validation) {
    return reply.code(400).send({ error: 'Bad Request', details: error.validation });
  }
  app.log.error({ err: error, reqId: request.id }, 'Unhandled Route Exception');
  const isProduction = process.env.NODE_ENV === 'production';
  const statusCode = error.statusCode || 500;
  
  reply.code(statusCode).send({
    error: statusCode >= 500 ? 'Internal Server Error' : error.message,
    ...( !isProduction && { stack: error.stack } )
  });
});

// Graceful Shutdown
const shutdown = async (signal) => {
  app.log.info(`Received ${signal}. Initiating graceful shutdown...`);
  try {
    eldHistogram.disable();
    await app.close();
    if (typeof engine.shutdown === 'function') await engine.shutdown();
    process.exit(0);
  } catch (err) {
    app.log.error({ err }, 'Exception occurred during graceful shutdown');
    process.exit(1);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

// Startup Invocation
const start = async () => {
  try {
    const port = process.env.PORT || 3000;
    await app.listen({ port, host: '0.0.0.0' });
    app.log.info(`Shield Node Active on port ${port}. Breaker: ${engineState.status}`);
  } catch (err) {
    app.log.fatal({ err }, 'Network bind failed');
    process.exit(1);
  }
};

start();
