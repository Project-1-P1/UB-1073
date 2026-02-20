const engine = require('./engine');
const policy = require('./policy');

const SLOW_RESPONSE_THRESHOLD_MS = parseInt(process.env.SLOW_RESPONSE_THRESHOLD_MS, 10) || 500;

const formatError = (code, error, message, request, mode) => ({
  error,
  message,
  requestId: request.id,
  timestamp: new Date().toISOString(),
  mode: mode || 'UNKNOWN'
});

module.exports = async function serviceRoutes(fastify) {

  fastify.addHook('onRequest', async (request, reply) => {
    if (request.url.length > 2048) {
      return reply.code(414).send(formatError(414, 'URI Too Long', 'The requested URI exceeds the maximum allowed length', request, engine.getMetrics().mode));
    }

    if (Object.keys(request.headers).length > 50) {  
      return reply.code(431).send(formatError(431, 'Request Header Fields Too Large', 'The number of headers exceeds the maximum allowed', request, engine.getMetrics().mode));  
    }
  });

  fastify.addHook('preHandler', async (request, reply) => {
    const metrics = engine.getMetrics();
    const currentPolicy = policy.getPolicy();

    reply.header('X-Engine-Mode', metrics.mode);  
    reply.header('X-Queue-Size', metrics.queueSizeEstimate.toString());  

    if (request.method === 'POST') {  
      const contentType = request.headers['content-type'];  
      if (!contentType || !contentType.includes('application/json')) {  
        return reply.code(415).send(formatError(415, 'Unsupported Media Type', 'Expected application/json', request, metrics.mode));  
      }  
    }  

    if (metrics.mode === 'EMERGENCY') {  
      if (metrics.operationalMode === 'MONITOR') {  
        request.log.warn({ reqId: request.id, ip: request.ip }, 'MONITOR: Would reject (EMERGENCY mode)');  
      } else {  
        request.log.warn({ reqId: request.id, ip: request.ip }, 'Service rejected: System in EMERGENCY mode');  
        reply.header('Retry-After', '30');  
        reply.header('X-RateLimit-Remaining', '0');  
        return reply.code(503).send(formatError(503, 'Service Unavailable', 'System is currently at maximum capacity', request, metrics.mode));  
      }  
    }  

    if (metrics.queueSizeEstimate > currentPolicy.maxQueueEstimate) {  
      if (metrics.operationalMode === 'MONITOR') {  
        request.log.warn({ reqId: request.id, ip: request.ip, queueSize: metrics.queueSizeEstimate }, 'MONITOR: Would reject (Queue capacity exceeded)');  
      } else {  
        request.log.warn({ reqId: request.id, ip: request.ip, queueSize: metrics.queueSizeEstimate }, 'Service rejected: Queue capacity exceeded');  
        reply.header('Retry-After', '60');  
        reply.header('X-RateLimit-Remaining', '0');  
        return reply.code(429).send(formatError(429, 'Too Many Requests', 'Maximum queue capacity reached', request, metrics.mode));  
      }  
    }
  });

  fastify.addHook('onResponse', async (request, reply) => {
    const responseTime = reply.getResponseTime();

    if (responseTime > SLOW_RESPONSE_THRESHOLD_MS) {  
      request.log.warn({  
        reqId: request.id,  
        ip: request.ip,  
        url: request.url,  
        responseTimeMs: responseTime  
      }, `Slow response detected (> ${SLOW_RESPONSE_THRESHOLD_MS}ms)`);  
    }  

    if (process.env.NODE_ENV !== 'production' || reply.statusCode >= 400) {  
      request.log.info({  
        reqId: request.id,  
        ip: request.ip,  
        method: request.method,  
        url: request.url,  
        statusCode: reply.statusCode,  
        responseTimeMs: responseTime  
      }, 'Service request completed');  
    }
  });

  fastify.get('/status', async (request, reply) => {
    return reply.code(200).send({
      status: 'OK',
      message: 'CivicShield Service Active',
      timestamp: new Date().toISOString()
    });
  });

  fastify.get('/stats', async (request, reply) => {
    const metrics = engine.getMetrics();
    return reply.code(200).send({
      rps: metrics.currentRPS,
      avgRps10s: metrics.avgRPS10s,
      mode: metrics.mode,
      operationalMode: metrics.operationalMode,
      queueSize: metrics.queueSizeEstimate,
      trackedIPs: metrics.tokenBucketStats ? metrics.tokenBucketStats.totalTrackedIPs : 0
    });
  });

  fastify.post('/simulate', {
    schema: {
      body: {
        type: 'object',
        required: ['payloadSize', 'artificialDelayMs'],
        properties: {
          payloadSize: { type: 'integer', minimum: 0, maximum: 1048576 },
          artificialDelayMs: { type: 'integer', minimum: 0, maximum: 10000 }
        },
        additionalProperties: false
      }
    },
    bodyLimit: 1048576
  }, async (request, reply) => {
    const { artificialDelayMs } = request.body;

    if (artificialDelayMs > 0) {  
      await new Promise(resolve => setTimeout(resolve, artificialDelayMs));  
    }  

    const metrics = engine.getMetrics();  
      
    return reply.code(200).send({  
      accepted: true,  
      simulatedDelay: artificialDelayMs,  
      policyVersion: policy.getVersion(),  
      engineMode: metrics.mode,  
      operationalMode: metrics.operationalMode,  
      requestId: request.id,  
      timestamp: new Date().toISOString()  
    });
  });
};
