/**
 * CivicShield Traffic Orchestration Engine
 * Adaptive, high-performance, constant-time rate limiting and traffic shaping.
 * * Architecture: Singleton, Lock-free, Lazy-evaluation, O(1) complexity, Memory-capped.
 * * Clock: performance.now() for monotonic microsecond precision (micro-burst fairness).
 */

const { performance } = require('perf_hooks');

const ALLOW_RESPONSE = Object.freeze({ action: 'ALLOW' });
const BYPASS_RESPONSE = Object.freeze({ action: 'BYPASS' });

class TrafficEngine {
  constructor() {
    this.buckets = new Map(); 
    this.trustedIPs = new Set(); // Fast-path registry for known clean IPs
    this.policy = this._getDefaultPolicy();
    this.cleanupIterator = null;
    this.cleanupTimer = null;
    this.queueDecayTimer = null;

    this.currentSecond = Math.floor(performance.now() / 1000);
    this.currentSecondCount = 0;
    this.history10s = new Int32Array(10);
    this.historyIndex = 0;
    this.total10sCount = 0;
    this.currentMode = 'NORMAL';

    this.queueSizeEstimate = 0;
    this.queueIdCounter = 0;
    
    this._startBackgroundTasks();
  }

  _getDefaultPolicy() {
    return {
      bucketSize: 100,
      refillRate: 10,
      queueTolerance: 20,
      rpsLimits: { elevated: 500, surge: 1000, critical: 2000, emergency: 5000 },
      staleTTLMs: 60000,
      cleanupBatchSize: 100,
      cleanupIntervalMs: 1000,
      queueDrainRate: 10,
      maxQueueEstimate: 50000,
      maxTrackedIPs: 100000,
      maxGlobalRPS: 10000 // Global hard cap threshold
    };
  }

  bindPolicy(newPolicy) {
    if (!newPolicy || typeof newPolicy !== 'object') return;
    this.policy = { ...this.policy, ...newPolicy };
  }

  trustIP(ip) {
    this.trustedIPs.add(ip);
  }

  untrustIP(ip) {
    this.trustedIPs.delete(ip);
  }

  handleRequest(payload) {
    try {
      if (payload.signal && payload.signal.aborted) {
        return ALLOW_RESPONSE;
      }

      const now = performance.now();
      const ip = payload.ip || 'unknown';
      
      // Micro-optimization: Cache header lookup in the hot path
      const headers = payload.headers;
      const isPriority = headers && headers['x-priority'] === 'emergency';

      this._recordRPS(now);

      if (isPriority) {
        return BYPASS_RESPONSE;
      }

      // Hardware/Backend protection: Global RPS Hard Cap
      if (this.policy.maxGlobalRPS && this.currentSecondCount > this.policy.maxGlobalRPS) {
        return { action: 'THROTTLE', retryAfter: 5 };
      }

      // Fast-path bypass for known clean IPs (O(1) Set lookup)
      if (this.trustedIPs.has(ip)) {
        return ALLOW_RESPONSE;
      }

      if (payload.signal && payload.signal.aborted) {
        return ALLOW_RESPONSE;
      }

      return this._evaluateBucket(ip, now);

    } catch (err) {
      return ALLOW_RESPONSE;
    }
  }

  _recordRPS(nowMs) {
    const nowSec = Math.floor(nowMs / 1000);
    const diff = nowSec - this.currentSecond;

    if (diff > 0) {
      if (diff >= 10) {
        this.history10s.fill(0);
        this.total10sCount = 0;
      } else {
        const iterations = Math.min(diff, 10);
        for (let i = 1; i <= iterations; i++) {
          this.historyIndex = (this.historyIndex + 1) % 10;
          this.total10sCount -= this.history10s[this.historyIndex];
          this.history10s[this.historyIndex] = 0;
        }
      }
      this.currentSecond = nowSec;
      this.currentSecondCount = 0;
      this._updateMode();
    }

    this.currentSecondCount++;
    this.history10s[this.historyIndex]++;
    this.total10sCount++;
  }

  _evaluateBucket(ip, now) {
    let bucket = this.buckets.get(ip);
    const { bucketSize, refillRate, queueTolerance, maxTrackedIPs, maxQueueEstimate } = this.policy;

    if (!bucket) {
      if (this.buckets.size >= maxTrackedIPs) {
        return { action: 'THROTTLE', retryAfter: 30 };
      }
      bucket = { tokens: bucketSize - 1, lastRefill: now };
      this.buckets.set(ip, bucket);
      return ALLOW_RESPONSE;
    }

    const deltaSec = (now - bucket.lastRefill) / 1000;
    if (deltaSec > 0) {
      const addedTokens = Math.floor(deltaSec * refillRate);
      if (addedTokens > 0) {
        bucket.tokens = Math.min(bucketSize, bucket.tokens + addedTokens);
        
        const msConsumed = (addedTokens / refillRate) * 1000;
        bucket.lastRefill += msConsumed;
      }
    }

    bucket.tokens -= 1;

    if (bucket.tokens >= 0) {
      return ALLOW_RESPONSE;
    }

    if (bucket.tokens >= -queueTolerance) {
      this.queueSizeEstimate = Math.min(this.queueSizeEstimate + 1, maxQueueEstimate);
      
      this.queueIdCounter = (this.queueIdCounter + 1) & 0x7FFFFFFF;
      const qId = `q-${Math.floor(now).toString(36)}-${this.queueIdCounter}`;
      
      return { action: 'QUEUE', queueId: qId };
    }

    bucket.tokens = Math.max(bucket.tokens, -queueTolerance - 1);
    const deficit = Math.abs(bucket.tokens);
    const retryAfter = Math.ceil(deficit / refillRate) || 1;

    return { action: 'THROTTLE', retryAfter };
  }

  _updateMode() {
    const rps = this.currentSecondCount;
    const { emergency, critical, surge, elevated } = this.policy.rpsLimits;

    if (rps >= emergency) this.currentMode = 'EMERGENCY';
    else if (rps >= critical) this.currentMode = 'CRITICAL';
    else if (rps >= surge) this.currentMode = 'SURGE';
    else if (rps >= elevated) this.currentMode = 'ELEVATED';
    else this.currentMode = 'NORMAL';
  }

  getMetrics() {
    return {
      currentRPS: this.currentSecondCount,
      avgRPS10s: Math.floor(this.total10sCount / 10),
      mode: this.currentMode,
      queueSizeEstimate: this.queueSizeEstimate,
      tokenBucketStats: {
        totalTrackedIPs: this.buckets.size,
        activeBuckets: this.buckets.size 
      },
      trustedIPsCount: this.trustedIPs.size
    };
  }

  _startBackgroundTasks() {
    this.cleanupTimer = setInterval(() => {
      this._runCleanupBatch();
    }, this.policy.cleanupIntervalMs || 1000);

    this.queueDecayTimer = setInterval(() => {
      this.queueSizeEstimate = Math.max(0, this.queueSizeEstimate - this.policy.queueDrainRate);
    }, 1000);

    if (this.cleanupTimer.unref) this.cleanupTimer.unref();
    if (this.queueDecayTimer.unref) this.queueDecayTimer.unref();
  }

  _runCleanupBatch() {
    if (this.buckets.size === 0) return;
    
    if (!this.cleanupIterator) {
      this.cleanupIterator = this.buckets.keys();
    }

    const now = performance.now();
    const { staleTTLMs, cleanupBatchSize } = this.policy;
    let processed = 0;

    while (processed < cleanupBatchSize) {
      const { value: ip, done } = this.cleanupIterator.next();
      
      if (done) {
        this.cleanupIterator = null;
        break;
      }

      const bucket = this.buckets.get(ip);
      if (bucket && (now - bucket.lastRefill) > staleTTLMs) {
        this.buckets.delete(ip);
      }
      processed++;
    }
  }

  shutdown() {
    if (this.cleanupTimer) clearInterval(this.cleanupTimer);
    if (this.queueDecayTimer) clearInterval(this.queueDecayTimer);
    this.buckets.clear();
    this.trustedIPs.clear();
    this.cleanupIterator = null;
  }
}

module.exports = new TrafficEngine();
