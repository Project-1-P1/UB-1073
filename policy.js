/**
 * CivicShield Policy Manager
 * Enterprise-grade, purely synchronous, deeply frozen, and defensively validated
 * policy configuration for the traffic orchestration engine.
 * * Architecture: Singleton, Reactive (Pub/Sub), Immutable, Deterministic.
 */

const SAFE_DEFAULTS = Object.freeze({
  bucketSize: 100,
  refillRate: 10,
  queueTolerance: 20,
  rpsLimits: Object.freeze({
    elevated: 500,
    surge: 1000,
    critical: 2000,
    emergency: 5000
  }),
  staleTTLMs: 60000,
  cleanupBatchSize: 100,
  cleanupIntervalMs: 1000,
  queueDrainRate: 10,
  maxQueueEstimate: 50000,
  maxTrackedIPs: 100000,
  maxGlobalRPS: 10000
});

const WHITELISTED_KEYS = new Set(Object.keys(SAFE_DEFAULTS));
const WHITELISTED_RPS_KEYS = new Set(Object.keys(SAFE_DEFAULTS.rpsLimits));

class PolicyManager {
  constructor() {
    this._version = 0;
    this._policy = null;
    this._listeners = new Set();
    this.resetToDefault();
  }

  /**
   * Internal helper to deeply freeze objects to prevent external mutation.
   * Includes WeakSet guard against circular references.
   */
  _deepFreeze(object, seen = new WeakSet()) {
    if (seen.has(object)) return object;
    seen.add(object);

    const propNames = Object.keys(object);
    for (const name of propNames) {
      const value = object[name];
      if (value && typeof value === 'object') {
        this._deepFreeze(value, seen);
      }
    }
    return Object.freeze(object);
  }

  /**
   * Internal helper to safely clone and merge without prototype pollution.
   */
  _safeMerge(base, candidate) {
    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return base;
    }

    const merged = Object.create(null);
    
    for (const key of WHITELISTED_KEYS) {
      if (key === 'rpsLimits') {
        merged.rpsLimits = Object.create(null);
        const baseLimits = base.rpsLimits || {};
        const candidateLimits = candidate.rpsLimits || {};
        
        for (const limitKey of WHITELISTED_RPS_KEYS) {
          merged.rpsLimits[limitKey] = candidateLimits[limitKey] !== undefined 
            ? candidateLimits[limitKey] 
            : baseLimits[limitKey];
        }
      } else {
        merged[key] = candidate[key] !== undefined ? candidate[key] : base[key];
      }
    }
    
    return merged;
  }

  /**
   * Reactive pattern: Subscribe to atomic policy updates.
   */
  subscribe(listener) {
    if (typeof listener === 'function') {
      this._listeners.add(listener);
    }
  }

  /**
   * Reactive pattern: Unsubscribe from updates.
   */
  unsubscribe(listener) {
    this._listeners.delete(listener);
  }

  /**
   * Pushes the new frozen policy memory reference to all listeners.
   */
  _notifyListeners() {
    for (const listener of this._listeners) {
      try {
        listener(this._policy);
      } catch (err) {
        // Fail-safe: A broken listener must never crash the policy manager
      }
    }
  }

  /**
   * Validates a complete policy object. Returns structured validation result.
   */
  validatePolicy(candidate) {
    const errors = [];

    if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
      return { valid: false, errors: ['Candidate policy must be a valid JSON object.'] };
    }

    if (!Number.isInteger(candidate.bucketSize) || candidate.bucketSize <= 0) errors.push('bucketSize must be an integer > 0');
    if (!Number.isInteger(candidate.refillRate) || candidate.refillRate <= 0) errors.push('refillRate must be an integer > 0');
    if (!Number.isInteger(candidate.queueTolerance) || candidate.queueTolerance < 0) errors.push('queueTolerance must be an integer >= 0');
    if (!Number.isInteger(candidate.staleTTLMs) || candidate.staleTTLMs <= 0) errors.push('staleTTLMs must be an integer > 0');
    
    if (!Number.isInteger(candidate.cleanupBatchSize) || candidate.cleanupBatchSize <= 0 || candidate.cleanupBatchSize > 10000) {
      errors.push('cleanupBatchSize must be an integer between 1 and 10000');
    }
    
    if (!Number.isInteger(candidate.cleanupIntervalMs) || candidate.cleanupIntervalMs <= 0) errors.push('cleanupIntervalMs must be an integer > 0');
    if (!Number.isInteger(candidate.queueDrainRate) || candidate.queueDrainRate < 0) errors.push('queueDrainRate must be an integer >= 0');
    
    if (!Number.isInteger(candidate.maxQueueEstimate) || candidate.maxQueueEstimate <= 0 || candidate.maxQueueEstimate > 1000000) {
      errors.push('maxQueueEstimate must be an integer between 1 and 1000000');
    }
    
    if (!Number.isInteger(candidate.maxTrackedIPs) || candidate.maxTrackedIPs <= 0 || candidate.maxTrackedIPs > 5000000) {
      errors.push('maxTrackedIPs must be an integer between 1 and 5000000');
    }

    if (!Number.isInteger(candidate.maxGlobalRPS) || candidate.maxGlobalRPS <= 0 || candidate.maxGlobalRPS > 1000000) {
      errors.push('maxGlobalRPS must be an integer between 1 and 1000000');
    }

    if (candidate.bucketSize < candidate.refillRate) {
      errors.push('bucketSize must be greater than or equal to refillRate');
    }

    const rps = candidate.rpsLimits;
    if (!rps || typeof rps !== 'object') {
      errors.push('rpsLimits must be a valid object');
    } else {
      if (!Number.isInteger(rps.elevated) || rps.elevated <= 0) errors.push('rpsLimits.elevated must be an integer > 0');
      if (!Number.isInteger(rps.surge) || rps.surge <= 0) errors.push('rpsLimits.surge must be an integer > 0');
      if (!Number.isInteger(rps.critical) || rps.critical <= 0) errors.push('rpsLimits.critical must be an integer > 0');
      if (!Number.isInteger(rps.emergency) || rps.emergency <= 0) errors.push('rpsLimits.emergency must be an integer > 0');

      if (errors.length === 0) {
        if (!(rps.emergency >= rps.critical && rps.critical >= rps.surge && rps.surge >= rps.elevated)) {
          errors.push('rpsLimits must maintain order: emergency >= critical >= surge >= elevated');
        }
      }
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }

  /**
   * Applies new policy parameters defensively and notifies subscribers.
   */
  updatePolicy(newPolicy) {
    try {
      // 1. Merge incoming partials with current state
      const mergedCandidate = this._safeMerge(this._policy, newPolicy);
      
      // 2. Validate the complete picture
      const validation = this.validatePolicy(mergedCandidate);

      if (!validation.valid) {
        return { success: false, errors: validation.errors };
      }

      // 3. Commit, freeze, increment, and broadcast
      this._version += 1;
      this._policy = this._deepFreeze(mergedCandidate);
      this._notifyListeners();

      return { success: true, version: this._version };
    } catch (err) {
      return { success: false, errors: ['An unexpected error occurred during policy evaluation.'] };
    }
  }

  /**
   * Restores the deeply frozen safe defaults.
   */
  resetToDefault() {
    this._version += 1;
    this._policy = SAFE_DEFAULTS; // Micro-optimization: Point directly to pre-frozen constant
    this._notifyListeners();
    return { success: true, version: this._version };
  }

  /**
   * Returns the exact frozen memory reference of the current policy.
   * O(1) access. Intended for internal engine reads.
   */
  getPolicy() {
    return this._policy;
  }

  /**
   * Returns a safely extracted payload with versioning for external use/APIs.
   */
  getSafeSnapshot() {
    return Object.freeze({
      version: this._version,
      timestamp: Date.now(),
      config: this._policy
    });
  }

  /**
   * Returns the current policy version integer.
   */
  getVersion() {
    return this._version;
  }
}

module.exports = new PolicyManager();
