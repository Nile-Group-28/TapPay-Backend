// src/services/fraudEngine.js
//
// ================================================================
// TAPPAY FRAUD ENGINE
// ================================================================
// Implements the same fraud prevention concepts as Yuno's
// Risk Conditions product:
//
//   1. Allowlist check  — trusted users pass through immediately
//   2. Blocklist check  — blocked users are rejected immediately
//   3. Rule evaluation  — velocity rules, amount thresholds, etc.
//   4. Behavioral score — device, time, history signals
//   5. Decision         — APPROVED / FLAGGED / BLOCKED / MANUAL_REVIEW
//   6. Audit log        — every screening saved to fraud_screenings
//
// The engine runs BEFORE any money moves (pre-authorization).
// ================================================================

const pool = require('../db/pool');

// Score thresholds
const SCORE_BLOCK         = 70;   // block the transaction
const SCORE_MANUAL_REVIEW = 50;   // flag for manual review
const SCORE_FLAG          = 30;   // flag but allow through

/**
 * screenTransaction()
 *
 * Main entry point. Call this before every NFC, QR, or TRANSFER.
 *
 * Returns:
 *   {
 *     outcome:    'APPROVED' | 'FLAGGED' | 'BLOCKED' | 'MANUAL_REVIEW',
 *     score:      0-100,
 *     signals:    { signalName: score, ... },
 *     blockReason: string | null,
 *     screeningId: UUID
 *   }
 *
 * Throws only on database errors — fraud decisions are returned, not thrown.
 */
async function screenTransaction({
  userId,
  amount,
  transactionType,
  ipAddress,
  deviceId,
}) {
  const startTime = Date.now();

  let totalScore = 0;
  const signals  = {};
  let outcome    = 'APPROVED';
  let blockReason = null;

  // ── Step 1: Allowlist check ──────────────────────────────────────
  // Trusted users bypass all other checks (Yuno allowlist feature)
  const allowed = await checkAllowlist(userId, ipAddress, deviceId);
  if (allowed) {
    const screeningId = await saveScreening({
      userId, amount, transactionType, ipAddress, deviceId,
      score: 0, signals: { allowlisted: true }, outcome: 'APPROVED',
      processingMs: Date.now() - startTime,
    });
    return { outcome: 'APPROVED', score: 0, signals: { allowlisted: true }, blockReason: null, screeningId };
  }

  // ── Step 2: Blocklist check ──────────────────────────────────────
  // Blocked identifiers are rejected immediately
  const blocked = await checkBlocklist(userId, ipAddress, deviceId);
  if (blocked) {
    const screeningId = await saveScreening({
      userId, amount, transactionType, ipAddress, deviceId,
      score: 100, signals: { blocklisted: true }, outcome: 'BLOCKED',
      blockReason: `Blocked: ${blocked}`,
      processingMs: Date.now() - startTime,
    });
    return {
      outcome:    'BLOCKED',
      score:      100,
      signals:    { blocklisted: true },
      blockReason: `Transaction blocked. Reason: ${blocked}`,
      screeningId,
    };
  }

  // ── Step 3: Load and evaluate active fraud rules ─────────────────
  const rules = await pool.query(
    'SELECT * FROM fraud_rules WHERE is_active = true ORDER BY score_impact DESC'
  );

  for (const rule of rules.rows) {
    const result = await evaluateRule(rule, { userId, amount, transactionType, ipAddress, deviceId });
    if (result.fired) {
      signals[rule.name] = result.score;
      totalScore += result.score;

      // Hard BLOCK from a rule — stop evaluating, reject immediately
      if (rule.action === 'BLOCK') {
        outcome     = 'BLOCKED';
        blockReason = rule.description;
        break;
      }
    }
  }

  // Cap at 100
  totalScore = Math.min(totalScore, 100);

  // ── Step 4: Behavioral signals ───────────────────────────────────
  // These add score but don't have their own DB rules
  const behavioral = await scoreBehavioral({ userId, amount, deviceId });
  Object.assign(signals, behavioral.signals);
  totalScore = Math.min(totalScore + behavioral.score, 100);

  // ── Step 5: Determine final outcome ─────────────────────────────
  if (outcome !== 'BLOCKED') {
    if (totalScore >= SCORE_BLOCK) {
      outcome     = 'BLOCKED';
      blockReason = 'High fraud risk score.';
    } else if (totalScore >= SCORE_MANUAL_REVIEW) {
      outcome = 'MANUAL_REVIEW';
    } else if (totalScore >= SCORE_FLAG) {
      outcome = 'FLAGGED';
    } else {
      outcome = 'APPROVED';
    }
  }

  // ── Step 6: Save audit record ────────────────────────────────────
  const screeningId = await saveScreening({
    userId, amount, transactionType, ipAddress, deviceId,
    score: totalScore, signals, outcome,
    blockReason: outcome === 'BLOCKED' ? blockReason : null,
    processingMs: Date.now() - startTime,
  });

  return { outcome, score: totalScore, signals, blockReason, screeningId };
}

// ── Rule evaluator ───────────────────────────────────────────────

async function evaluateRule(rule, context) {
  const { userId, amount, transactionType, ipAddress, deviceId } = context;
  const params = rule.params;

  switch (rule.rule_type) {

    case 'VELOCITY_COUNT': {
      // How many transactions has this user made in the last N minutes?
      const windowMs = params.window_minutes * 60 * 1000;
      const cutoff   = new Date(Date.now() - windowMs).toISOString();
      const result   = await pool.query(
        `SELECT COUNT(*) FROM fraud_screenings
         WHERE user_id = $1 AND created_at > $2 AND outcome != 'BLOCKED'`,
        [userId, cutoff]
      );
      const count = parseInt(result.rows[0].count);
      if (count >= params.max_count) {
        return { fired: true, score: rule.score_impact };
      }
      return { fired: false, score: 0 };
    }

    case 'VELOCITY_AMOUNT': {
      // How much has this user sent in the last N minutes?
      const windowMs = params.window_minutes * 60 * 1000;
      const cutoff   = new Date(Date.now() - windowMs).toISOString();
      const result   = await pool.query(
        `SELECT COALESCE(SUM(amount), 0) as total FROM fraud_screenings
         WHERE user_id = $1 AND created_at > $2 AND outcome != 'BLOCKED'`,
        [userId, cutoff]
      );
      const total = parseFloat(result.rows[0].total);
      if (total + amount > params.max_amount) {
        return { fired: true, score: rule.score_impact };
      }
      return { fired: false, score: 0 };
    }

    case 'AMOUNT_THRESHOLD': {
      // Is this single transaction over the threshold?
      if (amount > params.threshold) {
        return { fired: true, score: rule.score_impact };
      }
      return { fired: false, score: 0 };
    }

    case 'TIME_WINDOW': {
      // Is this transaction happening during high-risk hours?
      // Using Nigeria WAT (UTC+1)
      const hour = new Date(new Date().getTime() + 3600000).getUTCHours();
      const { blocked_hours_start, blocked_hours_end } = params;
      if (hour >= blocked_hours_start && hour < blocked_hours_end) {
        return { fired: true, score: rule.score_impact };
      }
      return { fired: false, score: 0 };
    }

    case 'NEW_DEVICE': {
      // Has this device ever been used by this user before?
      if (!deviceId) return { fired: false, score: 0 };
      const result = await pool.query(
        `SELECT COUNT(*) FROM fraud_screenings
         WHERE user_id = $1 AND device_id = $2`,
        [userId, deviceId]
      );
      const count = parseInt(result.rows[0].count);
      if (count === 0) {
        return { fired: true, score: rule.score_impact };
      }
      return { fired: false, score: 0 };
    }

    default:
      return { fired: false, score: 0 };
  }
}

// ── Behavioral scoring ───────────────────────────────────────────
// Additional signals that don't need DB rules

async function scoreBehavioral({ userId, amount, deviceId }) {
  const signals = {};
  let score = 0;

  // Signal: Amount much higher than user's average
  try {
    const result = await pool.query(
      `SELECT AVG(amount) as avg, MAX(amount) as max
       FROM fraud_screenings
       WHERE user_id = $1 AND outcome = 'APPROVED'
         AND created_at > NOW() - INTERVAL '30 days'`,
      [userId]
    );
    const avg = parseFloat(result.rows[0].avg);
    const max = parseFloat(result.rows[0].max);

    if (avg && amount > avg * 4) {
      signals.amount_anomaly_vs_avg = 15;
      score += 15;
    } else if (max && amount > max * 2) {
      signals.amount_exceeds_personal_max = 8;
      score += 8;
    }
  } catch (_) {}

  // Signal: Recent failed/blocked screenings by this user
  try {
    const result = await pool.query(
      `SELECT COUNT(*) FROM fraud_screenings
       WHERE user_id = $1 AND outcome = 'BLOCKED'
         AND created_at > NOW() - INTERVAL '1 hour'`,
      [userId]
    );
    const blocked = parseInt(result.rows[0].count);
    if (blocked >= 2) {
      signals.repeated_blocks_last_hour = 20;
      score += 20;
    }
  } catch (_) {}

  return { score, signals };
}

// ── Blocklist / Allowlist checks ──────────────────────────────────

async function checkBlocklist(userId, ipAddress, deviceId) {
  const checks = [
    { type: 'USER_ID',   value: userId },
    { type: 'IP',        value: ipAddress },
    { type: 'DEVICE_ID', value: deviceId },
  ].filter(c => c.value);

  for (const check of checks) {
    const result = await pool.query(
      `SELECT reason FROM fraud_blocklist
       WHERE type = $1 AND value = $2
         AND is_active = true
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [check.type, check.value]
    );
    if (result.rows.length) {
      return result.rows[0].reason || `${check.type} is blocklisted`;
    }
  }
  return null;
}

async function checkAllowlist(userId, ipAddress, deviceId) {
  const checks = [
    { type: 'USER_ID',   value: userId },
    { type: 'IP',        value: ipAddress },
    { type: 'DEVICE_ID', value: deviceId },
  ].filter(c => c.value);

  for (const check of checks) {
    const result = await pool.query(
      `SELECT id FROM fraud_allowlist
       WHERE type = $1 AND value = $2
         AND is_active = true
         AND (expires_at IS NULL OR expires_at > NOW())`,
      [check.type, check.value]
    );
    if (result.rows.length) return true;
  }
  return false;
}

// ── Save screening record ─────────────────────────────────────────

async function saveScreening({
  userId, amount, transactionType, ipAddress, deviceId,
  score, signals, outcome, blockReason, processingMs,
}) {
  const result = await pool.query(
    `INSERT INTO fraud_screenings
       (user_id, amount, transaction_type, ip_address, device_id,
        fraud_score, signals, outcome, block_reason, processing_ms)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
     RETURNING id`,
    [
      userId, amount, transactionType, ipAddress || null, deviceId || null,
      score, JSON.stringify(signals), outcome,
      blockReason || null, processingMs,
    ]
  );
  return result.rows[0].id;
}

/**
 * linkScreeningToTransaction()
 * Call after a transaction is successfully created to link the
 * screening record to the real transaction ID.
 */
async function linkScreeningToTransaction(screeningId, transactionId) {
  await pool.query(
    'UPDATE fraud_screenings SET transaction_ref = $1 WHERE id = $2',
    [transactionId, screeningId]
  );
}

module.exports = { screenTransaction, linkScreeningToTransaction };
