// src/db/fraud_migrate.js
// Run AFTER your main migrate.js:
//   node src/db/fraud_migrate.js
//
// This adds all fraud-related tables to your existing TapPay database.
// It is safe to run multiple times (uses IF NOT EXISTS).

require('dotenv').config();
const pool = require('./pool');

const sql = `

-- ================================================================
-- TAPPAY FRAUD PREVENTION TABLES
-- Modelled on Yuno's Risk Conditions architecture:
--   - Velocity rules (flag/block by frequency + amount)
--   - Blocklists / Allowlists (by phone, email, IP, device)
--   - Fraud screening log (one record per transaction, like Yuno's
--     FRAUD_SCREENING transaction type)
--   - Fraud rules engine (configurable rules stored in DB)
-- ================================================================

-- ── Fraud Screening Log ──────────────────────────────────────────
-- Every transaction gets a fraud screening record before it settles.
-- Status mirrors Yuno's FRAUD_SCREENING transaction states.
CREATE TABLE IF NOT EXISTS fraud_screenings (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_ref UUID,                           -- links to transactions.id after settlement
  user_id         UUID        NOT NULL REFERENCES users(id),
  amount          DECIMAL(15,2) NOT NULL,
  transaction_type VARCHAR(20) NOT NULL,           -- NFC, QR, TRANSFER, etc.
  ip_address      VARCHAR(45),
  device_id       VARCHAR(255),

  -- Fraud score 0–100 (higher = more suspicious)
  fraud_score     INTEGER     NOT NULL DEFAULT 0,

  -- Individual signal scores that make up the total
  signals         JSONB       NOT NULL DEFAULT '{}',

  -- Outcome: APPROVED, FLAGGED, BLOCKED, MANUAL_REVIEW
  outcome         VARCHAR(20) NOT NULL DEFAULT 'APPROVED'
                    CHECK (outcome IN ('APPROVED','FLAGGED','BLOCKED','MANUAL_REVIEW')),

  -- If blocked, why
  block_reason    TEXT,

  -- Processing time in milliseconds (for performance monitoring)
  processing_ms   INTEGER,

  created_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Blocklist ────────────────────────────────────────────────────
-- Prevent transactions from high-risk identifiers.
-- Matches Yuno's Risk Conditions blocklist feature.
CREATE TABLE IF NOT EXISTS fraud_blocklist (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  type        VARCHAR(20) NOT NULL
                CHECK (type IN ('PHONE','EMAIL','IP','DEVICE_ID','USER_ID')),
  value       VARCHAR(255) NOT NULL,
  reason      TEXT,
  added_by    UUID        REFERENCES users(id),   -- admin who added it
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  expires_at  TIMESTAMP,                           -- NULL = permanent
  created_at  TIMESTAMP   NOT NULL DEFAULT NOW(),
  UNIQUE(type, value)
);

-- ── Allowlist ─────────────────────────────────────────────────────
-- Trusted users who bypass fraud screening (Yuno allowlist feature).
CREATE TABLE IF NOT EXISTS fraud_allowlist (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  type        VARCHAR(20) NOT NULL
                CHECK (type IN ('PHONE','EMAIL','IP','DEVICE_ID','USER_ID')),
  value       VARCHAR(255) NOT NULL,
  reason      TEXT,
  added_by    UUID        REFERENCES users(id),
  is_active   BOOLEAN     NOT NULL DEFAULT true,
  expires_at  TIMESTAMP,
  created_at  TIMESTAMP   NOT NULL DEFAULT NOW(),
  UNIQUE(type, value)
);

-- ── Fraud Rules ───────────────────────────────────────────────────
-- Configurable velocity and amount rules stored in DB.
-- Admins can update these without code changes.
CREATE TABLE IF NOT EXISTS fraud_rules (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name            VARCHAR(100) NOT NULL UNIQUE,
  description     TEXT,
  rule_type       VARCHAR(30) NOT NULL
                    CHECK (rule_type IN (
                      'VELOCITY_COUNT',    -- too many tx in a time window
                      'VELOCITY_AMOUNT',   -- too much volume in a time window
                      'AMOUNT_THRESHOLD',  -- single tx over a fixed amount
                      'TIME_WINDOW',       -- transaction at unusual hours
                      'NEW_DEVICE'         -- first time seeing this device
                    )),
  -- Rule parameters (flexible JSON)
  -- Examples:
  --   VELOCITY_COUNT: { "max_count": 5, "window_minutes": 10 }
  --   VELOCITY_AMOUNT: { "max_amount": 50000, "window_minutes": 60 }
  --   AMOUNT_THRESHOLD: { "threshold": 100000 }
  --   TIME_WINDOW: { "blocked_hours_start": 1, "blocked_hours_end": 5 }
  params          JSONB       NOT NULL DEFAULT '{}',

  -- Score to add when this rule fires (0–40)
  score_impact    INTEGER     NOT NULL DEFAULT 10 CHECK (score_impact BETWEEN 0 AND 40),

  -- What to do when rule fires: ADD_SCORE, FLAG, BLOCK
  action          VARCHAR(20) NOT NULL DEFAULT 'ADD_SCORE'
                    CHECK (action IN ('ADD_SCORE','FLAG','BLOCK')),

  is_active       BOOLEAN     NOT NULL DEFAULT true,
  created_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_fraud_screen_user    ON fraud_screenings(user_id);
CREATE INDEX IF NOT EXISTS idx_fraud_screen_created ON fraud_screenings(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_fraud_screen_outcome ON fraud_screenings(outcome);
CREATE INDEX IF NOT EXISTS idx_blocklist_lookup     ON fraud_blocklist(type, value) WHERE is_active = true;
CREATE INDEX IF NOT EXISTS idx_allowlist_lookup     ON fraud_allowlist(type, value) WHERE is_active = true;

-- ── Seed default fraud rules ─────────────────────────────────────
-- These mirror the velocity + threshold rules in Yuno's Risk Conditions.
-- Admins can modify or add more via the /api/fraud/rules endpoint.
INSERT INTO fraud_rules (name, description, rule_type, params, score_impact, action)
VALUES
  (
    'high_velocity_count',
    'More than 5 transactions in 10 minutes — possible card testing',
    'VELOCITY_COUNT',
    '{"max_count": 5, "window_minutes": 10}',
    35,
    'BLOCK'
  ),
  (
    'moderate_velocity_count',
    'More than 3 transactions in 5 minutes',
    'VELOCITY_COUNT',
    '{"max_count": 3, "window_minutes": 5}',
    20,
    'FLAG'
  ),
  (
    'high_volume_amount',
    'More than ₦200,000 sent in 1 hour',
    'VELOCITY_AMOUNT',
    '{"max_amount": 200000, "window_minutes": 60}',
    25,
    'FLAG'
  ),
  (
    'large_single_transaction',
    'Single transaction over ₦100,000',
    'AMOUNT_THRESHOLD',
    '{"threshold": 100000}',
    15,
    'ADD_SCORE'
  ),
  (
    'unusual_hours',
    'Transaction between 1am and 5am Nigeria time',
    'TIME_WINDOW',
    '{"blocked_hours_start": 1, "blocked_hours_end": 5}',
    10,
    'ADD_SCORE'
  ),
  (
    'new_device',
    'Transaction from a device never seen before for this user',
    'NEW_DEVICE',
    '{}',
    10,
    'ADD_SCORE'
  )
ON CONFLICT (name) DO NOTHING;

`;

async function migrate() {
  const client = await pool.connect();
  try {
    console.log('Running fraud prevention migrations...');
    await client.query(sql);
    console.log('✅  Fraud tables created and default rules seeded.');
  } catch (err) {
    console.error('❌  Fraud migration failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
