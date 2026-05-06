// src/db/migrate.js
// Run once: node src/db/migrate.js
require('dotenv').config();
const pool = require('./pool');

const schema = `

-- ================================================================
-- TAPPAY DATABASE  — CBN Compliant Schema
-- ================================================================

-- ── Users ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  name                VARCHAR(100) NOT NULL,
  email               VARCHAR(255) UNIQUE,
  phone               VARCHAR(20)  UNIQUE,
  pin_hash            TEXT         NOT NULL,
  role                VARCHAR(20)  NOT NULL DEFAULT 'CONSUMER'
                        CHECK (role IN ('CONSUMER','MERCHANT','ADMIN')),

  -- CBN KYC tier system
  -- Tier 0: no transactions allowed (no BVN/NIN yet)
  -- Tier 1: BVN or NIN provided — ₦30k/day, ₦300k balance max
  -- Tier 2: BVN + NIN + gov ID — ₦200k/day, ₦500k balance max
  -- Tier 3: full KYC — ₦5M/day, unlimited balance
  kyc_tier            INTEGER      NOT NULL DEFAULT 0 CHECK (kyc_tier IN (0,1,2,3)),
  kyc_status          VARCHAR(20)  NOT NULL DEFAULT 'UNVERIFIED'
                        CHECK (kyc_status IN ('UNVERIFIED','PENDING','VERIFIED','REJECTED')),

  -- Identity numbers (stored for CBN compliance, not used for login)
  bvn                 VARCHAR(11),
  nin                 VARCHAR(11),
  date_of_birth       DATE,

  -- Device binding (CBN March 2026 directive: one device at a time)
  device_id           VARCHAR(255),
  device_registered_at TIMESTAMP,

  -- Security
  is_active           BOOLEAN     NOT NULL DEFAULT true,
  is_biometrics_enabled BOOLEAN   NOT NULL DEFAULT false,
  failed_login_attempts INTEGER   NOT NULL DEFAULT 0,
  locked_until        TIMESTAMP,

  created_at          TIMESTAMP   NOT NULL DEFAULT NOW(),
  updated_at          TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Wallets ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS wallets (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  balance         DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  currency        VARCHAR(3)    NOT NULL DEFAULT 'NGN',
  is_locked       BOOLEAN       NOT NULL DEFAULT false,

  -- CBN daily spend tracking (resets every midnight)
  daily_spent     DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  last_reset_date DATE,

  created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
  UNIQUE(user_id)
);

-- ── Transactions ─────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS transactions (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  sender_id       UUID          REFERENCES users(id),
  receiver_id     UUID          REFERENCES users(id),
  wallet_id       UUID          NOT NULL REFERENCES wallets(id),
  amount          DECIMAL(15,2) NOT NULL CHECK (amount > 0),
  currency        VARCHAR(3)    NOT NULL DEFAULT 'NGN',
  type            VARCHAR(20)   NOT NULL
                    CHECK (type IN ('NFC','QR','TRANSFER','TOP_UP','WITHDRAWAL','RECEIVE')),
  status          VARCHAR(20)   NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','SUCCESS','FAILED','REVERSED')),
  description     TEXT,
  category        VARCHAR(50)   DEFAULT 'OTHER',
  paystack_reference VARCHAR(100),
  created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- ── KYC Documents ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS kyc_documents (
  id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  document_type   VARCHAR(50),
  front_url       TEXT,
  back_url        TEXT,
  selfie_url      TEXT,
  status          VARCHAR(20) NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING','APPROVED','REJECTED')),
  rejection_note  TEXT,
  submitted_at    TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Linked Bank Accounts ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bank_accounts (
  id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id             UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  bank_name           VARCHAR(100) NOT NULL,
  account_number      VARCHAR(20)  NOT NULL,
  account_name        VARCHAR(100),
  paystack_recipient  VARCHAR(100),
  is_default          BOOLEAN     NOT NULL DEFAULT false,
  created_at          TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Security Audit Log ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_logs (
  id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID        REFERENCES users(id),
  event_type  VARCHAR(50) NOT NULL,
  ip_address  VARCHAR(45),
  device_id   VARCHAR(255),
  note        TEXT,
  created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

-- ── Indexes ──────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_tx_sender   ON transactions(sender_id);
CREATE INDEX IF NOT EXISTS idx_tx_receiver ON transactions(receiver_id);
CREATE INDEX IF NOT EXISTS idx_tx_created  ON transactions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sec_user    ON security_logs(user_id);

`;

async function migrate() {
  const client = await pool.connect();
  try {
    console.log('Running TapPay migrations...');
    await client.query(schema);
    console.log('✅  All tables created successfully.');
  } catch (err) {
    console.error('❌  Migration failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
