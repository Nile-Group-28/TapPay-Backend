// src/db/migrate_offline_pos.js
// Run: node src/db/migrate_offline_pos.js
require('dotenv').config();
const pool = require('./pool');

const schema = `

-- ── Offline transaction support columns on users ────────────────
ALTER TABLE users ADD COLUMN IF NOT EXISTS offline_payment_enabled BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN IF NOT EXISTS offline_daily_limit DECIMAL(15,2) DEFAULT 5000.00;
ALTER TABLE users ADD COLUMN IF NOT EXISTS public_key_ed25519 TEXT;

-- ── Device offline state ─────────────────────────────────────────
CREATE TABLE IF NOT EXISTS device_offline_state (
  id                    UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id               UUID          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id             VARCHAR(255)  NOT NULL,
  last_known_balance    DECIMAL(15,2),
  pending_offline_debits DECIMAL(15,2) DEFAULT 0.00,
  last_sync_timestamp   TIMESTAMP,
  device_public_key     TEXT,
  device_certificate    TEXT,
  created_at            TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMP     NOT NULL DEFAULT NOW(),
  UNIQUE(user_id, device_id)
);

-- ── Offline transaction queue ────────────────────────────────────
CREATE TABLE IF NOT EXISTS offline_transaction_queue (
  id                    UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  local_transaction_id  UUID          NOT NULL,
  sender_id             UUID          NOT NULL REFERENCES users(id),
  receiver_id           UUID          NOT NULL REFERENCES users(id),
  amount                DECIMAL(15,2) NOT NULL,
  transaction_type      VARCHAR(20)   DEFAULT 'NFC_OFFLINE',
  token_signature       TEXT          NOT NULL,
  nonce                 VARCHAR(64)   NOT NULL UNIQUE,
  device_fingerprint    TEXT,
  status                VARCHAR(20)   DEFAULT 'PENDING'
                          CHECK (status IN ('PENDING','SYNCED','FAILED','REJECTED')),
  sync_status           VARCHAR(20)   DEFAULT 'QUEUED'
                          CHECK (sync_status IN ('QUEUED','PROCESSING','COMPLETED')),
  created_at_device     TIMESTAMP     NOT NULL,
  synced_at             TIMESTAMP,
  fraud_screening_id    UUID,
  rejection_reason      TEXT,
  device_os_version     TEXT,
  app_version           TEXT,
  ip_address            INET,
  transaction_id        UUID          REFERENCES transactions(id),
  created_at            TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_offline_queue_sender ON offline_transaction_queue(sender_id);
CREATE INDEX IF NOT EXISTS idx_offline_queue_status ON offline_transaction_queue(status);
CREATE INDEX IF NOT EXISTS idx_offline_queue_nonce  ON offline_transaction_queue(nonce);

-- ── Merchant profiles ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS merchant_profiles (
  id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                 UUID          NOT NULL UNIQUE REFERENCES users(id),
  business_name           VARCHAR(255),
  business_category       VARCHAR(100),
  business_address        TEXT,
  business_phone          VARCHAR(20),
  currency                VARCHAR(3)    DEFAULT 'NGN',
  tax_rate                DECIMAL(5,2)  DEFAULT 0.00,
  tip_enabled             BOOLEAN       DEFAULT false,
  tip_preset_percentages  JSONB,
  receipt_footer_text     TEXT,
  auto_print_receipt      BOOLEAN       DEFAULT false,
  settlement_bank_account UUID          REFERENCES bank_accounts(id),
  settlement_frequency    VARCHAR(20)   DEFAULT 'DAILY',
  created_at              TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at              TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- ── POS transaction metadata ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS pos_transaction_metadata (
  id                  UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  transaction_id      UUID          NOT NULL UNIQUE REFERENCES transactions(id),
  terminal_id         VARCHAR(100),
  cashier_name        VARCHAR(255),
  subtotal            DECIMAL(15,2),
  tax_amount          DECIMAL(15,2) DEFAULT 0.00,
  tip_amount          DECIMAL(15,2) DEFAULT 0.00,
  discount_amount     DECIMAL(15,2) DEFAULT 0.00,
  total_amount        DECIMAL(15,2),
  items               JSONB,
  receipt_sent        BOOLEAN       DEFAULT false,
  receipt_email       VARCHAR(255),
  receipt_phone       VARCHAR(20),
  is_refunded         BOOLEAN       DEFAULT false,
  refund_transaction_id UUID        REFERENCES transactions(id),
  customer_name       VARCHAR(255),
  customer_phone      VARCHAR(20),
  customer_notes      TEXT,
  created_at          TIMESTAMP     NOT NULL DEFAULT NOW()
);

-- ── Daily settlement reports ──────────────────────────────────────
CREATE TABLE IF NOT EXISTS pos_daily_settlements (
  id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id             UUID          NOT NULL REFERENCES users(id),
  settlement_date         DATE          NOT NULL,
  total_sales_amount      DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  total_transactions      INT           NOT NULL DEFAULT 0,
  total_tips              DECIMAL(15,2) DEFAULT 0.00,
  total_refunds           DECIMAL(15,2) DEFAULT 0.00,
  net_amount              DECIMAL(15,2) NOT NULL DEFAULT 0.00,
  nfc_payments_count      INT           DEFAULT 0,
  nfc_payments_amount     DECIMAL(15,2) DEFAULT 0.00,
  qr_payments_count       INT           DEFAULT 0,
  qr_payments_amount      DECIMAL(15,2) DEFAULT 0.00,
  status                  VARCHAR(20)   DEFAULT 'PENDING',
  settled_at              TIMESTAMP,
  settlement_reference    VARCHAR(255),
  created_at              TIMESTAMP     NOT NULL DEFAULT NOW(),
  UNIQUE(merchant_id, settlement_date)
);

-- ── Merchant inventory ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS merchant_inventory (
  id              UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  merchant_id     UUID          NOT NULL REFERENCES users(id),
  sku             VARCHAR(100)  NOT NULL,
  item_name       VARCHAR(255)  NOT NULL,
  category        VARCHAR(100),
  price           DECIMAL(15,2) NOT NULL,
  stock_quantity  INT           DEFAULT 0,
  low_stock_alert INT           DEFAULT 5,
  is_active       BOOLEAN       DEFAULT true,
  created_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
  updated_at      TIMESTAMP     NOT NULL DEFAULT NOW(),
  UNIQUE(merchant_id, sku)
);

-- ── POS refunds ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS pos_refunds (
  id                      UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
  original_transaction_id UUID          NOT NULL REFERENCES transactions(id),
  refund_transaction_id   UUID          NOT NULL REFERENCES transactions(id),
  merchant_id             UUID          NOT NULL REFERENCES users(id),
  refund_amount           DECIMAL(15,2) NOT NULL,
  refund_reason           TEXT,
  refund_type             VARCHAR(20),
  processed_by            UUID          REFERENCES users(id),
  approved_by             UUID          REFERENCES users(id),
  created_at              TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pos_settlements_merchant ON pos_daily_settlements(merchant_id, settlement_date);
CREATE INDEX IF NOT EXISTS idx_pos_inventory_merchant   ON merchant_inventory(merchant_id);
CREATE INDEX IF NOT EXISTS idx_device_offline_user      ON device_offline_state(user_id);

`;

async function migrate() {
  const client = await pool.connect();
  try {
    console.log('Running offline/POS migrations...');
    await client.query(schema);
    console.log('✅  Offline + POS tables created successfully.');
  } catch (err) {
    console.error('❌  Migration failed:', err.message);
    process.exit(1);
  } finally {
    client.release();
    await pool.end();
  }
}

migrate();
