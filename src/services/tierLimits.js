// src/services/tierLimits.js
//
// CBN 3-Tier KYC Limits (per December 2023 circular + 2024 updates)
// Enforced on every outgoing transaction.

const TIER_LIMITS = {
  0: { daily: 0,         maxBalance: 0,         label: 'Unverified' },
  1: { daily: 30000,     maxBalance: 300000,     label: 'Tier 1 (BVN/NIN)' },
  2: { daily: 200000,    maxBalance: 500000,     label: 'Tier 2 (BVN + NIN + ID)' },
  3: { daily: 5000000,   maxBalance: Infinity,   label: 'Tier 3 (Full KYC)' },
};

// New device cap — CBN March 2026 directive
const NEW_DEVICE_CAP    = 20000;   // ₦20,000 max per transaction in first 24hrs
const NEW_DEVICE_WINDOW = 24;      // hours

/**
 * Check whether a transaction is allowed for this user.
 * Must be called inside a DB transaction (client param).
 * Throws an Error with a user-friendly message if blocked.
 * Returns the updated daily_spent value on success.
 */
async function checkAndDebitLimit(userId, amount, client) {
  const result = await client.query(
    `SELECT u.kyc_tier, u.device_id, u.device_registered_at,
            w.balance, w.daily_spent, w.last_reset_date, w.is_locked
     FROM users u
     JOIN wallets w ON w.user_id = u.id
     WHERE u.id = $1`,
    [userId]
  );

  if (!result.rows.length) throw new Error('Wallet not found.');

  const row    = result.rows[0];
  const limits = TIER_LIMITS[row.kyc_tier] || TIER_LIMITS[0];

  // ── 1. KYC tier check ───────────────────────────────────────────
  if (limits.daily === 0) {
    throw new Error(
      'Identity verification required. Please complete KYC (BVN or NIN) before making transactions.'
    );
  }

  // ── 2. Wallet locked check ──────────────────────────────────────
  if (row.is_locked) {
    throw new Error('Your wallet is temporarily locked. Please contact support.');
  }

  // ── 3. New device 24-hour cap (CBN March 2026) ──────────────────
  if (row.device_registered_at) {
    const hoursOnDevice =
      (Date.now() - new Date(row.device_registered_at).getTime()) / 3_600_000;
    if (hoursOnDevice < NEW_DEVICE_WINDOW && amount > NEW_DEVICE_CAP) {
      throw new Error(
        `New device detected. Transactions are capped at ₦${NEW_DEVICE_CAP.toLocaleString()} ` +
        `for the first 24 hours. Remaining window: ${(NEW_DEVICE_WINDOW - hoursOnDevice).toFixed(1)}h.`
      );
    }
  }

  // ── 4. Reset daily spend if new calendar day ────────────────────
  const today        = new Date().toISOString().slice(0, 10);
  const lastReset    = row.last_reset_date
    ? new Date(row.last_reset_date).toISOString().slice(0, 10)
    : null;
  let currentSpent   = parseFloat(row.daily_spent);

  if (lastReset !== today) {
    currentSpent = 0;
    await client.query(
      `UPDATE wallets SET daily_spent = 0, last_reset_date = $1 WHERE user_id = $2`,
      [today, userId]
    );
  }

  // ── 5. Daily limit check ────────────────────────────────────────
  if (currentSpent + amount > limits.daily) {
    const remaining = Math.max(0, limits.daily - currentSpent);
    throw new Error(
      `Daily transaction limit reached (${limits.label}: ₦${limits.daily.toLocaleString()}/day). ` +
      `You can send ₦${remaining.toLocaleString()} more today. ` +
      `Upgrade your KYC tier to increase limits.`
    );
  }

  // ── 6. Balance limit check ──────────────────────────────────────
  // (applies to receiver's balance — checked on top-up/receive)
  // Skip here since this is the sender side.

  // ── 7. Debit daily_spent ────────────────────────────────────────
  await client.query(
    `UPDATE wallets SET daily_spent = daily_spent + $1 WHERE user_id = $2`,
    [amount, userId]
  );

  return currentSpent + amount;
}

/**
 * Check if a credit would push the receiver's balance over their tier cap.
 * Used on top-up and receive operations.
 */
async function checkBalanceCap(userId, incomingAmount, client) {
  const result = await client.query(
    `SELECT u.kyc_tier, w.balance
     FROM users u JOIN wallets w ON w.user_id = u.id
     WHERE u.id = $1`,
    [userId]
  );
  if (!result.rows.length) return; // wallet will be created, skip

  const { kyc_tier, balance } = result.rows[0];
  const limits = TIER_LIMITS[kyc_tier] || TIER_LIMITS[0];

  if (limits.maxBalance === Infinity) return; // Tier 3 — no cap

  const projected = parseFloat(balance) + incomingAmount;
  if (projected > limits.maxBalance) {
    throw new Error(
      `This top-up would exceed your wallet balance limit of ₦${limits.maxBalance.toLocaleString()} ` +
      `(${limits.label}). Please upgrade your KYC tier or reduce the amount.`
    );
  }
}

module.exports = { checkAndDebitLimit, checkBalanceCap, TIER_LIMITS };
