// src/routes/wallet.js
const express  = require('express');
const { v4: uuidv4 } = require('uuid');
const pool     = require('../db/pool');
const { log }  = require('../logger');
const paystack = require('../services/paystack');
const { authenticate }                            = require('../middleware/auth');
const { checkAndDebitLimit, checkBalanceCap }     = require('../services/tierLimits');
const { screenTransaction, linkScreeningToTransaction } = require('../services/fraudEngine');
const {
  verifyOfflineTransactionSignature,
  checkNonceUniqueness,
  isValidEd25519PublicKey,
} = require('../utils/cryptoVerification');

const router = express.Router();

const MAX_OFFLINE_AMOUNT      = 2000.00;
const MAX_OFFLINE_DAILY_TOTAL = 5000.00;
const MAX_PENDING_OFFLINE     = 10;

function getDeviceId(req) {
  return req.headers['x-device-id'] || req.body?.deviceId || null;
}

// ─────────────────────────────────────────────────────────────────
// GET /api/wallet
// ─────────────────────────────────────────────────────────────────
router.get('/', authenticate, async (req, res) => {
  try {
    const walletRes   = await pool.query(
      'SELECT balance, currency, is_locked, daily_spent FROM wallets WHERE user_id = $1',
      [req.user.id]
    );
    const accountsRes = await pool.query(
      'SELECT id, bank_name, account_name, is_default FROM bank_accounts WHERE user_id = $1',
      [req.user.id]
    );
    return res.json({
      success: true,
      wallet: {
        balance:    parseFloat(walletRes.rows[0]?.balance    || 0),
        currency:   walletRes.rows[0]?.currency              || 'NGN',
        isLocked:   walletRes.rows[0]?.is_locked             || false,
        dailySpent: parseFloat(walletRes.rows[0]?.daily_spent || 0),
      },
      linkedAccounts: accountsRes.rows,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to load wallet.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/wallet/transactions
// ─────────────────────────────────────────────────────────────────
router.get('/transactions', authenticate, async (req, res) => {
  const { type, limit = 20, offset = 0 } = req.query;
  try {
    const params = [req.user.id];
    let where    = '(t.sender_id = $1 OR t.receiver_id = $1)';
    if (type) { params.push(type.toUpperCase()); where += ` AND t.type = $${params.length}`; }
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(
      `SELECT t.id, t.type, t.amount, t.currency, t.status,
              t.description, t.category, t.created_at,
              t.sender_id, t.receiver_id,
              s.name AS sender_name, r.name AS receiver_name
       FROM transactions t
       LEFT JOIN users s ON s.id = t.sender_id
       LEFT JOIN users r ON r.id = t.receiver_id
       WHERE ${where}
       ORDER BY t.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    return res.json({
      success: true,
      transactions: result.rows.map(tx => ({
        id: tx.id, type: tx.type, amount: parseFloat(tx.amount),
        currency: tx.currency, status: tx.status, description: tx.description,
        category: tx.category, timestamp: tx.created_at,
        senderId: tx.sender_id, senderName: tx.sender_name,
        receiverId: tx.receiver_id, receiverName: tx.receiver_name,
        isCredit: tx.receiver_id === req.user.id,
      })),
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to load transactions.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/topup/initialize
// ─────────────────────────────────────────────────────────────────
router.post('/topup/initialize', authenticate, async (req, res) => {
  if (req.user.kyc_tier === 0) {
    return res.status(403).json({ success: false, message: 'Complete KYC before topping up.' });
  }
  const amount = parseFloat(req.body.amount);
  if (!amount || amount < 100) {
    return res.status(400).json({ success: false, message: 'Minimum top-up is ₦100.' });
  }
  try {
    const result = await paystack.initializePayment({
      email: req.user.email || `${req.user.id}@tappay.ng`,
      amount, userId: req.user.id,
      callbackUrl: `${process.env.FRONTEND_URL}/topup/callback`,
    });
    return res.json({ success: true, authorizationUrl: result.authorizationUrl, reference: result.reference });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not start payment.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/topup/verify
// ─────────────────────────────────────────────────────────────────
router.post('/topup/verify', authenticate, async (req, res) => {
  const { reference } = req.body;
  if (!reference) return res.status(400).json({ success: false, message: 'Reference required.' });

  const already = await pool.query(
    'SELECT id FROM transactions WHERE paystack_reference = $1', [reference]
  );
  if (already.rows.length) {
    return res.status(409).json({ success: false, message: 'Payment already processed.' });
  }

  const client = await pool.connect();
  try {
    const verified = await paystack.verifyPayment(reference);
    if (!verified.success) return res.status(400).json({ success: false, message: 'Payment not successful.' });

    await client.query('BEGIN');
    await checkBalanceCap(req.user.id, verified.amount, client);

    const walletRes = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW()
       WHERE user_id = $2 RETURNING id, balance`,
      [verified.amount, req.user.id]
    );
    await client.query(
      `INSERT INTO transactions (receiver_id, wallet_id, amount, type, status, description, paystack_reference)
       VALUES ($1,$2,$3,'TOP_UP','SUCCESS','Wallet Top-Up',$4)`,
      [req.user.id, walletRes.rows[0].id, verified.amount, reference]
    );
    await client.query('COMMIT');
    return res.json({ success: true, message: `₦${verified.amount.toLocaleString()} added.`, newBalance: parseFloat(walletRes.rows[0].balance) });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(500).json({ success: false, message: err.message || 'Top-up failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/nfc-settle
// ─────────────────────────────────────────────────────────────────
router.post('/nfc-settle', authenticate, async (req, res) => {
  const { senderId, amount, deviceId: bodyDeviceId, tokenId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);
  const receiverId   = req.user.id;

  if (!senderId || !parsedAmount || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'Transaction failed.' });
  }
  if (senderId === receiverId) {
    return res.status(400).json({ success: false, message: 'Cannot pay yourself.' });
  }
  if (tokenId) {
    const dup = await pool.query(
      `SELECT id FROM transactions WHERE description LIKE $1 AND type = 'NFC' AND status = 'SUCCESS' LIMIT 1`,
      [`%${tokenId}%`]
    );
    if (dup.rows.length) {
      return res.status(409).json({ success: false, message: 'This payment has already been processed.' });
    }
  }

  let screening;
  try {
    screening = await screenTransaction({
      userId: senderId, amount: parsedAmount, transactionType: 'NFC',
      ipAddress: req.ip, deviceId,
    });
  } catch {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }
  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({ success: false, message: 'Transaction declined by security system.', fraudScore: screening.score, reason: screening.blockReason });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await checkAndDebitLimit(senderId, parsedAmount, client);
    const debitRes = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false RETURNING id, balance`,
      [parsedAmount, senderId]
    );
    if (!debitRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Transaction failed. The sender may have insufficient funds.' });
    }
    await checkBalanceCap(receiverId, parsedAmount, client);
    const creditRes = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2 RETURNING id, balance`,
      [parsedAmount, receiverId]
    );
    const txRes = await client.query(
      `INSERT INTO transactions (sender_id, receiver_id, wallet_id, amount, type, status, description)
       VALUES ($1,$2,$3,$4,'NFC','SUCCESS',$5) RETURNING id, created_at`,
      [senderId, receiverId, creditRes.rows[0].id, parsedAmount,
       tokenId ? `NFC Contactless Payment [${tokenId}]` : 'NFC Contactless Payment']
    );
    await client.query('COMMIT');
    if (screening.screeningId) await linkScreeningToTransaction(screening.screeningId, txRes.rows[0].id);
    return res.json({
      success: true, message: 'Payment settled successfully.',
      receiverBalance: parseFloat(creditRes.rows[0].balance),
      fraudScore: screening.score,
      transaction: { id: txRes.rows[0].id, amount: parsedAmount, timestamp: txRes.rows[0].created_at },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(err.message.includes('limit') ? 403 : 500).json({ success: false, message: err.message || 'Settlement failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/offline-capability
// Enable offline payments and register device public key
// ─────────────────────────────────────────────────────────────────
router.post('/offline-capability', authenticate, async (req, res) => {
  const { enable, deviceId, publicKey, dailyLimit } = req.body;
  if (!deviceId) return res.status(400).json({ success: false, message: 'deviceId is required.' });
  if (enable && !publicKey) return res.status(400).json({ success: false, message: 'publicKey is required to enable offline payments.' });
  if (enable && !isValidEd25519PublicKey(publicKey)) {
    return res.status(400).json({ success: false, message: 'Invalid Ed25519 public key (must be 32 bytes base64).' });
  }

  const offlineLimit = enable
    ? Math.min(parseFloat(dailyLimit) || MAX_OFFLINE_DAILY_TOTAL, MAX_OFFLINE_DAILY_TOTAL)
    : null;

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (enable) {
      await client.query(
        `UPDATE users SET offline_payment_enabled = true, public_key_ed25519 = $1,
         offline_daily_limit = $2, updated_at = NOW() WHERE id = $3`,
        [publicKey, offlineLimit, req.user.id]
      );
    } else {
      await client.query(
        `UPDATE users SET offline_payment_enabled = false, updated_at = NOW() WHERE id = $1`,
        [req.user.id]
      );
    }

    const walletRes = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    await client.query(
      `INSERT INTO device_offline_state (user_id, device_id, last_known_balance, device_public_key, last_sync_timestamp)
       VALUES ($1, $2, $3, $4, NOW())
       ON CONFLICT (user_id, device_id) DO UPDATE SET
         device_public_key     = EXCLUDED.device_public_key,
         last_known_balance    = EXCLUDED.last_known_balance,
         last_sync_timestamp   = NOW(),
         updated_at            = NOW()`,
      [req.user.id, deviceId, walletRes.rows[0]?.balance || 0, enable ? publicKey : null]
    );

    const pendingRes = await client.query(
      `SELECT COALESCE(SUM(amount), 0) AS total FROM offline_transaction_queue
       WHERE sender_id = $1 AND status = 'PENDING'`,
      [req.user.id]
    );

    await client.query('COMMIT');

    return res.json({
      success:             true,
      offlineEnabled:      !!enable,
      dailyLimit:          offlineLimit || 0,
      maxTransactionAmount: MAX_OFFLINE_AMOUNT,
      pendingDebits:       parseFloat(pendingRes.rows[0].total),
    });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(500).json({ success: false, message: err.message || 'Failed to configure offline payments.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/wallet/offline-status
// ─────────────────────────────────────────────────────────────────
router.get('/offline-status', authenticate, async (req, res) => {
  const { deviceId } = req.query;
  try {
    const userRes = await pool.query(
      'SELECT offline_payment_enabled, offline_daily_limit FROM users WHERE id = $1',
      [req.user.id]
    );
    const user = userRes.rows[0];

    const walletRes = await pool.query(
      'SELECT balance FROM wallets WHERE user_id = $1',
      [req.user.id]
    );

    const pendingRes = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt
       FROM offline_transaction_queue
       WHERE sender_id = $1 AND status = 'PENDING'`,
      [req.user.id]
    );

    // Today's offline total
    const todayRes = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS today_total
       FROM offline_transaction_queue
       WHERE sender_id = $1 AND DATE(created_at) = CURRENT_DATE`,
      [req.user.id]
    );

    let deviceState = null;
    if (deviceId) {
      const stateRes = await pool.query(
        'SELECT * FROM device_offline_state WHERE user_id = $1 AND device_id = $2',
        [req.user.id, deviceId]
      );
      deviceState = stateRes.rows[0] || null;
    }

    const balance          = parseFloat(walletRes.rows[0]?.balance || 0);
    const pendingDebits    = parseFloat(pendingRes.rows[0].total);
    const pendingCount     = parseInt(pendingRes.rows[0].cnt);
    const dailyLimit       = parseFloat(user?.offline_daily_limit || MAX_OFFLINE_DAILY_TOTAL);
    const todayTotal       = parseFloat(todayRes.rows[0].today_total);
    const remainingDaily   = Math.max(dailyLimit - todayTotal, 0);
    const availableBalance = Math.max(balance - pendingDebits, 0);

    return res.json({
      enabled:                  !!user?.offline_payment_enabled,
      lastKnownBalance:         balance,
      pendingOfflineDebits:     pendingDebits,
      availableForOffline:      Math.min(availableBalance, remainingDaily),
      pendingTransactionsCount: pendingCount,
      lastSyncTimestamp:        deviceState?.last_sync_timestamp || null,
      dailyLimit,
      maxPerTransaction:        MAX_OFFLINE_AMOUNT,
      todayOfflineTotal:        todayTotal,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to fetch offline status.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/sync-offline-transactions
// ─────────────────────────────────────────────────────────────────
router.post('/sync-offline-transactions', authenticate, async (req, res) => {
  const { transactions: txList } = req.body;
  if (!Array.isArray(txList) || txList.length === 0) {
    return res.status(400).json({ success: false, message: 'transactions array is required.' });
  }
  if (txList.length > MAX_PENDING_OFFLINE) {
    return res.status(400).json({ success: false, message: `Cannot sync more than ${MAX_PENDING_OFFLINE} transactions at once.` });
  }

  // Fetch sender's public key
  const userRes = await pool.query(
    'SELECT public_key_ed25519, offline_payment_enabled, offline_daily_limit FROM users WHERE id = $1',
    [req.user.id]
  );
  const user = userRes.rows[0];
  if (!user?.offline_payment_enabled) {
    return res.status(403).json({ success: false, message: 'Offline payments are not enabled for this account.' });
  }
  if (!user.public_key_ed25519) {
    return res.status(403).json({ success: false, message: 'No public key registered. Please enable offline payments first.' });
  }

  const results = [];
  let syncedCount = 0;
  let rejectedCount = 0;

  const client = await pool.connect();
  try {
    // Calculate running balance to catch double-spends within this batch
    const walletRes = await client.query(
      'SELECT balance FROM wallets WHERE user_id = $1 FOR UPDATE',
      [req.user.id]
    );
    let runningBalance = parseFloat(walletRes.rows[0]?.balance || 0);

    // Today's offline spend so far
    const todayRes = await client.query(
      `SELECT COALESCE(SUM(amount), 0) AS today_total
       FROM offline_transaction_queue
       WHERE sender_id = $1 AND DATE(created_at_device) = CURRENT_DATE AND status != 'REJECTED'`,
      [req.user.id]
    );
    let todayOfflineSpent = parseFloat(todayRes.rows[0].today_total);
    const dailyLimit = parseFloat(user.offline_daily_limit || MAX_OFFLINE_DAILY_TOTAL);

    for (const tx of txList) {
      const { localTransactionId, receiverId, amount, nonce, signature, deviceTimestamp, deviceId } = tx;
      const parsedAmount = parseFloat(amount);
      let rejectReason = null;

      // Basic validation
      if (!localTransactionId || !receiverId || !nonce || !signature || !deviceTimestamp) {
        rejectReason = 'Missing required fields.';
      } else if (isNaN(parsedAmount) || parsedAmount <= 0) {
        rejectReason = 'Invalid amount.';
      } else if (parsedAmount > MAX_OFFLINE_AMOUNT) {
        rejectReason = `Amount exceeds offline limit of ₦${MAX_OFFLINE_AMOUNT}.`;
      } else if (todayOfflineSpent + parsedAmount > dailyLimit) {
        rejectReason = `Daily offline limit of ₦${dailyLimit} would be exceeded.`;
      } else if (req.user.id === receiverId) {
        rejectReason = 'Cannot pay yourself.';
      } else {
        // Verify signature
        const signatureValid = verifyOfflineTransactionSignature(
          { senderId: req.user.id, receiverId, amount: parsedAmount, nonce, signature, deviceTimestamp },
          user.public_key_ed25519
        );
        if (!signatureValid) {
          rejectReason = 'Invalid cryptographic signature.';
        } else {
          // Check nonce uniqueness
          const isUnique = await checkNonceUniqueness(nonce, client);
          if (!isUnique) {
            rejectReason = 'Duplicate nonce — replay attack detected.';
          } else if (runningBalance < parsedAmount) {
            rejectReason = 'Insufficient balance.';
          }
        }
      }

      if (rejectReason) {
        // Insert rejected record
        try {
          await client.query(
            `INSERT INTO offline_transaction_queue
             (local_transaction_id, sender_id, receiver_id, amount, token_signature, nonce,
              status, sync_status, created_at_device, rejection_reason, ip_address)
             VALUES ($1,$2,$3,$4,$5,$6,'REJECTED','COMPLETED',$7,$8,$9::inet)
             ON CONFLICT (nonce) DO NOTHING`,
            [localTransactionId, req.user.id, receiverId, parsedAmount, signature || 'INVALID',
             nonce || `rejected-${Date.now()}`, deviceTimestamp || new Date().toISOString(),
             rejectReason, req.ip]
          );
        } catch { /* nonce conflict — already recorded */ }
        results.push({ localTransactionId, status: 'REJECTED', reason: rejectReason });
        rejectedCount++;
        continue;
      }

      // Process valid transaction
      try {
        await client.query('BEGIN');

        // Debit sender
        const debitRes = await client.query(
          `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
           WHERE user_id = $2 AND balance >= $1 AND is_locked = false RETURNING id`,
          [parsedAmount, req.user.id]
        );
        if (!debitRes.rows.length) {
          await client.query('ROLLBACK');
          results.push({ localTransactionId, status: 'REJECTED', reason: 'Wallet locked or insufficient funds at settlement.' });
          rejectedCount++;
          continue;
        }

        // Credit receiver
        const creditRes = await client.query(
          `UPDATE wallets SET balance = balance + $1, updated_at = NOW()
           WHERE user_id = $2 RETURNING id`,
          [parsedAmount, receiverId]
        );
        if (!creditRes.rows.length) {
          await client.query('ROLLBACK');
          results.push({ localTransactionId, status: 'REJECTED', reason: 'Receiver wallet not found.' });
          rejectedCount++;
          continue;
        }

        // Create transaction record
        const txRes = await client.query(
          `INSERT INTO transactions
           (sender_id, receiver_id, wallet_id, amount, type, status, description)
           VALUES ($1,$2,$3,$4,'NFC','SUCCESS',$5) RETURNING id, created_at`,
          [req.user.id, receiverId, creditRes.rows[0].id, parsedAmount,
           `NFC Offline Payment [${localTransactionId}]`]
        );
        const txId = txRes.rows[0].id;

        // Record in offline queue
        await client.query(
          `INSERT INTO offline_transaction_queue
           (local_transaction_id, sender_id, receiver_id, amount, token_signature, nonce,
            status, sync_status, created_at_device, synced_at, transaction_id, ip_address)
           VALUES ($1,$2,$3,$4,$5,$6,'SYNCED','COMPLETED',$7,NOW(),$8,$9::inet)`,
          [localTransactionId, req.user.id, receiverId, parsedAmount,
           signature, nonce, deviceTimestamp, txId, req.ip]
        );

        await client.query('COMMIT');

        runningBalance -= parsedAmount;
        todayOfflineSpent += parsedAmount;
        results.push({ localTransactionId, status: 'SYNCED', transactionId: txId });
        syncedCount++;
      } catch (err) {
        await client.query('ROLLBACK');
        results.push({ localTransactionId, status: 'REJECTED', reason: 'Processing error.' });
        rejectedCount++;
      }
    }

    // Update device state
    const deviceId = getDeviceId(req);
    if (deviceId) {
      const finalBalance = await client.query(
        'SELECT balance FROM wallets WHERE user_id = $1', [req.user.id]
      );
      await client.query(
        `INSERT INTO device_offline_state (user_id, device_id, last_known_balance, pending_offline_debits, last_sync_timestamp)
         VALUES ($1,$2,$3,0,NOW())
         ON CONFLICT (user_id, device_id) DO UPDATE SET
           last_known_balance    = EXCLUDED.last_known_balance,
           pending_offline_debits = 0,
           last_sync_timestamp   = NOW(),
           updated_at            = NOW()`,
        [req.user.id, deviceId, finalBalance.rows[0]?.balance || 0]
      );
    }

    return res.json({
      success: true,
      results,
      syncedCount,
      rejectedCount,
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Sync failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/transfer
// ─────────────────────────────────────────────────────────────────
router.post('/transfer', authenticate, async (req, res) => {
  const { recipientIdentifier, amount, description, deviceId: bodyDeviceId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);

  if (!recipientIdentifier || !parsedAmount || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'Recipient and amount are required.' });
  }

  let screening;
  try {
    screening = await screenTransaction({
      userId: req.user.id, amount: parsedAmount, transactionType: 'TRANSFER',
      ipAddress: req.ip, deviceId,
    });
  } catch {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }
  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({ success: false, message: 'Transfer declined by security system.', fraudScore: screening.score, reason: screening.blockReason });
  }

  const client = await pool.connect();
  try {
    const recipientRes = await client.query(
      `SELECT id, name FROM users WHERE (email = $1 OR phone = $1) AND is_active = true`,
      [recipientIdentifier]
    );
    if (!recipientRes.rows.length) return res.status(404).json({ success: false, message: 'Recipient not found.' });
    const recipient = recipientRes.rows[0];
    if (recipient.id === req.user.id) return res.status(400).json({ success: false, message: 'Cannot transfer to yourself.' });

    await client.query('BEGIN');
    await checkAndDebitLimit(req.user.id, parsedAmount, client);
    const debitRes = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false RETURNING id, balance`,
      [parsedAmount, req.user.id]
    );
    if (!debitRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Insufficient balance or wallet locked.' });
    }
    await checkBalanceCap(recipient.id, parsedAmount, client);
    await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2`,
      [parsedAmount, recipient.id]
    );
    const txRes = await client.query(
      `INSERT INTO transactions (sender_id, receiver_id, wallet_id, amount, type, status, description)
       VALUES ($1,$2,$3,$4,'TRANSFER','SUCCESS',$5) RETURNING id, created_at`,
      [req.user.id, recipient.id, debitRes.rows[0].id, parsedAmount, description || `Transfer to ${recipient.name}`]
    );
    await client.query('COMMIT');
    if (screening.screeningId) await linkScreeningToTransaction(screening.screeningId, txRes.rows[0].id);
    return res.json({
      success: true, message: `₦${parsedAmount.toLocaleString()} sent to ${recipient.name}.`,
      newBalance: parseFloat(debitRes.rows[0].balance), fraudScore: screening.score,
      transaction: { id: txRes.rows[0].id, amount: parsedAmount, recipientName: recipient.name, timestamp: txRes.rows[0].created_at },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(err.message.includes('limit') ? 403 : 500).json({ success: false, message: err.message || 'Transfer failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/withdraw
// ─────────────────────────────────────────────────────────────────
router.post('/withdraw', authenticate, async (req, res) => {
  const { amount, bankAccountId, deviceId: bodyDeviceId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);

  if (!parsedAmount || parsedAmount < 500) {
    return res.status(400).json({ success: false, message: 'Minimum withdrawal is ₦500.' });
  }

  let screening;
  try {
    screening = await screenTransaction({
      userId: req.user.id, amount: parsedAmount, transactionType: 'WITHDRAWAL',
      ipAddress: req.ip, deviceId,
    });
  } catch {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }
  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({ success: false, message: 'Withdrawal declined by security system.', fraudScore: screening.score, reason: screening.blockReason });
  }

  const client = await pool.connect();
  try {
    const accountRes = await client.query(
      'SELECT * FROM bank_accounts WHERE id = $1 AND user_id = $2',
      [bankAccountId, req.user.id]
    );
    if (!accountRes.rows.length) return res.status(404).json({ success: false, message: 'Bank account not found.' });

    await client.query('BEGIN');
    await checkAndDebitLimit(req.user.id, parsedAmount, client);
    const debitRes = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false RETURNING id, balance`,
      [parsedAmount, req.user.id]
    );
    if (!debitRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Insufficient balance.' });
    }
    const reference = `WD-${req.user.id}-${Date.now()}`;
    await paystack.sendTransfer({
      amount: parsedAmount, recipientCode: accountRes.rows[0].paystack_recipient,
      reference, reason: 'TapPay Withdrawal',
    });
    await client.query(
      `INSERT INTO transactions (sender_id, wallet_id, amount, type, status, description, paystack_reference)
       VALUES ($1,$2,$3,'WITHDRAWAL','PENDING',$4,$5)`,
      [req.user.id, debitRes.rows[0].id, parsedAmount, `Withdrawal to ${accountRes.rows[0].bank_name}`, reference]
    );
    await client.query('COMMIT');
    return res.json({
      success: true, message: `₦${parsedAmount.toLocaleString()} withdrawal initiated.`,
      newBalance: parseFloat(debitRes.rows[0].balance), fraudScore: screening.score,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(err.message.includes('limit') ? 403 : 500).json({ success: false, message: err.message || 'Withdrawal failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/bank-account
// ─────────────────────────────────────────────────────────────────
router.post('/bank-account', authenticate, async (req, res) => {
  const { bankName, accountNumber, accountName } = req.body;
  if (!bankName || !accountNumber) {
    return res.status(400).json({ success: false, message: 'Bank name and account number are required.' });
  }
  if (!/^\d{10}$/.test(accountNumber)) {
    return res.status(400).json({ success: false, message: 'Account number must be exactly 10 digits.' });
  }
  try {
    const dup = await pool.query(
      'SELECT id FROM bank_accounts WHERE user_id = $1 AND account_number = $2',
      [req.user.id, accountNumber]
    );
    if (dup.rows.length) {
      return res.status(409).json({ success: false, message: 'This account number is already linked.' });
    }
    const displayName = accountName?.trim() || 'Account Holder';
    await pool.query(
      `INSERT INTO bank_accounts (user_id, bank_name, account_number, account_name, paystack_recipient)
       VALUES ($1,$2,$3,$4,$5)`,
      [req.user.id, bankName.trim(), accountNumber, displayName, `DIRECT-${req.user.id}-${Date.now()}`]
    );
    return res.status(201).json({ success: true, message: 'Bank account linked successfully.', accountName: displayName });
  } catch (err) {
    log.error('Link bank account error', err.message);
    return res.status(500).json({ success: false, message: 'Failed to link bank account.' });
  }
});

module.exports = router;
