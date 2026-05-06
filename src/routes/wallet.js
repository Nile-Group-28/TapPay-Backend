// src/routes/wallet.js  (FRAUD-INTEGRATED VERSION)
//
// Every outgoing transaction now runs through the fraud engine
// BEFORE any money moves — matching Yuno's pre-authorization
// fraud screening model.
//
// Replace your existing src/routes/wallet.js with this file.

const express  = require('express');
const pool     = require('../db/pool');
const paystack = require('../services/paystack');
const { authenticate }                            = require('../middleware/auth');
const { checkAndDebitLimit, checkBalanceCap }     = require('../services/tierLimits');
const { screenTransaction, linkScreeningToTransaction } = require('../services/fraudEngine');

const router = express.Router();

// Helper: extract device ID from request (sent by Flutter)
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
// POST /api/wallet/nfc-settle     ← FRAUD SCREENING ADDED
// Body: { senderId, amount, deviceId? }
// ─────────────────────────────────────────────────────────────────
router.post('/nfc-settle', authenticate, async (req, res) => {
  const { senderId, amount, deviceId: bodyDeviceId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);

  if (!senderId || !parsedAmount || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'senderId and amount are required.' });
  }
  if (senderId === req.user.id) {
    return res.status(400).json({ success: false, message: 'Cannot pay yourself.' });
  }

  // ── PRE-AUTHORIZATION FRAUD SCREENING ────────────────────────────
  // Screen the SENDER before any money moves
  let screening;
  try {
    screening = await screenTransaction({
      userId:          senderId,
      amount:          parsedAmount,
      transactionType: 'NFC',
      ipAddress:       req.ip,
      deviceId,
    });
  } catch (err) {
    console.error('Fraud screening error:', err.message);
    // If screening itself fails, allow through but log it
    screening = { outcome: 'APPROVED', score: 0, signals: { screening_error: true }, screeningId: null };
  }

  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({
      success:     false,
      message:     'Transaction declined by security system.',
      fraudScore:  screening.score,
      reason:      screening.blockReason,
    });
  }
  // ─────────────────────────────────────────────────────────────────

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await checkAndDebitLimit(senderId, parsedAmount, client);

    const debitRes = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false
       RETURNING id, balance`,
      [parsedAmount, senderId]
    );

    if (!debitRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Sender has insufficient balance or wallet is locked.' });
    }

    await checkBalanceCap(req.user.id, parsedAmount, client);

    const creditRes = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW()
       WHERE user_id = $2 RETURNING id, balance`,
      [parsedAmount, req.user.id]
    );

    const txRes = await client.query(
      `INSERT INTO transactions
         (sender_id, receiver_id, wallet_id, amount, type, status, description)
       VALUES ($1,$2,$3,$4,'NFC','SUCCESS','NFC Contactless Payment')
       RETURNING id, created_at`,
      [senderId, req.user.id, creditRes.rows[0].id, parsedAmount]
    );

    await client.query('COMMIT');

    // Link fraud screening to the settled transaction
    if (screening.screeningId) {
      await linkScreeningToTransaction(screening.screeningId, txRes.rows[0].id);
    }

    return res.json({
      success:         true,
      message:         'Payment settled successfully.',
      receiverBalance: parseFloat(creditRes.rows[0].balance),
      fraudScore:      screening.score,
      transaction: {
        id:        txRes.rows[0].id,
        amount:    parsedAmount,
        timestamp: txRes.rows[0].created_at,
      },
    });

  } catch (err) {
    await client.query('ROLLBACK');
    return res.status(err.message.includes('limit') ? 403 : 500).json({
      success: false, message: err.message || 'Settlement failed.',
    });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/wallet/transfer       ← FRAUD SCREENING ADDED
// Body: { recipientIdentifier, amount, description?, deviceId? }
// ─────────────────────────────────────────────────────────────────
router.post('/transfer', authenticate, async (req, res) => {
  const { recipientIdentifier, amount, description, deviceId: bodyDeviceId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);

  if (!recipientIdentifier || !parsedAmount || parsedAmount <= 0) {
    return res.status(400).json({ success: false, message: 'Recipient and amount are required.' });
  }

  // ── PRE-AUTHORIZATION FRAUD SCREENING ────────────────────────────
  let screening;
  try {
    screening = await screenTransaction({
      userId:          req.user.id,
      amount:          parsedAmount,
      transactionType: 'TRANSFER',
      ipAddress:       req.ip,
      deviceId,
    });
  } catch (err) {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }

  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({
      success:    false,
      message:    'Transfer declined by security system.',
      fraudScore: screening.score,
      reason:     screening.blockReason,
    });
  }
  // ─────────────────────────────────────────────────────────────────

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
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false
       RETURNING id, balance`,
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
       VALUES ($1,$2,$3,$4,'TRANSFER','SUCCESS',$5)
       RETURNING id, created_at`,
      [req.user.id, recipient.id, debitRes.rows[0].id, parsedAmount, description || `Transfer to ${recipient.name}`]
    );

    await client.query('COMMIT');

    if (screening.screeningId) {
      await linkScreeningToTransaction(screening.screeningId, txRes.rows[0].id);
    }

    return res.json({
      success:    true,
      message:    `₦${parsedAmount.toLocaleString()} sent to ${recipient.name}.`,
      newBalance: parseFloat(debitRes.rows[0].balance),
      fraudScore: screening.score,
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
// POST /api/wallet/withdraw       ← FRAUD SCREENING ADDED
// ─────────────────────────────────────────────────────────────────
router.post('/withdraw', authenticate, async (req, res) => {
  const { amount, bankAccountId, deviceId: bodyDeviceId } = req.body;
  const parsedAmount = parseFloat(amount);
  const deviceId     = bodyDeviceId || getDeviceId(req);

  if (!parsedAmount || parsedAmount < 500) {
    return res.status(400).json({ success: false, message: 'Minimum withdrawal is ₦500.' });
  }

  // ── PRE-AUTHORIZATION FRAUD SCREENING ────────────────────────────
  let screening;
  try {
    screening = await screenTransaction({
      userId:          req.user.id,
      amount:          parsedAmount,
      transactionType: 'WITHDRAWAL',
      ipAddress:       req.ip,
      deviceId,
    });
  } catch (err) {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }

  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({
      success:    false,
      message:    'Withdrawal declined by security system.',
      fraudScore: screening.score,
      reason:     screening.blockReason,
    });
  }
  // ─────────────────────────────────────────────────────────────────

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
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false
       RETURNING id, balance`,
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
      success:    true,
      message:    `₦${parsedAmount.toLocaleString()} withdrawal initiated.`,
      newBalance: parseFloat(debitRes.rows[0].balance),
      fraudScore: screening.score,
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
  const { bankName, accountNumber, bankCode, accountName } = req.body;
  if (!bankName || !accountNumber || !bankCode) {
    return res.status(400).json({ success: false, message: 'Bank name, account number, and bank code are required.' });
  }
  try {
    const recipient = await paystack.createRecipient({ accountNumber, bankCode, accountName: accountName || 'Account Holder' });
    await pool.query(
      `INSERT INTO bank_accounts (user_id, bank_name, account_number, account_name, paystack_recipient)
       VALUES ($1,$2,$3,$4,$5)`,
      [req.user.id, bankName, accountNumber, recipient.accountName, recipient.recipientCode]
    );
    return res.status(201).json({ success: true, message: 'Bank account linked.', accountName: recipient.accountName });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to link bank account.' });
  }
});

module.exports = router;
