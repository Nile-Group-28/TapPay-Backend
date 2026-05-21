// src/routes/webhook.js
// Register this URL in Paystack dashboard → Settings → Webhooks:
//   https://your-server.com/api/webhook/paystack

const express  = require('express');
const { pool } = require('../db/pool');
const paystack = require('../services/paystack');

const router = express.Router();

router.post('/paystack', express.raw({ type: 'application/json' }), async (req, res) => {
  res.sendStatus(200); // Always respond first

  const signature = req.headers['x-paystack-signature'];
  if (!paystack.verifyWebhook(req.body, signature)) {
    console.warn('Rejected webhook — bad signature.');
    return;
  }

  const { event, data } = JSON.parse(req.body);
  console.log(`Paystack webhook: ${event}`);

  switch (event) {
    case 'charge.success':      await handleChargeSuccess(data);   break;
    case 'transfer.success':    await handleTransferSuccess(data);  break;
    case 'transfer.failed':
    case 'transfer.reversed':   await handleTransferFailed(data);  break;
  }
});

async function handleChargeSuccess(data) {
  const { reference, amount, metadata } = data;
  const userId = metadata?.userId;
  if (!userId) return;

  const exists = await pool.query(
    'SELECT id FROM transactions WHERE paystack_reference = $1', [reference]
  );
  if (exists.rows.length) return; // already processed

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const amountNaira = amount / 100;

    const walletRes = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW()
       WHERE user_id = $2 RETURNING id`,
      [amountNaira, userId]
    );

    if (walletRes.rows.length) {
      await client.query(
        `INSERT INTO transactions
           (receiver_id, wallet_id, amount, type, status, description, paystack_reference)
         VALUES ($1, $2, $3, 'TOP_UP', 'SUCCESS', 'Top-Up (webhook)', $4)`,
        [userId, walletRes.rows[0].id, amountNaira, reference]
      );
    }
    await client.query('COMMIT');
    console.log(`Credited ₦${amountNaira} → user ${userId}`);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('charge.success error:', err.message);
  } finally {
    client.release();
  }
}

async function handleTransferSuccess(data) {
  await pool.query(
    `UPDATE transactions SET status = 'SUCCESS', updated_at = NOW()
     WHERE paystack_reference = $1`,
    [data.reference]
  );
}

async function handleTransferFailed(data) {
  const { reference, amount } = data;
  const client = await pool.connect();
  try {
    const txRes = await client.query(
      `SELECT sender_id FROM transactions WHERE paystack_reference = $1 AND type = 'WITHDRAWAL'`,
      [reference]
    );
    if (!txRes.rows.length) return;

    const userId      = txRes.rows[0].sender_id;
    const amountNaira = amount / 100;

    await client.query('BEGIN');
    await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2`,
      [amountNaira, userId]
    );
    await client.query(
      `UPDATE transactions SET status = 'REVERSED', updated_at = NOW() WHERE paystack_reference = $1`,
      [reference]
    );
    await client.query('COMMIT');
    console.log(`Reversed ₦${amountNaira} → user ${userId}`);
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('transfer.failed error:', err.message);
  } finally {
    client.release();
  }
}

module.exports = router;
