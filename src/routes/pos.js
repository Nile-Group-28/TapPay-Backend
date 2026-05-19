// src/routes/pos.js
const express = require('express');
const pool    = require('../db/pool');
const { log } = require('../logger');
const { authenticate } = require('../middleware/auth');
const { screenTransaction, linkScreeningToTransaction } = require('../services/fraudEngine');
const { checkAndDebitLimit, checkBalanceCap } = require('../services/tierLimits');

const router = express.Router();

const MAX_REFUND_DAYS = 90;

// ─────────────────────────────────────────────────────────────────
// POST /api/pos/activate
// ─────────────────────────────────────────────────────────────────
router.post('/activate', authenticate, async (req, res) => {
  const { businessName, businessCategory, businessAddress, businessPhone,
          taxRate, tipEnabled, tipPresets, receiptFooter, settlementFrequency } = req.body;

  try {
    await pool.query(
      `INSERT INTO merchant_profiles
         (user_id, business_name, business_category, business_address, business_phone,
          tax_rate, tip_enabled, tip_preset_percentages, receipt_footer_text, settlement_frequency)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
       ON CONFLICT (user_id) DO UPDATE SET
         business_name          = COALESCE(EXCLUDED.business_name, merchant_profiles.business_name),
         business_category      = COALESCE(EXCLUDED.business_category, merchant_profiles.business_category),
         business_address       = COALESCE(EXCLUDED.business_address, merchant_profiles.business_address),
         business_phone         = COALESCE(EXCLUDED.business_phone, merchant_profiles.business_phone),
         tax_rate               = COALESCE(EXCLUDED.tax_rate, merchant_profiles.tax_rate),
         tip_enabled            = COALESCE(EXCLUDED.tip_enabled, merchant_profiles.tip_enabled),
         tip_preset_percentages = COALESCE(EXCLUDED.tip_preset_percentages, merchant_profiles.tip_preset_percentages),
         receipt_footer_text    = COALESCE(EXCLUDED.receipt_footer_text, merchant_profiles.receipt_footer_text),
         settlement_frequency   = COALESCE(EXCLUDED.settlement_frequency, merchant_profiles.settlement_frequency),
         updated_at             = NOW()
       RETURNING *`,
      [req.user.id, businessName, businessCategory, businessAddress, businessPhone,
       taxRate || 0, tipEnabled || false,
       tipPresets ? JSON.stringify(tipPresets) : null,
       receiptFooter, settlementFrequency || 'DAILY']
    );

    // Ensure user role is MERCHANT
    await pool.query(
      `UPDATE users SET role = 'MERCHANT', updated_at = NOW() WHERE id = $1 AND role = 'CONSUMER'`,
      [req.user.id]
    );

    const profile = await pool.query(
      'SELECT * FROM merchant_profiles WHERE user_id = $1', [req.user.id]
    );

    return res.json({ success: true, message: 'POS terminal activated.', profile: profile.rows[0] });
  } catch (err) {
    log.error('POS activate error', err.message);
    return res.status(500).json({ success: false, message: err.message || 'Failed to activate POS.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/pos/transaction
// Process a POS payment (customer pays merchant)
// ─────────────────────────────────────────────────────────────────
router.post('/transaction', authenticate, async (req, res) => {
  const {
    customerId, subtotal, taxAmount = 0, tipAmount = 0, discountAmount = 0,
    items, paymentMethod = 'NFC', customerName, customerPhone,
    sendReceipt = false, receiptDelivery, terminalId,
  } = req.body;

  if (!customerId) return res.status(400).json({ success: false, message: 'customerId is required.' });
  const parsedSubtotal  = parseFloat(subtotal)  || 0;
  const parsedTax       = parseFloat(taxAmount)  || 0;
  const parsedTip       = parseFloat(tipAmount)  || 0;
  const parsedDiscount  = parseFloat(discountAmount) || 0;
  const totalAmount     = parsedSubtotal + parsedTax + parsedTip - parsedDiscount;

  if (totalAmount <= 0) return res.status(400).json({ success: false, message: 'Total amount must be positive.' });
  if (customerId === req.user.id) return res.status(400).json({ success: false, message: 'Cannot pay yourself.' });

  // Verify merchant profile exists
  const merchantRes = await pool.query(
    'SELECT * FROM merchant_profiles WHERE user_id = $1', [req.user.id]
  );
  if (!merchantRes.rows.length) {
    return res.status(403).json({ success: false, message: 'POS not activated. Call /api/pos/activate first.' });
  }
  const merchant = merchantRes.rows[0];

  // Fraud screening
  let screening;
  try {
    screening = await screenTransaction({
      userId: customerId, amount: totalAmount, transactionType: paymentMethod,
      ipAddress: req.ip, deviceId: terminalId,
    });
  } catch {
    screening = { outcome: 'APPROVED', score: 0, signals: {}, screeningId: null };
  }
  if (screening.outcome === 'BLOCKED') {
    return res.status(403).json({ success: false, message: 'Transaction declined by security system.', fraudScore: screening.score });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await checkAndDebitLimit(customerId, totalAmount, client);

    // Debit customer
    const debitRes = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 AND is_locked = false RETURNING id, balance`,
      [totalAmount, customerId]
    );
    if (!debitRes.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Customer has insufficient funds or wallet is locked.' });
    }

    // Credit merchant
    await checkBalanceCap(req.user.id, totalAmount, client);
    const creditRes = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2 RETURNING id, balance`,
      [totalAmount, req.user.id]
    );

    // Create transaction
    const txType = paymentMethod === 'QR' ? 'QR' : 'NFC';
    const txRes = await client.query(
      `INSERT INTO transactions (sender_id, receiver_id, wallet_id, amount, type, status, description)
       VALUES ($1,$2,$3,$4,$5,'SUCCESS',$6) RETURNING id, created_at`,
      [customerId, req.user.id, creditRes.rows[0].id, totalAmount, txType,
       `POS Payment — ${merchant.business_name || 'Merchant'}`]
    );
    const txId = txRes.rows[0].id;

    // POS metadata
    await client.query(
      `INSERT INTO pos_transaction_metadata
         (transaction_id, terminal_id, subtotal, tax_amount, tip_amount, discount_amount,
          total_amount, items, customer_name, customer_phone, receipt_email, receipt_phone)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [txId, terminalId, parsedSubtotal, parsedTax, parsedTip, parsedDiscount,
       totalAmount, items ? JSON.stringify(items) : null,
       customerName, customerPhone,
       receiptDelivery === 'EMAIL' ? customerPhone : null,
       receiptDelivery === 'SMS'   ? customerPhone : null]
    );

    // Update inventory stock if items provided
    if (Array.isArray(items)) {
      for (const item of items) {
        if (item.sku) {
          await client.query(
            `UPDATE merchant_inventory SET stock_quantity = GREATEST(stock_quantity - $1, 0), updated_at = NOW()
             WHERE merchant_id = $2 AND sku = $3`,
            [item.qty || 1, req.user.id, item.sku]
          );
        }
      }
    }

    await client.query('COMMIT');
    if (screening.screeningId) await linkScreeningToTransaction(screening.screeningId, txId);

    return res.json({
      success: true,
      transactionId: txId,
      totalAmount,
      merchantBalance: parseFloat(creditRes.rows[0].balance),
      fraudScore: screening.score,
      timestamp: txRes.rows[0].created_at,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    log.error('POS transaction error', err.message);
    return res.status(err.message.includes('limit') ? 403 : 500).json({ success: false, message: err.message || 'Transaction failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/pos/daily-report
// ─────────────────────────────────────────────────────────────────
router.get('/daily-report', authenticate, async (req, res) => {
  const date = req.query.date || new Date().toISOString().split('T')[0];
  try {
    const summaryRes = await pool.query(
      `SELECT
         COALESCE(SUM(t.amount), 0)           AS total_sales,
         COUNT(t.id)                           AS transaction_count,
         COALESCE(SUM(p.tip_amount), 0)        AS total_tips,
         COALESCE(SUM(p.discount_amount), 0)   AS total_discounts,
         COALESCE(AVG(t.amount), 0)            AS avg_transaction,
         COUNT(CASE WHEN t.type = 'NFC' THEN 1 END) AS nfc_count,
         COALESCE(SUM(CASE WHEN t.type = 'NFC' THEN t.amount END), 0) AS nfc_amount,
         COUNT(CASE WHEN t.type = 'QR'  THEN 1 END) AS qr_count,
         COALESCE(SUM(CASE WHEN t.type = 'QR'  THEN t.amount END), 0) AS qr_amount
       FROM transactions t
       LEFT JOIN pos_transaction_metadata p ON p.transaction_id = t.id
       WHERE t.receiver_id = $1
         AND t.status = 'SUCCESS'
         AND DATE(t.created_at) = $2
         AND t.type IN ('NFC','QR')`,
      [req.user.id, date]
    );

    const refundRes = await pool.query(
      `SELECT COALESCE(SUM(r.refund_amount), 0) AS total_refunds
       FROM pos_refunds r
       WHERE r.merchant_id = $1 AND DATE(r.created_at) = $2`,
      [req.user.id, date]
    );

    const hourlyRes = await pool.query(
      `SELECT EXTRACT(HOUR FROM t.created_at) AS hour,
              COUNT(*) AS count, COALESCE(SUM(t.amount), 0) AS amount
       FROM transactions t
       WHERE t.receiver_id = $1 AND t.status = 'SUCCESS'
         AND DATE(t.created_at) = $2 AND t.type IN ('NFC','QR')
       GROUP BY hour ORDER BY hour`,
      [req.user.id, date]
    );

    const topItemsRes = await pool.query(
      `SELECT item->>'name' AS name,
              SUM((item->>'qty')::int) AS total_qty,
              SUM((item->>'price')::numeric * (item->>'qty')::int) AS total_revenue
       FROM transactions t
       JOIN pos_transaction_metadata p ON p.transaction_id = t.id,
       jsonb_array_elements(p.items) AS item
       WHERE t.receiver_id = $1 AND t.status = 'SUCCESS'
         AND DATE(t.created_at) = $2
       GROUP BY item->>'name'
       ORDER BY total_qty DESC
       LIMIT 10`,
      [req.user.id, date]
    );

    const s = summaryRes.rows[0];
    const totalSales    = parseFloat(s.total_sales);
    const totalRefunds  = parseFloat(refundRes.rows[0].total_refunds);
    const totalTips     = parseFloat(s.total_tips);

    return res.json({
      date,
      totalSales,
      transactionCount:    parseInt(s.transaction_count),
      averageTransaction:  parseFloat(s.avg_transaction),
      totalTips,
      totalRefunds,
      netAmount:           totalSales + totalTips - totalRefunds,
      breakdown: {
        nfc: { count: parseInt(s.nfc_count), amount: parseFloat(s.nfc_amount) },
        qr:  { count: parseInt(s.qr_count),  amount: parseFloat(s.qr_amount)  },
      },
      topSellingItems:     topItemsRes.rows,
      hourlyDistribution:  hourlyRes.rows,
    });
  } catch (err) {
    log.error('Daily report error', err.message);
    return res.status(500).json({ success: false, message: err.message || 'Failed to generate report.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/pos/transactions
// ─────────────────────────────────────────────────────────────────
router.get('/transactions', authenticate, async (req, res) => {
  const { page = 1, limit = 50, startDate, endDate, status } = req.query;
  const offset = (parseInt(page) - 1) * parseInt(limit);

  try {
    const params = [req.user.id];
    let where = `t.receiver_id = $1 AND t.type IN ('NFC','QR')`;

    if (startDate) { params.push(startDate); where += ` AND DATE(t.created_at) >= $${params.length}`; }
    if (endDate)   { params.push(endDate);   where += ` AND DATE(t.created_at) <= $${params.length}`; }
    if (status)    { params.push(status.toUpperCase()); where += ` AND t.status = $${params.length}`; }

    params.push(parseInt(limit), offset);
    const result = await pool.query(
      `SELECT t.id, t.type, t.amount, t.status, t.created_at,
              t.sender_id, s.name AS customer_name,
              p.subtotal, p.tax_amount, p.tip_amount, p.discount_amount, p.total_amount,
              p.items, p.customer_name AS pos_customer_name, p.customer_phone,
              p.receipt_sent, p.is_refunded
       FROM transactions t
       LEFT JOIN users s ON s.id = t.sender_id
       LEFT JOIN pos_transaction_metadata p ON p.transaction_id = t.id
       WHERE ${where}
       ORDER BY t.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    const countRes = await pool.query(
      `SELECT COUNT(*) FROM transactions t WHERE ${where.replace(`LIMIT $${params.length - 1} OFFSET $${params.length}`, '')}`,
      params.slice(0, -2)
    );

    return res.json({
      success: true,
      transactions: result.rows,
      pagination: {
        page: parseInt(page), limit: parseInt(limit),
        total: parseInt(countRes.rows[0].count),
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to fetch transactions.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/pos/refund
// ─────────────────────────────────────────────────────────────────
router.post('/refund', authenticate, async (req, res) => {
  const { transactionId, refundAmount, reason, refundType = 'FULL' } = req.body;
  if (!transactionId || !refundAmount) {
    return res.status(400).json({ success: false, message: 'transactionId and refundAmount are required.' });
  }
  const parsedRefund = parseFloat(refundAmount);
  if (parsedRefund <= 0) return res.status(400).json({ success: false, message: 'Refund amount must be positive.' });

  const client = await pool.connect();
  try {
    // Fetch original transaction
    const txRes = await client.query(
      `SELECT t.*, p.is_refunded, p.total_amount
       FROM transactions t
       LEFT JOIN pos_transaction_metadata p ON p.transaction_id = t.id
       WHERE t.id = $1 AND t.receiver_id = $2 AND t.status = 'SUCCESS'`,
      [transactionId, req.user.id]
    );
    if (!txRes.rows.length) {
      return res.status(404).json({ success: false, message: 'Transaction not found or not eligible for refund.' });
    }
    const original = txRes.rows[0];

    if (original.is_refunded) {
      return res.status(409).json({ success: false, message: 'Transaction has already been refunded.' });
    }

    // Time limit check
    const daysSince = (Date.now() - new Date(original.created_at).getTime()) / (1000 * 60 * 60 * 24);
    if (daysSince > MAX_REFUND_DAYS) {
      return res.status(403).json({ success: false, message: `Refunds are only allowed within ${MAX_REFUND_DAYS} days.` });
    }

    const maxRefund = parseFloat(original.amount);
    if (parsedRefund > maxRefund) {
      return res.status(400).json({ success: false, message: `Refund cannot exceed original amount of ₦${maxRefund}.` });
    }

    await client.query('BEGIN');

    // Debit merchant, credit customer
    const merchantDebit = await client.query(
      `UPDATE wallets SET balance = balance - $1, updated_at = NOW()
       WHERE user_id = $2 AND balance >= $1 RETURNING id`,
      [parsedRefund, req.user.id]
    );
    if (!merchantDebit.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Insufficient merchant balance for refund.' });
    }

    const customerCredit = await client.query(
      `UPDATE wallets SET balance = balance + $1, updated_at = NOW() WHERE user_id = $2 RETURNING id`,
      [parsedRefund, original.sender_id]
    );
    if (!customerCredit.rows.length) {
      await client.query('ROLLBACK');
      return res.status(400).json({ success: false, message: 'Customer wallet not found.' });
    }

    // Create refund transaction
    const refundTxRes = await client.query(
      `INSERT INTO transactions (sender_id, receiver_id, wallet_id, amount, type, status, description)
       VALUES ($1,$2,$3,$4,$5,'SUCCESS',$6) RETURNING id, created_at`,
      [req.user.id, original.sender_id, customerCredit.rows[0].id,
       parsedRefund, original.type, `Refund for transaction ${transactionId.substring(0, 8)}`]
    );
    const refundTxId = refundTxRes.rows[0].id;

    // Record refund
    await client.query(
      `INSERT INTO pos_refunds
         (original_transaction_id, refund_transaction_id, merchant_id, refund_amount, refund_reason, refund_type, processed_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [transactionId, refundTxId, req.user.id, parsedRefund, reason, refundType, req.user.id]
    );

    // Mark original as refunded
    await client.query(
      `UPDATE pos_transaction_metadata SET is_refunded = true, refund_transaction_id = $1
       WHERE transaction_id = $2`,
      [refundTxId, transactionId]
    );

    await client.query('COMMIT');
    return res.json({
      success: true,
      message: `Refund of ₦${parsedRefund} processed successfully.`,
      refundTransactionId: refundTxId,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    log.error('POS refund error', err.message);
    return res.status(500).json({ success: false, message: err.message || 'Refund failed.' });
  } finally {
    client.release();
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/pos/settlement-report
// ─────────────────────────────────────────────────────────────────
router.get('/settlement-report', authenticate, async (req, res) => {
  const { period = 'daily', startDate, endDate } = req.query;
  const start = startDate || new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  const end   = endDate   || new Date().toISOString().split('T')[0];

  try {
    let groupBy;
    if (period === 'weekly')  groupBy = `DATE_TRUNC('week', t.created_at)`;
    else if (period === 'monthly') groupBy = `DATE_TRUNC('month', t.created_at)`;
    else groupBy = `DATE(t.created_at)`;

    const result = await pool.query(
      `SELECT
         ${groupBy} AS period,
         COUNT(t.id) AS transaction_count,
         COALESCE(SUM(t.amount), 0) AS total_sales,
         COALESCE(SUM(p.tip_amount), 0) AS total_tips,
         COUNT(CASE WHEN t.type = 'NFC' THEN 1 END) AS nfc_count,
         COUNT(CASE WHEN t.type = 'QR' THEN 1 END) AS qr_count
       FROM transactions t
       LEFT JOIN pos_transaction_metadata p ON p.transaction_id = t.id
       WHERE t.receiver_id = $1 AND t.status = 'SUCCESS'
         AND DATE(t.created_at) BETWEEN $2 AND $3
         AND t.type IN ('NFC','QR')
       GROUP BY ${groupBy}
       ORDER BY period DESC`,
      [req.user.id, start, end]
    );

    return res.json({ success: true, period, startDate: start, endDate: end, settlements: result.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to generate settlement report.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/pos/inventory/add
// ─────────────────────────────────────────────────────────────────
router.post('/inventory/add', authenticate, async (req, res) => {
  const { sku, itemName, category, price, stockQuantity, lowStockAlert } = req.body;
  if (!sku || !itemName || price === undefined) {
    return res.status(400).json({ success: false, message: 'sku, itemName, and price are required.' });
  }
  try {
    const result = await pool.query(
      `INSERT INTO merchant_inventory (merchant_id, sku, item_name, category, price, stock_quantity, low_stock_alert)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (merchant_id, sku) DO UPDATE SET
         item_name = EXCLUDED.item_name, category = EXCLUDED.category,
         price = EXCLUDED.price, stock_quantity = EXCLUDED.stock_quantity,
         low_stock_alert = EXCLUDED.low_stock_alert, updated_at = NOW()
       RETURNING *`,
      [req.user.id, sku, itemName, category, parseFloat(price), parseInt(stockQuantity) || 0, parseInt(lowStockAlert) || 5]
    );
    return res.status(201).json({ success: true, item: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to add item.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/pos/inventory
// ─────────────────────────────────────────────────────────────────
router.get('/inventory', authenticate, async (req, res) => {
  const { search, lowStock } = req.query;
  try {
    let where = 'merchant_id = $1 AND is_active = true';
    const params = [req.user.id];
    if (search) { params.push(`%${search}%`); where += ` AND (item_name ILIKE $${params.length} OR sku ILIKE $${params.length})`; }
    if (lowStock === 'true') where += ' AND stock_quantity <= low_stock_alert';

    const result = await pool.query(
      `SELECT * FROM merchant_inventory WHERE ${where} ORDER BY item_name`, params
    );
    return res.json({ success: true, items: result.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to fetch inventory.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// PUT /api/pos/inventory/:sku
// ─────────────────────────────────────────────────────────────────
router.put('/inventory/:sku', authenticate, async (req, res) => {
  const { sku } = req.params;
  const { itemName, category, price, stockQuantity, lowStockAlert, isActive } = req.body;
  try {
    const result = await pool.query(
      `UPDATE merchant_inventory SET
         item_name       = COALESCE($1, item_name),
         category        = COALESCE($2, category),
         price           = COALESCE($3, price),
         stock_quantity  = COALESCE($4, stock_quantity),
         low_stock_alert = COALESCE($5, low_stock_alert),
         is_active       = COALESCE($6, is_active),
         updated_at      = NOW()
       WHERE merchant_id = $7 AND sku = $8 RETURNING *`,
      [itemName, category, price ? parseFloat(price) : null,
       stockQuantity !== undefined ? parseInt(stockQuantity) : null,
       lowStockAlert !== undefined ? parseInt(lowStockAlert) : null,
       isActive !== undefined ? isActive : null,
       req.user.id, sku]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Item not found.' });
    return res.json({ success: true, item: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to update item.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/pos/inventory/adjust-stock
// ─────────────────────────────────────────────────────────────────
router.post('/inventory/adjust-stock', authenticate, async (req, res) => {
  const { sku, adjustment, reason } = req.body;
  if (!sku || adjustment === undefined) {
    return res.status(400).json({ success: false, message: 'sku and adjustment are required.' });
  }
  try {
    const result = await pool.query(
      `UPDATE merchant_inventory
       SET stock_quantity = GREATEST(stock_quantity + $1, 0), updated_at = NOW()
       WHERE merchant_id = $2 AND sku = $3 RETURNING *`,
      [parseInt(adjustment), req.user.id, sku]
    );
    if (!result.rows.length) return res.status(404).json({ success: false, message: 'Item not found.' });
    return res.json({ success: true, item: result.rows[0] });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to adjust stock.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/pos/receipt/:transactionId  (public)
// ─────────────────────────────────────────────────────────────────
router.get('/receipt/:transactionId', async (req, res) => {
  const { transactionId } = req.params;
  try {
    const txRes = await pool.query(
      `SELECT t.id, t.amount, t.type, t.status, t.created_at,
              t.sender_id, s.name AS customer_name, t.receiver_id,
              mp.business_name, mp.business_address, mp.business_phone,
              mp.tax_rate, mp.receipt_footer_text,
              p.subtotal, p.tax_amount, p.tip_amount, p.discount_amount, p.total_amount,
              p.items, p.customer_name AS pos_customer_name, p.cashier_name
       FROM transactions t
       LEFT JOIN users s ON s.id = t.sender_id
       LEFT JOIN merchant_profiles mp ON mp.user_id = t.receiver_id
       LEFT JOIN pos_transaction_metadata p ON p.transaction_id = t.id
       WHERE t.id = $1 AND t.status = 'SUCCESS'`,
      [transactionId]
    );
    if (!txRes.rows.length) {
      return res.status(404).json({ success: false, message: 'Receipt not found.' });
    }
    const tx = txRes.rows[0];
    return res.json({
      success: true,
      receipt: {
        id:           tx.id,
        reference:    tx.id.substring(0, 8).toUpperCase(),
        businessName: tx.business_name || 'Merchant',
        businessAddress: tx.business_address,
        businessPhone:   tx.business_phone,
        customer:     tx.pos_customer_name || tx.customer_name,
        cashier:      tx.cashier_name,
        date:         tx.created_at,
        paymentMethod: tx.type,
        subtotal:     parseFloat(tx.subtotal || tx.amount),
        taxAmount:    parseFloat(tx.tax_amount || 0),
        tipAmount:    parseFloat(tx.tip_amount || 0),
        discountAmount: parseFloat(tx.discount_amount || 0),
        totalAmount:  parseFloat(tx.total_amount || tx.amount),
        items:        tx.items || [],
        footer:       tx.receipt_footer_text,
        status:       tx.status,
      },
    });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message || 'Failed to fetch receipt.' });
  }
});

module.exports = router;
