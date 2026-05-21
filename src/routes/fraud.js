// src/routes/fraud.js
//
// Admin-facing fraud management endpoints.
// All routes require authentication + admin role.
// Regular users only have read access to their own screening history.

const express = require('express');
const { pool } = require('../db/pool');
const { authenticate, requireAdmin } = require('../middleware/auth');

const router = express.Router();

// ─────────────────────────────────────────────────────────────────
// GET /api/fraud/screenings?outcome=BLOCKED&limit=20&offset=0
// Admin: view all fraud screening records
// ─────────────────────────────────────────────────────────────────
router.get('/screenings', authenticate, requireAdmin, async (req, res) => {
  const { outcome, limit = 20, offset = 0 } = req.query;

  try {
    const params = [];
    let where    = '';

    if (outcome) {
      params.push(outcome.toUpperCase());
      where = `WHERE fs.outcome = $${params.length}`;
    }

    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(
      `SELECT fs.*, u.name as user_name, u.phone, u.email
       FROM fraud_screenings fs
       JOIN users u ON u.id = fs.user_id
       ${where}
       ORDER BY fs.created_at DESC
       LIMIT $${params.length - 1} OFFSET $${params.length}`,
      params
    );

    // Count totals by outcome for dashboard stats
    const stats = await pool.query(
      `SELECT outcome, COUNT(*) as count
       FROM fraud_screenings
       WHERE created_at > NOW() - INTERVAL '24 hours'
       GROUP BY outcome`
    );

    return res.json({
      success:    true,
      screenings: result.rows,
      stats:      Object.fromEntries(stats.rows.map(r => [r.outcome, parseInt(r.count)])),
    });
  } catch (err) {
    console.error('Get screenings error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to load screenings.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/fraud/screenings/me
// User: view their own fraud screening history
// ─────────────────────────────────────────────────────────────────
router.get('/screenings/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, amount, transaction_type, outcome, fraud_score, created_at
       FROM fraud_screenings
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 20`,
      [req.user.id]
    );
    return res.json({ success: true, screenings: result.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to load history.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/fraud/screening/:id/resolve
// Admin: resolve a MANUAL_REVIEW case
// Body: { decision: 'APPROVE' | 'BLOCK', note? }
// ─────────────────────────────────────────────────────────────────
router.post('/screening/:id/resolve', authenticate, requireAdmin, async (req, res) => {
  const { decision, note } = req.body;

  if (!['APPROVE','BLOCK'].includes(decision)) {
    return res.status(400).json({ success: false, message: 'Decision must be APPROVE or BLOCK.' });
  }

  try {
    const newOutcome = decision === 'APPROVE' ? 'APPROVED' : 'BLOCKED';
    await pool.query(
      `UPDATE fraud_screenings
       SET outcome = $1, block_reason = $2
       WHERE id = $3 AND outcome = 'MANUAL_REVIEW'`,
      [newOutcome, note || null, req.params.id]
    );
    return res.json({ success: true, message: `Case marked as ${newOutcome}.` });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to resolve case.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/fraud/rules
// Admin: list all fraud rules
// ─────────────────────────────────────────────────────────────────
router.get('/rules', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM fraud_rules ORDER BY score_impact DESC'
    );
    return res.json({ success: true, rules: result.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to load rules.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// PUT /api/fraud/rules/:id
// Admin: update a fraud rule (change thresholds, enable/disable)
// Body: { params?, scoreImpact?, action?, isActive? }
// ─────────────────────────────────────────────────────────────────
router.put('/rules/:id', authenticate, requireAdmin, async (req, res) => {
  const { params, scoreImpact, action, isActive } = req.body;

  try {
    const sets   = [];
    const values = [];

    if (params !== undefined)      { values.push(JSON.stringify(params)); sets.push(`params = $${values.length}`); }
    if (scoreImpact !== undefined) { values.push(scoreImpact);            sets.push(`score_impact = $${values.length}`); }
    if (action !== undefined)      { values.push(action);                 sets.push(`action = $${values.length}`); }
    if (isActive !== undefined)    { values.push(isActive);               sets.push(`is_active = $${values.length}`); }

    if (!sets.length) {
      return res.status(400).json({ success: false, message: 'No fields to update.' });
    }

    values.push(req.params.id);
    await pool.query(
      `UPDATE fraud_rules SET ${sets.join(', ')}, updated_at = NOW() WHERE id = $${values.length}`,
      values
    );

    return res.json({ success: true, message: 'Rule updated.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to update rule.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/fraud/blocklist
// Admin: view blocklist
// ─────────────────────────────────────────────────────────────────
router.get('/blocklist', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM fraud_blocklist WHERE is_active = true ORDER BY created_at DESC'
    );
    return res.json({ success: true, entries: result.rows });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to load blocklist.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/fraud/blocklist
// Admin: add an entry to the blocklist
// Body: { type, value, reason, expiresAt? }
// ─────────────────────────────────────────────────────────────────
router.post('/blocklist', authenticate, requireAdmin, async (req, res) => {
  const { type, value, reason, expiresAt } = req.body;

  const validTypes = ['PHONE','EMAIL','IP','DEVICE_ID','USER_ID'];
  if (!validTypes.includes(type) || !value) {
    return res.status(400).json({ success: false, message: `Type must be one of: ${validTypes.join(', ')}` });
  }

  try {
    await pool.query(
      `INSERT INTO fraud_blocklist (type, value, reason, added_by, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (type, value) DO UPDATE
         SET is_active = true, reason = $3, expires_at = $5, added_by = $4`,
      [type, value, reason || null, req.user.id, expiresAt || null]
    );
    return res.status(201).json({ success: true, message: `${type} ${value} added to blocklist.` });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to add to blocklist.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// DELETE /api/fraud/blocklist/:id
// Admin: remove an entry from the blocklist
// ─────────────────────────────────────────────────────────────────
router.delete('/blocklist/:id', authenticate, requireAdmin, async (req, res) => {
  try {
    await pool.query(
      'UPDATE fraud_blocklist SET is_active = false WHERE id = $1',
      [req.params.id]
    );
    return res.json({ success: true, message: 'Entry removed from blocklist.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to remove entry.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/fraud/allowlist
// Admin: add a trusted user/device/IP to the allowlist
// Body: { type, value, reason, expiresAt? }
// ─────────────────────────────────────────────────────────────────
router.post('/allowlist', authenticate, requireAdmin, async (req, res) => {
  const { type, value, reason, expiresAt } = req.body;

  const validTypes = ['PHONE','EMAIL','IP','DEVICE_ID','USER_ID'];
  if (!validTypes.includes(type) || !value) {
    return res.status(400).json({ success: false, message: `Type must be one of: ${validTypes.join(', ')}` });
  }

  try {
    await pool.query(
      `INSERT INTO fraud_allowlist (type, value, reason, added_by, expires_at)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (type, value) DO UPDATE
         SET is_active = true, reason = $3, expires_at = $5, added_by = $4`,
      [type, value, reason || null, req.user.id, expiresAt || null]
    );
    return res.status(201).json({ success: true, message: `${type} ${value} added to allowlist.` });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to add to allowlist.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/fraud/stats
// Admin: fraud dashboard summary for the last 24 hours
// ─────────────────────────────────────────────────────────────────
router.get('/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    const [outcomes, topScored, blockedAmount] = await Promise.all([
      pool.query(
        `SELECT outcome, COUNT(*) as count, AVG(fraud_score) as avg_score
         FROM fraud_screenings
         WHERE created_at > NOW() - INTERVAL '24 hours'
         GROUP BY outcome`
      ),
      pool.query(
        `SELECT fs.fraud_score, fs.signals, fs.outcome, fs.amount,
                u.name, u.phone
         FROM fraud_screenings fs
         JOIN users u ON u.id = fs.user_id
         WHERE fs.created_at > NOW() - INTERVAL '24 hours'
           AND fs.fraud_score >= 30
         ORDER BY fs.fraud_score DESC
         LIMIT 10`
      ),
      pool.query(
        `SELECT COALESCE(SUM(amount), 0) as total
         FROM fraud_screenings
         WHERE outcome = 'BLOCKED'
           AND created_at > NOW() - INTERVAL '24 hours'`
      ),
    ]);

    return res.json({
      success: true,
      period:  'last_24_hours',
      byOutcome: Object.fromEntries(
        outcomes.rows.map(r => [r.outcome, {
          count:    parseInt(r.count),
          avgScore: parseFloat(r.avg_score || 0).toFixed(1),
        }])
      ),
      topScoredTransactions: topScored.rows,
      blockedAmountNGN:      parseFloat(blockedAmount.rows[0].total),
    });
  } catch (err) {
    console.error('Fraud stats error:', err.message);
    return res.status(500).json({ success: false, message: 'Failed to load stats.' });
  }
});

module.exports = router;
