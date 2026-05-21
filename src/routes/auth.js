// src/routes/auth.js
const express = require('express');
const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const { pool } = require('../db/pool');
const { authenticate } = require('../middleware/auth');
const { log } = require('../logger');

const router = express.Router();

// ─── POST /api/auth/register ─────────────────────────────────────────────────
router.post('/register', async (req, res) => {
  const { name, email, phone, pin, password, deviceId } = req.body;
  log.auth(`Register attempt — name:"${name}" email:${email || '-'} phone:${phone || '-'} device:${deviceId || 'n/a'}`);

  if (!name || (!email && !phone) || !pin) {
    log.warn('Register rejected — missing required fields');
    return res.status(400).json({ success: false, message: 'Name, email or phone, and PIN are required.' });
  }
  if (!/^\d{4}$/.test(pin)) {
    return res.status(400).json({ success: false, message: 'PIN must be exactly 4 digits.' });
  }
  if (password && password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query(
      'SELECT id FROM users WHERE email = $1 OR phone = $2',
      [email || null, phone || null]
    );
    if (existing.rows.length) {
      await client.query('ROLLBACK');
      log.warn(`Register rejected — email/phone already exists email:${email} phone:${phone}`);
      return res.status(409).json({ success: false, message: 'An account with this email or phone already exists.' });
    }

    const pinHash = await bcrypt.hash(pin, 12);
    const pwHash  = password ? await bcrypt.hash(password, 12) : null;

    const userRes = await client.query(
      `INSERT INTO users (name, email, phone, pin_hash, password_hash, device_id, device_registered_at)
       VALUES ($1,$2,$3,$4,$5,$6,NOW())
       RETURNING id, name, email, phone, role, kyc_tier, kyc_status`,
      [name, email || null, phone || null, pinHash, pwHash, deviceId || null]
    );
    const user = userRes.rows[0];
    await client.query('INSERT INTO wallets (user_id) VALUES ($1)', [user.id]);
    await client.query('COMMIT');

    await pool.query(
      `INSERT INTO security_logs (user_id, event_type, ip_address, device_id) VALUES ($1,'REGISTER',$2,$3)`,
      [user.id, req.ip, deviceId || null]
    );

    log.ok(`Register SUCCESS — user:${user.id} name:"${user.name}"`);
    const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
    return res.status(201).json({
      success: true,
      message: 'Account created. Please complete KYC to start transacting.',
      token,
      user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role, kycTier: user.kyc_tier, kycStatus: user.kyc_status, balance: 0, hasPassword: !!pwHash },
    });
  } catch (err) {
    await client.query('ROLLBACK');
    log.error('Register DB error', err.message);
    return res.status(500).json({ success: false, message: 'Registration failed.' });
  } finally { client.release(); }
});

// ─── POST /api/auth/login ─────────────────────────────────────────────────────
router.post('/login', async (req, res) => {
  const { identifier, pin, password, deviceId } = req.body;
  log.auth(`Login attempt — identifier:${identifier} method:${pin ? 'PIN' : 'password'} device:${deviceId || 'n/a'}`);

  if (!identifier || (!pin && !password)) {
    return res.status(400).json({ success: false, message: 'Identifier and PIN (or password) are required.' });
  }
  try {
    const result = await pool.query(
      `SELECT u.*, w.balance FROM users u LEFT JOIN wallets w ON w.user_id = u.id
       WHERE (u.email=$1 OR u.phone=$1) AND u.is_active=true`,
      [identifier]
    );
    if (!result.rows.length) {
      log.warn(`Login failed — account not found identifier:${identifier}`);
      return res.status(401).json({ success: false, message: 'Account not found.' });
    }
    const user = result.rows[0];

    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      const mins = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      log.warn(`Login blocked — account locked user:${user.id} unlocks in ${mins}m`);
      return res.status(429).json({ success: false, message: `Account locked. Try again in ${mins} minute(s).` });
    }

    let match = false;
    if (pin) match = await bcrypt.compare(pin, user.pin_hash);
    else if (password && user.password_hash) match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      const attempts  = user.failed_login_attempts + 1;
      const lockUntil = attempts >= 5 ? new Date(Date.now() + 15 * 60 * 1000) : null;
      await pool.query('UPDATE users SET failed_login_attempts=$1, locked_until=$2 WHERE id=$3', [attempts, lockUntil, user.id]);
      log.warn(`Login failed — wrong credentials user:${user.id} attempts:${attempts}/5`);
      return res.status(401).json({ success: false, message: attempts >= 5 ? 'Too many attempts. Account locked for 15 minutes.' : `Incorrect credentials. ${5 - attempts} attempt(s) remaining.` });
    }

    let isNewDevice = false;
    if (deviceId && user.device_id && user.device_id !== deviceId) {
      isNewDevice = true;
      await pool.query(`UPDATE users SET failed_login_attempts=0, locked_until=NULL, device_id=$1, device_registered_at=NOW(), updated_at=NOW() WHERE id=$2`, [deviceId, user.id]);
      await pool.query(`INSERT INTO security_logs (user_id, event_type, ip_address, device_id, note) VALUES ($1,'NEW_DEVICE_LOGIN',$2,$3,$4)`, [user.id, req.ip, deviceId, `Previous: ${user.device_id}`]);
      log.warn(`Login — new device detected user:${user.id} prev:${user.device_id} new:${deviceId}`);
    } else {
      await pool.query('UPDATE users SET failed_login_attempts=0, locked_until=NULL WHERE id=$1', [user.id]);
    }
    await pool.query(`INSERT INTO security_logs (user_id, event_type, ip_address, device_id) VALUES ($1,'LOGIN',$2,$3)`, [user.id, req.ip, deviceId || null]);

    log.ok(`Login SUCCESS — user:${user.id} name:"${user.name}" balance:₦${parseFloat(user.balance || 0)}`);
    const token = jwt.sign({ userId: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
    return res.json({
      success: true, token,
      user: { id: user.id, name: user.name, email: user.email, phone: user.phone, role: user.role,
        kycTier: user.kyc_tier, kycStatus: user.kyc_status, balance: parseFloat(user.balance || 0),
        isBiometricsEnabled: user.is_biometrics_enabled, isNewDevice, hasPassword: !!user.password_hash },
    });
  } catch (err) {
    log.error('Login DB error', err.message);
    return res.status(500).json({ success: false, message: 'Login failed.' });
  }
});

// ─── POST /api/auth/change-pin ────────────────────────────────────────────────
router.post('/change-pin', authenticate, async (req, res) => {
  const { currentPin, newPin } = req.body;
  if (!currentPin || !newPin || !/^\d{4}$/.test(newPin)) {
    return res.status(400).json({ success: false, message: 'Both PINs required and new PIN must be 4 digits.' });
  }
  try {
    const result  = await pool.query('SELECT pin_hash FROM users WHERE id=$1', [req.user.id]);
    const correct = await bcrypt.compare(currentPin, result.rows[0].pin_hash);
    if (!correct) return res.status(401).json({ success: false, message: 'Current PIN is incorrect.' });
    const newHash = await bcrypt.hash(newPin, 12);
    await pool.query('UPDATE users SET pin_hash=$1, updated_at=NOW() WHERE id=$2', [newHash, req.user.id]);
    await pool.query(`INSERT INTO security_logs (user_id, event_type, ip_address) VALUES ($1,'PIN_CHANGED',$2)`, [req.user.id, req.ip]);
    return res.json({ success: true, message: 'PIN changed successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to change PIN.' });
  }
});

// ─── POST /api/auth/set-password ─────────────────────────────────────────────
router.post('/set-password', authenticate, async (req, res) => {
  const { password, currentPin } = req.body;
  if (!password || password.length < 6) return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
  if (!currentPin) return res.status(400).json({ success: false, message: 'Your current PIN is required to set a password.' });
  try {
    const result  = await pool.query('SELECT pin_hash FROM users WHERE id=$1', [req.user.id]);
    const correct = await bcrypt.compare(currentPin, result.rows[0].pin_hash);
    if (!correct) return res.status(401).json({ success: false, message: 'Incorrect PIN.' });
    const hash = await bcrypt.hash(password, 12);
    await pool.query('UPDATE users SET password_hash=$1, updated_at=NOW() WHERE id=$2', [hash, req.user.id]);
    await pool.query(`INSERT INTO security_logs (user_id, event_type, ip_address) VALUES ($1,'PASSWORD_SET',$2)`, [req.user.id, req.ip]);
    return res.json({ success: true, message: 'Password set successfully.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to set password.' });
  }
});

// ─── PUT /api/auth/profile ────────────────────────────────────────────────────
router.put('/profile', authenticate, async (req, res) => {
  const { name, email, phone, address, dateOfBirth } = req.body;
  const sets = [], vals = [];
  if (name)        { vals.push(name);        sets.push(`name=$${vals.length}`); }
  if (email)       { vals.push(email);       sets.push(`email=$${vals.length}`); }
  if (phone)       { vals.push(phone);       sets.push(`phone=$${vals.length}`); }
  if (address)     { vals.push(address);     sets.push(`address=$${vals.length}`); }
  if (dateOfBirth) { vals.push(dateOfBirth); sets.push(`date_of_birth=$${vals.length}`); }
  if (!sets.length) return res.status(400).json({ success: false, message: 'No fields to update.' });
  try {
    vals.push(req.user.id);
    await pool.query(`UPDATE users SET ${sets.join(',')}, updated_at=NOW() WHERE id=$${vals.length}`, vals);
    return res.json({ success: true, message: 'Profile updated.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to update profile.' });
  }
});

// ─── GET /api/auth/me ─────────────────────────────────────────────────────────
router.get('/me', authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id, u.name, u.email, u.phone, u.role, u.kyc_tier, u.kyc_status,
              u.is_biometrics_enabled, u.address, u.date_of_birth,
              (u.password_hash IS NOT NULL) as has_password, w.balance
       FROM users u LEFT JOIN wallets w ON w.user_id=u.id WHERE u.id=$1`,
      [req.user.id]
    );
    const r = result.rows[0];
    return res.json({ success: true, user: {
      id: r.id, name: r.name, email: r.email, phone: r.phone, role: r.role,
      kycTier: r.kyc_tier, kycStatus: r.kyc_status, balance: parseFloat(r.balance || 0),
      isBiometricsEnabled: r.is_biometrics_enabled, hasPassword: r.has_password,
      address: r.address, dateOfBirth: r.date_of_birth,
    }});
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Failed to fetch profile.' });
  }
});

module.exports = router;
