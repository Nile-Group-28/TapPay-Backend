// src/routes/kyc.js
//
// CBN-compliant KYC tier upgrade flow.
// Tier 0 → 1: provide BVN or NIN
// Tier 1 → 2: provide BVN + NIN + government ID photo
//
// For a final year project, BVN/NIN verification is mocked.
// In production, swap the mock for a real call to Dojah (app.dojah.io)
// or Smile Identity — both have free developer tiers.

const express = require('express');
const axios   = require('axios');
const pool    = require('../db/pool');
const { authenticate } = require('../middleware/auth');
const { TIER_LIMITS }  = require('../services/tierLimits');

const router = express.Router();

// ─────────────────────────────────────────────────────────────────
// POST /api/kyc/tier1
// Body: { bvn?, nin?, dateOfBirth }
// Upgrades user from Tier 0 → Tier 1 (₦30k/day limit)
// CBN requirement: BVN OR NIN is sufficient for Tier 1
// ─────────────────────────────────────────────────────────────────
router.post('/tier1', authenticate, async (req, res) => {
  if (req.user.kyc_tier >= 1) {
    return res.status(400).json({
      success: false,
      message: `You are already on ${TIER_LIMITS[req.user.kyc_tier].label}.`,
    });
  }

  const { bvn, nin, dateOfBirth } = req.body;

  if (!bvn && !nin) {
    return res.status(400).json({
      success: false,
      message: 'Please provide your BVN or NIN to complete Tier 1 verification.',
    });
  }

  if (bvn && !/^\d{11}$/.test(bvn)) {
    return res.status(400).json({ success: false, message: 'BVN must be exactly 11 digits.' });
  }

  if (nin && !/^\d{11}$/.test(nin)) {
    return res.status(400).json({ success: false, message: 'NIN must be exactly 11 digits.' });
  }

  try {
    // ── BVN/NIN Verification ──────────────────────────────────────
    // Production: call Dojah API to verify BVN matches the user's name
    // Development: we skip the API call and trust the number provided
    let verificationPassed = true;
    let verifiedName       = req.user.name;

    if (process.env.DOJAH_APP_ID && process.env.DOJAH_SECRET_KEY && bvn) {
      try {
        const dojahRes = await axios.get(
          `https://api.dojah.io/api/v1/kyc/bvn?bvn=${bvn}`,
          {
            headers: {
              AppId:         process.env.DOJAH_APP_ID,
              Authorization: process.env.DOJAH_SECRET_KEY,
            },
          }
        );
        const entity = dojahRes.data?.entity;
        if (!entity) {
          verificationPassed = false;
        } else {
          verifiedName = `${entity.first_name} ${entity.last_name}`;
          // Basic name match (fuzzy — last name must appear in registered name)
          const lastNameMatch = req.user.name
            .toLowerCase()
            .includes(entity.last_name?.toLowerCase() || '');
          if (!lastNameMatch) {
            return res.status(422).json({
              success: false,
              message: 'BVN does not match the name on your TapPay account. Please check and try again.',
            });
          }
        }
      } catch (dojahErr) {
        console.error('Dojah verification error:', dojahErr.message);
        // If Dojah API fails, flag for manual review instead of blocking user
        verificationPassed = false;
      }
    }

    const kycStatus = verificationPassed ? 'VERIFIED' : 'PENDING';
    const kycTier   = verificationPassed ? 1 : 0;

    await pool.query(
      `UPDATE users
       SET bvn = $1, nin = $2, date_of_birth = $3,
           kyc_tier = $4, kyc_status = $5, updated_at = NOW()
       WHERE id = $6`,
      [bvn || null, nin || null, dateOfBirth || null, kycTier, kycStatus, req.user.id]
    );

    return res.json({
      success:   true,
      message:   verificationPassed
        ? 'Tier 1 verification complete. You can now transact up to ₦30,000 per day.'
        : 'Details submitted. Manual review in progress — you will be notified within 24 hours.',
      kycTier,
      kycStatus,
      dailyLimit: TIER_LIMITS[kycTier].daily,
    });

  } catch (err) {
    console.error('KYC Tier 1 error:', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// POST /api/kyc/tier2
// Body: { bvn, nin, documentType, frontImageBase64, selfieBase64 }
// Upgrades user from Tier 1 → Tier 2 (₦200k/day limit)
// CBN requirement: BVN + NIN + government-issued ID
// ─────────────────────────────────────────────────────────────────
router.post('/tier2', authenticate, async (req, res) => {
  if (req.user.kyc_tier < 1) {
    return res.status(400).json({
      success: false,
      message: 'Please complete Tier 1 verification first.',
    });
  }
  if (req.user.kyc_tier >= 2) {
    return res.status(400).json({
      success: false,
      message: `You are already on ${TIER_LIMITS[req.user.kyc_tier].label}.`,
    });
  }

  const { bvn, nin, documentType } = req.body;

  if (!bvn || !nin || !documentType) {
    return res.status(400).json({
      success: false,
      message: 'BVN, NIN, and a government-issued ID type are required for Tier 2.',
    });
  }

  try {
    // Store the document submission — set to PENDING for manual/automated review
    await pool.query(
      `INSERT INTO kyc_documents (user_id, document_type, status)
       VALUES ($1, $2, 'PENDING')`,
      [req.user.id, documentType]
    );

    // Update user to reflect pending Tier 2 upgrade
    await pool.query(
      `UPDATE users
       SET bvn = $1, nin = $2, kyc_status = 'PENDING', updated_at = NOW()
       WHERE id = $3`,
      [bvn, nin, req.user.id]
    );

    return res.json({
      success:   true,
      message:   'Tier 2 documents submitted. Review usually takes 1-2 business days.',
      kycTier:   1,
      kycStatus: 'PENDING',
    });

  } catch (err) {
    console.error('KYC Tier 2 error:', err.message);
    return res.status(500).json({ success: false, message: 'Submission failed. Please try again.' });
  }
});

// ─────────────────────────────────────────────────────────────────
// GET /api/kyc/status    (protected)
// Returns current KYC tier + limits for the logged-in user
// ─────────────────────────────────────────────────────────────────
router.get('/status', authenticate, async (req, res) => {
  const limits = TIER_LIMITS[req.user.kyc_tier] || TIER_LIMITS[0];
  return res.json({
    success:   true,
    kycTier:   req.user.kyc_tier,
    kycStatus: req.user.kyc_status,
    limits: {
      daily:      limits.daily,
      maxBalance: limits.maxBalance === Infinity ? null : limits.maxBalance,
      label:      limits.label,
    },
  });
});

module.exports = router;

// ─────────────────────────────────────────────────────────────────
// POST /api/kyc/tier3
// Tier 3 = full KYC — admin manually approves after document review
// Body: { proofOfAddress, utilityBill? }
// ─────────────────────────────────────────────────────────────────
router.post('/tier3', authenticate, async (req, res) => {
  if (req.user.kyc_tier < 2) {
    return res.status(400).json({ success: false, message: 'Please complete Tier 2 verification first.' });
  }
  if (req.user.kyc_tier >= 3) {
    return res.status(400).json({ success: false, message: 'You are already on Tier 3.' });
  }
  const { documentType } = req.body;
  if (!documentType) {
    return res.status(400).json({ success: false, message: 'A document type is required for Tier 3 verification.' });
  }
  try {
    await pool.query(
      `INSERT INTO kyc_documents (user_id, document_type, status) VALUES ($1, $2, 'PENDING')`,
      [req.user.id, documentType]
    );
    await pool.query(
      `UPDATE users SET kyc_status='PENDING', updated_at=NOW() WHERE id=$1`,
      [req.user.id]
    );
    return res.json({
      success: true,
      message: 'Tier 3 application submitted. Manual review usually takes 2-3 business days.',
      kycTier: 2, kycStatus: 'PENDING',
    });
  } catch (err) {
    console.error('KYC Tier 3 error:', err.message);
    return res.status(500).json({ success: false, message: 'Submission failed. Please try again.' });
  }
});
