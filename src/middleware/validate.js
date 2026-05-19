// src/middleware/validate.js
const { body, param, validationResult } = require('express-validator');

function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed',
      details: errors.array().map(e => ({ field: e.path, message: e.msg })),
    });
  }
  next();
}

const registerRules = [
  body('name').trim().isLength({ min: 2, max: 100 }).withMessage('Name must be 2–100 characters'),
  body('phone').optional().trim().matches(/^\+?[1-9]\d{9,14}$/).withMessage('Invalid phone number'),
  body('email').optional().isEmail().normalizeEmail().withMessage('Invalid email address'),
  body('pin').isLength({ min: 4, max: 6 }).isNumeric().withMessage('PIN must be 4–6 digits'),
  body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

const loginRules = [
  body('identifier').trim().notEmpty().withMessage('Identifier is required'),
  body('pin').optional().isNumeric().isLength({ min: 4, max: 6 }).withMessage('PIN must be 4–6 digits'),
  body('password').optional().isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

const offlineSyncRules = [
  body('deviceId').trim().notEmpty().withMessage('Device ID is required'),
  body('transactions').isArray({ min: 1, max: 10 }).withMessage('Provide 1–10 transactions'),
  body('transactions.*.receiverId').isUUID().withMessage('Each receiverId must be a valid UUID'),
  body('transactions.*.amount').isFloat({ min: 1, max: 2000 }).withMessage('Amount must be ₦1–₦2,000'),
  body('transactions.*.nonce').isLength({ min: 16, max: 128 }).withMessage('Invalid nonce length'),
  body('transactions.*.signature').notEmpty().withMessage('Signature is required'),
  body('transactions.*.timestamp').isISO8601().withMessage('Timestamp must be ISO-8601'),
];

module.exports = { handleValidation, registerRules, loginRules, offlineSyncRules };
