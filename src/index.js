// src/index.js  (updated — add fraud route)
// Replace your existing index.js with this.
// Only change from previous version: added /api/fraud route.

require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors({
  origin:         process.env.FRONTEND_URL || '*',
  methods:        ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id'],
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000, max: 100,
  message:  { success: false, message: 'Too many requests.' },
}));

const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message:  { success: false, message: 'Too many login attempts.' },
});

// Webhook needs raw body — register before express.json()
app.use('/api/webhook', require('./routes/webhook'));
app.use(express.json({ limit: '10kb' }));

// Routes
app.use('/api/auth',   authLimit, require('./routes/auth'));
app.use('/api/wallet', require('./routes/wallet'));
app.use('/api/kyc',    require('./routes/kyc'));
app.use('/api/fraud',  require('./routes/fraud'));   // ← NEW

app.get('/health', (_, res) => res.json({
  status: 'ok', service: 'TapPay API',
  timestamp: new Date().toISOString(),
}));

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.path}` });
});
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ success: false, message: 'Unexpected error.' });
});

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║   TAPPAY BACKEND — CBN + Fraud Engine        ║
  ║   Port        : ${PORT}                         ║
  ║   Fraud Screen: Pre-authorization            ║
  ║   KYC Tiers   : 0 → 1 → 2 → 3              ║
  ╚══════════════════════════════════════════════╝
  `);
});

module.exports = app;
