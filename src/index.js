require('dotenv').config();
const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { log, requestLogger } = require('./logger');

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

const syncLimit = rateLimit({
  windowMs: 60 * 1000, max: 5,
  message:  { success: false, message: 'Too many sync attempts. Please wait.' },
});

app.use(requestLogger);
app.use('/api/webhook', require('./routes/webhook'));
app.use(express.json({ limit: '50kb' }));

// Routes
app.use('/api/auth',   authLimit, require('./routes/auth'));
app.use('/api/wallet', require('./routes/wallet'));
app.use('/api/kyc',    require('./routes/kyc'));
app.use('/api/fraud',  require('./routes/fraud'));
app.use('/api/pos',    require('./routes/pos'));

// Tighter rate limit on offline sync to prevent abuse
app.use('/api/wallet/sync-offline-transactions', syncLimit);

app.get('/health', (_, res) => {
  log.ok('Health check');
  res.json({ status: 'ok', service: 'TapPay API', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
  log.warn(`404 — ${req.method} ${req.path}`);
  res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.path}` });
});

app.use((err, req, res, next) => {
  log.error('Unhandled exception', err.stack || err.message);
  res.status(500).json({ success: false, message: 'Unexpected error.' });
});

app.listen(PORT, () => {
  console.log(`
  ╔══════════════════════════════════════════════════╗
  ║   TAPPAY BACKEND — CBN + Fraud Engine            ║
  ║   Port        : ${PORT}                             ║
  ║   Offline Pay : Ed25519-signed, queued sync      ║
  ║   SoftPOS     : Merchant profiles, receipts      ║
  ║   Fraud Screen: Pre-authorization                ║
  ║   KYC Tiers   : 0 → 1 → 2 → 3                  ║
  ╚══════════════════════════════════════════════════╝
  `);
  log.ok(`Server listening on port ${PORT}`);
});

module.exports = app;
