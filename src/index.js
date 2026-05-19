require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const compression = require('compression');
const { log, requestLogger } = require('./logger');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(compression());
app.use(cors({
  origin:         process.env.FRONTEND_URL || '*',
  methods:        ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Device-Id'],
}));

const globalLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 200,
  standardHeaders: true, legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please slow down.' },
});
const authLimit = rateLimit({
  windowMs: 15 * 60 * 1000, max: 10,
  message: { success: false, message: 'Too many login attempts. Try again later.' },
});
const syncLimit = rateLimit({
  windowMs: 60 * 1000, max: 5,
  message: { success: false, message: 'Too many sync attempts. Please wait.' },
});

app.use(globalLimit);
app.use(requestLogger);
app.use('/api/webhook', require('./routes/webhook'));
app.use(express.json({ limit: '50kb' }));

// Routes
app.use('/api/auth',   authLimit, require('./routes/auth'));
app.use('/api/wallet/sync-offline-transactions', syncLimit);
app.use('/api/wallet', require('./routes/wallet'));
app.use('/api/kyc',    require('./routes/kyc'));
app.use('/api/fraud',  require('./routes/fraud'));
app.use('/api/pos',    require('./routes/pos'));

app.get('/health', (_, res) => {
  res.json({ status: 'ok', service: 'TapPay API', timestamp: new Date().toISOString() });
});

app.use((req, res) => {
  res.status(404).json({ success: false, message: `Not found: ${req.method} ${req.path}` });
});

app.use((err, req, res, _next) => {
  log.error('Unhandled exception', err.stack || err.message);
  res.status(500).json({ success: false, message: 'An unexpected error occurred.' });
});

app.listen(PORT, () => {
  log.ok(`TapPay API running on port ${PORT}`);
});

module.exports = app;
