'use strict';

const c = {
  reset:   '\x1b[0m',
  bold:    '\x1b[1m',
  gray:    '\x1b[90m',
  cyan:    '\x1b[36m',
  green:   '\x1b[32m',
  yellow:  '\x1b[33m',
  red:     '\x1b[31m',
  magenta: '\x1b[35m',
  blue:    '\x1b[34m',
};

function ts() {
  return new Date().toISOString().replace('T', ' ').slice(0, 23);
}

function statusColor(code) {
  if (code >= 500) return c.red;
  if (code >= 400) return c.yellow;
  return c.green;
}

function fmt(level, color, msg, data) {
  const prefix = `${c.gray}[${ts()}]${c.reset} ${color}${level.padEnd(5)}${c.reset}`;
  if (data !== undefined && data !== '') {
    const extra = typeof data === 'object' ? JSON.stringify(data) : String(data);
    console.log(`${prefix} ${msg} ${c.gray}${extra}${c.reset}`);
  } else {
    console.log(`${prefix} ${msg}`);
  }
}

const log = {
  info:  (msg, data) => fmt('INFO',  c.cyan,    msg, data),
  ok:    (msg, data) => fmt('OK',    c.green,   msg, data),
  warn:  (msg, data) => fmt('WARN',  c.yellow,  msg, data),
  error: (msg, data) => fmt('ERROR', c.red,     msg, data),
  nfc:   (msg, data) => fmt('NFC',   c.magenta, msg, data),
  auth:  (msg, data) => fmt('AUTH',  c.blue,    msg, data),
};

// Express middleware — logs every request with method, path, status, duration
function requestLogger(req, res, next) {
  const start = Date.now();

  res.on('finish', () => {
    const ms    = Date.now() - start;
    const sc    = statusColor(res.statusCode);
    const body  = req.method !== 'GET' && req.body
      ? ' ' + c.gray + '← ' + JSON.stringify(req.body).slice(0, 120) + c.reset
      : '';

    console.log(
      `${c.gray}[${ts()}]${c.reset} ` +
      `${sc}${res.statusCode}${c.reset} ` +
      `${c.bold}${req.method}${c.reset} ${req.path} ` +
      `${c.gray}(${ms}ms)${c.reset}` +
      body
    );
  });

  next();
}

module.exports = { log, requestLogger };
