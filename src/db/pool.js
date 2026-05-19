// src/db/pool.js
require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST     || 'localhost',
  port:     parseInt(process.env.DB_PORT || '5432', 10),
  database: process.env.DB_NAME     || 'tappay_db',
  user:     process.env.DB_USER     || 'postgres',
  password: process.env.DB_PASSWORD,
  max:      parseInt(process.env.DB_POOL_MAX || '20', 10),
  min:      parseInt(process.env.DB_POOL_MIN || '2',  10),
  idleTimeoutMillis:       30000,
  connectionTimeoutMillis: 5000,
  allowExitOnIdle:         false,
});

pool.on('error', (err) => {
  console.error('Idle client error:', err.message);
});

pool.on('connect', () => {
  if (process.env.NODE_ENV === 'development') {
    console.log('[pool] new connection established');
  }
});

async function query(text, params) {
  const start = Date.now();
  const res   = await pool.query(text, params);
  const ms    = Date.now() - start;
  if (ms > 1000) console.warn(`[pool] slow query (${ms}ms):`, text.slice(0, 120));
  return res;
}

async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, withTransaction };
