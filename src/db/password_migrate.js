// src/db/password_migrate.js
// Run ONCE after your existing migrations:
//   node src/db/password_migrate.js
// Adds password_hash column and profile fields to users table

require('dotenv').config();
const pool = require('./pool');

async function migrate() {
  const client = await pool.connect();
  try {
    await client.query(`
      ALTER TABLE users
        ADD COLUMN IF NOT EXISTS password_hash TEXT,
        ADD COLUMN IF NOT EXISTS avatar_initials VARCHAR(3),
        ADD COLUMN IF NOT EXISTS address TEXT,
        ADD COLUMN IF NOT EXISTS date_of_birth DATE;
    `);
    console.log('✅  Password and profile columns added.');
  } catch (err) {
    console.error('❌  Migration failed:', err.message);
  } finally {
    client.release();
    await pool.end();
  }
}
migrate();
