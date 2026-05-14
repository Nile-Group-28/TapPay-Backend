'use strict';
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const fs   = require('fs');
const path = require('path');

// Start Express server
require('../src/index');

// Give Express a moment to bind, then open the ngrok tunnel
setTimeout(async () => {
  try {
    const ngrok = require('ngrok');

    const opts = { proto: 'http', addr: PORT };
    if (process.env.NGROK_AUTHTOKEN) {
      opts.authtoken = process.env.NGROK_AUTHTOKEN;
    }
    // Paid plan: set NGROK_DOMAIN to get a fixed URL that never changes
    if (process.env.NGROK_DOMAIN) {
      opts.hostname = process.env.NGROK_DOMAIN;
    }

    const url = await ngrok.connect(opts);
    const apiUrl = `${url}/api`;

    // Write to file so other scripts can read it
    fs.writeFileSync(path.join(__dirname, '..', '.ngrok-url'), apiUrl + '\n');

    const line = '═'.repeat(62);
    console.log(`\n${line}`);
    console.log('  NGROK TUNNEL ACTIVE');
    console.log(`  Public URL : ${url}`);
    console.log(line);
    console.log('\n  Run Flutter against this tunnel:\n');
    console.log(`  flutter run --dart-define=API_BASE_URL=${apiUrl}\n`);
    console.log('  (The URL is also saved to .ngrok-url in this directory)');
    console.log(`${line}\n`);
  } catch (err) {
    console.error('\n[ngrok] Could not start tunnel:', err.message);
    if (err.message.includes('authtoken')) {
      console.log('[ngrok] Tip: set NGROK_AUTHTOKEN in .env for a stable session.');
      console.log('[ngrok]      Sign up free at https://dashboard.ngrok.com');
    }
    console.log('[ngrok] Continuing on local network only.\n');
  }
}, 500);
