'use strict';
require('dotenv').config();

const PORT = process.env.PORT || 3000;
const fs   = require('fs');
const path = require('path');

// Start Express server
require('../src/index');

setTimeout(async () => {
  const authtoken = process.env.NGROK_AUTHTOKEN;

  if (!authtoken) {
    console.log('\n' + '─'.repeat(60));
    console.log('  [ngrok] NGROK_AUTHTOKEN not found in .env');
    console.log('─'.repeat(60));
    console.log('  To get a free token:');
    console.log('    1. Go to https://dashboard.ngrok.com/signup');
    console.log('    2. Copy your authtoken from the "Your Authtoken" page');
    console.log('    3. Add this line to TapPay-Backend/.env:');
    console.log('         NGROK_AUTHTOKEN=your_token_here');
    console.log('    4. Re-run: npm run dev:ngrok');
    console.log('─'.repeat(60) + '\n');
    return;
  }

  try {
    const ngrok = require('@ngrok/ngrok');

    const forwardOpts = { addr: PORT, authtoken };
    if (process.env.NGROK_DOMAIN) {
      forwardOpts.domain = process.env.NGROK_DOMAIN;
    }

    const listener = await ngrok.forward(forwardOpts);
    const url    = listener.url();
    const apiUrl = `${url}/api`;

    fs.writeFileSync(path.join(__dirname, '..', '.ngrok-url'), apiUrl + '\n');

    const line = '═'.repeat(62);
    console.log(`\n${line}`);
    console.log('  NGROK TUNNEL ACTIVE');
    console.log(`  Public URL : ${url}`);
    console.log(line);
    console.log('\n  Run Flutter with this command:\n');
    console.log(`  flutter run --dart-define=API_BASE_URL=${apiUrl}\n`);
    if (process.env.NGROK_DOMAIN) {
      console.log('  (Fixed domain — this URL never changes)');
    } else {
      console.log('  Tip: set NGROK_DOMAIN=your-name.ngrok-free.app in .env');
      console.log('  for a URL that stays the same every time (free static domains');
      console.log('  available at https://dashboard.ngrok.com/domains)');
    }
    console.log(`${line}\n`);
  } catch (err) {
    console.error('\n[ngrok] Failed to start tunnel:', err.message);
    if (err.message.includes('authtoken') || err.message.includes('auth')) {
      console.log('[ngrok] Your NGROK_AUTHTOKEN may be invalid. Check it at:');
      console.log('[ngrok] https://dashboard.ngrok.com/get-started/your-authtoken');
    }
    console.log('[ngrok] Continuing on local network only.\n');
  }
}, 500);
