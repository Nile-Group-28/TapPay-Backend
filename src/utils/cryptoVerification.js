// src/utils/cryptoVerification.js
const nacl = require('tweetnacl');

/**
 * Verify Ed25519 signature on an offline transaction payload.
 * Returns true only if the signature is cryptographically valid.
 */
function verifyOfflineTransactionSignature(transaction, publicKeyBase64) {
  try {
    const payload = {
      senderId:        transaction.senderId,
      receiverId:      transaction.receiverId,
      amount:          transaction.amount,
      nonce:           transaction.nonce,
      timestamp:       transaction.deviceTimestamp,
    };
    const message   = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = Buffer.from(transaction.signature, 'base64');
    const publicKey = Buffer.from(publicKeyBase64, 'base64');

    if (publicKey.length !== 32) return false;
    if (signature.length !== 64) return false;

    return nacl.sign.detached.verify(
      new Uint8Array(message),
      new Uint8Array(signature),
      new Uint8Array(publicKey)
    );
  } catch {
    return false;
  }
}

/**
 * Returns true when the nonce has NOT been used before (no row in DB).
 */
async function checkNonceUniqueness(nonce, client) {
  const result = await client.query(
    'SELECT 1 FROM offline_transaction_queue WHERE nonce = $1 LIMIT 1',
    [nonce]
  );
  return result.rows.length === 0;
}

/**
 * Validate Ed25519 public key: must be 32 bytes when base64-decoded.
 */
function isValidEd25519PublicKey(base64Key) {
  try {
    const buf = Buffer.from(base64Key, 'base64');
    return buf.length === 32;
  } catch {
    return false;
  }
}

module.exports = {
  verifyOfflineTransactionSignature,
  checkNonceUniqueness,
  isValidEd25519PublicKey,
};
