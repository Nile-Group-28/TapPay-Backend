// src/services/paystack.js
require('dotenv').config();
const axios  = require('axios');
const crypto = require('crypto');

const http = axios.create({
  baseURL: 'https://api.paystack.co',
  headers: {
    Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
    'Content-Type': 'application/json',
  },
});

const paystack = {

  async initializePayment({ email, amount, userId, callbackUrl }) {
    const res = await http.post('/transaction/initialize', {
      email,
      amount:       Math.round(amount * 100),
      currency:     'NGN',
      callback_url: callbackUrl,
      metadata:     { userId },
    });
    if (!res.data.status) throw new Error(res.data.message);
    return {
      authorizationUrl: res.data.data.authorization_url,
      reference:        res.data.data.reference,
    };
  },

  async verifyPayment(reference) {
    const res = await http.get(`/transaction/verify/${reference}`);
    if (!res.data.status) return { success: false };
    const tx = res.data.data;
    return {
      success:   tx.status === 'success',
      amount:    tx.amount / 100,
      reference: tx.reference,
      channel:   tx.channel,
      paidAt:    tx.paid_at,
    };
  },

  async createRecipient({ accountNumber, bankCode, accountName }) {
    const res = await http.post('/transferrecipient', {
      type:           'nuban',
      name:           accountName,
      account_number: accountNumber,
      bank_code:      bankCode,
      currency:       'NGN',
    });
    if (!res.data.status) throw new Error(res.data.message);
    return {
      recipientCode: res.data.data.recipient_code,
      accountName:   res.data.data.details.account_name,
    };
  },

  async sendTransfer({ amount, recipientCode, reference, reason }) {
    const res = await http.post('/transfer', {
      source:    'balance',
      amount:    Math.round(amount * 100),
      recipient: recipientCode,
      reason:    reason || 'TapPay Withdrawal',
      reference,
    });
    if (!res.data.status) throw new Error(res.data.message);
    return {
      transferCode: res.data.data.transfer_code,
      reference:    res.data.data.reference,
      status:       res.data.data.status,
    };
  },

  verifyWebhook(rawBody, signature) {
    const hash = crypto
      .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(rawBody)
      .digest('hex');
    return hash === signature;
  },

};

module.exports = paystack;
