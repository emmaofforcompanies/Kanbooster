/** 
 * KanBooster Secure API Server
 * All sensitive keys stay here — never exposed to browser
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');
const ws = require('ws');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// ============================================
// SUPABASE (server-side only)
// ============================================
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY,
  {
    realtime: { transport: ws }
  }
);
// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Helmet — sets secure HTTP headers
app.use(helmet({
  contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'",
      "https://checkout.flutterwave.com",
      "https://cdn.jsdelivr.net",
      "https://fonts.googleapis.com",
    ],
    scriptSrcAttr: ["'unsafe-inline'"],
    styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    fontSrc: ["'self'", "https://fonts.gstatic.com"],
    frameSrc: [
      "https://checkout.flutterwave.com",
      "https://checkout-v3-ui-prod.f4b-flutterwave.com",
      "https://www.youtube.com",
      "https://www.youtube-nocookie.com",
      "https://drive.google.com",
    ],
connectSrc: [
  "'self'",
  "https://checkout.flutterwave.com",
  "https://api.flutterwave.com",
  "https://api.ravepay.co",
],
    imgSrc: ["'self'", "data:", "https:"],
  }
  }
}));

// CORS — only allow your domain
const allowedOrigins = [
  `http://localhost:${PORT}`,
  `https://localhost:${PORT}`,
  'https://www.kanbooster.website',
  'https://kanbooster.website',
  'http://www.kanbooster.website',
  'http://kanbooster.website',
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else if (/^http:\/\/192\.168\.\d+\.\d+(:\d+)?$/.test(origin)) {
      // Allow requests from the local Omada portal page (any 192.168.x.x address)
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json({ limit: '10kb' })); // limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// ============================================
// RATE LIMITING
// ============================================

// General API limiter
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  message: { error: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for purchase flow
const purchaseLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 10,
  message: { error: 'Too many purchase attempts. Please wait 10 minutes.' },
  keyGenerator: (req) => req.ip + (req.body?.phone || ''),
});

// Admin login limiter — very strict
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts. Try again in 15 minutes.' },
  skipSuccessfulRequests: true,
});

app.use('/api/', apiLimiter);

// ============================================
// SERVE STATIC FILES
// ============================================
app.use(express.static(path.join(__dirname), {
  index: false,
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    if (filePath.endsWith('.mp4')) {
      res.setHeader('Content-Type', 'video/mp4');
      res.setHeader('Accept-Ranges', 'bytes');
      // Don't block video from being used in same-origin page
    } else {
      res.setHeader('X-Frame-Options', 'DENY');
    }
  }
}));

// ============================================
// INPUT VALIDATION HELPERS
// ============================================


function normalizeSiteName(s) {
  return (s || '').toLowerCase().replace(/\s+/g, '');
}


function sanitizeString(str, maxLen = 200) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().substring(0, maxLen).replace(/[<>\"']/g, '');
}

function isValidPhone(phone) {
  return /^(0|234|\+234)[789][01]\d{8}$/.test(phone.replace(/[\s\-().]/g, ''));
}

function isValidIdentifier(code) {
  return /^[A-Za-z0-9_-]{10,30}$/.test(code);
}

// ============================================
// PUBLIC API ROUTES
// ============================================

// Get active products + site prices
app.get('/api/products', async (req, res) => {
  try {
    const siteName = sanitizeString(req.query.site || '', 50);
    if (!siteName) return res.json({ products: [], requires_site: true });

    const { data, error } = await supabase
  .from('site_prices')
  .select('id, product_id, site_name, price, name, status')
  .ilike('site_name', siteName)
  .eq('status', 'active')
  .order('price', { ascending: true });

    if (error) throw error;

    const result = (data || []).map(p => ({
      product_id: p.product_id,
      name: p.name,
      price: p.price,
      effective_price: p.price,
      status: p.status
    }));

    res.json({ products: result });
  } catch(e) {
    console.error('GET /api/products error:', e);
    res.status(500).json({ error: 'Failed to load products' });
  }
});



// ============================================
// VOUCHER BALANCE LINK TRACKING
// ============================================
app.options('/api/save-balance-link', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.sendStatus(204);
});

app.post('/api/save-balance-link', async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    const voucherCode = sanitizeString(req.body.voucher_code || '', 30);
    const balancePath = sanitizeString(req.body.balance_url || '', 500);
    const siteName = normalizeSiteName(sanitizeString(req.body.site_name || '', 50));
    if (!voucherCode || !balancePath) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    await supabase.from('voucher_balance_links').upsert({
      voucher_code: voucherCode,
      balance_url: balancePath,
      site_name: siteName,
      updated_at: new Date().toISOString(),
    }, { onConflict: 'voucher_code' });
    res.json({ success: true });
  } catch(e) {
    console.error('save-balance-link error:', e);
    res.status(500).json({ error: 'Failed to save' });
  }
});

app.post('/api/get-balance-link', async (req, res) => {
  try {
    const voucherCode = sanitizeString(req.body.voucher_code || '', 30);
    const confirmedSite = normalizeSiteName(sanitizeString(req.body.site_name || '', 50));
    if (!voucherCode) return res.status(400).json({ error: 'Voucher code required' });
    if (!confirmedSite) return res.json({ found: false, error: 'site_required' });

    const { data: link } = await supabase.from('voucher_balance_links')
      .select('balance_url, updated_at')
      .eq('voucher_code', voucherCode)
      .single();

    if (!link) return res.json({ found: false });

    const { data: config } = await supabase.from('site_balance_config')
      .select('balance_url')
      .eq('site_name', confirmedSite)
      .single();

    if (!config) return res.json({ found: false, error: 'site_config_missing' });

    if (!link.balance_url) {
      return res.json({ found: false, error: 'no_balance_url' });
    }
    const fullUrl = config.balance_url.replace(/\/$/, '') + link.balance_url;
    res.json({ found: true, balance_url: fullUrl, updated_at: link.updated_at });
  } catch(e) {
    res.json({ found: false });
  }
});

// Validate site name
app.post('/api/validate-site', async (req, res) => {
  try {
    const siteName = sanitizeString(req.body.site_name || '', 50);
    if (!siteName) return res.json({ valid: false });

    const { data } = await supabase
      .from('settings')
      .select('setting_value')
      .eq('setting_name', 'site_names')
      .single();

    const validSites = data
      ? data.setting_value.split(',').map(s => s.trim().toLowerCase().replace(/\s+/g, ''))
      : [];

    const siteClean = siteName.toLowerCase().replace(/\s+/g, '');
    res.json({ valid: validSites.includes(siteClean) });
  } catch(e) {
  console.error('validate-site error:', e);
  res.status(500).json({ error: e.message });
}
});

// Get list of valid site names
app.get('/api/sites', async (req, res) => {
  try {
    const { data } = await supabase
      .from('settings')
      .select('setting_value')
      .eq('setting_name', 'site_names')
      .single();

    const sites = data
      ? data.setting_value.split(',').map(s => s.trim()).filter(Boolean)
      : [];

    res.json({ sites });
  } catch(e) {
    res.status(500).json({ error: 'Could not load sites' });
  }
});



// Check stock
app.post('/api/check-stock', async (req, res) => {
  try {
    const productId = parseInt(req.body.product_id);
    const siteName = sanitizeString(req.body.site_name || '', 50).replace(/\s+/g, '');

    if (!productId || !siteName) return res.json({ in_stock: false });

    const { count } = await supabase
      .from('codes')
      .select('*', { count: 'exact', head: true })
      .eq('product_id', String(productId))
      .eq('status', 'unused')
      .ilike('site_name', siteName);

    res.json({ in_stock: (count || 0) > 0, count: count || 0 });
  } catch(e) {
    res.status(500).json({ error: 'Stock check failed' });
  }
});


app.post('/api/check-customer', purchaseLimiter, async (req, res) => {
  try {
    const phone = sanitizeString(req.body.phone || '', 15);
    const siteName = sanitizeString(req.body.site_name || '', 50).replace(/\s+/g,'').toLowerCase();
    if (!isValidPhone(phone)) return res.status(400).json({ error: 'Invalid phone number' });

    const { data: existing } = await supabase
      .from('customer_register').select('id').eq('phone', phone).single();

    if (existing) return res.json({ is_new: false });

    // New customer — caller must collect lodge_name next, then call /api/register-customer
    return res.json({ is_new: true });
  } catch(e) {
    res.status(500).json({ error: 'Check failed' });
  }
});

app.post('/api/register-customer', purchaseLimiter, async (req, res) => {
  try {
    const phone = sanitizeString(req.body.phone || '', 15);
    const siteName = sanitizeString(req.body.site_name || '', 50).replace(/\s+/g,'').toLowerCase();
    const lodgeName = sanitizeString(req.body.lodge_name || '', 100);
    if (!isValidPhone(phone)) return res.status(400).json({ error: 'Invalid phone number' });
    if (!lodgeName) return res.status(400).json({ error: 'Lodge name required' });

    await supabase.from('customer_register').upsert({
      phone, site_name: siteName, lodge_name: lodgeName,
      source: 'auto', updated_at: new Date().toISOString(),
    }, { onConflict: 'phone' });

    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: 'Registration failed' });
  }
});


// Pre-fetch: generate a bank account speculatively at site validation time.
// The identifier is reserved here; /api/create-transaction will link phone+product later.
app.post('/api/create-transaction-prefetch', async (req, res) => {
  try {
    const siteName = sanitizeString(req.body.site_name || '', 50).replace(/\s+/g, '').toLowerCase();
    const prefetchId = sanitizeString(req.body.prefetch_id || '', 30);

    if (!siteName || !isValidIdentifier(prefetchId)) {
      return res.status(400).json({ error: 'Invalid prefetch params' });
    }

    // Use a placeholder phone/amount — the real values come later at create-transaction
    // We just want Flutterwave to warm up the account
    const PLACEHOLDER_PHONE = '08000000000';
    const PLACEHOLDER_AMOUNT = 500; // smallest typical amount; will be replaced

    const https = require('https');
    const payload = JSON.stringify({
      tx_ref: prefetchId,
      amount: PLACEHOLDER_AMOUNT,
      currency: 'NGN',
      email: 'customer@kanbooster.website',
      phone_number: PLACEHOLDER_PHONE,
      fullname: 'KanBooster Customer',
      is_permanent: false,
    });

    const bankAccount = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.flutterwave.com',
        path: '/v3/charges?type=bank_transfer',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      };
      const r = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch(e) { reject(new Error('Invalid FLW response')); }
        });
      });
      r.on('error', reject);
      r.write(payload);
      r.end();
    });

    if (bankAccount.status !== 'success') {
      return res.status(400).json({ error: bankAccount.message || 'Prefetch failed' });
    }

const meta = bankAccount.meta?.authorization;
    console.log('FLW FULL META:', JSON.stringify(bankAccount.meta, null, 2));
    res.json({
      success: true,
      bank_name: meta?.transfer_bank || meta?.bank_name || '',
      account_number: meta?.transfer_account || '',
      account_name: meta?.account_name || 'KanBooster Payment',
      amount: meta?.transfer_amount || PLACEHOLDER_AMOUNT,
      note: meta?.transfer_note || '',
      expires_at: meta?.transfer_expires_at || '',
    });

  } catch(e) {
    console.error('prefetch error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Create transaction (purchase initiation)
app.post('/api/create-transaction', purchaseLimiter, async (req, res) => {
  try {
    const phone = sanitizeString(req.body.phone || '', 15);
    const siteName = sanitizeString(req.body.site_name || '', 50).replace(/\s+/g, '').toLowerCase();
    const productId = parseInt(req.body.product_id);
    const identifierCode = sanitizeString(req.body.identifier_code || '', 30);

    // Validate inputs
    if (!isValidPhone(phone)) return res.status(400).json({ error: 'Invalid phone number' });
    if (!productId) return res.status(400).json({ error: 'Invalid product' });
    if (!isValidIdentifier(identifierCode)) return res.status(400).json({ error: 'Invalid identifier' });

    // Validate site
    const { data: sitesSetting } = await supabase
      .from('settings').select('setting_value').eq('setting_name', 'site_names').single();
    const validSites = sitesSetting
      ? sitesSetting.setting_value.split(',').map(s => s.trim().toLowerCase().replace(/\s+/g,''))
      : [];
    if (!validSites.includes(siteName)) return res.status(400).json({ error: 'Invalid site name' });

    // Check stock
    const { count } = await supabase.from('codes')
      .select('*', { count: 'exact', head: true })
      .eq('product_id', String(productId))
      .eq('status', 'unused')
      .ilike('site_name', siteName);
    if (!count || count === 0) return res.status(400).json({ error: 'Out of stock' });

    // Get price
    const { data: spProduct } = await supabase
  .from('site_prices')
  .select('price, name')
  .eq('product_id', String(productId))
  .ilike('site_name', siteName)
  .eq('status', 'active')
  .single();
if (!spProduct) return res.status(400).json({ error: 'Product not found for this site' });

const finalPrice = parseInt(spProduct.price);
const product = { name: spProduct.name, price: finalPrice };

    // Check for duplicate identifier
    const { data: existing } = await supabase
      .from('web_transactions').select('id').eq('payment_code', identifierCode).single();
    if (existing) return res.status(400).json({ error: 'Identifier already used' });

    // Insert transaction
    const { data, error } = await supabase.from('web_transactions').insert({
      timestamp: new Date().toISOString(),
      product_id: String(productId),
      amount: String(finalPrice),
      payment_code: identifierCode,
      status: 'pending',
      site_name: siteName,
      voucher_code: '',
      sent: 'undelivered',
      check_count: 0,
      phone: phone,
      recipient_phone: phone,
      device_id: sanitizeString(req.body.device_id || '', 100),
      delivery_method: 'web',
    }).select().single();

    if (error) throw error;

    res.json({
      success: true,
      identifier: identifierCode,
      amount: finalPrice,
      product_name: product.name,
      flw_public_key: process.env.FLW_PUBLIC_KEY,  // only public key sent to browser
    });
  } catch(e) {
    console.error('create-transaction error:', e);
    res.status(500).json({ error: 'Failed to create transaction' });
  }
});


// Get Flutterwave temp bank account for direct bank transfer
app.post('/api/get-bank-account', async (req, res) => {
  try {
    const identifierCode = sanitizeString(req.body.identifier_code || '', 30);
    const phone = sanitizeString(req.body.phone || '', 15);
    const amount = parseInt(req.body.amount);
    const email = 'customer@kanbooster.website';

    if (!identifierCode || !phone || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const https = require('https');
    const payload = JSON.stringify({
      tx_ref: identifierCode,
      amount: amount,
      currency: 'NGN',
      email: email,
      phone_number: phone,
      fullname: 'KanBooster Customer',
      is_permanent: false,
    });

    const bankAccount = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.flutterwave.com',
        path: '/v3/charges?type=bank_transfer',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload),
        },
      };

      const r = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          try { resolve(JSON.parse(data)); }
          catch(e) { reject(new Error('Invalid response from Flutterwave')); }
        });
      });
      r.on('error', reject);
      r.write(payload);
      r.end();
    });

    if (bankAccount.status !== 'success') {
      console.error('FLW bank account error:', bankAccount);
      return res.status(400).json({ error: bankAccount.message || 'Could not generate bank account' });
    }

    const meta = bankAccount.meta?.authorization;
res.json({
  success: true,
  bank_name: meta?.transfer_bank || '',
  account_number: meta?.transfer_account || '',
  account_name: meta?.transfer_note || 'KanBooster Payment',
  amount: meta?.transfer_amount || amount,
  note: meta?.transfer_note || '',
  expires_at: meta?.account_expiration || '',
});
  } catch(e) {
    console.error('get-bank-account error:', e);
    res.status(500).json({ error: e.message });
  }
});


// Get Paystack virtual account for bank transfer
app.post('/api/get-paystack-bank-account', async (req, res) => {
  try {
    const identifierCode = sanitizeString(req.body.identifier_code || '', 30);
    const phone = sanitizeString(req.body.phone || '', 15);
    const amount = parseInt(req.body.amount);

    if (!identifierCode || !phone || !amount) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const https = require('https');

    // Step 1: Create a Paystack customer
    const customerPayload = JSON.stringify({
      email: `${phone}@kanbooster.website`,
      phone: phone,
      first_name: 'KanBooster',
      last_name: 'Customer',
    });

    const customer = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.paystack.co',
        path: '/customer',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(customerPayload),
        },
      };
      const r = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(new Error('Invalid Paystack response')); } });
      });
      r.on('error', reject);
      r.write(customerPayload);
      r.end();
    });

    if (!customer.status) {
      return res.status(400).json({ error: customer.message || 'Could not create Paystack customer' });
    }

    const customerCode = customer.data.customer_code;

    // Step 2: Create dedicated virtual account
    const dvaPayload = JSON.stringify({
      customer: customerCode,
      preferred_bank: 'wema-bank',
    });

    const dva = await new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.paystack.co',
        path: '/dedicated_account',
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(dvaPayload),
        },
      };
      const r = https.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => { try { resolve(JSON.parse(data)); } catch(e) { reject(new Error('Invalid Paystack DVA response')); } });
      });
      r.on('error', reject);
      r.write(dvaPayload);
      r.end();
    });

    if (!dva.status) {
      return res.status(400).json({ error: dva.message || 'Could not generate Paystack virtual account' });
    }

    const acct = dva.data;
    res.json({
      success: true,
      bank_name: acct.bank?.name || 'Wema Bank',
      account_number: acct.account_number || '',
      account_name: acct.account_name || 'KanBooster Payment',
      amount: amount,
    });

  } catch(e) {
    console.error('get-paystack-bank-account error:', e);
    res.status(500).json({ error: e.message });
  }
});

// ============================================
// FLUTTERWAVE WEBHOOK
// ============================================
app.post('/api/flw-webhook', async (req, res) => {
  try {
    // Verify the request actually came from Flutterwave
    const signature = req.headers['verif-hash'];
    if (!signature || signature !== process.env.FLW_SECRET_HASH) {
      console.warn('Webhook: invalid signature');
      return res.status(401).end();
    }

    const payload = req.body;
    const txRef = payload?.data?.tx_ref;
    const flwStatus = payload?.data?.status;
    const paidAmount = parseFloat(payload?.data?.amount);
    const flwRef = String(payload?.data?.id || '');

    // Acknowledge immediately — Flutterwave just wants a fast 200
    res.status(200).json({ received: true });

    if (!txRef || flwStatus !== 'successful') return;

    const identifierCode = txRef;

    const { data: txn } = await supabase
      .from('web_transactions').select('*').eq('payment_code', identifierCode).single();
    if (!txn) return;

    // Already completed — nothing to do
    if (txn.status === 'completed' && txn.voucher_code) return;

    const expectedAmount = parseFloat(txn.amount);

    if (paidAmount < expectedAmount) {
      await supabase.from('web_transactions').update({ status: 'underpaid', flw_ref: flwRef })
        .eq('payment_code', identifierCode);
      return;
    }
    if (paidAmount > expectedAmount) {
      await supabase.from('web_transactions').update({ status: 'overpaid', flw_ref: flwRef })
        .eq('payment_code', identifierCode);
      return;
    }

    // Exact match — deliver voucher
    const voucher = await assignVoucher(txn.product_id, txn.site_name);
    if (!voucher) {
      await supabase.from('web_transactions').update({ status: 'out_of_stock', flw_ref: flwRef })
        .eq('payment_code', identifierCode);
      return;
    }

    await supabase.from('web_transactions').update({
      status: 'completed',
      voucher_code: voucher,
      sent: 'delivered',
      flw_ref: flwRef,
      delivered_at: new Date().toISOString(),
    }).eq('payment_code', identifierCode);

  } catch(e) {
    console.error('webhook error:', e);
    // Already responded 200 above, so just log
  }
});


// ============================================
// PAYSTACK WEBHOOK
// ============================================
app.post('/api/paystack-webhook', async (req, res) => {
  try {
    const crypto = require('crypto');
    const hash = crypto.createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(JSON.stringify(req.body)).digest('hex');

    if (hash !== req.headers['x-paystack-signature']) {
      console.warn('Paystack webhook: invalid signature');
      return res.status(401).send('Unauthorized');
    }

    res.status(200).send('OK'); // acknowledge immediately

    const event = req.body;
    if (event.event !== 'charge.success') return;

    const amountPaid = event.data.amount / 100; // Paystack sends kobo
    const customerEmail = event.data.customer?.email || '';
    const phone = customerEmail.replace('@kanbooster.website', '');

    // Find the latest pending transaction for this phone
    const { data: txns } = await supabase
      .from('web_transactions')
      .select('*')
      .eq('phone', phone)
      .eq('status', 'pending')
      .order('timestamp', { ascending: false })
      .limit(1);

    if (!txns || txns.length === 0) {
      console.warn('Paystack webhook: no pending transaction for phone', phone);
      return;
    }

    const txn = txns[0];
    const expectedAmount = parseInt(txn.amount);

    if (amountPaid < expectedAmount) {
      await supabase.from('web_transactions').update({ status: 'underpaid' }).eq('id', txn.id);
      return;
    }

    // Mark as confirmed then deliver voucher
    await supabase.from('web_transactions').update({ status: 'confirmed' }).eq('id', txn.id);

    // Reuse your existing voucher delivery logic
    const { data: code } = await supabase
      .from('codes')
      .select('*')
      .eq('product_id', String(txn.product_id))
      .eq('status', 'unused')
      .ilike('site_name', txn.site_name)
      .limit(1)
      .single();

    if (!code) {
      await supabase.from('web_transactions').update({ status: 'out_of_stock' }).eq('id', txn.id);
      return;
    }

    await supabase.from('codes').update({ status: 'used' }).eq('id', code.id);
    await supabase.from('web_transactions').update({
      status: 'completed',
      voucher_code: code.code,
      sent: 'delivered',
    }).eq('id', txn.id);

    console.log(`Paystack: voucher ${code.code} delivered to ${phone}`);

  } catch(e) {
    console.error('Paystack webhook error:', e);
  }
});

// Confirm payment and deliver voucher (called after FLW callback)
app.post('/api/confirm-payment', purchaseLimiter, async (req, res) => {
  try {
    const identifierCode = sanitizeString(req.body.identifier_code || '', 30);
    const flwRef = sanitizeString(req.body.flw_ref || '', 100);
    const txRef = sanitizeString(req.body.tx_ref || '', 100);

    if (!isValidIdentifier(identifierCode)) return res.status(400).json({ error: 'Invalid identifier' });

    // Verify payment with Flutterwave API server-side
    let verifiedAmount = null;
    let verifiedStatus = null;

    if (flwRef) {
      try {
        const https = require('https');
        const verifyResponse = await new Promise((resolve, reject) => {
          const options = {
            hostname: 'api.flutterwave.com',
            path: `/v3/transactions/${flwRef}/verify`,
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
              'Content-Type': 'application/json',
              'User-Agent': 'Mozilla/5.0 (compatible; KanBooster/1.0)',
            }
          };
          const r = https.request(options, (resp) => {
            let data = '';
            resp.on('data', chunk => data += chunk);
            resp.on('end', () => resolve(JSON.parse(data)));
          });
          r.on('error', reject);
          r.end();
        });

        if (verifyResponse.status === 'success') {
          verifiedAmount = parseFloat(verifyResponse.data.amount);
          verifiedStatus = verifyResponse.data.status;
        }
      } catch(e) {
        console.error('FLW verify error:', e);
      }
    }

    // Get transaction
    const { data: txn } = await supabase
      .from('web_transactions').select('*').eq('payment_code', identifierCode).single();
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    // Already completed
    if (txn.status === 'completed' && txn.voucher_code) {
      return res.json({ success: true, voucher: txn.voucher_code });
    }

    // Amount check (if verified)
    if (verifiedAmount !== null) {
      const expectedAmount = parseFloat(txn.amount);
      if (verifiedAmount < expectedAmount) {
        await supabase.from('web_transactions').update({ status: 'underpaid', flw_ref: flwRef })
          .eq('payment_code', identifierCode);
        return res.status(400).json({ error: 'underpaid', paid: verifiedAmount, expected: expectedAmount });
      }
      if (verifiedAmount > expectedAmount) {
        await supabase.from('web_transactions').update({ status: 'overpaid', flw_ref: flwRef })
          .eq('payment_code', identifierCode);
        return res.status(400).json({ error: 'overpaid', paid: verifiedAmount, expected: expectedAmount });
      }
    }

    // Update to confirmed
    await supabase.from('web_transactions').update({
      status: 'confirmed',
      flw_ref: flwRef || txn.flw_ref,
    }).eq('payment_code', identifierCode);

    // Assign voucher
    const voucher = await assignVoucher(txn.product_id, txn.site_name);

    if (!voucher) {
      await supabase.from('web_transactions').update({ status: 'out_of_stock' }).eq('payment_code', identifierCode);
      return res.status(400).json({ error: 'out_of_stock' });
    }

    // Mark delivered
    await supabase.from('web_transactions').update({
      status: 'completed',
      voucher_code: voucher,
      sent: 'delivered',
      delivered_at: new Date().toISOString(),
    }).eq('payment_code', identifierCode);

    res.json({ success: true, voucher });

  } catch(e) {
    console.error('confirm-payment error:', e);
    res.status(500).json({ error: 'Payment confirmation failed' });
  }
});





app.get('/api/admin/customer-register', verifyAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('customer_register').select('*').order('created_at', { ascending: false }).limit(500);
    if (error) throw error;
    res.json({ customers: data || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/admin/upload-register', verifyAdmin, async (req, res) => {
  try {
    const rows = req.body.rows;
    if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'No rows provided' });

    const batch = rows.map(r => ({
      phone: sanitizeString(r.phone, 15),
      site_name: sanitizeString(r.site_name || '', 50).replace(/\s+/g,'').toLowerCase(),
      lodge_name: sanitizeString(r.lodge_name || '', 100),
      source: 'admin_upload',
      updated_at: new Date().toISOString(),
    })).filter(r => isValidPhone(r.phone));

    const { error } = await supabase.from('customer_register')
      .upsert(batch, { onConflict: 'phone' });   // <-- updates existing row if phone exists
    if (error) throw error;

    res.json({ success: true, uploaded: batch.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// Admin: bulk-assign lodge name to selected phones (marks source as admin_upload)
app.post('/api/admin/bulk-update-lodge', verifyAdmin, async (req, res) => {
  try {
    const { phones, lodge_name } = req.body;
    if (!Array.isArray(phones) || phones.length === 0) return res.status(400).json({ error: 'No phones selected' });
    const lodgeName = sanitizeString(lodge_name || '', 100);
    if (!lodgeName) return res.status(400).json({ error: 'Lodge name required' });

    const { error } = await supabase.from('customer_register')
      .update({ lodge_name: lodgeName, source: 'admin_upload', updated_at: new Date().toISOString() })
      .in('phone', phones);
    if (error) throw error;

    res.json({ success: true, updated: phones.length });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// Check transaction status (polling)
// Check transaction status (polling) — also auto-verifies pending payments via FLW
app.get('/api/transaction-status', async (req, res) => {
  try {
    const identifierCode = sanitizeString(req.query.code || '', 30);
    if (!isValidIdentifier(identifierCode)) return res.status(400).json({ error: 'Invalid code' });

    const { data: txn } = await supabase.from('web_transactions')
      .select('status, voucher_code, sent, check_count, flw_ref, amount, product_id, site_name')
      .eq('payment_code', identifierCode)
      .single();

    if (!txn) return res.status(404).json({ error: 'Not found' });

    // Always increment check_count
    await supabase.from('web_transactions')
      .update({ check_count: (txn.check_count || 0) + 1 })
      .eq('payment_code', identifierCode);

    // Already done — return immediately
    if (txn.status === 'completed' && txn.voucher_code) {
      const { data: spName } = await supabase
  .from('site_prices')
  .select('name')
  .eq('product_id', txn.product_id)
  .ilike('site_name', txn.site_name)
  .single();
return res.json({ status: 'completed', voucher: txn.voucher_code, product_name: spName?.name || '' });
    }

    // If still pending, search FLW for a matching payment by tx_ref
    if (txn.status === 'pending' || txn.status === 'confirmed') {
      try {
        const https = require('https');

        // Search FLW transactions by tx_ref (the identifierCode)
        const flwSearch = await new Promise((resolve, reject) => {
          const options = {
            hostname: 'api.flutterwave.com',
            path: `/v3/transactions?tx_ref=${encodeURIComponent(identifierCode)}`,
            method: 'GET',
            headers: {
              'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}`,
              'Content-Type': 'application/json',
              'User-Agent': 'Mozilla/5.0 (compatible; KanBooster/1.0)',
            }
          };
          const req2 = https.request(options, (resp) => {
            let d = '';
            resp.on('data', chunk => d += chunk);
            resp.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
          });
          req2.on('error', reject);
          req2.end();
        });

        console.log(`[status-poll] FLW search for ${identifierCode}:`, JSON.stringify(flwSearch?.data?.length), 'results');

        if (flwSearch.status === 'success' && flwSearch.data && flwSearch.data.length > 0) {
          const flwTxn = flwSearch.data[0];
          const paidAmount = parseFloat(flwTxn.amount);
          const expectedAmount = parseFloat(txn.amount);
          const flwRef = String(flwTxn.id);

          if (flwTxn.status === 'successful') {
            if (paidAmount < expectedAmount) {
              await supabase.from('web_transactions')
                .update({ status: 'underpaid', flw_ref: flwRef })
                .eq('payment_code', identifierCode);
              return res.json({ status: 'underpaid', voucher: null });
            }

            if (paidAmount > expectedAmount) {
              await supabase.from('web_transactions')
                .update({ status: 'overpaid', flw_ref: flwRef })
                .eq('payment_code', identifierCode);
              return res.json({ status: 'overpaid', voucher: null });
            }

            // Exact match — deliver voucher
            const voucher = await assignVoucher(txn.product_id, txn.site_name);
            if (!voucher) {
              await supabase.from('web_transactions')
                .update({ status: 'out_of_stock', flw_ref: flwRef })
                .eq('payment_code', identifierCode);
              return res.json({ status: 'out_of_stock', voucher: null });
            }

            await supabase.from('web_transactions').update({
              status: 'completed',
              voucher_code: voucher,
              sent: 'delivered',
              flw_ref: flwRef,
              delivered_at: new Date().toISOString(),
            }).eq('payment_code', identifierCode);

            return res.json({ status: 'completed', voucher });
          }
        }
      } catch(e) {
        console.error('[status-poll] FLW lookup error:', e.message);
        // Fall through — return current status without delivery
      }
    }

    res.json({ status: txn.status, voucher: null });
  } catch(e) {
    res.status(500).json({ error: 'Status check failed' });
  }
});

// Retrieve voucher (device-verified)
app.post('/api/retrieve-voucher', async (req, res) => {
  try {
    const phone = sanitizeString(req.body.phone || '', 15);
    const deviceId = sanitizeString(req.body.device_id || '', 100);

    if (!isValidPhone(phone)) return res.status(400).json({ error: 'Invalid phone' });
    if (!deviceId) return res.status(400).json({ error: 'Missing device ID' });

    // Get Max_no_id window from settings (default 15 mins)
    const cutoff = new Date(Date.now() - 15 * 60 * 1000).toISOString(); // 15 mins only
    const pendingCutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // 24hrs — pending FLW check

    // First check for already-completed transactions
    let { data } = await supabase.from('web_transactions')
      .select('payment_code, voucher_code, amount, timestamp, site_name, device_id')
      .eq('phone', phone)
      .eq('status', 'completed')
      .gte('timestamp', cutoff)
      .order('timestamp', { ascending: false })
      .limit(3);

    // Also check for pending transactions — user may have paid after closing browser
    const { data: pending } = await supabase.from('web_transactions')
      .select('*')
      .eq('phone', phone)
      .eq('status', 'pending')
      .gte('timestamp', pendingCutoff)
      .order('timestamp', { ascending: false })
      .limit(3);

    // For each pending transaction, check FLW and complete it on the spot
    if (pending && pending.length > 0) {
      for (const txn of pending) {
        try {
          const flwSearch = await new Promise((resolve, reject) => {
            const https = require('https');
            const options = {
              hostname: 'api.flutterwave.com',
              path: `/v3/transactions?tx_ref=${encodeURIComponent(txn.payment_code)}`,
              method: 'GET',
              headers: { 'Authorization': `Bearer ${process.env.FLW_SECRET_KEY}` },
            };
            const r = https.request(options, (response) => {
              let d = '';
              response.on('data', chunk => d += chunk);
              response.on('end', () => { try { resolve(JSON.parse(d)); } catch(e) { reject(e); } });
            });
            r.on('error', reject);
            r.end();
          });

          const flwTxn = flwSearch?.data?.[0];
          if (flwTxn && flwTxn.status === 'successful') {
            // Payment confirmed — assign voucher now
            const voucherCode = await assignVoucher(txn.product_id, txn.site_name);
            if (voucherCode) {
              await supabase.from('web_transactions').update({
                status: 'completed',
                voucher_code: voucherCode,
                sent: 'delivered',
                delivery_method: 'web',
                flw_ref: flwTxn.flw_ref,
                delivered_at: new Date().toISOString(),
              }).eq('payment_code', txn.payment_code);

              // Add to completed list so it shows up below
              if (!data) data = [];
              data.push({ ...txn, voucher_code: voucherCode, status: 'completed' });
            }
          }
        } catch(e) {
          console.error('retrieve: pending FLW check error:', e.message);
        }
      }
    }

    if (!data || data.length === 0) {
      return res.json({ found: false });
    }
    // Device must always match — no exceptions
    const matching = data.filter(t => t.device_id === deviceId);

    if (matching.length === 0) {
      return res.json({ found: false, device_mismatch: true });
    }

    res.json({
      found: true,
      vouchers: matching.map(t => ({
        voucher_code: t.voucher_code,
        amount: t.amount,
        timestamp: t.timestamp,
        site_name: t.site_name,
      }))
    });
  } catch(e) {
    console.error('retrieve-voucher error:', e);
    res.status(500).json({ error: e.message });
  }
});

// Get settings (only safe public ones)
app.get('/api/public-settings', async (req, res) => {
  try {
    const SAFE_SETTINGS = ['support_phone', 'terms_link', 'tutorial_link', 'auto_check_interval', 'review_link', 'Max_no_id'];
    const { data } = await supabase.from('settings').select('*').in('setting_name', SAFE_SETTINGS);
    const result = {};
    if (data) data.forEach(s => { result[s.setting_name] = s.setting_value; });
    res.json(result);
  } catch(e) {
    res.status(500).json({ error: 'Settings error' });
  }
});

// ============================================
// ADMIN API ROUTES (protected by admin token)
// ============================================

async function verifyAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const { data } = await supabase.from('admin_sessions')
    .select('username, expires_at')
    .eq('token', token)
    .single();

  if (!data || new Date(data.expires_at) < new Date()) {
    return res.status(401).json({ error: 'Session expired. Please login again.' });
  }
  req.adminUser = data.username;
  next();
}

// Admin login
// Admin login
app.post('/api/admin/login', async (req, res) => {
  try {
    // Strip ALL whitespace and special chars from username, just trim password
    const username = (req.body.username || '').replace(/\s+/g, '').substring(0, 50);
    const password = (req.body.password || '').trim().substring(0, 100);

    if (!username || !password) {
      return res.status(400).json({ error: 'Missing credentials' });
    }

    console.log(`Login attempt — username: "${username}" password length: ${password.length}`);

    // Fetch by username only, then check password manually (case insensitive username)
    const { data: users } = await supabase
      .from('admin_users')
      .select('*')
      .ilike('username', username)
      .eq('active', true);

    const user = users && users.find(u => u.password === password);

    if (!user) {
      console.warn(`Failed login — username: "${username}" from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000);

    await supabase.from('admin_sessions').insert({
      token,
      username: user.username,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
    });

    try {
      await supabase.from('admin_logins').insert({
        username: user.username,
        logged_in_at: new Date().toISOString(),
        ip: req.ip
      });
    } catch(e) {}

    res.json({ success: true, token, username: user.username });
  } catch(e) {
    console.error('Admin login error:', e);
    res.status(500).json({ error: 'Login failed: ' + e.message });
  }
});

// Admin logout
app.post('/api/admin/logout', verifyAdmin, async (req, res) => {
  const token = req.headers['x-admin-token'];
  await supabase.from('admin_sessions').delete().eq('token', token);
  res.json({ success: true });
});

// Admin: get transactions
app.get('/api/admin/transactions', verifyAdmin, async (req, res) => {
  try {
    const { from, to, status, search, site, lodge, page = 1 } = req.query;
    const pageSize = 50;

    let phoneFilter = null;
    if (lodge) {
      const { data: lodgeMatches } = await supabase
        .from('customer_register').select('phone').ilike('lodge_name', `%${lodge}%`);
      phoneFilter = (lodgeMatches || []).map(r => r.phone);
      if (phoneFilter.length === 0) return res.json({ data: [], count: 0 });
    }

    let query = supabase.from('web_transactions').select('*', { count: 'exact' });
    if (from) query = query.gte('timestamp', from + 'T00:00:00');
    if (to) query = query.lte('timestamp', to + 'T23:59:59');
    if (status) query = query.eq('status', status);
    if (site) query = query.ilike('site_name', site.replace(/\s+/g, ''));
    if (phoneFilter) query = query.in('phone', phoneFilter);
    if (search) query = query.or(`phone.ilike.%${search}%,payment_code.ilike.%${search}%`);
    query = query.order('timestamp', { ascending: false })
      .range((page - 1) * pageSize, page * pageSize - 1);

    const { data, count } = await query;

    const phones = [...new Set((data || []).map(t => t.phone).filter(Boolean))];
    let lodgeMap = {};
    if (phones.length > 0) {
      const { data: regs } = await supabase
        .from('customer_register').select('phone, lodge_name').in('phone', phones);
      (regs || []).forEach(r => { lodgeMap[r.phone] = r.lodge_name; });
    }
    const enriched = (data || []).map(t => ({ ...t, lodge_name: lodgeMap[t.phone] || '' }));

    res.json({ data: enriched, count });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
// Admin: get dashboard stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { from, to } = req.query;
    let query = supabase.from('web_transactions').select('status, amount, site_name, phone');
    if (from) query = query.gte('timestamp', from + 'T00:00:00');
    if (to) query = query.lte('timestamp', to + 'T23:59:59');
    const { data } = await query;

    // Enrich with lodge_name from customer_register
    const phones = [...new Set((data || []).map(t => t.phone).filter(Boolean))];
    let lodgeMap = {};
    if (phones.length > 0) {
      const { data: regs } = await supabase
        .from('customer_register').select('phone, lodge_name').in('phone', phones);
      (regs || []).forEach(r => { lodgeMap[r.phone] = r.lodge_name; });
    }
    const enriched = (data || []).map(t => ({ ...t, lodge_name: lodgeMap[t.phone] || '' }));

    res.json({ data: enriched });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get stock
app.get('/api/admin/stock', verifyAdmin, async (req, res) => {
  try {
    const { data: productsRaw } = await supabase.from('site_prices').select('*').order('product_id');
    const { data: sitesSetting } = await supabase.from('settings').select('setting_value').eq('setting_name','site_names').single();
    const sites = sitesSetting ? sitesSetting.setting_value.split(',').map(s => s.trim()) : [];

    // Deduplicate products by product_id — site_prices may have one row per site per product
    const seen = new Set();
    const products = (productsRaw || []).filter(p => {
      if (seen.has(p.product_id)) return false;
      seen.add(p.product_id);
      return true;
    });

    const stock = [];
    for (const p of products) {
      for (const site of sites) {
        const siteClean = site.toLowerCase().replace(/\s+/g,'');
        const { count: unused } = await supabase.from('codes').select('*', { count:'exact', head:true })
          .eq('product_id', String(p.product_id)).eq('status','unused').ilike('site_name', siteClean);
        const { count: used } = await supabase.from('codes').select('*', { count:'exact', head:true })
          .eq('product_id', String(p.product_id)).eq('status','used').ilike('site_name', siteClean);
        stock.push({ product_id: p.product_id, product_name: p.name, site, unused: unused||0, used: used||0 });
      }
    }
    res.json({ stock });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: upload codes
app.post('/api/admin/upload-codes', verifyAdmin, async (req, res) => {
  try {
    const codes = req.body.codes;
    if (!Array.isArray(codes) || codes.length === 0) return res.status(400).json({ error: 'No codes provided' });

    const batchSize = 500;
    let total = 0;
    for (let i = 0; i < codes.length; i += batchSize) {
      const batch = codes.slice(i, i + batchSize).map(c => ({
        voucher_code: sanitizeString(c.voucher_code, 100),
        product_id: String(parseInt(c.product_id)),
        site_name: sanitizeString(c.site_name, 50),
        status: 'unused'
      }));
      const { error } = await supabase.from('codes').insert(batch);
      if (error) throw error;
      total += batch.length;
    }
    res.json({ success: true, uploaded: total });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get settings
app.get('/api/admin/settings', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('settings').select('*').order('setting_name');
    res.json({ data });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: update setting
app.post('/api/admin/settings', verifyAdmin, async (req, res) => {
  try {
    const name = sanitizeString(req.body.name, 50);
    const value = sanitizeString(req.body.value, 500);
    await supabase.from('settings').update({ setting_value: value }).eq('setting_name', name);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get products
app.get('/api/admin/products', verifyAdmin, async (req, res) => {
  try {
    const { data } = await supabase.from('site_prices').select('*').order('site_name').order('product_id');
res.json({ products: data, site_prices: data });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: save product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
  try {
    const { id, product_id, site_name, name, price, status } = req.body;
    if (id) {
      // Edit existing row
      await supabase.from('site_prices')
        .update({ name, price: parseInt(price), status, site_name })
        .eq('id', parseInt(id));
    } else {
      // New row
      await supabase.from('site_prices').insert({
        product_id: parseInt(product_id),
        site_name: sanitizeString(site_name, 50),
        name: sanitizeString(name, 100),
        price: parseInt(price),
        status: status || 'active'
      });
    }
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get site-specific products
app.get('/api/admin/site-products', verifyAdmin, async (req, res) => {
  try {
    const siteName = sanitizeString(req.query.site || '', 50);
    if (!siteName) return res.json({ products: [] });

    const { data, error } = await supabase
      .from('site_prices')
      .select('*')
      .ilike('site_name', siteName)
      .order('product_id');

    if (error) throw error;
    res.json({ products: data || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// ============================================
// MANUAL DELIVER
// ============================================

// Admin: get pending/issues
app.get('/api/admin/pending', verifyAdmin, async (req, res) => {
  try {
    const { data: confirmed } = await supabase.from('web_transactions').select('*')
      .in('status', ['confirmed']).eq('sent', 'undelivered').order('timestamp', { ascending: false }).limit(50);
    const { data: issues } = await supabase.from('web_transactions').select('*')
      .in('status', ['underpaid','overpaid','out_of_stock']).order('timestamp', { ascending: false }).limit(50);
    res.json({ confirmed: confirmed || [], issues: issues || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// Admin: customer ranking
app.get('/api/admin/customer-ranking', verifyAdmin, async (req, res) => {
  try {
    const { from, to, site } = req.query;
    let query = supabase
      .from('web_transactions')
      .select('phone, amount, site_name, timestamp')
      .eq('status', 'completed');
    if (from) query = query.gte('timestamp', from + 'T00:00:00');
    if (to)   query = query.lte('timestamp', to + 'T23:59:59');
    if (site) query = query.ilike('site_name', site);

    const { data, error } = await query;
    if (error) throw error;

    // Aggregate by phone
    const map = {};
for (const t of data || []) {
  const ph = t.phone || 'unknown';
  if (!map[ph]) map[ph] = { phone: ph, purchases: 0, total_spent: 0, sites: new Set() };
  map[ph].purchases++;
  map[ph].total_spent += parseFloat(t.amount || 0);
  if (t.site_name) map[ph].sites.add(t.site_name);
}
    const ranked = Object.values(map)
  .sort((a, b) => b.total_spent - a.total_spent)
  .map((c, i) => ({ rank: i + 1, ...c, sites: [...c.sites].join(', ') }));

    const rankedPhones = ranked.map(c => c.phone).filter(Boolean);
    let crLodgeMap = {};
    if (rankedPhones.length > 0) {
      const { data: regs } = await supabase
        .from('customer_register').select('phone, lodge_name').in('phone', rankedPhones);
      (regs || []).forEach(r => { crLodgeMap[r.phone] = r.lodge_name; });
    }
    const enrichedRanked = ranked.map(c => ({ ...c, lodge_name: crLodgeMap[c.phone] || '' }));

    res.json({ customers: enrichedRanked });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: new customers (first-time buyers in date range)
app.get('/api/admin/new-customers', verifyAdmin, async (req, res) => {
  try {
    const { from, to, site } = req.query;

    // Get all completed transactions ever (to find each phone's first purchase)
    let allQuery = supabase
      .from('web_transactions')
      .select('phone, site_name, timestamp, amount, product_id')
      .eq('status', 'completed')
      .order('timestamp', { ascending: true });

    const { data: allData, error } = await allQuery;
    if (error) throw error;

    // Find first purchase date per phone
    const firstPurchase = {};
    for (const t of allData || []) {
      if (!firstPurchase[t.phone]) firstPurchase[t.phone] = t;
    }

    // Filter: first purchase fell within date range (and site if given)
    const fromDt = from ? new Date(from + 'T00:00:00') : null;
    const toDt   = to   ? new Date(to   + 'T23:59:59') : null;

    const newCustomers = Object.values(firstPurchase).filter(t => {
      const d = new Date(t.timestamp);
      if (fromDt && d < fromDt) return false;
      if (toDt   && d > toDt)   return false;
      if (site && !t.site_name?.toLowerCase().includes(site.toLowerCase())) return false;
      return true;
    });

    const ncPhones = [...new Set(newCustomers.map(c => c.phone).filter(Boolean))];
    let ncLodgeMap = {};
    if (ncPhones.length > 0) {
      const { data: regs } = await supabase
        .from('customer_register').select('phone, lodge_name').in('phone', ncPhones);
      (regs || []).forEach(r => { ncLodgeMap[r.phone] = r.lodge_name; });
    }
    const enrichedNew = newCustomers.map(c => ({ ...c, lodge_name: ncLodgeMap[c.phone] || '' }));

    enrichedNew.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
res.json({ customers: enrichedNew });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});


// Admin: manual deliver
app.post('/api/admin/deliver', verifyAdmin, async (req, res) => {
  try {
    const { product_id, site_name, phone, amount_paid } = req.body;

    if (!product_id || !site_name || !phone || !amount_paid) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const { data: sp } = await supabase
      .from('site_prices')
      .select('name, price')
      .eq('product_id', String(product_id))
      .ilike('site_name', site_name.replace(/\s+/g, ''))
      .single();

    if (!sp) return res.status(404).json({ error: 'Product not found for this site' });

    const voucherCode = await assignVoucher(product_id, site_name);
    if (!voucherCode) return res.status(404).json({ error: 'No voucher codes available for this product' });

    const paymentCode = 'MANUAL-' + Date.now();
    await supabase.from('web_transactions').insert({
      phone: sanitizeString(phone, 15),
      site_name: sanitizeString(site_name, 50),
      product_id: String(product_id),
      amount: parseFloat(amount_paid),
      status: 'completed',
      voucher_code: voucherCode,
      payment_code: paymentCode,
      delivery_method: 'manual',
      sent: 'delivered',
      timestamp: new Date().toISOString(),
    });

    res.json({
      success: true,
      voucher: voucherCode,
      product_name: sp.name,
      phone: sanitizeString(phone, 15),
      amount: parseFloat(amount_paid),
      site_name: sanitizeString(site_name, 50),
      payment_code: paymentCode,
    });
  } catch(e) {
    console.error('Manual deliver error:', e);
    res.status(500).json({ error: e.message });
  }
});


// ============================================
// VOUCHER ASSIGNMENT (server-side)
// ============================================
async function assignVoucher(productId, siteName) {
  const siteClean = String(siteName || '').replace(/\s+/g, '').toLowerCase();

  const { data: vouchers } = await supabase.from('codes')
    .select('*').eq('product_id', String(productId)).eq('status', 'unused')
    .ilike('site_name', siteClean).limit(1);

  if (!vouchers || vouchers.length === 0) return null;

  const voucher = vouchers[0];
  const { data: updated } = await supabase.from('codes')
    .update({ status: 'used', used_timestamp: new Date().toISOString() })
    .eq('id', voucher.id).eq('status', 'unused').select();

  if (!updated || updated.length === 0) {
    // Race condition — retry once with different voucher
    const { data: retry } = await supabase.from('codes')
      .select('*').eq('product_id', String(productId)).eq('status', 'unused')
      .ilike('site_name', siteClean).neq('id', voucher.id).limit(1);

    if (!retry || retry.length === 0) return null;

    const { data: updated2 } = await supabase.from('codes')
      .update({ status: 'used', used_timestamp: new Date().toISOString() })
      .eq('id', retry[0].id).eq('status', 'unused').select();

    return updated2 && updated2.length > 0 ? retry[0].voucher_code : null;
  }

  return voucher.voucher_code;
}

// ============================================
// PAGE ROUTES
// ============================================
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// 404
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// START SERVER
// ============================================
app.listen(PORT, () => {
  console.log(`✅ KanBooster server running on port ${PORT}`);
  console.log(`🌐 Site: http://localhost:${PORT}`);
  console.log(`🔐 Admin: http://localhost:${PORT}/admin`);
});
