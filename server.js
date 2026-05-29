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
        "'unsafe-inline'",  // needed for inline JS in HTML
        "https://checkout.flutterwave.com",
        "https://cdn.jsdelivr.net",
        "https://fonts.googleapis.com",
      ],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      frameSrc: ["https://checkout.flutterwave.com"],
      connectSrc: [
        "'self'",
        "https://checkout.flutterwave.com",
        "https://api.flutterwave.com",
      ],
      imgSrc: ["'self'", "data:", "https:"],
    }
  }
}));

// CORS — only allow your domain
const allowedOrigins = [
  `http://localhost:${PORT}`,
  process.env.SITE_URL,  // e.g. https://yourdomain.com
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
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
  index: false, // don't auto-serve index
  setHeaders: (res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  }
}));

// ============================================
// INPUT VALIDATION HELPERS
// ============================================
function sanitizeString(str, maxLen = 200) {
  if (!str || typeof str !== 'string') return '';
  return str.trim().substring(0, maxLen).replace(/[<>\"']/g, '');
}

function isValidPhone(phone) {
  return /^(0|234|\+234)[789][01]\d{8}$/.test(phone.replace(/\s/g, ''));
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

    const { data: products, error } = await supabase
      .from('products')
      .select('product_id, name, price, status')
      .eq('status', 'active')
      .order('product_id');

    if (error) throw error;

    let sitePrices = {};
    if (siteName) {
      const { data: sp } = await supabase
        .from('site_prices')
        .select('product_id, price')
        .ilike('site_name', siteName);
      if (sp) sp.forEach(p => { sitePrices[p.product_id] = p.price; });
    }

    // Attach effective price
    const result = products.map(p => ({
      ...p,
      effective_price: sitePrices[p.product_id] || p.price
    }));

    res.json({ products: result });
  } catch(e) {
    console.error('GET /api/products error:', e);
    res.status(500).json({ error: 'Failed to load products' });
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
    res.status(500).json({ error: 'Validation error' });
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
    const { data: product } = await supabase
      .from('products').select('price, name').eq('product_id', productId).single();
    if (!product) return res.status(400).json({ error: 'Product not found' });

    let finalPrice = parseInt(product.price);
    const { data: sp } = await supabase.from('site_prices')
      .select('price').eq('product_id', String(productId)).ilike('site_name', siteName);
    if (sp && sp.length > 0) finalPrice = parseInt(sp[0].price);

    // Check for duplicate identifier
    const { data: existing } = await supabase
      .from('transactions').select('id').eq('payment_code', identifierCode).single();
    if (existing) return res.status(400).json({ error: 'Identifier already used' });

    // Insert transaction
    const { data, error } = await supabase.from('transactions').insert({
      timestamp: new Date().toISOString(),
      telegram_id: 'WEB_FLOW',
      username: 'N/A',
      product_id: String(productId),
      amount: String(finalPrice),
      payment_code: identifierCode,
      status: 'pending',
      site_name: siteName,
      voucher_code: '',
      sent: 'undelivered',
      check_count: 0,
      phone: phone,
      delivery_method: 'web',
      recipient_phone: phone,
      device_id: sanitizeString(req.body.device_id || '', 100),
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
              'Content-Type': 'application/json'
            }
          };
          const req2 = https.request(options, (resp) => {
            let data = '';
            resp.on('data', chunk => data += chunk);
            resp.on('end', () => resolve(JSON.parse(data)));
          });
          req2.on('error', reject);
          req2.end();
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
      .from('transactions').select('*').eq('payment_code', identifierCode).single();
    if (!txn) return res.status(404).json({ error: 'Transaction not found' });

    // Already completed
    if (txn.status === 'completed' && txn.voucher_code) {
      return res.json({ success: true, voucher: txn.voucher_code });
    }

    // Amount check (if verified)
    if (verifiedAmount !== null) {
      const expectedAmount = parseFloat(txn.amount);
      if (verifiedAmount < expectedAmount) {
        await supabase.from('transactions').update({ status: 'underpaid', flw_ref: flwRef })
          .eq('payment_code', identifierCode);
        return res.status(400).json({ error: 'underpaid', paid: verifiedAmount, expected: expectedAmount });
      }
      if (verifiedAmount > expectedAmount) {
        await supabase.from('transactions').update({ status: 'overpaid', flw_ref: flwRef })
          .eq('payment_code', identifierCode);
        return res.status(400).json({ error: 'overpaid', paid: verifiedAmount, expected: expectedAmount });
      }
    }

    // Update to confirmed
    await supabase.from('transactions').update({
      status: 'confirmed',
      flw_ref: flwRef || txn.flw_ref,
    }).eq('payment_code', identifierCode);

    // Assign voucher
    const voucher = await assignVoucher(txn.product_id, txn.site_name);

    if (!voucher) {
      await supabase.from('transactions').update({ status: 'out_of_stock' }).eq('payment_code', identifierCode);
      return res.status(400).json({ error: 'out_of_stock' });
    }

    // Mark delivered
    await supabase.from('transactions').update({
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

// Check transaction status (polling)
app.get('/api/transaction-status', async (req, res) => {
  try {
    const identifierCode = sanitizeString(req.query.code || '', 30);
    if (!isValidIdentifier(identifierCode)) return res.status(400).json({ error: 'Invalid code' });

    const { data } = await supabase.from('transactions')
      .select('status, voucher_code, sent')
      .eq('payment_code', identifierCode)
      .single();

    if (!data) return res.status(404).json({ error: 'Not found' });

    res.json({
      status: data.status,
      voucher: data.status === 'completed' ? data.voucher_code : null,
    });
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

    const cutoff = new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString();

    const { data } = await supabase.from('transactions')
      .select('payment_code, voucher_code, amount, timestamp, site_name, device_id')
      .eq('phone', phone)
      .eq('status', 'completed')
      .eq('delivery_method', 'web')
      .gte('timestamp', cutoff)
      .order('timestamp', { ascending: false })
      .limit(10);

    if (!data || data.length === 0) {
      return res.json({ found: false });
    }

    // Device check server-side
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
    res.status(500).json({ error: 'Retrieval failed' });
  }
});

// Get settings (only safe public ones)
app.get('/api/public-settings', async (req, res) => {
  try {
    const SAFE_SETTINGS = ['support_phone', 'terms_link', 'tutorial_link', 'auto_check_interval'];
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
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const username = sanitizeString(req.body.username || '', 50);
    const password = sanitizeString(req.body.password || '', 100);

    if (!username || !password) return res.status(400).json({ error: 'Missing credentials' });

    const { data, error } = await supabase.from('admin_users')
      .select('*').eq('username', username).eq('password', password).eq('active', true).single();

    if (error || !data) {
      // Log failed attempt
      console.warn(`Failed admin login attempt: ${username} from ${req.ip}`);
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    // Create session token
    const crypto = require('crypto');
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 8 * 60 * 60 * 1000); // 8 hours

    await supabase.from('admin_sessions').insert({
      token,
      username,
      created_at: new Date().toISOString(),
      expires_at: expiresAt.toISOString(),
    });

    // Log login
    await supabase.from('admin_logins').insert({
      username, logged_in_at: new Date().toISOString(), ip: req.ip
    }).catch(() => {});

    res.json({ success: true, token, username });
  } catch(e) {
    console.error('Admin login error:', e);
    res.status(500).json({ error: 'Login failed' });
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
    const { from, to, status, search, page = 1 } = req.query;
    const pageSize = 50;

    let query = supabase.from('transactions').select('*', { count: 'exact' });
    if (from) query = query.gte('timestamp', from + 'T00:00:00');
    if (to) query = query.lte('timestamp', to + 'T23:59:59');
    if (status) query = query.eq('status', status);
    if (search) query = query.or(`phone.ilike.%${search}%,payment_code.ilike.%${search}%`);
    query = query.order('timestamp', { ascending: false })
      .range((page - 1) * pageSize, page * pageSize - 1);

    const { data, count } = await query;
    res.json({ data, count });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get dashboard stats
app.get('/api/admin/stats', verifyAdmin, async (req, res) => {
  try {
    const { from, to } = req.query;
    let query = supabase.from('transactions').select('status, amount, site_name');
    if (from) query = query.gte('timestamp', from + 'T00:00:00');
    if (to) query = query.lte('timestamp', to + 'T23:59:59');
    const { data } = await query;
    res.json({ data: data || [] });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get stock
app.get('/api/admin/stock', verifyAdmin, async (req, res) => {
  try {
    const { data: products } = await supabase.from('products').select('*').order('product_id');
    const { data: sitesSetting } = await supabase.from('settings').select('setting_value').eq('setting_name','site_names').single();
    const sites = sitesSetting ? sitesSetting.setting_value.split(',').map(s => s.trim()) : [];

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
    const { data } = await supabase.from('products').select('*').order('product_id');
    const { data: sp } = await supabase.from('site_prices').select('*');
    res.json({ products: data, site_prices: sp });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: save product
app.post('/api/admin/products', verifyAdmin, async (req, res) => {
  try {
    const { product_id, name, price, status } = req.body;
    if (product_id) {
      await supabase.from('products').update({ name, price: parseInt(price), status }).eq('product_id', parseInt(product_id));
    } else {
      const { data: last } = await supabase.from('products').select('product_id').order('product_id', { ascending: false }).limit(1);
      const nextId = last && last.length > 0 ? last[0].product_id + 1 : 1;
      await supabase.from('products').insert({ product_id: nextId, name, price: parseInt(price), status });
    }
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: manual deliver
app.post('/api/admin/deliver', verifyAdmin, async (req, res) => {
  try {
    const paymentCode = sanitizeString(req.body.payment_code, 30);
    const productId = req.body.product_id;
    const siteName = sanitizeString(req.body.site_name, 50);

    const voucher = await assignVoucher(productId, siteName);
    if (!voucher) return res.status(400).json({ error: 'No stock available' });

    await supabase.from('transactions').update({
      status: 'completed', voucher_code: voucher,
      sent: 'delivered', delivered_at: new Date().toISOString()
    }).eq('payment_code', paymentCode);

    res.json({ success: true, voucher });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Admin: get pending/issues
app.get('/api/admin/pending', verifyAdmin, async (req, res) => {
  try {
    const { data: confirmed } = await supabase.from('transactions').select('*')
      .in('status', ['confirmed']).eq('sent', 'undelivered').order('timestamp', { ascending: false }).limit(50);
    const { data: issues } = await supabase.from('transactions').select('*')
      .in('status', ['underpaid','overpaid','out_of_stock']).order('timestamp', { ascending: false }).limit(50);
    res.json({ confirmed: confirmed || [], issues: issues || [] });
  } catch(e) {
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
