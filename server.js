require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const Anthropic = require('@anthropic-ai/sdk');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3001;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: 587,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

// ── SECURITY HEADERS ──────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

// ── RATE LIMITING ─────────────────────────────────────
const rateLimitStore = new Map();
const adminAttempts = new Map();

function rateLimit(maxReqs, windowMs) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    const key = `${ip}:${req.path}`;
    const now = Date.now();
    const entry = rateLimitStore.get(key);
    if (!entry || now > entry.resetAt) {
      rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
      return next();
    }
    entry.count++;
    if (entry.count > maxReqs) {
      return res.status(429).json({ error: 'Too many requests. Please wait and try again.' });
    }
    next();
  };
}

// Brute force protection for admin routes
function adminBruteForce(req, res, next) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  const now = Date.now();
  const entry = adminAttempts.get(ip) || { count: 0, lockedUntil: 0 };
  if (now < entry.lockedUntil) {
    const mins = Math.ceil((entry.lockedUntil - now) / 60000);
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${mins} minute(s).` });
  }
  req._adminIp = ip;
  next();
}

function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
  const entry = adminAttempts.get(ip) || { count: 0, lockedUntil: 0 };

  if (!key || key !== process.env.ADMIN_KEY) {
    entry.count++;
    if (entry.count >= 5) {
      entry.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 min lockout
      entry.count = 0;
    }
    adminAttempts.set(ip, entry);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  // Successful auth — clear failed attempts
  adminAttempts.delete(ip);
  next();
}

// ── INPUT SANITIZATION ────────────────────────────────
function sanitize(str) {
  if (typeof str !== 'string') return str;
  return str.replace(/[<>'"]/g, '').trim().slice(0, 500);
}

app.use(cors({
  origin: ['https://plutur.com', 'https://www.plutur.com', 'http://localhost:3000', 'http://localhost:5500'],
  credentials: true
}));
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10kb' }));

// Apply rate limiting
app.use('/api/auth/signup', rateLimit(5, 60 * 1000));     // 5 signups/min per IP
app.use('/api/auth/signin', rateLimit(10, 60 * 1000));    // 10 logins/min per IP
app.use('/api/ai/chat', rateLimit(20, 60 * 1000));        // 20 AI msgs/min per IP
app.use('/api/admin', adminBruteForce);

async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) return res.status(401).json({ error: 'Invalid token' });
  req.user = user;
  next();
}

async function requirePro(req, res, next) {
  const { data: profile } = await supabase.from('profiles').select('plan').eq('id', req.user.id).single();
  if (!profile || profile.plan !== 'pro') return res.status(403).json({ error: 'Pro required' });
  next();
}

// AUTH
app.post('/api/auth/signup', async (req, res) => {
  const name = sanitize(req.body.name);
  const email = sanitize(req.body.email);
  const password = req.body.password;
  const ref = sanitize(req.body.ref);
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Invalid email address' });
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  await supabase.from('profiles').insert({
    id: data.user.id, name, email, plan: 'free',
    analyses_today: 0, analyses_date: new Date().toDateString(),
    referred_by: ref || null, created_at: new Date().toISOString()
  });
  sendWelcomeEmail(email, name).catch(console.error);
  res.json({ user: data.user, session: data.session });
});

// Cancel subscription
app.post('/api/stripe/cancel', requireAuth, async (req, res) => {
  const { data: profile } = await supabase.from('profiles').select('stripe_subscription_id').eq('id', req.user.id).single();
  if (!profile?.stripe_subscription_id) return res.status(400).json({ error: 'No active subscription' });
  try {
    await stripe.subscriptions.update(profile.stripe_subscription_id, { cancel_at_period_end: true });
    res.json({ message: 'Subscription will cancel at end of billing period.' });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/signin', async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  const { data: profile } = await supabase.from('profiles').select('*').eq('id', data.user.id).single();
  res.json({ user: data.user, session: data.session, profile });
});

app.get('/api/auth/profile', requireAuth, async (req, res) => {
  const { data: profile } = await supabase.from('profiles').select('*').eq('id', req.user.id).single();
  res.json(profile);
});

// STRIPE
app.post('/api/stripe/checkout', requireAuth, async (req, res) => {
  const { data: profile } = await supabase.from('profiles').select('stripe_customer_id, email').eq('id', req.user.id).single();
  let customerId = profile?.stripe_customer_id;
  if (!customerId) {
    const customer = await stripe.customers.create({ email: profile?.email || req.user.email, metadata: { supabase_id: req.user.id } });
    customerId = customer.id;
    await supabase.from('profiles').update({ stripe_customer_id: customerId }).eq('id', req.user.id);
  }
  const session = await stripe.checkout.sessions.create({
    customer: customerId,
    payment_method_types: ['card'],
    line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
    mode: 'subscription',
    success_url: `${process.env.FRONTEND_URL}/?success=true`,
    cancel_url: `${process.env.FRONTEND_URL}/`,
    metadata: { user_id: req.user.id },
  });
  res.json({ url: session.url });
});

app.post('/api/stripe/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET); }
  catch (err) { return res.status(400).send(`Webhook error: ${err.message}`); }

  switch(event.type) {
    case 'checkout.session.completed': {
      const s = event.data.object;
      const userId = s.metadata?.user_id;
      if (userId) {
        await supabase.from('profiles').update({ plan: 'pro', stripe_subscription_id: s.subscription }).eq('id', userId);
        const { data: p } = await supabase.from('profiles').select('email,name').eq('id', userId).single();
        if (p) sendUpgradeEmail(p.email, p.name).catch(console.error);
        activateReferral(userId).catch(console.error);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const sub = event.data.object;
      const { data: p } = await supabase.from('profiles').select('id,email,name').eq('stripe_subscription_id', sub.id).single();
      if (p) {
        await supabase.from('profiles').update({ plan: 'free', stripe_subscription_id: null }).eq('id', p.id);
        sendCancellationEmail(p.email, p.name).catch(console.error);
      }
      break;
    }
    case 'customer.subscription.updated': {
      // Handle plan changes / reactivations
      const sub = event.data.object;
      if (sub.status === 'active') {
        const { data: p } = await supabase.from('profiles').select('id').eq('stripe_subscription_id', sub.id).single();
        if (p) await supabase.from('profiles').update({ plan: 'pro' }).eq('id', p.id);
      }
      break;
    }
    case 'invoice.payment_failed': {
      const invoice = event.data.object;
      const { data: p } = await supabase.from('profiles').select('email,name').eq('stripe_customer_id', invoice.customer).single();
      if (p) sendPaymentFailedEmail(p.email, p.name).catch(console.error);
      break;
    }
  }
  res.json({ received: true });
});

// MARKET DATA
app.get('/api/market/rates', async (req, res) => {
  try {
    const apiKey = process.env.FRED_API_KEY || 'abcdefghijklmnop'; // real key needed
    const url = `https://api.stlouisfed.org/fred/series/observations?series_id=MORTGAGE30US&api_key=${apiKey}&sort_order=desc&limit=1&file_type=json`;
    const r = await fetch(url);
    const data = await r.json();
    const rate = parseFloat(data.observations?.[0]?.value);
    if(isNaN(rate)) throw new Error('No rate');
    res.json({ rate_30yr: rate, date: data.observations?.[0]?.date, source: 'Federal Reserve FRED' });
  } catch { res.json({ rate_30yr: 6.89, source: 'Plutur Default' }); }
});

// Walk Score proxy — avoids CORS from browser
app.get('/api/market/walkscore', async (req, res) => {
  const { address, lat, lng } = req.query;
  if (!process.env.WALK_SCORE_KEY) {
    return res.json({ walkscore: null, source: 'No Walk Score API key configured' });
  }
  try {
    const url = `https://api.walkscore.com/score?format=json&address=${encodeURIComponent(address)}&lat=${lat}&lon=${lng}&transit=1&bike=1&wsapikey=${process.env.WALK_SCORE_KEY}`;
    const r = await fetch(url);
    const data = await r.json();
    res.json(data);
  } catch(e) {
    res.json({ walkscore: null, source: 'Walk Score unavailable' });
  }
});

app.get('/api/market/str', requireAuth, requirePro, async (req, res) => {
  const { city, state, beds } = req.query;
  if (!city || !state) return res.status(400).json({ error: 'City and state required' });
  const data = getMarketData(`${city.toLowerCase()},${state.toLowerCase()}`, parseInt(beds) || 2);
  await supabase.from('market_lookups').insert({ user_id: req.user.id, city, state, beds: parseInt(beds)||2, timestamp: new Date().toISOString() }).catch(()=>{});
  res.json(data);
});

// ML SCORING
app.post('/api/ml/score', requireAuth, async (req, res) => {
  const deal = req.body;
  const score = mlScoreDeal(deal);
  await supabase.from('analyses').insert({ user_id: req.user.id, type: deal.type, inputs: deal, score: score.total, cash_flow: deal.cashFlow, coc_return: deal.cocReturn, cap_rate: deal.capRate, created_at: new Date().toISOString() }).catch(()=>{});
  await incrementUsage(req.user.id);
  res.json(score);
});

function mlScoreDeal(deal) {
  const { type, cashFlow, cocReturn, capRate, dscr, grm, onePercent, vacancy, occupancy } = deal;
  let scores = {}, labels = {};
  if (type === 'sfr' || type === 'mfr') {
    scores.cashFlow = cashFlow >= 500 ? 25 : cashFlow >= 300 ? 20 : cashFlow >= 100 ? 14 : cashFlow >= 0 ? 8 : Math.max(0, 8 + cashFlow/50); labels.cashFlow = 'Monthly Cash Flow';
    scores.coc = cocReturn >= 12 ? 25 : cocReturn >= 8 ? 20 : cocReturn >= 5 ? 14 : cocReturn >= 2 ? 8 : Math.max(0, cocReturn * 2); labels.coc = 'Cash-on-Cash Return';
    scores.capRate = capRate >= 8 ? 20 : capRate >= 6 ? 16 : capRate >= 4 ? 11 : capRate >= 2 ? 6 : Math.max(0, capRate * 2); labels.capRate = 'Cap Rate';
    scores.onePercent = onePercent >= 1.2 ? 15 : onePercent >= 1.0 ? 12 : onePercent >= 0.8 ? 8 : onePercent >= 0.6 ? 4 : 1; labels.onePercent = '1% Rule';
    scores.vacancy = (vacancy||5) <= 4 ? 15 : (vacancy||5) <= 7 ? 12 : (vacancy||5) <= 10 ? 8 : 4; labels.vacancy = 'Vacancy Risk';
  } else if (type === 'str' || type === 'arb') {
    scores.cashFlow = cashFlow >= 800 ? 25 : cashFlow >= 500 ? 20 : cashFlow >= 300 ? 15 : cashFlow >= 0 ? 8 : Math.max(0, 8 + cashFlow/100); labels.cashFlow = 'Monthly Cash Flow';
    scores.coc = cocReturn >= 40 ? 25 : cocReturn >= 25 ? 20 : cocReturn >= 15 ? 14 : cocReturn >= 5 ? 8 : 2; labels.coc = 'ROI on Capital';
    scores.occ = (occupancy||65) >= 70 ? 25 : (occupancy||65) >= 60 ? 18 : (occupancy||65) >= 50 ? 12 : 5; labels.occ = 'Occupancy Rate';
    scores.risk = type === 'arb' ? 20 : 15; labels.risk = type === 'arb' ? 'Low Capital Risk' : 'Ownership Upside';
  } else if (type === 'commercial') {
    scores.cashFlow = cashFlow >= 50000 ? 25 : cashFlow >= 25000 ? 20 : cashFlow >= 10000 ? 14 : cashFlow >= 0 ? 8 : 0; labels.cashFlow = 'Annual Cash Flow';
    scores.coc = cocReturn >= 10 ? 20 : cocReturn >= 7 ? 16 : cocReturn >= 4 ? 11 : cocReturn >= 0 ? 6 : 0; labels.coc = 'Cash-on-Cash';
    scores.capRate = capRate >= 7 ? 20 : capRate >= 5 ? 16 : capRate >= 3 ? 10 : 5; labels.capRate = 'Cap Rate';
    scores.dscr = (dscr||0) >= 1.5 ? 20 : (dscr||0) >= 1.25 ? 15 : (dscr||0) >= 1.0 ? 8 : 0; labels.dscr = 'DSCR';
    scores.grm = (grm||20) <= 8 ? 15 : (grm||20) <= 12 ? 12 : (grm||20) <= 16 ? 8 : 4; labels.grm = 'GRM';
  }
  const total = Math.min(100, Math.round(Object.values(scores).reduce((a, b) => a + b, 0)));
  const grade = total >= 85 ? 'A+' : total >= 75 ? 'A' : total >= 65 ? 'B+' : total >= 55 ? 'B' : total >= 45 ? 'C' : total >= 35 ? 'D' : 'F';
  const recommendation = total >= 75 ? 'STRONG BUY' : total >= 60 ? 'BUY' : total >= 45 ? 'HOLD / NEGOTIATE' : total >= 30 ? 'PASS' : 'STRONG PASS';
  return { total, grade, recommendation, breakdown: scores, labels };
}

app.get('/api/analyses', requireAuth, async (req, res) => {
  const { data } = await supabase.from('analyses').select('*').eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
  res.json(data || []);
});

app.get('/api/usage', requireAuth, async (req, res) => {
  const today = new Date().toDateString();
  const { data: profile } = await supabase.from('profiles').select('analyses_today, analyses_date, plan').eq('id', req.user.id).single();
  const used = profile?.analyses_date === today ? (profile.analyses_today || 0) : 0;
  res.json({ used, limit: profile?.plan === 'pro' ? 999 : 3, plan: profile?.plan });
});

async function incrementUsage(userId) {
  const today = new Date().toDateString();
  const { data: p } = await supabase.from('profiles').select('analyses_today, analyses_date, plan').eq('id', userId).single();
  if (!p || p.plan === 'pro') return;
  const count = p.analyses_date === today ? (p.analyses_today || 0) + 1 : 1;
  await supabase.from('profiles').update({ analyses_today: count, analyses_date: today }).eq('id', userId);
}

const emailBase = (content) => `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"></head>
<body style="margin:0;padding:0;background:#0e0d0b;font-family:Georgia,serif">
<div style="max-width:560px;margin:0 auto;padding:40px 20px">
<div style="border:1px solid rgba(201,168,76,.2);border-radius:12px;overflow:hidden">
<div style="background:#111210;padding:28px 36px;border-bottom:1px solid rgba(255,255,255,.06)">
  <div style="font-family:Georgia,serif;font-size:20px;font-style:italic;color:#c9a84c">Plutur</div>
  <div style="font-family:monospace;font-size:8px;color:#605850;letter-spacing:2px;text-transform:uppercase;margin-top:3px">Real Estate Investment Intelligence</div>
</div>
<div style="background:#181815;padding:36px">${content}</div>
<div style="background:#111210;padding:18px 36px;border-top:1px solid rgba(255,255,255,.06)">
  <div style="font-family:monospace;font-size:8px;color:#302e28;letter-spacing:.3px">© 2025 Plutur · plutur.com · Not financial advice · <a href="${process.env.FRONTEND_URL}" style="color:#605850">Unsubscribe</a></div>
</div>
</div></div></body></html>`;

const emailBtn = (text, url) => `<a href="${url}" style="display:inline-block;background:#c9a84c;color:#0e0c08;font-family:monospace;font-size:11px;font-weight:600;letter-spacing:.5px;padding:12px 26px;border-radius:4px;text-decoration:none;margin-top:4px">${text}</a>`;
const emailH = (text) => `<h1 style="font-family:Georgia,serif;font-size:26px;font-weight:300;font-style:italic;color:#f5f0e8;margin:0 0 14px;letter-spacing:-.3px">${text}</h1>`;
const emailP = (text) => `<p style="font-family:monospace;font-size:11px;color:#a09888;line-height:1.9;margin:0 0 18px;letter-spacing:.3px">${text}</p>`;

async function sendWelcomeEmail(email, name) {
  if (!process.env.SMTP_USER) return;
  const n = name.split(' ')[0];
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: `Welcome to Plutur, ${n}.`,
    html: emailBase(`
      ${emailH(`Welcome, ${n}.`)}
      ${emailP(`Your account is ready. You have <strong style="color:#f5f0e8">3 free analyses per day</strong> to get started — no card required.`)}
      <div style="background:#1e1e1a;border:1px solid rgba(255,255,255,.06);border-radius:6px;padding:18px;margin-bottom:22px">
        <div style="font-family:monospace;font-size:8px;color:#605850;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px">Free plan includes</div>
        <div style="font-family:monospace;font-size:10px;color:#a09888;line-height:2.2">✓&nbsp; Single family rental analyzer<br>✓&nbsp; Cash flow & cap rate modeling<br>✓&nbsp; ML deal scoring<br>✓&nbsp; 3 analyses per day</div>
      </div>
      ${emailBtn('Open Plutur →', `${process.env.FRONTEND_URL}/app.html`)}
      ${emailP(`Upgrade to Pro ($29/mo) for unlimited analyses, all 5 property types, live market data, AI Advisor, and PDF reports.`)}
    `),
  });
}

async function sendUpgradeEmail(email, name) {
  if (!process.env.SMTP_USER) return;
  const n = name.split(' ')[0];
  const features = ['Unlimited deal analyses','All 5 property types','Live market data · 30+ cities','ML deal scoring (0–100)','AI Investment Advisor','Neighborhood Intel','Branded PDF reports','Deal comparison tool'];
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: `You're on Plutur Pro, ${n}.`,
    html: emailBase(`
      <div style="font-family:monospace;font-size:8px;color:#c9a84c;letter-spacing:2px;text-transform:uppercase;margin-bottom:10px">Pro · Active</div>
      ${emailH(`You're all set, ${n}.`)}
      ${emailP(`Your Pro subscription is active. Everything is unlocked.`)}
      <div style="border:1px solid rgba(255,255,255,.06);border-radius:6px;overflow:hidden;margin-bottom:22px">
        ${features.map(f=>`<div style="padding:9px 16px;border-bottom:1px solid rgba(255,255,255,.04);font-family:monospace;font-size:10px;color:#a09888;background:#1e1e1a"><span style="color:#4a9e72;margin-right:8px">✓</span>${f}</div>`).join('')}
      </div>
      ${emailBtn('Start Analyzing →', `${process.env.FRONTEND_URL}/app.html`)}
      ${emailP(`$29/mo · Cancel anytime · Secured by Stripe`)}
    `),
  });
}

async function sendCancellationEmail(email, name) {
  if (!process.env.SMTP_USER) return;
  const n = name.split(' ')[0];
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: `Your Plutur Pro subscription has been cancelled`,
    html: emailBase(`
      ${emailH(`Subscription cancelled, ${n}.`)}
      ${emailP(`Your Pro subscription has been cancelled. You'll keep Pro access until the end of your current billing period, then revert to the free plan (3 analyses/day, SFR only).`)}
      ${emailP(`If this was a mistake, you can resubscribe anytime.`)}
      ${emailBtn('Resubscribe →', process.env.FRONTEND_URL)}
    `),
  });
}

async function sendPaymentFailedEmail(email, name) {
  if (!process.env.SMTP_USER) return;
  const n = name.split(' ')[0];
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: `Action required — Plutur payment failed`,
    html: emailBase(`
      ${emailH(`Payment failed, ${n}.`)}
      ${emailP(`We couldn't process your Plutur Pro payment. Please update your payment method to keep your Pro access — your subscription will be cancelled if payment continues to fail.`)}
      ${emailBtn('Update Payment Method →', 'https://billing.stripe.com')}
    `),
  });
}

function getMarketData(key, beds) {
  const b = Math.min(Math.max(beds, 1), 4);
  const DB = {
    'miami beach,fl':{str:{1:198,2:312,3:488,4:720},occ:{1:.71,2:.73,3:.70,4:.65},rent:{1:2850,2:3900,3:5200},price:{1:420000,2:680000,3:950000},cap:3.2},
    'miami,fl':{str:{1:165,2:248,3:380,4:520},occ:{1:.70,2:.72,3:.68,4:.63},rent:{1:2450,2:3200,3:4100},price:{1:380000,2:560000,3:780000},cap:3.8},
    'destin,fl':{str:{1:185,2:295,3:465,4:680},occ:{1:.72,2:.74,3:.73,4:.68},rent:{1:1950,2:2600,3:3400},price:{1:420000,2:620000,3:890000},cap:4.8},
    'orlando,fl':{str:{1:142,2:195,3:285,4:395},occ:{1:.75,2:.76,3:.74,4:.70},rent:{1:1820,2:2350,3:3100},price:{1:310000,2:430000,3:580000},cap:5.4},
    'tampa,fl':{str:{1:148,2:210,3:315,4:445},occ:{1:.72,2:.73,3:.71,4:.67},rent:{1:2080,2:2750,3:3600},price:{1:360000,2:510000,3:700000},cap:5.8},
    'nashville,tn':{str:{1:188,2:278,3:415,4:580},occ:{1:.74,2:.75,3:.73,4:.68},rent:{1:2190,2:2890,3:3800},price:{1:380000,2:520000,3:710000},cap:5.6},
    'gatlinburg,tn':{str:{1:165,2:248,3:395,4:560},occ:{1:.76,2:.77,3:.75,4:.70},rent:{1:1450,2:1950,3:2600},price:{1:320000,2:460000,3:650000},cap:6.8},
    'scottsdale,az':{str:{1:178,2:268,3:420,4:600},occ:{1:.68,2:.70,3:.68,4:.63},rent:{1:2250,2:3000,3:3900},price:{1:520000,2:720000,3:980000},cap:4.5},
    'phoenix,az':{str:{1:138,2:205,3:310,4:430},occ:{1:.67,2:.69,3:.67,4:.62},rent:{1:1950,2:2550,3:3300},price:{1:380000,2:510000,3:680000},cap:5.4},
    'austin,tx':{str:{1:155,2:235,3:355,4:490},occ:{1:.64,2:.66,3:.64,4:.60},rent:{1:2380,2:3100,3:4050},price:{1:480000,2:650000,3:870000},cap:4.2},
    'dallas,tx':{str:{1:135,2:198,3:295,4:405},occ:{1:.66,2:.67,3:.65,4:.61},rent:{1:1950,2:2550,3:3300},price:{1:350000,2:480000,3:650000},cap:5.2},
    'myrtle beach,sc':{str:{1:142,2:225,3:338,4:480},occ:{1:.70,2:.72,3:.70,4:.65},rent:{1:1650,2:2150,3:2800},price:{1:290000,2:420000,3:590000},cap:6.2},
    'charlotte,nc':{str:{1:142,2:212,3:315,4:440},occ:{1:.68,2:.70,3:.68,4:.63},rent:{1:1890,2:2450,3:3200},price:{1:340000,2:470000,3:640000},cap:5.5},
    'atlanta,ga':{str:{1:148,2:220,3:328,4:460},occ:{1:.68,2:.70,3:.68,4:.63},rent:{1:1980,2:2600,3:3400},price:{1:370000,2:510000,3:690000},cap:5.3},
    'denver,co':{str:{1:158,2:238,3:358,4:495},occ:{1:.66,2:.68,3:.66,4:.61},rent:{1:2250,2:2950,3:3850},price:{1:490000,2:680000,3:920000},cap:4.0},
    'las vegas,nv':{str:{1:145,2:215,3:320,4:450},occ:{1:.71,2:.73,3:.71,4:.66},rent:{1:1750,2:2280,3:2980},price:{1:360000,2:495000,3:670000},cap:5.5},
    'new york,ny':{str:{1:245,2:380,3:570,4:780},occ:{1:.73,2:.75,3:.73,4:.68},rent:{1:3800,2:5200,3:7000},price:{1:850000,2:1250000,3:1700000},cap:3.2},
    'los angeles,ca':{str:{1:185,2:275,3:410,4:570},occ:{1:.68,2:.69,3:.67,4:.62},rent:{1:2850,2:3800,3:5000},price:{1:780000,2:1100000,3:1500000},cap:2.9},
    'seattle,wa':{str:{1:178,2:268,3:400,4:560},occ:{1:.67,2:.69,3:.67,4:.62},rent:{1:2600,2:3450,3:4550},price:{1:620000,2:870000,3:1180000},cap:3.5},
  };
  const d = DB[key];
  if (d) {
    const nightly=d.str[b], occ=d.occ[b], rent=d.rent[Math.min(b,3)], price=d.price[Math.min(b,3)];
    return { nightly, occ: Math.round(occ*100), rent, price, capRate: d.cap, monthlyRev: Math.round(nightly*30*occ), annualRev: Math.round(nightly*30*occ*12), beds: b, source: 'Plutur Market Intelligence', confidence: 'High', lastUpdated: 'Q1 2025' };
  }
  const nat={1:[120,.63,1600,280000],2:[175,.65,2100,380000],3:[260,.65,2800,510000],4:[375,.63,3600,680000]};
  const [nightly,occ,rent,price]=nat[b]||nat[2];
  return { nightly, occ: Math.round(occ*100), rent, price, capRate: 5.0, monthlyRev: Math.round(nightly*30*occ), annualRev: Math.round(nightly*30*occ*12), beds: b, source: 'Plutur National Averages', confidence: 'Moderate', lastUpdated: 'Q1 2025' };
}

// ═══════════════════════════════════════════════════════
//  ADMIN ENDPOINTS
// ═══════════════════════════════════════════════════════
function requireAdmin(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    // All users
    const { data: users } = await supabase.from('profiles').select('*').order('created_at', { ascending: false });
    const pro = users?.filter(u => u.plan === 'pro') || [];
    const free = users?.filter(u => u.plan === 'free') || [];

    // Signups by day (last 30 days)
    const thirtyDaysAgo = new Date(Date.now() - 30*24*60*60*1000).toISOString();
    const recent = users?.filter(u => u.created_at > thirtyDaysAgo) || [];

    // Referrals
    const { data: referrals } = await supabase.from('referrals').select('*');
    const activeRefs = referrals?.filter(r => r.status === 'active') || [];

    // Payout requests
    const { data: payouts } = await supabase.from('payout_requests').select('*, user:user_id(name,email)').eq('status','pending');

    // Analyses count
    const { count: analysisCount } = await supabase.from('analyses').select('*', { count: 'exact', head: true });

    res.json({
      users: users || [],
      stats: {
        totalUsers: users?.length || 0,
        proUsers: pro.length,
        freeUsers: free.length,
        mrr: pro.length * 29,
        newLast30: recent.length,
        activeReferrals: activeRefs.length,
        totalAnalyses: analysisCount || 0,
      },
      pendingPayouts: payouts || [],
      referrals: referrals || [],
    });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Upgrade a user to Pro manually
app.post('/api/admin/upgrade', requireAdmin, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  await supabase.from('profiles').update({ plan: 'pro' }).eq('id', userId);
  res.json({ message: 'User upgraded to Pro' });
});

// Downgrade a user to Free
app.post('/api/admin/downgrade', requireAdmin, async (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  await supabase.from('profiles').update({ plan: 'free' }).eq('id', userId);
  res.json({ message: 'User downgraded to Free' });
});

// Create user (admin)
app.post('/api/admin/create-user', requireAdmin, async (req, res) => {
  const { name, email, password, plan } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  try {
    // Create auth user
    const { data, error } = await supabase.auth.admin.createUser({
      email, password, email_confirm: true
    });
    if (error) return res.status(400).json({ error: error.message });

    // Create profile
    await supabase.from('profiles').insert({
      id: data.user.id, name, email,
      plan: plan || 'free',
      analyses_today: 0,
      analyses_date: new Date().toDateString(),
      created_at: new Date().toISOString()
    });

    // Send welcome email
    if (plan === 'pro') {
      sendUpgradeEmail(email, name).catch(console.error);
    } else {
      sendWelcomeEmail(email, name).catch(console.error);
    }

    res.json({ message: `Account created for ${name}`, userId: data.user.id });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});
  const { payoutId } = req.body;
  if (!payoutId) return res.status(400).json({ error: 'payoutId required' });
  await supabase.from('payout_requests').update({ status: 'paid', processed_at: new Date().toISOString() }).eq('id', payoutId);
  res.json({ message: 'Payout marked as paid' });
});

// Generate a unique referral code for a user
function generateCode(name) {
  const base = name.split(' ')[0].toUpperCase().replace(/[^A-Z]/g,'').slice(0,6);
  const suffix = Math.floor(Math.random()*900)+100;
  return base + suffix;
}

// Get or create referral code for user
app.get('/api/referral/code', requireAuth, async (req, res) => {
  let { data: profile } = await supabase.from('profiles').select('referral_code, name').eq('id', req.user.id).single();
  if (!profile.referral_code) {
    // Generate unique code
    let code, exists = true;
    while (exists) {
      code = generateCode(profile.name || 'USER');
      const { data } = await supabase.from('profiles').select('id').eq('referral_code', code).single();
      exists = !!data;
    }
    await supabase.from('profiles').update({ referral_code: code }).eq('id', req.user.id);
    profile.referral_code = code;
  }
  res.json({ code: profile.referral_code, url: `${process.env.FRONTEND_URL}?ref=${profile.referral_code}` });
});

// Get referral stats for a user
app.get('/api/referral/stats', requireAuth, async (req, res) => {
  const { data: refs } = await supabase
    .from('referrals')
    .select('*, referee:referee_id(name, email, plan, created_at)')
    .eq('referrer_id', req.user.id)
    .order('created_at', { ascending: false });

  const active = refs?.filter(r => r.status === 'active') || [];
  const pending = refs?.filter(r => r.status === 'pending') || [];
  const totalEarned = refs?.reduce((sum, r) => sum + (r.total_earned || 0), 0) || 0;
  const monthlyEarning = active.length * 5.80;

  // Get pending payout requests
  const { data: payouts } = await supabase
    .from('payout_requests')
    .select('*')
    .eq('user_id', req.user.id)
    .order('created_at', { ascending: false });

  res.json({
    referrals: refs || [],
    stats: {
      total: refs?.length || 0,
      active: active.length,
      pending: pending.length,
      totalEarned,
      monthlyEarning,
      pendingPayout: totalEarned - (payouts?.filter(p=>p.status==='paid').reduce((s,p)=>s+p.amount,0)||0),
    },
    payouts: payouts || [],
  });
});

// Request a payout
app.post('/api/referral/payout', requireAuth, async (req, res) => {
  const { method, details, amount } = req.body;
  if (!method || !details || !amount) return res.status(400).json({ error: 'Method, details and amount required' });
  if (amount < 10) return res.status(400).json({ error: 'Minimum payout is $10' });

  await supabase.from('payout_requests').insert({
    user_id: req.user.id,
    amount, method, details,
    status: 'pending',
    created_at: new Date().toISOString(),
  });

  // Email you (the admin) about the payout request
  const { data: profile } = await supabase.from('profiles').select('name, email').eq('id', req.user.id).single();
  if (process.env.SMTP_USER) {
    mailer.sendMail({
      from: `"Plutur" <${process.env.SMTP_USER}>`,
      to: process.env.SMTP_USER,
      subject: `Payout request — $${amount} — ${profile?.name}`,
      html: `<div style="font-family:monospace;padding:20px"><h2>Payout Request</h2>
        <p><strong>From:</strong> ${profile?.name} (${profile?.email})</p>
        <p><strong>Amount:</strong> $${amount}</p>
        <p><strong>Method:</strong> ${method}</p>
        <p><strong>Details:</strong> ${details}</p>
        <p>Log in to Supabase to approve: <a href="https://supabase.com">supabase.com</a></p>
      </div>`,
    }).catch(console.error);
  }

  res.json({ message: 'Payout request submitted. We\'ll process it within 48 hours.' });
});

// Called from webhook when a referred user upgrades to Pro
async function activateReferral(refereeId) {
  const { data: referee } = await supabase.from('profiles').select('referred_by').eq('id', refereeId).single();
  if (!referee?.referred_by) return;

  const { data: referrer } = await supabase.from('profiles').select('id').eq('referral_code', referee.referred_by).single();
  if (!referrer) return;

  // Create or update referral record
  const { data: existing } = await supabase.from('referrals').select('id').eq('referee_id', refereeId).single();
  if (existing) {
    await supabase.from('referrals').update({ status: 'active', activated_at: new Date().toISOString() }).eq('id', existing.id);
  } else {
    await supabase.from('referrals').insert({
      referrer_id: referrer.id, referee_id: refereeId,
      referral_code: referee.referred_by,
      status: 'active', commission_rate: 0.20,
      monthly_commission: 5.80, total_earned: 5.80,
      activated_at: new Date().toISOString(),
    });
  }

  // Add $5.80 to referrer's total
  const { data: ref } = await supabase.from('referrals').select('total_earned').eq('referee_id', refereeId).single();
  if (ref) {
    await supabase.from('referrals').update({ total_earned: (ref.total_earned||0) + 5.80 }).eq('referee_id', refereeId);
  }
}

// ═══════════════════════════════════════════════════════
//  AI ADVISOR
// ═══════════════════════════════════════════════════════
const AI_SYSTEM = `You are Plutur AI, an expert real estate investment advisor at plutur.com. 
You specialize in SFR, multi-family, Airbnb STR, arbitrage, and commercial real estate.
Give clear, direct, actionable advice with specific numbers when relevant.
Be concise and professional. Format responses with line breaks for readability.
Never give legal or tax advice — always recommend consulting a professional for those.
When discussing deals, reference key metrics: cash flow, cap rate, CoC return, DSCR, 1% rule.`;

app.post('/api/ai/chat', requireAuth, requirePro, async (req, res) => {
  const { messages } = req.body;
  if (!messages || !Array.isArray(messages)) {
    return res.status(400).json({ error: 'Messages array required' });
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    return res.status(503).json({ error: 'AI Advisor not configured. Add ANTHROPIC_API_KEY to Railway.' });
  }
  try {
    const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system: AI_SYSTEM,
      messages: messages.slice(-10), // last 10 messages to stay within context
    });
    const reply = response.content?.[0]?.text || 'Something went wrong.';
    res.json({ reply });
  } catch (err) {
    console.error('AI chat error:', err.message);
    res.status(500).json({ error: 'AI Advisor temporarily unavailable. Please try again.' });
  }
});

app.get('/api/health', (req,res) => res.json({ status:'online', service:'Plutur API', version:'1.0.0', timestamp: new Date().toISOString(), features:{ supabase:!!process.env.SUPABASE_URL, stripe:!!process.env.STRIPE_SECRET_KEY, fred:!!process.env.FRED_API_KEY, walkscore:!!process.env.WALK_SCORE_KEY, email:!!process.env.SMTP_USER, ai:!!process.env.ANTHROPIC_API_KEY }}));

app.listen(PORT, () => console.log(`Plutur API running on port ${PORT}`));
module.exports = app;
