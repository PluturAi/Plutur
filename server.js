require('dotenv').config();
const express = require('express');
const cors = require('cors');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { createClient } = require('@supabase/supabase-js');
const nodemailer = require('nodemailer');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));

const app = express();
const PORT = process.env.PORT || 3001;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: 587,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
});

app.use(cors({ origin: process.env.FRONTEND_URL || '*' }));
app.use('/api/stripe/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

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
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  const { data, error } = await supabase.auth.signUp({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  await supabase.from('profiles').insert({ id: data.user.id, name, email, plan: 'free', analyses_today: 0, analyses_date: new Date().toDateString(), created_at: new Date().toISOString() });
  sendWelcomeEmail(email, name).catch(console.error);
  res.json({ user: data.user, session: data.session });
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
  if (event.type === 'checkout.session.completed') {
    const s = event.data.object;
    const userId = s.metadata?.user_id;
    if (userId) {
      await supabase.from('profiles').update({ plan: 'pro', stripe_subscription_id: s.subscription }).eq('id', userId);
      const { data: p } = await supabase.from('profiles').select('email,name').eq('id', userId).single();
      if (p) sendUpgradeEmail(p.email, p.name).catch(console.error);
    }
  } else if (event.type === 'customer.subscription.deleted') {
    const { data: p } = await supabase.from('profiles').select('id').eq('stripe_subscription_id', event.data.object.id).single();
    if (p) await supabase.from('profiles').update({ plan: 'free', stripe_subscription_id: null }).eq('id', p.id);
  }
  res.json({ received: true });
});

// MARKET DATA
app.get('/api/market/rates', async (req, res) => {
  try {
    const url = `https://api.stlouisfed.org/fred/series/observations?series_id=MORTGAGE30US&api_key=${process.env.FRED_API_KEY}&sort_order=desc&limit=1&file_type=json`;
    const r = await fetch(url);
    const data = await r.json();
    const rate = parseFloat(data.observations?.[0]?.value);
    res.json({ rate_30yr: isNaN(rate) ? 6.89 : rate, date: data.observations?.[0]?.date, source: 'Federal Reserve FRED' });
  } catch { res.json({ rate_30yr: 6.89, source: 'Plutur Default' }); }
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

async function sendWelcomeEmail(email, name) {
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Welcome to Plutur — Real Estate Investment Intelligence',
    html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0b1f3a;color:white;border-radius:12px;padding:32px 36px"><h1 style="color:white;margin:0 0 16px">Welcome to Plutur, ${name.split(' ')[0]}.</h1><p style="color:rgba(255,255,255,.7);line-height:1.7">Your account is ready. You have 3 free analyses per day to get started.</p><br><a href="${process.env.FRONTEND_URL}" style="background:#1e5cdc;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Open Plutur →</a></div>`,
  });
}

async function sendUpgradeEmail(email, name) {
  await mailer.sendMail({
    from: `"Plutur" <${process.env.SMTP_USER}>`,
    to: email,
    subject: 'Welcome to Plutur Pro.',
    html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;background:#0b1f3a;color:white;border-radius:12px;padding:32px 36px"><h1 style="color:white;margin:0 0 16px">You're now on Plutur Pro, ${name.split(' ')[0]}.</h1><p style="color:rgba(255,255,255,.7);line-height:1.7">Unlimited analyses, all property types, live market data, ML scoring, AI Advisor, and PDF export are now unlocked.</p><br><a href="${process.env.FRONTEND_URL}" style="background:#1e5cdc;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:600">Start Analyzing →</a></div>`,
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

app.get('/api/health', (req,res) => res.json({ status:'online', service:'Plutur API', version:'1.0.0', timestamp: new Date().toISOString(), features:{ supabase:!!process.env.SUPABASE_URL, stripe:!!process.env.STRIPE_SECRET_KEY, fred:!!process.env.FRED_API_KEY, email:!!process.env.SMTP_USER }}));

app.listen(PORT, () => console.log(`Plutur API running on port ${PORT}`));
module.exports = app;
