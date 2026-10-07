'use strict';
/**
 * TRHGN server (Render web service)
 *  - Serves index.html and logo.png (only those files — nothing else in the repo is exposed)
 *  - GET  /healthz            health check for Render
 *  - GET  /api/stats          { members, lgaUnits } (cached ~10s)
 *  - POST /api/register       validated server-side registration (Admin SDK → bypasses client rules)
 *  - Keeps trhgn_settings/member_stats equal to the real registrations count (boot + every 30 min),
 *    which also seeds the counter for members who registered before the counter existed.
 *
 * Env vars (Render → Environment):
 *   FIREBASE_SERVICE_ACCOUNT  full service-account JSON (one line)   [required for /api/*]
 *   ADMIN_PIN                 admin password/PIN, verified server-side (use 8+ characters)  [required for admin]
 *   ADMIN_SESSION_HOURS       admin session length, default 8                                [optional]
 *   ALLOWED_ORIGINS           comma-separated origins for CORS, e.g. https://yoursite.com  [optional]
 *   PORT                      set by Render automatically
 */
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

const PORT = process.env.PORT || 3000;
const COL_REG = 'trhgn_registrations';
const COL_SET = 'trhgn_settings';
const DOC_STATS = 'member_stats';

// ── Firebase Admin (lazy-safe: site still serves if credentials are missing) ──
let db = null;
try {
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    if (sa.private_key) sa.private_key = sa.private_key.replace(/\\n/g, '\n');
    admin.initializeApp({
      credential: admin.credential.cert(sa),
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET || `${sa.project_id}.firebasestorage.app`
    });
    db = admin.firestore();
    db.settings({ ignoreUndefinedProperties: true });
  } else {
    console.warn('⚠️  FIREBASE_SERVICE_ACCOUNT not set — /api/* will return 503.');
  }
} catch (e) {
  console.error('❌ Firebase Admin init failed:', e.message);
}

const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy → correct client IPs for rate limiting
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false })); // site uses inline scripts + several CDNs
app.use(compression());

const origins = (process.env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use('/api', cors({ origin: origins.length ? origins : true, methods: ['GET', 'POST', 'PUT', 'DELETE'] }));
const jsonSmall = express.json({ limit: '20kb' });
const jsonBig = express.json({ limit: '2mb' });
app.use((req, res, next) => (req.path.startsWith('/api/admin') ? jsonBig(req, res, next) : jsonSmall(req, res, next)));

const needDb = (req, res, next) => (db ? next() : res.status(503).json({ ok: false, error: 'Server database not configured' }));

// ── Static: only the site page ──
const indexFile = path.join(__dirname, 'index.html');
app.get(['/', '/index.html'], (req, res) => res.sendFile(indexFile));
app.get('/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'logo.png'), { maxAge: '7d' })); // default site logo
app.get('/healthz', (req, res) => res.json({ ok: true, db: !!db, uptime: Math.round(process.uptime()) }));

// ── Stats ──
let statsCache = { at: 0, members: 0 };
async function realCount() {
  const snap = await db.collection(COL_REG).count().get();
  return snap.data().count;
}
async function syncCounter() {
  if (!db) return;
  try {
    const n = await realCount();
    await db.collection(COL_SET).doc(DOC_STATS).set({ count: n }, { merge: true });
    statsCache = { at: Date.now(), members: n };
    console.log(`🔢 member_stats synced → ${n}`);
  } catch (e) {
    console.error('Counter sync failed:', e.message);
  }
}

app.get('/api/stats', needDb, async (req, res) => {
  try {
    if (Date.now() - statsCache.at > 10000) {
      statsCache = { at: Date.now(), members: await realCount() };
    }
    res.set('Cache-Control', 'public, max-age=5');
    res.json({ ok: true, members: statsCache.members, lgaUnits: 774 });
  } catch (e) {
    console.error('stats error:', e.message);
    res.status(500).json({ ok: false, error: 'Could not load stats' });
  }
});

// ── Registration ──
const str = (v, max) => (typeof v === 'string' ? v.trim().replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max) : '');

// Same algorithm as the website's generateSerial() (name + LGA + polling unit + phone digits).
function generateSerial(name, lga, pollingUnit, phone) {
  // Phone digits are part of the ID so two different people can't collide (must match index.html)
  const raw = (name + lga + pollingUnit + String(phone || '').replace(/\D/g, '')).toUpperCase().replace(/\s+/g, '');
  let hash = 0;
  for (let i = 0; i < raw.length; i++) {
    hash = ((hash << 5) - hash) + raw.charCodeAt(i);
    hash |= 0;
  }
  const abs = Math.abs(hash);
  const initials = name.trim().split(/\s+/).map(w => w[0]).join('').substring(0, 3).toUpperCase();
  const lgaCode = lga.replace(/\s+/g, '').substring(0, 3).toUpperCase();
  return `RH-${initials}${lgaCode}-${String(abs % 100000).padStart(5, '0')}`;
}

const registerLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 60, // was 15 — many users share one mobile-carrier IP (CGNAT)
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many attempts. Please try again later.' }
});

app.post('/api/register', needDb, registerLimiter, async (req, res) => {
  try {
    const b = req.body || {};
    const name = str(b.name, 120);
    const phone = str(b.phone, 20);
    const email = str(b.email, 120);
    if (name.length < 2) return res.status(400).json({ ok: false, error: 'Full name is required' });
    if (!/^[+\d][\d\s-]{5,19}$/.test(phone)) return res.status(400).json({ ok: false, error: 'A valid phone number is required' });
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, error: 'Email address is invalid' });

    const lga = str(b.lga, 80);
    const pollingUnit = str(b.pollingUnit, 160);
    const memberId = generateSerial(name, lga, pollingUnit, phone);
    const now = Date.now();

    const record = {
      memberId,
      registeredAt: now,
      registeredAtISO: new Date(now).toISOString(),
      name,
      dob: str(b.dob, 20),
      gender: str(b.gender, 20),
      occupation: str(b.occupation, 120),
      marital: str(b.marital, 30),
      phone,
      email,
      address: str(b.address, 300),
      stateResidence: str(b.stateResidence, 60),
      lga,
      stateOrigin: str(b.stateOrigin, 60),
      lgaOrigin: str(b.lgaOrigin, 80),
      ward: str(b.ward, 120),
      pollingUnit
    };

    const regRef = db.collection(COL_REG).doc(memberId);
    const statsRef = db.collection(COL_SET).doc(DOC_STATS);

    const created = await db.runTransaction(async (tx) => {
      const existing = await tx.get(regRef);
      if (existing.exists) return false;
      tx.set(regRef, record);
      tx.set(statsRef, { count: admin.firestore.FieldValue.increment(1) }, { merge: true });
      return true;
    });

    if (created) statsCache.at = 0; // invalidate stats cache
    res.status(created ? 201 : 200).json({
      ok: true,
      alreadyRegistered: !created,
      memberId,
      qrCodeUrl: `https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=${encodeURIComponent(memberId)}`
    });
  } catch (e) {
    console.error('register error:', e.message);
    res.status(500).json({ ok: false, error: 'Registration failed. Please try again.' });
  }
});

// ── Admin login: verifies the PIN server-side and returns a Firebase custom token.
// Firestore/Storage rules require { admin: true, adminUntil > now }, so the PIN is never in the page.
const ADMIN_PIN = process.env.ADMIN_PIN || '';
const ADMIN_SESSION_HOURS = Number(process.env.ADMIN_SESSION_HOURS) || 8;
if (!ADMIN_PIN) console.warn('⚠️  ADMIN_PIN not set — admin login is disabled.');
const sha = (v) => crypto.createHash('sha256').update(String(v)).digest();

// ── Stateless admin session (HMAC-signed). The browser never needs Google sign-in for admin work.
const SESSION_SECRET = crypto.createHash('sha256').update('trhgn-session|' + ADMIN_PIN + '|' + (process.env.SESSION_SECRET || '')).digest();
const hmac = (p) => crypto.createHmac('sha256', SESSION_SECRET).update(p).digest('base64url');
function signSession(exp) { const p = Buffer.from(JSON.stringify({ exp })).toString('base64url'); return p + '.' + hmac(p); }
function verifySession(t) {
  try {
    const [p, sig] = String(t || '').split('.');
    if (!p || !sig) return false;
    const a = Buffer.from(sig), b = Buffer.from(hmac(p));
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
    return Number(JSON.parse(Buffer.from(p, 'base64url').toString()).exp) > Date.now();
  } catch (e) { return false; }
}
function requireAdmin(req, res, next) {
  if (!ADMIN_PIN) return res.status(503).json({ ok: false, error: 'Admin login is not configured on the server' });
  const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
  if (m && verifySession(m[1])) return next();
  res.status(401).json({ ok: false, error: 'Admin session expired — re-enter your PIN.' });
}

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 6,
  skipSuccessfulRequests: true, // only failed attempts count
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, error: 'Too many attempts. Try again in 15 minutes.' }
});

app.post('/api/admin/login', needDb, adminLimiter, async (req, res) => {
  try {
    if (!ADMIN_PIN) return res.status(503).json({ ok: false, error: 'Admin login is not configured on the server' });
    const pin = typeof (req.body && req.body.pin) === 'string' ? req.body.pin : '';
    const good = pin.length > 0 && pin.length <= 64 && crypto.timingSafeEqual(sha(pin), sha(ADMIN_PIN));
    if (!good) {
      await new Promise(r => setTimeout(r, 500)); // slow down guessing
      return res.status(401).json({ ok: false, error: 'Incorrect PIN' });
    }
    const expiresAt = Date.now() + ADMIN_SESSION_HOURS * 3600 * 1000;
    res.json({ ok: true, session: signSession(expiresAt), expiresAt });
  } catch (e) {
    console.error('admin login error:', e.message);
    res.status(500).json({ ok: false, error: 'Login failed. Please try again.' });
  }
});

// ── Admin API (all require a valid admin session) ──
const ID_RE = /^[\w.-]{1,120}$/;
const SETTINGS_OK = new Set(['site_logo', 'tinubu_profile', 'convener_profile']);
const wrap = (fn) => async (req, res) => {
  try { await fn(req, res); } catch (e) { console.error('admin api error:', e.message); res.status(500).json({ ok: false, error: 'Server error: ' + e.message }); }
};
async function deleteAll(colName) {
  const snap = await db.collection(colName).get();
  for (let i = 0; i < snap.docs.length; i += 450) {
    const batch = db.batch();
    snap.docs.slice(i, i + 450).forEach(d => batch.delete(d.ref));
    await batch.commit();
  }
  return snap.size;
}

// Quick check used by the page to confirm a stored session is still valid
app.get('/api/admin/session', requireAdmin, (req, res) => res.json({ ok: true }));

app.get('/api/admin/registrations', needDb, requireAdmin, wrap(async (req, res) => {
  const snap = await db.collection(COL_REG).orderBy('registeredAt', 'desc').get();
  res.set('Cache-Control', 'no-store');
  res.json({ ok: true, registrations: snap.docs.map(d => ({ fsId: d.id, ...d.data() })) });
}));
app.delete('/api/admin/registrations/:id', needDb, requireAdmin, wrap(async (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ ok: false, error: 'Bad id' });
  await db.collection(COL_REG).doc(req.params.id).delete();
  statsCache.at = 0; syncCounter();
  res.json({ ok: true });
}));
app.delete('/api/admin/registrations', needDb, requireAdmin, wrap(async (req, res) => {
  const n = await deleteAll(COL_REG);
  await db.collection(COL_SET).doc(DOC_STATS).set({ count: 0 }, { merge: true });
  statsCache = { at: 0, members: 0 };
  res.json({ ok: true, deleted: n });
}));

app.put('/api/admin/media/:id', needDb, requireAdmin, wrap(async (req, res) => {
  if (!ID_RE.test(req.params.id) || !req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ ok: false, error: 'Bad request' });
  await db.collection('trhgn_media').doc(req.params.id).set(req.body);
  res.json({ ok: true });
}));
app.delete('/api/admin/media/:id', needDb, requireAdmin, wrap(async (req, res) => {
  if (!ID_RE.test(req.params.id)) return res.status(400).json({ ok: false, error: 'Bad id' });
  await db.collection('trhgn_media').doc(req.params.id).delete();
  res.json({ ok: true });
}));
app.delete('/api/admin/media', needDb, requireAdmin, wrap(async (req, res) => {
  res.json({ ok: true, deleted: await deleteAll('trhgn_media') });
}));

app.put('/api/admin/settings/:name', needDb, requireAdmin, wrap(async (req, res) => {
  if (!SETTINGS_OK.has(req.params.name) || !req.body || typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ ok: false, error: 'Bad request' });
  await db.collection(COL_SET).doc(req.params.name).set(req.body);
  res.json({ ok: true });
}));

// Upload: the browser PUTs the raw file here; the server streams it into Firebase Storage (Admin SDK).
app.put('/api/admin/upload', needDb, requireAdmin, (req, res) => {
  const p = String(req.query.path || '');
  const m = /^(admin_media|settings_media)\/[A-Za-z0-9._-]{1,200}$/.exec(p);
  if (!m) return res.status(400).json({ ok: false, error: 'Bad upload path' });
  const ct = String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  const isMedia = m[1] === 'admin_media';
  const typeOk = isMedia ? (/^(image|video)\//.test(ct) || ct === 'application/pdf') : /^image\//.test(ct);
  if (!typeOk) return res.status(415).json({ ok: false, error: 'File type not allowed' });
  const max = (isMedia ? 200 : 10) * 1024 * 1024;
  if (Number(req.headers['content-length'] || 0) > max) return res.status(413).json({ ok: false, error: 'File too large' });
  const bucket = admin.storage().bucket();
  const ws = bucket.file(p).createWriteStream({ resumable: false, metadata: { contentType: ct, cacheControl: 'public, max-age=31536000' } });
  let size = 0, done = false;
  const fail = (code, msg) => { if (done) return; done = true; ws.destroy(); res.status(code).json({ ok: false, error: msg }); };
  req.on('data', (c) => { size += c.length; if (size > max) { fail(413, 'File too large'); req.unpause && req.resume(); } });
  req.on('aborted', () => { done = true; ws.destroy(); });
  ws.on('error', (e) => { console.error('upload error:', e.message); fail(500, 'Upload failed: ' + e.message); });
  ws.on('finish', () => {
    if (done) return; done = true;
    res.json({ ok: true, url: `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(p)}?alt=media` });
  });
  req.pipe(ws);
});

app.use('/api', (req, res) => res.status(404).json({ ok: false, error: 'Not found' }));
app.use((req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => {
  console.log(`✅ TRHGN server listening on :${PORT}`);
  syncCounter();
  setInterval(syncCounter, 30 * 60 * 1000).unref();
});