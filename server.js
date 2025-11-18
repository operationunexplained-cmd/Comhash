// server.js
// Single-file Express server that verifies MoneyTag ad webhooks and verifyPlay calls,
// updates Firebase Realtime Database (users, lootHistory), and protects verifyPlay with ADMIN_API_KEY.

// INSTALL: npm init -y
// npm i express body-parser firebase-admin dotenv crypto express-rate-limit

require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const admin = require('firebase-admin');

const app = express();
app.use(bodyParser.json({ limit: '500kb' }));

// === CONFIG from env ===
const PORT = process.env.PORT || 3000;
const MONEYTAG_SECRET = process.env.MONEYTAG_SECRET || ''; // HMAC secret sent by MoneyTag webhooks
const ADMIN_API_KEY = process.env.ADMIN_API_KEY || '';     // expected header value for verifyPlay
const FIREBASE_SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON || null;
const FIREBASE_RTDB_URL = process.env.FIREBASE_RTDB_URL || null; // e.g. https://comhashgame-default-rtdb.firebaseio.com

if (!FIREBASE_RTDB_URL && !process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  console.error('Set FIREBASE_RTDB_URL env (and FIREBASE_SERVICE_ACCOUNT_JSON or GOOGLE_APPLICATION_CREDENTIALS).');
  // continue, but will fail on init
}

// Initialize firebase-admin
if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
  admin.initializeApp({
    databaseURL: FIREBASE_RTDB_URL
  });
} else if (FIREBASE_SERVICE_ACCOUNT_JSON) {
  const svc = JSON.parse(FIREBASE_SERVICE_ACCOUNT_JSON);
  admin.initializeApp({
    credential: admin.credential.cert(svc),
    databaseURL: FIREBASE_RTDB_URL
  });
} else {
  console.error('Missing Firebase credentials. Use GOOGLE_APPLICATION_CREDENTIALS or FIREBASE_SERVICE_ACCOUNT_JSON.');
  process.exit(1);
}

const db = admin.database();
const usersRef = db.ref('users');
const lootRef = db.ref('lootHistory');
const playRef = db.ref('playHistory');
const adRef = db.ref('adHistory');

// === Rate limiter ===
const limiter = rateLimit({
  windowMs: 10 * 1000,
  max: 50
});
app.use(limiter);

// === Helper functions ===
function timingSafeEqual(a, b) {
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch (e) {
    return false;
  }
}
function verifyHmac(rawBodyString, signatureHeader) {
  if (!MONEYTAG_SECRET) return false;
  if (!signatureHeader) return false;
  const hmac = crypto.createHmac('sha256', MONEYTAG_SECRET).update(rawBodyString).digest('hex');
  return timingSafeEqual(hmac, signatureHeader);
}
function isSuspiciousPlay({ taps, durationMs }) {
  if (!Number.isFinite(taps) || !Number.isFinite(durationMs)) return true;
  if (taps <= 0) return true;
  if (taps > 1000 && durationMs < 10000) return true;
  const avgMs = durationMs / taps;
  if (avgMs < 10) return true;
  return false;
}
function calculatePlayReward(taps) {
  return Math.max(0, Math.floor(taps * 0.5)); // example: 0.5 TOK per tap
}

// === Endpoints ===

/**
 * MoneyTag webhook -> verify and credit user. MoneyTag should POST raw JSON and include header 'x-moneytag-signature'
 * Adjust header name if MoneyTag uses different one.
 */
app.post('/verifyAd', async (req, res) => {
  try {
    // We'll re-stringify body for HMAC verification. If MoneyTag provides raw bytes/signature process differently, adapt.
    const raw = JSON.stringify(req.body || {});
    const sig = req.get('x-moneytag-signature') || req.get('x-signature') || '';
    if (MONEYTAG_SECRET) {
      if (!verifyHmac(raw, sig)) {
        console.warn('Invalid HMAC on verifyAd', sig);
        return res.status(403).json({ ok: false, error: 'invalid_signature' });
      }
    } else {
      console.warn('No MONEYTAG_SECRET set - skipping HMAC check (NOT RECOMMENDED)');
    }

    // Expect MoneyTag payload to include playerId and amount (or ad_id)
    const { playerId, amount, adId } = req.body;
    if (!playerId) return res.status(400).json({ ok: false, error: 'missing_playerId' });

    const reward = Number(amount || 50);

    // Transaction-like behavior with RTDB: read then update
    const userRef = usersRef.child(String(playerId));
    const lbRef = db.ref('leaderboard').child(String(playerId)); // optional leaderboard node
    const now = Date.now();

    // update user balance & loot history atomically using transaction
    await userRef.transaction(current => {
      if (current === null) {
        return { playerId, balance: reward, score: 0, totalTaps: 0, createdAt: now };
      } else {
        current.balance = (Number(current.balance || 0) + reward);
        return current;
      }
    });

    // push ad history entry
    await adRef.push({ playerId, adId: adId || null, amount: reward, ts: now, source: 'moneytag' });

    // update leaderboard snapshot (overwrite or set)
    const userSnap = await userRef.once('value');
    const newBal = Number(userSnap.val().balance || 0);
    await lbRef.set({ playerId: String(playerId), username: userSnap.val().username || null, balance: newBal });

    console.log(`Ad reward credited ${reward} TOK to ${playerId}`);
    return res.json({ ok: true, rewarded: reward });
  } catch (err) {
    console.error('verifyAd error', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

/**
 * POST /verifyPlay
 * Body: { playerId, sessionId, taps, durationMs, username? }
 * Protected by header x-admin-key === ADMIN_API_KEY
 */
app.post('/verifyPlay', async (req, res) => {
  try {
    const providedKey = req.get('x-admin-key') || '';
    if (!ADMIN_API_KEY || providedKey !== ADMIN_API_KEY) {
      return res.status(403).json({ ok: false, error: 'invalid_admin_key' });
    }
    const { playerId, sessionId, taps, durationMs, username } = req.body;
    if (!playerId || typeof taps === 'undefined' || typeof durationMs === 'undefined' || !sessionId) {
      return res.status(400).json({ ok: false, error: 'missing_params' });
    }
    const t = Number(taps);
    const d = Number(durationMs);
    if (isSuspiciousPlay({ taps: t, durationMs: d })) {
      console.warn('Suspicious play detected', { playerId, taps: t, durationMs: d });
      return res.status(403).json({ ok: false, error: 'suspicious_play' });
    }
    const reward = calculatePlayReward(t);

    const userRef = usersRef.child(String(playerId));
    const lbRef = db.ref('leaderboard').child(String(playerId));
    const now = Date.now();

    // Update user in transaction
    await userRef.transaction(current => {
      if (current === null) {
        return { playerId, username: username || null, balance: reward, score: 0, totalTaps: t, createdAt: now };
      } else {
        current.balance = (Number(current.balance || 0) + reward);
        current.totalTaps = (Number(current.totalTaps || 0) + t);
        if (username) current.username = username;
        return current;
      }
    });

    // Push play history
    await playRef.push({ playerId, sessionId, taps: t, durationMs: d, reward, ts: now });

    // Update leaderboard snapshot
    const userSnap = await userRef.once('value');
    const newBal = Number(userSnap.val().balance || 0);
    await lbRef.set({ playerId: String(playerId), username: userSnap.val().username || null, balance: newBal });

    return res.json({ ok: true, reward });
  } catch (err) {
    console.error('verifyPlay error', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// Health check
app.get('/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

app.listen(PORT, () => console.log(`verify server listening on ${PORT}`));
