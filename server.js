'use strict';

const express  = require('express');
const crypto   = require('crypto');
const Database = require('better-sqlite3');
const { Resend } = require('resend');
const path     = require('path');
const fs       = require('fs');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT                = process.env.PORT || 3000;
const WHOP_WEBHOOK_SECRET = process.env.WHOP_WEBHOOK_SECRET || '';
const WHOP_API_KEY        = process.env.WHOP_API_KEY        || '';
const RESEND_API_KEY      = process.env.RESEND_API_KEY      || '';
const FROM_EMAIL          = process.env.FROM_EMAIL          || 'noreply@atomicscraper.com';
const ADMIN_TOKEN         = process.env.ADMIN_TOKEN         || 'change-me';

const DOWNLOAD_LINKS = {
  windows: 'https://github.com/bensblueprints/atomic-scraper/releases/download/v1.0.0/AtomicScraper.exe',
  mac_arm: 'https://github.com/bensblueprints/atomic-scraper/releases/download/v1.0.0/AtomicScraper_arm64.dmg',
  mac_intel: 'https://github.com/bensblueprints/atomic-scraper/releases/download/v1.0.0/AtomicScraper_x86_64.dmg',
};

// ── Database ──────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'data', 'hub.db');
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS purchases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    membership_id TEXT UNIQUE NOT NULL,
    license_key   TEXT NOT NULL,
    email         TEXT NOT NULL,
    plan_id       TEXT,
    plan_price    REAL DEFAULT 0,
    status        TEXT DEFAULT 'active',
    email_sent    INTEGER DEFAULT 0,
    created_at    INTEGER DEFAULT (unixepoch()),
    updated_at    INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS webhook_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT,
    membership TEXT,
    payload    TEXT,
    received_at INTEGER DEFAULT (unixepoch())
  );
`);

// ── Helpers ───────────────────────────────────────────────────────────────────
function verifyWhopSignature(rawBody, header) {
  if (!WHOP_WEBHOOK_SECRET || !header) return false;
  const parts = Object.fromEntries(header.split(',').map(p => p.split('=')));
  const { t: ts, v1: sig } = parts;
  if (!ts || !sig) return false;
  if (Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const expected = crypto.createHmac('sha256', WHOP_WEBHOOK_SECRET)
    .update(`${ts}.${rawBody}`).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expected, 'hex'));
  } catch { return false; }
}

function requireAdmin(req, res, next) {
  const tok = req.headers['x-admin-token'] || req.query.token;
  if (tok !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  next();
}

async function sendDownloadEmail(email, licenseKey) {
  if (!RESEND_API_KEY) { console.warn('[email] RESEND_API_KEY not set — skipping'); return; }
  const resend = new Resend(RESEND_API_KEY);

  const html = `
    <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0D0D1A;color:#fff;padding:32px;border-radius:12px">
      <h1 style="color:#00BCD4;margin:0 0 8px">AtomicScraper</h1>
      <p style="color:#aaa;margin:0 0 24px">Your license is ready.</p>

      <div style="background:#12121E;border:1px solid #1E1E32;border-radius:8px;padding:20px;margin-bottom:24px">
        <p style="margin:0 0 8px;font-size:12px;color:#78909C;text-transform:uppercase;letter-spacing:1px">Your License Key</p>
        <p style="font-family:monospace;font-size:18px;color:#00BCD4;margin:0;letter-spacing:2px">${licenseKey}</p>
      </div>

      <p style="color:#ccc;margin:0 0 16px">Download AtomicScraper and enter your key to activate:</p>

      <table style="width:100%;border-collapse:collapse;margin-bottom:24px">
        <tr>
          <td style="padding:8px 0">
            <a href="${DOWNLOAD_LINKS.windows}" style="display:inline-block;background:#00BCD4;color:#000;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold">
              Download for Windows (.exe)
            </a>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0">
            <a href="${DOWNLOAD_LINKS.mac_arm}" style="display:inline-block;background:#1E1E32;color:#00BCD4;border:1px solid #00BCD4;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold">
              Download for Mac — Apple Silicon (.dmg)
            </a>
          </td>
        </tr>
        <tr>
          <td style="padding:8px 0">
            <a href="${DOWNLOAD_LINKS.mac_intel}" style="display:inline-block;background:#1E1E32;color:#00BCD4;border:1px solid #00BCD4;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:bold">
              Download for Mac — Intel (.dmg)
            </a>
          </td>
        </tr>
      </table>

      <p style="color:#78909C;font-size:12px;margin:0">
        Need help? Reply to this email or visit your Whop hub to manage your license.<br>
        To activate on a new device, reset your key at <a href="https://whop.com/@me" style="color:#00BCD4">whop.com/@me</a>.
      </p>
    </div>
  `;

  await resend.emails.send({
    from: FROM_EMAIL,
    to: email,
    subject: 'Your AtomicScraper license key + download links',
    html,
  });

  console.log(`[email] sent to ${email}`);
}

// ── App ───────────────────────────────────────────────────────────────────────
const app = express();

// Raw body needed for signature verification
app.use('/api/whop/webhook', express.raw({ type: '*/*' }));
app.use(express.json());

// Health
app.get('/healthz', (req, res) => res.json({ ok: true }));

// ── Whop Webhook ──────────────────────────────────────────────────────────────
app.post('/api/whop/webhook', async (req, res) => {
  const rawBody = req.body.toString('utf8');
  const sig     = req.headers['whop-signature'];

  if (!verifyWhopSignature(rawBody, sig)) {
    console.warn('[webhook] invalid signature');
    return res.status(401).json({ error: 'invalid signature' });
  }

  let payload;
  try { payload = JSON.parse(rawBody); } catch {
    return res.status(400).json({ error: 'bad json' });
  }

  const { action, data } = payload;
  const membershipId = data?.id;
  const licenseKey   = data?.license_key;
  const email        = data?.user?.email;
  const planId       = data?.plan?.id;
  const planPrice    = data?.plan?.price ?? 0;

  // Log everything
  db.prepare('INSERT INTO webhook_log (action, membership, payload) VALUES (?,?,?)')
    .run(action || 'unknown', membershipId || '', rawBody);

  console.log(`[webhook] ${action} | ${membershipId} | ${email}`);

  if (action === 'membership_activated' && licenseKey && email) {
    const existing = db.prepare('SELECT * FROM purchases WHERE membership_id = ?').get(membershipId);

    if (!existing) {
      // New purchase
      db.prepare(`
        INSERT INTO purchases (membership_id, license_key, email, plan_id, plan_price, status)
        VALUES (?, ?, ?, ?, ?, 'active')
      `).run(membershipId, licenseKey, email, planId || '', planPrice);

      try {
        await sendDownloadEmail(email, licenseKey);
        db.prepare('UPDATE purchases SET email_sent = 1 WHERE membership_id = ?').run(membershipId);
      } catch (err) {
        console.error('[email] failed:', err.message);
      }

    } else if (existing.license_key !== licenseKey) {
      // Key was reset — update it
      db.prepare(`
        UPDATE purchases SET license_key = ?, status = 'active', updated_at = unixepoch()
        WHERE membership_id = ?
      `).run(licenseKey, membershipId);

      // Re-send email with new key
      try {
        await sendDownloadEmail(email, licenseKey);
        db.prepare('UPDATE purchases SET email_sent = 1 WHERE membership_id = ?').run(membershipId);
      } catch (err) {
        console.error('[email] failed on key reset:', err.message);
      }
    }
  }

  if (action === 'membership_deactivated' && membershipId) {
    db.prepare(`UPDATE purchases SET status = 'cancelled', updated_at = unixepoch() WHERE membership_id = ?`)
      .run(membershipId);
    console.log(`[webhook] cancelled: ${membershipId}`);
  }

  res.json({ ok: true });
});

// ── Admin routes ──────────────────────────────────────────────────────────────
app.get('/api/admin/purchases', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM purchases ORDER BY created_at DESC').all();
  res.json(rows);
});

app.post('/api/admin/resend-email/:membershipId', requireAdmin, async (req, res) => {
  const row = db.prepare('SELECT * FROM purchases WHERE membership_id = ?').get(req.params.membershipId);
  if (!row) return res.status(404).json({ error: 'not found' });
  try {
    await sendDownloadEmail(row.email, row.license_key);
    db.prepare('UPDATE purchases SET email_sent = 1 WHERE membership_id = ?').run(row.membership_id);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/admin/webhook-log', requireAdmin, (req, res) => {
  const rows = db.prepare('SELECT * FROM webhook_log ORDER BY received_at DESC LIMIT 100').all();
  res.json(rows);
});

app.listen(PORT, () => console.log(`[atomic-scraper-hub] :${PORT}`));
