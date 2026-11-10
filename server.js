require("dotenv").config();

const express = require("express");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DB_PATH = process.env.DATABASE_PATH || "./data/bano.sqlite";
const dbDir = path.dirname(path.resolve(DB_PATH));
fs.mkdirSync(dbDir, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  throw new Error("SESSION_SECRET must be set and at least 32 characters long.");
}
if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD_HASH) {
  throw new Error("Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH in .env");
}

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS customers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  public_id TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  phone TEXT NOT NULL UNIQUE,
  referrer_id INTEGER NULL REFERENCES customers(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  created_by TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customers_created_at ON customers(created_at);
CREATE INDEX IF NOT EXISTS idx_customers_referrer_id ON customers(referrer_id);
`);

app.disable("x-powered-by");
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: null
    }
  }
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dbDir }),
  name: "bano.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 8 * 60 * 60 * 1000
  }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const otpLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 5, standardHeaders: true, legacyHeaders: false });
const registerLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });

function normalizeIranPhone(value) {
  let p = String(value || "").replace(/[\s\-()]/g, "");
  if (p.startsWith("+98")) p = "0" + p.slice(3);
  else if (p.startsWith("0098")) p = "0" + p.slice(4);
  else if (p.startsWith("98") && p.length === 12) p = "0" + p.slice(2);
  return /^09\d{9}$/.test(p) ? p : null;
}
function cleanName(value) {
  const name = String(value || "").trim().replace(/\s+/g, " ");
  if (name.length < 2 || name.length > 80) return null;
  if (/[<>]/.test(name)) return null;
  return name;
}
function requireAuth(req, res, next) {
  if (!req.session || !req.session.staff) return res.status(401).json({ error: "برای ادامه وارد پنل شوید." });
  next();
}
function generatePublicId() {
  // 5 digits, including leading zero. Database UNIQUE constraint is the final authority.
  for (let i = 0; i < 100; i++) {
    const id = String(Math.floor(Math.random() * 100000)).padStart(5, "0");
    if (!db.prepare("SELECT 1 FROM customers WHERE public_id = ?").get(id)) return id;
  }
  throw new Error("Could not allocate a unique customer ID");
}
async function sendKavenegarOtp(phone, code) {
  const apiKey = process.env.KAVENEGAR_API_KEY;
  const template = process.env.KAVENEGAR_VERIFY_TEMPLATE;
  if (!apiKey || !template || apiKey === "your-kavenegar-api-key") {
    throw new Error("تنظیمات کاوه‌نگار کامل نشده است.");
  }
  const url = `https://api.kavenegar.com/v1/${encodeURIComponent(apiKey)}/verify/lookup.json`;
  const body = new URLSearchParams({
    receptor: phone,
    token: code,
    template
  });
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || data?.return?.status !== 200) {
    throw new Error(data?.return?.message || "ارسال پیامک ناموفق بود.");
  }
}

const otpChallenges = new Map(); // short-lived OTPs; use Redis for multi-instance production deployments
const OTP_TTL_MS = 3 * 60 * 1000;

app.post("/api/login", loginLimiter, async (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const okUser = username === process.env.ADMIN_USERNAME;
  const okPass = await bcrypt.compare(password, process.env.ADMIN_PASSWORD_HASH);
  if (!okUser || !okPass) return res.status(401).json({ error: "نام کاربری یا رمز عبور اشتباه است." });
  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: "خطا در ایجاد نشست." });
    req.session.staff = username;
    res.json({ ok: true, username });
  });
});
app.post("/api/logout", requireAuth, (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/me", (req, res) => res.json({ authenticated: !!req.session?.staff, username: req.session?.staff || null }));

app.post("/api/otp/send", requireAuth, otpLimiter, async (req, res) => {
  const phone = normalizeIranPhone(req.body.phone);
  if (!phone) return res.status(400).json({ error: "شماره موبایل معتبر نیست. نمونه: 09123456789" });
  if (db.prepare("SELECT 1 FROM customers WHERE phone = ?").get(phone)) {
    return res.status(409).json({ error: "این شماره قبلاً در بانو ثبت شده است." });
  }
  const code = String(Math.floor(100000 + Math.random() * 900000));
  try {
    await sendKavenegarOtp(phone, code);
    otpChallenges.set(phone, { code, expires: Date.now() + OTP_TTL_MS, attempts: 0 });
    res.json({ ok: true, message: "کد تأیید ارسال شد. اعتبار کد ۳ دقیقه است." });
  } catch (e) {
    res.status(502).json({ error: e.message || "ارسال پیامک انجام نشد." });
  }
});

app.post("/api/customers", requireAuth, registerLimiter, (req, res) => {
  const name = cleanName(req.body.name);
  const phone = normalizeIranPhone(req.body.phone);
  const code = String(req.body.otp || "").trim();
  const referralCode = String(req.body.referralCode || "").trim();

  if (!name) return res.status(400).json({ error: "نام باید بین ۲ تا ۸۰ کاراکتر باشد." });
  if (!phone) return res.status(400).json({ error: "شماره موبایل معتبر نیست." });

  const challenge = otpChallenges.get(phone);
  if (!challenge || challenge.expires < Date.now()) {
    otpChallenges.delete(phone);
    return res.status(400).json({ error: "کد تأیید منقضی شده یا ارسال نشده است." });
  }
  if (challenge.attempts >= 5) {
    otpChallenges.delete(phone);
    return res.status(429).json({ error: "تعداد تلاش بیش از حد مجاز است. دوباره کد بگیرید." });
  }
  challenge.attempts += 1;
  if (challenge.code !== code) return res.status(400).json({ error: "کد تأیید اشتباه است." });

  const duplicate = db.prepare("SELECT 1 FROM customers WHERE phone = ?").get(phone);
  if (duplicate) {
    otpChallenges.delete(phone);
    return res.status(409).json({ error: "این شماره قبلاً ثبت شده است." });
  }

  let referrer = null;
  if (referralCode) {
    if (!/^\d{5}$/.test(referralCode)) return res.status(400).json({ error: "کد معرف باید ۵ رقم باشد." });
    referrer = db.prepare("SELECT id, phone FROM customers WHERE public_id = ?").get(referralCode);
    if (!referrer) return res.status(400).json({ error: "کد معرف پیدا نشد." });
    if (referrer.phone === phone) return res.status(400).json({ error: "هر شخص نمی‌تواند معرف خودش باشد." });
  }

  // Retry on the very unlikely 5-digit collision. UNIQUE(phone) prevents duplicate numbers even in races.
  for (let attempt = 0; attempt < 10; attempt++) {
    try {
      const publicId = generatePublicId();
      const result = db.prepare(`
        INSERT INTO customers (public_id, name, phone, referrer_id, created_by)
        VALUES (?, ?, ?, ?, ?)
      `).run(publicId, name, phone, referrer?.id || null, req.session.staff);
      otpChallenges.delete(phone);
      return res.status(201).json({
        ok: true,
        customer: {
          id: result.lastInsertRowid,
          publicId,
          name,
          phone,
          referrerCode: referrerCode || null
        }
      });
    } catch (e) {
      if (String(e.message).includes("UNIQUE constraint failed: customers.phone")) {
        otpChallenges.delete(phone);
        return res.status(409).json({ error: "این شماره قبلاً ثبت شده است." });
      }
      if (String(e.message).includes("UNIQUE constraint failed: customers.public_id")) continue;
      console.error(e);
      return res.status(500).json({ error: "ثبت مشتری انجام نشد." });
    }
  }
  res.status(500).json({ error: "ساخت شناسه یکتا ناموفق بود. دوباره تلاش کنید." });
});

app.get("/api/dashboard", requireAuth, (req, res) => {
  const total = db.prepare("SELECT COUNT(*) AS n FROM customers").get().n;
  const today = db.prepare("SELECT COUNT(*) AS n FROM customers WHERE date(created_at, 'localtime') = date('now','localtime')").get().n;
  const week = db.prepare("SELECT COUNT(*) AS n FROM customers WHERE datetime(created_at) >= datetime('now','-6 days')").get().n;
  const referrals = db.prepare("SELECT COUNT(*) AS n FROM customers WHERE referrer_id IS NOT NULL").get().n;
  const topReferrers = db.prepare(`
    SELECT c.public_id, c.name, c.phone, COUNT(r.id) AS referral_count
    FROM customers c LEFT JOIN customers r ON r.referrer_id = c.id
    GROUP BY c.id ORDER BY referral_count DESC, c.created_at DESC LIMIT 10
  `).all();
  const weekly = db.prepare(`
    SELECT date(created_at) AS day, COUNT(*) AS count
    FROM customers
    WHERE datetime(created_at) >= datetime('now','-6 days')
    GROUP BY date(created_at) ORDER BY day
  `).all();
  res.json({ total, today, week, referrals, topReferrers, weekly });
});

app.get("/api/customers", requireAuth, (req, res) => {
  const q = String(req.query.q || "").trim().slice(0, 80);
  const rows = q
    ? db.prepare(`
        SELECT c.public_id, c.name, c.phone, c.created_at, c2.public_id AS referrer_code, c2.name AS referrer_name,
          (SELECT COUNT(*) FROM customers x WHERE x.referrer_id = c.id) AS referral_count
        FROM customers c LEFT JOIN customers c2 ON c.referrer_id = c2.id
        WHERE c.name LIKE ? OR c.phone LIKE ? OR c.public_id LIKE ?
        ORDER BY c.id DESC LIMIT 500
      `).all(`%${q}%`, `%${q}%`, `%${q}%`)
    : db.prepare(`
        SELECT c.public_id, c.name, c.phone, c.created_at, c2.public_id AS referrer_code, c2.name AS referrer_name,
          (SELECT COUNT(*) FROM customers x WHERE x.referrer_id = c.id) AS referral_count
        FROM customers c LEFT JOIN customers c2 ON c.referrer_id = c2.id
        ORDER BY c.id DESC LIMIT 500
      `).all();
  res.json({ customers: rows });
});

app.get("/api/customers/:publicId", requireAuth, (req, res) => {
  const customer = db.prepare(`
    SELECT c.public_id, c.name, c.phone, c.created_at, c2.public_id AS referrer_code, c2.name AS referrer_name,
      (SELECT COUNT(*) FROM customers x WHERE x.referrer_id = c.id) AS referral_count
    FROM customers c LEFT JOIN customers c2 ON c.referrer_id = c2.id
    WHERE c.public_id = ?
  `).get(req.params.publicId);
  if (!customer) return res.status(404).json({ error: "مشتری پیدا نشد." });
  res.json({ customer });
});

app.use(express.static(path.join(__dirname, "public")));
app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

app.listen(PORT, () => console.log(`Bano system running on port ${PORT}`));
