const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const Database = require('better-sqlite3');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

// ─── JWT SECRET (simpan dalam .env untuk production) ─────────────────────────
const JWT_SECRET = crypto.randomBytes(64).toString('hex');
const JWT_EXPIRES = '2h';

// ─── DATABASE SETUP ───────────────────────────────────────────────────────────
const db = new Database('./sellers.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS admin (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sellers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    phone TEXT NOT NULL,
    image_path TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    success INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS blacklist_ip (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT,
    blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME
  );
`);

// ─── SEED ADMIN (hanya sekali) ────────────────────────────────────────────────
// TUKAR USERNAME & PASSWORD DI SINI
const ADMIN_USERNAME = 'KizxBjir';
const ADMIN_PASSWORD = 'KizxAmatJembut1267@Secure#2025!';

const existingAdmin = db.prepare('SELECT id FROM admin WHERE username = ?').get(ADMIN_USERNAME);
if (!existingAdmin) {
  const hash = bcrypt.hashSync(ADMIN_PASSWORD, 14); // cost factor 14 = sangat kuat
  db.prepare('INSERT INTO admin (username, password_hash) VALUES (?, ?)').run(ADMIN_USERNAME, hash);
  console.log(`[INIT] Admin created: ${ADMIN_USERNAME}`);
}

// ─── UPLOAD SETUP ─────────────────────────────────────────────────────────────
const uploadDir = './uploads';
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const safeName = crypto.randomBytes(16).toString('hex') + ext;
    cb(null, safeName);
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 3 * 1024 * 1024 }, // max 3MB
  fileFilter: (req, file, cb) => {
    const allowed = ['.jpg', '.jpeg', '.png', '.webp'];
    const ext = path.extname(file.originalname).toLowerCase();
    if (!allowed.includes(ext)) {
      return cb(new Error('Hanya imej JPG/PNG/WEBP dibenarkan'));
    }
    cb(null, true);
  }
});

// ─── MIDDLEWARE ───────────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '1mb' }));
app.use(express.static('.'));
app.use('/uploads', express.static('uploads'));

// ─── RATE LIMITER GLOBAL ──────────────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { error: 'Too many requests' }
});
app.use(globalLimiter);

// ─── RATE LIMITER LOGIN (KETAT) ───────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5, // hanya 5 cubaan per 15 minit
  message: { error: 'Too many login attempts. Cuba lagi selepas 15 minit.' },
  skipSuccessfulRequests: true
});

// ─── BLACKLIST CHECK MIDDLEWARE ───────────────────────────────────────────────
function checkBlacklist(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = new Date().toISOString();
  const blocked = db.prepare(`
    SELECT * FROM blacklist_ip 
    WHERE ip = ? AND (expires_at IS NULL OR expires_at > ?)
  `).get(ip, now);

  if (blocked) {
    return res.status(403).json({ error: 'IP ANDA TELAH DISEKAT. Hubungi admin.' });
  }
  next();
}

// ─── JWT VERIFY MIDDLEWARE ────────────────────────────────────────────────────
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Token diperlukan' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Token tidak sah atau tamat tempoh' });
  }
}

// ─── LOG LOGIN ATTEMPT ────────────────────────────────────────────────────────
function logAttempt(ip, success) {
  db.prepare('INSERT INTO login_attempts (ip, success) VALUES (?, ?)').run(ip, success ? 1 : 0);
  
  if (!success) {
    // Kira cubaan gagal dalam 30 minit
    const since = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    const failCount = db.prepare(`
      SELECT COUNT(*) as count FROM login_attempts 
      WHERE ip = ? AND success = 0 AND attempted_at > ?
    `).get(ip, since).count;

    // Lebih dari 10 cubaan gagal = blacklist 24 jam
    if (failCount >= 10) {
      const expires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
      db.prepare(`
        INSERT OR REPLACE INTO blacklist_ip (ip, reason, expires_at) 
        VALUES (?, 'Brute force detected', ?)
      `).run(ip, expires);
      console.log(`[SECURITY] IP blacklisted: ${ip}`);
    }
  }
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════════════════════

// ─── GET ALL SELLERS (public) ─────────────────────────────────────────────────
app.get('/api/sellers', (req, res) => {
  const sellers = db.prepare('SELECT id, name, role, phone, image_path FROM sellers ORDER BY id DESC').all();
  res.json({ sellers });
});

// ─── ADMIN LOGIN ──────────────────────────────────────────────────────────────
app.post('/api/admin/login', checkBlacklist, loginLimiter, async (req, res) => {
  const ip = req.ip || req.connection.remoteAddress;
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username dan password diperlukan' });
  }

  // Artificial delay untuk halang timing attack
  await new Promise(r => setTimeout(r, 500 + Math.random() * 500));

  const admin = db.prepare('SELECT * FROM admin WHERE username = ?').get(username);

  if (!admin) {
    logAttempt(ip, false);
    return res.status(401).json({ error: 'Username atau password salah' });
  }

  const valid = bcrypt.compareSync(password, admin.password_hash);

  if (!valid) {
    logAttempt(ip, false);
    return res.status(401).json({ error: 'Username atau password salah' });
  }

  logAttempt(ip, true);

  const token = jwt.sign(
    { id: admin.id, username: admin.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );

  console.log(`[AUTH] Admin login: ${username} dari ${ip}`);

  res.json({
    success: true,
    token,
    message: 'Login berjaya'
  });
});

// ─── VERIFY TOKEN (semak jika token masih sah) ────────────────────────────────
app.get('/api/admin/verify', verifyToken, (req, res) => {
  res.json({ valid: true, admin: req.admin.username });
});

// ─── ADD SELLER ───────────────────────────────────────────────────────────────
app.post('/api/sellers', verifyToken, upload.single('image'), (req, res) => {
  const { name, role, phone } = req.body;

  if (!name || !role || !phone || !req.file) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Semua field diperlukan' });
  }

  const cleanPhone = phone.replace(/[^0-9]/g, '');
  if (cleanPhone.length < 10 || cleanPhone.length > 15) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: 'Nombor telefon tidak sah' });
  }

  const imagePath = `/uploads/${req.file.filename}`;

  const result = db.prepare(`
    INSERT INTO sellers (name, role, phone, image_path) VALUES (?, ?, ?, ?)
  `).run(name.trim(), role.trim(), cleanPhone, imagePath);

  res.json({
    success: true,
    seller: { id: result.lastInsertRowid, name, role, phone: cleanPhone, image_path: imagePath }
  });
});

// ─── DELETE SELLER ────────────────────────────────────────────────────────────
app.delete('/api/sellers/:id', verifyToken, (req, res) => {
  const { id } = req.params;

  const seller = db.prepare('SELECT * FROM sellers WHERE id = ?').get(id);
  if (!seller) return res.status(404).json({ error: 'Seller tidak dijumpai' });

  // Padam imej dari disk
  const imgPath = '.' + seller.image_path;
  if (fs.existsSync(imgPath)) {
    try { fs.unlinkSync(imgPath); } catch (e) {}
  }

  db.prepare('DELETE FROM sellers WHERE id = ?').run(id);
  res.json({ success: true });
});

// ─── DEFAULT sellers (seed kalau db kosong) ───────────────────────────────────
const count = db.prepare('SELECT COUNT(*) as c FROM sellers').get().c;
if (count === 0) {
  const defaultSellers = [
    { name: 'Kizx Store', role: 'SELLER', phone: '601161019275', image_path: 'https://files.catbox.moe/5d5i9r.jpg' },
    { name: 'Kael Store', role: 'SELLER', phone: '60136198316', image_path: 'https://files.catbox.moe/sm2lvd.jpg' },
    { name: 'IKYY Store', role: 'SELLER', phone: '601161834315', image_path: 'https://files.catbox.moe/rj3tbw.jpg' },
    { name: 'Minz Store', role: 'SELLER', phone: '60137750974', image_path: 'https://files.catbox.moe/qgqf6v.jpg' },
    { name: 'Yanzary Store', role: 'SELLER', phone: '601137650485', image_path: 'https://files.catbox.moe/bjtvh8.jpg' },
    { name: 'Ipanz Store', role: 'SELLER', phone: '60175970694', image_path: 'https://files.catbox.moe/wnx2ny.jpg' },
  ];
  const ins = db.prepare('INSERT INTO sellers (name, role, phone, image_path) VALUES (?, ?, ?, ?)');
  defaultSellers.forEach(s => ins.run(s.name, s.role, s.phone, s.image_path));
  console.log('[INIT] Default sellers seeded');
}

// ─── 404 ──────────────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ─── ERROR HANDLER ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[ERROR]', err.message);
  res.status(500).json({ error: err.message || 'Server error' });
});

app.listen(PORT, () => {
  console.log(`\n🚀 Server running on http://localhost:${PORT}`);
  console.log(`🔐 Admin: ${ADMIN_USERNAME}`);
  console.log(`📦 Database: sellers.db\n`);
});
                                            
