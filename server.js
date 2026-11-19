// server.js — OrderParts KE production backend
const dns = require('dns');
// Keep this line to prevent DNS issues on some networks
dns.setServers(['8.8.8.8', '8.8.4.4']);

require('dotenv').config();
const express   = require('express');
const mongoose  = require('mongoose');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const multer    = require('multer');
const cors      = require('cors');
const path      = require('path');
const fs        = require('fs');

const SEED = require('./seed');

const app    = express();
const PORT   = process.env.PORT || 3000;

//  SECURITY FIX: Read secrets from environment variables (Render/.env)
const MONGODB_URI = process.env.MONGODB_URI;
const SECRET      = process.env.JWT_SECRET || 'dev-secret-change-me';
const ADMIN_PASS  = process.env.ADMIN_PASSWORD || 'orderparts';

if (!MONGODB_URI) {
  console.error(' CRITICAL ERROR: MONGODB_URI is missing!');
  console.error(' If running locally, check your .env file.');
  console.error('If on Render, check your Environment Variables settings.');
  process.exit(1);
}

/* ---------- middleware ---------- */
// CORS: permissive by default (current behaviour). To lock it to your domain,
// set ALLOWED_ORIGINS in Render env vars, e.g.:
//   ALLOWED_ORIGINS=https://orderpartske.com,https://www.orderpartske.com
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

app.use(cors({
  origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true
}));
app.use(express.json({ limit: '25mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

/* ---------- Schemas ---------- */
const Product = mongoose.model('Product', new mongoose.Schema({
  id:            { type: Number, unique: true, index: true },
  name:          String,
  category:      String,
  description:   String,
  price:         Number,
  image:         String,
  images:        [String],
  badge:         String,
  stock:         Number,
  featured:      Boolean,
  fallbackImage: String
}, { timestamps: true }));

const Settings = mongoose.model('Settings', new mongoose.Schema({
  _key:  { type: String, default: 'main', unique: true },
  phone: { type: String, default: '254705976736' },
  email: { type: String, default: 'info@orderpartske.com' },
  ship:  { type: Number, default: 500 },
  cur:   { type: String, default: 'KES' },
  logo:  { type: String, default: 'img/logo.jpeg' }
}));

const Admin = mongoose.model('Admin', new mongoose.Schema({
  _key:     { type: String, default: 'main', unique: true },
  passHash: String
}));

/* ---------- Seeding Functions ---------- */
async function ensureAdmin() {
  const existing = await Admin.findOne({ _key: 'main' });
  if (!existing) {
    await Admin.create({ _key: 'main', passHash: bcrypt.hashSync(ADMIN_PASS, 10) });
    console.log('👤 Admin created (password:', ADMIN_PASS + ')');
  }
}

async function ensureSettings() {
  const existing = await Settings.findOne({ _key: 'main' });
  if (!existing) await Settings.create({ _key: 'main' });
}

async function ensureProducts() {
  const count = await Product.estimatedDocumentCount();
  if (count === 0) {
    await Product.insertMany(SEED);
    console.log(` Seeded ${SEED.length} default products`);
  }
}

/* ---------- Auth middleware ---------- */
function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/, '');
  try {
    jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
}

/* ---------- Upload ---------- */
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, 'uploads'),
  filename:    (_, file, cb) => {
    const safe = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, safe + path.extname(file.originalname).toLowerCase());
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) =>
    /^image\//.test(file.mimetype) ? cb(null, true) : cb(new Error('Only images allowed'))
});

/* ============================================================
   AUTH
   ============================================================ */
app.post('/api/login', async (req, res) => {
  const { password } = req.body || {};
  if (!password) return res.status(400).json({ error: 'Password required' });

  const admin = await Admin.findOne({ _key: 'main' });
  if (!admin || !bcrypt.compareSync(password, admin.passHash)) {
    return res.status(401).json({ error: 'Wrong password' });
  }
  const token = jwt.sign({ role: 'admin' }, SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.post('/api/change-password', requireAdmin, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });

  const admin = await Admin.findOne({ _key: 'main' });
  if (!bcrypt.compareSync(currentPassword, admin.passHash)) {
    return res.status(401).json({ error: 'Current password is wrong' });
  }
  admin.passHash = bcrypt.hashSync(newPassword, 10);
  await admin.save();
  res.json({ ok: true });
});

/* ============================================================
   SETTINGS
   ============================================================ */
app.get('/api/settings', async (_req, res) => {
  let s = await Settings.findOne({ _key: 'main' }).lean();
  if (!s) s = { phone: '254705976736', email: 'info@orderpartske.com', ship: 500, cur: 'KES', logo: 'img/logo.jpeg' };
  delete s._id; delete s._key; delete s.__v;
  res.json(s);
});

app.put('/api/settings', requireAdmin, async (req, res) => {
  const allowed = ['phone', 'email', 'ship', 'cur', 'logo'];
  const patch = {};
  for (const k of allowed) if (req.body[k] !== undefined) patch[k] = req.body[k];

  const s = await Settings.findOneAndUpdate(
    { _key: 'main' },
    { $set: patch },
    { new: true, upsert: true }
  ).lean();
  delete s._id; delete s._key; delete s.__v;
  res.json(s);
});

/* ============================================================
   PRODUCTS
   ============================================================ */
app.get('/api/products', async (_req, res) => {
  const rows = await Product.find().sort({ id: 1 }).lean();
  res.json(rows.map(r => {
    delete r._id; delete r.__v; delete r.createdAt; delete r.updatedAt;
    return r;
  }));
});

app.post('/api/products', requireAdmin, async (req, res) => {
  const last = await Product.findOne().sort({ id: -1 }).select('id').lean();
  const nextId = (last?.id || 0) + 1;

  const product = await Product.create({ ...req.body, id: nextId });
  const out = product.toObject();
  delete out._id; delete out.__v; delete out.createdAt; delete out.updatedAt;
  res.status(201).json(out);
});

app.put('/api/products/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ error: 'Invalid product id' });

  const body = { ...req.body };
  delete body._id; delete body.__v; delete body.id;

  const updated = await Product.findOneAndUpdate({ id }, body, { new: true }).lean();
  if (!updated) return res.status(404).json({ error: 'Product not found' });
  delete updated._id; delete updated.__v; delete updated.createdAt; delete updated.updatedAt;
  res.json(updated);
});

//  HARDENED DELETE — returns JSON, distinguishes 400 / 404 / 200
app.delete('/api/products/:id', requireAdmin, async (req, res) => {
  const raw = req.params.id;
  const id  = Number(raw);

  if (!Number.isFinite(id)) {
    console.warn('DELETE /api/products -> invalid id:', raw);
    return res.status(400).json({ error: 'Invalid product id', id: raw });
  }

  try {
    const result = await Product.deleteOne({ id });

    if (result.deletedCount === 0) {
      console.warn('DELETE /api/products -> not found:', id);
      return res.status(404).json({ error: 'Product not found', id });
    }

    console.log('🗑️  Deleted product id', id);
    res.json({ ok: true, deleted: id });
  } catch (err) {
    console.error('DELETE /api/products -> error:', err);
    res.status(500).json({ error: 'Delete failed', detail: err.message });
  }
});

app.post('/api/products/bulk', requireAdmin, async (req, res) => {
  const products = (req.body && req.body.products) || [];
  if (!Array.isArray(products) || !products.length) {
    return res.status(400).json({ error: 'products array required' });
  }
  await Product.deleteMany({});
  const docs = products.map((p, i) => ({ ...p, id: p.id || (i + 1) }));
  await Product.insertMany(docs);
  res.json({ ok: true, count: docs.length });
});

app.post('/api/products/reset', requireAdmin, async (_req, res) => {
  await Product.deleteMany({});
  await Product.insertMany(SEED);
  res.json({ ok: true, count: SEED.length });
});

/* ============================================================
   UPLOAD
   ============================================================ */
app.post('/api/upload', requireAdmin, upload.array('files', 8), (req, res) => {
  if (!req.files || !req.files.length) return res.status(400).json({ error: 'No files' });
  res.json({ urls: req.files.map(f => '/uploads/' + f.filename) });
});

/* ============================================================
   Health + SPA fallback
   ============================================================ */
app.get('/healthz', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('*', (req, res, next) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/uploads/')) return next();
  res.sendFile(path.join(__dirname, 'public', 'index.html'), err => err && next());
});

/* ============================================================
   Boot Sequence
   ============================================================ */
async function startServer() {
  try {
    console.log(' Attempting to connect to MongoDB...');

    await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      autoSelectFamily: false
    });

    console.log(' MongoDB connected');

    await ensureAdmin();
    await ensureSettings();
    await ensureProducts();

    app.listen(PORT, () => console.log(` Server running on port ${PORT}`));

  } catch (err) {
    console.error('\n CONNECTION FAILED!');
    console.error('Error Type:', err.name);
    console.error('Message:', err.message);
    process.exit(1);
  }
}

startServer();
