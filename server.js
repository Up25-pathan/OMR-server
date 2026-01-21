// server.js - Production Ready (PostgreSQL + Neon)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg'); // <--- Using Postgres
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken'); 
const crypto = require('crypto');
const Razorpay = require('razorpay');
const bcrypt = require('bcryptjs'); 

const app = express();

// --- 1. CONFIGURATION ---
app.use(cors()); 
app.use(express.json());

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "fallback_secret";
const ADMIN_SECRET_CODE = "OMR-ADMIN-2026"; 

// Razorpay Config
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID, 
  key_secret: process.env.RAZORPAY_KEY_SECRET,
});

// --- 2. DATABASE CONNECTION (NEON) ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for Neon
});

// Test Connection on Startup
pool.connect((err, client, release) => {
  if (err) return console.error('❌ Cloud DB Connection Failed:', err.stack);
  console.log('✅ Connected to Neon Cloud Database (Postgres)');
  release();
});

// Initialize Tables (Postgres Syntax)
const initDB = async () => {
  try {
    // Users Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name VARCHAR(255),
        company VARCHAR(255),
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Licenses Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id VARCHAR(255) PRIMARY KEY,
        license_key VARCHAR(255) UNIQUE NOT NULL,
        tier VARCHAR(50),
        status VARCHAR(50) DEFAULT 'ACTIVE',
        hardware_id VARCHAR(255),
        device_name VARCHAR(255),
        email VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    console.log("✅ Tables Initialized");
  } catch (err) {
    console.error("Error initializing DB:", err);
  }
};

initDB(); // Run immediately

// Helper: Generate Key
const generateKey = (tier) => {
  const rand = () => crypto.randomBytes(2).toString('hex').toUpperCase();
  return `${tier}-${rand()}-${rand()}-${rand()}`;
};

// --- 3. MIDDLEWARE ---

const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if(!authHeader) return res.status(401).json({error: "No token"});
  
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e) {
    res.status(403).json({error: "Invalid Token"});
  }
};

const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({error: "Access Denied: Admins Only"});
  }
  next();
};

// --- 4. AUTH ROUTES ---

app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, company } = req.body;
  if(!email || !password) return res.status(400).json({error: "Missing fields"});

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    const role = (company === ADMIN_SECRET_CODE) ? 'admin' : 'user'; 

    await pool.query(
      `INSERT INTO users (id, email, password_hash, name, company, role) VALUES ($1, $2, $3, $4, $5, $6)`,
      [userId, email, hashedPassword, name, company, role]
    );

    const token = jwt.sign({ id: userId, email, role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { name, email, role, company } });

  } catch (e) {
    if (e.code === '23505') return res.status(400).json({ error: "Email already exists" });
    console.error(e);
    res.status(500).json({ error: "Server Error" });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [email]);
    const user = result.rows[0];

    if (!user) return res.status(404).json({ error: "User not found" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: "Incorrect password" });

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { name: user.name, email: user.email, role: user.role, company: user.company } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login Error" });
  }
});

app.get('/api/my-licenses', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM licenses WHERE email = $1`, [req.user.email]);
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: "DB Error" });
  }
});

// --- 5. ADMIN ROUTES ---

app.post('/api/admin/generate-key', verifyToken, verifyAdmin, async (req, res) => {
  const { tier, email } = req.body; 
  const newKey = generateKey(tier || 'PRO');
  const id = uuidv4();
  
  try {
    await pool.query(
      `INSERT INTO licenses (id, license_key, tier, email, status) VALUES ($1, $2, $3, $4, 'ACTIVE')`,
      [id, newKey, tier, email]
    );
    console.log(`👑 ADMIN GENERATED: ${tier} Key for ${email}`);
    res.json({ success: true, license_key: newKey });
  } catch (err) {
    res.status(500).json({ error: "DB Error" });
  }
});

// --- 6. PAYMENT ROUTES ---

app.post('/api/create-order', verifyToken, async (req, res) => {
  const { tier } = req.body;
  let amount = (tier === 'BASIC') ? 49900 : (tier === 'PRO') ? 149900 : 0;
  if (!amount) return res.status(400).json({ error: 'Invalid Tier' });

  try {
    const options = {
      amount: amount, 
      currency: "INR",
      receipt: "order_" + uuidv4().substring(0,8),
    };
    const order = await razorpay.orders.create(options);
    res.json({ success: true, order_id: order.id, amount: amount, key_id: process.env.RAZORPAY_KEY_ID });
  } catch (error) {
    res.status(500).json({ error: "Razorpay Error" });
  }
});

app.post('/api/verify-payment', verifyToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, tier, email } = req.body;
  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

  if (expectedSignature === razorpay_signature) {
    const newKey = generateKey(tier);
    const id = uuidv4();
    try {
      await pool.query(
        `INSERT INTO licenses (id, license_key, tier, email) VALUES ($1, $2, $3, $4)`,
        [id, newKey, tier, email]
      );
      res.json({ success: true, license_key: newKey });
    } catch (err) { res.status(500).json({ error: "DB Error" }); }
  } else {
    res.status(400).json({ success: false, error: "Invalid Signature" });
  }
});

// --- 7. DESKTOP ACTIVATION ---

app.post('/api/activate', async (req, res) => {
  const { license_key, hardware_id, device_name } = req.body;
  if (!license_key || !hardware_id) return res.status(400).json({ error: "Missing data" });

  try {
    const result = await pool.query(`SELECT * FROM licenses WHERE license_key = $1`, [license_key]);
    const row = result.rows[0];

    if (!row) return res.status(404).json({ error: "Invalid License Key" });
    if (row.hardware_id && row.hardware_id !== hardware_id) {
      return res.status(403).json({ error: "License locked to another machine", locked_to: row.device_name });
    }

    if (!row.hardware_id) {
      await pool.query(`UPDATE licenses SET hardware_id = $1, device_name = $2 WHERE id = $3`, [hardware_id, device_name, row.id]);
    }

    const token = jwt.sign({ key: row.license_key, tier: row.tier, email: row.email, hwid: hardware_id }, JWT_SECRET, { expiresIn: '365d' });
    res.json({ success: true, token, tier: row.tier });
  } catch (err) {
    res.status(500).json({ error: "Activation Error" });
  }
});

// Start Server
app.listen(PORT, () => {
  console.log(`🚀 OMR Cloud Server running on port ${PORT}`);
});