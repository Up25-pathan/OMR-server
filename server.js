require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs'); // ✅ Using bcryptjs for stability
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for Render/Neon
  }
});

// --- RAZORPAY INSTANCE ---
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// --- DATABASE INITIALIZATION ---
const initDB = async () => {
  try {
    console.log("🔄 Initializing Database...");

    // 🔴 DELETE THESE 3 LINES AFTER YOUR FIRST SUCCESSFUL SIGNUP!
    // This wipes the database to fix your current schema errors.
    await pool.query('DROP TABLE IF EXISTS licenses CASCADE');
    await pool.query('DROP TABLE IF EXISTS jobs CASCADE');
    await pool.query('DROP TABLE IF EXISTS users CASCADE');
    console.log("⚠️ Old tables dropped (Schema Reset)"); 
    // ---------------------------------------------------------

    // 1. Users Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        company VARCHAR(100),
        role VARCHAR(20) DEFAULT 'user', 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // 2. Licenses Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS licenses (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        tier VARCHAR(50),
        license_key VARCHAR(100) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. Jobs Table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS jobs (
        id SERIAL PRIMARY KEY,
        title VARCHAR(100) NOT NULL,
        department VARCHAR(100),
        location VARCHAR(100),
        type VARCHAR(50), 
        description TEXT,
        posted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ Database Tables Ready: Users, Licenses, Jobs");
  } catch (err) {
    console.error("❌ Database Init Error:", err);
  }
};
initDB();

// --- HELPER FUNCTIONS ---
const generateLicenseKey = () => {
  return 'OMR-' + crypto.randomBytes(4).toString('hex').toUpperCase() + 
         '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: "Access Denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid Token" });
    req.user = user;
    next();
  });
};

// ==================================================================
//                            API ROUTES
// ==================================================================

// ----------------------
// 1. AUTHENTICATION
// ----------------------

// SIGNUP
app.post('/api/auth/signup', async (req, res) => {
  const { name, email, password, company } = req.body;
  try {
    // Check if user exists
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    // Hash Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Admin Backdoor
    const role = company === 'OMR-ADMIN-2026' ? 'admin' : 'user';

    // Insert User
    const result = await pool.query(
      'INSERT INTO users (name, email, password, company, role) VALUES ($1, $2, $3, $4, $5) RETURNING id, name, email, role, company',
      [name, email, hashedPassword, company, role]
    );

    const user = result.rows[0];
    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET);

    res.json({ success: true, token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server Error during Signup" });
  }
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(400).json({ error: "User not found" });

    const user = result.rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass) return res.status(400).json({ error: "Invalid Password" });

    const token = jwt.sign({ id: user.id, role: user.role, email: user.email }, process.env.JWT_SECRET);

    res.json({ 
      success: true, 
      token, 
      user: { id: user.id, name: user.name, email: user.email, role: user.role, company: user.company } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server Error during Login" });
  }
});

// ----------------------
// 2. PAYMENT (Razorpay)
// ----------------------

app.post('/api/create-order', authenticateToken, async (req, res) => {
  const { tier } = req.body;
  const amount = tier === 'PRO' ? 149900 : 49900; // in paise

  try {
    const options = {
      amount: amount,
      currency: "INR",
      receipt: "order_rcptid_" + Date.now()
    };
    const order = await razorpay.orders.create(options);
    res.json({ 
      success: true, 
      order_id: order.id, 
      amount: order.amount, 
      key_id: process.env.RAZORPAY_KEY_ID 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Payment Gateway Failed" });
  }
});

app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, tier } = req.body;

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body.toString())
    .digest('hex');

  if (expectedSignature === razorpay_signature) {
    const licenseKey = generateLicenseKey();
    try {
      await pool.query(
        'INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)',
        [req.user.id, tier, licenseKey]
      );
      res.json({ success: true, license_key: licenseKey });
    } catch (dbErr) {
      res.status(500).json({ error: "License Generation Failed" });
    }
  } else {
    res.status(400).json({ success: false, error: "Invalid Signature" });
  }
});

// ----------------------
// 3. LICENSES
// ----------------------

app.get('/api/my-licenses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch licenses" });
  }
});

app.post('/api/admin/generate-key', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin access required" });

  const { email, tier } = req.body;
  const licenseKey = generateLicenseKey();

  try {
    const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "User not found" });

    await pool.query(
      'INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)',
      [userRes.rows[0].id, tier, licenseKey]
    );
    res.json({ success: true, license_key: licenseKey });
  } catch (err) {
    res.status(500).json({ error: "Database Error" });
  }
});

// ----------------------
// 4. CAREERS (Jobs)
// ----------------------

// Public: Get all jobs
app.get('/api/jobs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobs ORDER BY posted_at DESC');
    res.json({ success: true, jobs: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch jobs" });
  }
});

// Admin: Post Job
app.post('/api/admin/jobs', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });

  const { title, department, location, type, description } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO jobs (title, department, location, type, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, department, location, type, description]
    );
    res.json({ success: true, job: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Failed to post job" });
  }
});

// Admin: Delete Job
app.delete('/api/admin/jobs/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });

  try {
    await pool.query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true, message: "Job deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// --- SERVER START ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
