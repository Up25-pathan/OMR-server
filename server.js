require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// --- DATABASE CONNECTION ---
// Connects to your Neon/Postgres Cloud DB
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false // Required for secure cloud connections (Render/Neon)
  }
});

// --- RAZORPAY INSTANCE ---
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// --- INITIALIZE TABLES ---
const initDB = async () => {
  try {
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
        user_id INTEGER REFERENCES users(id),
        tier VARCHAR(50),
        license_key VARCHAR(100) UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 3. Jobs Table (For Careers Page)
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

    console.log("✅ Database Tables Initialized: Users, Licenses, Jobs");
  } catch (err) {
    console.error("❌ Database Initialization Error:", err);
  }
};
initDB();

// --- HELPER: GENERATE LICENSE KEY ---
const generateLicenseKey = () => {
  return 'OMR-' + crypto.randomBytes(4).toString('hex').toUpperCase() + 
         '-' + crypto.randomBytes(4).toString('hex').toUpperCase();
};

// --- MIDDLEWARE: AUTHENTICATE TOKEN ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.status(401).json({ error: "Access Denied. No token provided." });

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

    // Check for Admin Code (Backdoor for testing)
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
    res.status(500).json({ error: "Server Error" });
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

    // Return user info (excluding password)
    res.json({ 
      success: true, 
      token, 
      user: { id: user.id, name: user.name, email: user.email, role: user.role, company: user.company } 
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server Error" });
  }
});

// ----------------------
// 2. PAYMENT & ORDERS (Razorpay)
// ----------------------

// CREATE ORDER
app.post('/api/create-order', authenticateToken, async (req, res) => {
  const { tier } = req.body;
  const amount = tier === 'PRO' ? 149900 : 49900; // Amount in paise (1499 INR or 499 INR)

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
    res.status(500).json({ error: "Payment Gateway Error" });
  }
});

// VERIFY PAYMENT & GENERATE LICENSE
app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, tier } = req.body;

  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body.toString())
    .digest('hex');

  if (expectedSignature === razorpay_signature) {
    // Payment Successful -> Generate License
    const licenseKey = generateLicenseKey();
    
    try {
      await pool.query(
        'INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)',
        [req.user.id, tier, licenseKey]
      );
      res.json({ success: true, license_key: licenseKey });
    } catch (dbErr) {
      console.error(dbErr);
      res.status(500).json({ error: "Payment verified but license generation failed." });
    }
  } else {
    res.status(400).json({ success: false, error: "Invalid Signature" });
  }
});

// ----------------------
// 3. LICENSES
// ----------------------

// GET MY LICENSES
app.get('/api/my-licenses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch licenses" });
  }
});

// ADMIN: GENERATE KEY MANUALLY
app.post('/api/admin/generate-key', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin access required" });

  const { email, tier } = req.body;
  const licenseKey = generateLicenseKey();

  try {
    // Find user ID by email
    const userRes = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
    
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: "User email not found. User must register first." });
    }

    const userId = userRes.rows[0].id;
    
    await pool.query(
      'INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)',
      [userId, tier, licenseKey]
    );

    res.json({ success: true, license_key: licenseKey });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database Error" });
  }
});

// ----------------------
// 4. JOBS / CAREERS (New!)
// ----------------------

// PUBLIC: GET ALL JOBS
app.get('/api/jobs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobs ORDER BY posted_at DESC');
    res.json({ success: true, jobs: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch jobs" });
  }
});

// ADMIN: POST A JOB
app.post('/api/admin/jobs', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Admins only." });
  }

  const { title, department, location, type, description } = req.body;

  try {
    const result = await pool.query(
      'INSERT INTO jobs (title, department, location, type, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [title, department, location, type, description]
    );
    res.json({ success: true, job: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to post job" });
  }
});

// ADMIN: DELETE A JOB
app.delete('/api/admin/jobs/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only." });

  try {
    await pool.query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
    res.json({ success: true, message: "Job deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// --- START SERVER ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`OMR Cloud Server running on port ${PORT}`));
