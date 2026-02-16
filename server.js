require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
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
    rejectUnauthorized: false
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
    
    // ⚠️ DISABLED DESTRUCTIVE DROP for safety
    // await pool.query('DROP TABLE IF EXISTS licenses CASCADE');
    // await pool.query('DROP TABLE IF EXISTS jobs CASCADE');
    // await pool.query('DROP TABLE IF EXISTS users CASCADE');
    
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
    const userCheck = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const role = company === 'OMR-ADMIN-2026' ? 'admin' : 'user';

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
// 2. ACTIVATE LICENSE (NEW)
// ----------------------
app.post('/api/activate', async (req, res) => {
    const { license_key, hardware_id, device_name } = req.body;
    
    try {
        const result = await pool.query(
            `SELECT l.*, u.email, u.name 
             FROM licenses l 
             JOIN users u ON l.user_id = u.id 
             WHERE l.license_key = $1`, 
            [license_key]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, error: "Invalid License Key" });
        }

        const license = result.rows[0];
        
        // Generate a standard JWT token for the desktop app
        const token = jwt.sign({ 
            key: license_key,
            email: license.email,
            tier: license.tier,
            exp: Math.floor(Date.now() / 1000) + (365 * 24 * 60 * 60) // 1 year expiry
        }, process.env.JWT_SECRET);

        res.json({ 
            success: true, 
            token: token,
            tier: license.tier 
        });

    } catch (err) {
        console.error("Activation Error:", err);
        res.status(500).json({ error: "Activation Server Error" });
    }
});

// ----------------------
// 3. AUTO-UPDATES
// ----------------------
app.get('/api/updates/:target/:arch/:current_version', async (req, res) => {
    const { target, arch, current_version } = req.params;
    
    const LATEST_VERSION = "0.2.0"; 
    const UPDATE_NOTES = "Performance improvements, new drilling module, and notifications system.";
    const PUB_DATE = new Date().toISOString(); 
    const BASE_URL = "https://github.com/Start-OT/EdgePredict-Desktop/releases/latest/download";
    const SIGNATURE_WIN64 = "REPLACE_WITH_CONTENT_FROM_NSIS_ZIP_SIG_FILE";

    if (current_version === LATEST_VERSION) {
        return res.status(204).send(); 
    }

    let url = "";
    let signature = "";
    
    if (target.includes("windows")) {
        url = `${BASE_URL}/EdgePredict_${LATEST_VERSION}_x64-setup.nsis.zip`;
        signature = SIGNATURE_WIN64;
    }

    res.json({
        version: LATEST_VERSION,
        notes: UPDATE_NOTES,
        pub_date: PUB_DATE,
        url: url,
        signature: signature
    });
});

// ----------------------
// 4. NOTIFICATIONS (NEW) ✅
// ----------------------
app.get('/api/notifications', async (req, res) => {
    // In a real app, you'd fetch this from a 'messages' table
    // For now, hardcode your announcements here!
    
    const notifications = [
        {
            id: 'welcome-msg',
            type: 'INFO',
            title: 'Welcome to EdgePredict v0.1',
            message: 'Thanks for using our simulation software. Check out the new Tools Library!',
            timestamp: new Date().toISOString()
        },
        {
            id: 'maintenance-alert',
            type: 'WARNING',
            title: 'Scheduled Maintenance',
            message: 'Server maintenance this Sunday at 2:00 AM UTC.',
            timestamp: new Date().toISOString()
        }
    ];

    res.json({ success: true, notifications });
});

// ----------------------
// 5. PAYMENT & LICENSES
// ----------------------
app.post('/api/create-order', authenticateToken, async (req, res) => {
  const { tier } = req.body;
  const amount = tier === 'PRO' ? 149900 : 49900; 
  try {
    const options = {
      amount: amount,
      currency: "INR",
      receipt: "order_rcptid_" + Date.now()
    };
    const order = await razorpay.orders.create(options);
    res.json({ success: true, order_id: order.id, amount: order.amount, key_id: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    res.status(500).json({ error: "Payment Gateway Failed" });
  }
});

app.post('/api/verify-payment', authenticateToken, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, tier } = req.body;
  const body = razorpay_order_id + "|" + razorpay_payment_id;
  const expectedSignature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest('hex');

  if (expectedSignature === razorpay_signature) {
    const licenseKey = generateLicenseKey();
    try {
      await pool.query('INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)', [req.user.id, tier, licenseKey]);
      res.json({ success: true, license_key: licenseKey });
    } catch (dbErr) {
      res.status(500).json({ error: "License Generation Failed" });
    }
  } else {
    res.status(400).json({ success: false, error: "Invalid Signature" });
  }
});

app.get('/api/my-licenses', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ success: true, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch licenses" });
  }
});

// ----------------------
// 6. JOBS (Careers)
// ----------------------
app.get('/api/jobs', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM jobs ORDER BY posted_at DESC');
    res.json({ success: true, jobs: result.rows });
  } catch (err) { res.status(500).json({ error: "Failed to post job" }); }
});

app.post('/api/admin/jobs', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
  const { title, department, location, type, description } = req.body;
  try {
    const result = await pool.query('INSERT INTO jobs (title, department, location, type, description) VALUES ($1, $2, $3, $4, $5) RETURNING *', [title, department, location, type, description]);
    res.json({ success: true, job: result.rows[0] });
  } catch (err) { res.status(500).json({ error: "Failed to post job" }); }
});

app.delete('/api/admin/jobs/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: "Admins only" });
    try {
        await pool.query('DELETE FROM jobs WHERE id = $1', [req.params.id]);
        res.json({ success: true, message: "Job deleted" });
    } catch (err) { res.status(500).json({ error: "Failed to delete job" }); }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
