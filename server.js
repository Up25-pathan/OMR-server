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

    // 4. Support Tickets Table (UPDATED ✅ - Added priority field)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS support_tickets (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100),
        category VARCHAR(50),
        subject VARCHAR(255),
        message TEXT,
        system_info TEXT,
        priority VARCHAR(20) DEFAULT 'medium',
        status VARCHAR(20) DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 5. Ticket Replies Table (NEW ✅ - For conversation history)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ticket_replies (
        id SERIAL PRIMARY KEY,
        ticket_id INTEGER REFERENCES support_tickets(id) ON DELETE CASCADE,
        sender_type VARCHAR(20) NOT NULL,
        message TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ Database Tables Ready: Users, Licenses, Jobs, Support Tickets, Ticket Replies");
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
// 2. ACTIVATE LICENSE
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
// 4. NOTIFICATIONS
// ----------------------
app.get('/api/notifications', async (req, res) => {
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
// 6. JOBS
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

// ----------------------
// 7. SUPPORT SYSTEM (UPDATED ✅)
// ----------------------

// Submit Ticket (From Desktop App) - Both endpoints for compatibility
const submitTicket = async (req, res) => {
    const { name, email, category, subject, message, system_info, priority } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO support_tickets (name, email, category, subject, message, system_info, priority, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at, status',
            [name, email, category, subject, message, system_info, priority || 'medium', 'OPEN']
        );
        res.json({ success: true, ticket_id: result.rows[0].id, created_at: result.rows[0].created_at, status: result.rows[0].status });
    } catch (err) {
        console.error('Ticket submission error:', err);
        res.status(500).json({ error: "Failed to submit ticket" });
    }
};

// Both endpoints (new and old for compatibility)
app.post('/api/support/tickets', submitTicket);
app.post('/api/support', submitTicket);

// Get All Tickets (For OMR Systems Website / Admin)
app.get('/api/admin/tickets', (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: "Access Denied - No token provided" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Token verification error:', err.message);
            return res.status(403).json({ error: "Invalid Token" });
        }
        
        if (user.role !== 'admin') {
            return res.status(403).json({ error: "Admins only" });
        }
        
        req.user = user;
        next();
    });
}, async (req, res) => {
    const status = req.query.status;
    try {
        let query = 'SELECT * FROM support_tickets';
        let params = [];
        
        if (status && status !== 'all') {
            query += ' WHERE UPPER(status) = $1';
            params.push(status.toUpperCase());
        }
        
        query += ' ORDER BY created_at DESC';
        const result = await pool.query(query, params);
        res.json({ success: true, tickets: result.rows });
    } catch (err) {
        console.error('Fetch tickets error:', err);
        res.status(500).json({ error: "Failed to fetch tickets" });
    }
});

// ✅ NEW: Get Single Ticket with Replies
app.get('/api/support/tickets/:id', (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: "Access Denied - No token provided" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Invalid Token" });
        }
        req.user = user;
        next();
    });
}, async (req, res) => {
    const ticketId = req.params.id;
    
    try {
        // Fetch ticket
        const ticketResult = await pool.query(
            'SELECT * FROM support_tickets WHERE id = $1',
            [ticketId]
        );
        
        if (ticketResult.rows.length === 0) {
            return res.status(404).json({ error: "Ticket not found" });
        }
        
        const ticket = ticketResult.rows[0];
        
        // Fetch all replies for this ticket
        const repliesResult = await pool.query(
            'SELECT id, sender_type, message, created_at FROM ticket_replies WHERE ticket_id = $1 ORDER BY created_at ASC',
            [ticketId]
        );
        
        res.json({ 
            success: true, 
            ticket: {
                ...ticket,
                replies: repliesResult.rows
            }
        });
    } catch (err) {
        console.error('Fetch ticket details error:', err);
        res.status(500).json({ error: "Failed to fetch ticket details" });
    }
});

// ✅ NEW: Add Reply to Ticket
app.post('/api/support/tickets/:id/reply', (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: "Access Denied - No token provided" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: "Invalid Token" });
        }
        req.user = user;
        next();
    });
}, async (req, res) => {
    const ticketId = req.params.id;
    const { message } = req.body;
    
    if (!message?.trim()) {
        return res.status(400).json({ error: "Message cannot be empty" });
    }
    
    try {
        // Check if ticket exists
        const ticketCheck = await pool.query('SELECT * FROM support_tickets WHERE id = $1', [ticketId]);
        if (ticketCheck.rows.length === 0) {
            return res.status(404).json({ error: "Ticket not found" });
        }
        
        // Determine sender type (admin or user)
        const senderType = req.user.role === 'admin' ? 'admin' : 'user';
        
        // Insert reply
        const result = await pool.query(
            'INSERT INTO ticket_replies (ticket_id, sender_type, message) VALUES ($1, $2, $3) RETURNING *',
            [ticketId, senderType, message]
        );
        
        res.json({ success: true, reply: result.rows[0] });
    } catch (err) {
        console.error('Add reply error:', err);
        res.status(500).json({ error: "Failed to add reply" });
    }
});

// ✅ NEW: Update Ticket Status (Admin only)
app.patch('/api/admin/tickets/:id/status', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: "Admins only" });
    }
    
    const ticketId = req.params.id;
    const { status } = req.body;
    
    const validStatuses = ['OPEN', 'IN_PROGRESS', 'RESOLVED', 'CLOSED'];
    if (!validStatuses.includes(status?.toUpperCase())) {
        return res.status(400).json({ error: "Invalid status" });
    }
    
    try {
        const result = await pool.query(
            'UPDATE support_tickets SET status = $1 WHERE id = $2 RETURNING *',
            [status.toUpperCase(), ticketId]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Ticket not found" });
        }
        
        res.json({ success: true, ticket: result.rows[0] });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Failed to update ticket status" });
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
