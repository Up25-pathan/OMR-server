require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const PDFDocument = require('pdfkit');
const fs = require('fs');
const path = require('path');

const app = express();

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json());

// --- EMAIL CONFIGURATION (Nodemailer + Gmail) ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Test email connection
transporter.verify((error, success) => {
  if (error) {
    console.error('❌ Email service error:', error.message);
  } else {
    console.log('✅ Email service ready');
  }
});

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
        reset_token VARCHAR(255),
        reset_token_expires TIMESTAMP, 
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Add reset_token columns if they don't exist
    try {
      await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS reset_token VARCHAR(255),
        ADD COLUMN IF NOT EXISTS reset_token_expires TIMESTAMP;
      `);
      console.log("✅ Reset token columns added to users table");
    } catch (migErr) {
      // Columns may already exist, ignore
    }

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
        status VARCHAR(20) DEFAULT 'OPEN',
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

    // 6. MIGRATION: Add priority column if it doesn't exist
    try {
      await pool.query(`
        ALTER TABLE support_tickets 
        ADD COLUMN IF NOT EXISTS priority VARCHAR(20) DEFAULT 'medium';
      `);
      console.log("✅ Priority column added to support_tickets");
    } catch (migErr) {
      // Column may already exist, ignore
    }

    // 7. Newsroom Table (NEW ✅ - For blog articles)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS newsroom (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        category VARCHAR(100) NOT NULL,
        summary TEXT NOT NULL,
        content TEXT NOT NULL,
        read_time INT NOT NULL DEFAULT 5,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 8. Invoices Table (NEW ✅ - For billing & invoices)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS invoices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        order_id VARCHAR(100),
        payment_id VARCHAR(100),
        tier VARCHAR(50),
        amount DECIMAL(10, 2),
        currency VARCHAR(10) DEFAULT 'INR',
        status VARCHAR(20) DEFAULT 'completed',
        invoice_number VARCHAR(50) UNIQUE,
        pdf_path VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
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
    // Token with 30 day expiration
    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

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

    // Token with 30 day expiration
    const token = jwt.sign(
      { id: user.id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

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

    // Calculate amount based on tier for invoice
    const amount = tier === 'PRO' ? 1499.00 : 499.00; // Assuming this is correct without decimal for INR
    const invoiceNumber = `INV-${Date.now()}`;
    const invoiceFileName = `${invoiceNumber}.pdf`;
    const invoiceDir = path.join(__dirname, 'invoices');
    const invoicePath = path.join(invoiceDir, invoiceFileName);

    try {
      // 1. Ensure invoices directory exists
      if (!fs.existsSync(invoiceDir)) {
        fs.mkdirSync(invoiceDir, { recursive: true });
      }

      // 2. Generate PDF using PDFKit
      const doc = new PDFDocument({ margin: 50 });
      const stream = fs.createWriteStream(invoicePath);
      doc.pipe(stream);

      // --- PDF Content ---
      // Header
      doc.fontSize(20).text('OMR Systems', { align: 'right' });
      doc.fontSize(10).text('123 Innovation Drive', { align: 'right' });
      doc.text('Tech City, TC 12345', { align: 'right' });
      doc.moveDown();

      // Title
      doc.fontSize(24).text('INVOICE', { align: 'left' });
      doc.moveDown();

      // Invoice Details
      doc.fontSize(12)
        .text(`Invoice Number: ${invoiceNumber}`)
        .text(`Date: ${new Date().toLocaleDateString()}`)
        .text(`Order ID: ${razorpay_order_id}`)
        .text(`Payment ID: ${razorpay_payment_id}`);
      doc.moveDown();

      // Bill To
      doc.text(`Bill To:`).moveDown(0.5);
      doc.text(`User ID: ${req.user.id}`);
      doc.text(`Email: ${req.user.email}`);
      doc.moveDown();

      // Line Items Table (Simple Boxed Text for now)
      doc.rect(50, doc.y, 500, 20).fillAndStroke('#eeeeee', '#cccccc');
      doc.fillColor('black').text('Description', 60, doc.y + 5);
      doc.text('Amount', 450, doc.y, { width: 90, align: 'right' });
      doc.moveDown(2);

      // Item 1
      const itemY = doc.y;
      doc.text(`EdgePredict License - ${tier} Tier`, 60, itemY);
      doc.text(`INR ${amount.toFixed(2)}`, 450, itemY, { width: 90, align: 'right' });
      doc.moveDown();

      // Total
      doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
      doc.moveDown(0.5);
      doc.fontSize(14).text('Total Paid:', 350, doc.y);
      doc.text(`INR ${amount.toFixed(2)}`, 450, doc.y, { width: 90, align: 'right' });
      doc.moveDown(2);

      // License Key Note
      doc.fontSize(12).fillColor('green').text(`Your License Key: ${licenseKey}`, { align: 'center' });
      doc.moveDown();

      doc.fillColor('black').fontSize(10).text('Thank you for your business!', { align: 'center', align: 'center' });

      doc.end();

      // Wait for file creation to resolve
      await new Promise((resolve, reject) => {
        stream.on('finish', resolve);
        stream.on('error', reject);
      });

      // 3. Database Updates
      await pool.query('INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3)', [req.user.id, tier, licenseKey]);

      await pool.query(
        'INSERT INTO invoices (user_id, order_id, payment_id, tier, amount, invoice_number, pdf_path) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [req.user.id, razorpay_order_id, razorpay_payment_id, tier, amount, invoiceNumber, invoicePath]
      );

      res.json({ success: true, license_key: licenseKey });
    } catch (dbErr) {
      console.error("Invoice or License Generation Error:", dbErr);
      res.status(500).json({ error: "Processing completed with error: " + dbErr.message });
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

// ✅ NEW: Fetch user invoices
app.get('/api/my-invoices', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM invoices WHERE user_id = $1 ORDER BY created_at DESC', [req.user.id]);
    res.json({ success: true, invoices: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch invoices" });
  }
});

// ✅ NEW: Download specific invoice PDF
app.get('/api/invoices/:id/download', authenticateToken, async (req, res) => {
  const invoiceId = req.params.id;
  try {
    const result = await pool.query('SELECT * FROM invoices WHERE id = $1 AND user_id = $2', [invoiceId, req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Invoice not found or unauthorized" });
    }

    const invoice = result.rows[0];
    const filePath = invoice.pdf_path;

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Invoice file missing on server" });
    }

    res.download(filePath, invoice.invoice_number + '.pdf', (err) => {
      if (err) {
        console.error("Download Error:", err);
      }
    });

  } catch (err) {
    res.status(500).json({ error: "Failed to process download" });
  }
});

// ✅ NEW: Admin Generate License Directly (without payment)
app.post('/api/admin/generate-license', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: "Admins only" });
  }

  const { email, tier } = req.body;

  if (!email || !tier) {
    return res.status(400).json({ error: "Email and tier are required" });
  }

  try {
    // Find or create user with the provided email
    let userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    let userId;

    if (userResult.rows.length === 0) {
      // Create new user with this email (user won't have a password, admin-generated)
      const tempPassword = crypto.randomBytes(16).toString('hex');
      const hashedPassword = await bcrypt.hash(tempPassword, 10);
      const createResult = await pool.query(
        'INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, $4) RETURNING id',
        [email.split('@')[0], email, hashedPassword, 'user']
      );
      userId = createResult.rows[0].id;
      console.log(`✅ Created new user for email: ${email}`);
    } else {
      userId = userResult.rows[0].id;
      console.log(`✅ Using existing user for email: ${email}`);
    }

    // Generate license key
    const licenseKey = generateLicenseKey();

    // Create license
    const result = await pool.query(
      'INSERT INTO licenses (user_id, tier, license_key) VALUES ($1, $2, $3) RETURNING *',
      [userId, tier, licenseKey]
    );

    res.json({
      success: true,
      license_key: licenseKey,
      tier: tier,
      email: email,
      message: `License generated successfully for ${email}`
    });
  } catch (err) {
    console.error('Admin license generation error:', err.message);
    res.status(500).json({ error: "Failed to generate license: " + err.message });
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
    // Try with priority column first
    let result;
    try {
      result = await pool.query(
        'INSERT INTO support_tickets (name, email, category, subject, message, system_info, priority, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id, created_at, status',
        [name, email, category, subject, message, system_info, priority || 'medium', 'OPEN']
      );
    } catch (columnErr) {
      // If priority column doesn't exist, insert without it
      if (columnErr.code === '42703') {
        console.log('Priority column not found, inserting without it');
        result = await pool.query(
          'INSERT INTO support_tickets (name, email, category, subject, message, system_info, status) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, created_at, status',
          [name, email, category, subject, message, system_info, 'OPEN']
        );
      } else {
        throw columnErr;
      }
    }
    res.json({ success: true, ticket_id: result.rows[0].id, created_at: result.rows[0].created_at, status: result.rows[0].status });
  } catch (err) {
    console.error('Ticket submission error:', err.message);
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
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: "Token Expired - Please login again" });
      }
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
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: "Token Expired - Please login again" });
      }
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
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: "Token Expired - Please login again" });
      }
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
app.patch('/api/admin/tickets/:id/status', (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "Access Denied - No token provided" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: "Token Expired - Please login again" });
      }
      return res.status(403).json({ error: "Invalid Token" });
    }

    if (user.role !== 'admin') {
      return res.status(403).json({ error: "Admins only" });
    }

    req.user = user;
    next();
  });
}, async (req, res) => {
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
    console.error('Update status error:', err);
    res.status(500).json({ error: "Failed to update ticket status" });
  }
});

// ============================================
// NEWSROOM API ENDPOINTS
// ============================================

// 1. CREATE NEW ARTICLE (Admin Only)
app.post('/api/newsroom', authenticateToken, async (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  const { title, category, summary, content, readTime } = req.body;

  if (!title || !category || !summary || !content || !readTime) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO newsroom (title, category, summary, content, read_time, created_at, updated_at)
       VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
       RETURNING *`,
      [title, category, summary, content, readTime]
    );

    const article = result.rows[0];
    const date = new Date(article.created_at).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });

    res.json({
      success: true,
      article: {
        ...article,
        date,
        readTime: `${article.read_time} min`
      }
    });
  } catch (err) {
    console.error('Error creating article:', err);
    res.status(500).json({ success: false, error: 'Failed to create article' });
  }
});

// 2. GET ALL ARTICLES (Public)
app.get('/api/newsroom', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title, category, summary, content, read_time, created_at, updated_at 
       FROM newsroom 
       ORDER BY created_at DESC`
    );

    const articles = result.rows.map(article => ({
      ...article,
      date: new Date(article.created_at).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
      }),
      readTime: `${article.read_time} min`
    }));

    res.json({ success: true, articles });
  } catch (err) {
    console.error('Error fetching articles:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch articles' });
  }
});

// 3. GET SINGLE ARTICLE (Public)
app.get('/api/newsroom/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query(
      `SELECT id, title, category, summary, content, read_time, created_at 
       FROM newsroom 
       WHERE id = $1`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Article not found' });
    }

    const article = result.rows[0];
    const date = new Date(article.created_at).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });

    res.json({
      success: true,
      article: {
        ...article,
        date,
        readTime: `${article.read_time} min`
      }
    });
  } catch (err) {
    console.error('Error fetching article:', err);
    res.status(500).json({ success: false, error: 'Failed to fetch article' });
  }
});

// 4. UPDATE ARTICLE (Admin Only)
app.put('/api/newsroom/:id', authenticateToken, async (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  const { id } = req.params;
  const { title, category, summary, content, readTime } = req.body;

  try {
    const result = await pool.query(
      `UPDATE newsroom 
       SET title = COALESCE($1, title),
           category = COALESCE($2, category),
           summary = COALESCE($3, summary),
           content = COALESCE($4, content),
           read_time = COALESCE($5, read_time),
           updated_at = NOW()
       WHERE id = $6
       RETURNING *`,
      [title, category, summary, content, readTime, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Article not found' });
    }

    const article = result.rows[0];
    res.json({ success: true, article });
  } catch (err) {
    console.error('Error updating article:', err);
    res.status(500).json({ success: false, error: 'Failed to update article' });
  }
});

// 5. DELETE ARTICLE (Admin Only)
app.delete('/api/newsroom/:id', authenticateToken, async (req, res) => {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ success: false, error: 'Admin access required' });
  }

  const { id } = req.params;

  try {
    const result = await pool.query(
      `DELETE FROM newsroom WHERE id = $1 RETURNING id`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Article not found' });
    }

    res.json({ success: true, message: 'Article deleted' });
  } catch (err) {
    console.error('Error deleting article:', err);
    res.status(500).json({ success: false, error: 'Failed to delete article' });
  }
});

// FORGOT PASSWORD
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (user.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'User not found.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = await bcrypt.hash(resetToken, 10);
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      'UPDATE users SET reset_token = $1, reset_token_expires = $2 WHERE email = $3',
      [hashedToken, expiresAt, email]
    );

    const resetLink = `https://omr-systems.com/reset-password/${resetToken}`;

    // Send email via Nodemailer + Gmail
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'OMR Systems - Password Reset Request',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333;">Password Reset Request</h2>
          <p>Hello,</p>
          <p>You requested to reset your password for your OMR Systems account. Click the button below to reset your password. This link is valid for <strong>1 hour</strong>.</p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" style="background-color: #FF6B35; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Reset Password</a>
          </div>
          <p>Or copy and paste this link in your browser:</p>
          <p style="background-color: #f4f4f4; padding: 10px; word-break: break-all;">${resetLink}</p>
          <p style="color: #666; font-size: 12px;">If you did not request a password reset, please ignore this email or contact support.</p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
          <p style="color: #999; font-size: 12px;">© 2026 OMR Systems. All rights reserved.</p>
        </div>
      `
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Password reset email sent to ${email}`);

    res.json({
      success: true,
      message: 'Password reset link sent to your email. Please check your inbox.',
    });
  } catch (err) {
    console.error('Forgot password error:', err);
    res.status(500).json({ success: false, error: 'Failed to send reset email. Please try again.' });
  }
});

// RESET PASSWORD
app.post('/api/auth/reset-password/:token', async (req, res) => {
  const { token } = req.params;
  const { password } = req.body;
  try {
    // Find user with valid reset token
    const users = await pool.query('SELECT * FROM users WHERE reset_token IS NOT NULL AND reset_token_expires > NOW()');

    if (users.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid or expired token.' });
    }

    // Find the matching user by comparing tokens
    let validUser = null;
    for (const user of users.rows) {
      const isValid = await bcrypt.compare(token, user.reset_token);
      if (isValid) {
        validUser = user;
        break;
      }
    }

    if (!validUser) {
      return res.status(400).json({ success: false, error: 'Invalid token.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'UPDATE users SET password = $1, reset_token = NULL, reset_token_expires = NULL WHERE id = $2',
      [hashedPassword, validUser.id]
    );

    res.json({ success: true, message: 'Password reset successfully.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: 'Internal server error.' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
