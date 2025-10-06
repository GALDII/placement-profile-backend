const express = require('express');
const mysql = require('mysql2/promise');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const cors = require('cors');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// --- GOOGLE AUTH CLIENT SETUP ---
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// --- DATABASE & CLOUDINARY CONFIGURATION ---
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
};
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});


// --- NEW: FUNCTION TO TEST CONNECTIONS ON STARTUP ---
async function testConnections() {
  // Test Google Cloud SQL Connection
  try {
    const connection = await mysql.createConnection(dbConfig);
    await connection.end();
    console.log('✅ Google Cloud SQL connection successful!');
  } catch (error) {
    console.error('❌ Google Cloud SQL connection failed:', error.message);
    console.log('   -> Tip: Check if your IP is authorized in GCP and if .env credentials are correct.');
  }

  // Test Cloudinary Connection
  try {
    const cloudinaryCheck = await cloudinary.api.ping();
    if (cloudinaryCheck.status === 'ok') {
      console.log('✅ Cloudinary connection successful!');
    } else {
      throw new Error('Cloudinary ping did not return "ok".');
    }
  } catch (error) {
    console.error('❌ Cloudinary connection failed:', error.message);
    console.log('   -> Tip: Check your Cloudinary credentials in the .env file.');
  }
}


// --- CORE AUTHENTICATION MIDDLEWARE ---
async function verifyToken(req, res, next) {
    // ... (existing verifyToken code is correct, no changes needed)
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).send('Unauthorized: No token provided');
    }
    const idToken = authHeader.split('Bearer ')[1];
    try {
        const ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT role FROM students WHERE email = ?', [payload.email]);
        await connection.end();
        req.user = {
            email: payload.email,
            name: payload.name,
            picture: payload.picture,
            role: rows.length > 0 ? rows[0].role : 'student' 
        };
        next();
    } catch (error) {
        console.error("Token verification or role fetch failed:", error);
        res.status(403).send('Unauthorized: Invalid token');
    }
}

// --- ADMIN-ONLY MIDDLEWARE ---
const isAdmin = (req, res, next) => {
    // ... (existing isAdmin code is correct, no changes needed)
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send('Forbidden: This resource requires admin privileges.');
    }
};

const storage = multer.memoryStorage();
const upload = multer({ storage });

// ===============================================
//         PUBLIC & USER API ENDPOINTS
// ===============================================

// NEW - Public endpoint for the homepage. No token required.
app.get('/api/public/profiles', async (req, res) => {
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT id, name, specialization, skills, github, linkedin, portfolio, photo_url FROM students ORDER BY name');
        await connection.end();
        res.json(rows);
    } catch (error) {
        console.error("Public profile fetch error:", error);
        res.status(500).json([]);
    }
});

// GET the logged-in user's own profile (protected)
app.get('/api/profiles/me', verifyToken, async (req, res) => {
    // ... (existing code is correct)
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM students WHERE email = ?', [req.user.email]);
        await connection.end();
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(404).json({ message: 'Profile not found.', user: req.user });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch your profile' });
    }
});

// UPDATE the logged-in user's own profile (protected)
app.put('/api/profiles/me', verifyToken, upload.single('photo'), async (req, res) => {
    // ... (existing code is correct)
    const { name, specialization, skills, github, linkedin, portfolio } = req.body;
    let photo_url = req.body.existing_photo_url;
    try {
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "student_profiles" });
            photo_url = result.secure_url;
        }
        const connection = await mysql.createConnection(dbConfig);
        const sql = `
            INSERT INTO students (email, name, specialization, skills, github, linkedin, portfolio, photo_url, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            name=VALUES(name), specialization=VALUES(specialization), skills=VALUES(skills), github=VALUES(github),
            linkedin=VALUES(linkedin), portfolio=VALUES(portfolio), photo_url=VALUES(photo_url)
        `;
        await connection.execute(sql, [req.user.email, name, specialization, skills, github, linkedin, portfolio, photo_url || '', req.user.role]);
        await connection.end();
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ error: 'Failed to update profile', details: error.message });
    }
});

// ===============================================
//                ADMIN API ENDPOINTS
// ===============================================
// All admin routes remain protected.

app.get('/api/profiles', verifyToken, isAdmin, async (req, res) => {
    // ... (existing code is correct)
    try {
        const connection = await mysql.createConnection(dbConfig);
        const [rows] = await connection.execute('SELECT * FROM students ORDER BY name');
        await connection.end();
        res.json(rows);
    } catch (error) {
        console.error("Admin Fetch Error:", error);
        res.status(500).json([]);
    }
});

app.post('/api/profiles', verifyToken, isAdmin, upload.single('photo'), async (req, res) => { /* ... */ });
app.delete('/api/profiles/:id', verifyToken, isAdmin, async (req, res) => { /* ... */ });
app.put('/api/profiles/:id', verifyToken, isAdmin, upload.single('photo'), async (req, res) => { /* ... */ });


// --- START SERVER & RUN CONNECTION TESTS ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    testConnections(); // <-- Run the connectivity tests on startup
});

