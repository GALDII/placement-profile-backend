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

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10, // Adjust as needed
    queueLimit: 0
};

// --- NEW: Create a connection pool instead of single connections ---
const pool = mysql.createPool(dbConfig);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- UPDATED MIDDLEWARE to use the connection pool ---
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).send('Unauthorized: No token provided');
    }
    const idToken = authHeader.split('Bearer ')[1];
    let connection; // Define connection here to use in finally block
    try {
        const ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        
        connection = await pool.getConnection(); // Get a connection from the pool
        const [rows] = await connection.execute('SELECT role FROM students WHERE email = ?', [payload.email]);
        
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
    } finally {
        if (connection) connection.release(); // IMPORTANT: Release the connection back to the pool
    }
}

// ... (isAdmin, multer, etc. remain the same)
const isAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        res.status(403).send('Forbidden: This resource requires admin privileges.');
    }
};
const storage = multer.memoryStorage();
const upload = multer({ storage });


// --- ALL API ENDPOINTS UPDATED to use the pool ---

app.get('/api/public/profiles', async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT id, name, specialization, skills, github, linkedin, portfolio, photo_url FROM students ORDER BY name');
        res.json(rows);
    } catch (error) {
        console.error("Public profile fetch error:", error);
        res.status(500).json([]);
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/profiles/me', verifyToken, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT * FROM students WHERE email = ?', [req.user.email]);
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(404).json({ message: 'Profile not found.', user: req.user });
        }
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch your profile' });
    } finally {
        if (connection) connection.release();
    }
});

app.put('/api/profiles/me', verifyToken, upload.single('photo'), async (req, res) => {
    // ... (rest of the logic is the same, just wrapped in connection handling)
    const { name, specialization, skills, github, linkedin, portfolio } = req.body;
    let photo_url = req.body.existing_photo_url;
    let connection;
    try {
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "student_profiles" });
            photo_url = result.secure_url;
        }
        connection = await pool.getConnection();
        const sql = `
            INSERT INTO students (email, name, specialization, skills, github, linkedin, portfolio, photo_url, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
            name=VALUES(name), specialization=VALUES(specialization), skills=VALUES(skills), github=VALUES(github),
            linkedin=VALUES(linkedin), portfolio=VALUES(portfolio), photo_url=VALUES(photo_url)
        `;
        await connection.execute(sql, [req.user.email, name, specialization, skills, github, linkedin, portfolio, photo_url || '', req.user.role]);
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ error: 'Failed to update profile', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

app.get('/api/profiles', verifyToken, isAdmin, async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.execute('SELECT * FROM students ORDER BY name');
        res.json(rows);
    } catch (error) {
        console.error("Admin Fetch Error:", error);
        res.status(500).json([]);
    } finally {
        if (connection) connection.release();
    }
});

// ... (wrap your other admin POST, PUT, DELETE endpoints in the same try/catch/finally with connection.release())

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

