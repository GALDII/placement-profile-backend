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

// --- DATABASE & CLOUDINARY CONFIGURATION ---
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

// --- FUNCTION TO TEST CONNECTIONS ON STARTUP ---
async function testConnections() {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Google Cloud SQL connection successful!');
        connection.release();
    } catch (error) {
        console.error('❌ Google Cloud SQL connection failed:', error.message);
    }
    try {
        const cloudinaryCheck = await cloudinary.api.ping();
        if (cloudinaryCheck.status === 'ok') {
            console.log('✅ Cloudinary connection successful!');
        } else {
            throw new Error('Cloudinary ping did not return "ok".');
        }
    } catch (error) {
        console.error('❌ Cloudinary connection failed:', error.message);
    }
}

// --- MIDDLEWARE ---
async function verifyToken(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(403).send('Unauthorized: No token provided');
    }
    const idToken = authHeader.split('Bearer ')[1];
    let connection;
    try {
        const ticket = await client.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
        const payload = ticket.getPayload();
        connection = await pool.getConnection();
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
        if (connection) connection.release();
    }
}

const isAdmin = (req, res, next) => {
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

// Get all public profiles (no authentication required)
app.get('/api/public/profiles', async (req, res) => {
    let connection;
    try {
        connection = await pool.getConnection();
        const [rows] = await connection.execute(
            'SELECT id, name, specialization, skills, github, linkedin, portfolio, photo_url FROM students ORDER BY name'
        );
        res.json(rows);
    } catch (error) {
        console.error("Public profile fetch error:", error);
        res.status(500).json([]);
    } finally {
        if (connection) connection.release();
    }
});

// Get current user's profile
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
        console.error("Fetch user profile error:", error);
        res.status(500).json({ error: 'Failed to fetch your profile' });
    } finally {
        if (connection) connection.release();
    }
});

// Update current user's profile (with improved photo handling)
app.put('/api/profiles/me', verifyToken, upload.single('photo'), async (req, res) => {
    const { name, specialization, skills, github, linkedin, portfolio } = req.body;
    let connection;
    try {
        connection = await pool.getConnection();

        // If a new photo is uploaded, handle it and update the photo_url
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "student_profiles" });
            const photo_url = result.secure_url;

            // Insert or update with new photo
            const sql = `
                INSERT INTO students (email, name, specialization, skills, github, linkedin, portfolio, photo_url, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                name=VALUES(name), specialization=VALUES(specialization), skills=VALUES(skills), 
                github=VALUES(github), linkedin=VALUES(linkedin), portfolio=VALUES(portfolio), 
                photo_url=VALUES(photo_url)
            `;
            await connection.execute(sql, [
                req.user.email, name, specialization, skills, github, linkedin, portfolio, photo_url, req.user.role
            ]);
        } else {
            // If NO new photo is uploaded, update without touching photo_url
            const sql = `
                INSERT INTO students (email, name, specialization, skills, github, linkedin, portfolio, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                name=VALUES(name), specialization=VALUES(specialization), skills=VALUES(skills),
                github=VALUES(github), linkedin=VALUES(linkedin), portfolio=VALUES(portfolio)
            `;
            await connection.execute(sql, [
                req.user.email, name, specialization, skills, github, linkedin, portfolio, req.user.role
            ]);
        }
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ error: 'Failed to update profile', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

// ===============================================
//             ADMIN API ENDPOINTS
// ===============================================

// Get all profiles (admin only)
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

// Create new profile (admin only)
app.post('/api/profiles', verifyToken, isAdmin, upload.single('photo'), async (req, res) => {
    const { name, email, specialization, skills, github, linkedin, portfolio, role = 'student' } = req.body;
    
    if (!email) {
        return res.status(400).json({ error: 'Email is required.' });
    }

    let connection;
    try {
        let photo_url = '';
        
        // Handle photo upload if provided
        if (req.file) {
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "student_profiles" });
            photo_url = result.secure_url;
        }
        
        connection = await pool.getConnection();
        const sql = `
            INSERT INTO students (name, email, specialization, skills, github, linkedin, portfolio, photo_url, role) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [insertResult] = await connection.execute(sql, [
            name, email, specialization, skills, github, linkedin, portfolio, photo_url, role
        ]);
        
        res.status(201).json({ 
            id: insertResult.insertId, 
            message: 'Profile created successfully' 
        });
    } catch (error) {
        console.error("Admin Create Profile Error:", error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'A profile with this email already exists.' });
        } else {
            res.status(500).json({ error: 'Failed to create profile', details: error.message });
        }
    } finally {
        if (connection) connection.release();
    }
});

// Update profile by ID (admin only, with improved photo handling)
app.put('/api/profiles/:id', verifyToken, isAdmin, upload.single('photo'), async (req, res) => {
    const { id } = req.params;
    const { name, email, specialization, skills, github, linkedin, portfolio, role } = req.body;
    
    let connection;
    try {
        connection = await pool.getConnection();

        if (req.file) {
            // If a new photo is uploaded, update all fields including the photo
            const b64 = Buffer.from(req.file.buffer).toString("base64");
            const dataURI = `data:${req.file.mimetype};base64,${b64}`;
            const result = await cloudinary.uploader.upload(dataURI, { folder: "student_profiles" });
            const photo_url = result.secure_url;
            
            const sql = `
                UPDATE students 
                SET name = ?, email = ?, specialization = ?, skills = ?, github = ?, 
                    linkedin = ?, portfolio = ?, photo_url = ?, role = ? 
                WHERE id = ?
            `;
            await connection.execute(sql, [
                name, email, specialization, skills, github, linkedin, portfolio, photo_url, role, id
            ]);
        } else {
            // If NO new photo is uploaded, update all fields EXCEPT the photo
            const sql = `
                UPDATE students 
                SET name = ?, email = ?, specialization = ?, skills = ?, github = ?, 
                    linkedin = ?, portfolio = ?, role = ? 
                WHERE id = ?
            `;
            await connection.execute(sql, [
                name, email, specialization, skills, github, linkedin, portfolio, role, id
            ]);
        }
        
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error(`Admin update error for ID ${id}:`, error);
        if (error.code === 'ER_DUP_ENTRY') {
            res.status(400).json({ error: 'Another profile with this email already exists.' });
        } else {
            res.status(500).json({ error: 'Failed to update profile', details: error.message });
        }
    } finally {
        if (connection) connection.release();
    }
});

// Delete profile by ID (admin only)
app.delete('/api/profiles/:id', verifyToken, isAdmin, async (req, res) => {
    const { id } = req.params;
    let connection;
    try {
        connection = await pool.getConnection();
        const [result] = await connection.execute('DELETE FROM students WHERE id = ?', [id]);
        
        if (result.affectedRows === 0) {
            res.status(404).json({ error: 'Profile not found' });
        } else {
            res.json({ message: 'Profile deleted successfully' });
        }
    } catch (error) {
        console.error("Admin Delete Profile Error:", error);
        res.status(500).json({ error: 'Failed to delete profile', details: error.message });
    } finally {
        if (connection) connection.release();
    }
});

// ===============================================
//              START SERVER
// ===============================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    testConnections();
});