// Import libraries
const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');

// Initialize app
const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());
app.use(helmet()); // Secure HTTP headers

// -------------------- ROOT ROUTE --------------------
app.get('/', (req, res) => {
    res.send("Secure Backend is Running 🚀");
});
// -------------------- REGISTER ROUTE --------------------
app.post('/register', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    if (!validator.isEmail(email)) {
        return res.status(400).json({ message: "Invalid email format" });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            message: "Password must be at least 8 characters, include 1 uppercase letter and 1 number"
        });
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    res.status(200).json({
        message: "Registration successful!",
        hashedPassword: hashedPassword
    });
});
// -------------------- LOGIN ROUTE --------------------
app.post('/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        return res.status(400).json({ message: "Email and password are required" });
    }

    // Demo stored password
    const storedHashedPassword = await bcrypt.hash("Tooba@123", 10);

    const isMatch = await bcrypt.compare(password, storedHashedPassword);
    if (!isMatch) {
        return res.status(401).json({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
        { email: email },
        'your-secret-key',
        { expiresIn: '1h' }
    );

    res.status(200).json({
        message: "Login successful!",
        token: token
    });
});
// -------------------- PROTECTED DASHBOARD --------------------
app.get('/dashboard', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, 'your-secret-key');
        res.status(200).json({
            message: `Welcome ${decoded.email} to your dashboard!`
        });
    } catch (err) {
        res.status(401).json({ message: "Invalid or expired token" });
    }
});
// -------------------- START SERVER --------------------
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});