// Import libraries
const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');

// Initialize app
const app = express();
const PORT = 3000;

// ==================== WINSTON LOGGER ====================
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

logger.info("Application started");

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(helmet());

// Log every request
app.use((req, res, next) => {
    logger.info(`Incoming request: ${req.method} ${req.url}`);
    next();
});

// -------------------- ROOT ROUTE --------------------
app.get('/', (req, res) => {
    logger.info("Root endpoint accessed");
    res.send("Secure Backend is Running 🚀");
});

// -------------------- REGISTER ROUTE --------------------
app.post('/register', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        logger.warn("Registration failed: Missing email or password");
        return res.status(400).json({ message: "Email and password are required" });
    }

    if (!validator.isEmail(email)) {
        logger.warn("Registration failed: Invalid email format");
        return res.status(400).json({ message: "Invalid email format" });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(password)) {
        logger.warn("Registration failed: Weak password");
        return res.status(400).json({
            message: "Password must be at least 8 characters, include 1 uppercase letter and 1 number"
        });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    logger.info(`User registered successfully: ${email}`);

    res.status(200).json({
        message: "Registration successful!",
        hashedPassword: hashedPassword
    });
});

// -------------------- LOGIN ROUTE --------------------
app.post('/login', async (req, res) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
        logger.warn("Login failed: Missing email or password");
        return res.status(400).json({ message: "Email and password are required" });
    }

    const storedHashedPassword = await bcrypt.hash("Tooba@123", 10);

    const isMatch = await bcrypt.compare(password, storedHashedPassword);
    if (!isMatch) {
        logger.warn(`Login failed for email: ${email}`);
        return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
        { email: email },
        'your-secret-key',
        { expiresIn: '1h' }
    );

    logger.info(`User logged in successfully: ${email}`);

    res.status(200).json({
        message: "Login successful!",
        token: token
    });
});

// -------------------- PROTECTED DASHBOARD --------------------
app.get('/dashboard', (req, res) => {
    const token = req.headers['authorization'];

    if (!token) {
        logger.warn("Dashboard access denied: No token provided");
        return res.status(401).json({ message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, 'your-secret-key');
        logger.info(`Dashboard accessed by: ${decoded.email}`);
        res.status(200).json({
            message: `Welcome ${decoded.email} to your dashboard!`
        });
    } catch (err) {
        logger.warn("Dashboard access failed: Invalid or expired token");
        res.status(401).json({ message: "Invalid or expired token" });
    }
});

// -------------------- START SERVER --------------------
app.listen(PORT, () => {
    logger.info(`Server running on port ${PORT}`);
});