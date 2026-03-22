// -------------------- IMPORTS --------------------
const express = require('express');
const validator = require('validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const winston = require('winston');
const fs = require('fs');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// -------------------- INITIALIZE --------------------
const app = express();
const PORT = 3000;

// -------------------- WINSTON LOGGER --------------------
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

// -------------------- MIDDLEWARE --------------------
app.use(express.json());

// -------------------- HELMET FOR SECURITY HEADERS --------------------
app.use(helmet()); // sets default headers
// CSP
app.use(
    helmet.contentSecurityPolicy({
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", 'https://fonts.googleapis.com'],
            fontSrc: ["'self'", 'https://fonts.gstatic.com'],
            imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"],
        },
    })
);
// HSTS
app.use(
    helmet.hsts({
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    })
);

// -------------------- CORS CONFIGURATION --------------------
const corsOptions = {
    origin: ['http://localhost:5500', 'https://mytrustedclient.com'],
    methods: ['GET','POST']
};
app.use(cors(corsOptions));

// -------------------- RATE LIMITING --------------------
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 min
    max: 10,
    message: "Too many requests from this IP, please try again later."
});
app.use('/login', limiter);

// -------------------- LOG FAILED LOGIN FUNCTION --------------------
function logFailedLogin(ip, email) {
    const log = `${new Date().toISOString()} FAILED LOGIN IP:${ip} EMAIL:${email}\n`;
    fs.appendFileSync("security.log", log);
}

// -------------------- API KEY MIDDLEWARE --------------------
const apiKeyMiddleware = (req,res,next)=>{
    const apiKey = req.headers['x-api-key'];
    if(!apiKey || apiKey !== "my-secret-api-key"){
        logger.warn("Unauthorized access attempt");
        return res.status(401).json({ message: "Unauthorized: Invalid API key" });
    }
    next();
};

// -------------------- LOG ALL REQUESTS --------------------
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
    const ip = req.ip;

    if (!email || !password) {
        logger.warn("Login failed: Missing email or password");
        return res.status(400).json({ message: "Email and password are required" });
    }

    // For demo: stored password is "Tooba@123"
    const storedHashedPassword = await bcrypt.hash("Tooba@123", 10);
    const isMatch = await bcrypt.compare(password, storedHashedPassword);

    if (!isMatch) {
        logger.warn(`Login failed for email: ${email}`);
        logFailedLogin(ip, email);
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

// -------------------- DASHBOARD ROUTE (Protected) --------------------
app.get('/dashboard', apiKeyMiddleware, (req, res) => {
    const authHeader = req.headers['authorization'];
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        logger.warn("Dashboard access denied: No token provided");
        return res.status(401).json({ message: "No token provided" });
    }

    const token = authHeader.split(' ')[1]; // Extract token

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