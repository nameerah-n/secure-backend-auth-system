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
const mysql = require('mysql');

const csrf = require('csurf');
const cookieParser = require('cookie-parser');

// -------------------- INIT --------------------
const app = express();
const PORT = 3000;

// -------------------- DB --------------------
const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "testdb"
});

db.connect(err => {
    if (err) console.log("❌ DB error");
    else console.log("✅ DB Connected");
});

// -------------------- LOGGER --------------------
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.simple(),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'security.log' })
    ]
});

// -------------------- MIDDLEWARE --------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // ✅ IMPORTANT
app.use(cookieParser());
app.use(helmet());

app.use(cors({
    origin: ['http://localhost:5500'],
    methods: ['GET','POST']
}));

// -------------------- RATE LIMIT --------------------
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10
});
app.use('/login', limiter);

// -------------------- CSRF --------------------
const csrfProtection = csrf({ cookie: true });

// -------------------- FRONTEND PAGE --------------------
app.get('/', (req, res) => {
    res.send(`
    <html>
    <body style="font-family: Arial; padding: 40px;">
        <h2>🔐 Secure App</h2>

        <h3>Register</h3>
        <form action="/register" method="POST">
            <input name="email" placeholder="Email" required/><br><br>
            <input name="password" type="password" placeholder="Password" required/><br><br>
            <input type="hidden" name="_csrf" id="csrf1"/>
            <button type="submit">Register</button>
        </form>

        <h3>Login</h3>
        <form action="/login" method="POST">
            <input name="email" placeholder="Email" required/><br><br>
            <input name="password" type="password" placeholder="Password" required/><br><br>
            <input type="hidden" name="_csrf" id="csrf2"/>
            <button type="submit">Login</button>
        </form>

        <script>
            fetch('/csrf-token')
            .then(res => res.json())
            .then(data => {
                document.getElementById('csrf1').value = data.csrfToken;
                document.getElementById('csrf2').value = data.csrfToken;
            });
        </script>
    </body>
    </html>
    `);
});

// -------------------- CSRF TOKEN --------------------
app.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// -------------------- REGISTER --------------------
app.post('/register', csrfProtection, async (req, res) => {
    const { email, password } = req.body;

    if (!validator.isEmail(email))
        return res.send("Invalid email");

    const hash = await bcrypt.hash(password, 10);

    res.send("Registered ✅");
});

// -------------------- LOGIN --------------------
app.post('/login', csrfProtection, async (req, res) => {
    const { email, password } = req.body;

    const stored = await bcrypt.hash("Tooba@123", 10);
    const match = await bcrypt.compare(password, stored);

    if (!match)
        return res.send("Login Failed ❌");

    res.send("Login Success ✅");
});

// -------------------- SQLi VULNERABLE --------------------
app.get('/user', (req, res) => {
    const username = req.query.username;

    const query = `SELECT * FROM users WHERE username = '${username}'`;

    db.query(query, (err, result) => {
        if (err) return res.send("Error");
        res.json(result);
    });
});

// -------------------- SQLi FIXED --------------------
app.get('/secure-user', (req, res) => {
    const username = req.query.username;

    const query = "SELECT * FROM users WHERE username = ?";

    db.query(query, [username], (err, result) => {
        if (err) return res.send("Error");
        res.json(result);
    });
});

// -------------------- START --------------------
app.listen(PORT, () => {
    console.log("🚀 http://localhost:3000");
});