require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const morgan = require("morgan");

// 🛡 WAF Imports
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// ===============================
// 🔐 BASIC MIDDLEWARE
// ===============================
app.use(express.json());
app.use(morgan("combined"));

// ===============================
// 🛡 WAF SECURITY LAYER
// ===============================

// Secure HTTP headers
app.use(helmet());


// Rate limiting (anti brute-force)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5, // limit each IP
  message: "Too many requests, try again later"
});

app.use(limiter);

// ===============================
// 🗄 TEMP DATABASE
// ===============================
let users = [];

const SECRET_KEY = "supersecretkey";

// ===============================
// 🔐 REGISTER
// ===============================
app.post("/register", async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || password.length < 6) {
      return res.status(400).send("Invalid input");
    }

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).send("User already exists");
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    users.push({
      email,
      password: hashedPassword,
      role: role || "user"
    });

    res.send("User registered securely");
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// ===============================
// 🔑 LOGIN
// ===============================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) return res.status(400).send("User not found");

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(403).send("Invalid password");

    const token = jwt.sign(
      { email: user.email, role: user.role },
      SECRET_KEY,
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).send("Server error");
  }
});

// ===============================
// 🛡 AUTH MIDDLEWARE
// ===============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) return res.sendStatus(401);

  const token = authHeader.split(" ")[1];

  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);

    req.user = user;
    next();
  });
}

// ===============================
// 👑 ROLE-BASED ACCESS
// ===============================
function authorize(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send("Access Denied");
    }
    next();
  };
}

// ===============================
// 🔒 PROTECTED ROUTES
// ===============================
app.get("/dashboard", authenticateToken, (req, res) => {
  res.send(Welcome ${req.user.email});
});

app.get("/admin", authenticateToken, authorize("admin"), (req, res) => {
  res.send("Admin Panel Access Granted");
});

// ===============================
// 🚀 START SERVER
// ===============================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});