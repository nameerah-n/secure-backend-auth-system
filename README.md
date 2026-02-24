"SECURE BACKEND PROJECT" 

OVERVIEW:

This project implements a secure backend using Node.js and Express.
It demonstrates:

1- Input validation
2- Password hashing
3- JWT authentication
4- Protected routes
5- Secure HTTP headers using Helmet

TECHNOLOGIES USED:

1- Node.js
2- Express.js
3- bcrypt
4- jsonwebtoken (JWT)
5- Helmet.js
6- Validator.js

SECURITY FEATURES IMPLEMENTED:

1️⃣ Input Validation
Email format validation
Strong password enforcement

2️⃣ Password Hashing
bcrypt hashing with salt rounds

3️⃣ JWT Authentication
Token generation on login
Token verification for protected routes
Token expiration (1 hour)

4️⃣ Secure HTTP Headers
Implemented using Helmet.js to protect against:
XSS
Clickjacking
MIME sniffing
Cross-origin attacks



HOW TO RUN:

1. Install dependencies
npm install

2. Start server 
node server.js
Server runs on:
http://localhost:3000


API ENDPOINTS:

1- POST /register:
    Register user with email & strong password.
2- POST /login:
    Returns JWT token on valid credentials.
3- GET /dashboard:
    Protected route requiring JWT token.