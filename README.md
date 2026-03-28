# "SECURE BACKEND AUTHENTICATION SYSTEM" 

## Project Overview

A secure Node.js backend application demonstrating robust authentication, security hardening, penetration testing, and compliance with best practices.  
The system integrates Zero Trust principles, Web Application Firewall (WAF), and phishing simulation for user awareness.
⚠️ Ethical Note:
Phishing simulation was conducted in a controlled environment for educational purposes only. No real user data was collected or misused.


## Features

1. **User Registration & Login with Validation**  

   - Email and password validated and sanitized to prevent malicious input.

2. **Secure Password Hashing**  

   - Passwords hashed and salted with bcrypt for safe storage.

3. **JWT-Based Authentication**  

   - Role-based access (User/Admin) with protected routes.

4. **Protected Routes & Zero Trust Security**  

   - Enforced least-privilege access.  

   - Re-authentication required for sensitive endpoints.

5. **Security Headers with Helmet**  

   - CSP, X-Frame-Options, Strict-Transport-Security, X-Content-Type-Options, and others applied.

6. **Logging using Winston**  

   - Application events and security events logged in `security.log`.

7. **Rate Limiting**  

   - Protects against brute-force login attempts.

8. **Web Application Firewall (WAF)**  

   - Extra layer of protection against web attacks.

9. **Input Validation & Sanitization**  

   - Prevents SQL Injection (SQLi) and Cross-Site Scripting (XSS).

10. **CSRF Protection**  

    - CSRF tokens enforced on register/login forms.

11. **Phishing Simulation**  

    - Social engineering attack simulated for awareness.


## Technologies Used

- Node.js & Express.js  

- bcrypt  

- jsonwebtoken  

- helmet  

- winston  

- validator  

- csurf  

- xss-clean  

- express-rate-limit  

- Docker  

- HTML (phishing simulation)  

## Install dependencies:

npm install

Start the server:

node server.js


## Access the application:

Server: http://localhost:3000

Phishing simulation: phishing.html