# Secret Scanner Test Application

A realistic multi-tier JavaScript application with embedded secrets for testing security scanners like Wiz.

## Project Structure
```
secret-scanner-test/
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── config.js
├── backend/
│   ├── server.js
│   ├── routes/
│   │   ├── auth.js
│   │   ├── users.js
│   │   └── payments.js
│   ├── middleware/
│   │   ├── auth.js
│   │   └── logging.js
│   ├── models/
│   │   └── user.js
│   └── utils/
│       ├── encryption.js
│       └── email.js
├── database/
│   └── init.sql
├── config/
│   ├── database.js
│   ├── redis.js
│   └── services.js
├── .env
├── .env.example
├── docker-compose.yml
└── package.json
```

## Installation & Setup

1. Clone/download this project
2. Run `npm install`
3. Start with `docker-compose up` or `npm start`

---

## package.json
```json
{
  "name": "secret-scanner-test-app",
  "version": "1.0.0",
  "description": "Test application for secret scanners",
  "main": "backend/server.js",
  "scripts": {
    "start": "node backend/server.js",
    "dev": "nodemon backend/server.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.2",
    "bcryptjs": "^2.4.3",
    "mysql2": "^3.6.0",
    "redis": "^4.6.7",
    "stripe": "^12.18.0",
    "nodemailer": "^6.9.4",
    "aws-sdk": "^2.1419.0",
    "axios": "^1.5.0",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "dotenv": "^16.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.0.1",
    "jest": "^29.6.2"
  }
}
```

## .env (Production secrets - should never be in repo!)
```env
# Database Configuration
DB_HOST=prod-mysql.company.com
DB_USER=root
DB_PASSWORD=P@ssw0rd123!MySQL
DB_NAME=production_app

# Redis Configuration  
REDIS_URL=redis://prod-redis.company.com:6379
REDIS_PASSWORD=R3d1s_S3cr3t_2023!

# JWT Configuration
JWT_SECRET=super_secret_jwt_key_that_should_not_be_here_9876543210
JWT_REFRESH_SECRET=refresh_token_secret_key_abc123xyz789

# API Keys
STRIPE_SECRET_KEY=sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210
STRIPE_PUBLISHABLE_KEY=pk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGx1234567890
SENDGRID_API_KEY=SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345
TWILIO_ACCOUNT_SID=AC1234567890abcdef1234567890abcdef
TWILIO_AUTH_TOKEN=1234567890abcdef1234567890abcdef

# AWS Configuration
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
AWS_S3_BUCKET=company-prod-bucket

# Google Services
GOOGLE_CLIENT_ID=123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz12
GOOGLE_MAPS_API_KEY=AIzaSyBkXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX

# Slack Integration
SLACK_BOT_TOKEN=xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx123

# GitHub Integration
GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz123456
GITHUB_CLIENT_SECRET=1234567890abcdefghijklmnopqrstuvwxyz123456

# External APIs
WEATHER_API_KEY=1234567890abcdef1234567890abcdef
NEWS_API_KEY=abcdef1234567890abcdef1234567890
CRYPTO_API_KEY=CMC_PRO_API_KEY_1234567890abcdef1234567890abcdef

# Security Keys
ENCRYPTION_KEY=AES256_ENCRYPTION_KEY_32_BYTES_12345678
HASH_SALT=bcrypt_salt_rounds_secret_key_xyz789
API_RATE_LIMIT_SECRET=rate_limit_bypass_secret_abc123

# Payment Processing
PAYPAL_CLIENT_ID=AeA1QIZXJr1-1234567890abcdefghijklmnopqrstuvwxyz
PAYPAL_CLIENT_SECRET=EE8lDEeO2K3-1234567890abcdefghijklmnopqrstuvwxyz

# Monitoring & Analytics
DATADOG_API_KEY=1234567890abcdef1234567890abcdef12
NEW_RELIC_LICENSE_KEY=1234567890abcdef1234567890abcdef12345678
SENTRY_DSN=https://1234567890abcdef1234567890abcdef@o123456.ingest.sentry.io/1234567
```

## frontend/index.html
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureApp Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { border: 1px solid #ddd; padding: 20px; margin: 10px 0; border-radius: 5px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 3px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        input, textarea { width: 100%; padding: 8px; margin: 5px 0; border: 1px solid #ddd; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>SecureApp Dashboard</h1>
        
        <div class="card">
            <h2>User Authentication</h2>
            <input type="email" id="email" placeholder="Email">
            <input type="password" id="password" placeholder="Password">
            <button class="btn" onclick="login()">Login</button>
            <button class="btn" onclick="register()">Register</button>
        </div>

        <div class="card">
            <h2>Payment Processing</h2>
            <input type="text" id="cardNumber" placeholder="Card Number">
            <input type="text" id="amount" placeholder="Amount">
            <button class="btn" onclick="processPayment()">Process Payment</button>
        </div>

        <div class="card">
            <h2>Data Upload</h2>
            <input type="file" id="fileUpload">
            <button class="btn" onclick="uploadFile()">Upload to S3</button>
        </div>

        <div class="card">
            <h2>Notifications</h2>
            <textarea id="message" placeholder="Message to send"></textarea>
            <button class="btn" onclick="sendNotification()">Send via Slack</button>
        </div>

        <div id="output"></div>
    </div>

    <script src="config.js"></script>
    <script src="app.js"></script>
</body>
</html>
```

## frontend/config.js
```javascript
// Frontend Configuration - SECRETS EXPOSED TO CLIENT!
const CONFIG = {
    // API Configuration
    API_BASE_URL: 'http://localhost:3000/api',
    
    // Third-party API Keys (SHOULD NEVER BE IN FRONTEND!)
    STRIPE_PUBLISHABLE_KEY: 'pk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGx1234567890',
    GOOGLE_MAPS_API_KEY: 'AIzaSyBkXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX',
    FIREBASE_API_KEY: 'AIzaSyCXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
    
    // Analytics Keys
    GOOGLE_ANALYTICS_ID: 'GA-123456789-1',
    MIXPANEL_TOKEN: '1234567890abcdef1234567890abcdef',
    
    // Social Media
    FACEBOOK_APP_ID: '123456789012345',
    TWITTER_API_KEY: 'AbCdEfGhIjKlMnOpQrStUvWxYz1234567890',
    
    // Development flags
    DEBUG_MODE: true,
    ENABLE_LOGGING: true,
    
    // Hardcoded admin credentials (TERRIBLE PRACTICE!)
    ADMIN_USERNAME: 'admin',
    ADMIN_PASSWORD: 'admin123!',
    
    // JWT Secret (SHOULD NEVER BE HERE!)
    JWT_SECRET: 'frontend_jwt_secret_should_not_exist_here',
    
    // Database connection (EXPOSED TO CLIENT!)
    DB_CONFIG: {
        host: 'prod-mysql.company.com',
        user: 'readonly_user',
        password: 'ReadOnly_P@ss123!',
        database: 'production_app'
    }
};

// Legacy hardcoded tokens
const LEGACY_TOKENS = {
    api_key: 'legacy_api_key_1234567890abcdef',
    auth_token: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
};
```

## frontend/app.js
```javascript
// Main application logic
let currentUser = null;

async function login() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Hardcoded API key in frontend (BAD!)
                'X-API-Key': 'frontend_api_key_xyz789'
            },
            body: JSON.stringify({ email, password })
        });
        
        const result = await response.json();
        
        if (result.success) {
            // Store sensitive data in localStorage (INSECURE!)
            localStorage.setItem('auth_token', result.token);
            localStorage.setItem('refresh_token', result.refreshToken);
            localStorage.setItem('user_id', result.user.id);
            
            currentUser = result.user;
            showOutput('Login successful!');
        } else {
            showOutput('Login failed: ' + result.message);
        }
    } catch (error) {
        showOutput('Error: ' + error.message);
    }
}

async function register() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    // Hardcoded registration key
    const registrationData = {
        email,
        password,
        api_key: 'registration_api_key_abc123',
        master_key: 'master_registration_key_xyz789'
    };
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/auth/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer hardcoded_auth_token_123456'
            },
            body: JSON.stringify(registrationData)
        });
        
        const result = await response.json();
        showOutput(result.success ? 'Registration successful!' : 'Registration failed: ' + result.message);
    } catch (error) {
        showOutput('Error: ' + error.message);
    }
}

async function processPayment() {
    const cardNumber = document.getElementById('cardNumber').value;
    const amount = document.getElementById('amount').value;
    
    // Stripe secret key in frontend (EXTREMELY BAD!)
    const stripe = {
        secret_key: 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210',
        webhook_secret: 'whsec_1234567890abcdefghijklmnopqrstuvwxyz'
    };
    
    const paymentData = {
        card_number: cardNumber,
        amount: amount,
        stripe_key: stripe.secret_key,
        // Test credit card (common in insecure apps)
        test_card: '4242424242424242',
        test_cvc: '123',
        test_exp: '12/25'
    };
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/payments/process`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                'X-Stripe-Key': stripe.secret_key
            },
            body: JSON.stringify(paymentData)
        });
        
        const result = await response.json();
        showOutput('Payment processed: ' + JSON.stringify(result));
    } catch (error) {
        showOutput('Payment error: ' + error.message);
    }
}

async function uploadFile() {
    const fileInput = document.getElementById('fileUpload');
    const file = fileInput.files[0];
    
    if (!file) {
        showOutput('Please select a file');
        return;
    }
    
    // AWS credentials in frontend (TERRIBLE!)
    const awsConfig = {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1',
        bucket: 'company-prod-bucket'
    };
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('aws_access_key', awsConfig.accessKeyId);
    formData.append('aws_secret_key', awsConfig.secretAccessKey);
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/upload`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                'X-AWS-Key': awsConfig.accessKeyId
            },
            body: formData
        });
        
        const result = await response.json();
        showOutput('File uploaded: ' + JSON.stringify(result));
    } catch (error) {
        showOutput('Upload error: ' + error.message);
    }
}

async function sendNotification() {
    const message = document.getElementById('message').value;
    
    // Slack webhook in frontend (BAD!)
    const slackConfig = {
        webhook_url: 'https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx123',
        bot_token: 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        channel: '#general'
    };
    
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/notifications/slack`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${localStorage.getItem('auth_token')}`,
                'X-Slack-Token': slackConfig.bot_token
            },
            body: JSON.stringify({
                message,
                webhook_url: slackConfig.webhook_url,
                bot_token: slackConfig.bot_token
            })
        });
        
        const result = await response.json();
        showOutput('Notification sent: ' + JSON.stringify(result));
    } catch (error) {
        showOutput('Notification error: ' + error.message);
    }
}

function showOutput(message) {
    const output = document.getElementById('output');
    output.innerHTML += `<div class="card">${message}</div>`;
}

// Initialize app with hardcoded admin session
document.addEventListener('DOMContentLoaded', function() {
    // Auto-login as admin (INSECURE!)
    if (localStorage.getItem('auto_admin_login') !== 'false') {
        localStorage.setItem('auth_token', 'admin_token_abc123xyz789');
        localStorage.setItem('admin_session', 'true');
        localStorage.setItem('super_user_key', 'super_user_master_key_123');
        
        currentUser = {
            id: 1,
            email: 'admin@company.com',
            role: 'admin',
            api_key: 'admin_api_key_456def'
        };
    }
});
```

## backend/server.js
```javascript
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(helmet());
app.use(express.json());

// Hardcoded secrets in server file (BAD PRACTICE!)
const SERVER_SECRETS = {
    master_key: 'server_master_key_abcdef123456',
    admin_override: 'admin_override_password_xyz789',
    debug_token: 'debug_access_token_112233',
    internal_api_key: 'internal_service_api_key_445566'
};

// Database connection with hardcoded credentials
const mysql = require('mysql2');
const dbConnection = mysql.createConnection({
    host: 'prod-mysql.company.com',
    user: 'root',
    password: 'P@ssw0rd123!MySQL', // Hardcoded password
    database: 'production_app'
});

// Redis connection with hardcoded credentials
const redis = require('redis');
const redisClient = redis.createClient({
    host: 'prod-redis.company.com',
    port: 6379,
    password: 'R3d1s_S3cr3t_2023!' // Hardcoded Redis password
});

// JWT secret hardcoded
const jwt = require('jsonwebtoken');
const JWT_SECRET = 'super_secret_jwt_key_that_should_not_be_here_9876543210';

// Import routes
const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/users');
const paymentRoutes = require('./routes/payments');

// Import middleware
const authMiddleware = require('./middleware/auth');
const loggingMiddleware = require('./middleware/logging');

// Use middleware
app.use(loggingMiddleware);

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/users', authMiddleware, userRoutes);
app.use('/api/payments', authMiddleware, paymentRoutes);

// Debug endpoint with secrets (DANGEROUS!)
app.get('/api/debug', (req, res) => {
    // Only allow with debug token
    if (req.headers['x-debug-token'] === SERVER_SECRETS.debug_token) {
        res.json({
            server_secrets: SERVER_SECRETS,
            environment: process.env,
            database_config: {
                host: 'prod-mysql.company.com',
                user: 'root',
                password: 'P@ssw0rd123!MySQL'
            },
            api_keys: {
                stripe: 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210',
                sendgrid: 'SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345',
                aws_access: 'AKIAIOSFODNN7EXAMPLE',
                aws_secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
            }
        });
    } else {
        res.status(401).json({ error: 'Invalid debug token' });
    }
});

// Admin backdoor (SECURITY VULNERABILITY!)
app.post('/api/admin/backdoor', (req, res) => {
    const { password } = req.body;
    
    if (password === SERVER_SECRETS.admin_override) {
        const adminToken = jwt.sign(
            { id: 0, email: 'admin@system', role: 'super_admin' },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            success: true,
            token: adminToken,
            message: 'Admin access granted',
            secrets: {
                master_key: SERVER_SECRETS.master_key,
                all_api_keys: process.env
            }
        });
    } else {
        res.status(401).json({ error: 'Access denied' });
    }
});

// File upload endpoint
const multer = require('multer');
const upload = multer({ dest: 'uploads/' });

app.post('/api/upload', upload.single('file'), (req, res) => {
    const AWS = require('aws-sdk');
    
    // Hardcoded AWS credentials (BAD!)
    const s3 = new AWS.S3({
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1'
    });
    
    res.json({
        success: true,
        aws_config: {
            accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
            secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        }
    });
});

// Slack notification endpoint
app.post('/api/notifications/slack', (req, res) => {
    const { message } = req.body;
    
    // Hardcoded Slack credentials
    const slackConfig = {
        bot_token: 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        webhook_url: 'https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx123',
        signing_secret: 'slack_signing_secret_abcdef123456'
    };
    
    res.json({
        success: true,
        message: 'Notification sent',
        slack_config: slackConfig
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Debug token: ${SERVER_SECRETS.debug_token}`);
    console.log(`Master key: ${SERVER_SECRETS.master_key}`);
});

module.exports = app;
```

## backend/routes/auth.js
```javascript
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Hardcoded JWT secrets (BAD!)
const JWT_SECRET = 'super_secret_jwt_key_that_should_not_be_here_9876543210';
const REFRESH_SECRET = 'refresh_token_secret_key_abc123xyz789';

// Hardcoded admin credentials
const ADMIN_CREDENTIALS = {
    email: 'admin@company.com',
    password: '$2a$10$8K1p/a0dCNA0DQwk4D4LOuF8iZnw8M8M8M8M8M8M8M8M8M8M8M', // "admin123"
    api_key: 'admin_api_key_master_xyz789'
};

// Database connection with exposed credentials
const mysql = require('mysql2');
const db = mysql.createConnection({
    host: 'prod-mysql.company.com',
    user: 'app_user',
    password: 'App_User_P@ssw0rd_2023!', // Hardcoded DB password
    database: 'user_auth'
});

// Login endpoint
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Check for hardcoded admin login
        if (email === ADMIN_CREDENTIALS.email) {
            const isValidPassword = await bcrypt.compare(password, ADMIN_CREDENTIALS.password);
            
            if (isValidPassword) {
                const token = jwt.sign(
                    { 
                        id: 0, 
                        email: email, 
                        role: 'admin',
                        api_key: ADMIN_CREDENTIALS.api_key 
                    },
                    JWT_SECRET,
                    { expiresIn: '24h' }
                );
                
                const refreshToken = jwt.sign(
                    { id: 0, type: 'refresh' },
                    REFRESH_SECRET,
                    { expiresIn: '7d' }
                );
                
                return res.json({
                    success: true,
                    token,
                    refreshToken,
                    user: {
                        id: 0,
                        email: email,
                        role: 'admin',
                        api_key: ADMIN_CREDENTIALS.api_key
                    },
                    secrets: {
                        jwt_secret: JWT_SECRET,
                        refresh_secret: REFRESH_SECRET,
                        database_password: 'App_User_P@ssw0rd_2023!'
                    }
                });
            }
        }
        
        // Regular user login logic
        const query = 'SELECT * FROM users WHERE email = ?';
        db.execute(query, [email], async (err, results) => {
            if (err) {
                console.error('Database error:', err);
                return res.status(500).json({ 
                    error: 'Database error',
                    db_credentials: {
                        host: 'prod-mysql.company.com',
                        user: 'app_user',
                        password: 'App_User_P@ssw0rd_2023!'
                    }
                });
            }
            
            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const user = results[0];
            const isValidPassword = await bcrypt.compare(password, user.password);
            
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const token = jwt.sign(
                { 
                    id: user.id, 
                    email: user.email, 
                    role: user.role 
                },
                JWT_SECRET,
                { expiresIn: '1h' }
            );
            
            res.json({
                success: true,
                token,
                user: {
                    id: user.id,
                    email: user.email,
                    role: user.role
                }
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            error: 'Internal server error',
            jwt_secret: JWT_SECRET // Exposed in error response
        });
    }
});

// Register endpoint
router.post('/register', async (req, res) => {
    const { email, password, api_key } = req.body;
    
    // Check for master registration key
    if (api_key === 'master_registration_key_xyz789') {
        // Allow registration with admin privileges
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const query = 'INSERT INTO users (email, password, role, api_key) VALUES (?, ?, ?, ?)';
        db.execute(query, [email, hashedPassword, 'admin', 'generated_admin_key_' + Date.now()], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Registration failed' });
            }
            
            res.json({
                success: true,
                message: 'Admin user created',
                secrets: {
                    master_key: 'master_registration_key_xyz789',
                    jwt_secret: JWT_SECRET,
                    database_info: {
                        host: 'prod-mysql.company.com',
                        password: 'App_User_P@ssw0rd_2023!'
                    }
                }
            });
        });
    } else {
        // Regular user registration
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const query = 'INSERT INTO users (email, password, role) VALUES (?, ?, ?)';
        db.execute(query, [email, hashedPassword, 'user'], (err, results) => {
            if (err) {
                return res.status(500).json({ error: 'Registration failed' });
            }
            
            res.json({
                success: true,
                message: 'User registered successfully'
            });
        });
    }
});

// Password reset with secret recovery
router.post('/reset-password', (req, res) => {
    const { email } = req.body;
    
    // Generate reset token with secret
    const resetToken = jwt.sign(
        { email, type: 'reset' },
        'password_reset_secret_key_123abc', // Hardcoded reset secret
        { expiresIn: '1h' }
    );
    
    res.json({
        success: true,
        reset_token: resetToken,
        reset_url: `http://localhost:3000/reset?token=${resetToken}`,
        secrets: {
            reset_secret: 'password_reset_secret_key_123abc',
            admin_email: 'admin@company.com',
            admin_reset_code: 'ADMIN_RESET_123456'
        }
    });
});

module.exports = router;
```

## backend/routes/users.js
```javascript
const express = require('express');
const router = express.Router();

// Hardcoded database credentials
const mysql = require('mysql2');
const db = mysql.createConnection({
    host: 'prod-mysql.company.com',
    user: 'users_service',
    password: 'Users_Service_P@ss123!', // Another hardcoded password
    database: 'user_data'
});

// External API keys hardcoded
const EXTERNAL_APIS = {
    sendgrid_key: 'SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345',
    twilio_sid: 'AC1234567890abcdef1234567890abcdef',
    twilio_token: '1234567890abcdef1234567890abcdef',
    mailgun_key: 'key-1234567890abcdef1234567890abcdef',
    mailgun_domain: 'mg.company.com'
};

// Get user profile
router.get('/profile/:id', (req, res) => {
    const userId = req.params.id;
    
    // Check for admin override
    if (req.headers['x-admin-key'] === 'admin_override_key_xyz789') {
        return res.json({
            message: 'Admin access granted',
            all_secrets: {
                database: {
                    host: 'prod-mysql.company.com',
                    user: 'users_service',
                    password: 'Users_Service_P@ss123!'
                },
                external_apis: EXTERNAL_APIS,
                encryption_key: 'user_data_encryption_key_abc123'
            }
        });
    }
    
    const query = 'SELECT id, email, role, created_at FROM users WHERE id = ?';
    db.execute(query, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ 
                error: 'Database error',
                debug_info: {
                    db_password: 'Users_Service_P@ss123!',
                    connection_string: 'mysql://users_service:Users_Service_P@ss123!@prod-mysql.company.com/user_data'
                }
            });
        }
        
        res.json({
            success: true,
            user: results[0]
        });
    });
});

// Update user profile
router.put('/profile/:id', (req, res) => {
    const userId = req.params.id;
    const { email, name } = req.body;
    
    // Audit logging with sensitive data
    const auditData = {
        user_id: userId,
        action: 'profile_update',
        timestamp: new Date(),
        ip_address: req.ip,
        sensitive_data: {
            internal_api_key: 'internal_audit_key_def456',
            encryption_salt: 'audit_salt_ghi789',
            backup_key: 'backup_encryption_key_jkl012'
        }
    };
    
    console.log('Audit log:', JSON.stringify(auditData, null, 2));
    
    const query = 'UPDATE users SET email = ?, name = ? WHERE id = ?';
    db.execute(query, [email, name, userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Update failed' });
        }
        
        res.json({
            success: true,
            message: 'Profile updated',
            audit_id: auditData.sensitive_data.internal_api_key
        });
    });
});

// Send notification to user
router.post('/notify/:id', (req, res) => {
    const userId = req.params.id;
    const { message, type } = req.body;
    
    // Email service configuration
    const emailConfig = {
        service: 'sendgrid',
        api_key: EXTERNAL_APIS.sendgrid_key,
        from: 'noreply@company.com',
        smtp_password: 'smtp_password_mno345'
    };
    
    // SMS service configuration  
    const smsConfig = {
        service: 'twilio',
        account_sid: EXTERNAL_APIS.twilio_sid,
        auth_token: EXTERNAL_APIS.twilio_token,
        from: '+1234567890'
    };
    
    res.json({
        success: true,
        message: 'Notification sent',
        config_used: type === 'email' ? emailConfig : smsConfig,
        debug_keys: {
            sendgrid: EXTERNAL_APIS.sendgrid_key,
            twilio: EXTERNAL_APIS.twilio_token,
            internal_notify_key: 'notify_service_key_pqr678'
        }
    });
});

// Get user analytics
router.get('/analytics/:id', (req, res) => {
    const userId = req.params.id;
    
    // Analytics service credentials
    const analyticsConfig = {
        google_analytics: {
            client_email: 'analytics@company-12345.iam.gserviceaccount.com',
            private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...\n-----END PRIVATE KEY-----',
            project_id: 'company-analytics-12345'
        },
        mixpanel: {
            token: '1234567890abcdef1234567890abcdef',
            secret: 'mixpanel_secret_stu901'
        },
        segment: {
            write_key: 'segment_write_key_vwx234',
            source_id: 'js:abc123def456'
        }
    };
    
    res.json({
        success: true,
        analytics: {
            page_views: 1250,
            session_duration: '5m 32s',
            last_active: '2023-08-15T10:30:00Z'
        },
        service_configs: analyticsConfig
    });
});

module.exports = router;
```

## backend/routes/payments.js
```javascript
const express = require('express');
const router = express.Router();

// Payment service credentials (EXPOSED!)
const PAYMENT_SECRETS = {
    stripe: {
        secret_key: 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210',
        publishable_key: 'pk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGx1234567890',
        webhook_secret: 'whsec_1234567890abcdefghijklmnopqrstuvwxyz',
        connect_client_id: 'ca_1234567890abcdefghijklmnopqrstuvwx'
    },
    paypal: {
        client_id: 'AeA1QIZXJr1-1234567890abcdefghijklmnopqrstuvwxyz',
        client_secret: 'EE8lDEeO2K3-1234567890abcdefghijklmnopqrstuvwxyz',
        webhook_id: 'WH-1234567890abcdefghijklmnopqrstuvwxyz',
        merchant_id: 'ABCDEFGHIJKLM'
    },
    square: {
        access_token: 'EAAAEAAA1234567890abcdefghijklmnopqrstuvwxyz',
        application_id: 'sq0idp-1234567890abcdefghijklmnopqrstuvwx',
        webhook_signature_key: 'webhook_signature_key_abc123'
    }
};

// Database with payment data
const mysql = require('mysql2');
const paymentDb = mysql.createConnection({
    host: 'payments-db.company.com',
    user: 'payment_service',
    password: 'P@yment_DB_S3cr3t_2023!', // Payment DB password
    database: 'payment_transactions'
});

// Process payment
router.post('/process', (req, res) => {
    const { amount, card_number, stripe_key } = req.body;
    
    // Validate Stripe key (but expose it in logs)
    console.log('Processing payment with Stripe key:', stripe_key);
    console.log('Full payment secrets:', JSON.stringify(PAYMENT_SECRETS, null, 2));
    
    // Mock payment processing
    const transactionId = 'txn_' + Math.random().toString(36).substr(2, 9);
    
    // Store in database with sensitive data
    const query = `
        INSERT INTO transactions 
        (id, amount, card_last4, stripe_key, processed_at, internal_ref) 
        VALUES (?, ?, ?, ?, NOW(), ?)
    `;
    
    const cardLast4 = card_number.slice(-4);
    const internalRef = 'INT_' + Date.now();
    
    paymentDb.execute(query, [
        transactionId, 
        amount, 
        cardLast4, 
        stripe_key, 
        internalRef
    ], (err, results) => {
        if (err) {
            console.error('Payment DB error:', err);
            return res.status(500).json({ 
                error: 'Payment processing failed',
                debug_info: {
                    db_host: 'payments-db.company.com',
                    db_password: 'P@yment_DB_S3cr3t_2023!',
                    stripe_keys: PAYMENT_SECRETS.stripe
                }
            });
        }
        
        res.json({
            success: true,
            transaction_id: transactionId,
            amount: amount,
            payment_methods: {
                stripe: PAYMENT_SECRETS.stripe,
                paypal: PAYMENT_SECRETS.paypal,
                square: PAYMENT_SECRETS.square
            },
            debug: {
                internal_processing_key: 'payment_processor_key_xyz789',
                admin_override_code: 'PAYMENT_ADMIN_123456'
            }
        });
    });
});

// Get payment history
router.get('/history/:userId', (req, res) => {
    const userId = req.params.userId;
    
    // Check for admin access
    if (req.headers['x-payment-admin'] === 'payment_admin_master_key_abc123') {
        return res.json({
            message: 'Payment admin access granted',
            all_secrets: PAYMENT_SECRETS,
            database_access: {
                host: 'payments-db.company.com',
                user: 'payment_service',
                password: 'P@yment_DB_S3cr3t_2023!',
                root_password: 'Payment_Root_P@ss_456!'
            },
            encryption_keys: {
                pci_encryption_key: 'PCI_ENCRYPT_KEY_def456ghi789',
                card_tokenization_key: 'CARD_TOKEN_KEY_jkl012mno345'
            }
        });
    }
    
    const query = 'SELECT * FROM transactions WHERE user_id = ? ORDER BY processed_at DESC';
    paymentDb.execute(query, [userId], (err, results) => {
        if (err) {
            return res.status(500).json({ error: 'Failed to fetch payment history' });
        }
        
        res.json({
            success: true,
            transactions: results,
            service_info: {
                processor: 'stripe',
                api_version: '2023-08-16',
                webhook_endpoint: 'https://api.company.com/webhooks/stripe',
                api_keys: {
                    live: PAYMENT_SECRETS.stripe.secret_key,
                    test: 'sk_test_1234567890abcdefghijklmnopqrstuvwxyz'
                }
            }
        });
    });
});

// Refund payment
router.post('/refund/:transactionId', (req, res) => {
    const transactionId = req.params.transactionId;
    const { reason, amount } = req.body;
    
    // Refund processing with exposed credentials
    const refundData = {
        transaction_id: transactionId,
        refund_amount: amount,
        reason: reason,
        processed_by: 'system',
        stripe_refund_key: PAYMENT_SECRETS.stripe.secret_key,
        internal_refund_code: 'REFUND_CODE_' + Math.random().toString(36).substr(2, 8)
    };
    
    // Log refund with sensitive data
    console.log('Processing refund:', JSON.stringify(refundData, null, 2));
    
    res.json({
        success: true,
        refund_id: 'rf_' + Math.random().toString(36).substr(2, 9),
        original_transaction: transactionId,
        refund_amount: amount,
        processing_details: {
            stripe_key_used: PAYMENT_SECRETS.stripe.secret_key,
            paypal_credentials: PAYMENT_SECRETS.paypal,
            internal_codes: {
                refund_processor_key: 'refund_proc_key_pqr678',
                audit_bypass_code: 'AUDIT_BYPASS_901234'
            }
        }
    });
});

// Webhook handler (with secret exposure)
router.post('/webhook/stripe', (req, res) => {
    const signature = req.headers['stripe-signature'];
    const payload = req.body;
    
    // Verify webhook with exposed secret
    const webhookSecret = PAYMENT_SECRETS.stripe.webhook_secret;
    
    console.log('Webhook received with secret:', webhookSecret);
    console.log('Full webhook config:', {
        stripe_webhook_secret: webhookSecret,
        paypal_webhook_id: PAYMENT_SECRETS.paypal.webhook_id,
        square_webhook_key: PAYMENT_SECRETS.square.webhook_signature_key
    });
    
    res.json({
        success: true,
        message: 'Webhook processed',
        webhook_secrets: {
            stripe: webhookSecret,
            paypal: PAYMENT_SECRETS.paypal.webhook_id,
            square: PAYMENT_SECRETS.square.webhook_signature_key,
            internal_webhook_key: 'internal_webhook_validator_stu567'
        }
    });
});

module.exports = router;
```

## backend/middleware/auth.js
```javascript
const jwt = require('jsonwebtoken');

// Hardcoded JWT secrets
const JWT_SECRET = 'super_secret_jwt_key_that_should_not_be_here_9876543210';
const ADMIN_BYPASS_KEY = 'admin_bypass_middleware_xyz789';

// Service account credentials
const SERVICE_ACCOUNTS = {
    monitoring: {
        username: 'monitoring_service',
        password: 'Monitor_Service_P@ss123!',
        api_key: 'monitoring_api_key_abc456'
    },
    backup: {
        username: 'backup_service', 
        password: 'Backup_Service_P@ss456!',
        api_key: 'backup_api_key_def789'
    },
    analytics: {
        username: 'analytics_service',
        password: 'Analytics_Service_P@ss789!',
        api_key: 'analytics_api_key_ghi012'
    }
};

const authMiddleware = (req, res, next) => {
    // Check for admin bypass
    if (req.headers['x-admin-bypass'] === ADMIN_BYPASS_KEY) {
        console.log('Admin bypass used!');
        req.user = {
            id: 0,
            email: 'admin@system',
            role: 'super_admin',
            bypass_used: true
        };
        return next();
    }
    
    // Check for service account access
    const serviceAuth = req.headers['x-service-auth'];
    if (serviceAuth) {
        for (const [serviceName, serviceConfig] of Object.entries(SERVICE_ACCOUNTS)) {
            if (serviceAuth === serviceConfig.api_key) {
                req.user = {
                    id: serviceName,
                    service: serviceName,
                    role: 'service',
                    credentials: serviceConfig
                };
                return next();
            }
        }
    }
    
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            error: 'No token provided',
            hint: 'Use admin bypass key: ' + ADMIN_BYPASS_KEY,
            service_accounts: SERVICE_ACCOUNTS
        });
    }
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('JWT verification failed:', error);
        return res.status(401).json({ 
            error: 'Invalid token',
            jwt_secret: JWT_SECRET, // Exposed in error response
            valid_bypass_key: ADMIN_BYPASS_KEY,
            service_api_keys: Object.values(SERVICE_ACCOUNTS).map(s => s.api_key)
        });
    }
};

module.exports = authMiddleware;
```

## backend/middleware/logging.js
```javascript
const fs = require('fs');
const path = require('path');

// Logging configuration with sensitive data
const LOGGING_CONFIG = {
    api_key: 'logging_service_api_key_xyz123',
    endpoint: 'https://logs.company.com/api/ingest',
    auth_token: 'logging_auth_token_abc456def789',
    encryption_key: 'log_encryption_key_ghi012jkl345'
};

// External logging services
const EXTERNAL_LOGGERS = {
    datadog: {
        api_key: '1234567890abcdef1234567890abcdef12',
        app_key: 'abcdef1234567890abcdef1234567890ab',
        site: 'datadoghq.com'
    },
    newrelic: {
        license_key: '1234567890abcdef1234567890abcdef12345678',
        api_key: 'NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'
    },
    sentry: {
        dsn: 'https://1234567890abcdef1234567890abcdef@o123456.ingest.sentry.io/1234567',
        auth_token: 'sentry_auth_token_mno678pqr901'
    }
};

const loggingMiddleware = (req, res, next) => {
    const startTime = Date.now();
    
    // Capture request details including sensitive headers
    const logEntry = {
        timestamp: new Date().toISOString(),
        method: req.method,
        url: req.url,
        ip: req.ip,
        user_agent: req.headers['user-agent'],
        headers: req.headers, // Includes authorization tokens!
        body: req.body, // May contain passwords/secrets!
        query: req.query,
        params: req.params,
        session_id: req.sessionID,
        request_id: Math.random().toString(36).substr(2, 9)
    };
    
    // Add sensitive debugging info
    if (req.headers['x-debug-logging']) {
        logEntry.debug_info = {
            logging_config: LOGGING_CONFIG,
            external_services: EXTERNAL_LOGGERS,
            internal_keys: {
                audit_key: 'audit_service_key_stu345',
                compliance_key: 'compliance_key_vwx678',
                security_key: 'security_log_key_yzab90'
            }
        };
    }
    
    // Intercept response
    const originalJson = res.json;
    res.json = function(data) {
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        // Log response including potentially sensitive data
        const responseLog = {
            ...logEntry,
            duration: duration,
            status_code: res.statusCode,
            response_data: data, // May contain secrets/tokens!
            response_headers: res.getHeaders()
        };
        
        // Write to log file with sensitive data
        const logLine = JSON.stringify(responseLog, null, 2) + '\n';
        fs.appendFileSync(path.join(__dirname, '../logs/access.log'), logLine);
        
        // Send to external services (with credentials exposed)
        if (process.env.NODE_ENV === 'production') {
            sendToExternalLogger(responseLog);
        }
        
        // Console log with sensitive data
        console.log('Request completed:', {
            method: req.method,
            url: req.url,
            duration: duration + 'ms',
            status: res.statusCode,
            auth_header: req.headers.authorization,
            sensitive_data: data,
            logging_secrets: LOGGING_CONFIG
        });
        
        return originalJson.call(this, data);
    };
    
    next();
};

function sendToExternalLogger(logData) {
    // Send to DataDog with API key exposed
    console.log('Sending to DataDog with key:', EXTERNAL_LOGGERS.datadog.api_key);
    
    // Send to New Relic with license key exposed
    console.log('Sending to New Relic with license:', EXTERNAL_LOGGERS.newrelic.license_key);
    
    // Send to Sentry with DSN exposed
    console.log('Sending to Sentry with DSN:', EXTERNAL_LOGGERS.sentry.dsn);
    
    // Mock HTTP request with credentials
    const payload = {
        log_data: logData,
        service_credentials: EXTERNAL_LOGGERS,
        internal_auth: LOGGING_CONFIG.auth_token
    };
    
    // In real app, this would be an HTTP request exposing credentials
    console.log('External logging payload:', JSON.stringify(payload, null, 2));
}

module.exports = loggingMiddleware;
```

## config/database.js
```javascript
// Database configuration with multiple environments

const DATABASE_CONFIGS = {
    production: {
        host: 'prod-mysql.company.com',
        port: 3306,
        user: 'prod_user',
        password: 'Pr0d_MySQL_P@ssw0rd_2023!',
        database: 'production_app',
        ssl: {
            ca: '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKJ...',
            key: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w...',
            cert: '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAKJ...'
        },
        backup_credentials: {
            user: 'backup_user',
            password: 'Backup_User_P@ss456!',
            readonly_user: 'readonly',
            readonly_password: 'ReadOnly_P@ss789!'
        }
    },
    staging: {
        host: 'staging-mysql.company.com',
        port: 3306,
        user: 'staging_user',
        password: 'St@ging_MySQL_P@ss_2023!',
        database: 'staging_app',
        admin_access: {
            user: 'admin',
            password: 'Admin_DB_P@ss123!',
            root_password: 'DB_Root_P@ssw0rd_456!'
        }
    },
    development: {
        host: 'localhost',
        port: 3306,
        user: 'dev_user',
        password: 'dev_password_123',
        database: 'dev_app',
        debug_user: {
            user: 'debug',
            password: 'debug_pass_xyz'
        }
    },
    test: {
        host: 'test-db.company.com',
        port: 3306,
        user: 'test_user',
        password: 'Test_DB_P@ss_789!',
        database: 'test_app'
    }
};

// Redis configurations
const REDIS_CONFIGS = {
    production: {
        host: 'prod-redis.company.com',
        port: 6379,
        password: 'R3d1s_Pr0d_P@ss_2023!',
        auth: 'redis_auth_token_abc123',
        cluster_password: 'Redis_Cluster_P@ss_456!'
    },
    staging: {
        host: 'staging-redis.company.com',
        port: 6379,
        password: 'R3d1s_St@ging_P@ss_2023!',
        auth: 'redis_staging_token_def456'
    },
    development: {
        host: 'localhost',
        port: 6379,
        password: 'dev_redis_pass',
        auth: 'dev_redis_token'
    }
};

// MongoDB configurations
const MONGO_CONFIGS = {
    production: {
        uri: 'mongodb://prod_mongo_user:M0ng0_Pr0d_P@ss_2023!@prod-mongo.company.com:27017/production_app',
        options: {
            authSource: 'admin',
            ssl: true,
            sslCA: 'path/to/ca.pem',
            sslCert: 'path/to/client.pem',
            sslKey: 'path/to/client.key'
        },
        admin_credentials: {
            username: 'admin',
            password: 'M0ng0_Admin_P@ss_456!',
            database: 'admin'
        },
        backup_user: {
            username: 'backup',
            password: 'M0ng0_Backup_P@ss_789!'
        }
    },
    staging: {
        uri: 'mongodb://staging_mongo_user:M0ng0_St@g_P@ss_2023!@staging-mongo.company.com:27017/staging_app',
        admin_password: 'M0ng0_Staging_Admin_123!'
    }
};

// Database connection pools
const CONNECTION_POOLS = {
    mysql_pool: {
        host: 'prod-mysql.company.com',
        user: 'pool_user',
        password: 'MySQL_Pool_P@ss_2023!',
        connectionLimit: 10,
        acquireTimeout: 60000,
        timeout: 60000
    },
    postgres_pool: {
        host: 'prod-postgres.company.com',
        user: 'postgres_user',
        password: 'P0stgres_P@ss_2023!',
        database: 'production_app',
        port: 5432,
        max: 20,
        idleTimeoutMillis: 30000,
        admin_user: 'postgres',
        admin_password: 'P0stgres_Admin_P@ss_456!'
    }
};

// Export environment-specific config
function getDatabaseConfig(env = 'production') {
    const config = {
        mysql: DATABASE_CONFIGS[env],
        redis: REDIS_CONFIGS[env], 
        mongodb: MONGO_CONFIGS[env],
        pools: CONNECTION_POOLS
    };
    
    // Add debug info in non-production
    if (env !== 'production') {
        config.debug_info = {
            all_environments: DATABASE_CONFIGS,
            redis_configs: REDIS_CONFIGS,
            mongo_configs: MONGO_CONFIGS,
            master_db_key: 'master_database_access_key_xyz123',
            encryption_key: 'db_encryption_key_abc456def789'
        };
    }
    
    return config;
}

module.exports = {
    getDatabaseConfig,
    DATABASE_CONFIGS,
    REDIS_CONFIGS,
    MONGO_CONFIGS,
    CONNECTION_POOLS
};
```

## config/services.js
```javascript
// Third-party service configurations

const AWS_CONFIGS = {
    production: {
        accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
        secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        region: 'us-east-1',
        s3_bucket: 'company-prod-bucket',
        ses_smtp_user: 'AKIAI...EXAMPLE',
        ses_smtp_password: 'AhC...EXAMPLE',
        lambda_role_arn: 'arn:aws:iam::123456789012:role/lambda-execution-role',
        rds_master_password: 'RDS_Master_P@ss_2023!',
        elasticache_auth: 'ElastiCache_Auth_Token_abc123'
    },
    staging: {
        accessKeyId: 'AKIAI...STAGING',
        secretAccessKey: 'wJalr...STAGING',
        region: 'us-west-2',
        s3_bucket: 'company-staging-bucket'
    }
};

const GOOGLE_CONFIGS = {
    client_id: '123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com',
    client_secret: 'GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz12',
    api_key: 'AIzaSyBkXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX',
    service_account: {
        type: 'service_account',
        project_id: 'company-project-12345',
        private_key_id: 'abcdef1234567890',
        private_key: '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...\n-----END PRIVATE KEY-----',
        client_email: 'service@company-project-12345.iam.gserviceaccount.com',
        client_id: '123456789012345678901',
        auth_uri: 'https://accounts.google.com/o/oauth2/auth',
        token_uri: 'https://oauth2.googleapis.com/token'
    },
    firebase: {
        api_key: 'AIzaSyCXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX',
        messaging_sender_id: '123456789012',
        app_id: '1:123456789012:web:abcdef1234567890',
        server_key: 'AAAA...server_key_for_fcm'
    }
};

const PAYMENT_CONFIGS = {
    stripe: {
        secret_key: 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210',
        publishable_key: 'pk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGx1234567890',
        webhook_secret: 'whsec_1234567890abcdefghijklmnopqrstuvwxyz',
        connect_client_id: 'ca_1234567890abcdefghijklmnopqrstuvwx',
        test_secret: 'sk_test_1234567890abcdefghijklmnopqrstuvwxyz',
        restricted_key: 'rk_live_1234567890abcdefghijklmnopqrstuvwx'
    },
    paypal: {
        client_id: 'AeA1QIZXJr1-1234567890abcdefghijklmnopqrstuvwxyz',
        client_secret: 'EE8lDEeO2K3-1234567890abcdefghijklmnopqrstuvwxyz',
        webhook_id: 'WH-1234567890abcdefghijklmnopqrstuvwxyz',
        partner_id: 'partner_id_1234567890',
        merchant_id: 'ABCDEFGHIJKLM'
    },
    square: {
        application_id: 'sq0idp-1234567890abcdefghijklmnopqrstuvwx',
        access_token: 'EAAAEAAA1234567890abcdefghijklmnopqrstuvwxyz',
        webhook_signature_key: 'webhook_signature_key_abc123',
        environment: 'production'
    }
};

const COMMUNICATION_CONFIGS = {
    sendgrid: {
        api_key: 'SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345',
        webhook_public_key: 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...',
        template_engine_key: 'template_engine_key_abc123'
    },
    twilio: {
        account_sid: 'AC1234567890abcdef1234567890abcdef',
        auth_token: '1234567890abcdef1234567890abcdef',
        api_key: 'SK1234567890abcdef1234567890abcdef',
        api_secret: 'api_secret_1234567890abcdef',
        webhook_auth: 'webhook_auth_token_xyz789'
    },
    slack: {
        bot_token: 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        webhook_url: 'https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx123',
        signing_secret: 'slack_signing_secret_abcdef123456',
        client_id: '123456789012.123456789012',
        client_secret: 'abcdef1234567890abcdef1234567890',
        verification_token: 'verification_token_ghi789jkl012'
    },
    discord: {
        bot_token: 'MTIzNDU2Nzg5MDEyMzQ1Njc4OTA.GhIjKl.MnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWx',
        client_id: '123456789012345678',
        client_secret: 'abcdef1234567890abcdef1234567890',
        webhook_url: 'https://discord.com/api/webhooks/123456789012345678/AbCdEfGhIjKlMnOpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvWxYz'
    }
};

const ANALYTICS_CONFIGS = {
    google_analytics: {
        tracking_id: 'GA-123456789-1',
        measurement_id: 'G-ABCDEF1234',
        api_secret: 'api_secret_1234567890abcdef'
    },
    mixpanel: {
        token: '1234567890abcdef1234567890abcdef',
        secret: 'mixpanel_secret_abcdef123456',
        api_key: 'mixpanel_api_key_ghijkl789012'
    },
    segment: {
        write_key: 'segment_write_key_1234567890abcdef',
        source_id: 'js:abc123def456ghi789jkl012',
        workspace_slug: 'company-workspace'
    },
    amplitude: {
        api_key: 'amplitude_api_key_mnopqr345678',
        secret_key: 'amplitude_secret_key_stuvwx901234'
    }
};

const MONITORING_CONFIGS = {
    datadog: {
        api_key: '1234567890abcdef1234567890abcdef12',
        app_key: 'abcdef1234567890abcdef1234567890ab',
        site: 'datadoghq.com',
        rum_application_id: 'rum_app_id_yzabcd567890',
        rum_client_token: 'rum_client_token_efghij123456'
    },
    newrelic: {
        license_key: '1234567890abcdef1234567890abcdef12345678',
        api_key: 'NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456',
        insert_key: 'insert_key_klmnop789012qrstuv345678',
        account_id: '1234567'
    },
    sentry: {
        dsn: 'https://1234567890abcdef1234567890abcdef@o123456.ingest.sentry.io/1234567',
        auth_token: 'sentry_auth_token_wxyzab901234cdefgh567890',
        org: 'company-org',
        project: 'company-project'
    },
    rollbar: {
        access_token: 'rollbar_access_token_ijklmn345678opqrst901234',
        environment: 'production'
    }
};

// AI/ML Service configs
const AI_CONFIGS = {
    openai: {
        api_key: 'sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX',
        organization: 'org-1234567890abcdefghijklmnop'
    },
    anthropic: {
        api_key: 'sk-ant-api03-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    },
    azure_openai: {
        api_key: 'azure_openai_key_1234567890abcdef',
        endpoint: 'https://company-openai.openai.azure.com/',
        deployment_name: 'gpt-4-deployment'
    }
};

// Social Media API configs
const SOCIAL_CONFIGS = {
    twitter: {
        api_key: 'twitter_api_key_AbCdEfGhIjKlMnOpQrStUvWxYz',
        api_secret: 'twitter_api_secret_1234567890abcdefghijklmnopqrstuvwxyzABCDEF',
        access_token: 'twitter_access_token_1234567890-AbCdEfGhIjKlMnOpQrStUvWxYzAb',
        access_token_secret: 'twitter_access_secret_CdEfGhIjKlMnOpQrStUvWxYzAbCdEf',
        bearer_token: 'twitter_bearer_token_AAAAAAAAAAAAAAAAAAAAAA%2FAAAAAAAAAA'
    },
    facebook: {
        app_id: '123456789012345',
        app_secret: 'facebook_app_secret_abcdef1234567890abcdef1234567890',
        access_token: 'facebook_access_token_EAAxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        page_access_token: 'facebook_page_token_EAAyyyyyyyyyyyyyyyyyyyyyyyyyy'
    },
    linkedin: {
        client_id: 'linkedin_client_id_1234567890ab',
        client_secret: 'linkedin_client_secret_AbCdEfGhIjKlMnOp',
        access_token: 'linkedin_access_token_AQV1234567890abcdefghijklmnopqr'
    }
};

module.exports = {
    aws: AWS_CONFIGS,
    google: GOOGLE_CONFIGS,
    payments: PAYMENT_CONFIGS,
    communication: COMMUNICATION_CONFIGS,
    analytics: ANALYTICS_CONFIGS,
    monitoring: MONITORING_CONFIGS,
    ai: AI_CONFIGS,
    social: SOCIAL_CONFIGS,
    
    // Master configuration access
    getAllSecrets: () => ({
        aws: AWS_CONFIGS,
        google: GOOGLE_CONFIGS,
        payments: PAYMENT_CONFIGS,
        communication: COMMUNICATION_CONFIGS,
        analytics: ANALYTICS_CONFIGS,
        monitoring: MONITORING_CONFIGS,
        ai: AI_CONFIGS,
        social: SOCIAL_CONFIGS,
        master_access_key: 'master_service_access_key_xyz789abc123',
        config_encryption_key: 'config_encrypt_key_def456ghi789jkl012'
    })
};
```

## docker-compose.yml
```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      # Database secrets
      - DB_HOST=prod-mysql.company.com
      - DB_USER=root
      - DB_PASSWORD=P@ssw0rd123!MySQL
      - DB_NAME=production_app
      
      # Redis secrets
      - REDIS_URL=redis://prod-redis.company.com:6379
      - REDIS_PASSWORD=R3d1s_S3cr3t_2023!
      
      # JWT secrets
      - JWT_SECRET=super_secret_jwt_key_that_should_not_be_here_9876543210
      - JWT_REFRESH_SECRET=refresh_token_secret_key_abc123xyz789
      
      # API Keys
      - STRIPE_SECRET_KEY=sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210
      - SENDGRID_API_KEY=SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345
      - AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      - AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
      
      # Slack integration
      - SLACK_BOT_TOKEN=xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx
      - SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T12345678/B12345678/AbCdEfGhIjKlMnOpQrStUvWx123
      
      # GitHub secrets
      - GITHUB_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz123456
      - GITHUB_CLIENT_SECRET=1234567890abcdefghijklmnopqrstuvwxyz123456
      
      # Monitoring
      - DATADOG_API_KEY=1234567890abcdef1234567890abcdef12
      - NEW_RELIC_LICENSE_KEY=1234567890abcdef1234567890abcdef12345678
      - SENTRY_DSN=https://1234567890abcdef1234567890abcdef@o123456.ingest.sentry.io/1234567
    volumes:
      - .:/app
      - /app/node_modules
    depends_on:
      - mysql
      - redis

  mysql:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=MySQL_Root_P@ssw0rd_2023!
      - MYSQL_DATABASE=production_app
      - MYSQL_USER=app_user
      - MYSQL_PASSWORD=App_User_P@ssw0rd_2023!
    ports:
      - "3306:3306"
    volumes:
      - mysql_data:/var/lib/mysql
      - ./database/init.sql:/docker-entrypoint-initdb.d/init.sql

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass R3d1s_S3cr3t_2023!
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data

  # Additional services with secrets
  mongodb:
    image: mongo:6
    environment:
      - MONGO_INITDB_ROOT_USERNAME=admin
      - MONGO_INITDB_ROOT_PASSWORD=M0ng0_Admin_P@ss_2023!
      - MONGO_INITDB_DATABASE=production_app
    ports:
      - "27017:27017"
    volumes:
      - mongo_data:/data/db

  elasticsearch:
    image: elasticsearch:8.8.0
    environment:
      - discovery.type=single-node
      - ELASTIC_PASSWORD=El@stic_P@ss_2023!
      - xpack.security.enabled=true
    ports:
      - "9200:9200"
    volumes:
      - elastic_data:/usr/share/elasticsearch/data

volumes:
  mysql_data:
  redis_data:
  mongo_data:
  elastic_data:
```

## database/init.sql
```sql
-- Database initialization with embedded secrets

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin', 'super_admin') DEFAULT 'user',
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Create transactions table with sensitive data
CREATE TABLE IF NOT EXISTS transactions (
    id VARCHAR(50) PRIMARY KEY,
    user_id INT,
    amount DECIMAL(10,2),
    card_last4 VARCHAR(4),
    stripe_key VARCHAR(255), -- Storing API keys in DB (BAD!)
    status VARCHAR(50) DEFAULT 'pending',
    processed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    internal_ref VARCHAR(100),
    INDEX idx_user_id (user_id)
);

-- Create secrets table (TERRIBLE IDEA!)
CREATE TABLE IF NOT EXISTS application_secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    service_name VARCHAR(100) NOT NULL,
    secret_type VARCHAR(50) NOT NULL,
    secret_value TEXT NOT NULL,
    environment VARCHAR(20) DEFAULT 'production',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample secrets into database (EXTREMELY BAD!)
INSERT INTO application_secrets (service_name, secret_type, secret_value, environment) VALUES
('stripe', 'api_key', 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210', 'production'),
('stripe', 'webhook_secret', 'whsec_1234567890abcdefghijklmnopqrstuvwxyz', 'production'),
('aws', 'access_key', 'AKIAIOSFODNN7EXAMPLE', 'production'),
('aws', 'secret_key', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'production'),
('sendgrid', 'api_key', 'SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345', 'production'),
('twilio', 'account_sid', 'AC1234567890abcdef1234567890abcdef', 'production'),
('twilio', 'auth_token', '1234567890abcdef1234567890abcdef', 'production'),
('slack', 'bot_token', 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx', 'production'),
('github', 'token', 'ghp_1234567890abcdefghijklmnopqrstuvwxyz123456', 'production'),
('database', 'root_password', 'MySQL_Root_P@ssw0rd_2023!', 'production'),
('jwt', 'secret', 'super_secret_jwt_key_that_should_not_be_here_9876543210', 'production'),
('encryption', 'master_key', 'master_encryption_key_abc123def456ghi789', 'production');

-- Create admin user with hardcoded credentials
INSERT INTO users (email, password, role, api_key) VALUES 
('admin@company.com', '$2a$10$8K1p/a0dCNA0DQwk4D4LOuF8iZnw8M8M8M8M8M8M8M8M8M8M8M', 'super_admin', 'admin_api_key_master_xyz789');

-- Create API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    secret_key TEXT,
    service_url VARCHAR(255),
    environment VARCHAR(20),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert API keys (STORING SECRETS IN PLAIN TEXT!)
INSERT INTO api_keys (key_name, api_key, secret_key, service_url, environment) VALUES
('stripe_live', 'pk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGx1234567890', 'sk_live_51H7x8vKZQNHzGKkXxVKGKqKGQGxGxGKGxKGQ9876543210', 'https://api.stripe.com', 'production'),
('paypal_live', 'AeA1QIZXJr1-1234567890abcdefghijklmnopqrstuvwxyz', 'EE8lDEeO2K3-1234567890abcdefghijklmnopqrstuvwxyz', 'https://api.paypal.com', 'production'),
('aws_s3', 'AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', 'https://s3.amazonaws.com', 'production'),
('google_apis', 'AIzaSyBkXxXxXxXxXxXxXxXxXxXxXxXxXxXxXxX', 'GOCSPX-AbCdEfGhIjKlMnOpQrStUvWxYz12', 'https://googleapis.com', 'production'),
('sendgrid_mail', 'SG.xyzABC123.defGHI456-jklMNO789-pqrSTU012-vwxYZ345', NULL, 'https://api.sendgrid.com', 'production'),
('twilio_sms', 'AC1234567890abcdef1234567890abcdef', '1234567890abcdef1234567890abcdef', 'https://api.twilio.com', 'production'),
('slack_bot', 'xoxb-1234567890123-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx', NULL, 'https://slack.com/api', 'production'),
('github_api', 'ghp_1234567890abcdefghijklmnopqrstuvwxyz123456', NULL, 'https://api.github.com', 'production'),
('datadog_monitor', '1234567890abcdef1234567890abcdef12', 'abcdef1234567890abcdef1234567890ab', 'https://api.datadoghq.com', 'production'),
('newrelic_apm', 'NRAK-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456', '1234567890abcdef1234567890abcdef12345678', 'https://api.newrelic.com', 'production');

-- Create database connection strings table (VERY BAD IDEA!)
CREATE TABLE IF NOT EXISTS database_connections (
    id INT AUTO_INCREMENT PRIMARY KEY,
    connection_name VARCHAR(100),
    connection_string TEXT NOT NULL,
    username VARCHAR(100),
    password VARCHAR(255),
    host VARCHAR(255),
    port INT,
    database_name VARCHAR(100),
    environment VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert database connections with passwords (TERRIBLE!)
INSERT INTO database_connections (connection_name, connection_string, username, password, host, port, database_name, environment) VALUES
('main_db', 'mysql://root:P@ssw0rd123!MySQL@prod-mysql.company.com:3306/production_app', 'root', 'P@ssw0rd123!MySQL', 'prod-mysql.company.com', 3306, 'production_app', 'production'),
('user_db', 'mysql://app_user:App_User_P@ssw0rd_2023!@prod-mysql.company.com:3306/user_data', 'app_user', 'App_User_P@ssw0rd_2023!', 'prod-mysql.company.com', 3306, 'user_data', 'production'),
('payment_db', 'mysql://payment_service:P@yment_DB_S3cr3t_2023!@payments-db.company.com:3306/payment_transactions', 'payment_service', 'P@yment_DB_S3cr3t_2023!', 'payments-db.company.com', 3306, 'payment_transactions', 'production'),
('redis_cache', 'redis://:R3d1s_S3cr3t_2023!@prod-redis.company.com:6379', NULL, 'R3d1s_S3cr3t_2023!', 'prod-redis.company.com', 6379, '0', 'production'),
('mongo_logs', 'mongodb://admin:M0ng0_Admin_P@ss_2023!@prod-mongo.company.com:27017/logs', 'admin', 'M0ng0_Admin_P@ss_2023!', 'prod-mongo.company.com', 27017, 'logs', 'production'),
('postgres_analytics', 'postgresql://postgres:P0stgres_P@ss_2023!@prod-postgres.company.com:5432/analytics', 'postgres', 'P0stgres_P@ss_2023!', 'prod-postgres.company.com', 5432, 'analytics', 'production');

-- Create deployment secrets table
CREATE TABLE IF NOT EXISTS deployment_secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    deployment_name VARCHAR(100),
    secret_data JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert deployment secrets (INCLUDING PRIVATE KEYS!)
INSERT INTO deployment_secrets (deployment_name, secret_data) VALUES
('production_deploy', '{
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB...\\n-----END OPENSSH PRIVATE KEY-----",
    "ssl_private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7...\\n-----END PRIVATE KEY-----",
    "docker_registry_password": "Docker_Registry_P@ss_2023!",
    "kubeconfig": "apiVersion: v1\\nclusters:\\n- cluster:\\n    certificate-authority-data: LS0t...",
    "master_deployment_key": "deploy_master_key_xyz789abc123def456"
}'),
('staging_deploy', '{
    "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\\nstaging_ssh_key_data_here...\\n-----END OPENSSH PRIVATE KEY-----",
    "ssl_private_key": "-----BEGIN PRIVATE KEY-----\\nstaging_ssl_key_data_here...\\n-----END PRIVATE KEY-----",
    "docker_registry_password": "Staging_Docker_P@ss_456!",
    "deployment_token": "staging_deploy_token_ghi789jkl012"
}');

-- Comment with additional secrets (bad practice)
-- Production database master password: MySQL_Master_P@ss_Root_2023!
-- Backup encryption key: backup_encrypt_key_mno345pqr678stu901
-- System admin password: SysAdmin_P@ss_Ultimate_456!
```

---

This comprehensive test application contains numerous types of secrets embedded in various realistic scenarios that security scanners should detect:

- **Frontend secrets** (API keys, credentials exposed to clients)
- **Backend hardcoded secrets** (JWT secrets, database passwords, API keys)
- **Configuration files** with sensitive data
- **Environment variables** with real-looking secrets
- **Database stored secrets** (worst practice scenarios)
- **Docker configuration** with embedded secrets
- **Comments** containing sensitive information
- **Various API key formats** (Stripe, AWS, Google, GitHub, etc.)
- **Different secret types** (passwords, tokens, private keys, connection strings)

Perfect for testing Wiz's secret scanning capabilities across multiple file types and secret patterns!
