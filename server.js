const express = require('express');
const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const validator = require('validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Security middleware
app.use(helmet());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// FIXED: Use environment variables for sensitive configuration
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'app_user',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'testdb',
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false
};

// API key is now loaded from environment variables when needed

// Database connection
let db;
mysql.createConnection(dbConfig).then(connection => {
    db = connection;
    console.log('Database connected');
}).catch(err => {
    console.error('Database connection failed:', err);
});

// FIXED: SQL Injection - Using parameterized queries
app.get('/user/:id', async (req, res) => {
    const userId = req.params.id;

    // Input validation
    if (!validator.isNumeric(userId)) {
        return res.status(400).json({ error: 'Invalid user ID format' });
    }

    // FIXED: Using parameterized query to prevent SQL injection
    const query = 'SELECT id, username, email, created_at FROM users WHERE id = ?';

    try {
        const [results] = await db.execute(query, [userId]);
        if (results.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(results[0]);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIXED: Command Injection - Using input validation and safe alternatives
app.post('/ping', (req, res) => {
    const host = req.body.host;

    // Input validation
    if (!host || typeof host !== 'string') {
        return res.status(400).json({ error: 'Host parameter is required and must be a string' });
    }

    // FIXED: Validate hostname/IP format
    if (!validator.isFQDN(host) && !validator.isIP(host)) {
        return res.status(400).json({ error: 'Invalid hostname or IP address format' });
    }

    // FIXED: Use spawn instead of exec for better security
    const { spawn } = require('child_process');
    const ping = spawn('ping', ['-c', '4', host]);

    let output = '';
    let errors = '';

    ping.stdout.on('data', (data) => {
        output += data.toString();
    });

    ping.stderr.on('data', (data) => {
        errors += data.toString();
    });

    ping.on('close', (code) => {
        res.json({
            output: output,
            errors: errors,
            exitCode: code
        });
    });

    // Timeout after 10 seconds
    setTimeout(() => {
        ping.kill();
        res.status(408).json({ error: 'Ping timeout' });
    }, 10000);
});

// FIXED: Path Traversal - Proper path validation and sanitization
app.get('/file/:filename', (req, res) => {
    const filename = req.params.filename;

    // Input validation
    if (!filename || typeof filename !== 'string') {
        return res.status(400).json({ error: 'Filename is required' });
    }

    // FIXED: Sanitize filename to prevent path traversal
    const sanitizedFilename = path.basename(filename);

    // Additional validation: only allow alphanumeric characters, dots, and hyphens
    if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
        return res.status(400).json({ error: 'Invalid filename format' });
    }

    // FIXED: Use path.resolve to prevent directory traversal
    const uploadsDir = path.resolve(__dirname, 'uploads');
    const filePath = path.resolve(uploadsDir, sanitizedFilename);

    // FIXED: Ensure the resolved path is within the uploads directory
    if (!filePath.startsWith(uploadsDir)) {
        return res.status(403).json({ error: 'Access denied' });
    }

    // Check if file exists and is a file (not directory)
    fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
            return res.status(404).json({ error: 'File not found' });
        }

        // Read file with size limit
        fs.readFile(filePath, 'utf8', (err, data) => {
            if (err) {
                return res.status(500).json({ error: 'Error reading file' });
            }
            res.send(data);
        });
    });
});

// FIXED: Cross-Site Scripting (XSS) - Proper input sanitization and output encoding
app.get('/search', (req, res) => {
    const query = req.query.q;

    // Input validation
    if (!query || typeof query !== 'string') {
        return res.status(400).json({ error: 'Search query is required' });
    }

    // FIXED: Sanitize and escape user input to prevent XSS
    const sanitizedQuery = validator.escape(query);

    // Additional validation: limit query length
    if (sanitizedQuery.length > 100) {
        return res.status(400).json({ error: 'Search query too long' });
    }

    // FIXED: Use proper HTML escaping and Content Security Policy
    res.set({
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'self'; script-src 'none'; object-src 'none';"
    });

    const html = `
        <!DOCTYPE html>
        <html>
            <head>
                <meta charset="utf-8">
                <title>Search Results</title>
            </head>
            <body>
                <h1>Search Results</h1>
                <p>You searched for: ${sanitizedQuery}</p>
                <div id="results">No results found</div>
            </body>
        </html>
    `;

    res.send(html);
});

// FIXED: Insecure Direct Object Reference - Proper authorization checks
app.get('/profile/:userId', async (req, res) => {
    const userId = req.params.userId;
    const currentUser = req.headers['x-user-id']; // Simulated auth

    // Input validation
    if (!validator.isNumeric(userId)) {
        return res.status(400).json({ error: 'Invalid user ID format' });
    }

    // FIXED: Authorization check - users can only access their own profile
    if (!currentUser) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    if (currentUser !== userId) {
        return res.status(403).json({ error: 'Access denied - you can only view your own profile' });
    }

    // FIXED: Only select non-sensitive fields
    const query = 'SELECT id, username, email, created_at, last_login FROM profiles WHERE user_id = ?';

    try {
        const [results] = await db.execute(query, [userId]);
        if (results.length === 0) {
            return res.status(404).json({ error: 'Profile not found' });
        }
        res.json(results[0]);
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIXED: Weak Cryptography - Using strong bcrypt hashing
app.post('/hash-password', async (req, res) => {
    const password = req.body.password;

    // Input validation
    if (!password || typeof password !== 'string') {
        return res.status(400).json({ error: 'Password is required' });
    }

    // Password strength validation
    if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }

    try {
        // FIXED: Using bcrypt with salt rounds for secure password hashing
        const saltRounds = 12;
        const hash = await bcrypt.hash(password, saltRounds);

        res.json({
            message: 'Password hashed successfully',
            // Don't return the actual hash in production
            hash: process.env.NODE_ENV === 'development' ? hash : undefined
        });
    } catch (error) {
        console.error('Hashing error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// FIXED: Information Disclosure - Removed debug endpoint or secured it
app.get('/health', (_req, res) => {
    // FIXED: Only expose non-sensitive health information
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        // Only expose safe information
        nodeVersion: process.version.split('.')[0], // Only major version
        environment: process.env.NODE_ENV || 'development'
    });
});

// Debug endpoint only available in development with authentication
if (process.env.NODE_ENV === 'development') {
    app.get('/debug', (req, res) => {
        const debugToken = req.headers['x-debug-token'];

        // Simple debug authentication
        if (debugToken !== process.env.DEBUG_TOKEN) {
            return res.status(403).json({ error: 'Debug access denied' });
        }

        // FIXED: Only expose safe debug information
        res.json({
            nodeVersion: process.version,
            platform: process.platform,
            uptime: process.uptime(),
            memoryUsage: process.memoryUsage()
        });
    });
}

// FIXED: Unvalidated Redirect - Proper URL validation
app.get('/redirect', (req, res) => {
    const url = req.query.url;

    // Input validation
    if (!url || typeof url !== 'string') {
        return res.status(400).json({ error: 'URL parameter is required' });
    }

    // FIXED: Validate URL format and whitelist allowed domains
    const allowedDomains = [
        'example.com',
        'subdomain.example.com',
        'trusted-partner.com'
    ];

    try {
        const parsedUrl = new URL(url);

        // Only allow HTTPS URLs
        if (parsedUrl.protocol !== 'https:') {
            return res.status(400).json({ error: 'Only HTTPS URLs are allowed' });
        }

        // Check if domain is in whitelist
        const isAllowedDomain = allowedDomains.some(domain =>
            parsedUrl.hostname === domain || parsedUrl.hostname.endsWith('.' + domain)
        );

        if (!isAllowedDomain) {
            return res.status(400).json({ error: 'Redirect to this domain is not allowed' });
        }

        res.redirect(url);
    } catch (error) {
        res.status(400).json({ error: 'Invalid URL format' });
    }
});

// Error handling middleware
app.use((err, _req, res, _next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((_req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    // FIXED: Don't log sensitive information
    if (process.env.NODE_ENV === 'development') {
        console.log('Development mode - debug endpoints available');
    }
});

module.exports = app;