// FIXED: Secure configuration using environment variables
module.exports = {
    database: {
        host: process.env.DB_HOST || 'localhost',
        username: process.env.DB_USER || 'app_user',
        password: process.env.DB_PASSWORD || '',
        port: parseInt(process.env.DB_PORT) || 3306,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: true } : false,
        connectionLimit: parseInt(process.env.DB_CONNECTION_LIMIT) || 10,
        acquireTimeout: parseInt(process.env.DB_ACQUIRE_TIMEOUT) || 60000,
        timeout: parseInt(process.env.DB_TIMEOUT) || 60000
    },

    api: {
        key: process.env.API_KEY || '',
        secret: process.env.API_SECRET || '',
        webhook_secret: process.env.WEBHOOK_SECRET || '',
        rate_limit: {
            window_ms: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000, // 15 minutes
            max_requests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
        }
    },

    jwt: {
        secret: process.env.JWT_SECRET || '',
        algorithm: 'HS256',
        expiresIn: process.env.JWT_EXPIRES_IN || '1h',
        issuer: process.env.JWT_ISSUER || 'secure-app'
    },

    encryption: {
        key: process.env.ENCRYPTION_KEY || '',
        algorithm: 'aes-256-gcm'
    },

    third_party: {
        aws_access_key: process.env.AWS_ACCESS_KEY_ID || '',
        aws_secret: process.env.AWS_SECRET_ACCESS_KEY || '',
        aws_region: process.env.AWS_REGION || 'us-east-1',
        stripe_key: process.env.STRIPE_SECRET_KEY || '',
        github_token: process.env.GITHUB_TOKEN || ''
    },

    security: {
        bcrypt_rounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
        session_secret: process.env.SESSION_SECRET || '',
        cors_origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
        helmet_config: {
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'"],
                    styleSrc: ["'self'", "'unsafe-inline'"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"],
                    fontSrc: ["'self'"],
                    objectSrc: ["'none'"],
                    mediaSrc: ["'self'"],
                    frameSrc: ["'none'"]
                }
            }
        }
    },

    // Validation function to check required environment variables
    validate: function() {
        const required = [
            'DB_PASSWORD',
            'API_KEY',
            'JWT_SECRET',
            'ENCRYPTION_KEY',
            'SESSION_SECRET'
        ];

        const missing = required.filter(key => !process.env[key]);

        if (missing.length > 0) {
            throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
        }

        // Validate key lengths
        if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
            throw new Error('JWT_SECRET must be at least 32 characters long');
        }

        if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY.length !== 32) {
            throw new Error('ENCRYPTION_KEY must be exactly 32 characters long');
        }

        return true;
    }
};