# Secure Demo Application

This application demonstrates security best practices by fixing common web application vulnerabilities.

## 🔒 Security Fixes Applied

All major security vulnerabilities have been identified and fixed:

- ✅ **SQL Injection** - Parameterized queries implemented
- ✅ **Command Injection** - Input validation and safe command execution
- ✅ **Cross-Site Scripting (XSS)** - Input sanitization and output encoding
- ✅ **Path Traversal** - Proper path validation and sanitization
- ✅ **Hardcoded Secrets** - Environment variable configuration
- ✅ **Weak Cryptography** - Strong bcrypt password hashing
- ✅ **Information Disclosure** - Secured debug endpoints
- ✅ **Unvalidated Redirects** - URL validation and domain whitelisting
- ✅ **Insecure Direct Object Reference** - Authorization checks implemented

## 🚀 Quick Start

### Prerequisites

- Node.js 18.0.0 or higher
- npm 8.0.0 or higher

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sample_test
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env
   ```
   
   Edit `.env` file and fill in your actual values:
   ```bash
   # Required variables
   DB_PASSWORD=your_secure_database_password
   API_KEY=your_api_key_here
   JWT_SECRET=your_jwt_secret_at_least_32_characters_long
   ENCRYPTION_KEY=your_32_character_encryption_key_here
   SESSION_SECRET=your_session_secret_here
   ```

4. **Start the application**
   ```bash
   # Development mode
   npm run dev
   
   # Production mode
   npm run prod
   ```

## 🧪 Testing Security

Run the security test suite to verify all fixes:

```bash
# Start the server first
npm start

# In another terminal, run security tests
node test-security.js
```

## 📋 API Endpoints

### Secure Endpoints

- `GET /health` - Health check endpoint
- `GET /user/:id` - Get user by ID (with validation)
- `POST /ping` - Ping a host (with validation)
- `GET /file/:filename` - Get file (with path validation)
- `GET /search?q=query` - Search with XSS protection
- `GET /profile/:userId` - Get user profile (with authorization)
- `POST /hash-password` - Hash password securely
- `GET /redirect?url=url` - Secure redirect with validation

### Development Only

- `GET /debug` - Debug information (requires authentication)

## 🔧 Configuration

### Environment Variables

See `.env.example` for all available configuration options.

**Critical Variables:**
- `NODE_ENV` - Set to 'production' for production deployment
- `DB_PASSWORD` - Database password
- `JWT_SECRET` - JWT signing secret (minimum 32 characters)
- `ENCRYPTION_KEY` - Encryption key (exactly 32 characters)

### Security Headers

The application automatically sets security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Content-Security-Policy` - Strict CSP policy

### Rate Limiting

- Default: 100 requests per 15 minutes per IP
- Configurable via `RATE_LIMIT_MAX_REQUESTS` and `RATE_LIMIT_WINDOW_MS`

## 🛡️ Security Features

### Input Validation
- All user inputs are validated and sanitized
- File upload restrictions and path validation
- SQL injection prevention with parameterized queries

### Authentication & Authorization
- JWT-based authentication
- User ownership validation
- Role-based access control

### Cryptography
- bcrypt for password hashing (12 salt rounds)
- Secure random token generation
- AES-256-GCM encryption for sensitive data

### Error Handling
- Secure error messages (no sensitive data exposure)
- Centralized error handling
- Proper HTTP status codes

## 📊 Security Audit

Run security audits regularly:

```bash
# Check for vulnerable dependencies
npm audit

# Fix automatically fixable vulnerabilities
npm audit fix
```

## 🚀 Deployment

### Production Checklist

1. Set `NODE_ENV=production`
2. Configure all required environment variables
3. Use HTTPS/TLS for all connections
4. Enable database SSL
5. Configure proper CORS origins
6. Set up monitoring and alerting
7. Regular security updates

### Docker Deployment

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

## 📚 Documentation

- [SECURITY.md](./SECURITY.md) - Detailed security fixes documentation
- [.env.example](./.env.example) - Environment configuration template

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run security tests
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🆘 Support

For security issues, please email: security@example.com

For general support, create an issue in the repository.
