#!/usr/bin/env node

/**
 * Security Test Script
 * This script tests the security fixes applied to the application
 */

const http = require('http');
const https = require('https');
const querystring = require('querystring');

const BASE_URL = 'http://localhost:3000';

// Test cases for security vulnerabilities
const securityTests = [
    {
        name: 'SQL Injection Protection',
        path: '/user/1%27%20OR%20%271%27=%271',
        method: 'GET',
        expectedStatus: 400,
        description: 'Should reject SQL injection attempts'
    },
    {
        name: 'XSS Protection',
        path: '/search?q=<script>alert("xss")</script>',
        method: 'GET',
        expectedStatus: 200,
        description: 'Should escape XSS attempts'
    },
    {
        name: 'Path Traversal Protection',
        path: '/file/..%2F..%2Fetc%2Fpasswd',
        method: 'GET',
        expectedStatus: 400,
        description: 'Should reject path traversal attempts'
    },
    {
        name: 'Command Injection Protection',
        path: '/ping',
        method: 'POST',
        data: { host: 'localhost; rm -rf /' },
        expectedStatus: 400,
        description: 'Should reject command injection attempts'
    },
    {
        name: 'Unvalidated Redirect Protection',
        path: '/redirect?url=http://evil.com',
        method: 'GET',
        expectedStatus: 400,
        description: 'Should reject redirects to unauthorized domains'
    },
    {
        name: 'Information Disclosure Protection',
        path: '/debug',
        method: 'GET',
        expectedStatus: 403,
        description: 'Should require authentication for debug endpoints'
    },
    {
        name: 'Health Endpoint',
        path: '/health',
        method: 'GET',
        expectedStatus: 200,
        description: 'Should provide safe health information'
    }
];

function makeRequest(test) {
    return new Promise((resolve, reject) => {
        const url = new URL(test.path, BASE_URL);
        const options = {
            hostname: url.hostname,
            port: url.port,
            path: url.pathname + url.search,
            method: test.method,
            headers: {
                'Content-Type': 'application/json',
                'User-Agent': 'Security-Test-Script'
            }
        };

        const req = http.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: data
                });
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        if (test.data && test.method === 'POST') {
            req.write(JSON.stringify(test.data));
        }

        req.end();
    });
}

async function runSecurityTests() {
    console.log('🔒 Running Security Tests...\n');
    
    let passed = 0;
    let failed = 0;

    for (const test of securityTests) {
        try {
            console.log(`Testing: ${test.name}`);
            console.log(`Description: ${test.description}`);
            
            const response = await makeRequest(test);
            
            if (response.statusCode === test.expectedStatus) {
                console.log(`✅ PASS - Status: ${response.statusCode}`);
                passed++;
            } else {
                console.log(`❌ FAIL - Expected: ${test.expectedStatus}, Got: ${response.statusCode}`);
                failed++;
            }
            
            // Check for security headers
            if (response.headers['x-content-type-options']) {
                console.log(`✅ Security header present: X-Content-Type-Options`);
            }
            if (response.headers['x-frame-options']) {
                console.log(`✅ Security header present: X-Frame-Options`);
            }
            
        } catch (error) {
            console.log(`❌ ERROR - ${error.message}`);
            failed++;
        }
        
        console.log('---');
    }

    console.log(`\n📊 Test Results:`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📈 Success Rate: ${((passed / (passed + failed)) * 100).toFixed(1)}%`);

    if (failed === 0) {
        console.log('\n🎉 All security tests passed!');
        process.exit(0);
    } else {
        console.log('\n⚠️  Some security tests failed. Please review the fixes.');
        process.exit(1);
    }
}

// Check if server is running
function checkServer() {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: 'localhost',
            port: 3000,
            path: '/health',
            method: 'GET'
        }, (res) => {
            resolve(true);
        });

        req.on('error', (err) => {
            reject(false);
        });

        req.end();
    });
}

async function main() {
    try {
        console.log('🔍 Checking if server is running...');
        await checkServer();
        console.log('✅ Server is running\n');
        await runSecurityTests();
    } catch (error) {
        console.log('❌ Server is not running. Please start the server first:');
        console.log('   npm start');
        console.log('\nThen run this test script again.');
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}

module.exports = { runSecurityTests, securityTests };
