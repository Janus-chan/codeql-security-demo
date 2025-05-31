const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('crypto');

class FileHandler {
    // FIXED: Path traversal protection with proper validation
    static async readUserFile(filename) {
        // Input validation
        if (!filename || typeof filename !== 'string') {
            throw new Error('Filename is required and must be a string');
        }

        // FIXED: Sanitize filename to prevent path traversal
        const sanitizedFilename = path.basename(filename);

        // Additional validation: only allow safe characters
        if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
            throw new Error('Invalid filename format');
        }

        // FIXED: Use path.resolve to prevent directory traversal
        const userFilesDir = path.resolve(__dirname, '..', 'user_files');
        const filePath = path.resolve(userFilesDir, sanitizedFilename);

        // FIXED: Ensure the resolved path is within the user_files directory
        if (!filePath.startsWith(userFilesDir)) {
            throw new Error('Access denied - path traversal detected');
        }

        try {
            // Check file size before reading
            const stats = await fs.stat(filePath);
            const maxFileSize = 10 * 1024 * 1024; // 10MB limit

            if (stats.size > maxFileSize) {
                throw new Error('File too large');
            }

            return await fs.readFile(filePath, 'utf8');
        } catch (error) {
            throw new Error(`Error reading file: ${error.message}`);
        }
    }

    // FIXED: Command injection protection with allowlist and safe execution
    static async processFile(filename, operation) {
        // Input validation
        if (!filename || typeof filename !== 'string') {
            throw new Error('Filename is required and must be a string');
        }

        if (!operation || typeof operation !== 'string') {
            throw new Error('Operation is required and must be a string');
        }

        // FIXED: Use allowlist of safe operations instead of arbitrary commands
        const allowedOperations = {
            'compress': ['gzip', '-c'],
            'checksum': ['sha256sum'],
            'info': ['file', '-b'],
            'size': ['wc', '-c']
        };

        if (!allowedOperations[operation]) {
            throw new Error('Operation not allowed');
        }

        // Sanitize filename
        const sanitizedFilename = path.basename(filename);
        if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
            throw new Error('Invalid filename format');
        }

        const uploadsDir = path.resolve(__dirname, '..', 'uploads');
        const filePath = path.resolve(uploadsDir, sanitizedFilename);

        // Ensure file is within uploads directory
        if (!filePath.startsWith(uploadsDir)) {
            throw new Error('Access denied - path traversal detected');
        }

        // Check if file exists
        try {
            await fs.access(filePath);
        } catch (error) {
            throw new Error('File not found');
        }

        return new Promise((resolve, reject) => {
            const command = allowedOperations[operation];
            const process = spawn(command[0], [...command.slice(1), filePath]);

            let output = '';
            let errors = '';

            process.stdout.on('data', (data) => {
                output += data.toString();
            });

            process.stderr.on('data', (data) => {
                errors += data.toString();
            });

            process.on('close', (code) => {
                if (code === 0) {
                    resolve({ output, operation });
                } else {
                    reject(new Error(`Process failed with code ${code}: ${errors}`));
                }
            });

            // Timeout after 30 seconds
            setTimeout(() => {
                process.kill();
                reject(new Error('Process timeout'));
            }, 30000);
        });
    }

    // FIXED: Safe file reading with size limits and streaming
    static async readLargeFile(filename) {
        // Input validation
        if (!filename || typeof filename !== 'string') {
            throw new Error('Filename is required and must be a string');
        }

        const sanitizedFilename = path.basename(filename);
        if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
            throw new Error('Invalid filename format');
        }

        const userFilesDir = path.resolve(__dirname, '..', 'user_files');
        const filePath = path.resolve(userFilesDir, sanitizedFilename);

        if (!filePath.startsWith(userFilesDir)) {
            throw new Error('Access denied - path traversal detected');
        }

        try {
            // FIXED: Check file size before reading
            const stats = await fs.stat(filePath);
            const maxFileSize = 100 * 1024 * 1024; // 100MB limit for large files

            if (stats.size > maxFileSize) {
                throw new Error('File exceeds maximum size limit');
            }

            // For very large files, consider using streams instead
            if (stats.size > 50 * 1024 * 1024) { // 50MB
                return this.readFileStream(filePath);
            }

            return await fs.readFile(filePath);
        } catch (error) {
            throw new Error(`Error reading file: ${error.message}`);
        }
    }

    // FIXED: Safe file writing with atomic operations
    static async safeFileWrite(filename, data) {
        // Input validation
        if (!filename || typeof filename !== 'string') {
            throw new Error('Filename is required and must be a string');
        }

        if (!data) {
            throw new Error('Data is required');
        }

        const sanitizedFilename = path.basename(filename);
        if (!/^[a-zA-Z0-9._-]+$/.test(sanitizedFilename)) {
            throw new Error('Invalid filename format');
        }

        const userFilesDir = path.resolve(__dirname, '..', 'user_files');
        const finalPath = path.resolve(userFilesDir, sanitizedFilename);

        if (!finalPath.startsWith(userFilesDir)) {
            throw new Error('Access denied - path traversal detected');
        }

        // FIXED: Use atomic write operation to prevent race conditions
        const tempFilename = `${sanitizedFilename}.${crypto.randomBytes(8).toString('hex')}.tmp`;
        const tempPath = path.resolve(userFilesDir, tempFilename);

        try {
            // Write to temporary file first
            await fs.writeFile(tempPath, data);

            // Atomically move to final location
            await fs.rename(tempPath, finalPath);

            return await fs.readFile(finalPath, 'utf8');
        } catch (error) {
            // Clean up temporary file if it exists
            try {
                await fs.unlink(tempPath);
            } catch (cleanupError) {
                // Ignore cleanup errors
            }
            throw new Error(`Error writing file: ${error.message}`);
        }
    }

    // Helper method for streaming large files
    static readFileStream(filePath) {
        return new Promise((resolve, reject) => {
            const stream = fsSync.createReadStream(filePath);
            const chunks = [];

            stream.on('data', (chunk) => {
                chunks.push(chunk);
            });

            stream.on('end', () => {
                resolve(Buffer.concat(chunks));
            });

            stream.on('error', (error) => {
                reject(error);
            });
        });
    }
}

module.exports = FileHandler;