import crypto from 'crypto';
import * as jose from 'jose';

/**
 * EnvCryptr class for encrypting and decrypting environment variables
 * @class
 */
class EnvCryptr {
    /**
     * Creates an instance of EnvCryptr
     * @param {string} [token] - Optional JWT token for decryption
     * @throws {Error} If token is invalid or ENV_KEY is missing
     */
    constructor(token = null) {
        this.token = token;
        this.secret = null;

        if (token) {
            try {
                // Decode the token without verification
                const decoded = jose.decodeJwt(token);
                if (!decoded) {
                    throw new Error('Invalid JWT token format');
                }

                if (!decoded.ENV_KEY) {
                    throw new Error('ENV_KEY not found in token payload');
                }

                if (decoded.ENV_KEY.length !== 32) {
                    throw new Error('ENV_KEY must be 32 characters long');
                }

                this.secret = decoded.ENV_KEY;
            } catch (error) {
                throw new Error(`Failed to initialize from token: ${error.message}`);
            }
        }
    }

    /**
     * Encrypts environment variables into a JWT token
     * @param {Object} env - Object containing environment variables
     * @param {string} env.ENV_KEY - 32-character encryption key
     * @returns {string} JWT token containing encrypted values
     * @throws {Error} If ENV_KEY is missing or invalid
     */
    async encrypt(env) {
        if (!env.ENV_KEY) {
            throw new Error('ENV_KEY is required in process.env');
        }

        if (env.ENV_KEY.length !== 32) {
            throw new Error('ENV_KEY must be 32 characters long');
        }

        this.secret = env.ENV_KEY;
        const payload = {
            ENV_KEY: env.ENV_KEY
        };

        // Encrypt each environment variable
        for (let key in env) {
            if (key === 'ENV_KEY') continue;
            payload[key] = this.encryptValue(env[key], this.secret);
        }

        // Create JWT with jose
        const secret = new TextEncoder().encode(this.secret);
        this.token = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'HS256' })
            .sign(secret);

        return this.token;
    }

    /**
     * Decrypts a specific environment variable from the token
     * @param {string} envKey - Key of the environment variable to decrypt
     * @returns {string} Decrypted value
     * @throws {Error} If key not found or decryption fails
     */
    async decrypt(envKey) {
        if (!this.token || !this.secret) {
            throw new Error('No token or secret found. Initialize with token or run encrypt() first.');
        }

        try {
            const secret = new TextEncoder().encode(this.secret);
            const { payload } = await jose.jwtVerify(this.token, secret);

            if (!payload[envKey]) {
                throw new Error(`Key ${envKey} not found in token`);
            }

            if (envKey === 'ENV_KEY') {
                return payload[envKey];
            }

            return this.decryptValue(payload[envKey], this.secret);
        } catch (error) {
            throw error;
        }
    }

    // Helper function to encrypt a value using AES-256-CBC 
    encryptValue(value, secret) {
        // Generate a random salt
        const salt = crypto.randomBytes(16);
        // Derive a key using PBKDF2
        const key = crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha512');
        // Create a random 16-byte initialization vector
        const iv = crypto.randomBytes(16);
        // Create a cipher using the derived key and iv
        const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        let encrypted = cipher.update(value, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        // Create HMAC for authentication
        const hmac = crypto.createHmac('sha256', key)
            .update(encrypted)
            .digest('hex');
        // Return the salt, iv, hmac and encrypted text together, separated by ':'
        return salt.toString('hex') + ':' + iv.toString('hex') + ':' + hmac + ':' + encrypted;
    }

    // Helper function to decrypt the value
    decryptValue(encrypted, secret) {
        const parts = encrypted.split(':');
        if (parts.length !== 4) {
            throw new Error('Invalid encrypted format');
        }
        const salt = Buffer.from(parts[0], 'hex');
        const iv = Buffer.from(parts[1], 'hex');
        const hmac = parts[2];
        const encryptedText = parts[3];

        // Derive the same key using PBKDF2
        const key = crypto.pbkdf2Sync(secret, salt, 100000, 32, 'sha512');

        // Verify HMAC
        const calculatedHmac = crypto.createHmac('sha256', key)
            .update(encryptedText)
            .digest('hex');

        if (calculatedHmac !== hmac) {
            throw new Error('Message authentication failed');
        }

        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
}

export default EnvCryptr;