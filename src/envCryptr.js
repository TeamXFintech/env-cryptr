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
        for (const [key, value] of Object.entries(env)) {
            if (key === 'ENV_KEY') continue;

            // Use jose's encryption with a consistent key
            const encoder = new TextEncoder();
            const secretKey = await jose.importJWK(
                {
                    kty: 'oct',
                    k: Buffer.from(this.secret).toString('base64url'),
                    alg: 'A256GCM',
                    use: 'enc'
                },
                'A256GCM'
            );

            const encrypted = await new jose.CompactEncrypt(encoder.encode(value))
                .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                .encrypt(secretKey);

            payload[key] = encrypted;
        }

        // Create JWT
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

            // Use the same key configuration for decryption
            const secretKey = await jose.importJWK(
                {
                    kty: 'oct',
                    k: Buffer.from(this.secret).toString('base64url'),
                    alg: 'A256GCM',
                    use: 'enc'
                },
                'A256GCM'
            );

            const { plaintext } = await jose.compactDecrypt(payload[envKey], secretKey);
            return new TextDecoder().decode(plaintext);
        } catch (error) {
            throw error;
        }
    }
}

export default EnvCryptr;