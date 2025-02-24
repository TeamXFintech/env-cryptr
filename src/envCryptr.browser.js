import * as jose from 'jose';

/**
 * Browser-compatible version of EnvCryptr
 * Note: This version only supports JWT operations, not encryption
 */
class EnvCryptr {
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

    // Helper function to convert string to base64url
    toBase64Url(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        return jose.base64url.encode(data);
    }

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

            try {
                const encoder = new TextEncoder();
                const secretKey = await jose.importJWK(
                    {
                        kty: 'oct',
                        k: this.toBase64Url(this.secret),
                        alg: 'A256GCM',
                        use: 'enc'
                    },
                    'A256GCM'
                );

                const encrypted = await new jose.CompactEncrypt(encoder.encode(value))
                    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
                    .encrypt(secretKey);

                payload[key] = encrypted;
            } catch (error) {
                console.error(`Error encrypting ${key}:`, error);
                throw error;
            }
        }

        // Create JWT
        const secret = new TextEncoder().encode(this.secret);
        this.token = await new jose.SignJWT(payload)
            .setProtectedHeader({ alg: 'HS256' })
            .sign(secret);

        return this.token;
    }

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

            try {
                const secretKey = await jose.importJWK(
                    {
                        kty: 'oct',
                        k: this.toBase64Url(this.secret),
                        alg: 'A256GCM',
                        use: 'enc'
                    },
                    'A256GCM'
                );

                const { plaintext } = await jose.compactDecrypt(payload[envKey], secretKey);
                return new TextDecoder().decode(plaintext);
            } catch (error) {
                console.error(`Error decrypting ${envKey}:`, error);
                throw error;
            }
        } catch (error) {
            console.error('Error in decrypt:', error);
            throw error;
        }
    }
}

export default EnvCryptr; 