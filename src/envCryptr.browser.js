import * as jose from 'jose';

/**
 * Browser-compatible version of EnvCryptr
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
        this.decryptedValues = new Map(); // Store decrypted values in memory

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
                // Decrypt all values during initialization
                this.initializeDecryptedValues();
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

    async initializeDecryptedValues() {
        try {
            const secret = new TextEncoder().encode(this.secret);
            const { payload } = await jose.jwtVerify(this.token, secret);

            // Store ENV_KEY
            this.decryptedValues.set('ENV_KEY', payload.ENV_KEY);

            // Decrypt and store all other values
            for (const [key, value] of Object.entries(payload)) {
                if (key === 'ENV_KEY') continue;

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

                    const { plaintext } = await jose.compactDecrypt(value, secretKey);
                    this.decryptedValues.set(key, new TextDecoder().decode(plaintext));
                } catch (error) {
                    console.error(`Error decrypting ${key}:`, error);
                    // Skip failed decryptions but continue with others
                }
            }
        } catch (error) {
            console.error('Error initializing decrypted values:', error);
            throw error;
        }
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

        // Initialize decrypted values after encryption
        await this.initializeDecryptedValues();

        return this.token;
    }

    /**
     * Get a decrypted environment value
     * @param {string} envKey - Key of the environment variable to get
     * @returns {string} Decrypted value
     * @throws {Error} If key not found
     */
    decrypt(envKey) {
        if (!this.decryptedValues.has(envKey)) {
            throw new Error(`Key ${envKey} not found in token`);
        }
        return this.decryptedValues.get(envKey);
    }
}

export default EnvCryptr; 