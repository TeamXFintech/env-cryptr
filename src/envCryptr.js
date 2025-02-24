/**
 * ChaCha20 is both secure and fast:
 * Security:
 * - Modern cipher (designed in 2008, widely adopted)
 * - No known vulnerabilities
 * - Recommended by IETF for TLS
 * - Used in WireGuard, Signal, and other secure protocols
 * - Better than AES against timing attacks
 */

// Minimal JWT implementation
const jwt = {
    decode: (token, _, noVerify = false) => {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) throw new Error('Invalid token format');

            const base64Decode = isBrowser ? atob : str =>
                Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();

            const payload = JSON.parse(base64Decode(parts[1]));
            return payload;
        } catch (e) {
            throw new Error('Invalid JWT');
        }
    },

    encode: (payload, secret) => {
        const header = { typ: 'JWT', alg: 'HS256' };
        const base64Encode = isBrowser ? btoa : str =>
            Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        const headerStr = base64Encode(JSON.stringify(header));
        const payloadStr = base64Encode(JSON.stringify(payload));
        return `${headerStr}.${payloadStr}.signature`;
    }
};

const isBrowser = typeof window !== 'undefined';

// Base64 helpers
const toBase64 = (str) => {
    return isBrowser
        ? btoa(str)
        : Buffer.from(str).toString('base64');
};

const fromBase64 = (str) => {
    return isBrowser
        ? atob(str)
        : Buffer.from(str, 'base64').toString();
};

// Generate random nonce
const generateNonce = () => {
    const nonce = new Uint8Array(12);
    if (isBrowser) {
        crypto.getRandomValues(nonce);
    } else {
        for (let i = 0; i < 12; i++) {
            nonce[i] = Math.floor(Math.random() * 256);
        }
    }
    return Array.from(nonce);
};

// ChaCha20 quarter round operation
const quarterRound = (state, a, b, c, d) => {
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl((state[d] ^ state[a]), 16);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl((state[b] ^ state[c]), 12);
    state[a] = (state[a] + state[b]) >>> 0;
    state[d] = rotl((state[d] ^ state[a]), 8);
    state[c] = (state[c] + state[d]) >>> 0;
    state[b] = rotl((state[b] ^ state[c]), 7);
};

// Rotate left operation
const rotl = (a, b) => ((a << b) | (a >>> (32 - b))) >>> 0;

// ChaCha20 block function
const chacha20Block = (key, nonce, counter) => {
    const state = new Uint32Array(16);

    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // Key
    for (let i = 0; i < 8; i++) {
        state[4 + i] = key[i];
    }

    // Counter
    state[12] = counter;

    // Nonce
    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];

    // Copy state
    const working = new Uint32Array(state);

    // 20 rounds (10 iterations of 2 rounds each)
    for (let i = 0; i < 10; i++) {
        // Column rounds
        quarterRound(working, 0, 4, 8, 12);
        quarterRound(working, 1, 5, 9, 13);
        quarterRound(working, 2, 6, 10, 14);
        quarterRound(working, 3, 7, 11, 15);
        // Diagonal rounds
        quarterRound(working, 0, 5, 10, 15);
        quarterRound(working, 1, 6, 11, 12);
        quarterRound(working, 2, 7, 8, 13);
        quarterRound(working, 3, 4, 9, 14);
    }

    // Add working state to initial state
    for (let i = 0; i < 16; i++) {
        working[i] = (working[i] + state[i]) >>> 0;
    }

    return working;
};

// ChaCha20 encryption
const chachaEncrypt = (text, key) => {
    const nonce = generateNonce();
    const keyBytes = Array.from(key).map(c => c.charCodeAt(0));
    const textBytes = Array.from(text).map(c => c.charCodeAt(0));

    // Convert key to 32-bit words
    const keyWords = new Uint32Array(8);
    for (let i = 0; i < 32; i += 4) {
        keyWords[i >> 2] = (
            (keyBytes[i & 31] << 24) |
            (keyBytes[(i + 1) & 31] << 16) |
            (keyBytes[(i + 2) & 31] << 8) |
            keyBytes[(i + 3) & 31]
        );
    }

    // Encrypt blocks
    let counter = 1;
    let result = '';
    for (let i = 0; i < textBytes.length; i += 64) {
        const block = chacha20Block(keyWords, nonce, counter++);
        const blockBytes = new Uint8Array(block.buffer);
        for (let j = 0; j < 64 && i + j < textBytes.length; j++) {
            result += String.fromCharCode(textBytes[i + j] ^ blockBytes[j]);
        }
    }

    // Prepend nonce to result
    const nonceStr = String.fromCharCode(...nonce);
    return toBase64(nonceStr + result);
};

// ChaCha20 decryption
const chachaDecrypt = (encoded, key) => {
    const text = fromBase64(encoded);

    // Extract nonce from first 12 bytes
    const nonce = Array.from(text.slice(0, 12)).map(c => c.charCodeAt(0));
    const encryptedText = text.slice(12);
    const textBytes = Array.from(encryptedText).map(c => c.charCodeAt(0));

    // Convert key to 32-bit words
    const keyBytes = Array.from(key).map(c => c.charCodeAt(0));
    const keyWords = new Uint32Array(8);
    for (let i = 0; i < 32; i += 4) {
        keyWords[i >> 2] = (
            (keyBytes[i & 31] << 24) |
            (keyBytes[(i + 1) & 31] << 16) |
            (keyBytes[(i + 2) & 31] << 8) |
            keyBytes[(i + 3) & 31]
        );
    }

    // Decrypt blocks
    let counter = 1;
    let result = '';
    for (let i = 0; i < textBytes.length; i += 64) {
        const block = chacha20Block(keyWords, nonce, counter++);
        const blockBytes = new Uint8Array(block.buffer);
        for (let j = 0; j < 64 && i + j < textBytes.length; j++) {
            result += String.fromCharCode(textBytes[i + j] ^ blockBytes[j]);
        }
    }

    return result;
};

/**
 * EnvCryptr class for encrypting and decrypting environment variables
 */
const EnvCryptr = (() => {
    // Private WeakMaps to store instance data
    const decryptedValues = new WeakMap();
    const secrets = new WeakMap();

    return class {
        /**
         * Creates an instance of EnvCryptr
         * @param {string} [token] - Optional JWT token for decryption
         * @throws {Error} If token is invalid or ENV_KEY is missing
         */
        constructor(token = null) {
            this.token = token;
            secrets.set(this, null);
            decryptedValues.set(this, new Map());

            if (token) {
                try {
                    const decoded = jwt.decode(token, '', true);
                    if (!decoded) {
                        throw new Error('Invalid JWT token format');
                    }

                    if (!decoded.ENV_KEY) {
                        throw new Error('ENV_KEY not found in token payload');
                    }

                    if (decoded.ENV_KEY.length !== 32) {
                        throw new Error('ENV_KEY must be 32 characters long');
                    }

                    secrets.set(this, decoded.ENV_KEY);
                    this.initializeDecryptedValues();
                } catch (error) {
                    throw new Error(`Failed to initialize from token: ${error.message}`);
                }
            }
        }

        initializeDecryptedValues() {
            const values = decryptedValues.get(this);
            const secret = secrets.get(this);
            const decoded = jwt.decode(this.token, secret);

            // Store ENV_KEY
            values.set('ENV_KEY', decoded.ENV_KEY);

            // Decrypt and store all other values
            for (const [key, value] of Object.entries(decoded)) {
                if (key === 'ENV_KEY') continue;

                try {
                    const decrypted = chachaDecrypt(value, secret);
                    values.set(key, decrypted);
                } catch (error) {
                    console.error(`Error decrypting ${key}:`, error);
                }
            }
        }

        encrypt(env) {
            if (!env.ENV_KEY) {
                throw new Error('ENV_KEY is required in process.env');
            }

            if (env.ENV_KEY.length !== 32) {
                throw new Error('ENV_KEY must be 32 characters long');
            }

            secrets.set(this, env.ENV_KEY);
            const secret = secrets.get(this);
            const payload = {
                ENV_KEY: env.ENV_KEY
            };

            // Encrypt each environment variable
            for (const [key, value] of Object.entries(env)) {
                if (key === 'ENV_KEY') continue;

                try {
                    const encrypted = chachaEncrypt(value, secret);
                    payload[key] = encrypted;
                } catch (error) {
                    console.error(`Error encrypting ${key}:`, error);
                    throw error;
                }
            }

            // Create JWT
            this.token = jwt.encode(payload, secret);
            this.initializeDecryptedValues();
            return this.token;
        }

        /**
         * Get a decrypted environment value
         * @param {string} envKey - Key of the environment variable to get
         * @returns {string} Decrypted value
         * @throws {Error} If key not found
         */
        decrypt(envKey) {
            const values = decryptedValues.get(this);
            if (!values.has(envKey)) {
                throw new Error(`Key ${envKey} not found in token`);
            }
            return values.get(envKey);
        }
    };
})();

export default EnvCryptr;