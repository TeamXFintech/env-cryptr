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

    async verifyToken() {
        if (!this.token || !this.secret) {
            throw new Error('No token or secret found');
        }

        const secret = new TextEncoder().encode(this.secret);
        return jose.jwtVerify(this.token, secret);
    }

    encrypt() {
        throw new Error('Encryption is not supported in browser environment');
    }

    decrypt() {
        throw new Error('Decryption is not supported in browser environment');
    }
}

export default EnvCryptr; 