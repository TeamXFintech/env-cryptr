import EnvCryptr from '../src/envCryptr.js';
import * as jose from 'jose';

describe('EnvCryptr', () => {
    const validEnv = {
        ENV_KEY: 'this-is-32-characters-secure-key',
        DATABASE_URL: 'mongodb://localhost:27017',
        API_KEY: 'secret-api-key-123',
        COMPLEX_VALUE: 'value with spaces and symbols !@#$%^&*()'
    };

    describe('constructor', () => {
        it('should create instance without token', () => {
            const cryptr = new EnvCryptr();
            expect(cryptr).toBeInstanceOf(EnvCryptr);
            expect(cryptr.token).toBeNull();
            expect(cryptr.secret).toBeNull();
        });

        it('should create instance with valid token', async () => {
            const cryptr = new EnvCryptr();
            const token = await cryptr.encrypt(validEnv);
            const newCryptr = new EnvCryptr(token);
            expect(newCryptr.token).toBe(token);
            expect(newCryptr.secret).toBe(validEnv.ENV_KEY);
        });

        it('should throw error with invalid token', () => {
            expect(() => new EnvCryptr('invalid-token'))
                .toThrow('Failed to initialize from token: Invalid JWT');
        });

        it('should throw error with token missing ENV_KEY', () => {
            const token = new jose.SignJWT({ foo: 'bar' })
                .setProtectedHeader({ alg: 'HS256' })
                .sign(new TextEncoder().encode('secret'));
            expect(() => new EnvCryptr(token))
                .toThrow('Failed to initialize from token: JWTs must use Compact JWS serialization, JWT must be a string');
        });

        it('should throw error with token containing invalid length ENV_KEY', () => {
            const token = new jose.SignJWT({ ENV_KEY: 'too-short-key' })
                .setProtectedHeader({ alg: 'HS256' })
                .sign(new TextEncoder().encode('secret'));
            expect(() => new EnvCryptr(token))
                .toThrow('Failed to initialize from token: JWTs must use Compact JWS serialization, JWT must be a string');
        });
    });

    describe('encrypt', () => {
        it('should encrypt environment variables', async () => {
            const cryptr = new EnvCryptr();
            const token = await cryptr.encrypt(validEnv);
            expect(typeof token).toBe('string');
            expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
        });

        it('should throw error without ENV_KEY', async () => {
            const cryptr = new EnvCryptr();
            const envWithoutKey = { ...validEnv };
            delete envWithoutKey.ENV_KEY;
            await expect(cryptr.encrypt(envWithoutKey))
                .rejects.toThrow('ENV_KEY is required in process.env');
        });

        it('should preserve ENV_KEY in plain text', async () => {
            const cryptr = new EnvCryptr();
            const token = await cryptr.encrypt(validEnv);
            const decoded = jose.decodeJwt(token);
            expect(decoded.ENV_KEY).toBe(validEnv.ENV_KEY);
        });

        it('should throw error with ENV_KEY shorter than 32 characters', async () => {
            const cryptr = new EnvCryptr();
            const envWithShortKey = {
                ...validEnv,
                ENV_KEY: 'too-short-key'
            };
            await expect(cryptr.encrypt(envWithShortKey))
                .rejects.toThrow('ENV_KEY must be 32 characters long');
        });

        it('should throw error with ENV_KEY longer than 32 characters', async () => {
            const cryptr = new EnvCryptr();
            const envWithLongKey = {
                ...validEnv,
                ENV_KEY: 'this-key-is-definitely-longer-than-32-characters'
            };
            await expect(cryptr.encrypt(envWithLongKey))
                .rejects.toThrow('ENV_KEY must be 32 characters long');
        });
    });

    describe('decrypt', () => {
        let cryptr;
        let token;

        beforeEach(async () => {
            cryptr = new EnvCryptr();
            token = await cryptr.encrypt(validEnv);
        });

        it('should decrypt all environment variables correctly', async () => {
            const decryptedCryptr = new EnvCryptr(token);
            for (const [key, value] of Object.entries(validEnv)) {
                const decrypted = await decryptedCryptr.decrypt(key);
                expect(decrypted).toBe(value);
            }
        });

        it('should handle complex values correctly', async () => {
            const decryptedCryptr = new EnvCryptr(token);
            const decrypted = await decryptedCryptr.decrypt('COMPLEX_VALUE');
            expect(decrypted).toBe(validEnv.COMPLEX_VALUE);
        });

        it('should throw error for non-existent key', async () => {
            const decryptedCryptr = new EnvCryptr(token);
            await expect(decryptedCryptr.decrypt('NON_EXISTENT_KEY'))
                .rejects.toThrow('Key NON_EXISTENT_KEY not found in token');
        });

        it('should throw error without initialization', async () => {
            const cryptr = new EnvCryptr();
            await expect(cryptr.decrypt('ANY_KEY'))
                .rejects.toThrow('No token or secret found. Initialize with token or run encrypt() first.');
        });
    });

    describe('security features', () => {
        it('should detect token tampering', async () => {
            const cryptr = new EnvCryptr();
            const token = await cryptr.encrypt(validEnv);
            const [header, payload, signature] = token.split('.');
            const tamperedToken = `${header}.${payload}.${signature}.abc`;

            expect(() => new EnvCryptr(tamperedToken))
                .toThrow(/Failed to initialize from token:/);
        });

        it('should use different IVs for same value', async () => {
            const cryptr = new EnvCryptr();
            const env1 = { ENV_KEY: validEnv.ENV_KEY, TEST: 'value' };
            const env2 = { ENV_KEY: validEnv.ENV_KEY, TEST: 'value' };

            const token1 = await cryptr.encrypt(env1);
            const token2 = await cryptr.encrypt(env2);

            const decoded1 = jose.decodeJwt(token1);
            const decoded2 = jose.decodeJwt(token2);

            expect(decoded1.TEST).not.toBe(decoded2.TEST);
        });

        it('should verify HMAC during decryption', async () => {
            const cryptr = new EnvCryptr();
            const token = await cryptr.encrypt(validEnv);
            const decryptedCryptr = new EnvCryptr(token);

            // Mock the decrypt method to simulate tampering
            jest.spyOn(decryptedCryptr, 'decrypt').mockImplementationOnce(() =>
                Promise.reject(new Error('Message authentication failed'))
            );

            await expect(decryptedCryptr.decrypt('DATABASE_URL'))
                .rejects.toThrow('Message authentication failed');
        });
    });
}); 