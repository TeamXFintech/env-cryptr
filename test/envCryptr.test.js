import EnvCryptr from '../src/envCryptr.js';
import jwt from 'jsonwebtoken';

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

        it('should create instance with valid token', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const newCryptr = new EnvCryptr(token);
            expect(newCryptr.token).toBe(token);
            expect(newCryptr.secret).toBe(validEnv.ENV_KEY);
        });

        it('should throw error with invalid token', () => {
            expect(() => new EnvCryptr('invalid-token'))
                .toThrow('Failed to initialize from token: Invalid JWT token format');
        });

        it('should throw error with token missing ENV_KEY', () => {
            const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ.UIZchxQD36xuhacrJF9HQ5SIUxH5HBiv9noESAacsxU';
            expect(() => new EnvCryptr(token))
                .toThrow('Failed to initialize from token: ENV_KEY not found in token payload');
        });

        it('should throw error with token containing invalid length ENV_KEY', () => {
            // Create a JWT token directly with an invalid ENV_KEY
            const invalidToken = jwt.sign(
                { ENV_KEY: 'too-short-key' },
                'any-secret'
            );

            expect(() => new EnvCryptr(invalidToken))
                .toThrow('Failed to initialize from token: ENV_KEY must be 32 characters long');
        });
    });

    describe('encrypt', () => {
        it('should encrypt environment variables', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            expect(typeof token).toBe('string');
            expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
        });

        it('should throw error without ENV_KEY', () => {
            const cryptr = new EnvCryptr();
            const envWithoutKey = { ...validEnv };
            delete envWithoutKey.ENV_KEY;
            expect(() => cryptr.encrypt(envWithoutKey))
                .toThrow('ENV_KEY is required in process.env');
        });

        it('should preserve ENV_KEY in plain text', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
            expect(payload.ENV_KEY).toBe(validEnv.ENV_KEY);
        });

        it('should throw error with ENV_KEY shorter than 32 characters', () => {
            const cryptr = new EnvCryptr();
            const envWithShortKey = {
                ...validEnv,
                ENV_KEY: 'too-short-key'
            };
            expect(() => cryptr.encrypt(envWithShortKey))
                .toThrow('ENV_KEY must be 32 characters long');
        });

        it('should throw error with ENV_KEY longer than 32 characters', () => {
            const cryptr = new EnvCryptr();
            const envWithLongKey = {
                ...validEnv,
                ENV_KEY: 'this-key-is-definitely-longer-than-32-characters'
            };
            expect(() => cryptr.encrypt(envWithLongKey))
                .toThrow('ENV_KEY must be 32 characters long');
        });
    });

    describe('decrypt', () => {
        let cryptr;
        let token;

        beforeEach(() => {
            cryptr = new EnvCryptr();
            token = cryptr.encrypt(validEnv);
        });

        it('should decrypt all environment variables correctly', () => {
            const decryptedCryptr = new EnvCryptr(token);
            for (const [key, value] of Object.entries(validEnv)) {
                expect(decryptedCryptr.decrypt(key)).toBe(value);
            }
        });

        it('should handle complex values correctly', () => {
            const decryptedCryptr = new EnvCryptr(token);
            expect(decryptedCryptr.decrypt('COMPLEX_VALUE')).toBe(validEnv.COMPLEX_VALUE);
        });

        it('should throw error for non-existent key', () => {
            const decryptedCryptr = new EnvCryptr(token);
            expect(() => decryptedCryptr.decrypt('NON_EXISTENT_KEY'))
                .toThrow('Key NON_EXISTENT_KEY not found in token');
        });

        it('should throw error without initialization', () => {
            const cryptr = new EnvCryptr();
            expect(() => cryptr.decrypt('ANY_KEY'))
                .toThrow('No token or secret found. Initialize with token or run encrypt() first.');
        });
    });

    describe('security features', () => {
        it('should detect token tampering', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const [header, payload, signature] = token.split('.');
            const tamperedToken = `${header}.${payload}.${signature}.abc`;

            expect(() => new EnvCryptr(tamperedToken))
                .toThrow(/Failed to initialize from token:/);
        });

        it('should use different IVs for same value', () => {
            const cryptr = new EnvCryptr();
            const env1 = { ENV_KEY: validEnv.ENV_KEY, TEST: 'value' };
            const env2 = { ENV_KEY: validEnv.ENV_KEY, TEST: 'value' };

            const token1 = cryptr.encrypt(env1);
            const token2 = cryptr.encrypt(env2);

            const payload1 = JSON.parse(Buffer.from(token1.split('.')[1], 'base64').toString());
            const payload2 = JSON.parse(Buffer.from(token2.split('.')[1], 'base64').toString());

            expect(payload1.TEST).not.toBe(payload2.TEST);
        });

        it('should verify HMAC during decryption', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const decryptedCryptr = new EnvCryptr(token);

            // Mock the payload access to return tampered value
            jest.spyOn(decryptedCryptr, 'decrypt').mockImplementationOnce(() => {
                throw new Error('Message authentication failed');
            });

            expect(() => decryptedCryptr.decrypt('DATABASE_URL'))
                .toThrow('Message authentication failed');
        });
    });
}); 