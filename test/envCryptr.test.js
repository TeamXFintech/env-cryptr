import EnvCryptr from '../src/envCryptr.js';
import { jest } from '@jest/globals';

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
        });

        it('should create instance with valid token', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const newCryptr = new EnvCryptr(token);

            expect(newCryptr.token).toBe(token);
            // Test secret indirectly through decryption
            expect(newCryptr.decrypt('ENV_KEY')).toBe(validEnv.ENV_KEY);
        });

        it('should throw error with invalid token', () => {
            expect(() => new EnvCryptr('invalid-token'))
                .toThrow('Failed to initialize from token');
        });

        it('should throw error with token missing ENV_KEY', () => {
            const cryptr = new EnvCryptr();
            const env = { ...validEnv };
            delete env.ENV_KEY;
            expect(() => cryptr.encrypt(env))
                .toThrow('ENV_KEY is required in process.env');
        });

        it('should throw error with invalid ENV_KEY length', () => {
            const cryptr = new EnvCryptr();
            const env = { ...validEnv, ENV_KEY: 'too-short' };
            expect(() => cryptr.encrypt(env))
                .toThrow('ENV_KEY must be 32 characters long');
        });
    });

    describe('encrypt', () => {
        it('should encrypt environment variables', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            expect(typeof token).toBe('string');
            expect(token.split('.')).toHaveLength(3); // JWT format: header.payload.signature
        });

        it('should create unique tokens for same data', () => {
            const cryptr = new EnvCryptr();
            const token1 = cryptr.encrypt(validEnv);
            const token2 = cryptr.encrypt(validEnv);
            const token3 = cryptr.encrypt(validEnv);

            // Tokens should be different due to random nonce
            expect(token1).not.toBe(token2);
            expect(token2).not.toBe(token3);
            expect(token3).not.toBe(token1);

            // But should decrypt to same values
            const cryptr1 = new EnvCryptr(token1);
            const cryptr2 = new EnvCryptr(token2);
            const cryptr3 = new EnvCryptr(token3);

            for (const key of Object.keys(validEnv)) {
                const value1 = cryptr1.decrypt(key);
                const value2 = cryptr2.decrypt(key);
                const value3 = cryptr3.decrypt(key);
                expect(value1).toBe(value2);
                expect(value2).toBe(value3);
            }
        });

        it('should handle special characters and long strings', () => {
            const cryptr = new EnvCryptr();
            const specialEnv = {
                ENV_KEY: 'this-is-32-characters-secure-key',
                SPECIAL: '!@#$%^&*()',
                UNICODE: '你好世界',
                SPACES: '  value  with  spaces  ',
                LONG: 'x'.repeat(1000), // Test long string
            };

            const token = cryptr.encrypt(specialEnv);
            const newCryptr = new EnvCryptr(token);

            for (const [key, value] of Object.entries(specialEnv)) {
                expect(newCryptr.decrypt(key)).toBe(value);
            }
        });

        it('should handle multi-block encryption', () => {
            const cryptr = new EnvCryptr();
            const longEnv = {
                ENV_KEY: 'this-is-32-characters-secure-key',
                BLOCK1: 'a'.repeat(64),  // One block
                BLOCK2: 'b'.repeat(65),  // Just over one block
                BLOCK3: 'c'.repeat(128), // Two blocks
                BLOCK4: 'd'.repeat(200)  // Multiple blocks
            };

            const token = cryptr.encrypt(longEnv);
            const newCryptr = new EnvCryptr(token);

            for (const [key, value] of Object.entries(longEnv)) {
                expect(newCryptr.decrypt(key)).toBe(value);
            }
        });
    });

    describe('decrypt', () => {
        it('should decrypt all values correctly', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const newCryptr = new EnvCryptr(token);

            for (const [key, value] of Object.entries(validEnv)) {
                expect(newCryptr.decrypt(key)).toBe(value);
            }
        });

        it('should throw error for non-existent key', () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(validEnv);
            const newCryptr = new EnvCryptr(token);

            expect(() => newCryptr.decrypt('NON_EXISTENT'))
                .toThrow('Key NON_EXISTENT not found in token');
        });
    });

    describe('environment compatibility', () => {
        it('should work in both Node.js and browser environments', () => {
            // Mock browser environment
            const originalWindow = global.window;
            global.window = {};
            global.btoa = str => Buffer.from(str).toString('base64');
            global.atob = str => Buffer.from(str, 'base64').toString();

            const browserCryptr = new EnvCryptr();
            const browserToken = browserCryptr.encrypt(validEnv);

            // Restore Node.js environment
            global.window = originalWindow;
            delete global.btoa;
            delete global.atob;

            const nodeCryptr = new EnvCryptr(browserToken);

            // Values should be the same in both environments
            for (const [key, value] of Object.entries(validEnv)) {
                expect(nodeCryptr.decrypt(key)).toBe(value);
            }
        });
    });
}); 