import { jest } from '@jest/globals';
import dotenv from 'dotenv';
import EnvCryptr from '../src/envCryptr.js';

// Mock modules first
const mockFs = {
    readFile: jest.fn(),
    writeFile: jest.fn(),
    default: { readFile: jest.fn(), writeFile: jest.fn() }
};

jest.unstable_mockModule('fs/promises', () => mockFs);

// Mock Commander with named export
jest.unstable_mockModule('commander', () => ({
    Command: class {
        constructor() {
            return {
                name: jest.fn().mockReturnThis(),
                description: jest.fn().mockReturnThis(),
                version: jest.fn().mockReturnThis(),
                option: jest.fn().mockReturnThis(),
                action: jest.fn().mockReturnThis(),
                parse: jest.fn().mockReturnThis(),
                help: jest.fn().mockReturnThis(),
                command: jest.fn().mockReturnThis(),
                argument: jest.fn().mockReturnThis(),
                addCommand: jest.fn().mockReturnThis(),
                args: ['something'] // Prevent help from being called
            };
        }
    }
}));

// Then import the CLI module
const cli = await import('../bin/cli.js');
const { encryptAction, decryptAction } = cli;

// Mock console
const consoleSpy = {
    log: jest.spyOn(console, 'log').mockImplementation(() => { }),
    error: jest.spyOn(console, 'error').mockImplementation(() => { })
};

describe('CLI', () => {
    const mockEnv = {
        ENV_KEY: 'this-is-32-characters-secure-key',
        DATABASE_URL: 'mongodb://localhost:27017',
        API_KEY: 'secret-api-key-123'
    };

    beforeEach(() => {
        jest.clearAllMocks();
        process.exit = jest.fn();
    });

    describe('encrypt', () => {
        it('should encrypt env file to token', async () => {
            // Mock reading .env file
            mockFs.readFile.mockResolvedValue(
                Object.entries(mockEnv)
                    .map(([key, value]) => `${key}=${value}`)
                    .join('\n')
            );

            // Test file output
            await encryptAction({ input: '.env', output: '.env.encrypted' });

            expect(mockFs.writeFile).toHaveBeenCalledWith(
                '.env.encrypted',
                expect.any(String)
            );
            expect(consoleSpy.log).toHaveBeenCalledWith(
                expect.stringContaining('saved to .env.encrypted')
            );
        });

        it('should handle encryption errors', async () => {
            // Mock invalid env file
            mockFs.readFile.mockRejectedValue(new Error('File not found'));

            await encryptAction({ input: 'invalid.env' });

            expect(consoleSpy.error).toHaveBeenCalledWith(
                '❌ Error:',
                expect.any(String)
            );
            expect(process.exit).toHaveBeenCalledWith(1);
        });
    });

    describe('decrypt', () => {
        it('should decrypt token to env file', async () => {
            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(mockEnv);

            await decryptAction(token, { output: '.env.decrypted' });

            const writeCall = mockFs.writeFile.mock.calls[0];
            const writtenContent = writeCall[1];

            // Verify decrypted content
            const decryptedEnv = dotenv.parse(writtenContent);
            expect(decryptedEnv).toEqual(mockEnv);
            expect(consoleSpy.log).toHaveBeenCalledWith(
                expect.stringContaining('saved to .env.decrypted')
            );
        });

        it('should handle invalid token', async () => {
            await decryptAction('invalid.token', {});

            expect(consoleSpy.error).toHaveBeenCalledWith(
                '❌ Error:',
                expect.stringContaining('Invalid JWT')
            );
            expect(process.exit).toHaveBeenCalledWith(1);
        });

        it('should handle file reading errors', async () => {
            mockFs.readFile.mockRejectedValue(new Error('ENOENT'));

            await decryptAction(null, { input: 'invalid.token' });

            expect(consoleSpy.error).toHaveBeenCalledWith(
                '❌ Error reading file: ENOENT',
            );
            expect(process.exit).toHaveBeenCalledWith(1);
        });

        it('should skip JWT claims during decryption', async () => {
            const envWithClaims = {
                ...mockEnv,
                iat: 1234567890,
                exp: 9876543210
            };

            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(envWithClaims);

            await decryptAction(token, { output: '.env.decrypted' });

            const writeCall = mockFs.writeFile.mock.calls[0];
            const writtenContent = writeCall[1];
            const decryptedEnv = dotenv.parse(writtenContent);

            // JWT claims should not be in output
            expect(decryptedEnv).not.toHaveProperty('iat');
            expect(decryptedEnv).not.toHaveProperty('exp');
            expect(decryptedEnv).toEqual(mockEnv);
        });
    });

    describe('CLI and EnvCryptr compatibility', () => {
        it('should be compatible between CLI encryption and direct decryption', async () => {
            // Mock .env file content
            const envContent = `ENV_KEY=this-is-32-characters-secure-key
DATABASE_URL=mongodb://localhost:27017
API_KEY=secret-api-key-123`;

            // Mock fs read
            mockFs.readFile.mockResolvedValue(envContent);

            // Encrypt using CLI
            let encryptedToken;
            consoleSpy.log.mockImplementationOnce((token) => {
                encryptedToken = token;
            });

            await encryptAction({ input: '.env' });

            // Try to decrypt using EnvCryptr directly
            const cryptr = new EnvCryptr(encryptedToken);

            // Verify decrypted values match original
            expect(cryptr.decrypt('DATABASE_URL')).toBe('mongodb://localhost:27017');
            expect(cryptr.decrypt('API_KEY')).toBe('secret-api-key-123');
        });
    });
}); 