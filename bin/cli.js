#!/usr/bin/env node

import { program } from 'commander';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import EnvCryptr from '../src/envCryptr.js';
import jwt from 'jsonwebtoken';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const { version } = JSON.parse(
    readFileSync(join(__dirname, '../package.json'), 'utf8')
);

// Helper function for encryption
async function encryptAction(options) {
    try {
        // Load .env file
        const envConfig = dotenv.parse(await fs.readFile(options.input));

        // Create new instance and encrypt
        const cryptr = new EnvCryptr();
        const token = cryptr.encrypt(envConfig);

        // If output file is specified, save to file, otherwise print to console
        if (options.output) {
            await fs.writeFile(options.output, token);
            console.log(`✅ Environment variables encrypted and saved to ${options.output}`);
        } else {
            console.log(token);
        }
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

// Helper function for decryption
async function decryptAction(token, options) {
    try {
        // If token is not provided directly, try to read from file
        if (!token) {
            try {
                // Add debug logging
                const rawFileContent = await fs.readFile(options.input, 'utf8');

                // Read and clean the token from file - remove whitespace and newlines
                token = rawFileContent
                    .toString()
                    .replace(/\s+/g, '')
                    .trim();

                if (!token) {
                    throw new Error('Empty token file');
                }

                // Validate basic token format
                const parts = token.split('.');
                if (parts.length !== 3) {
                    throw new Error(`Invalid JWT token format - found ${parts.length} parts, expected 3 (header.payload.signature)`);
                }

                // Try to decode each part to validate base64url format
                try {
                    const header = Buffer.from(parts[0], 'base64url').toString();
                    const payload = Buffer.from(parts[1], 'base64url').toString();
                    JSON.parse(header);
                    JSON.parse(payload);
                } catch (error) {
                    throw new Error('Invalid JWT token format - parts must be valid base64url encoded JSON');
                }

            } catch (error) {
                if (error.code === 'ENOENT') {
                    console.error(`❌ File not found: ${options.input}`);
                } else {
                    console.error(`❌ Error reading file: ${error.message}`);
                }
                process.exit(1);
            }
        }

        try {
            const cryptr = new EnvCryptr(token);
            const payload = jwt.verify(token, cryptr.secret);

            let envContent = '';
            for (const [key, value] of Object.entries(payload)) {
                // Skip JWT-specific claims
                if (['iat', 'exp', 'nbf', 'sub', 'aud', 'iss'].includes(key)) {
                    continue;
                }

                try {
                    const decryptedValue = cryptr.decrypt(key);
                    envContent += `${key}=${decryptedValue}\n`;
                } catch (error) {
                    console.error(`❌ Warning: Could not decrypt ${key}: ${error.message}`);
                }
            }

            if (options.output) {
                await fs.writeFile(options.output, envContent);
                console.log(`✅ Token decrypted and saved to ${options.output}`);
            } else {
                console.log(envContent);
            }
        } catch (error) {
            if (error.name === 'JsonWebTokenError') {
                console.error('❌ Invalid token format or signature');
            } else {
                console.error('❌ Error:', error.message);
            }
            process.exit(1);
        }
    } catch (error) {
        console.error('❌ Error:', error.message);
        process.exit(1);
    }
}

program
    .name('env-cryptr')
    .description('CLI tool to encrypt and decrypt environment variables')
    .version(version)
    .option('-e, --encrypt', 'Encrypt mode')
    .option('-d, --decrypt', 'Decrypt mode')
    .option('-i, --input <path>', 'Input file path')
    .option('-o, --output <path>', 'Output file path (optional)')
    .addCommand(program.command('encrypt')
        .description('Encrypt a .env file into a JWT token')
        .option('-i, --input <path>', 'Input .env file path')
        .option('-o, --output <path>', 'Output file path for the token (optional)')
        .action((cmdOptions) => {
            const options = {
                input: cmdOptions.input || program.opts().input || '.env',
                output: cmdOptions.output || program.opts().output
            };
            encryptAction(options);
        }))
    .addCommand(program.command('decrypt')
        .description('Decrypt a JWT token back to .env format')
        .argument('[token]', 'JWT token to decrypt (optional)')
        .option('-i, --input <path>', 'Input encrypted file path')
        .option('-o, --output <path>', 'Output .env file path (optional)')
        .action((token, cmdOptions) => {
            // Use command options first, fall back to global options
            const options = {
                input: cmdOptions.input || program.opts().input,
                output: cmdOptions.output || program.opts().output
            };

            if (!token && !options.input) {
                console.error('❌ Error: Please provide either a token or input file (-i)');
                process.exit(1);
            }
            decryptAction(token, options);
        }))
    .action((options) => {
        if (options.encrypt && options.decrypt) {
            console.error('❌ Error: Cannot use both encrypt and decrypt modes simultaneously');
            process.exit(1);
        }

        if (options.encrypt) {
            if (!options.input) {
                console.error('❌ Error: Please provide an input file for encryption using -i');
                process.exit(1);
            }
            encryptAction(options);
        } else if (options.decrypt) {
            if (options.input) {
                decryptAction(null, { input: options.input, output: options.output });
            } else {
                console.error('❌ Error: Please provide an input file for decryption using -i');
                process.exit(1);
            }
        } else if (!program.args.length) {
            program.help();
        }
    });

program.parse(); 