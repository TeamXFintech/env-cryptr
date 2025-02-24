#!/usr/bin/env node

import { Command } from 'commander';
import dotenv from 'dotenv';
import * as fs from 'fs/promises';
import EnvCryptr from '../src/envCryptr.js';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { readFileSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const { version } = JSON.parse(
    readFileSync(join(__dirname, '../package.json'), 'utf8')
);

const program = new Command();

// Helper function for encryption
async function encryptAction(options) {
    try {
        const envConfig = dotenv.parse(await fs.readFile(options.input));
        const cryptr = new EnvCryptr();
        const token = await cryptr.encrypt(envConfig);

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
                // Read and clean the token from file
                token = (await fs.readFile(options.input, 'utf8'))
                    .toString()
                    .replace(/\s+/g, '')
                    .trim();

                if (!token) {
                    throw new Error('Empty token file');
                }

                // Basic validation of token format
                const parts = token.split('.');
                if (parts.length !== 3) {
                    throw new Error('Invalid JWT token format - must have three parts (header.payload.signature)');
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
            const decoded = cryptr.token ? JSON.parse(atob(token.split('.')[1])) : {};

            let envContent = '';
            for (const [key, value] of Object.entries(decoded)) {
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
            console.error('❌ Error:', error.message);
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

// Make functions available for testing
export { encryptAction, decryptAction }; 