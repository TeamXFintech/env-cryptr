#!/usr/bin/env node

import { program } from 'commander';
import dotenv from 'dotenv';
import fs from 'fs/promises';
import EnvCryptr from '../src/envCryptr.js';
import jwt from 'jsonwebtoken';

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
async function decryptAction(options) {
    try {
        // Read the token from file
        let token;
        try {
            token = (await fs.readFile(options.input, 'utf8')).trim();
            if (!token) {
                throw new Error('Empty token file');
            }
        } catch (error) {
            if (error.code === 'ENOENT') {
                console.error(`❌ File not found: ${options.input}`);
            } else {
                console.error(`❌ Error reading file: ${error.message}`);
            }
            process.exit(1);
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
    .version('1.0.0')
    .option('-e, --encrypt', 'Encrypt mode')
    .option('-d, --decrypt', 'Decrypt mode')
    .option('-i, --input <path>', 'Input file path')
    .option('-o, --output <path>', 'Output file path (optional)')
    .addCommand(program.command('encrypt')
        .description('Encrypt a .env file into a JWT token')
        .option('-i, --input <path>', 'Input .env file path', '.env')
        .option('-o, --output <path>', 'Output file path for the token (optional)')
        .action(encryptAction))
    .addCommand(program.command('decrypt')
        .description('Decrypt a JWT token back to .env format')
        .option('-i, --input <path>', 'Input encrypted file path', '.env.encrypted')
        .option('-o, --output <path>', 'Output .env file path (optional)')
        .action(decryptAction))
    .action((options) => {
        if (options.encrypt && options.decrypt) {
            console.error('❌ Error: Cannot use both encrypt and decrypt modes simultaneously');
            process.exit(1);
        }

        if (options.encrypt) {
            options.input = options.input || '.env';
            encryptAction(options);
        } else if (options.decrypt) {
            options.input = options.input || '.env.encrypted';
            decryptAction(options);
        } else if (!program.args.length) {
            program.help();
        }
    });

program.parse(); 