# env-cryptr 

A secure command-line tool to encrypt and decrypt environment variables using JWT tokens. Perfect for safely storing sensitive environment variables.

## Features

- 🔒 Encrypts .env files using AES-256-CBC encryption with enhanced security:
  - Random salt generation for each encryption
  - PBKDF2 key derivation (100,000 iterations)
  - HMAC-SHA256 message authentication
  - Unique salt:iv:hmac:ciphertext format
- 🎯 Uses JWT for secure token management
- 🚀 Simple CLI interface
- ⚡ Easy to use with any project
- 🔑 Secure key management

## Installation

You can install the package globally:
```bash
npm install -g env-cryptr
```

Or use it directly with npx:
```bash
npx env-cryptr <command>
```

## Usage

### As a CLI Tool

#### Basic Structure

Your .env file must include an `ENV_KEY` that will be used for encryption/decryption. This key MUST be 32 characters long.

```env
ENV_KEY=this-is-32-characters-secure-key
DATABASE_URL=mongodb://localhost:27017
API_KEY=your-secret-api-key
```

#### Encrypting .env file

Basic usage with flags, will print the encrypted token to console:
```bash
npx env-cryptr -e -i .env.example
```

With custom input/output paths:
```bash
npx env-cryptr -e -i .env.example -o .env.encrypted
```

Using command syntax:
```bash
npx env-cryptr encrypt -i .env.example -o .env.encrypted
```

#### Decrypting .env file

From a file, will print the decrypted .env to console:
```bash
npx env-cryptr -d -i .env.encrypted
```

From a file with output:
```bash
npx env-cryptr -d -i .env.encrypted -o .env.decrypted
```

Directly from a token:
```bash
npx env-cryptr decrypt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

With token and output file:
```bash
npx env-cryptr decrypt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9... -o .env.decrypted
```

### As a Node.js Module

Install the package:
```bash
npm install env-cryptr
```

Import and use in your code:

```javascript
import EnvCryptr from 'env-cryptr';

// Encrypt environment variables
const env = {
    ENV_KEY: 'this-is-32-characters-secure-key',
    DATABASE_URL: 'mongodb://localhost:27017',
    API_KEY: 'your-secret-api-key'
};

// Create a new instance for encryption
const cryptr = new EnvCryptr();
const token = cryptr.encrypt(env);
console.log('Encrypted token:', token);

// Initialize with an existing token for decryption
const decryptor = new EnvCryptr(token);

// Decrypt specific variables
const dbUrl = decryptor.decrypt('DATABASE_URL');
console.log('Decrypted DATABASE_URL:', dbUrl);

// Get all decrypted values
const allValues = Object.keys(env).reduce((acc, key) => {
    acc[key] = decryptor.decrypt(key);
    return acc;
}, {});
console.log('All decrypted values:', allValues);
```

### API Reference

#### `new EnvCryptr(token?: string)`
Creates a new instance of EnvCryptr. Optionally accepts an existing token for decryption.

#### `encrypt(env: object): string`
Encrypts an object containing environment variables. The object must include an ENV_KEY property that is 32 characters long.

#### `decrypt(key: string): string`
Decrypts a specific environment variable value from the token. Throws an error if the key doesn't exist or if decryption fails.

### Error Handling

```javascript
try {
    const cryptr = new EnvCryptr(token);
    const value = cryptr.decrypt('SOME_KEY');
} catch (error) {
    if (error.message.includes('ENV_KEY')) {
        console.error('Missing or invalid ENV_KEY');
    } else if (error.message.includes('not found')) {
        console.error('Key not found in token');
    } else if (error.message.includes('authentication failed')) {
        console.error('Token tampering detected');
    } else {
        console.error('Decryption error:', error.message);
    }
}
```

## Command Options

### Encrypt Mode
- `-e, --encrypt`: Encrypt mode
- `-i, --input <path>`: Input .env file path (default: ".env")
- `-o, --output <path>`: Output file path for the encrypted token (optional)

### Decrypt Mode
- `-d, --decrypt`: Decrypt mode with file input
- `-i, --input <path>`: Input encrypted file path
- `-o, --output <path>`: Output .env file path (optional)

### Direct Token Decrypt
```bash
env-cryptr decrypt <token> [-o output-file]
```

## Error Handling

The tool includes comprehensive error handling for common scenarios:
- Missing ENV_KEY
- Wrong length of ENV_KEY (must be 32 characters)
- Invalid file paths
- Corrupted encrypted files
- Invalid JWT tokens
- Token tampering detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT © [Mohd Khairulnizam](mailto:khairulnizam.md@rhbgroup.com)

## Support

If you encounter any issues or have questions, please file an issue on the GitHub repository.
