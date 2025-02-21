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
COMPLEX_VALUE='value with spaces and symbols !@#$%^&*()'
```

#### Encrypting .env file

Using flags:
```bash
# Print to console
npx env-cryptr -e -i .env.example

# Save to file
npx env-cryptr -e -i .env.example -o .env.encrypted
```

Using command:
```bash
# Print to console
npx env-cryptr encrypt -i .env.example

# Save to file
npx env-cryptr encrypt -i .env.example -o .env.encrypted
```

#### Decrypting .env file

Using flags:
```bash
# From file, print to console
npx env-cryptr -d -i .env.encrypted

# From file, save to file
npx env-cryptr -d -i .env.encrypted -o .env.decrypted
```

Using command:
```bash
# From file, print to console
npx env-cryptr decrypt -i .env.encrypted

# From file, save to file
npx env-cryptr decrypt -i .env.encrypted -o .env.decrypted

# From token, print to console
npx env-cryptr decrypt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# From token, save to file
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

## Command Options

### Encrypt Mode
```bash
# Using flags
env-cryptr -e -i <input-file> [-o output-file]

# Using command
env-cryptr encrypt -i <input-file> [-o output-file]
```

### Decrypt Mode
```bash
# Using flags with file
env-cryptr -d -i <input-file> [-o output-file]

# Using command with file
env-cryptr decrypt -i <input-file> [-o output-file]

# Using command with token
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
