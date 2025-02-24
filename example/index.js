import EnvCryptr from '../src/envCryptr.js';

// Remove imports and exports
function parseEnv(text) {
    const env = {};
    text.split('\n').forEach(line => {
        line = line.trim();
        if (!line || line.startsWith('#')) return;

        const [key, ...valueParts] = line.split('=');
        let value = valueParts.join('=');

        // Remove quotes if present
        if (value.startsWith("'") && value.endsWith("'") ||
            value.startsWith('"') && value.endsWith('"')) {
            value = value.slice(1, -1);
        }

        env[key.trim()] = value.trim();
    });
    return env;
}

// Wait for EnvCryptr to be available
document.addEventListener('DOMContentLoaded', () => {
    window.encrypt = function () {
        try {
            const envText = document.getElementById('envInput').value;
            const env = parseEnv(envText);

            const cryptr = new EnvCryptr();
            const token = cryptr.encrypt(env);

            document.getElementById('encryptResult').textContent = token;
            document.getElementById('encryptResult').className = 'success';

            // Auto-fill decrypt input
            document.getElementById('tokenInput').value = token;
        } catch (error) {
            document.getElementById('encryptResult').textContent = `Error: ${error.message}`;
            document.getElementById('encryptResult').className = 'error';
        }
    };

    window.decrypt = function () {
        try {
            const token = document.getElementById('tokenInput').value;
            const key = document.getElementById('keyInput').value;

            if (!key) throw new Error('Please enter a key to decrypt');

            const cryptr = new EnvCryptr(token);
            const value = cryptr.decrypt(key);

            document.getElementById('decryptResult').textContent = value;
            document.getElementById('decryptResult').className = 'success';
        } catch (error) {
            document.getElementById('decryptResult').textContent = `Error: ${error.message}`;
            document.getElementById('decryptResult').className = 'error';
        }
    };
});
