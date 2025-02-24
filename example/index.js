// Import and re-export jose for browser use
export { default as jose } from 'https://cdn.skypack.dev/jose';

import EnvCryptr from '@env-cryptr/browser';

function parseEnv(text) {
    const env = {};
    text.split('\n').forEach(line => {
        const [key, ...valueParts] = line.split('=');
        if (key && valueParts.length) {
            env[key.trim()] = valueParts.join('=').trim();
        }
    });
    return env;
}

window.encrypt = async function () {
    try {
        const envText = document.getElementById('envInput').value;
        const env = parseEnv(envText);

        const cryptr = new EnvCryptr();
        const token = await cryptr.encrypt(env);

        document.getElementById('encryptResult').textContent = token;
        document.getElementById('encryptResult').className = 'success';

        // Auto-fill decrypt input
        document.getElementById('tokenInput').value = token;
    } catch (error) {
        document.getElementById('encryptResult').textContent = `Error: ${error.message}`;
        document.getElementById('encryptResult').className = 'error';
    }
};

window.decrypt = async function () {
    try {
        const token = document.getElementById('tokenInput').value;
        const key = document.getElementById('keyInput').value;

        if (!key) throw new Error('Please enter a key to decrypt');

        const cryptr = new EnvCryptr(token);
        const value = await cryptr.decrypt(key);

        document.getElementById('decryptResult').textContent = value;
        document.getElementById('decryptResult').className = 'success';
    } catch (error) {
        document.getElementById('decryptResult').textContent = `Error: ${error.message}`;
        document.getElementById('decryptResult').className = 'error';
    }
};
