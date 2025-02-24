import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { TextEncoder, TextDecoder } = require('text-encoding');

if (typeof global.TextEncoder === 'undefined') {
    global.TextEncoder = TextEncoder;
}

if (typeof global.TextDecoder === 'undefined') {
    global.TextDecoder = TextDecoder;
} 