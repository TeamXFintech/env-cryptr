import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const { TextEncoder, TextDecoder } = require('text-encoding');

// Set up global mocks
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
