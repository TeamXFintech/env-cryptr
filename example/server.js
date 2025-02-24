import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const port = 3000;

// Serve static files from example directory
app.use(express.static(__dirname));
// Serve the library from src directory
app.use('/src', express.static(join(__dirname, '../src')));

app.listen(port, () => {
    console.log(`Demo running at http://localhost:${port}`);
}); 