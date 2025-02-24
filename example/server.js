import express from 'express';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();

// Serve static files from example directory
app.use(express.static(__dirname));
// Serve source files
app.use('/src', express.static(join(__dirname, '../src')));

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Demo running at http://localhost:${port}`);
}); 