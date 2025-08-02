const express = require('express');
const cors = require('cors');
const { spawn } = require('child_process');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('frontend')); // Serve frontend files

// Store encrypted data temporarily (in production, use a database)
const tempStorage = new Map();

// Utility function to execute C programs
function executeC(command, args = []) {
    return new Promise((resolve, reject) => {
        const child = spawn(`./c_programs/${command}`, args, { 
            cwd: __dirname,
            stdio: ['pipe', 'pipe', 'pipe']
        });
        
        let stdout = '';
        let stderr = '';
        
        child.stdout.on('data', (data) => {
            stdout += data.toString();
        });
        
        child.stderr.on('data', (data) => {
            stderr += data.toString();
        });
        
        child.on('close', (code) => {
            if (code !== 0) {
                console.error(`Error executing ${command}:`, stderr);
                reject({ error: stderr || `Process exited with code ${code}` });
                return;
            }
            
            try {
                // Parse JSON output from C program
                const result = JSON.parse(stdout);
                resolve(result);
            } catch (parseError) {
                console.error('JSON parse error:', parseError);
                console.error('Raw output:', stdout);
                reject({ error: 'Invalid JSON response from C program' });
            }
        });
        
        child.on('error', (error) => {
            console.error(`Error spawning ${command}:`, error);
            reject({ error: error.message });
        });
    });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

// RSA Endpoints
app.post('/api/rsa/generate', async (req, res) => {
    try {
        const result = await executeC('rsa_keygen', []);
        
        res.json({
            ...result,
            publicKey: `n: ${result.publicKey.n}\ne: ${result.publicKey.e}`,
            privateKey: `n: ${result.privateKey.n}\nd: ${result.privateKey.d}`
        });
    } catch (error) {
        res.status(500).json(error);
    }
});

app.post('/api/rsa/encrypt', async (req, res) => {
    try {
        const { message, publicKey } = req.body;
        
        if (!message || !publicKey) {
            return res.status(400).json({ error: 'Message and public key are required' });
        }

        // Parse public key (expecting format "n: ...\ne: ...")
        const lines = publicKey.split('\n');
        const n = lines[0].replace('n: ', '').trim();
        const e = lines[1].replace('e: ', '').trim();

        const result = await executeC('rsa_encrypt', [message, n, e]);
        res.json(result);
    } catch (error) {
        res.status(500).json(error);
    }
});

app.post('/api/rsa/decrypt', async (req, res) => {
    try {
        const { privateKey, encryptedData } = req.body;
        
        if (!privateKey || !encryptedData) {
            return res.status(400).json({ error: 'Private key and encrypted data are required' });
        }

        // Parse private key
        const lines = privateKey.split('\n');
        const n = lines[0].replace('n: ', '').trim();
        const d = lines[1].replace('d: ', '').trim();

        const result = await executeC('rsa_decrypt', [encryptedData, n, d]);
        res.json(result);
    } catch (error) {
        res.status(500).json(error);
    }
});

// AES Endpoints (placeholder - you'll need to adapt your AES C code similarly)
app.post('/api/aes/generate', async (req, res) => {
    try {
        const { keySize = 128 } = req.body;
        const result = await executeC('aes', ['generate', keySize]);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'AES program not implemented yet' });
    }
});

app.post('/api/aes/encrypt', async (req, res) => {
    try {
        const { message, key } = req.body;
        const result = await executeC('aes', ['encrypt', message, key]);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'AES program not implemented yet' });
    }
});

app.post('/api/aes/decrypt', async (req, res) => {
    try {
        const { key, encryptedData } = req.body;
        
        if (!key || !encryptedData) {
            return res.status(400).json({ error: 'Key and encrypted data are required' });
        }
        
        const result = await executeC('aes', ['decrypt', encryptedData, key]);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'AES program not implemented yet' });
    }
});

// ElGamal Endpoints (placeholder)
app.post('/api/elgamal/generate', async (req, res) => {
    try {
        const result = await executeC('elgamal', ['generate']);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'ElGamal program not implemented yet' });
    }
});

app.post('/api/elgamal/encrypt', async (req, res) => {
    try {
        const { message, p, g, y } = req.body;
        const result = await executeC('elgamal', ['encrypt', message, p, g, y]);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'ElGamal program not implemented yet' });
    }
});

app.post('/api/elgamal/decrypt', async (req, res) => {
    try {
        const { x, p, encryptedData } = req.body;
        
        if (!x || !p || !encryptedData) {
            return res.status(400).json({ error: 'Private key (x), prime (p), and encrypted data are required' });
        }
        
        const result = await executeC('elgamal', ['decrypt', encryptedData, x, p]);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'ElGamal program not implemented yet' });
    }
});

// Diffie-Hellman Endpoints (placeholder)
app.post('/api/diffie-hellman/exchange', async (req, res) => {
    try {
        const result = await executeC('diffie_hellman', ['exchange']);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: 'Diffie-Hellman program not implemented yet' });
    }
});

// Serve frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Make sure to compile your C programs:');
    console.log('  gcc -o c_programs/rsa_keygen rsa_keygen.c -lgmp');
    console.log('  gcc -o c_programs/rsa_encrypt rsa_encrypt.c -lgmp');
    console.log('  gcc -o c_programs/rsa_decrypt rsa_decrypt.c -lgmp');
    console.log('  chmod +x c_programs/rsa_*');
});

module.exports = app;