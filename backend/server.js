const express = require('express');
const cors = require('cors');
const { exec } = require('child_process');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('../frontend')); // Serve frontend files from parent directory // Serve frontend files

// Store encrypted data temporarily (in production, use a database)
const tempStorage = new Map();

// Utility function to execute C programs
function executeC(command, args = []) {
    return new Promise((resolve, reject) => {
        const fullCommand = `./c_programs/${command} ${args.join(' ')}`;
        exec(fullCommand, { cwd: __dirname }, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing ${command}:`, error);
                reject({ error: stderr || error.message });
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
    });
}

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Server is running' });
});

// RSA Endpoints
app.post('/api/rsa/generate', async (req, res) => {
    try {
        const result = await executeC('rsa', ['generate']);
        
        // Store keys for this session (use session ID in production)
        const sessionId = Date.now().toString();
        tempStorage.set(`rsa_keys_${sessionId}`, result);
        
        res.json({
            ...result,
            sessionId: sessionId,
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

        const result = await executeC('rsa', ['encrypt', message, n, e]);
        
        // Store encrypted data for decryption
        const encryptedId = Date.now().toString();
        tempStorage.set(`rsa_encrypted_${encryptedId}`, result.encrypted);
        
        res.json({
            ...result,
            encryptedId: encryptedId
        });
    } catch (error) {
        res.status(500).json(error);
    }
});

app.post('/api/rsa/decrypt', async (req, res) => {
    try {
        const { privateKey, encryptedId } = req.body;
        
        if (!privateKey) {
            return res.status(400).json({ error: 'Private key is required' });
        }

        // Get the last encrypted message (or use encryptedId if provided)
        let encryptedHex;
        if (encryptedId) {
            encryptedHex = tempStorage.get(`rsa_encrypted_${encryptedId}`);
        } else {
            // Get the most recent encrypted message
            const keys = Array.from(tempStorage.keys()).filter(k => k.startsWith('rsa_encrypted_'));
            if (keys.length > 0) {
                const latestKey = keys[keys.length - 1];
                encryptedHex = tempStorage.get(latestKey);
            }
        }

        if (!encryptedHex) {
            return res.status(400).json({ error: 'No encrypted message found. Please encrypt a message first.' });
        }

        // Parse private key
        const lines = privateKey.split('\n');
        const n = lines[0].replace('n: ', '').trim();
        const d = lines[1].replace('d: ', '').trim();

        const result = await executeC('rsa', ['decrypt', encryptedHex, n, d]);
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
        const { key } = req.body;
        const result = await executeC('aes', ['decrypt', key]);
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
        const { x, p } = req.body;
        const result = await executeC('elgamal', ['decrypt', x, p]);
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
    res.sendFile(path.join(__dirname, '../frontend', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Make sure to compile your C programs:');
    console.log('  gcc -o c_programs/rsa rsa.c -lgmp');
    console.log('  chmod +x c_programs/rsa');
});

module.exports = app;