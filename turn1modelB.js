require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware to parse JSON
app.use(express.json());

// Example of encrypting data using CryptoJS
const CryptoJS = require('crypto-js');

function encryptData(data, key) {
    try {
        const encrypted = CryptoJS.AES.encrypt(data, key).toString();
        return encrypted;
    } catch (error) {
        console.error('Error encrypting data:', error);
        return null;
    }
}

function decryptData(encryptedData, key) {
    try {
        const bytes = CryptoJS.AES.decrypt(encryptedData, key);
        return bytes.toString(CryptoJS.enc.Utf8);
    } catch (error) {
        console.error('Error decrypting data:', error);
        return null;
    }
}

function generateJWT(payload, secret, expiration) {
    try {
        const options = { expiresIn: expiration };
        return jwt.sign(payload, secret, options);
    } catch (error) {
        console.error('Error generating JWT:', error);
        return null;
    }
}

// Example of verifying a JWT using jsonwebtoken
function verifyJWT(token, secret) {
    try {
        return jwt.verify(token, secret);
    } catch (error) {
        console.error('Error verifying JWT:', error);
        return null;
    }
}

// User Registration Example
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const encryptedUsername = encryptData(username, process.env.ENCRYPTION_KEY);

    // Store hashedPassword and encryptedUsername in a database (mocked here)
    const user = { username: encryptedUsername, password: hashedPassword };
    // Save `user` to your database...

    res.status(201).send('User registered');
});

// User Login Example
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Fetch user from database (mocked here)
    const user = { username: encryptData(username, process.env.ENCRYPTION_KEY), password: 'hashed_password_from_db' }; // Replace with real user fetching logic

    if (user && await bcrypt.compare(password, user.password)) {
        const token = generateJWT({ username: user.username }, process.env.JWT_SECRET,{ expiresIn: '1h' })
        res.json({ token });
    } else {
        res.status(401).send('Invalid credentials');
    }
});

// Protected Route Example
app.get('/protected', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(403);
    verifyJWT(token, process.env.JWT_SECRET)
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
