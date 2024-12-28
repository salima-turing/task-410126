require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 4000;

app.use(express.json());

// Mock Database
const users = [];
const roles = {
    USER: 'USER',
    ADMIN: 'ADMIN',
};

// Middleware to check roles
const authorizeRoles = (requiredRoles) => {
    return (req, res, next) => {
        const token = req.headers['authorization']?.split(' ')[1];
        if (!token) return res.sendStatus(403);

        jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
            if (err) return res.sendStatus(403);
            // Check if user role is among the required roles
            if (requiredRoles.includes(user.role)) {
                req.user = user; // Attach user info to request
                next(); // Proceed to the next middleware/route
            } else {
                return res.sendStatus(403); // User is not authorized for this role
            }
        });
    };
};

// User Registration Example
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    if (!Object.values(roles).includes(role)) {
        return res.status(400).json({ message: 'Invalid role' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, password: hashedPassword, role }; // Include role in user object
    users.push(user);
    res.status(201).send('User registered');
});

// User Login Example
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    } else {
        return res.status(401).send('Invalid credentials');
    }
});

// Protected Route Example
app.get('/admin', authorizeRoles([roles.ADMIN]), (req, res) => {
    res.json({ message: "Welcome Admin", user: req.user });
});

app.get('/user', authorizeRoles([roles.USER, roles.ADMIN]), (req, res) => {
    res.json({ message: "Welcome User", user: req.user });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
