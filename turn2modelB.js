const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 4000;

// Middleware to parse JSON
app.use(express.json());

// Sample users with roles
const users = [
    {
        id: '1',
        username: 'admin',
        password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // hashed password for 'admin'
        roles: ['admin', 'user']
    },
    {
        id: '2',
        username: 'user1',
        password: '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // hashed password for 'user1'
        roles: ['user']
    }
];

const roles = ['admin', 'user'];

// Function to generate JWT
function generateJWT(user) {
    return jwt.sign({ id: user.id, username: user.username, roles: user.roles }, process.env.JWT_SECRET, {
        expiresIn: '1h'
    });
}

// Function to hash password
function hashPassword(password) {
    return bcrypt.hashSync(password, 10);
}

// Middleware to check if user is authenticated
function isAuthenticated(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        req.user = decoded;
        next();
    });
}

// Middleware to enforce role-based access control
function hasRole(requiredRole) {
    return (req, res, next) => {
        if (!req.user.roles.includes(requiredRole)) {
            return res.status(403).json({ message: 'Forbidden' });
        }
        next();
    };
}

// User Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(user => user.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = generateJWT(user);
    res.json({ token });
});

// Protected Route (accessible only to admins)
app.get('/admin', isAuthenticated, hasRole('admin'), (req, res) => {
    res.json({ message: 'This is an admin-only route' });
});

// Protected Route (accessible only to users)
app.get('/user', isAuthenticated, hasRole('user'), (req, res) => {
    res.json({ message: 'This is a user-only route' });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
