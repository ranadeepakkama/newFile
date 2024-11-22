const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const jwt = require('jsonwebtoken');
require('dotenv').config();
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());

// Database setup
const databasePath = path.join(__dirname, 'user.db');
const db = new sqlite3.Database(databasePath, (err) => {
    if (err) {
        console.error('Error connecting to SQLite database:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        createTables(); // Ensure tables are created on start
    }
});

const jwtSecret = crypto.randomBytes(64).toString('hex');
const PORT = process.env.PORT || 4040;

// Table creation function
const createTables = () => {
    const createUserTable = `
        CREATE TABLE IF NOT EXISTS register (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) NOT NULL,
            password VARCHAR(255) NOT NULL
        )`;

    const createTodoTable = `
        CREATE TABLE IF NOT EXISTS todo (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            task VARCHAR(255) NOT NULL,
            status VARCHAR(255) NOT NULL,
            userId VARCHAR(255) NOT NULL
        )`;

    db.serialize(() => {
        db.run(createUserTable, (err) => {
            if (err) {
                console.error('Error creating register table:', err.message);
            } else {
                console.log('Register table created or already exists.');
            }
        });

        db.run(createTodoTable, (err) => {
            if (err) {
                console.error('Error creating todo table:', err.message);
            } else {
                console.log('Todo table created or already exists.');
            }
        });
    });
};

// CORS setup
app.use(
    cors({
        origin: 'http://localhost:3000',
    })
);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'No token provided' });
    }

    const token = authHeader.split(' ')[1];
    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user; 
        next();
    });
};

// Endpoints

// User login
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    const getUser = `SELECT username, password FROM register WHERE username = ?`;
    db.get(getUser, [username], (err, user) => {
        if (err) {
            console.error('Error fetching user:', err.message);
            return res.status(500).json({ message: 'Error fetching user' });
        }

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const isPasswordValid = bcrypt.compareSync(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
        res.status(200).json({ message: 'Login successful', token });
    });
});

// User registration
app.post('/register', (req, res) => {
    const { username, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    const registerQuery = `INSERT INTO register (username, email, password) VALUES (?, ?, ?)`;
    db.run(registerQuery, [username, email, hashedPassword], function (err) {
        if (err) {
            console.error('Error registering user:', err.message);
            return res.status(500).json({ message: 'Error registering user' });
        }
        res.status(201).json({ message: 'User registered successfully', id: this.lastID });
    });
});

// Get user details
app.get('/userDetails',authenticateToken, (req, res) => {
    const getUserDetails = `SELECT * FROM register`;
    db.all(getUserDetails,[userId], (err, rows) => {
        if (err) {
            console.error('Error fetching user details:', err.message);
            res.status(500).json({ message: 'Error fetching user details' });
        }
        res.status(200).json({result : rows});
    });
});

// Add a new todo
app.post('/todoPost/:userId',authenticateToken, (req, res) => {
    const { task, status } = req.body;
    const userId = req.params.userId;

    const newTodo = `INSERT INTO todo (task, status, userId) VALUES (?, ?, ?)`;
    db.run(newTodo, [task, status, userId], function (err) {
        if (err) {
            console.error('Error adding todo:', err.message);
            return res.status(500).json({ message: 'Error adding todo' });
        }
        res.status(200).json({ message: 'New todo added successfully', id: this.lastID });
    });
});

// Get user's todo list
app.get('/todoList/:userId',authenticateToken, (req, res) => {
    const userId = req.params.userId;

    const todoListQuery = `SELECT * FROM todo WHERE userId = ${sumo}`;
    db.all(todoListQuery, [userId], (err, list) => {
        if (err) {
            console.error('Error fetching todos:', err.message);
            return res.status(500).json({ message: 'Error fetching todos' });
        }
        res.status(200).json({ todos: list });
    });
});

// Update a todo
app.put('/updateTodo/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    const { task, status } = req.body;

    const updateTodoQuery = `UPDATE todo SET task = ?, status = ? WHERE id = ?`;
    db.run(updateTodoQuery, [task, status, id], function (err) {
        if (err) {
            console.error('Error updating todo:', err.message);
            return res.status(500).json({ message: 'Failed to update todo' });
        }
        res.status(200).json({ message: 'Todo updated successfully' });
    });
});

// Delete a todo
app.delete('/deleteTodo/:id', (req, res) => {
    const id = req.params.id;

    const deleteTodoQuery = `DELETE FROM todo WHERE id = ?`;
    db.run(deleteTodoQuery, [id], function (err) {
        if (err) {
            console.error('Error deleting todo:', err.message);
            return res.status(500).json({ message: 'Failed to delete todo' });
        }
        res.status(200).json({ message: 'Todo deleted successfully' });
    });
});


app.delete('/deleteUsers', (req, res) => {
    try{
        const deleteQuery = `DELETE FROM register`
        db.run(deleteQuery)
        res.status(200).json({message: 'successfully deleted'})
    }catch(err){
        res.status(500).json({message: err.message})
    }
})

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
