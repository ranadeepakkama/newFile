const express = require('express');
const crypto = require('crypto');
const cors = require('cors');
const sqlite3 = require('better-sqlite3');
const path = require('path');
const jwt = require('jsonwebtoken');
require("dotenv").config();
const bcrypt = require('bcryptjs');
const { resourceLimits } = require('worker_threads');

const app = express();
app.use(express.json());

const db = new sqlite3(databasePath);
// Database setup
const databasePath = path.join(__dirname, 'user.db');
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

    // Execute the queries
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
        req.user = user; // Attach user info to request
        next();
    });
};

app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    try{
        const getUser = `SELECT username, password FROM register WHERE username = ?`;
        db.get(getUser, [username], (err, user) => {
            if (err) {
                console.error('Error fetching user:', err.message);
                return res.status(500).json({ message: 'Error fetching user' });
            }

            if (!user) {
                return res.status(404).json({ message: 'User not found' });
            }else{
                // Validate the password
                const isPasswordValid = bcrypt.compareSync(password, user.password);
                if (!isPasswordValid) {
                    return res.status(401).json({ message: 'Invalid credentials' });
                }
                const token = jwt.sign({ username: user.username }, jwtSecret, { expiresIn: '1h' });
                res.status(200).json({ message: 'Login successful', token});
            }
        });

    }catch(e){
        res.status(505).json({message:e.message});
    }
});


app.post('/register', async (req,res) => {
    try{
        const {username,email,password} = req.body;
        const hashedPassword = bcrypt.hashSync(password, 10);
        const registerQuery = `INSERT INTO register (username,email,password) VALUES (?,?,?)`;
        const result = await db.run(registerQuery,[username,email,hashedPassword])
        console.log('New data is registered');
        res.status(201).json({ message: result });
    } catch(e){
        res.status(500).json({message: e.message})
    }
})





app.get('/userDetails',authenticateToken,(req, res) => {
    try {
        const getUserDetails = `SELECT * FROM register`;
        db.all(getUserDetails, (err, rows) => {
            if (err) {
                console.error('Error fetching user details:', err.message);
                return res.status(500).json({ message: 'Error fetching user details' });
            }
            res.status(200).json({ result: rows });
        });
    } catch (e) {
        console.error('Unexpected error:', e.message);
        res.status(500).json({ message: e.message });
    }
});

app.post('/todoPost/:userId',authenticateToken, async (req,res) => {
    const {task, status} = req.body
    let {userId} = req.params
    userId = userId.replace(":","")
    try{
        const newTodo = `INSERT INTO todo (task, status, userId) VALUES (?,?,?)`
        await db.run(newTodo, [task,status,userId])
        res.status(200).json({message:"new todo added successfully"})
    }catch(e){
        res.status(500).json({ message: e.message });
    }
    
})

app.get('/todoList/:userId', authenticateToken, (req, res) => {
    let { userId } = req.params; 
    userId = userId.replace(":","")

    try {
        const todoListQuery = `SELECT * FROM todo WHERE userId = ?`;
        db.all(todoListQuery, [userId], (err, list) => {
            if (err) {
                console.error('Error fetching todos:', err.message);
                return res.status(500).json({ message: 'Error fetching todos' });
            }
            console.log('Todos:', list); // Log the fetched todos
            res.status(200).json({ todos: list });
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

app.put('/updateTodo/:id', async (req, res) => {
    const id = req.params.id;
    const { task, status } = req.body; 
    try {
        const updateTodoQuery = `UPDATE todo SET task = ?, status = ? WHERE id = ?`;
        await db.run(updateTodoQuery, [task, status, id]);
        res.status(200).json({ message: 'Todo updated successfully' });
    } catch (error) {
        console.error('Error updating todo:', error);
        res.status(500).json({ error: 'Failed to update todo' });
    }
});


app.delete('/deleteTodo/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const deleteTodoQuery = 'DELETE FROM todo WHERE id = ?';
        await db.run(deleteTodoQuery, [id]);
        res.status(200).json({ message: 'Todo deleted successfully' });
    } catch (error) {
        console.error('Error deleting todo:', error);
        res.status(500).json({ error: 'Failed to delete todo' });
    }
});

// Start the serverclear
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:5050/`);
});

