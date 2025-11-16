const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3')
const { open } = require('sqlite');
const path=require('path');
const token=require('jsonwebtoken');
const app=express()
const bcrypt = require('bcrypt');
app.use(cors());
app.use(express.json());

let db = null;
const dbPath = path.join(__dirname, 'codesnippet.db');

const initializeDbAndServer = async () => {
    try {
        db = await open({
            filename:dbPath,
            driver: sqlite3.Database
        });
        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS snippets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                code TEXT NOT NULL,
                language TEXT,
                tags TEXT,
                public INTEGER DEFAULT 0,
                user_id INTEGER NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
        );
            `);
        app.listen(3000, () => {
            console.log("Server Running at http://localhost:3000/");
        });
    }catch (e) {
        console.log(`DB Error: ${e.message}`);
        process.exit(1);
    }
}
initializeDbAndServer();
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if(!name || !email || !password){
        return response.status(400).send("All fields are required");   
    }
    try{

      
        const userExistsQuery = `SELECT * FROM users WHERE email = ?`;
        const existingUser = await db.get(userExistsQuery, [email]);
        if (existingUser) {
            return res.status(400).send({ error: "Email already exists" });
        }
        const insertUserQuery = `
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?);
        `;
        const hashedPassword = await bcrypt.hash(password, 10);
        await db.run(insertUserQuery, [name, email, hashedPassword]);
        res.status(201).send({ message: "User registered successfully" });

    } catch (err) {
       
        res.status(500).send({ error: err.message });
    }


});
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).send({ error: "Email and password required" });
    }

    try {
        // MUST SELECT id and password
        const user = await db.get(
            `SELECT id, email, password FROM users WHERE email = ?`,
            [email]
        );

        if (!user) {
            return res.status(400).send({ error: "Invalid email or password" });
        }

        // Compare bcrypt hashed password
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).send({ error: "Invalid email or password" });
        }

       
        const jwtToken = token.sign(
            { userId: user.id },
            "MY_SECRET"
        );

        res.send({
            message: "User Logged In Successfully",
            token: jwtToken
        });

    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});

const authenticateUser=(req,res,next)=>{
    let authHeader = req.headers["authorization"];

    if (!authHeader) {
        return res.status(401).send({ error: "No token provided" });
    }

    const jwtToken = authHeader.split(" ")[1];

    token.verify(jwtToken, "MY_SECRET", (err, payload) => {
        if (err) {
            return res.status(401).send({ error: "Invalid JWT Token" });
        }
        req.userId = payload.userId;
        next();
    });

}
app.post('/snippets', authenticateUser, async (req, res) => {
    const { title, code, language, tags, public } = req.body;

    if (!title || !code) {
        return res.status(400).send({ error: "Title and code are required" });
    }

    try {
        const result = await db.run(
            `INSERT INTO snippets (title, code, language, tags, public, user_id)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
                title,
                code,
                language || null,
                tags ? tags.join(",") : null,
                public ? 1 : 0,
                req.userId
            ]
        );

        res.send({ message: "Snippet created successfully", id: result.lastID });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});
app.get('/snippets', authenticateUser, async (req, res) => {
    try {
        const snippets = await db.all(
            `SELECT * FROM snippets WHERE user_id = ? ORDER BY created_at DESC`,
            [req.userId]
        );

        res.send(snippets);
    } catch (err) {
        res.status(500).send({ error: err.message });
    }

});
app.get('/snippets/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;

    try {
        const snippet = await db.get(
            `SELECT * FROM snippets WHERE id = ? AND user_id = ?`,
            [id, req.userId]
        );

        if (!snippet) {
            return res.status(404).send({ error: "Snippet not found" });
        }

        res.send(snippet);
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});
app.put('/snippets/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const { title, code, language, tags, public } = req.body;

    try {
        const snippet = await db.get(
            `SELECT * FROM snippets WHERE id = ? AND user_id = ?`,
            [id, req.userId]
        );

        if (!snippet) {
            return res.status(404).send({ error: "Snippet not found" });
        }

        await db.run(
            `UPDATE snippets 
             SET title = ?, code = ?, language = ?, tags = ?, public = ?
             WHERE id = ?`,
            [
                title || snippet.title,
                code || snippet.code,
                language || snippet.language,
                tags ? tags.join(",") : snippet.tags,
                public ? 1 : snippet.public,
                id
            ]
        );

        res.send({ message: "Snippet updated successfully" });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});
app.delete('/snippets/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;

    try {
        const snippet = await db.get(
            `SELECT * FROM snippets WHERE id = ? AND user_id = ?`,
            [id, req.userId]
        );

        if (!snippet) {
            return res.status(404).send({ error: "Snippet not found" });
        }

        await db.run(`DELETE FROM snippets WHERE id = ?`, [id]);

        res.send({ message: "Snippet deleted successfully" });
    } catch (err) {
        res.status(500).send({ error: err.message });
    }
});
module.exports = app;
// eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOjEsImlhdCI6MTc2MzI2NjgwNH0._u4S7Ijv3v5OnI7jF4l3bmRVRl8lwRAx-c1I9FzKLW0