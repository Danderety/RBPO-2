// Assignment example; only DB seed, error handling and loopback binding added.
const express = require('express');
const app = express();
const sqlite3 = require('sqlite3');
app.use(express.urlencoded({ extended: true }));
const db = new sqlite3.Database(':memory:');
app.get('/user', (req, res) => {
    const username = req.query.username;
    db.get(`SELECT * FROM users WHERE username = '${username}'`, (err, row) => { // JS-01 CWE-89
        if (err) return res.status(400).json({error: 'query failed'});
        res.json(row || null);
    });
});
app.get('/hello', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello, ${name}!</h1>`); // JS-02 CWE-79
});
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const { exec } = require('child_process');
    exec(`ping -c 1 ${host}`, {timeout: 3000}, (error, stdout) => { // JS-03 CWE-78
        res.status(error ? 400 : 200).send(stdout);
    });
});
db.serialize(() => {
    db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)');
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')", err => {
        if (err) throw err;
        app.listen(Number(process.env.PORT || 3000), '127.0.0.1');
    });
});
