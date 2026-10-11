const express = require('express');
const sqlite3 = require('sqlite3');
const { execFile } = require('child_process');
const { isIP } = require('net');
const app = express();
const db = new sqlite3.Database(':memory:');
const html = value => value.replace(/[&<>"']/g, ch => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[ch]));
app.get('/user', (req, res) => {
    if (typeof req.query.username !== 'string') return res.sendStatus(400);
    db.get('SELECT * FROM users WHERE username = ?', [req.query.username], (err, row) => {
        if (err) return res.sendStatus(500);
        res.json(row || null);
    });
});
app.get('/hello', (req, res) => {
    if (typeof req.query.name !== 'string') return res.sendStatus(400);
    res.send(`<h1>Hello, ${html(req.query.name)}!</h1>`);
});
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // Lab target restricted to loopback; no arbitrary network scanning.
    if (typeof host !== 'string' || !isIP(host) || !['127.0.0.1', '::1'].includes(host)) return res.sendStatus(400);
    execFile('ping', ['-c', '1', host], {timeout: 3000}, (error, stdout) => {
        res.status(error ? 400 : 200).send(stdout);
    });
});
db.serialize(() => {
    db.run('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, role TEXT)');
    db.run("INSERT INTO users VALUES (1, 'admin', 'admin'), (2, 'alice', 'user')", err => {
        if (err) throw err;
        app.listen(Number(process.env.PORT || 3001), '127.0.0.1');
    });
});
