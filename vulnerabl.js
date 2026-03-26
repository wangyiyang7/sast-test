const express = require('express');
const mysql = require('mysql');
const app = express();

// Hardcoded credentials (CWE-798)
const DB_PASSWORD = 'SuperSecret123!';
const API_KEY = 'sk-1234567890abcdef';
const AWS_SECRET_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: DB_PASSWORD,
  database: 'users'
});

app.use(express.urlencoded({ extended: true }));

// SQL Injection (CWE-89)
app.get('/user', (req, res) => {
  const username = req.query.username;
  const query = "SELECT * FROM users WHERE name = '" + username + "'";
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// Cross-Site Scripting / XSS (CWE-79)
app.get('/search', (req, res) => {
  const term = req.query.q;
  res.send(`<h1>Results for: ${term}</h1>`);
});

// Path Traversal (CWE-22)
const fs = require('fs');
const path = require('path');
app.get('/file', (req, res) => {
  const filename = req.query.name;
  const content = fs.readFileSync('/var/data/' + filename, 'utf8');
  res.send(content);
});

// Command Injection (CWE-78)
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 3 ' + host, (err, stdout) => {
    res.send(`<pre>${stdout}</pre>`);
  });
});

// Insecure eval (CWE-95)
app.get('/calc', (req, res) => {
  const expression = req.query.expr;
  const result = eval(expression);
  res.json({ result });
});

// Weak crypto (CWE-328)
const crypto = require('crypto');
app.post('/register', (req, res) => {
  const password = req.body.password;
  const hash = crypto.createHash('md5').update(password).digest('hex');
  res.json({ hash });
});

// No HTTPS, no helmet, no rate limiting
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});