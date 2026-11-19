require('dotenv').config();
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise');

const {
  DB_HOST = 'localhost', DB_PORT = 3306, DB_USER = 'root', DB_PASSWORD = '',
  DB_NAME = 'auth_site', SESSION_SECRET, PORT = 3000,
} = process.env;

if (!/^[A-Za-z0-9_]+$/.test(DB_NAME)) throw new Error('DB_NAME may only contain letters, numbers and _');

const app = express();
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7 },
}));

let pool;
async function initDb() {
  const base = { host: DB_HOST, port: Number(DB_PORT), user: DB_USER, password: DB_PASSWORD };
  const conn = await mysql.createConnection(base);
  await conn.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4`);
  await conn.end();
  pool = mysql.createPool({ ...base, database: DB_NAME, connectionLimit: 10 });
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(80) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
}

const emailOk = (s) => typeof s === 'string' && s.length <= 255 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);

function startSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = user.id;
      req.session.save((e) => (e ? reject(e) : resolve()));
    });
  });
}

app.post('/api/signup', async (req, res) => {
  try {
    const name = String(req.body.name || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!name || name.length > 80) return res.status(400).json({ error: 'Enter your name (up to 80 characters).' });
    if (!emailOk(email)) return res.status(400).json({ error: 'Enter a valid email address.' });
    if (password.length < 8 || password.length > 72) return res.status(400).json({ error: 'Password must be 8 to 72 characters.' });

    const hash = await bcrypt.hash(password, 12);
    const [result] = await pool.execute('INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)', [name, email, hash]);
    await startSession(req, { id: result.insertId });
    res.json({ ok: true });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'That email is already registered. Try logging in.' });
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const [rows] = await pool.execute('SELECT id, password_hash FROM users WHERE email = ?', [email]);
    const user = rows[0];
    const ok = user && (await bcrypt.compare(password, user.password_hash));
    if (!ok) return res.status(401).json({ error: 'Email or password is incorrect.' });
    await startSession(req, user);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong. Try again.' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not logged in.' });
  const [rows] = await pool.execute('SELECT name, email, created_at FROM users WHERE id = ?', [req.session.userId]);
  if (!rows[0]) return res.status(401).json({ error: 'Not logged in.' });
  res.json(rows[0]);
});

app.get('/', (req, res) => res.redirect(req.session.userId ? '/dashboard' : '/login.html'));
app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/login.html');
  res.sendFile(path.join(__dirname, 'views', 'dashboard.html'));
});
app.use(express.static(path.join(__dirname, 'public')));

initDb()
  .then(() => app.listen(PORT, () => console.log(`Running at http://localhost:${PORT}`)))
  .catch((err) => { console.error('Could not connect to the database:', err.message); process.exit(1); });
