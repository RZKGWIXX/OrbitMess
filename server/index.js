const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Low, JSONFile } = require('lowdb');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json());

const JWT_SECRET = 'supersecret';
const db = new Low(new JSONFile(path.join(__dirname, 'db.json')));

async function initDB() {
  await db.read();
  db.data ||= { users: [] };
  await db.write();
}

function generateToken(user) {
  return jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin, isPremium: user.isPremium, isVerified: user.isVerified, banned: user.banned }, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: 'Invalid token' });
  }
}

app.post('/api/register', async (req, res) => {
  await initDB();
  const { username, password } = req.body;
  if (db.data.users.find(u => u.username === username)) return res.status(400).json({ message: 'User exists' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), username, password: hash, isAdmin: false, isPremium: false, isVerified: false, banned: false };
  db.data.users.push(user);
  await db.write();
  res.json({ token: generateToken(user) });
});

app.post('/api/login', async (req, res) => {
  await initDB();
  const { username, password } = req.body;
  const user = db.data.users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'User not found' });
  if (user.banned) return res.status(403).json({ message: 'Banned' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: 'Wrong password' });
  res.json({ token: generateToken(user) });
});

app.get('/api/me', authMiddleware, async (req, res) => {
  await initDB();
  const user = db.data.users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ message: 'Not found' });
  res.json({ id: user.id, username: user.username, isAdmin: user.isAdmin, isPremium: user.isPremium, isVerified: user.isVerified, banned: user.banned });
});

app.get('/api/admin/users', authMiddleware, async (req, res) => {
  await initDB();
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Not admin' });
  res.json(db.data.users.map(u => ({ id: u.id, username: u.username, isAdmin: u.isAdmin, isPremium: u.isPremium, isVerified: u.isVerified, banned: u.banned })));
});

app.post('/api/admin/ban', authMiddleware, async (req, res) => {
  await initDB();
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Not admin' });
  const { userId, banned } = req.body;
  const user = db.data.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  user.banned = banned;
  await db.write();
  res.json({ success: true });
});

app.post('/api/admin/verify', authMiddleware, async (req, res) => {
  await initDB();
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Not admin' });
  const { userId, isVerified } = req.body;
  const user = db.data.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  user.isVerified = isVerified;
  await db.write();
  res.json({ success: true });
});

app.post('/api/admin/premium', authMiddleware, async (req, res) => {
  await initDB();
  if (!req.user.isAdmin) return res.status(403).json({ message: 'Not admin' });
  const { userId, isPremium } = req.body;
  const user = db.data.users.find(u => u.id === userId);
  if (!user) return res.status(404).json({ message: 'User not found' });
  user.isPremium = isPremium;
  await db.write();
  res.json({ success: true });
});

// Socket.io for chat
io.on('connection', (socket) => {
  socket.on('message', (msg) => {
    io.emit('message', msg);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log('Server started on port', PORT)); 