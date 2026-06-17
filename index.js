// === Messenger Server (single file) ===
const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Pool } = require('pg');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';

// --- DB ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false }
    : false,
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name VARCHAR(100),
      avatar_id INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_id INTEGER;

    CREATE TABLE IF NOT EXISTS files (
      id SERIAL PRIMARY KEY,
      mime VARCHAR(100) NOT NULL,
      data BYTEA NOT NULL,
      width INTEGER,
      height INTEGER,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      is_group BOOLEAN NOT NULL DEFAULT FALSE,
      title VARCHAR(150),
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS chat_members (
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMP DEFAULT NOW(),
      PRIMARY KEY (chat_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      chat_id INTEGER REFERENCES chats(id) ON DELETE CASCADE,
      sender_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      content TEXT NOT NULL DEFAULT '',
      image_id INTEGER REFERENCES files(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
    ALTER TABLE messages ADD COLUMN IF NOT EXISTS image_id INTEGER REFERENCES files(id) ON DELETE SET NULL;
    ALTER TABLE messages ALTER COLUMN content SET DEFAULT '';

    CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id, created_at);
    CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id);
  `);
  console.log('[db] schema ready');
}

// --- Auth helpers ---
function signToken(user) {
  return jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
}
function verifyToken(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch (e) { return null; }
}
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  const p = t && verifyToken(t);
  if (!p) return res.status(401).json({ error: 'unauthorized' });
  req.user = p;
  next();
}

// --- App ---
const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    if (!/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
      return cb(new Error('only images allowed'));
    cb(null, true);
  },
});

app.get('/', (_req, res) => res.json({ ok: true, name: 'messenger-server' }));
app.get('/health', (_req, res) => res.json({ ok: true }));

// --- Auth ---
app.post('/api/register', async (req, res) => {
  try {
    const { username, password, displayName } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    if (username.length < 3 || password.length < 4)
      return res.status(400).json({ error: 'username>=3, password>=4' });
    const exists = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
    if (exists.rowCount) return res.status(409).json({ error: 'username taken' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users(username, password_hash, display_name) VALUES($1,$2,$3) RETURNING id, username, display_name, avatar_id',
      [username, hash, displayName || username]
    );
    res.json({ token: signToken(rows[0]), user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const { rows } = await pool.query(
      'SELECT id, username, display_name, avatar_id, password_hash FROM users WHERE username=$1',
      [username]
    );
    if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const user = { id: u.id, username: u.username, display_name: u.display_name, avatar_id: u.avatar_id };
    res.json({ token: signToken(user), user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

// --- Users ---
app.get('/api/users', authMiddleware, async (req, res) => {
  const q = (req.query.q || '').toString().trim();
  const params = [req.user.id];
  let sql = 'SELECT id, username, display_name, avatar_id FROM users WHERE id <> $1';
  if (q) { params.push('%' + q.toLowerCase() + '%'); sql += ' AND (LOWER(username) LIKE $2 OR LOWER(display_name) LIKE $2)'; }
  sql += ' ORDER BY username LIMIT 100';
  const { rows } = await pool.query(sql, params);
  res.json(rows);
});

app.get('/api/me', authMiddleware, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, display_name, avatar_id FROM users WHERE id=$1', [req.user.id]);
  res.json(rows[0] || null);
});

// --- Files ---
app.post('/api/files', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'no file' });
    const { rows } = await pool.query('INSERT INTO files(mime, data) VALUES($1,$2) RETURNING id', [req.file.mimetype, req.file.buffer]);
    res.json({ id: rows[0].id });
  } catch (e) { console.error(e); res.status(500).json({ error: e.message || 'server error' }); }
});

app.get('/api/files/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!id) return res.status(400).end();
    const { rows } = await pool.query('SELECT mime, data FROM files WHERE id=$1', [id]);
    if (!rows.length) return res.status(404).end();
    res.set('Content-Type', rows[0].mime);
    res.set('Cache-Control', 'public, max-age=31536000, immutable');
    res.send(rows[0].data);
  } catch (e) { console.error(e); res.status(500).end(); }
});

app.put('/api/me/avatar', authMiddleware, async (req, res) => {
  try {
    const fileId = req.body && req.body.fileId ? parseInt(req.body.fileId, 10) : null;
    await pool.query('UPDATE users SET avatar_id=$1 WHERE id=$2', [fileId, req.user.id]);
    res.json({ ok: true, avatar_id: fileId });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

// --- Chats ---
app.get('/api/chats', authMiddleware, async (req, res) => {
  const { rows } = await pool.query(
    `SELECT c.id, c.is_group, c.title,
       (SELECT COALESCE(NULLIF(m.content,''), CASE WHEN m.image_id IS NOT NULL THEN '📷 Фото' ELSE '' END)
          FROM messages m WHERE m.chat_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_message,
       (SELECT m.created_at FROM messages m WHERE m.chat_id=c.id ORDER BY m.created_at DESC LIMIT 1) AS last_at,
       CASE WHEN c.is_group THEN c.title
            ELSE (SELECT u.display_name FROM chat_members cm JOIN users u ON u.id=cm.user_id
                  WHERE cm.chat_id=c.id AND cm.user_id<>$1 LIMIT 1) END AS display_title,
       CASE WHEN c.is_group THEN NULL
            ELSE (SELECT u.avatar_id FROM chat_members cm JOIN users u ON u.id=cm.user_id
                  WHERE cm.chat_id=c.id AND cm.user_id<>$1 LIMIT 1) END AS avatar_id
     FROM chats c JOIN chat_members cm ON cm.chat_id=c.id
     WHERE cm.user_id=$1
     ORDER BY last_at DESC NULLS LAST, c.id DESC`,
    [req.user.id]
  );
  res.json(rows);
});

app.post('/api/chats/direct', authMiddleware, async (req, res) => {
  const otherId = parseInt(req.body.userId, 10);
  if (!otherId || otherId === req.user.id) return res.status(400).json({ error: 'bad userId' });
  const existing = await pool.query(
    `SELECT c.id FROM chats c
     JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
     JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
     WHERE c.is_group=FALSE LIMIT 1`,
    [req.user.id, otherId]
  );
  if (existing.rowCount) return res.json({ id: existing.rows[0].id });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const c = await client.query('INSERT INTO chats(is_group, title) VALUES(FALSE, NULL) RETURNING id');
    const chatId = c.rows[0].id;
    await client.query('INSERT INTO chat_members(chat_id, user_id) VALUES($1,$2),($1,$3)', [chatId, req.user.id, otherId]);
    await client.query('COMMIT');
    res.json({ id: chatId });
  } catch (e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'server error' }); }
  finally { client.release(); }
});

app.post('/api/chats/group', authMiddleware, async (req, res) => {
  const { title, memberIds } = req.body || {};
  if (!title || !Array.isArray(memberIds) || memberIds.length < 1)
    return res.status(400).json({ error: 'title and memberIds required' });
  const ids = Array.from(new Set([req.user.id, ...memberIds.map(Number).filter(Boolean)]));
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const c = await client.query('INSERT INTO chats(is_group, title) VALUES(TRUE,$1) RETURNING id', [title]);
    const chatId = c.rows[0].id;
    const values = ids.map((_, i) => `($1,$${i + 2})`).join(',');
    await client.query(`INSERT INTO chat_members(chat_id, user_id) VALUES ${values}`, [chatId, ...ids]);
    await client.query('COMMIT');
    res.json({ id: chatId });
  } catch (e) { await client.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'server error' }); }
  finally { client.release(); }
});

app.get('/api/chats/:id/messages', authMiddleware, async (req, res) => {
  const chatId = parseInt(req.params.id, 10);
  const member = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!member.rowCount) return res.status(403).json({ error: 'forbidden' });
  const { rows } = await pool.query(
    `SELECT m.id, m.chat_id, m.sender_id, u.username AS sender_username,
            u.display_name AS sender_display_name, u.avatar_id AS sender_avatar_id,
            m.content, m.image_id, m.created_at
     FROM messages m LEFT JOIN users u ON u.id=m.sender_id
     WHERE m.chat_id=$1 ORDER BY m.created_at ASC LIMIT 200`,
    [chatId]
  );
  res.json(rows);
});

// multer errors as JSON
app.use((err, _req, res, _next) => {
  if (err) return res.status(400).json({ error: err.message || 'bad request' });
});

// --- Socket.IO ---
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  const payload = token && verifyToken(token);
  if (!payload) return next(new Error('unauthorized'));
  socket.user = payload;
  next();
});

io.on('connection', async (socket) => {
  console.log('[ws] connected', socket.user.username);
  try {
    const { rows } = await pool.query('SELECT chat_id FROM chat_members WHERE user_id=$1', [socket.user.id]);
    rows.forEach(r => socket.join('chat:' + r.chat_id));
  } catch (e) { console.error(e); }

  socket.on('join_chat', async (chatId) => {
    chatId = parseInt(chatId, 10);
    if (!chatId) return;
    const m = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, socket.user.id]);
    if (m.rowCount) socket.join('chat:' + chatId);
  });

  socket.on('send_message', async (data, ack) => {
    try {
      const chatId = parseInt(data.chatId, 10);
      const content = (data.content || '').toString().trim();
      const imageId = data.imageId ? parseInt(data.imageId, 10) : null;
      if (!chatId || (!content && !imageId)) return ack && ack({ error: 'bad payload' });
      if (content.length > 4000) return ack && ack({ error: 'too long' });
      const m = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, socket.user.id]);
      if (!m.rowCount) return ack && ack({ error: 'forbidden' });
      const ins = await pool.query(
        `INSERT INTO messages(chat_id, sender_id, content, image_id)
         VALUES($1,$2,$3,$4) RETURNING id, chat_id, sender_id, content, image_id, created_at`,
        [chatId, socket.user.id, content, imageId]
      );
      const msg = ins.rows[0];
      const u = await pool.query('SELECT avatar_id FROM users WHERE id=$1', [socket.user.id]);
      const out = {
        id: msg.id, chat_id: msg.chat_id, sender_id: msg.sender_id,
        sender_username: socket.user.username,
        sender_avatar_id: u.rows[0] ? u.rows[0].avatar_id : null,
        content: msg.content, image_id: msg.image_id, created_at: msg.created_at,
      };
      io.to('chat:' + chatId).emit('new_message', out);
      ack && ack({ ok: true, message: out });
    } catch (e) { console.error(e); ack && ack({ error: 'server error' }); }
  });

  socket.on('disconnect', () => console.log('[ws] disconnected', socket.user.username));
});

// --- Start ---
initDb()
  .then(() => server.listen(PORT, () => console.log('[http] listening on ' + PORT)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });
