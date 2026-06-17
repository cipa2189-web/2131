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

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes('render.com')
    ? { rejectUnauthorized: false } : false,
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

function signToken(u) { return jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn: '30d' }); }
function verifyToken(t) { try { return jwt.verify(t, JWT_SECRET); } catch (e) { return null; } }
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : null;
  const p = t && verifyToken(t);
  if (!p) return res.status(401).json({ error: 'unauthorized' });
  req.user = p; next();
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '1mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_r, f, cb) => {
    if (!/^image\/(jpeg|png|webp|gif)$/.test(f.mimetype)) return cb(new Error('only images allowed'));
    cb(null, true);
  },
});

app.get('/', (_r, res) => res.json({ ok: true, name: 'messenger-server' }));
app.get('/health', (_r, res) => res.json({ ok: true }));

app.post('/api/register', async (req, res) => {
  try {
    const { username, password, displayName } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    if (username.length < 3 || password.length < 4) return res.status(400).json({ error: 'username>=3, password>=4' });
    const ex = await pool.query('SELECT 1 FROM users WHERE username=$1', [username]);
    if (ex.rowCount) return res.status(409).json({ error: 'username taken' });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      'INSERT INTO users(username, password_hash, display_name) VALUES($1,$2,$3) RETURNING id, username, display_name, avatar_id',
      [username, hash, displayName || username]);
    res.json({ token: signToken(rows[0]), user: rows[0] });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });
    const { rows } = await pool.query('SELECT id, username, display_name, avatar_id, password_hash FROM users WHERE username=$1', [username]);
    if (!rows.length) return res.status(401).json({ error: 'invalid credentials' });
    const u = rows[0];
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const user = { id: u.id, username: u.username, display_name: u.display_name, avatar_id: u.avatar_id };
    res.json({ token: signToken(user), user });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

app.get('/api/users', auth, async (req, res) => {
  const q = (req.query.q || '').toString().trim();
  const params = [req.user.id];
  let sql = 'SELECT id, username, display_name, avatar_id FROM users WHERE id <> $1';
  if (q) { params.push('%' + q.toLowerCase() + '%'); sql += ' AND (LOWER(username) LIKE $2 OR LOWER(display_name) LIKE $2)'; }
  sql += ' ORDER BY username LIMIT 100';
  const { rows } = await pool.query(sql, params);
  res.json(rows);
});

app.get('/api/me', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT id, username, display_name, avatar_id FROM users WHERE id=$1', [req.user.id]);
  res.json(rows[0] || null);
});

app.post('/api/files', auth, upload.single('file'), async (req, res) => {
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

app.put('/api/me/avatar', auth, async (req, res) => {
  try {
    const fileId = req.body && req.body.fileId ? parseInt(req.body.fileId, 10) : null;
    await pool.query('UPDATE users SET avatar_id=$1 WHERE id=$2', [fileId, req.user.id]);
    res.json({ ok: true, avatar_id: fileId });
  } catch (e) { console.error(e); res.status(500).json({ error: 'server error' }); }
});

app.get('/api/chats', auth, async (req, res) => {
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
     WHERE cm.user_id=$1 ORDER BY last_at DESC NULLS LAST, c.id DESC`,
    [req.user.id]);
  res.json(rows);
});

app.post('/api/chats/direct', auth, async (req, res) => {
  const otherId = parseInt(req.body.userId, 10);
  if (!otherId || otherId === req.user.id) return res.status(400).json({ error: 'bad userId' });
  const ex = await pool.query(
    `SELECT c.id FROM chats c
     JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
     JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
     WHERE c.is_group=FALSE LIMIT 1`, [req.user.id, otherId]);
  if (ex.rowCount) return res.json({ id: ex.rows[0].id });
  const cl = await pool.connect();
  try {
    await cl.query('BEGIN');
    const c = await cl.query('INSERT INTO chats(is_group, title) VALUES(FALSE, NULL) RETURNING id');
    const id = c.rows[0].id;
    await cl.query('INSERT INTO chat_members(chat_id, user_id) VALUES($1,$2),($1,$3)', [id, req.user.id, otherId]);
    await cl.query('COMMIT');
    res.json({ id });
  } catch (e) { await cl.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'server error' }); }
  finally { cl.release(); }
});

app.post('/api/chats/group', auth, async (req, res) => {
  const { title, memberIds } = req.body || {};
  if (!title || !Array.isArray(memberIds) || memberIds.length < 1) return res.status(400).json({ error: 'title and memberIds required' });
  const ids = Array.from(new Set([req.user.id, ...memberIds.map(Number).filter(Boolean)]));
  const cl = await pool.connect();
  try {
    await cl.query('BEGIN');
    const c = await cl.query('INSERT INTO chats(is_group, title) VALUES(TRUE,$1) RETURNING id', [title]);
    const id = c.rows[0].id;
    const vals = ids.map((_, i) => `($1,$${i + 2})`).join(',');
    await cl.query(`INSERT INTO chat_members(chat_id, user_id) VALUES ${vals}`, [id, ...ids]);
    await cl.query('COMMIT');
    res.json({ id });
  } catch (e) { await cl.query('ROLLBACK'); console.error(e); res.status(500).json({ error: 'server error' }); }
  finally { cl.release(); }
});

app.get('/api/chats/:id/messages', auth, async (req, res) => {
  const chatId = parseInt(req.params.id, 10);
  const mb = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, req.user.id]);
  if (!mb.rowCount) return res.status(403).json({ error: 'forbidden' });
  const { rows } = await pool.query(
    `SELECT m.id, m.chat_id, m.sender_id, u.username AS sender_username,
            u.display_name AS sender_display_name, u.avatar_id AS sender_avatar_id,
            m.content, m.image_id, m.created_at
     FROM messages m LEFT JOIN users u ON u.id=m.sender_id
     WHERE m.chat_id=$1 ORDER BY m.created_at ASC LIMIT 200`, [chatId]);
  res.json(rows);
});

app.use((err, _r, res, _n) => { if (err) return res.status(400).json({ error: err.message || 'bad request' }); });

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

io.use((s, next) => {
  const t = s.handshake.auth && s.handshake.auth.token;
  const p = t && verifyToken(t);
  if (!p) return next(new Error('unauthorized'));
  s.user = p; next();
});

io.on('connection', async (s) => {
  console.log('[ws] connected', s.user.username);
  try {
    const { rows } = await pool.query('SELECT chat_id FROM chat_members WHERE user_id=$1', [s.user.id]);
    rows.forEach(r => s.join('chat:' + r.chat_id));
  } catch (e) { console.error(e); }

  s.on('join_chat', async (chatId) => {
    chatId = parseInt(chatId, 10);
    if (!chatId) return;
    const m = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, s.user.id]);
    if (m.rowCount) s.join('chat:' + chatId);
  });

  s.on('send_message', async (d, ack) => {
    try {
      const chatId = parseInt(d.chatId, 10);
      const content = (d.content || '').toString().trim();
      const imageId = d.imageId ? parseInt(d.imageId, 10) : null;
      if (!chatId || (!content && !imageId)) return ack && ack({ error: 'bad payload' });
      if (content.length > 4000) return ack && ack({ error: 'too long' });
      const m = await pool.query('SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2', [chatId, s.user.id]);
      if (!m.rowCount) return ack && ack({ error: 'forbidden' });
      const ins = await pool.query(
        `INSERT INTO messages(chat_id, sender_id, content, image_id)
         VALUES($1,$2,$3,$4) RETURNING id, chat_id, sender_id, content, image_id, created_at`,
        [chatId, s.user.id, content, imageId]);
      const msg = ins.rows[0];
      const u = await pool.query('SELECT avatar_id FROM users WHERE id=$1', [s.user.id]);
      const out = {
        id: msg.id, chat_id: msg.chat_id, sender_id: msg.sender_id,
        sender_username: s.user.username,
        sender_avatar_id: u.rows[0] ? u.rows[0].avatar_id : null,
        content: msg.content, image_id: msg.image_id, created_at: msg.created_at,
      };
      io.to('chat:' + chatId).emit('new_message', out);
      ack && ack({ ok: true, message: out });
    } catch (e) { console.error(e); ack && ack({ error: 'server error' }); }
  });

  s.on('disconnect', () => console.log('[ws] disconnected', s.user.username));
});

initDb().then(() => server.listen(PORT, () => console.log('[http] listening on ' + PORT)))
  .catch(e => { console.error('DB init failed', e); process.exit(1); });
