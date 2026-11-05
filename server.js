const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOADS = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const CATEGORIES = ['Classroom Maintenance', 'Laboratory Issues', 'Electrical Problems', 'Water Supply', 'Washroom Cleanliness', 'Hostel Issues', 'Library Issues', 'Internet and Wi-Fi', 'Furniture Damage', 'Other Issues'];
const STATUSES = ['Pending', 'Under Review', 'In Progress', 'Resolved', 'Rejected'];
const PRIORITIES = ['Low', 'Medium', 'High', 'Urgent'];
const DEPARTMENTS = ['Computer Science', 'Information Technology', 'Artificial Intelligence & Data Science', 'Electronics & Communication', 'Electrical & Electronics', 'Mechanical', 'Civil', 'Management Studies', 'Other'];

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-only-secret-change-me',
  resave: false,
  saveUninitialized: false,
  name: 'ccms.sid',
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use((req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });
app.use('/vendor/chart', express.static(path.join(__dirname, 'node_modules', 'chart.js', 'dist')));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- helpers ---------- */
const clean = (v, max = 255) => String(v ?? '').trim().slice(0, max);
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const pwOk = p => typeof p === 'string' && p.length >= 8 && p.length <= 72 && /[A-Za-z]/.test(p) && /\d/.test(p);
const bad = (res, msg, code = 400) => res.status(code).json({ error: msg });

const requireAuth = (req, res, next) => req.session.uid ? next() : bad(res, 'Please log in first', 401);
const requireStudent = (req, res, next) => (req.session.uid && req.session.role === 'student') ? next() : bad(res, 'Student access only', 403);
const requireAdmin = (req, res, next) => (req.session.uid && req.session.role === 'admin') ? next() : bad(res, 'Administrator access only', 403);

// simple in-memory brute-force limiter (10 failures / 15 min / IP)
const fails = new Map();
const limited = req => { const r = fails.get(req.ip); return r && r.n >= 10 && Date.now() - r.t < 9e5; };
const noteFail = req => { const r = fails.get(req.ip); if (!r || Date.now() - r.t > 9e5) fails.set(req.ip, { n: 1, t: Date.now() }); else r.n++; };

function startSession(req, res, role, id, payload) {
  req.session.regenerate(err => {
    if (err) return bad(res, 'Could not start session', 500);
    req.session.role = role; req.session.uid = id;
    res.json(payload);
  });
}

const counts = (where = '', p = []) => {
  const r = db.prepare(`SELECT COUNT(*) total, SUM(status='Pending') pending, SUM(status='Under Review') review,
    SUM(status='In Progress') progress, SUM(status='Resolved') resolved, SUM(status='Rejected') rejected,
    SUM(priority IN ('High','Urgent')) high FROM Complaints ${where}`).get(...p);
  for (const k in r) r[k] = r[k] || 0;
  return r;
};

/* ---------- meta ---------- */
app.get('/api/meta', (req, res) => res.json({ categories: CATEGORIES, statuses: STATUSES, priorities: PRIORITIES, departments: DEPARTMENTS }));

/* ---------- auth ---------- */
app.post('/api/auth/register', async (req, res) => {
  const b = req.body || {};
  const full_name = clean(b.full_name, 80), register_no = clean(b.register_no, 30).toUpperCase(), email = clean(b.email, 120).toLowerCase();
  const department = clean(b.department), year = parseInt(b.year, 10);
  if (full_name.length < 3) return bad(res, 'Enter your full name (at least 3 characters)');
  if (!/^[A-Z0-9-]{4,30}$/.test(register_no)) return bad(res, 'Register number must be 4-30 letters or digits');
  if (!emailRe.test(email)) return bad(res, 'Enter a valid email address');
  if (!DEPARTMENTS.includes(department)) return bad(res, 'Choose a department from the list');
  if (!(year >= 1 && year <= 5)) return bad(res, 'Choose your year of study');
  if (!pwOk(b.password)) return bad(res, 'Password must be 8+ characters with at least one letter and one number');
  if (b.password !== b.confirm_password) return bad(res, 'Passwords do not match');
  if (db.prepare('SELECT 1 FROM Users WHERE register_no=? OR email=?').get(register_no, email)) return bad(res, 'An account with this register number or email already exists', 409);
  const hash = await bcrypt.hash(b.password, 10);
  db.prepare('INSERT INTO Users(full_name,register_no,email,department,year,password_hash) VALUES(?,?,?,?,?,?)').run(full_name, register_no, email, department, year, hash);
  res.status(201).json({ ok: true });
});

app.post('/api/auth/login', async (req, res) => {
  if (limited(req)) return bad(res, 'Too many failed attempts. Try again in 15 minutes.', 429);
  const id = clean(req.body?.identifier, 120), pw = String(req.body?.password ?? '');
  const u = db.prepare('SELECT * FROM Users WHERE email=? OR register_no=?').get(id.toLowerCase(), id.toUpperCase());
  if (!u || !(await bcrypt.compare(pw, u.password_hash))) { noteFail(req); return bad(res, 'Incorrect register number/email or password', 401); }
  fails.delete(req.ip);
  startSession(req, res, 'student', u.id, { ok: true, role: 'student' });
});

app.post('/api/auth/admin-login', async (req, res) => {
  if (limited(req)) return bad(res, 'Too many failed attempts. Try again in 15 minutes.', 429);
  const id = clean(req.body?.username, 80), pw = String(req.body?.password ?? '');
  const a = db.prepare('SELECT * FROM Admins WHERE username=?').get(id);
  if (!a || !(await bcrypt.compare(pw, a.password_hash))) { noteFail(req); return bad(res, 'Incorrect username or password', 401); }
  fails.delete(req.ip);
  startSession(req, res, 'admin', a.id, { ok: true, role: 'admin' });
});

app.post('/api/auth/logout', (req, res) => req.session.destroy(() => { res.clearCookie('ccms.sid'); res.json({ ok: true }); }));

app.get('/api/auth/me', requireAuth, (req, res) => {
  if (req.session.role === 'student') {
    const u = db.prepare('SELECT id,full_name,register_no,email,department,year,created_at FROM Users WHERE id=?').get(req.session.uid);
    return u ? res.json({ role: 'student', user: u }) : bad(res, 'Account not found', 401);
  }
  const a = db.prepare('SELECT id,name AS full_name,username,email,created_at FROM Admins WHERE id=?').get(req.session.uid);
  a ? res.json({ role: 'admin', user: a }) : bad(res, 'Account not found', 401);
});

/* ---------- profile ---------- */
app.put('/api/profile', requireAuth, (req, res) => {
  const b = req.body || {}, name = clean(b.full_name, 80);
  if (name.length < 3) return bad(res, 'Enter your full name (at least 3 characters)');
  if (req.session.role === 'student') {
    const department = clean(b.department), year = parseInt(b.year, 10);
    if (!DEPARTMENTS.includes(department) || !(year >= 1 && year <= 5)) return bad(res, 'Choose a valid department and year');
    db.prepare('UPDATE Users SET full_name=?,department=?,year=? WHERE id=?').run(name, department, year, req.session.uid);
  } else {
    const email = clean(b.email, 120);
    if (!emailRe.test(email)) return bad(res, 'Enter a valid email address');
    db.prepare('UPDATE Admins SET name=?,email=? WHERE id=?').run(name, email, req.session.uid);
  }
  res.json({ ok: true });
});

app.put('/api/profile/password', requireAuth, async (req, res) => {
  const { current_password, new_password, confirm_password } = req.body || {};
  const table = req.session.role === 'admin' ? 'Admins' : 'Users';
  const row = db.prepare(`SELECT password_hash FROM ${table} WHERE id=?`).get(req.session.uid);
  if (!row || !(await bcrypt.compare(String(current_password ?? ''), row.password_hash))) return bad(res, 'Current password is incorrect');
  if (!pwOk(new_password)) return bad(res, 'New password must be 8+ characters with at least one letter and one number');
  if (new_password !== confirm_password) return bad(res, 'New passwords do not match');
  db.prepare(`UPDATE ${table} SET password_hash=? WHERE id=?`).run(await bcrypt.hash(new_password, 10), req.session.uid);
  res.json({ ok: true });
});

/* ---------- uploads ---------- */
const EXT = { 'image/jpeg': '.jpg', 'image/png': '.png' };
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, file, cb) => cb(null, crypto.randomBytes(16).toString('hex') + (EXT[file.mimetype] || '.bin'))
  }),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    const ok = EXT[file.mimetype] && /\.(jpe?g|png)$/i.test(file.originalname);
    cb(ok ? null : new Error('Only JPG, JPEG or PNG images are allowed'), ok);
  }
});
const uploadImage = (req, res, next) => upload.single('image')(req, res, err =>
  err ? bad(res, err.code === 'LIMIT_FILE_SIZE' ? 'Image must be smaller than 5 MB' : err.message) : next());

function validImageBytes(file) {
  const fd = fs.openSync(file, 'r'); const buf = Buffer.alloc(8); fs.readSync(fd, buf, 0, 8, 0); fs.closeSync(fd);
  return (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) || buf.equals(Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]));
}

// Images are only served to the complaint owner or an admin
app.get('/uploads/:file', requireAuth, (req, res) => {
  const f = path.basename(req.params.file);
  const c = db.prepare('SELECT user_id FROM Complaints WHERE image_path=?').get(f);
  if (!c || (req.session.role === 'student' && c.user_id !== req.session.uid)) return res.sendStatus(404);
  res.sendFile(path.join(UPLOADS, f));
});

/* ---------- student: complaints ---------- */
app.get('/api/student/stats', requireStudent, (req, res) => res.json(counts('WHERE user_id=?', [req.session.uid])));

app.get('/api/complaints', requireStudent, (req, res) => {
  const q = clean(req.query.q, 80), status = clean(req.query.status);
  let sql = 'SELECT id,complaint_code,title,category,location,block,priority,status,created_at,updated_at FROM Complaints WHERE user_id=?';
  const p = [req.session.uid];
  if (q) { sql += ' AND (complaint_code LIKE ? OR title LIKE ? OR category LIKE ?)'; p.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  if (STATUSES.includes(status)) { sql += ' AND status=?'; p.push(status); }
  res.json(db.prepare(sql + ' ORDER BY id DESC').all(...p));
});

app.post('/api/complaints', requireStudent, uploadImage, (req, res) => {
  const b = req.body || {}, file = req.file;
  const discard = msg => { if (file) fs.unlink(file.path, () => {}); return bad(res, msg); };
  const title = clean(b.title, 120), category = clean(b.category), description = clean(b.description, 2000);
  const location = clean(b.location, 120), block = clean(b.block, 80), room = clean(b.room, 40);
  if (title.length < 5) return discard('Title must be at least 5 characters');
  if (!CATEGORIES.includes(category)) return discard('Choose a complaint category');
  if (description.length < 15) return discard('Describe the problem in at least 15 characters');
  if (!location) return discard('Enter the campus location');
  if (!block) return discard('Enter the block or building');
  if (file && !validImageBytes(file.path)) return discard('The uploaded file is not a valid JPG or PNG image');

  const tx = db.transaction(() => {
    const r = db.prepare('INSERT INTO Complaints(user_id,title,category,description,location,block,room,image_path) VALUES(?,?,?,?,?,?,?,?)')
      .run(req.session.uid, title, category, description, location, block, room || null, file ? file.filename : null);
    const id = Number(r.lastInsertRowid);
    const code = `CC-${new Date().getFullYear()}-${String(id).padStart(4, '0')}`;
    db.prepare('UPDATE Complaints SET complaint_code=? WHERE id=?').run(code, id);
    db.prepare('INSERT INTO Complaint_Status_History(complaint_id,status,remarks,changed_by) VALUES(?,?,?,?)').run(id, 'Pending', 'Complaint submitted', 'Student');
    db.prepare('INSERT INTO Notifications(user_id,complaint_id,message) VALUES(?,?,?)').run(req.session.uid, id, `Your complaint ${code} was submitted successfully.`);
    return { id, code };
  });
  try { const r = tx(); res.status(201).json({ ok: true, id: r.id, complaint_code: r.code }); }
  catch (e) { if (file) fs.unlink(file.path, () => {}); bad(res, 'Could not save the complaint', 500); }
});

const historyOf = id => db.prepare('SELECT status,remarks,changed_by,created_at FROM Complaint_Status_History WHERE complaint_id=? ORDER BY id').all(id);
const withImage = c => ({ ...c, image_url: c.image_path ? '/uploads/' + c.image_path : null, image_path: undefined });

app.get('/api/complaints/:id', requireStudent, (req, res) => {
  const c = db.prepare('SELECT * FROM Complaints WHERE id=? AND user_id=?').get(+req.params.id, req.session.uid);
  if (!c) return bad(res, 'Complaint not found', 404);
  res.json({ complaint: withImage(c), history: historyOf(c.id) });
});

/* ---------- notifications ---------- */
app.get('/api/notifications', requireStudent, (req, res) => {
  const items = db.prepare('SELECT id,complaint_id,message,is_read,created_at FROM Notifications WHERE user_id=? ORDER BY id DESC LIMIT 100').all(req.session.uid);
  res.json({ unread: items.filter(n => !n.is_read).length, items });
});
app.get('/api/notifications/unread', requireStudent, (req, res) =>
  res.json({ count: db.prepare('SELECT COUNT(*) n FROM Notifications WHERE user_id=? AND is_read=0').get(req.session.uid).n }));
app.post('/api/notifications/read-all', requireStudent, (req, res) => {
  db.prepare('UPDATE Notifications SET is_read=1 WHERE user_id=?').run(req.session.uid); res.json({ ok: true });
});
app.post('/api/notifications/:id/read', requireStudent, (req, res) => {
  db.prepare('UPDATE Notifications SET is_read=1 WHERE id=? AND user_id=?').run(+req.params.id, req.session.uid); res.json({ ok: true });
});

/* ---------- admin ---------- */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const byCategory = db.prepare('SELECT category label, COUNT(*) n FROM Complaints GROUP BY category ORDER BY n DESC').all();
  const recent = db.prepare(`SELECT c.id,c.complaint_code,c.title,c.category,c.priority,c.status,c.created_at,u.full_name
    FROM Complaints c JOIN Users u ON u.id=c.user_id ORDER BY c.id DESC LIMIT 6`).all();
  res.json({ ...counts(), byCategory, recent });
});

app.get('/api/admin/complaints', requireAdmin, (req, res) => {
  const q = clean(req.query.q, 80), { category, department, priority, status } = req.query;
  let sql = `SELECT c.id,c.complaint_code,c.title,c.category,c.priority,c.status,c.location,c.block,c.created_at,
    u.full_name,u.register_no,u.department FROM Complaints c JOIN Users u ON u.id=c.user_id WHERE 1=1`;
  const p = [];
  if (q) { sql += ' AND (c.complaint_code LIKE ? OR u.full_name LIKE ? OR u.register_no LIKE ?)'; p.push(`%${q}%`, `%${q}%`, `%${q}%`); }
  if (CATEGORIES.includes(category)) { sql += ' AND c.category=?'; p.push(category); }
  if (DEPARTMENTS.includes(department)) { sql += ' AND u.department=?'; p.push(department); }
  if (PRIORITIES.includes(priority)) { sql += ' AND c.priority=?'; p.push(priority); }
  if (STATUSES.includes(status)) { sql += ' AND c.status=?'; p.push(status); }
  res.json(db.prepare(sql + ' ORDER BY c.id DESC').all(...p));
});

app.get('/api/admin/complaints/:id', requireAdmin, (req, res) => {
  const c = db.prepare('SELECT * FROM Complaints WHERE id=?').get(+req.params.id);
  if (!c) return bad(res, 'Complaint not found', 404);
  const student = db.prepare('SELECT full_name,register_no,email,department,year,created_at FROM Users WHERE id=?').get(c.user_id);
  const total = db.prepare('SELECT COUNT(*) n FROM Complaints WHERE user_id=?').get(c.user_id).n;
  res.json({ complaint: withImage(c), history: historyOf(c.id), student: { ...student, total_complaints: total } });
});

app.put('/api/admin/complaints/:id', requireAdmin, (req, res) => {
  const id = +req.params.id;
  const c = db.prepare('SELECT * FROM Complaints WHERE id=?').get(id);
  if (!c) return bad(res, 'Complaint not found', 404);
  const status = req.body?.status ?? c.status, priority = req.body?.priority ?? c.priority, remarks = clean(req.body?.remarks, 1000);
  if (!STATUSES.includes(status) || !PRIORITIES.includes(priority)) return bad(res, 'Invalid status or priority');
  const admin = db.prepare('SELECT name FROM Admins WHERE id=?').get(req.session.uid);
  const changed = status !== c.status;
  db.transaction(() => {
    db.prepare("UPDATE Complaints SET status=?,priority=?,admin_remarks=COALESCE(NULLIF(?,''),admin_remarks),updated_at=datetime('now') WHERE id=?").run(status, priority, remarks, id);
    if (changed || remarks) db.prepare('INSERT INTO Complaint_Status_History(complaint_id,status,remarks,changed_by) VALUES(?,?,?,?)').run(id, status, remarks || null, admin.name);
    const note = m => db.prepare('INSERT INTO Notifications(user_id,complaint_id,message) VALUES(?,?,?)').run(c.user_id, id, m);
    if (changed) note(status === 'Under Review' ? `Your complaint ${c.complaint_code} is now being reviewed by the administrator.`
      : status === 'Resolved' ? `Your complaint ${c.complaint_code} has been resolved.`
      : `The status of complaint ${c.complaint_code} changed to ${status}.`);
    if (remarks) note(`The administrator added remarks on complaint ${c.complaint_code}.`);
  })();
  res.json({ ok: true, changed: changed || !!remarks || priority !== c.priority });
});

function reportData(from, to) {
  const w = [], p = [];
  if (/^\d{4}-\d{2}-\d{2}$/.test(from)) { w.push('date(c.created_at)>=?'); p.push(from); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(to)) { w.push('date(c.created_at)<=?'); p.push(to); }
  const where = w.length ? 'WHERE ' + w.join(' AND ') : '';
  const base = 'FROM Complaints c JOIN Users u ON u.id=c.user_id ' + where;
  const group = col => db.prepare(`SELECT ${col} label, COUNT(*) n, SUM(c.status='Resolved') resolved ${base} GROUP BY ${col} ORDER BY n DESC`).all(...p);
  const t = db.prepare(`SELECT COUNT(*) total, SUM(c.status='Resolved') resolved, SUM(c.status IN ('Pending','Under Review','In Progress')) open,
    SUM(c.status='Rejected') rejected ${base}`).get(...p);
  const avg = db.prepare(`SELECT AVG(julianday((SELECT MAX(h.created_at) FROM Complaint_Status_History h WHERE h.complaint_id=c.id AND h.status='Resolved'))-julianday(c.created_at)) d
    ${base}${where ? ' AND' : ' WHERE'} c.status='Resolved'`).get(...p).d;
  return {
    totals: { total: t.total || 0, resolved: t.resolved || 0, open: t.open || 0, rejected: t.rejected || 0, avg_resolution_days: avg == null ? null : Math.round(avg * 10) / 10 },
    byCategory: group('c.category'), byDepartment: group('u.department'), byStatus: group('c.status'), byPriority: group('c.priority')
  };
}
app.get('/api/admin/reports', requireAdmin, (req, res) => res.json(reportData(req.query.from, req.query.to)));

app.get('/api/admin/reports/csv', requireAdmin, (req, res) => {
  const w = [], p = [];
  if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.from)) { w.push('date(c.created_at)>=?'); p.push(req.query.from); }
  if (/^\d{4}-\d{2}-\d{2}$/.test(req.query.to)) { w.push('date(c.created_at)<=?'); p.push(req.query.to); }
  const rows = db.prepare(`SELECT c.complaint_code,c.title,c.category,c.priority,c.status,c.location,c.block,c.room,c.created_at,c.updated_at,
    u.full_name,u.register_no,u.department,u.year,c.admin_remarks FROM Complaints c JOIN Users u ON u.id=c.user_id
    ${w.length ? 'WHERE ' + w.join(' AND ') : ''} ORDER BY c.id DESC`).all(...p);
  const cols = ['complaint_code', 'title', 'category', 'priority', 'status', 'location', 'block', 'room', 'created_at', 'updated_at', 'full_name', 'register_no', 'department', 'year', 'admin_remarks'];
  const cell = v => { let s = String(v ?? ''); if (/^[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
  const csv = [cols.join(',')].concat(rows.map(r => cols.map(c => cell(r[c])).join(','))).join('\r\n');
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="complaints-report.csv"' }).send('\ufeff' + csv);
});

/* ---------- errors ---------- */
app.use('/api', (req, res) => bad(res, 'Not found', 404));
app.use((err, req, res, next) => { console.error(err); bad(res, 'Something went wrong on the server', 500); });

app.listen(PORT, () => console.log(`Campus Complaint Management System running at http://localhost:${PORT}`));
