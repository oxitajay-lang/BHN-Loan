const express = require('express'), session = require('express-session'), Database = require('better-sqlite3'),
  bcrypt = require('bcryptjs'), nodemailer = require('nodemailer'), crypto = require('crypto'), QR = require('qrcode');
const E = process.env, UPI_ID = E.UPI_ID || 'aaryjha7@ptyes', RATE = 0.04;
const KEY = crypto.scryptSync(E.DATA_KEY || 'change-me', 'bhn', 32);
const enc = t => { const iv = crypto.randomBytes(12), c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const b = Buffer.concat([c.update(t, 'utf8'), c.final()]); return [iv, c.getAuthTag(), b].map(x => x.toString('hex')).join('.'); };
const dec = s => { const [i, g, b] = s.split('.').map(x => Buffer.from(x, 'hex')), d = crypto.createDecipheriv('aes-256-gcm', KEY, i);
  d.setAuthTag(g); return Buffer.concat([d.update(b), d.final()]).toString('utf8'); };

const db = new Database('data.db');
db.exec(`
create table if not exists users(id integer primary key, bhn text unique, name text, email text unique, acct text, ifsc text,
  state text, district text, aadhaar text, pass text, level text default 'silver', created text default (datetime('now')));
create table if not exists otps(email text, code text, purpose text, data text, exp integer);
create table if not exists loans(id integer primary key, user_id int, amount int, mobile text, status text default 'pending',
  created text default (datetime('now')), approved_at text);
create table if not exists inst(id integer primary key, loan_id int, no int, due text, amount real, status text default 'pending',
  utr text, reminded int default 0);
create table if not exists team(id integer primary key, login text unique, pass text, role text default 'team');
create table if not exists deleted(bhn text primary key, email text);`);
if (!db.prepare('select 1 from team where role=?').get('admin'))
  db.prepare('insert into team(login,pass,role) values(?,?,?)').run(E.ADMIN_ID || 'admin', bcrypt.hashSync(E.ADMIN_PASS || 'Admin@12345', 10), 'admin');

const mailer = E.SMTP_HOST ? nodemailer.createTransport({ host: E.SMTP_HOST, port: +E.SMTP_PORT || 587, auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } }) : null;
const sendMail = async (to, subject, text) => mailer ? mailer.sendMail({ from: E.SMTP_USER, to, subject, text }) : console.log(`[MAIL to ${to}] ${subject}: ${text}`);
const sendSms = (mobile, text) => console.log(`[SMS to ${mobile}] ${text}`); // TODO: plug in Fast2SMS / Twilio / MSG91 here

const LEVELS = { silver: [100, 200, 300], gold: [500, 700, 1000], diamond: [1500, 2000] };
const PASS_RE = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const ymd = d => d.toLocaleDateString('en-CA');
const firstDue = () => { const d = new Date(); d.setDate(d.getDate() + 7); d.setDate(d.getDate() + ((7 - d.getDay()) % 7 || 7)); return d; };
async function otp(email, purpose, data) {
  const code = String(crypto.randomInt(100000, 999999));
  db.prepare('delete from otps where email=? and purpose=?').run(email, purpose);
  db.prepare('insert into otps values(?,?,?,?,?)').run(email, code, purpose, JSON.stringify(data || {}), Date.now() + 10 * 60000);
  await sendMail(email, 'Bro Hai Na - OTP', `Your OTP is ${code}. Valid for 10 minutes.`);
}
function checkOtp(email, purpose, code) {
  const r = db.prepare('select * from otps where email=? and purpose=?').get(email, purpose);
  if (!r || r.exp < Date.now() || r.code !== String(code)) return null;
  db.prepare('delete from otps where email=? and purpose=?').run(email, purpose); return JSON.parse(r.data);
}

const app = express();
app.use(express.json(), express.static('public'), session({ secret: E.SESSION_SECRET || 'change-me-too', resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: 'lax' } }));
const A = fn => (req, res) => Promise.resolve(fn(req, res)).catch(e => { console.error(e); res.status(500).json({ error: 'Server error' }); });
const needU = (q, s, n) => q.session.uid ? n() : s.status(401).json({ error: 'Login required' });
const needT = (q, s, n) => q.session.tid ? n() : s.status(401).json({ error: 'Team login required' });
const needAdmin = (q, s, n) => q.session.trole === 'admin' ? n() : s.status(403).json({ error: 'Admin only' });
const attempts = {};
const limited = (k) => { const n = attempts[k] = (attempts[k] || 0) + 1; setTimeout(() => attempts[k]--, 15 * 60000); return n > 10; };

// ---------- customer ----------
app.post('/api/signup', A(async (q, s) => {
  const b = q.body, bad = m => s.json({ error: m });
  if (!b.name || !/^\S+@\S+\.\S+$/.test(b.email || '')) return bad('Valid name and email required');
  if (!/^\d{9,18}$/.test(b.acct || '')) return bad('Invalid account number');
  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test((b.ifsc || '').toUpperCase())) return bad('Invalid IFSC');
  if (!b.state || !b.district) return bad('State and district required');
  if (!/^\d{12}$/.test(b.aadhaar || '')) return bad('Aadhaar must be 12 digits');
  if (!PASS_RE.test(b.password || '')) return bad('Password: 8+ chars with letter, number and symbol');
  if (b.password !== b.confirm) return bad('Passwords do not match');
  if (db.prepare('select 1 from users where email=?').get(b.email)) return bad('Email already registered');
  if (limited('su' + q.ip)) return bad('Too many attempts, try later');
  await otp(b.email, 'signup', { ...b, ifsc: b.ifsc.toUpperCase(), password: bcrypt.hashSync(b.password, 10), confirm: undefined });
  s.json({ ok: true });
}));
app.post('/api/signup/verify', A(async (q, s) => {
  const d = checkOtp(q.body.email, 'signup', q.body.code);
  if (!d) return s.json({ error: 'Wrong or expired OTP' });
  let bhn; do bhn = 'BHN' + crypto.randomInt(100000, 999999); while (db.prepare('select 1 from users where bhn=?').get(bhn));
  db.prepare('insert into users(bhn,name,email,acct,ifsc,state,district,aadhaar,pass) values(?,?,?,?,?,?,?,?,?)')
    .run(bhn, d.name, d.email, d.acct, d.ifsc, d.state, d.district, enc(d.aadhaar), d.password);
  await sendMail(d.email, 'Your BHN ID', `Welcome! Your BHN ID is ${bhn}. Use it with your password to login.`);
  s.json({ ok: true, bhn });
}));
app.post('/api/login', A(async (q, s) => {
  if (limited('li' + q.ip)) return s.json({ error: 'Too many attempts, try later' });
  const bhn = (q.body.bhn || '').toUpperCase();
  const u = db.prepare('select * from users where bhn=?').get(bhn);
  if (!u) {
    if (db.prepare('select 1 from deleted where bhn=?').get(bhn))
      return s.json({ error: 'Aapka account delete ho chuka hai. Kripya naye account se sign up karein.' });
    return s.json({ error: 'Wrong BHN ID or password' });
  }
  if (!bcrypt.compareSync(q.body.password || '', u.pass)) return s.json({ error: 'Wrong BHN ID or password' });
  q.session.uid = u.id; s.json({ ok: true });
}));
app.post('/api/forgot', A(async (q, s) => {
  const u = db.prepare('select * from users where email=?').get(q.body.email || '');
  if (u && !limited('fp' + q.ip)) await otp(u.email, 'reset');
  s.json({ ok: true });
}));
app.post('/api/reset', A(async (q, s) => {
  if (!PASS_RE.test(q.body.password || '')) return s.json({ error: 'Password: 8+ chars with letter, number and symbol' });
  if (!checkOtp(q.body.email, 'reset', q.body.code)) return s.json({ error: 'Wrong or expired OTP' });
  db.prepare('update users set pass=? where email=?').run(bcrypt.hashSync(q.body.password, 10), q.body.email); s.json({ ok: true });
}));
app.post('/api/logout', (q, s) => q.session.destroy(() => s.json({ ok: true })));
app.get('/api/me', A((q, s) => {
  if (!q.session.uid) return s.json({});
  const u = db.prepare('select bhn,name,level from users where id=?').get(q.session.uid);
  const loan = db.prepare("select * from loans where user_id=? order by id desc limit 1").get(q.session.uid);
  const inst = loan && loan.status === 'approved' ? db.prepare('select * from inst where loan_id=? order by no').all(loan.id) : [];
  s.json({ user: u, plans: LEVELS[u.level], loan, inst, rate: RATE * 100 });
}));
app.post('/api/loan', needU, A((q, s) => {
  const u = db.prepare('select * from users where id=?').get(q.session.uid), amt = +q.body.amount;
  if (!LEVELS[u.level].includes(amt)) return s.json({ error: 'This amount is not available at your level' });
  if (!/^[6-9]\d{9}$/.test(q.body.mobile || '')) return s.json({ error: 'Enter a valid 10-digit mobile number' });
  const open = db.prepare("select 1 from loans l where user_id=? and (status in ('pending','mobile_verified') or (status='approved' and exists(select 1 from inst where loan_id=l.id and status!='paid')))").get(u.id);
  if (open) return s.json({ error: 'You already have an active loan/application' });
  db.prepare('insert into loans(user_id,amount,mobile) values(?,?,?)').run(u.id, amt, q.body.mobile); s.json({ ok: true });
}));
app.get('/api/upi', needU, A(async (q, s) => {
  const am = db.prepare('select amount from inst where id=?').get(+q.query.id)?.amount;
  const amt = am ? '&am=' + am.toFixed(2) : '';
  const base = `pa=${UPI_ID}&pn=BroHaiNa&cu=INR${amt}`;
  s.json({ upi: UPI_ID, amount: am, qr: await QR.toDataURL(`upi://pay?${base}`), links: {
    generic: `upi://pay?${base}`,
    phonepe: `phonepe://pay?${base}`,
    gpay: `tez://upi/pay?${base}`,
    paytm: `paytmmp://pay?${base}`
  } });
}));
app.post('/api/pay', needU, A((q, s) => {
  const i = db.prepare('select i.* from inst i join loans l on l.id=i.loan_id where i.id=? and l.user_id=?').get(q.body.id, q.session.uid);
  if (!i || i.status === 'paid') return s.json({ error: 'Invalid installment' });
  if (!/^\d{12}$/.test(q.body.utr || '')) return s.json({ error: 'UTR must be 12 digits' });
  db.prepare("update inst set status='submitted', utr=? where id=?").run(q.body.utr, i.id); s.json({ ok: true });
}));

// ---------- team ----------
app.post('/api/team/login', A((q, s) => {
  const t = db.prepare('select * from team where login=?').get(q.body.login || '');
  if (limited('tl' + q.ip) || !t || !bcrypt.compareSync(q.body.password || '', t.pass)) return s.json({ error: 'Wrong login' });
  q.session.tid = t.id; q.session.trole = t.role; s.json({ ok: true, role: t.role });
}));
app.get('/api/team/data', needT, A((q, s) => {
  const users = db.prepare('select * from users order by created desc').all().map(u => ({ ...u, pass: undefined, aadhaar: dec(u.aadhaar) }));
  const loans = db.prepare('select l.*, u.name, u.bhn from loans l join users u on u.id=l.user_id order by l.created desc').all();
  const pays = db.prepare("select i.*, u.name, u.bhn from inst i join loans l on l.id=i.loan_id join users u on u.id=l.user_id where i.status='submitted'").all();
  const team = q.session.trole === 'admin' ? db.prepare('select id,login,role from team').all() : [];
  s.json({ role: q.session.trole, users, loans, pays, team });
}));
app.post('/api/team/loan/:id/:act', needT, A((q, s) => {
  const l = db.prepare('select * from loans where id=?').get(q.params.id); if (!l) return s.json({ error: 'Not found' });
  const a = q.params.act;
  if (a === 'mobile') db.prepare("update loans set status='mobile_verified' where id=? and status='pending'").run(l.id);
  else if (a === 'reject') db.prepare("update loans set status='rejected' where id=? and status!='approved'").run(l.id);
  else if (a === 'approve') {
    if (l.status !== 'mobile_verified') return s.json({ error: 'Verify mobile first' });
    const per = Math.round(l.amount * (1 + RATE) / 4 * 100) / 100, d = firstDue();
    db.transaction(() => {
      db.prepare("update loans set status='approved', approved_at=datetime('now') where id=?").run(l.id);
      for (let n = 1; n <= 4; n++) { db.prepare('insert into inst(loan_id,no,due,amount) values(?,?,?,?)').run(l.id, n, ymd(d), per); d.setDate(d.getDate() + 7); }
    })();
  }
  s.json({ ok: true });
}));
app.post('/api/team/pay/:id/:act', needT, A((q, s) => {
  db.prepare('update inst set status=? where id=? and status=?').run(q.params.act === 'approve' ? 'paid' : 'pending', q.params.id, 'submitted'); s.json({ ok: true });
}));
app.post('/api/team/user/:id/level', needT, A((q, s) => {
  if (!LEVELS[q.body.level]) return s.json({ error: 'Bad level' });
  db.prepare('update users set level=? where id=?').run(q.body.level, q.params.id); s.json({ ok: true });
}));
app.delete('/api/team/user/:id', needT, A((q, s) => {
  db.transaction(() => { const id = q.params.id;
    const u = db.prepare('select bhn,email from users where id=?').get(id);
    if (u) db.prepare('insert or replace into deleted(bhn,email) values(?,?)').run(u.bhn, u.email);
    db.prepare('delete from inst where loan_id in (select id from loans where user_id=?)').run(id);
    db.prepare('delete from loans where user_id=?').run(id);
    db.prepare('delete from users where id=?').run(id); })();
  s.json({ ok: true });
}));
app.post('/api/admin/team', needT, needAdmin, A((q, s) => {
  if (!q.body.login || !PASS_RE.test(q.body.password || '')) return s.json({ error: 'Login + strong password required' });
  try { db.prepare('insert into team(login,pass) values(?,?)').run(q.body.login, bcrypt.hashSync(q.body.password, 10)); s.json({ ok: true }); }
  catch { s.json({ error: 'Login already exists' }); }
}));
app.delete('/api/admin/team/:id', needT, needAdmin, A((q, s) => { db.prepare("delete from team where id=? and role='team'").run(q.params.id); s.json({ ok: true }); }));

const csvCell = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
app.get('/api/team/export', needT, A((q, s) => {
  const rows = db.prepare('select * from users order by created').all();
  const head = ['BHN ID','Naam','Email','Account Number','IFSC','State','District','Aadhaar','Level','Joined'];
  const lines = [head.map(csvCell).join(',')];
  rows.forEach(u => lines.push([u.bhn, u.name, u.email, '="' + u.acct + '"', u.ifsc, u.state, u.district,
    '="' + dec(u.aadhaar) + '"', u.level, u.created].map(csvCell).join(',')));
  s.set('Content-Type', 'text/csv; charset=utf-8');
  s.set('Content-Disposition', 'attachment; filename="customers.csv"');
  s.send('\uFEFF' + lines.join('\r\n'));
}));

// SMS reminder: 2 days before due
setInterval(() => {
  const lim = ymd(new Date(Date.now() + 2 * 864e5));
  db.prepare("select i.id,i.due,i.amount,l.mobile from inst i join loans l on l.id=i.loan_id where i.status='pending' and i.reminded=0 and i.due<=?").all(lim)
    .forEach(r => { sendSms(r.mobile, `Bro Hai Na: installment of Rs ${r.amount} is pending, due on ${r.due}. Please pay on time.`); db.prepare('update inst set reminded=1 where id=?').run(r.id); });
}, 36e5);

app.listen(E.PORT || 3000, () => console.log('Running on http://localhost:' + (E.PORT || 3000)));
