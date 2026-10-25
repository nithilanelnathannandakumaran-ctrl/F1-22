// F1 22 account + admin API for Cloudflare Workers + D1.
// Secrets: ADMIN_PASSWORD (required). Bindings: DB (D1), ASSETS (static files).
const PERM = 9e15;
const adminName = env => String(env.ADMIN_USERNAME || 'elnathan').toLowerCase();
const enc = new TextEncoder();
const json = (o, status = 200, extra = {}) =>
  new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...extra } });

const hex = b => [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => hex(crypto.getRandomValues(new Uint8Array(n)));

async function pbkdf2(pw, salt) {
  const k = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 }, k, 256));
}
const sha = async t => hex(await crypto.subtle.digest('SHA-256', enc.encode(t)));
function safeEq(a, b) { if (a.length !== b.length) return false; let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i); return r === 0; }
async function hmac(key, msg) {
  const k = await crypto.subtle.importKey('raw', enc.encode(key), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(await crypto.subtle.sign('HMAC', k, enc.encode(msg)));
}
const cookies = req => Object.fromEntries((req.headers.get('cookie') || '').split(/;\s*/).filter(Boolean).map(c => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
const setCookie = (name, val, maxAge) => `${name}=${val}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

async function rateLimit(env, key, max, windowMs) {
  const now = Date.now();
  const r = await env.DB.prepare('SELECT n,reset FROM attempts WHERE k=?').bind(key).first();
  if (r && r.reset > now && r.n >= max) return false;
  if (!r || r.reset <= now) await env.DB.prepare('INSERT OR REPLACE INTO attempts(k,n,reset) VALUES(?,?,?)').bind(key, 1, now + windowMs).run();
  else await env.DB.prepare('UPDATE attempts SET n=n+1 WHERE k=?').bind(key).run();
  return true;
}
const clearAttempts = (env, key) => env.DB.prepare('DELETE FROM attempts WHERE k=?').bind(key).run();
const audit = (env, action, target = '', detail = '') =>
  env.DB.prepare('INSERT INTO audit(at,action,target,detail) VALUES(?,?,?,?)').bind(Date.now(), action, String(target), String(detail)).run();
async function setting(env, k, d) { const r = await env.DB.prepare('SELECT v FROM settings WHERE k=?').bind(k).first(); return r ? r.v : d; }

const banInfo = u => u.banned_until > Date.now()
  ? { banned: true, until: u.banned_until >= PERM ? null : u.banned_until, reason: u.ban_reason || '' } : null;
const validName = n => typeof n === 'string' && /^[A-Za-z0-9_.\- ]{3,20}$/.test(n.trim());

async function userFromSession(req, env) {
  const t = cookies(req).sid; if (!t) return null;
  const s = await env.DB.prepare('SELECT user_id,expires FROM sessions WHERE token_hash=?').bind(await sha(t)).first();
  if (!s || s.expires < Date.now()) return null;
  return env.DB.prepare('SELECT * FROM users WHERE id=?').bind(s.user_id).first();
}
async function newSession(env, userId) {
  const t = rand(32);
  await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)').bind(await sha(t), userId, Date.now() + 30 * 864e5).run();
  await env.DB.prepare('DELETE FROM sessions WHERE expires<?').bind(Date.now()).run();
  return t;
}
const pub = (u, env) => ({ user: u.username, profile: JSON.parse(u.profile || '{}'), isAdmin: u.username_lc === adminName(env) });

async function adminOK(req, env) {
  const su = await userFromSession(req, env);   // signed in to the game as the admin username
  if (su && su.username_lc === adminName(env)) return true;
  const t = cookies(req).adm; if (!t || !env.ADMIN_PASSWORD) return false;
  const [exp, sig] = t.split('.');
  if (!exp || !sig || +exp < Date.now()) return false;
  return safeEq(sig, await hmac(env.ADMIN_PASSWORD, 'admin.' + exp));
}
let schemaOK = false;
async function ensureSchema(env) {
  if (schemaOK) return;
  await env.DB.batch([
    env.DB.prepare('CREATE TABLE IF NOT EXISTS friends(id INTEGER PRIMARY KEY AUTOINCREMENT,a INTEGER,b INTEGER,status TEXT,at INTEGER,UNIQUE(a,b))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS dms(id INTEGER PRIMARY KEY AUTOINCREMENT,frm INTEGER,too INTEGER,txt TEXT,at INTEGER)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS dms_i ON dms(too,frm,id)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS grp(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,owner INTEGER,at INTEGER)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS grp_m(g INTEGER,u INTEGER,PRIMARY KEY(g,u))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS grp_msg(id INTEGER PRIMARY KEY AUTOINCREMENT,g INTEGER,u INTEGER,txt TEXT,at INTEGER)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS gm_i ON grp_msg(g,id)'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS reads(u INTEGER,k TEXT,last INTEGER,PRIMARY KEY(u,k))'),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS mutes(u INTEGER PRIMARY KEY,until INTEGER)'),
  ]);
  schemaOK = true;
}
const cleanTxt = t => String(t || '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 300);
const announceNow = async env => { try { const a = JSON.parse(await setting(env, 'announce', 'null')); return a && a.text && (!a.until || a.until > Date.now()) ? a.text : ''; } catch { return ''; } };
const maintOn = async env => { try { const a = JSON.parse(await setting(env, 'maint', 'null')); return a && a.on ? (a.msg || 'The game is down for maintenance. Back soon.') : ''; } catch { return ''; } };
const ip = req => req.headers.get('cf-connecting-ip') || 'x';

export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname, m = req.method;
    if (!p.startsWith('/api/')) return env.ASSETS.fetch(req);
    // CSRF: state-changing requests must be same-origin JSON
    if (m !== 'GET') {
      const o = req.headers.get('origin');
      if (o && o !== url.origin) return json({ error: 'Bad origin' }, 403);
    }
    try {
      await ensureSchema(env);
      /* ---------- multiplayer rooms (WebSocket -> Durable Object) ---------- */
      if (p === '/api/room') {
        if (req.headers.get('upgrade') !== 'websocket') return json({ error: 'WebSocket required' }, 426);
        const o = req.headers.get('origin'); if (o && o !== url.origin) return json({ error: 'Bad origin' }, 403);
        const u = await userFromSession(req, env);
        if (!u) return json({ error: 'Sign in to play online' }, 401);
        if (banInfo(u)) return json({ error: 'banned' }, 403);
        if (u.username_lc !== adminName(env) && (await maintOn(env))) return json({ error: 'maintenance' }, 503);
        const code = (url.searchParams.get('code') || '').toUpperCase();
        if (!/^[A-Z0-9]{4}$/.test(code)) return json({ error: 'Bad room code' }, 400);
        const h = new Headers(req.headers); h.set('x-f1-user', u.username);
        return env.ROOM.get(env.ROOM.idFromName(code)).fetch(new Request(req.url, { headers: h }));
      }
      let body = {};
      if (m !== 'GET' && m !== 'HEAD') { try { body = await req.json(); } catch { body = {}; } }

      /* ---------- player API ---------- */
      if (p === '/api/register' && m === 'POST') {
        if ((await setting(env, 'registration', 'on')) !== 'on') return json({ error: 'New sign-ups are closed right now' }, 403);
        { const mm = await maintOn(env); if (mm) return json({ error: mm }, 503); }
        if (!(await rateLimit(env, 'reg:' + ip(req), 10, 3600e3))) return json({ error: 'Too many sign-ups from this network. Try later.' }, 429);
        const name = (body.username || '').trim(), pw = body.password || '';
        if (name.toLowerCase() === adminName(env)) return json({ error: 'That username is reserved' }, 403);
        if (!validName(name)) return json({ error: 'Username: 3-20 letters, numbers, space . _ -' }, 400);
        if (typeof pw !== 'string' || pw.length < 6 || pw.length > 100) return json({ error: 'Password must be 6+ characters' }, 400);
        if (await env.DB.prepare('SELECT 1 FROM users WHERE username_lc=?').bind(name.toLowerCase()).first()) return json({ error: 'That username is taken' }, 409);
        const salt = rand(16), now = Date.now();
        const r = await env.DB.prepare('INSERT INTO users(username,username_lc,salt,hash,created_at,last_login,last_seen) VALUES(?,?,?,?,?,?,?)')
          .bind(name, name.toLowerCase(), salt, await pbkdf2(pw, salt), now, now, now).run();
        const tok = await newSession(env, r.meta.last_row_id);
        return json({ user: name, profile: {}, isNew: true }, 200, { 'set-cookie': setCookie('sid', tok, 30 * 86400) });
      }
      if (p === '/api/login' && m === 'POST') {
        const name = (body.username || '').trim().toLowerCase(), key = 'login:' + ip(req) + ':' + name;
        if (!(await rateLimit(env, key, 8, 600e3))) return json({ error: 'Too many attempts. Wait 10 minutes.' }, 429);
        let u = await env.DB.prepare('SELECT * FROM users WHERE username_lc=?').bind(name).first();
        let okPw;
        if (name === adminName(env)) {
          // the admin account always signs in with the ADMIN_PASSWORD secret and is created on first use
          okPw = !!env.ADMIN_PASSWORD && safeEq(await sha(String(body.password || '')), await sha(env.ADMIN_PASSWORD));
          if (okPw && !u) {
            const salt = rand(16), now = Date.now();
            await env.DB.prepare('INSERT INTO users(username,username_lc,salt,hash,created_at,last_login,last_seen) VALUES(?,?,?,?,?,?,?)').bind(name, name, salt, await pbkdf2(rand(16), salt), now, now, now).run();
            u = await env.DB.prepare('SELECT * FROM users WHERE username_lc=?').bind(name).first();
          }
        } else okPw = u && safeEq(await pbkdf2(String(body.password || ''), u.salt), u.hash);
        if (!okPw) return json({ error: 'Wrong username or password' }, 401);
        const b = (name === adminName(env)) ? null : banInfo(u); if (b) return json({ error: 'banned', ...b }, 403);
        if (name !== adminName(env)) { const mm = await maintOn(env); if (mm) return json({ error: mm }, 503); }
        await clearAttempts(env, key);
        await env.DB.prepare('UPDATE users SET last_login=?,last_seen=? WHERE id=?').bind(Date.now(), Date.now(), u.id).run();
        const tok = await newSession(env, u.id);
        return json(pub(u, env), 200, { 'set-cookie': setCookie('sid', tok, 30 * 86400) });
      }
      if (p === '/api/logout' && m === 'POST') {
        const t = cookies(req).sid; if (t) await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await sha(t)).run();
        return json({ ok: true }, 200, { 'set-cookie': setCookie('sid', '', 0) });
      }
      if (p === '/api/me' && m === 'GET') {
        const u = await userFromSession(req, env); if (!u) return json({ user: null });
        const b = banInfo(u); if (b) return json({ user: null, ...b }, 403);
        await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(Date.now(), u.id).run();
        const mm = u.username_lc === adminName(env) ? '' : await maintOn(env); if (mm) return json({ user: null, maint: mm }, 503);
        return json({ ...pub(u, env), announce: await announceNow(env) });
      }
      if (p === '/api/profile' && m === 'PUT') {
        const u = await userFromSession(req, env); if (!u) return json({ error: 'Not signed in' }, 401);
        if (banInfo(u)) return json({ error: 'banned' }, 403);
        const pr = body.profile; if (!pr || typeof pr !== 'object') return json({ error: 'Bad profile' }, 400);
        const clean = {};
        if (pr.drv && typeof pr.drv === 'object') clean.drv = { name: String(pr.drv.name || '').slice(0, 22), tag: String(pr.drv.tag || '').slice(0, 3), num: Math.max(1, Math.min(99, +pr.drv.num || 7)), nat: String(pr.drv.nat || 'GBR').slice(0, 3) };
        if (Array.isArray(pr.livery) && pr.livery.length === 3) clean.livery = pr.livery.map(x => String(x).slice(0, 9));
        if (pr.bests && typeof pr.bests === 'object') { clean.bests = {}; for (const [k, v] of Object.entries(pr.bests).slice(0, 30)) if (/^apex-(best|sec)[-a-z0-9]*$/.test(k)) clean.bests[k] = String(v).slice(0, 80); }
        const ch = pr.champ;
        if (ch && typeof ch === 'object' && Array.isArray(ch.p) && ch.p.length === 19) {
          const n = (v, lo, hi) => Math.max(lo, Math.min(hi, v | 0));
          clean.champ = { u: n(ch.u, 2, 20), r: n(ch.r, 0, 20), s: n(ch.s, 1, 9999), p: ch.p.map(v => n(v, 0, 9999)),
            h: (Array.isArray(ch.h) ? ch.h : []).slice(0, 20).map(x => Array.isArray(x) ? [n(x[0], 0, 30), n(x[1], 0, 30)] : null),
            c: (Array.isArray(ch.c) ? ch.c : []).slice(-12).map(v => n(v, 0, 30)) };
        }
        const s = JSON.stringify(clean); if (s.length > 7000) return json({ error: 'Too large' }, 400);
        await env.DB.prepare('UPDATE users SET profile=? WHERE id=?').bind(s, u.id).run();
        return json({ ok: true });
      }

      /* ---------- friends, chat and groups ---------- */
      if (p.startsWith('/api/friends') || p.startsWith('/api/chat') || p.startsWith('/api/groups')) {
        const me = await userFromSession(req, env); if (!me) return json({ error: 'Not signed in' }, 401);
        if (banInfo(me)) return json({ error: 'banned' }, 403);
        const now = Date.now(), M = me.id;
        await env.DB.prepare('UPDATE users SET last_seen=? WHERE id=?').bind(now, M).run();
        const byName = async n => env.DB.prepare('SELECT id,username FROM users WHERE username_lc=?').bind(String(n || '').trim().toLowerCase()).first();
        const isFriend = async o => !!(await env.DB.prepare("SELECT 1 FROM friends WHERE status='ok' AND ((a=? AND b=?) OR (a=? AND b=?))").bind(M, o, o, M).first());
        const isMuted = async () => { const r = await env.DB.prepare('SELECT until FROM mutes WHERE u=?').bind(M).first(); return r && r.until > now ? r.until : 0; };
        const markRead = (k, last) => env.DB.prepare('INSERT OR REPLACE INTO reads(u,k,last) VALUES(?,?,?)').bind(M, k, last).run();
        const inGroup = async g => !!(await env.DB.prepare('SELECT 1 FROM grp_m WHERE g=? AND u=?').bind(g, M).first());
        const MAXG = 12;

        if (p === '/api/friends' && m === 'GET') {
          const fr = (await env.DB.prepare(`SELECT u.id,u.username,u.last_seen,
              (SELECT COUNT(*) FROM dms d WHERE d.too=?1 AND d.frm=u.id AND d.id>COALESCE((SELECT last FROM reads r WHERE r.u=?1 AND r.k='dm:'||u.id),0)) AS unread
              FROM friends f JOIN users u ON u.id=CASE WHEN f.a=?1 THEN f.b ELSE f.a END
              WHERE f.status='ok' AND (f.a=?1 OR f.b=?1) ORDER BY u.last_seen DESC`).bind(M).all()).results.map(r => ({ id: r.id, name: r.username, online: r.last_seen > now - 120e3, unread: r.unread }));
          const inc = (await env.DB.prepare("SELECT f.id,u.username FROM friends f JOIN users u ON u.id=f.a WHERE f.status='pending' AND f.b=? ORDER BY f.id DESC").bind(M).all()).results.map(r => ({ id: r.id, name: r.username }));
          const out = (await env.DB.prepare("SELECT f.id,u.username FROM friends f JOIN users u ON u.id=f.b WHERE f.status='pending' AND f.a=? ORDER BY f.id DESC").bind(M).all()).results.map(r => ({ id: r.id, name: r.username }));
          const groups = (await env.DB.prepare(`SELECT g.id,g.name,g.owner,
              (SELECT group_concat(u.username,', ') FROM grp_m gm JOIN users u ON u.id=gm.u WHERE gm.g=g.id) AS members,
              (SELECT COUNT(*) FROM grp_msg x WHERE x.g=g.id AND x.u<>?1 AND x.id>COALESCE((SELECT last FROM reads r WHERE r.u=?1 AND r.k='g:'||g.id),0)) AS unread
              FROM grp g JOIN grp_m m2 ON m2.g=g.id AND m2.u=?1 ORDER BY g.id DESC`).bind(M).all()).results.map(r => ({ id: r.id, name: r.name, mine: r.owner === M, members: r.members || '', unread: r.unread }));
          return json({ me: me.username, friends: fr, incoming: inc, outgoing: out, groups, muted: !!(await isMuted()), announce: await announceNow(env) });
        }
        if (p === '/api/friends/add' && m === 'POST') {
          const t = await byName(body.username); if (!t) return json({ error: 'No player with that username' }, 404);
          if (t.id === M) return json({ error: 'That is you' }, 400);
          const ex = await env.DB.prepare('SELECT id,a,status FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(M, t.id, t.id, M).first();
          if (ex) {
            if (ex.status === 'ok') return json({ error: 'Already friends' }, 409);
            if (ex.a === M) return json({ error: 'Request already sent' }, 409);
            await env.DB.prepare("UPDATE friends SET status='ok' WHERE id=?").bind(ex.id).run(); return json({ ok: true, accepted: true, name: t.username });
          }
          if (!(await rateLimit(env, 'fadd:' + M, 20, 3600e3))) return json({ error: 'Too many requests. Try later.' }, 429);
          await env.DB.prepare("INSERT INTO friends(a,b,status,at) VALUES(?,?,'pending',?)").bind(M, t.id, now).run(); return json({ ok: true, name: t.username });
        }
        if (p === '/api/friends/respond' && m === 'POST') {
          const r = await env.DB.prepare("SELECT id FROM friends WHERE id=? AND b=? AND status='pending'").bind(+body.id, M).first(); if (!r) return json({ error: 'Request not found' }, 404);
          if (body.accept) await env.DB.prepare("UPDATE friends SET status='ok' WHERE id=?").bind(r.id).run(); else await env.DB.prepare('DELETE FROM friends WHERE id=?').bind(r.id).run();
          return json({ ok: true });
        }
        if (p === '/api/friends/remove' && m === 'POST') {
          const t = await byName(body.username); if (!t) return json({ error: 'Not found' }, 404);
          await env.DB.prepare('DELETE FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)').bind(M, t.id, t.id, M).run(); return json({ ok: true });
        }
        if (p === '/api/chat/dm' && m === 'GET') {
          const t = await byName(url.searchParams.get('with')); if (!t || !(await isFriend(t.id))) return json({ error: 'Not friends' }, 403);
          const after = +url.searchParams.get('after') || 0;
          const rows = (await env.DB.prepare('SELECT id,frm,txt,at FROM dms WHERE id>? AND ((frm=? AND too=?) OR (frm=? AND too=?)) ORDER BY id DESC LIMIT 80').bind(after, M, t.id, t.id, M).all()).results.reverse();
          if (rows.length) await markRead('dm:' + t.id, rows[rows.length - 1].id);
          return json({ msgs: rows.map(r => ({ id: r.id, mine: r.frm === M, text: r.txt, at: r.at })) });
        }
        if (p === '/api/chat/dm' && m === 'POST') {
          const t = await byName(body.to); if (!t || !(await isFriend(t.id))) return json({ error: 'You can only message friends' }, 403);
          const mu = await isMuted(); if (mu) return json({ error: 'You are muted' + (mu >= PERM ? '' : ' until ' + new Date(mu).toLocaleString()) }, 403);
          const txt = cleanTxt(body.text); if (!txt) return json({ error: 'Empty message' }, 400);
          if (!(await rateLimit(env, 'chat:' + M, 40, 60e3))) return json({ error: 'Slow down' }, 429);
          const r = await env.DB.prepare('INSERT INTO dms(frm,too,txt,at) VALUES(?,?,?,?)').bind(M, t.id, txt, now).run();
          await markRead('dm:' + t.id, r.meta.last_row_id); return json({ ok: true });
        }
        if (p === '/api/groups/create' && m === 'POST') {
          const name = cleanTxt(body.name).slice(0, 24); if (!name) return json({ error: 'Give the group a name' }, 400);
          const mu = await isMuted(); if (mu) return json({ error: 'You are muted' }, 403);
          if (!(await rateLimit(env, 'gmk:' + M, 10, 3600e3))) return json({ error: 'Too many groups created. Try later.' }, 429);
          const ids = [];
          for (const n of (Array.isArray(body.members) ? body.members : []).slice(0, MAXG - 1)) { const t = await byName(n); if (t && t.id !== M && !ids.includes(t.id) && await isFriend(t.id)) ids.push(t.id); }
          const r = await env.DB.prepare('INSERT INTO grp(name,owner,at) VALUES(?,?,?)').bind(name, M, now).run(); const g = r.meta.last_row_id;
          await env.DB.batch([M, ...ids].map(u => env.DB.prepare('INSERT OR IGNORE INTO grp_m(g,u) VALUES(?,?)').bind(g, u)));
          return json({ ok: true, id: g });
        }
        if (p === '/api/groups/msgs' && m === 'GET') {
          const g = +url.searchParams.get('g'); if (!(await inGroup(g))) return json({ error: 'Not in this group' }, 403);
          const after = +url.searchParams.get('after') || 0;
          const rows = (await env.DB.prepare('SELECT x.id,x.u,x.txt,x.at,u.username FROM grp_msg x JOIN users u ON u.id=x.u WHERE x.g=? AND x.id>? ORDER BY x.id DESC LIMIT 80').bind(g, after).all()).results.reverse();
          if (rows.length) await markRead('g:' + g, rows[rows.length - 1].id);
          return json({ msgs: rows.map(r => ({ id: r.id, mine: r.u === M, from: r.username, text: r.txt, at: r.at })) });
        }
        if (p === '/api/groups/send' && m === 'POST') {
          const g = +body.g; if (!(await inGroup(g))) return json({ error: 'Not in this group' }, 403);
          const mu = await isMuted(); if (mu) return json({ error: 'You are muted' + (mu >= PERM ? '' : ' until ' + new Date(mu).toLocaleString()) }, 403);
          const txt = cleanTxt(body.text); if (!txt) return json({ error: 'Empty message' }, 400);
          if (!(await rateLimit(env, 'chat:' + M, 40, 60e3))) return json({ error: 'Slow down' }, 429);
          const r = await env.DB.prepare('INSERT INTO grp_msg(g,u,txt,at) VALUES(?,?,?,?)').bind(g, M, txt, now).run();
          await markRead('g:' + g, r.meta.last_row_id); return json({ ok: true });
        }
        if (p === '/api/groups/add' && m === 'POST') {
          const g = +body.g; if (!(await inGroup(g))) return json({ error: 'Not in this group' }, 403);
          const t = await byName(body.username); if (!t || !(await isFriend(t.id))) return json({ error: 'You can only add your friends' }, 403);
          const c = await env.DB.prepare('SELECT COUNT(*) n FROM grp_m WHERE g=?').bind(g).first(); if (c.n >= MAXG) return json({ error: 'Group is full (' + MAXG + ')' }, 400);
          await env.DB.prepare('INSERT OR IGNORE INTO grp_m(g,u) VALUES(?,?)').bind(g, t.id).run(); return json({ ok: true });
        }
        if (p === '/api/groups/leave' && m === 'POST') {
          const g = +body.g; if (!(await inGroup(g))) return json({ error: 'Not in this group' }, 403);
          await env.DB.prepare('DELETE FROM grp_m WHERE g=? AND u=?').bind(g, M).run();
          const c = await env.DB.prepare('SELECT COUNT(*) n FROM grp_m WHERE g=?').bind(g).first();
          if (!c.n) await env.DB.batch([env.DB.prepare('DELETE FROM grp WHERE id=?').bind(g), env.DB.prepare('DELETE FROM grp_msg WHERE g=?').bind(g)]);
          else { const o = await env.DB.prepare('SELECT owner FROM grp WHERE id=?').bind(g).first(); if (o && o.owner === M) { const n = await env.DB.prepare('SELECT u FROM grp_m WHERE g=? LIMIT 1').bind(g).first(); await env.DB.prepare('UPDATE grp SET owner=? WHERE id=?').bind(n.u, g).run(); } }
          return json({ ok: true });
        }
        return json({ error: 'Not found' }, 404);
      }

      /* ---------- admin API ---------- */
      if (p === '/api/admin/login' && m === 'POST') {
        if (!env.ADMIN_PASSWORD) return json({ error: 'ADMIN_PASSWORD secret is not set' }, 500);
        if (!(await rateLimit(env, 'adm:' + ip(req), 6, 900e3))) return json({ error: 'Too many attempts. Wait 15 minutes.' }, 429);
        if (!safeEq(await sha(String(body.password || '')), await sha(env.ADMIN_PASSWORD))) return json({ error: 'Wrong admin password' }, 401);
        await clearAttempts(env, 'adm:' + ip(req));
        const exp = Date.now() + 12 * 3600e3, sig = await hmac(env.ADMIN_PASSWORD, 'admin.' + exp);
        return json({ ok: true }, 200, { 'set-cookie': setCookie('adm', exp + '.' + sig, 12 * 3600) });
      }
      if (p.startsWith('/api/admin/')) {
        if (!(await adminOK(req, env))) return json({ error: 'Admin sign-in required' }, 401);
        if (p === '/api/admin/logout') return json({ ok: true }, 200, { 'set-cookie': setCookie('adm', '', 0) });
        if (p === '/api/admin/overview' && m === 'GET') {
          const now = Date.now();
          const q = (url.searchParams.get('q') || '').trim().toLowerCase();
          const rows = (await env.DB.prepare(`SELECT id,username,profile,banned_until,ban_reason,created_at,last_login,last_seen,
              (SELECT COUNT(*) FROM sessions s WHERE s.user_id=users.id AND s.expires>?) AS sessions,(SELECT until FROM mutes m WHERE m.u=users.id) AS muted_until,(SELECT COUNT(*) FROM friends f WHERE f.status=\'ok\' AND (f.a=users.id OR f.b=users.id)) AS nfriends FROM users
              WHERE username_lc LIKE ? ORDER BY last_seen DESC LIMIT 500`).bind(now, '%' + q.replace(/[%_]/g, '') + '%').all()).results;
          const users = rows.map(r => { const pr = JSON.parse(r.profile || '{}'); return { ...r, profile: undefined, driver: pr.drv ? pr.drv.name : '', bests: pr.bests || {} }; });
          const st = await env.DB.prepare('SELECT COUNT(*) total,SUM(banned_until>?) banned,SUM(last_seen>?) online,SUM(created_at>?) today FROM users').bind(now, now - 5 * 60e3, now - 864e5).first();
          const log = (await env.DB.prepare('SELECT at,action,target,detail FROM audit ORDER BY id DESC LIMIT 60').all()).results;
          const ex = await env.DB.prepare('SELECT (SELECT COUNT(*) FROM dms) dms,(SELECT COUNT(*) FROM grp) groups,(SELECT COUNT(*) FROM grp_msg) gmsgs,(SELECT COUNT(*) FROM friends WHERE status=\'ok\') friends').first();
          return json({ now, stats: { ...st, ...ex }, registration: (await setting(env, 'registration', 'on')) === 'on', announce: await announceNow(env), maintenance: await maintOn(env), users, log });
        }
        if (p === '/api/admin/registration' && m === 'POST') {
          await env.DB.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)').bind('registration', body.on ? 'on' : 'off').run();
          await audit(env, 'registration', '', body.on ? 'opened' : 'closed'); return json({ ok: true });
        }
        if (p === '/api/admin/logout-all' && m === 'POST') { await env.DB.prepare('DELETE FROM sessions').run(); await audit(env, 'logout-all'); return json({ ok: true }); }

        if (p === '/api/admin/announce' && m === 'POST') {
          const text = cleanTxt(body.text), mins = +body.minutes;
          await env.DB.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)').bind('announce', JSON.stringify(text ? { text, until: mins > 0 ? Date.now() + mins * 60e3 : 0 } : null)).run();
          await audit(env, 'announce', '', text || 'cleared'); return json({ ok: true });
        }
        if (p === '/api/admin/maintenance' && m === 'POST') {
          await env.DB.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)').bind('maint', JSON.stringify({ on: !!body.on, msg: cleanTxt(body.msg) })).run();
          if (body.on) await env.DB.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username_lc<>?)').bind(adminName(env)).run();
          await audit(env, 'maintenance', '', body.on ? 'on' : 'off'); return json({ ok: true });
        }
        if (p === '/api/admin/purge' && m === 'POST') {
          const days = Math.max(1, +body.days || 90), cut = Date.now() - days * 864e5;
          const q = "FROM users WHERE username_lc<>? AND last_seen<? AND created_at<?";
          const n = (await env.DB.prepare('SELECT COUNT(*) n ' + q).bind(adminName(env), cut, cut).first()).n;
          if (body.confirm) {
            await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE user_id IN (SELECT id ' + q + ')').bind(adminName(env), cut, cut),
              env.DB.prepare('DELETE FROM friends WHERE a IN (SELECT id ' + q + ') OR b IN (SELECT id ' + q + ')').bind(adminName(env), cut, cut, adminName(env), cut, cut),
              env.DB.prepare('DELETE FROM users WHERE id IN (SELECT id ' + q + ')').bind(adminName(env), cut, cut)]);
            await audit(env, 'purge', '', n + ' accounts inactive ' + days + '+ days');
          }
          return json({ ok: true, count: n });
        }
        if (p === '/api/admin/groups' && m === 'GET') {
          const rows = (await env.DB.prepare(`SELECT g.id,g.name,g.at,(SELECT username FROM users WHERE id=g.owner) AS owner,
              (SELECT group_concat(u.username,', ') FROM grp_m gm JOIN users u ON u.id=gm.u WHERE gm.g=g.id) AS members,
              (SELECT COUNT(*) FROM grp_msg x WHERE x.g=g.id) AS msgs FROM grp g ORDER BY g.id DESC LIMIT 100`).all()).results;
          return json({ groups: rows });
        }
        if (p === '/api/admin/group-msgs' && m === 'GET') {
          const g = +url.searchParams.get('g');
          const rows = (await env.DB.prepare('SELECT x.id,x.at,x.txt,u.username FROM grp_msg x JOIN users u ON u.id=x.u WHERE x.g=? ORDER BY x.id DESC LIMIT 100').bind(g).all()).results.reverse();
          return json({ msgs: rows });
        }
        if (p === '/api/admin/group-delete' && m === 'POST') {
          const g = +body.id; await env.DB.batch([env.DB.prepare('DELETE FROM grp_msg WHERE g=?').bind(g), env.DB.prepare('DELETE FROM grp_m WHERE g=?').bind(g), env.DB.prepare('DELETE FROM grp WHERE id=?').bind(g)]);
          await audit(env, 'group-delete', '#' + g); return json({ ok: true });
        }
        if (p === '/api/admin/export' && m === 'GET') {
          const rows = (await env.DB.prepare('SELECT username,created_at,last_login,last_seen,banned_until FROM users ORDER BY id').all()).results;
          const csv = 'username,created,last_login,last_seen,banned\n' + rows.map(r => [r.username, new Date(r.created_at).toISOString(), new Date(r.last_login).toISOString(), new Date(r.last_seen).toISOString(), r.banned_until > Date.now() ? 'yes' : 'no'].map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
          return new Response(csv, { headers: { 'content-type': 'text/csv', 'content-disposition': 'attachment; filename="f1-22-users.csv"', 'cache-control': 'no-store' } });
        }

        const id = +body.id; const u = id ? await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(id).first() : null;
        if (!u) return json({ error: 'User not found' }, 404);
        const act = p.slice('/api/admin/'.length);
        if (u.username_lc === adminName(env) && ['ban', 'rename', 'password', 'delete'].includes(act)) return json({ error: 'The admin account is protected' }, 400);
        if (act === 'ban') {
          const mins = +body.minutes; const until = mins > 0 ? Date.now() + mins * 60e3 : PERM;
          // sessions are kept so the player's next /api/me check shows the ban reason; every request re-checks the ban
          await env.DB.prepare('UPDATE users SET banned_until=?,ban_reason=? WHERE id=?').bind(until, String(body.reason || '').slice(0, 200), id).run();
          await audit(env, 'ban', u.username, (mins > 0 ? mins + ' min' : 'permanent') + (body.reason ? ' - ' + body.reason : '')); return json({ ok: true });
        }
        if (act === 'unban') { await env.DB.prepare("UPDATE users SET banned_until=0,ban_reason='' WHERE id=?").bind(id).run(); await audit(env, 'unban', u.username); return json({ ok: true }); }
        if (act === 'kick') { await env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id).run(); await audit(env, 'force-logout', u.username); return json({ ok: true }); }
        if (act === 'rename') {
          const name = (body.username || '').trim(); if (!validName(name)) return json({ error: 'Username: 3-20 letters, numbers, space . _ -' }, 400);
          const clash = await env.DB.prepare('SELECT id FROM users WHERE username_lc=? AND id<>?').bind(name.toLowerCase(), id).first();
          if (clash) return json({ error: 'That username is taken' }, 409);
          await env.DB.prepare('UPDATE users SET username=?,username_lc=? WHERE id=?').bind(name, name.toLowerCase(), id).run();
          await audit(env, 'rename', u.username, '-> ' + name); return json({ ok: true });
        }
        if (act === 'driver') {
          const pr = JSON.parse(u.profile || '{}'); pr.drv = pr.drv || { name: u.username, tag: 'DRI', num: 7, nat: 'GBR' };
          pr.drv.name = String(body.name || '').trim().slice(0, 22) || u.username;
          await env.DB.prepare('UPDATE users SET profile=? WHERE id=?').bind(JSON.stringify(pr), id).run();
          await audit(env, 'driver-name', u.username, '-> ' + pr.drv.name); return json({ ok: true });
        }
        if (act === 'password') {
          const pw = String(body.password || ''); if (pw.length < 6) return json({ error: 'Password must be 6+ characters' }, 400);
          const salt = rand(16);
          await env.DB.batch([env.DB.prepare('UPDATE users SET salt=?,hash=? WHERE id=?').bind(salt, await pbkdf2(pw, salt), id), env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id)]);
          await audit(env, 'password-reset', u.username); return json({ ok: true });
        }
        if (act === 'reset-times') {
          const pr = JSON.parse(u.profile || '{}'); delete pr.bests;
          await env.DB.prepare('UPDATE users SET profile=? WHERE id=?').bind(JSON.stringify(pr), id).run(); await audit(env, 'reset-times', u.username); return json({ ok: true });
        }
        if (act === 'mute') { const mins = +body.minutes; await env.DB.prepare('INSERT OR REPLACE INTO mutes(u,until) VALUES(?,?)').bind(id, mins > 0 ? Date.now() + mins * 60e3 : PERM).run(); await audit(env, 'mute', u.username, mins > 0 ? mins + ' min' : 'permanent'); return json({ ok: true }); }
        if (act === 'unmute') { await env.DB.prepare('DELETE FROM mutes WHERE u=?').bind(id).run(); await audit(env, 'unmute', u.username); return json({ ok: true }); }
        if (act === 'unlock-all' || act === 'reset-champ') {
          const pr = JSON.parse(u.profile || '{}');
          if (act === 'reset-champ') delete pr.champ; else { const c = pr.champ || { u: 2, r: 0, s: 1, p: Array(19).fill(0), h: [], c: [] }; c.u = 20; pr.champ = c; }
          await env.DB.prepare('UPDATE users SET profile=? WHERE id=?').bind(JSON.stringify(pr), id).run(); await audit(env, act, u.username); return json({ ok: true });
        }
        if (act === 'reset-profile') { await env.DB.prepare("UPDATE users SET profile='{}' WHERE id=?").bind(id).run(); await audit(env, 'reset-profile', u.username); return json({ ok: true }); }
        if (act === 'chat') {
          const rows = (await env.DB.prepare('SELECT d.at,d.txt,(SELECT username FROM users WHERE id=d.frm) AS f,(SELECT username FROM users WHERE id=d.too) AS t FROM dms d WHERE d.frm=? OR d.too=? ORDER BY d.id DESC LIMIT 100').bind(id, id).all()).results.reverse();
          const g = (await env.DB.prepare('SELECT g.name,x.at,x.txt FROM grp_msg x JOIN grp g ON g.id=x.g WHERE x.u=? ORDER BY x.id DESC LIMIT 60').bind(id).all()).results.reverse();
          const fr = (await env.DB.prepare("SELECT u.username FROM friends f JOIN users u ON u.id=CASE WHEN f.a=? THEN f.b ELSE f.a END WHERE f.status='ok' AND (f.a=? OR f.b=?)").bind(id, id, id).all()).results.map(r => r.username);
          return json({ dms: rows, groups: g, friends: fr });
        }
        if (act === 'clear-chat') { await env.DB.batch([env.DB.prepare('DELETE FROM dms WHERE frm=? OR too=?').bind(id, id), env.DB.prepare('DELETE FROM grp_msg WHERE u=?').bind(id)]); await audit(env, 'clear-chat', u.username); return json({ ok: true }); }
        if (act === 'delete') {
          await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id), env.DB.prepare('DELETE FROM friends WHERE a=? OR b=?').bind(id, id), env.DB.prepare('DELETE FROM dms WHERE frm=? OR too=?').bind(id, id), env.DB.prepare('DELETE FROM grp_m WHERE u=?').bind(id), env.DB.prepare('DELETE FROM users WHERE id=?').bind(id)]);
          await audit(env, 'delete', u.username); return json({ ok: true });
        }
        return json({ error: 'Unknown action' }, 404);
      }
      return json({ error: 'Not found' }, 404);
    } catch (e) {
      return json({ error: 'Server error', detail: String(e && e.message || e) }, 500);
    }
  }
};


/* ---------- Durable Object: one race lobby / room ---------- */
const MAXP = 10;
const num = (v, lo, hi, d) => { v = +v; return Number.isFinite(v) ? Math.max(lo, Math.min(hi, v)) : d; };
const hexOk = c => (typeof c === 'string' && /^#[0-9a-fA-F]{6}$/.test(c)) ? c : '#888888';
export class Room {
  constructor(state, env) {
    this.players = new Map(); this.track = 'apex'; this.laps = 10; this.status = 'lobby'; this.nextId = 1; this.timer = null; this.raceSeq = 0;
  }
  hostId() { let m = Infinity; for (const id of this.players.keys()) if (id < m) m = id; return m; }
  send(p, o) { try { p.ws.send(JSON.stringify(o)); } catch (e) {} }
  all(o, except) { const s = JSON.stringify(o); for (const p of this.players.values()) if (p.id !== except) { try { p.ws.send(s); } catch (e) {} } }
  lobby() {
    const h = this.hostId();
    this.all({ t: 'lobby', track: this.track, laps: this.laps, status: this.status,
      players: [...this.players.values()].map(p => ({ id: p.id, name: p.name, drv: p.drv, tag: p.tag, num: p.num, des: p.des | 0, liv: p.liv, host: p.id === h })) });
  }
  endRace() {
    clearTimeout(this.timer); this.timer = null; if (this.status !== 'racing') return;
    this.status = 'lobby';
    const res = [...this.players.values()].filter(p => p.fin != null).sort((a, b) => a.fin - b.fin).map(p => ({ id: p.id, name: p.drv || p.name, time: p.fin }));
    this.all({ t: 'end', results: res }); this.lobby();
  }
  checkEnd() { if (this.status === 'racing' && [...this.players.values()].every(p => p.fin != null)) this.endRace(); }
  async fetch(req) {
    if (req.headers.get('upgrade') !== 'websocket') return new Response('WebSocket only', { status: 426 });
    const url = new URL(req.url), user = req.headers.get('x-f1-user') || 'Driver';
    const create = url.searchParams.get('create') === '1', trk = (url.searchParams.get('track') || 'apex');
    const pair = new WebSocketPair(), client = pair[0], server = pair[1];
    server.accept();
    const refuse = msg => { try { server.send(JSON.stringify({ t: 'err', msg })); server.close(1000, 'refused'); } catch (e) {} return new Response(null, { status: 101, webSocket: client }); };
    if (!create && this.players.size === 0) return refuse('Room not found. Check the code.');
    if (this.status !== 'lobby') return refuse('A race is in progress. Try again when it ends.');
    // same account joining again replaces the old connection
    for (const q of this.players.values()) if (q.name === user) { this.players.delete(q.id); try { q.ws.close(1000, 'replaced'); } catch (e) {} }
    if (this.players.size >= MAXP) return refuse('Room is full (10 players).');
    if (this.players.size === 0) { this.track = /^[a-z]{3,12}$/.test(trk) ? trk : 'apex'; this.laps = 10; }
    const me = { id: this.nextId++, name: user, drv: user, tag: 'DRI', num: 7, liv: ['#0d1f6b', '#e11b22', '#d4a937'], ws: server, fin: null, last: 0 };
    this.players.set(me.id, me);
    this.send(me, { t: 'hello', id: me.id, now: Date.now() });
    this.lobby();
    server.addEventListener('message', ev => {
      if (typeof ev.data !== 'string' || ev.data.length > 700) return;
      let m; try { m = JSON.parse(ev.data); } catch (e) { return; }
      if (!this.players.has(me.id)) return;
      switch (m.t) {
        case 's': {
          if (this.status !== 'racing' || !Array.isArray(m.a) || m.a.length !== 8) return;
          const a = m.a.map(Number); if (!a.every(Number.isFinite)) return;
          this.all({ t: 's', id: me.id, a }, me.id); break;
        }
        case 'ping': this.send(me, { t: 'pong', c: num(m.c, 0, 1e15, 0), now: Date.now() }); break;
        case 'hi':
          me.drv = String(m.drv || me.name).slice(0, 22); me.tag = String(m.tag || 'DRI').replace(/[^A-Za-z]/g, '').slice(0, 3).toUpperCase() || 'DRI';
          me.num = num(m.num, 1, 99, 7); me.des = num(m.des, 0, 40, 0) | 0; me.liv = Array.isArray(m.liv) && m.liv.length === 3 ? m.liv.map(hexOk) : me.liv; this.lobby(); break;
        case 'cfg':
          if (me.id !== this.hostId() || this.status !== 'lobby') return;
          this.laps = num(m.laps, 1, 100, 10) | 0; this.lobby(); break;
        case 'start':
          if (me.id !== this.hostId() || this.status !== 'lobby') return;
          this.status = 'racing'; this.raceSeq++;
          for (const q of this.players.values()) q.fin = null;
          this.all({ t: 'go', at: Date.now() + 10000, now: Date.now(), grid: [...this.players.keys()].sort((x, y) => x - y), laps: this.laps, wx: Math.random() });
          this.lobby(); clearTimeout(this.timer); this.timer = setTimeout(() => this.endRace(), 25 * 60e3); break;
        case 'fin': {
          if (this.status !== 'racing' || me.fin != null) return;
          me.fin = num(m.time, 1, 36000, 36000); this.all({ t: 'fin', id: me.id, time: me.fin });
          if (![...this.players.values()].some(q => q !== me && q.fin != null)) { clearTimeout(this.timer); this.timer = setTimeout(() => this.endRace(), 90e3); }
          this.checkEnd(); break;
        }
        case 'leave': try { server.close(1000, 'bye'); } catch (e) {} break;
      }
    });
    const gone = () => {
      if (this.players.get(me.id) !== me) return;
      this.players.delete(me.id);
      if (this.players.size === 0) { clearTimeout(this.timer); this.timer = null; this.status = 'lobby'; return; }
      this.all({ t: 'drop', id: me.id }); this.lobby(); this.checkEnd();
    };
    server.addEventListener('close', gone); server.addEventListener('error', gone);
    return new Response(null, { status: 101, webSocket: client });
  }
}
