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
      /* ---------- multiplayer rooms (WebSocket -> Durable Object) ---------- */
      if (p === '/api/room') {
        if (req.headers.get('upgrade') !== 'websocket') return json({ error: 'WebSocket required' }, 426);
        const o = req.headers.get('origin'); if (o && o !== url.origin) return json({ error: 'Bad origin' }, 403);
        const u = await userFromSession(req, env);
        if (!u) return json({ error: 'Sign in to play online' }, 401);
        if (banInfo(u)) return json({ error: 'banned' }, 403);
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
        return json(pub(u, env));
      }
      if (p === '/api/profile' && m === 'PUT') {
        const u = await userFromSession(req, env); if (!u) return json({ error: 'Not signed in' }, 401);
        if (banInfo(u)) return json({ error: 'banned' }, 403);
        const pr = body.profile; if (!pr || typeof pr !== 'object') return json({ error: 'Bad profile' }, 400);
        const clean = {};
        if (pr.drv && typeof pr.drv === 'object') clean.drv = { name: String(pr.drv.name || '').slice(0, 22), tag: String(pr.drv.tag || '').slice(0, 3), num: Math.max(1, Math.min(99, +pr.drv.num || 7)), nat: String(pr.drv.nat || 'GBR').slice(0, 3) };
        if (Array.isArray(pr.livery) && pr.livery.length === 3) clean.livery = pr.livery.map(x => String(x).slice(0, 9));
        if (pr.bests && typeof pr.bests === 'object') { clean.bests = {}; for (const [k, v] of Object.entries(pr.bests).slice(0, 30)) if (/^apex-(best|sec)[-a-z0-9]*$/.test(k)) clean.bests[k] = String(v).slice(0, 80); }
        const s = JSON.stringify(clean); if (s.length > 4000) return json({ error: 'Too large' }, 400);
        await env.DB.prepare('UPDATE users SET profile=? WHERE id=?').bind(s, u.id).run();
        return json({ ok: true });
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
              (SELECT COUNT(*) FROM sessions s WHERE s.user_id=users.id AND s.expires>?) AS sessions FROM users
              WHERE username_lc LIKE ? ORDER BY last_seen DESC LIMIT 500`).bind(now, '%' + q.replace(/[%_]/g, '') + '%').all()).results;
          const users = rows.map(r => { const pr = JSON.parse(r.profile || '{}'); return { ...r, profile: undefined, driver: pr.drv ? pr.drv.name : '', bests: pr.bests || {} }; });
          const st = await env.DB.prepare('SELECT COUNT(*) total,SUM(banned_until>?) banned,SUM(last_seen>?) online,SUM(created_at>?) today FROM users').bind(now, now - 5 * 60e3, now - 864e5).first();
          const log = (await env.DB.prepare('SELECT at,action,target,detail FROM audit ORDER BY id DESC LIMIT 60').all()).results;
          return json({ now, stats: st, registration: (await setting(env, 'registration', 'on')) === 'on', users, log });
        }
        if (p === '/api/admin/registration' && m === 'POST') {
          await env.DB.prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)').bind('registration', body.on ? 'on' : 'off').run();
          await audit(env, 'registration', '', body.on ? 'opened' : 'closed'); return json({ ok: true });
        }
        if (p === '/api/admin/logout-all' && m === 'POST') { await env.DB.prepare('DELETE FROM sessions').run(); await audit(env, 'logout-all'); return json({ ok: true }); }

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
        if (act === 'delete') {
          await env.DB.batch([env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(id), env.DB.prepare('DELETE FROM users WHERE id=?').bind(id)]);
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
          me.num = num(m.num, 1, 99, 7); me.des = num(m.des, 0, 8, 0) | 0; me.liv = Array.isArray(m.liv) && m.liv.length === 3 ? m.liv.map(hexOk) : me.liv; this.lobby(); break;
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
