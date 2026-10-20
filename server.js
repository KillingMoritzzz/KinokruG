import express from 'express';
import pg from 'pg';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const E = process.env;
const need = ['DISCORD_CLIENT_ID', 'DISCORD_CLIENT_SECRET', 'DISCORD_GUILD_ID', 'BASE_URL', 'SESSION_SECRET', 'DATABASE_URL', 'OMDB_API_KEY'];
const missing = need.filter(k => !E[k]);
if (missing.length) { console.error('Не заданы переменные окружения: ' + missing.join(', ')); process.exit(1); }

const BASE = E.BASE_URL.replace(/\/$/, '');
const SECURE = BASE.startsWith('https');
const REDIRECT = BASE + '/auth/callback';
const ADMINS = (E.ADMIN_IDS || '').split(',').map(s => s.trim()).filter(Boolean);
const DAY = 86400;

const pool = new pg.Pool({ connectionString: E.DATABASE_URL, ssl: E.PGSSL === 'off' ? false : { rejectUnauthorized: false } });
await pool.query(`
  create table if not exists films(
    imdb_id text primary key, title text not null, year text, poster text,
    imdb_rating numeric(3,1), added_at timestamptz default now());
  create table if not exists ratings(
    film_id text references films(imdb_id) on delete cascade,
    user_id text, score int check (score between 1 and 10),
    primary key (film_id, user_id));
  alter table films add column if not exists title_ru text;`);

// --- подписанные cookie (без внешних библиотек) ---
const hmac = b => crypto.createHmac('sha256', E.SESSION_SECRET).update(b).digest('base64url');
const sign = v => { const b = Buffer.from(JSON.stringify(v)).toString('base64url'); return b + '.' + hmac(b); };
const unsign = s => {
  if (!s) return null;
  const [b, m] = s.split('.');
  if (!b || !m) return null;
  const e = hmac(b);
  if (m.length !== e.length || !crypto.timingSafeEqual(Buffer.from(m), Buffer.from(e))) return null;
  try { const v = JSON.parse(Buffer.from(b, 'base64url')); return v.exp > Date.now() / 1000 ? v : null; } catch { return null; }
};
const cookies = h => Object.fromEntries((h || '').split(';').map(c => {
  const i = c.indexOf('='); return i < 0 ? [] : [c.slice(0, i).trim(), c.slice(i + 1).trim()];
}).filter(p => p.length));
const setCookie = (res, name, val, maxAge) =>
  res.append('Set-Cookie', `${name}=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${SECURE ? '; Secure' : ''}`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use((req, res, next) => { req.user = unsign(cookies(req.headers.cookie).s); next(); });
const needUser = (req, res, next) => req.user ? next() : res.status(401).json({ error: 'Войдите через Discord' });
const needAdmin = (req, res, next) => req.user && ADMINS.includes(req.user.id) ? next() : res.status(403).json({ error: 'Только для администраторов' });

// --- вход через Discord ---
app.get('/auth/login', (req, res) => {
  const state = crypto.randomBytes(16).toString('hex');
  setCookie(res, 'st', sign({ state, exp: Date.now() / 1000 + 600 }), 600);
  res.redirect('https://discord.com/oauth2/authorize?' + new URLSearchParams({
    client_id: E.DISCORD_CLIENT_ID, redirect_uri: REDIRECT, response_type: 'code',
    scope: 'identify guilds', state, prompt: 'none'
  }));
});

app.get('/auth/callback', async (req, res) => {
  const st = unsign(cookies(req.headers.cookie).st);
  setCookie(res, 'st', '', 0);
  if (!st || st.state !== req.query.state || !req.query.code) return res.redirect('/?error=login');
  try {
    const tr = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: E.DISCORD_CLIENT_ID, client_secret: E.DISCORD_CLIENT_SECRET,
        grant_type: 'authorization_code', code: req.query.code, redirect_uri: REDIRECT
      })
    });
    if (!tr.ok) throw new Error('token ' + tr.status);
    const { access_token } = await tr.json();
    const headers = { Authorization: 'Bearer ' + access_token };
    const [u, g] = await Promise.all([
      fetch('https://discord.com/api/users/@me', { headers }).then(r => r.json()),
      fetch('https://discord.com/api/users/@me/guilds', { headers }).then(r => r.json())
    ]);
    if (!Array.isArray(g) || !g.some(x => x.id === E.DISCORD_GUILD_ID)) return res.redirect('/?error=notmember');
    setCookie(res, 's', sign({ id: u.id, name: u.global_name || u.username, exp: Date.now() / 1000 + 30 * DAY }), 30 * DAY);
    res.redirect('/');
  } catch (e) { console.error(e); res.redirect('/?error=login'); }
});

app.get('/auth/logout', (req, res) => { setCookie(res, 's', '', 0); res.redirect('/'); });

app.get('/api/me', (req, res) =>
  res.json(req.user ? { id: req.user.id, name: req.user.name, admin: ADMINS.includes(req.user.id) } : null));

// --- фильмы и оценки ---
app.get('/api/films', async (req, res) => {
  const { rows } = await pool.query(`
    select f.imdb_id id, f.title, f.title_ru ru, f.year, f.poster, f.imdb_rating::float imdb,
           avg(r.score)::float srv, count(r.score)::int n,
           max(case when r.user_id = $1 then r.score end) mine
    from films f left join ratings r on r.film_id = f.imdb_id
    group by f.imdb_id order by f.added_at desc`, [req.user?.id || '']);
  res.json(rows);
});

app.post('/api/rate', needUser, async (req, res) => {
  const { filmId, score } = req.body || {};
  if (typeof filmId !== 'string') return res.status(400).json({ error: 'Неверный запрос' });
  if (score === null) {
    await pool.query('delete from ratings where film_id = $1 and user_id = $2', [filmId, req.user.id]);
    return res.json({ ok: true });
  }
  if (!Number.isInteger(score) || score < 1 || score > 10) return res.status(400).json({ error: 'Оценка от 1 до 10' });
  const r = await pool.query(`
    insert into ratings(film_id, user_id, score)
    select $1::text, $2::text, $3::int where exists (select 1 from films where imdb_id = $1::text)
    on conflict (film_id, user_id) do update set score = excluded.score`, [filmId, req.user.id, score]);
  if (!r.rowCount) return res.status(404).json({ error: 'Фильм не найден' });
  res.json({ ok: true });
});

// --- администратор: IMDb через OMDb API ---
const clean = x => x && x !== 'N/A' ? x : null;
async function fetchOmdb(id) {
  const r = await fetch(`https://www.omdbapi.com/?apikey=${encodeURIComponent(E.OMDB_API_KEY)}&i=${id}`);
  const d = await r.json();
  if (d.Response === 'False') return null;
  const poster = clean(d.Poster);
  return { id: d.imdbID, title: d.Title, year: clean(d.Year), poster: poster && poster.startsWith('https://') ? poster : null, imdb: clean(d.imdbRating) };
}
// Русское название берём из TMDB. Ключ TMDB_API_KEY необязателен: без него сайт работает, но без русских названий.
const TMDB_KEY = (E.TMDB_API_KEY || '').trim().replace(/^["']|["']$/g, '');
let ruError = '';
async function fetchRu(id) {
  if (!TMDB_KEY) return null;
  try {
    const r = await fetch(`https://api.themoviedb.org/3/find/${id}?api_key=${encodeURIComponent(TMDB_KEY)}&external_source=imdb_id&language=ru-RU`);
    const d = await r.json();
    if (!r.ok) { ruError = `TMDB ответил ${r.status}: ${d.status_message || ''}`; return null; }
    return d.movie_results?.[0]?.title || null;
  } catch (e) { ruError = 'Не удалось связаться с TMDB: ' + e.message; return null; }
}
async function loadFilm(id) {
  const f = await fetchOmdb(id);
  if (f) f.ru = await fetchRu(id);
  return f;
}
const upsert = f => pool.query(`
  insert into films(imdb_id, title, title_ru, year, poster, imdb_rating) values ($1, $2, $6::text, $3, $4, $5)
  on conflict (imdb_id) do update set title = $2, title_ru = coalesce($6::text, films.title_ru), year = $3, poster = $4, imdb_rating = $5`,
  [f.id, f.title, f.year, f.poster, f.imdb, f.ru || null]);

// Можно передать сразу много IMDb ID или ссылок (до 30 за запрос)
app.post('/api/films', needAdmin, async (req, res) => {
  const ids = [...new Set(String(req.body?.imdbId || '').match(/tt\d{7,9}/g) || [])].slice(0, 30);
  if (!ids.length) return res.status(400).json({ error: 'Укажите IMDb ID вида tt0111161 или ссылку на фильм' });
  const have = new Set((await pool.query('select imdb_id from films where imdb_id = any($1)', [ids])).rows.map(r => r.imdb_id));
  const todo = ids.filter(i => !have.has(i));
  let added = 0; const failed = [];
  for (let i = 0; i < todo.length; i += 5) {
    await Promise.all(todo.slice(i, i + 5).map(async id => {
      try { const f = await loadFilm(id); if (f) { await upsert(f); added++; } else failed.push(id); } catch { failed.push(id); }
    }));
  }
  res.json({ ok: true, added, skipped: ids.length - todo.length, failed });
});

app.post('/api/films/refresh', needAdmin, async (req, res) => {
  const { rows } = await pool.query('select imdb_id from films');
  let updated = 0, ru = 0, dbError = '';
  ruError = '';
  for (let i = 0; i < rows.length; i += 5) {
    await Promise.all(rows.slice(i, i + 5).map(async ({ imdb_id }) => {
      try { const f = await loadFilm(imdb_id); if (f) { await upsert(f); updated++; if (f.ru) ru++; } }
      catch (e) { dbError = dbError || e.message; }
    }));
  }
  res.json({ ok: true, updated, ru, key: !!TMDB_KEY, error: dbError || ruError });
});

app.delete('/api/films/:id', needAdmin, async (req, res) => {
  await pool.query('delete from films where imdb_id = $1', [req.params.id]);
  res.json({ ok: true });
});

app.use(express.static(path.join(path.dirname(fileURLToPath(import.meta.url)), 'public')));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); });
app.listen(E.PORT || 3000, () => console.log('Сайт запущен: ' + BASE));
