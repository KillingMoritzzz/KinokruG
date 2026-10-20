import express from 'express';
import jpeg from 'jpeg-js';
import { makePalette, hexToLab, labDist } from './palette.js';
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
  alter table films add column if not exists title_ru text;
  alter table films add column if not exists overview text;
  alter table films add column if not exists genres text;
  alter table films add column if not exists runtime int;
  alter table films add column if not exists palette text;
  alter table films add column if not exists backdrops text;
  alter table films add column if not exists trailer text;
  create table if not exists users(id text primary key, name text, avatar text, updated_at timestamptz default now());
  create table if not exists comments(
    id bigserial primary key, film_id text references films(imdb_id) on delete cascade,
    user_id text not null, text text not null, created_at timestamptz default now());
  create index if not exists comments_film on comments(film_id, created_at);
  alter table films add column if not exists composer text;
  create table if not exists tracks(
    id bigserial primary key, film_id text references films(imdb_id) on delete cascade,
    user_id text not null, artist text, title text, unknown boolean not null default false);
  create index if not exists tracks_film on tracks(film_id, id);`);

// Данные участника (имя и аватар из Discord) нужны, чтобы показывать, кто оценил фильм и кто написал комментарий
const saveUser = (u, avatar) => pool.query(`
  insert into users(id, name, avatar) values ($1, $2::text, $3::text)
  on conflict (id) do update set name = excluded.name, avatar = coalesce(excluded.avatar, users.avatar), updated_at = now()`,
  [u.id, u.name || null, avatar ?? null]);

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
    await saveUser({ id: u.id, name: u.global_name || u.username }, u.avatar || null);
    setCookie(res, 's', sign({ id: u.id, name: u.global_name || u.username, exp: Date.now() / 1000 + 30 * DAY }), 30 * DAY);
    res.redirect('/');
  } catch (e) { console.error(e); res.redirect('/?error=login'); }
});

app.get('/auth/logout', (req, res) => { setCookie(res, 's', '', 0); res.redirect('/'); });

app.get('/api/me', async (req, res) => {
  if (req.user) await saveUser(req.user, null);
  res.json(req.user ? { id: req.user.id, name: req.user.name, admin: ADMINS.includes(req.user.id) } : null);
});

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

const parseJson = (t, d) => { try { return t ? JSON.parse(t) : d; } catch { return d; } };
app.get('/api/films/:id', async (req, res) => {
  const { rows } = await pool.query(`
    select f.imdb_id id, f.title, f.title_ru ru, f.year, f.poster, f.imdb_rating::float imdb,
           f.overview, f.genres, f.runtime, f.palette, f.backdrops, f.trailer, f.composer,
           avg(r.score)::float srv, count(r.score)::int n,
           max(case when r.user_id = $2 then r.score end) mine
    from films f left join ratings r on r.film_id = f.imdb_id
    where f.imdb_id = $1 group by f.imdb_id`, [req.params.id, req.user?.id || '']);
  if (!rows.length) return res.status(404).json({ error: 'Фильм не найден' });
  const f = rows[0];
  const pal = parseJson(f.palette, null);
  // кто как оценил: видно только вошедшим участникам
  const raters = req.user ? (await pool.query(`
    select r.user_id id, r.score, u.name, u.avatar from ratings r left join users u on u.id = r.user_id
    where r.film_id = $1 order by r.score desc, u.name nulls last`, [req.params.id])).rows : null;
  const commentsCount = (await pool.query('select count(*)::int n from comments where film_id = $1', [req.params.id])).rows[0].n;
  const isAdmin = !!req.user && ADMINS.includes(req.user.id);
  const tracks = (await pool.query('select id, user_id, artist, title, unknown from tracks where film_id = $1 order by id', [req.params.id])).rows
    .map(t => ({ id: t.id, artist: t.artist, title: t.title, unknown: t.unknown, canDelete: isAdmin || (!!req.user && t.user_id === req.user.id) }));
  res.json({
    raters, commentsCount, tracks, ...f, genres: parseJson(f.genres, []), backdrops: parseJson(f.backdrops, []),
    palette: Array.isArray(pal) && pal.length === 4 && pal.every(c => /^#[0-9a-f]{6}$/i.test(c)) ? pal : null,
    trailer: /^[\w-]{6,20}$/.test(f.trailer || '') ? f.trailer : null
  });
});

// Похожие по цветам: без параметра color сравниваются палитры целиком, с color ищутся фильмы с близким оттенком
app.get('/api/films/:id/similar', async (req, res) => {
  const isHex = c => /^#[0-9a-f]{6}$/i.test(c);
  const { rows } = await pool.query('select imdb_id id, title, title_ru ru, year, poster, palette from films where palette is not null');
  const all = rows.map(r => ({ ...r, pal: parseJson(r.palette, null) }))
    .filter(r => Array.isArray(r.pal) && r.pal.length === 4 && r.pal.every(isHex)).map(r => ({ ...r, lab: r.pal.map(hexToLab) }));
  const cur = all.find(r => r.id === req.params.id);
  const color = String(req.query.color || '');
  let ranked;
  if (isHex(color)) {
    const lab = hexToLab(color);
    ranked = all.map(r => ({ r, d: Math.min(...r.lab.map(c => labDist(lab, c))) }));
  } else if (cur) {
    ranked = all.map(r => ({ r, d: 0.3 * labDist(cur.lab[0], r.lab[0]) + labDist(cur.lab[1], r.lab[1]) + 1.5 * labDist(cur.lab[2], r.lab[2]) }));
  } else return res.json([]);
  res.json(ranked.filter(x => x.r.id !== req.params.id).sort((a, b) => a.d - b.d).slice(0, 8)
    .map(({ r }) => ({ id: r.id, title: r.title, ru: r.ru, year: r.year, poster: r.poster, palette: r.pal })));
});

// Комментарии: читать и писать могут только вошедшие участники сервера
app.get('/api/films/:id/comments', needUser, async (req, res) => {
  const { rows } = await pool.query(`
    select c.id, c.user_id, c.text, c.created_at, u.name, u.avatar from comments c left join users u on u.id = c.user_id
    where c.film_id = $1 order by c.created_at desc limit 200`, [req.params.id]);
  res.json(rows.map(r => ({ id: r.id, userId: r.user_id, name: r.name || 'Участник', avatar: r.avatar, text: r.text, at: r.created_at, mine: r.user_id === req.user.id })));
});
app.post('/api/films/:id/comments', needUser, async (req, res) => {
  const text = String(req.body?.text || '').trim().slice(0, 1000);
  if (!text) return res.status(400).json({ error: 'Напишите текст комментария' });
  const recent = await pool.query(`select 1 from comments where user_id = $1 and created_at > now() - interval '5 seconds' limit 1`, [req.user.id]);
  if (recent.rowCount) return res.status(429).json({ error: 'Подождите несколько секунд перед следующим комментарием' });
  await saveUser(req.user, null);
  const r = await pool.query(`insert into comments(film_id, user_id, text)
    select $1::text, $2::text, $3::text where exists (select 1 from films where imdb_id = $1::text)`, [req.params.id, req.user.id, text]);
  if (!r.rowCount) return res.status(404).json({ error: 'Фильм не найден' });
  res.json({ ok: true });
});
app.delete('/api/comments/:cid', needUser, async (req, res) => {
  if (!/^\d+$/.test(req.params.cid)) return res.status(400).json({ error: 'Неверный запрос' });
  await pool.query('delete from comments where id = $1::bigint and ($2::boolean or user_id = $3::text)', [req.params.cid, ADMINS.includes(req.user.id), req.user.id]);
  res.json({ ok: true });
});

// Музыка из фильма: простой список треков. Добавлять могут вошедшие участники, удалять автор или администратор.
app.post('/api/films/:id/tracks', needUser, async (req, res) => {
  const have = +(await pool.query('select count(*) from tracks where film_id = $1', [req.params.id])).rows[0].count;
  if (req.body?.unknown) {
    if (have >= 150) return res.status(400).json({ error: 'Слишком много треков у одного фильма' });
    const r = await pool.query(`insert into tracks(film_id, user_id, artist, title, unknown)
      select $1::text, $2::text, (select composer from films where imdb_id = $1::text), null, true
      where exists (select 1 from films where imdb_id = $1::text)`, [req.params.id, req.user.id]);
    return r.rowCount ? res.json({ ok: true }) : res.status(404).json({ error: 'Фильм не найден' });
  }
  const rows = String(req.body?.text || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean).slice(0, 60).map(l => {
    const m = l.split(/\s+[—–-]\s+/);
    return m.length >= 2 ? { artist: m[0].slice(0, 120), title: m.slice(1).join(' — ').slice(0, 160) } : { artist: null, title: l.slice(0, 160) };
  });
  if (!rows.length) return res.status(400).json({ error: 'Напишите хотя бы один трек' });
  if (have + rows.length > 150) return res.status(400).json({ error: 'Слишком много треков у одного фильма' });
  const r = await pool.query(`insert into tracks(film_id, user_id, artist, title)
    select $1::text, $2::text, x.a, x.t from unnest($3::text[], $4::text[]) as x(a, t)
    where exists (select 1 from films where imdb_id = $1::text)`, [req.params.id, req.user.id, rows.map(x => x.artist), rows.map(x => x.title)]);
  return r.rowCount ? res.json({ ok: true, added: r.rowCount }) : res.status(404).json({ error: 'Фильм не найден' });
});
app.delete('/api/tracks/:tid', needUser, async (req, res) => {
  if (!/^\d+$/.test(req.params.tid)) return res.status(400).json({ error: 'Неверный запрос' });
  await pool.query('delete from tracks where id = $1::bigint and ($2::boolean or user_id = $3::text)', [req.params.tid, ADMINS.includes(req.user.id), req.user.id]);
  res.json({ ok: true });
});

app.post('/api/rate', needUser, async (req, res) => {
  const { filmId, score } = req.body || {};
  if (typeof filmId !== 'string') return res.status(400).json({ error: 'Неверный запрос' });
  await saveUser(req.user, null);
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
let omdbError = '';
const clean = x => x && x !== 'N/A' ? x : null;
async function fetchOmdb(id) {
  const r = await fetch(`https://www.omdbapi.com/?apikey=${encodeURIComponent(E.OMDB_API_KEY)}&i=${id}`);
  const d = await r.json();
  if (d.Response === 'False') { omdbError = d.Error || 'OMDb не ответил'; return null; }
  const poster = clean(d.Poster);
  return { id: d.imdbID, title: d.Title, year: clean(d.Year), poster: poster && poster.startsWith('https://') ? poster : null, imdb: clean(d.imdbRating) };
}
// Русское название берём из TMDB. Ключ TMDB_API_KEY необязателен: без него сайт работает, но без русских названий.
// --- TMDB: русское название, описание, жанры, кадры, трейлер (нужен TMDB_API_KEY, он необязателен) ---
const TMDB_KEY = (E.TMDB_API_KEY || '').trim().replace(/^["']|["']$/g, '');
let ruError = '';
async function fetchTmdb(id) {
  if (!TMDB_KEY) return null;
  try {
    const q = 'api_key=' + encodeURIComponent(TMDB_KEY);
    const r = await fetch(`https://api.themoviedb.org/3/find/${id}?${q}&external_source=imdb_id&language=ru-RU`);
    const d = await r.json();
    if (!r.ok) { ruError = `TMDB ответил ${r.status}: ${d.status_message || ''}`; return null; }
    const m = d.movie_results?.[0];
    if (!m) return null;
    const r2 = await fetch(`https://api.themoviedb.org/3/movie/${m.id}?${q}&language=ru-RU&append_to_response=videos,images,credits&include_video_language=ru,en&include_image_language=en,null`);
    const x = await r2.json();
    if (!r2.ok) return { ru: m.title || null };
    const vids = (x.videos?.results || []).filter(v => v.site === 'YouTube' && v.type === 'Trailer');
    const trailer = (vids.find(v => v.iso_639_1 === 'ru') || vids.find(v => v.official) || vids[0])?.key || null;
    const bk = x.images?.backdrops || [], clean = bk.filter(b => !b.iso_639_1);
    return {
      ru: m.title || null, overview: x.overview || m.overview || null,
      genres: (x.genres || []).map(g => g.name), runtime: x.runtime || null, trailer,
      composer: (x.credits?.crew || []).filter(c => c.job === 'Original Music Composer').map(c => c.name).slice(0, 3).join(', ') || null,
      backdrops: (clean.length >= 4 ? clean : bk).slice(0, 8).map(b => b.file_path)
    };
  } catch (e) { ruError = 'Не удалось связаться с TMDB: ' + e.message; return null; }
}

// --- палитра постера (считается один раз и хранится в базе) ---
async function paletteFrom(url) {
  if (!url) return null;
  try {
    const r = await fetch(url);
    if (!r.ok) return null;
    return makePalette(jpeg.decode(Buffer.from(await r.arrayBuffer()), { useTArray: true, maxMemoryUsageInMB: 128 }));
  } catch { return null; }
}

async function loadFilm(id) {
  const f = await fetchOmdb(id);
  if (f) { f.tm = await fetchTmdb(id); f.ru = f.tm?.ru || null; f.palette = await paletteFrom(f.poster); }
  return f;
}
const saveExtra = (id, tm, pal) => pool.query(`
  update films set title_ru = coalesce($2::text, title_ru), overview = coalesce($3::text, overview),
    genres = coalesce($4::text, genres), runtime = coalesce($5::int, runtime),
    backdrops = coalesce($6::text, backdrops), trailer = coalesce($7::text, trailer), palette = coalesce($8::text, palette), composer = coalesce($9::text, composer)
  where imdb_id = $1`,
  [id, tm?.ru || null, tm?.overview || null, tm?.genres?.length ? JSON.stringify(tm.genres) : null, tm?.runtime || null,
   tm?.backdrops?.length ? JSON.stringify(tm.backdrops) : null, tm?.trailer || null, pal ? JSON.stringify(pal) : null, tm?.composer || null]);
const upsert = f => pool.query(`
  insert into films(imdb_id, title, title_ru, year, poster, imdb_rating) values ($1, $2, $6::text, $3, $4, $5)
  on conflict (imdb_id) do update set title = $2, title_ru = coalesce($6::text, films.title_ru), year = $3, poster = $4, imdb_rating = $5`,
  [f.id, f.title, f.year, f.poster, f.imdb, f.ru || null]);
const saveFilm = async f => { await upsert(f); await saveExtra(f.id, f.tm, f.palette); };

// Можно передать сразу много IMDb ID или ссылок (до 30 за запрос)
app.post('/api/films', needAdmin, async (req, res) => {
  const ids = [...new Set(String(req.body?.imdbId || '').match(/tt\d{7,9}/g) || [])].slice(0, 30);
  if (!ids.length) return res.status(400).json({ error: 'Укажите IMDb ID вида tt0111161 или ссылку на фильм' });
  const have = new Set((await pool.query('select imdb_id from films where imdb_id = any($1)', [ids])).rows.map(r => r.imdb_id));
  const todo = ids.filter(i => !have.has(i));
  let added = 0; const failed = [];
  for (let i = 0; i < todo.length; i += 5) {
    await Promise.all(todo.slice(i, i + 5).map(async id => {
      try { const f = await loadFilm(id); if (f) { await saveFilm(f); added++; } else failed.push(id); } catch { failed.push(id); }
    }));
  }
  res.json({ ok: true, added, skipped: ids.length - todo.length, failed });
});

// Обновление данных частями (offset/limit): TMDB (названия, описание, кадры, трейлер), палитра постера и рейтинг IMDb (OMDb).
// Части независимы: если у OMDb закончился суточный лимит, остальное всё равно обновится.
app.post('/api/films/refresh', needAdmin, async (req, res) => {
  const offset = Math.max(0, +req.body?.offset || 0), limit = Math.min(30, Math.max(1, +req.body?.limit || 20));
  const total = +(await pool.query('select count(*) from films')).rows[0].count;
  const { rows } = await pool.query('select imdb_id, poster, palette from films order by imdb_id limit $1 offset $2', [limit, offset]);
  let ru = 0, rated = 0, pals = 0, dbError = '';
  ruError = ''; omdbError = '';
  for (let i = 0; i < rows.length; i += 5) {
    await Promise.all(rows.slice(i, i + 5).map(async row => {
      try {
        const tm = await fetchTmdb(row.imdb_id);
        const pal = row.palette ? null : await paletteFrom(row.poster);
        await saveExtra(row.imdb_id, tm, pal);
        if (tm?.ru) ru++;
        if (pal) pals++;
        const f = await fetchOmdb(row.imdb_id);
        if (f) { await upsert(f); rated++; }
      } catch (e) { dbError = dbError || e.message; }
    }));
  }
  res.json({ ok: true, total, ru, rated, pals, key: !!TMDB_KEY,
    error: [dbError, ruError, omdbError && 'OMDb: ' + omdbError].filter(Boolean).join('. ') });
});

app.delete('/api/films/:id', needAdmin, async (req, res) => {
  await pool.query('delete from films where imdb_id = $1', [req.params.id]);
  res.json({ ok: true });
});

const PUB = path.join(path.dirname(fileURLToPath(import.meta.url)), 'public');
app.get('/film/:id', (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.use(express.static(PUB));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); });
app.listen(E.PORT || 3000, () => console.log('Сайт запущен: ' + BASE));
