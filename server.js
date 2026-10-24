import express from 'express';
import jpeg from 'jpeg-js';
import { makePalette, hexToLab, labDist } from './palette.js';
import { NEWS } from './news.js';
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
  create index if not exists tracks_film on tracks(film_id, id);
  alter table films add column if not exists tmdb_id int;
  create table if not exists film_people(
    film_id text references films(imdb_id) on delete cascade, person_id int not null,
    name text, job text, character text, ord int, photo text);
  create index if not exists film_people_film on film_people(film_id);
  create index if not exists film_people_person on film_people(person_id);
  create table if not exists person_cache(id int primary key, data text, fetched_at timestamptz default now());
  alter table users add column if not exists seen_news int default 0;
  create table if not exists requests(
    tmdb_id int primary key, title text, year text, poster text, user_id text not null, created_at timestamptz default now());
  alter table films add column if not exists media text default 'movie';
  alter table films add column if not exists kind text default 'movie';
  alter table films add column if not exists kind_manual boolean default false;
  alter table films add column if not exists seasons int;
  create table if not exists req_items(
    media text not null, tmdb_id int not null, title text, year text, poster text, user_id text not null,
    created_at timestamptz default now(), primary key (media, tmdb_id));
  with moved as (delete from requests returning tmdb_id, title, year, poster, user_id, created_at)
    insert into req_items(media, tmdb_id, title, year, poster, user_id, created_at)
    select 'movie', tmdb_id, title, year, poster, user_id, created_at from moved on conflict do nothing;
  alter table films add column if not exists clip_mode text default 'off';
  alter table films add column if not exists clip_video text;
  alter table films add column if not exists clip_cuts text;
  alter table films add column if not exists trailer_alt text;`);

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
    select f.imdb_id id, f.title, f.title_ru ru, f.year, f.poster, f.imdb_rating::float imdb, f.kind,
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
           f.overview, f.genres, f.runtime, f.palette, f.backdrops, f.trailer, f.composer, f.kind, f.media, f.seasons, f.kind_manual, f.clip_mode, f.clip_video, f.clip_cuts, f.trailer_alt,
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
  const ppl = (await pool.query('select person_id id, name, job, character, photo from film_people where film_id = $1 order by job, ord', [req.params.id])).rows;
  const people = { directors: ppl.filter(x => x.job === 'director'), cast: ppl.filter(x => x.job === 'cast') };
  // фоновый клип страницы: свой ролик с отрезками или трейлер из TMDB с автоматической нарезкой
  const cm = f.clip_mode || 'off', okId = x => /^[\w-]{11}$/.test(x || '');
  const clip = cm === 'custom' && okId(f.clip_video) ? { mode: cm, video: f.clip_video, cuts: parseJson(f.clip_cuts, []) }
    : cm === 'auto' && okId(f.trailer) ? { mode: cm, video: f.trailer, cuts: [] } : { mode: 'off' };
  const trailerAlt = /^https:\/\/(rutube\.ru|vk\.com|vkvideo\.ru|vk\.ru)\//.test(f.trailer_alt || '') ? f.trailer_alt : null;
  res.json({
    raters, commentsCount, people, clip, trailerAlt, ...f, genres: parseJson(f.genres, []), backdrops: parseJson(f.backdrops, []),
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

// --- страницы людей: режиссёры и актёры ---
async function fetchPerson(pid) {
  try {
    const r = await fetch(`https://api.themoviedb.org/3/person/${pid}?api_key=${encodeURIComponent(TMDB_KEY)}&language=ru-RU&append_to_response=movie_credits,tv_credits`);
    if (!r.ok) return null;
    const d = await r.json();
    const yr = x => (x || '').slice(0, 4) || null;
    const byYear = (a, b) => (+b.year || 0) - (+a.year || 0);
    const pop = (a, b) => (b.popularity || 0) - (a.popularity || 0);
    return {
      name: d.name || null, photo: okPath(d.profile_path), dept: d.known_for_department || null,
      birthday: /^\d{4}-\d{2}-\d{2}$/.test(d.birthday || '') ? d.birthday : null, place: d.place_of_birth || null,
      bio: (d.biography || '').slice(0, 900),
      acted: [...(d.movie_credits?.cast || [])].sort(pop).slice(0, 40).map(c => ({ id: c.id, title: c.title, year: yr(c.release_date), character: c.character || null })).sort(byYear),
      directed: uniq([...(d.movie_credits?.crew || [])].filter(c => c.job === 'Director')).sort(pop).slice(0, 40).map(c => ({ id: c.id, title: c.title, year: yr(c.release_date) })).sort(byYear),
      actedTv: [...(d.tv_credits?.cast || [])].sort(pop).slice(0, 100).map(c => ({ id: c.id, character: c.character || null }))
    };
  } catch { return null; }
}
app.get('/api/people/:pid', async (req, res) => {
  if (!/^\d+$/.test(req.params.pid)) return res.status(400).json({ error: 'Неверный запрос' });
  const pid = +req.params.pid;
  const fp = (await pool.query('select film_id, job, character, name from film_people where person_id = $1', [pid])).rows;
  let info = null;
  const cached = (await pool.query(`select data from person_cache where id = $1 and fetched_at > now() - interval '30 days'`, [pid])).rows[0];
  if (cached) info = parseJson(cached.data, null);
  else if (TMDB_KEY) {
    info = await fetchPerson(pid);
    if (info) await pool.query(`insert into person_cache(id, data) values ($1, $2::text)
      on conflict (id) do update set data = excluded.data, fetched_at = now()`, [pid, JSON.stringify(info)]);
  }
  if (!fp.length && !info) return res.status(404).json({ error: 'Не нашли такого человека' });
  const films = (await pool.query(`
    select f.imdb_id id, f.title, f.title_ru ru, f.year, f.poster, f.imdb_rating::float imdb, f.tmdb_id, f.media,
           avg(r.score)::float srv, count(r.score)::int n
    from films f left join ratings r on r.film_id = f.imdb_id group by f.imdb_id`)).rows;
  const byId = new Map(films.map(f => [f.id, f])), byTmdb = new Map(films.filter(f => f.tmdb_id).map(f => [`${f.media || 'movie'}:${f.tmdb_id}`, f]));
  const onSite = new Map();
  const addRole = (f, kind, text) => { if (!onSite.has(f.id)) onSite.set(f.id, { f, roles: new Map() }); onSite.get(f.id).roles.set(kind, text); };
  for (const x of fp) { const f = byId.get(x.film_id); if (f) addRole(f, x.job, x.job === 'director' ? 'Режиссёр' : (x.character ? `Роль: ${x.character}` : 'Актёр')); }
  const others = { acted: [], directed: [] };
  for (const c of info?.acted || []) { const f = byTmdb.get('movie:' + c.id); if (f) addRole(f, 'cast', c.character ? `Роль: ${c.character}` : 'Актёр'); else others.acted.push(c); }
  for (const c of info?.actedTv || []) { const f = byTmdb.get('tv:' + c.id); if (f) addRole(f, 'cast', c.character ? `Роль: ${c.character}` : 'Актёр'); }
  for (const c of info?.directed || []) { const f = byTmdb.get('movie:' + c.id); if (f) addRole(f, 'director', 'Режиссёр'); else others.directed.push(c); }
  res.json({
    id: pid, name: info?.name || fp[0]?.name || 'Без имени', photo: info?.photo || null, dept: info?.dept || null,
    birthday: info?.birthday || null, place: info?.place || null, bio: info?.bio || '',
    onSite: [...onSite.values()].sort((a, b) => (b.f.year || '').localeCompare(a.f.year || ''))
      .map(({ f, roles }) => ({ id: f.id, title: f.title, ru: f.ru, year: f.year, poster: f.poster, imdb: f.imdb, srv: f.srv, n: f.n, roles: [...roles.values()] })),
    others
  });
});

// --- окно «Что нового»: записи лежат в news.js, а у каждого участника запоминается, что он уже видел ---
app.get('/api/news', async (req, res) => {
  const n = NEWS[NEWS.length - 1];
  if (!n) return res.json(null);
  let seen = null;
  if (req.user) seen = ((await pool.query('select seen_news from users where id = $1', [req.user.id])).rows[0]?.seen_news || 0) >= n.id;
  res.json({ id: n.id, title: n.title, items: n.items, seen });
});
app.post('/api/news/seen', needUser, async (req, res) => {
  const id = Number(req.body?.id);
  if (!Number.isInteger(id) || id < 1) return res.status(400).json({ error: 'Неверный запрос' });
  await pool.query('update users set seen_news = greatest(coalesce(seen_news, 0), $2::int) where id = $1', [req.user.id, id]);
  res.json({ ok: true });
});

// --- добавление фильмов и сериалов: поиск по названию, заявки участников, импорт подборок (всё через TMDB) ---
const tmdbGet = async (path, params = {}) => {
  const r = await fetch(`https://api.themoviedb.org/3${path}?${new URLSearchParams({ api_key: TMDB_KEY, ...params })}`);
  if (!r.ok) throw new Error('TMDB ответил ' + r.status);
  return r.json();
};
const siteMap = async () => new Map((await pool.query('select media, tmdb_id, imdb_id from films where tmdb_id is not null')).rows.map(r => [`${r.media || 'movie'}:${r.tmdb_id}`, r.imdb_id]));
const MEDIA = new Set(['movie', 'tv']);
const mapItem = (m, media, site) => ({
  media, tmdbId: m.id, title: m.title || m.name || m.original_title || m.original_name, original: m.original_title || m.original_name,
  year: (m.release_date || m.first_air_date || '').slice(0, 4) || null, poster: okPath(m.poster_path), siteId: site.get(`${media}:${m.id}`) || null
});
async function addByTmdb(media, tmdbId) {
  const d = await tmdbGet(`/${media}/${tmdbId}`, { language: 'en-US', append_to_response: 'external_ids' });
  const imdb = [d.imdb_id, d.external_ids?.imdb_id].find(x => /^tt\d{7,10}$/.test(x || '')) || null;
  if (!imdb) return { ok: false, reason: 'у произведения нет IMDb ID' };
  if ((await pool.query('select 1 from films where imdb_id = $1', [imdb])).rowCount) return { ok: true, skipped: true, id: imdb };
  const f = await loadFilm(imdb);
  if (!f) return { ok: false, reason: 'не удалось получить данные' };
  await saveFilm(f);
  return { ok: true, id: imdb };
}
app.get('/api/tmdb/search', needUser, async (req, res) => {
  if (!TMDB_KEY) return res.status(400).json({ error: 'На сервере не задан ключ TMDB_API_KEY' });
  const query = String(req.query.q || '').trim().slice(0, 100);
  if (query.length < 2) return res.json([]);
  const [d, site, asked] = await Promise.all([tmdbGet('/search/multi', { query, language: 'ru-RU', include_adult: 'false' }), siteMap(), pool.query('select media, tmdb_id from req_items')]);
  const pending = new Set(asked.rows.map(r => `${r.media}:${r.tmdb_id}`));
  res.json((d.results || []).filter(m => MEDIA.has(m.media_type)).slice(0, 8)
    .map(m => ({ ...mapItem(m, m.media_type, site), requested: pending.has(`${m.media_type}:${m.id}`) })));
});
app.get('/api/tmdb/discover', needAdmin, async (req, res) => {
  if (!TMDB_KEY) return res.status(400).json({ error: 'На сервере не задан ключ TMDB_API_KEY' });
  // Типы для импорта: фильмы, сериалы, аниме (сериалы и полнометражные), мультсериалы, полнометражные мультфильмы
  const PRESETS = { movie: { media: 'movie', not: '16' }, series: { media: 'tv', not: '16' },
    anime_series: { media: 'tv', anim: 'ja' }, anime_movie: { media: 'movie', anim: 'ja' },
    cartoon_series: { media: 'tv', anim: 'other' }, cartoon_movie: { media: 'movie', anim: 'other' } };
  const pr = PRESETS[req.query.preset] || PRESETS[req.query.media === 'tv' ? 'series' : 'movie'];
  const media = pr.media, dateKey = media === 'tv' ? 'first_air_date' : 'primary_release_date';
  const p = { language: 'ru-RU', include_adult: 'false', page: String(Math.min(50, Math.max(1, +req.query.page || 1))),
    sort_by: req.query.sort === 'popular' ? 'popularity.desc' : 'vote_average.desc',
    'vote_count.gte': String(Math.max(0, Math.min(1000000, +req.query.votes || 0))) };
  const gs = pr.anim ? ['16'] : [];
  if (/^\d+$/.test(req.query.genre || '')) gs.push(req.query.genre);
  if (gs.length) p.with_genres = gs.join(',');
  if (pr.not) p.without_genres = pr.not;
  if (pr.anim === 'ja') p.with_original_language = 'ja';
  if (/^\d{4}$/.test(req.query.from || '')) p[dateKey + '.gte'] = req.query.from + '-01-01';
  if (/^\d{4}$/.test(req.query.to || '')) p[dateKey + '.lte'] = req.query.to + '-12-31';
  const [d, site] = await Promise.all([tmdbGet(`/discover/${media}`, p), siteMap()]);
  let rs = d.results || [];
  if (pr.anim === 'other') rs = rs.filter(m => m.original_language !== 'ja');   // мультфильмы и мультсериалы без японской анимации
  res.json({ page: d.page, pages: Math.min(d.total_pages || 1, 50), results: rs.map(m => mapItem(m, media, site)) });
});
app.post('/api/films/add-tmdb', needAdmin, async (req, res) => {
  const media = req.body?.media === 'tv' ? 'tv' : 'movie';
  const ids = [...new Set((Array.isArray(req.body?.tmdbIds) ? req.body.tmdbIds : [req.body?.tmdbId]).map(Number).filter(n => Number.isInteger(n) && n > 0))].slice(0, 10);
  if (!ids.length) return res.status(400).json({ error: 'Не выбрано ни одного произведения' });
  const out = { added: 0, skipped: 0, failed: [], id: null }, done = [];
  for (let i = 0; i < ids.length; i += 3) {
    await Promise.all(ids.slice(i, i + 3).map(async tid => {
      try {
        const r = await addByTmdb(media, tid);
        if (!r.ok) { out.failed.push(r.reason); return; }
        done.push(tid); out.id = out.id || r.id;
        if (r.skipped) out.skipped++; else out.added++;
      } catch (e) { out.failed.push(e.message); }
    }));
  }
  if (done.length) await pool.query('delete from req_items where media = $1 and tmdb_id = any($2::int[])', [media, done]);
  res.json(out);
});
app.post('/api/requests', needUser, async (req, res) => {
  const media = req.body?.media === 'tv' ? 'tv' : 'movie', tmdbId = Number(req.body?.tmdbId);
  if (!TMDB_KEY || !Number.isInteger(tmdbId) || tmdbId < 1) return res.status(400).json({ error: 'Неверный запрос' });
  if ((await siteMap()).has(`${media}:${tmdbId}`)) return res.status(409).json({ error: 'Это уже есть на сайте' });
  if ((await pool.query('select count(*)::int n from req_items where user_id = $1', [req.user.id])).rows[0].n >= 20) return res.status(429).json({ error: 'У вас слишком много заявок на рассмотрении' });
  const d = await tmdbGet(`/${media}/${tmdbId}`, { language: 'ru-RU' });
  await saveUser(req.user, null);
  const r = await pool.query(`insert into req_items(media, tmdb_id, title, year, poster, user_id) values ($1::text, $2::int, $3::text, $4::text, $5::text, $6::text)
    on conflict (media, tmdb_id) do nothing`, [media, tmdbId, d.title || d.name || d.original_title || d.original_name, (d.release_date || d.first_air_date || '').slice(0, 4) || null, okPath(d.poster_path), req.user.id]);
  res.json({ ok: true, already: !r.rowCount });
});
app.get('/api/requests', needAdmin, async (req, res) => {
  const { rows } = await pool.query('select q.media, q.tmdb_id, q.title, q.year, q.poster, u.name from req_items q left join users u on u.id = q.user_id order by q.created_at');
  res.json(rows.map(r => ({ media: r.media, tmdbId: r.tmdb_id, title: r.title, year: r.year, poster: r.poster, name: r.name || 'Участник' })));
});
app.delete('/api/requests/:media/:tid', needAdmin, async (req, res) => {
  if (!MEDIA.has(req.params.media) || !/^\d+$/.test(req.params.tid)) return res.status(400).json({ error: 'Неверный запрос' });
  await pool.query('delete from req_items where media = $1 and tmdb_id = $2::int', [req.params.media, req.params.tid]);
  res.json({ ok: true });
});

// --- раздел произведения: определяется автоматически, но администратор может поправить вручную ---
const KINDS = ['movie', 'series', 'tvshow', 'cartoon', 'cartoon_series', 'anime'];
app.post('/api/films/:id/kind', needAdmin, async (req, res) => {
  const kind = String(req.body?.kind || '');
  if (kind === 'auto') { await pool.query('update films set kind_manual = false where imdb_id = $1', [req.params.id]); return res.json({ ok: true }); }
  if (!KINDS.includes(kind)) return res.status(400).json({ error: 'Неизвестный раздел' });
  await pool.query('update films set kind = $2::text, kind_manual = true where imdb_id = $1', [req.params.id, kind]);
  res.json({ ok: true });
});

// --- фоновый клип страницы фильма (настраивает администратор) ---
app.post('/api/films/:id/clip', needAdmin, async (req, res) => {
  const mode = ['off', 'auto', 'custom'].includes(req.body?.mode) ? req.body.mode : null;
  if (!mode) return res.status(400).json({ error: 'Неизвестный режим' });
  let video = null, cuts = null;
  if (mode === 'custom') {
    const raw = String(req.body?.video || '').trim();
    const m = raw.match(/^[\w-]{11}$/) || raw.match(/(?:v=|youtu\.be\/|embed\/|shorts\/)([\w-]{11})/);
    video = m ? (m[1] || m[0]) : null;
    cuts = (Array.isArray(req.body?.cuts) ? req.body.cuts : []).slice(0, 12).map(x => [Number(x?.[0]), Number(x?.[1])])
      .filter(([a, b]) => Number.isFinite(a) && Number.isFinite(b) && a >= 0 && b > a && b - a <= 20 && b < 36000);
    if (!video || !cuts.length) return res.status(400).json({ error: 'Нужны ссылка на ролик YouTube и хотя бы один отрезок (до 20 секунд)' });
  }
  await pool.query('update films set clip_mode = $2::text, clip_video = $3::text, clip_cuts = $4::text where imdb_id = $1',
    [req.params.id, mode, video, cuts ? JSON.stringify(cuts) : null]);
  res.json({ ok: true });
});

// --- картинки TMDB через наш сервер: в некоторых странах image.tmdb.org недоступен без VPN, а наш сайт открывается ---
const IMG_SIZES = new Set(['w92', 'w154', 'w185', 'w342', 'w500', 'w780', 'w1280']);
const imgCache = new Map(); let imgBytes = 0;
app.get('/img/:size/:file', async (req, res) => {
  const { size, file } = req.params;
  if (!IMG_SIZES.has(size) || !/^[\w-]+\.(jpg|jpeg|png)$/i.test(file)) return res.status(404).end();
  const key = size + '/' + file;
  let hit = imgCache.get(key);
  if (hit) { imgCache.delete(key); imgCache.set(key, hit); }
  else {
    try {
      const r = await fetch(`https://image.tmdb.org/t/p/${size}/${file}`);
      if (!r.ok) return res.status(r.status === 404 ? 404 : 502).end();
      hit = { type: r.headers.get('content-type') || 'image/jpeg', buf: Buffer.from(await r.arrayBuffer()) };
      if (hit.buf.length < 600000) {
        imgCache.set(key, hit); imgBytes += hit.buf.length;
        while (imgBytes > 40e6) { const k = imgCache.keys().next().value; imgBytes -= imgCache.get(k).buf.length; imgCache.delete(k); }
      }
    } catch { return res.status(502).end(); }
  }
  res.set({ 'Content-Type': hit.type, 'Cache-Control': 'public, max-age=2592000, immutable' });
  res.send(hit.buf);
});

// --- запасной трейлер для тех, у кого не открывается YouTube: RuTube или VK Видео ---
function altEmbed(raw) {
  try {
    const m = raw.match(/src=["']([^"']+)["']/);
    const u = new URL(m ? m[1] : raw);
    if (u.protocol !== 'https:') return null;
    const host = u.hostname.replace(/^www\./, '');
    if (host === 'rutube.ru') { const id = u.pathname.match(/\/(?:video|play\/embed)\/([0-9a-f]{32})/i)?.[1]; return id ? `https://rutube.ru/play/embed/${id}` : null; }
    if (['vk.com', 'vkvideo.ru', 'vk.ru'].includes(host) && u.pathname.includes('video_ext.php')) return u.toString();
    return null;
  } catch { return null; }
}
app.post('/api/films/:id/trailer-alt', needAdmin, async (req, res) => {
  const raw = String(req.body?.url || '').trim();
  if (!raw) { await pool.query('update films set trailer_alt = null where imdb_id = $1', [req.params.id]); return res.json({ ok: true }); }
  const url = altEmbed(raw);
  if (!url) return res.status(400).json({ error: 'Нужна ссылка на видео RuTube (rutube.ru/video/…) или код для вставки VK Видео (video_ext.php)' });
  await pool.query('update films set trailer_alt = $2::text where imdb_id = $1', [req.params.id, url]);
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
const okPath = x => (/^\/[\w-]+\.(jpg|jpeg|png)$/i.test(x || '') ? x : null);
const uniq = a => a.filter((c, i) => a.findIndex(z => z.id === c.id) === i);
const TV_SHOW_TYPES = ['Reality', 'Talk Show', 'News', 'Documentary'];
// Раздел сайта по данным TMDB: аниме = анимация на японском, остальная анимация = мультфильмы и мультсериалы
function kindOf(media, x) {
  const ids = (x.genres || []).map(g => g.id), anim = ids.includes(16);
  if (anim && x.original_language === 'ja') return 'anime';
  if (media === 'movie') return anim ? 'cartoon' : 'movie';
  if (anim) return 'cartoon_series';
  if (TV_SHOW_TYPES.includes(x.type) || ids.some(i => [10764, 10767, 10763].includes(i))) return 'tvshow';
  return 'series';
}
async function fetchTmdb(id) {
  if (!TMDB_KEY) return null;
  try {
    const q = 'api_key=' + encodeURIComponent(TMDB_KEY);
    const r = await fetch(`https://api.themoviedb.org/3/find/${id}?${q}&external_source=imdb_id&language=ru-RU`);
    const d = await r.json();
    if (!r.ok) { ruError = `TMDB ответил ${r.status}: ${d.status_message || ''}`; return null; }
    const mv = d.movie_results?.[0], tv = d.tv_results?.[0], m = mv || tv;
    if (!m) return null;
    const media = mv ? 'movie' : 'tv';
    const title = media === 'movie' ? m.title : m.name;
    const orig = media === 'movie' ? m.original_title : m.original_name;
    const date = media === 'movie' ? m.release_date : m.first_air_date;
    const meta = {
      title: orig || title || null, year: (date || '').slice(0, 4) || null,
      poster: okPath(m.poster_path) ? 'https://image.tmdb.org/t/p/w500' + m.poster_path : null
    };
    const r2 = await fetch(`https://api.themoviedb.org/3/${media}/${m.id}?${q}&language=ru-RU&append_to_response=videos,images,credits&include_video_language=ru,en&include_image_language=en,null`);
    const x = await r2.json();
    if (!r2.ok) return { ru: title || null, tmdbId: m.id, media, meta };
    const vids = (x.videos?.results || []).filter(v => v.site === 'YouTube' && v.type === 'Trailer');
    const trailer = (vids.find(v => v.iso_639_1 === 'ru') || vids.find(v => v.official) || vids[0])?.key || null;
    const bk = x.images?.backdrops || [], clean = bk.filter(b => !b.iso_639_1);
    const crew = x.credits?.crew || [];
    const directors = media === 'movie' ? uniq(crew.filter(c => c.job === 'Director')) : (x.created_by || []);
    return {
      ru: title || null, overview: x.overview || m.overview || null,
      genres: (x.genres || []).map(g => g.name),
      runtime: media === 'movie' ? (x.runtime || null) : ((x.episode_run_time || [])[0] || null),
      trailer,
      composer: crew.filter(c => c.job === 'Original Music Composer').map(c => c.name).slice(0, 3).join(', ') || null,
      tmdbId: m.id, media, meta, kind: kindOf(media, x), seasons: media === 'tv' ? (x.number_of_seasons || null) : null,
      people: {
        directors: directors.slice(0, 3).map(c => ({ id: c.id, name: c.name, photo: okPath(c.profile_path) })),
        cast: (x.credits?.cast || []).slice(0, 10).map(c => ({ id: c.id, name: c.name, character: c.character || null, photo: okPath(c.profile_path) }))
      },
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
  let f = await fetchOmdb(id);
  const tm = await fetchTmdb(id);
  // если OMDb не ответил (например, закончился суточный лимит), фильм всё равно добавится из данных TMDB, без рейтинга IMDb
  if (!f && tm?.meta?.title) f = { id, title: tm.meta.title, year: tm.meta.year, poster: tm.meta.poster, imdb: null };
  if (f) { f.tm = tm; f.ru = tm?.ru || null; f.palette = await paletteFrom(f.poster); }
  return f;
}
const saveExtraRow = (id, tm, pal) => pool.query(`
  update films set title_ru = coalesce($2::text, title_ru), overview = coalesce($3::text, overview),
    genres = coalesce($4::text, genres), runtime = coalesce($5::int, runtime),
    backdrops = coalesce($6::text, backdrops), trailer = coalesce($7::text, trailer), palette = coalesce($8::text, palette), composer = coalesce($9::text, composer), tmdb_id = coalesce($10::int, tmdb_id),
    media = coalesce($11::text, media), seasons = coalesce($12::int, seasons),
    kind = case when kind_manual then kind else coalesce($13::text, kind) end
  where imdb_id = $1`,
  [id, tm?.ru || null, tm?.overview || null, tm?.genres?.length ? JSON.stringify(tm.genres) : null, tm?.runtime || null,
   tm?.backdrops?.length ? JSON.stringify(tm.backdrops) : null, tm?.trailer || null, pal ? JSON.stringify(pal) : null, tm?.composer || null, tm?.tmdbId || null, tm?.media || null, tm?.seasons || null, tm?.kind || null]);
async function saveExtra(id, tm, pal) {
  await saveExtraRow(id, tm, pal);
  if (tm?.people) await savePeople(id, tm.people);
}
// Режиссёры и главные актёры фильма (для ссылок на странице фильма и для страниц людей)
async function savePeople(id, p) {
  const rows = [...p.directors.map((x, i) => ({ ...x, job: 'director', character: null, ord: i })), ...p.cast.map((x, i) => ({ ...x, job: 'cast', ord: i }))];
  await pool.query('delete from film_people where film_id = $1', [id]);
  if (!rows.length) return;
  await pool.query(`insert into film_people(film_id, person_id, name, job, character, ord, photo)
    select $1::text, x.pid, x.n, x.j, x.c, x.o, x.ph
    from unnest($2::int[], $3::text[], $4::text[], $5::text[], $6::int[], $7::text[]) as x(pid, n, j, c, o, ph)`,
    [id, rows.map(r => r.id), rows.map(r => r.name), rows.map(r => r.job), rows.map(r => r.character || null), rows.map(r => r.ord), rows.map(r => r.photo || null)]);
}
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
app.get(['/film/:id', '/person/:id', '/movies', '/series', '/tv', '/cartoons', '/cartoon-series', '/anime', '/chzl'], (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.use(express.static(PUB));
app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: 'Ошибка сервера' }); });
app.listen(E.PORT || 3000, () => console.log('Сайт запущен: ' + BASE));
