const T = {
  items: { cols: ['name','sku','qty','unit','cost','price','reorder'], order: 'name' },
  assets: { cols: ['name','category','purchased','cost','notes'], order: 'purchased DESC, id DESC' },
  expenses: { cols: ['date','category','description','amount','account_id'], order: 'date DESC, id DESC' },
  accounts: { cols: ['name','type','opening'], order: 'name' },
  transactions: { cols: ['account_id','date','description','amount'], order: 'date DESC, id DESC' },
};
const enc = new TextEncoder();
const json = (d, s = 200, h = {}) => new Response(JSON.stringify(d), { status: s, headers: { 'content-type': 'application/json', ...h } });
async function sign(msg, secret) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const s = await crypto.subtle.sign('HMAC', k, enc.encode(msg));
  return [...new Uint8Array(s)].map(b => b.toString(16).padStart(2, '0')).join('');
}
const eq = (a, b) => { a = String(a); b = String(b); let r = a.length ^ b.length; for (let i = 0; i < Math.max(a.length, b.length); i++) r |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0); return r === 0; };
async function authed(req, env) {
  const c = (req.headers.get('cookie') || '').match(/(?:^|; )s=([^;]+)/);
  if (!c) return false;
  const [exp, sig] = c[1].split('.');
  return !!exp && Date.now() < +exp && eq(sig || '', await sign(exp, env.SESSION_SECRET));
}

export async function onRequest({ request, env, params }) {
  const [res, id] = params.path || [];
  const m = request.method;
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({ error: 'Set ADMIN_PASSWORD and SESSION_SECRET in Cloudflare' }, 500);

  if (res === 'login' && m === 'POST') {
    const { password = '' } = await request.json().catch(() => ({}));
    if (!eq(password, env.ADMIN_PASSWORD)) return json({ error: 'Wrong password' }, 401);
    const exp = Date.now() + 30 * 864e5;
    return json({ ok: 1 }, 200, { 'set-cookie': `s=${exp}.${await sign(String(exp), env.SESSION_SECRET)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=2592000` });
  }
  if (res === 'logout') return json({ ok: 1 }, 200, { 'set-cookie': 's=; Path=/; Max-Age=0' });
  if (!(await authed(request, env))) return json({ error: 'Login required' }, 401);
  const db = env.DB;

  if (res === 'summary') {
    const month = new Date().toISOString().slice(0, 8) + '01';
    const [a, b, c, d] = await db.batch([
      db.prepare('SELECT COALESCE(SUM(qty*cost),0) stock, COALESCE(SUM(CASE WHEN reorder>0 AND qty<=reorder THEN 1 ELSE 0 END),0) low FROM items'),
      db.prepare('SELECT COALESCE(SUM(cost),0) assets FROM assets'),
      db.prepare('SELECT COALESCE(SUM(amount),0) spent FROM expenses WHERE date>=?').bind(month),
      db.prepare(`SELECT a.id,a.name,a.type, a.opening + COALESCE((SELECT SUM(amount) FROM transactions WHERE account_id=a.id),0) - COALESCE((SELECT SUM(amount) FROM expenses WHERE account_id=a.id),0) AS balance FROM accounts a ORDER BY a.name`),
    ]);
    return json({ ...a.results[0], ...b.results[0], ...c.results[0], accounts: d.results });
  }

  const t = T[res];
  if (!t) return json({ error: 'Not found' }, 404);
  if (m === 'GET') return json((await db.prepare(`SELECT * FROM ${res} ORDER BY ${t.order}`).all()).results);

  const body = await request.json().catch(() => ({}));
  const cols = t.cols.filter(c => c in body);
  const vals = cols.map(c => (body[c] === '' ? null : body[c]));
  try {
    if (m === 'POST') {
      const r = await db.prepare(`INSERT INTO ${res}(${cols.join(',')}) VALUES(${cols.map(() => '?').join(',')})`).bind(...vals).run();
      return json({ id: r.meta.last_row_id }, 201);
    }
    if (m === 'PUT' && id) {
      await db.prepare(`UPDATE ${res} SET ${cols.map(c => c + '=?').join(',')} WHERE id=?`).bind(...vals, id).run();
      return json({ ok: 1 });
    }
    if (m === 'DELETE' && id) {
      await db.prepare(`DELETE FROM ${res} WHERE id=?`).bind(id).run();
      return json({ ok: 1 });
    }
  } catch (e) {
    return json({ error: 'Could not save: check required fields' }, 400);
  }
  return json({ error: 'Bad request' }, 400);
}
