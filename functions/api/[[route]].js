// functions/api/[[route]].js
// mdalamin Blog CMS API — Ultra Premium Edition

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join('');
}

const SECRET = 'mdalamin_blog_secret_2024';
const IMGBB_API_KEY = '4a780b9806217405482ea7632dac862b';

async function signToken(payload) {
  const header = btoa(JSON.stringify({ alg:'HS256', typ:'JWT' }));
  const body = btoa(JSON.stringify(payload));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return `${header}.${body}.${sigB64}`;
}

async function verifyToken(token) {
  try {
    const [header, body, sig] = token.split('.');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(SECRET),
      { name:'HMAC', hash:'SHA-256' }, false, ['verify']);
    const sigBuf = Uint8Array.from(atob(sig), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sigBuf,
      new TextEncoder().encode(`${header}.${body}`));
    if (!valid) return null;
    const payload = JSON.parse(atob(body));
    if (payload.exp && Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

async function getUser(request) {
  const auth = request.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '').trim();
  if (!token) return null;
  return verifyToken(token);
}

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type,Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type':'application/json', ...CORS }
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function ensureTables(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS blog_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    is_blocked INTEGER DEFAULT 0,
    membership_type TEXT DEFAULT 'free',
    membership_expires DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    description TEXT,
    show_on_homepage INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    excerpt TEXT,
    body TEXT NOT NULL,
    category_id INTEGER,
    author_id INTEGER,
    featured_image TEXT,
    is_premium INTEGER DEFAULT 0,
    status TEXT DEFAULT 'draft',
    scheduled_at DATETIME,
    published_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS article_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER,
    image_url TEXT NOT NULL,
    uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS notices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    body TEXT,
    image_url TEXT,
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS notice_reads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    notice_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(notice_id, user_id)
  )`).run();

  await db.prepare(`CREATE TABLE IF NOT EXISTS homepage_featured (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER UNIQUE,
    sort_order INTEGER DEFAULT 0
  )`).run();
}

// ══════════════════════════════════
// AUTH
// ══════════════════════════════════
async function handleAuth(method, path, body, db) {
  // POST /api/auth/signup
  if (method === 'POST' && path === '/signup') {
    const { name, email, password } = body;
    if (!name || !email || !password) return err('All fields are required');
    if (password.length < 6) return err('Password must be at least 6 characters');
    const hashed = await sha256(password);
    try {
      const result = await db.prepare(
        'INSERT INTO blog_users (name, email, password) VALUES (?, ?, ?)'
      ).bind(name, email.toLowerCase().trim(), hashed).run();
      const user = await db.prepare('SELECT * FROM blog_users WHERE id = ?')
        .bind(result.meta.last_row_id).first();
      const token = await signToken({
        id: user.id, email: user.email, role: user.role,
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000
      });
      return json({
        token,
        user: {
          id: user.id, name: user.name, email: user.email,
          role: user.role, membership_type: user.membership_type,
          is_blocked: user.is_blocked
        }
      });
    } catch (e) {
      if (e.message && e.message.includes('UNIQUE')) return err('Email is already registered');
      return err('Signup failed. Please try again.');
    }
  }

  // POST /api/auth/login
  if (method === 'POST' && path === '/login') {
    const { email, password } = body;
    if (!email || !password) return err('Email and password are required');
    const hashed = await sha256(password);
    const user = await db.prepare(
      'SELECT * FROM blog_users WHERE email = ? AND password = ?'
    ).bind(email.toLowerCase().trim(), hashed).first();
    if (!user) return err('Invalid email or password', 401);
    if (user.is_blocked) return err('Your account has been suspended. Contact support.', 403);
    const token = await signToken({
      id: user.id, email: user.email, role: user.role,
      exp: Date.now() + 30 * 24 * 60 * 60 * 1000
    });
    return json({
      token,
      user: {
        id: user.id, name: user.name, email: user.email,
        role: user.role, membership_type: user.membership_type,
        is_blocked: user.is_blocked
      }
    });
  }

  return err('Not found', 404);
}

// ══════════════════════════════════
// PUBLIC BLOG
// ══════════════════════════════════
async function handleBlog(method, path, body, db, user, request) {
  // GET /api/blog/categories
  if (method === 'GET' && path === '/categories') {
    const cats = await db.prepare(
      'SELECT * FROM categories WHERE show_on_homepage = 1 ORDER BY sort_order ASC, name ASC'
    ).all();
    return json(cats.results);
  }

  // GET /api/blog/homepage
  if (method === 'GET' && path === '/homepage') {
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = 10;
    const offset = (page - 1) * limit;

    // Try homepage_featured first
    const featured = await db.prepare(`
      SELECT a.*, c.name as category_name, c.slug as category_slug, u.name as author_name
      FROM homepage_featured hf
      JOIN articles a ON hf.article_id = a.id
      LEFT JOIN categories c ON a.category_id = c.id
      LEFT JOIN blog_users u ON a.author_id = u.id
      WHERE a.status IN ('published','archived')
        AND (a.scheduled_at IS NULL OR a.scheduled_at <= datetime('now'))
      ORDER BY hf.sort_order ASC
      LIMIT ? OFFSET ?
    `).bind(limit, offset).all();

    if (!featured.results.length) {
      const recent = await db.prepare(`
        SELECT a.*, c.name as category_name, c.slug as category_slug, u.name as author_name
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        LEFT JOIN blog_users u ON a.author_id = u.id
        WHERE a.status IN ('published','archived')
          AND (a.scheduled_at IS NULL OR a.scheduled_at <= datetime('now'))
        ORDER BY a.published_at DESC
        LIMIT ? OFFSET ?
      `).bind(limit, offset).all();
      return json(recent.results);
    }
    return json(featured.results);
  }

  // GET /api/blog/category/:slug
  if (method === 'GET' && path.match(/^\/category\/[a-z0-9-]+$/)) {
    const slug = path.split('/')[2];
    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = 10;
    const offset = (page - 1) * limit;

    const cat = await db.prepare('SELECT * FROM categories WHERE slug = ?').bind(slug).first();
    if (!cat) return err('Category not found', 404);

    const articles = await db.prepare(`
      SELECT a.*, c.name as category_name, u.name as author_name
      FROM articles a
      LEFT JOIN categories c ON a.category_id = c.id
      LEFT JOIN blog_users u ON a.author_id = u.id
      WHERE a.category_id = ?
        AND a.status IN ('published','archived')
        AND (a.scheduled_at IS NULL OR a.scheduled_at <= datetime('now'))
      ORDER BY a.published_at DESC
      LIMIT ? OFFSET ?
    `).bind(cat.id, limit, offset).all();

    const count = await db.prepare(
      "SELECT COUNT(*) as cnt FROM articles WHERE category_id = ? AND status IN ('published','archived')"
    ).bind(cat.id).first();

    return json({
      category: cat,
      articles: articles.results,
      total: count.cnt,
      page,
      totalPages: Math.ceil(count.cnt / limit)
    });
  }

  // GET /api/blog/article/:slug
  if (method === 'GET' && path.match(/^\/article\/[a-z0-9-]+$/)) {
    const slug = path.split('/')[2];

    const article = await db.prepare(`
      SELECT a.*, c.name as category_name, c.slug as category_slug, u.name as author_name
      FROM articles a
      LEFT JOIN categories c ON a.category_id = c.id
      LEFT JOIN blog_users u ON a.author_id = u.id
      WHERE a.slug = ?
        AND a.status IN ('published','archived')
        AND (a.scheduled_at IS NULL OR a.scheduled_at <= datetime('now'))
    `).bind(slug).first();

    if (!article) return err('Article not found', 404);

    // Gate: not logged in
    if (!user) {
      return err('Please sign in to read articles.', 401);
    }

    // Premium access check
    if (article.is_premium) {
      // Admins and moderators get full access
      if (user.role === 'admin' || user.role === 'moderator') {
        // allow through
      } else {
        const dbUser = await db.prepare(
          'SELECT membership_type, membership_expires FROM blog_users WHERE id = ?'
        ).bind(user.id).first();

        if (!dbUser || dbUser.membership_type === 'free') {
          return json({ ...article, locked: true, body: null, images: [] });
        }

        // Check expiry
        if (dbUser.membership_expires && new Date(dbUser.membership_expires) < new Date()) {
          return json({ ...article, locked: true, body: null, images: [] });
        }

        const mType = dbUser.membership_type;

        if (mType === 'monthly_max' || mType === 'yearly') {
          // Full access to all premium articles
        } else if (mType === 'monthly') {
          // Monthly: only articles published on/after membership start
          // We infer membership_start as (membership_expires - 30 days)
          const expires = new Date(dbUser.membership_expires);
          const memberSince = new Date(expires.getTime() - 30 * 24 * 60 * 60 * 1000);
          const artDate = article.published_at ? new Date(article.published_at) : new Date(0);
          if (artDate < memberSince) {
            return json({ ...article, locked: true, body: null, images: [] });
          }
        } else {
          return json({ ...article, locked: true, body: null, images: [] });
        }
      }
    }

    const images = await db.prepare(
      'SELECT * FROM article_images WHERE article_id = ?'
    ).bind(article.id).all();

    return json({ ...article, locked: false, images: images.results });
  }

  // GET /api/blog/search?q=...
  if (method === 'GET' && path === '/search') {
    const url = new URL(request.url);
    const q = `%${url.searchParams.get('q') || ''}%`;
    const articles = await db.prepare(`
      SELECT a.id, a.title, a.slug, a.excerpt, a.is_premium, a.status,
             a.published_at, c.name as category_name, u.name as author_name
      FROM articles a
      LEFT JOIN categories c ON a.category_id = c.id
      LEFT JOIN blog_users u ON a.author_id = u.id
      WHERE a.status IN ('published','archived')
        AND (a.scheduled_at IS NULL OR a.scheduled_at <= datetime('now'))
        AND (a.title LIKE ? OR a.excerpt LIKE ?)
      ORDER BY a.published_at DESC
      LIMIT 20
    `).bind(q, q).all();
    return json(articles.results);
  }

  // GET /api/blog/notices
  if (method === 'GET' && path === '/notices') {
    const notices = await db.prepare(
      'SELECT * FROM notices WHERE is_active = 1 ORDER BY created_at DESC'
    ).all();
    return json(notices.results);
  }

  // GET /api/blog/unread-count
  if (method === 'GET' && path === '/unread-count') {
    if (!user) return json({ count: 0 });
    const count = await db.prepare(`
      SELECT COUNT(*) as cnt FROM notices n
      WHERE n.is_active = 1
        AND n.id NOT IN (SELECT notice_id FROM notice_reads WHERE user_id = ?)
    `).bind(user.id).first();
    return json({ count: count.cnt });
  }

  // POST /api/blog/read-notice/:id
  if (method === 'POST' && path.match(/^\/read-notice\/\d+$/)) {
    if (!user) return err('Login required', 401);
    const noticeId = parseInt(path.split('/')[2]);
    await db.prepare(
      'INSERT OR IGNORE INTO notice_reads (notice_id, user_id) VALUES (?, ?)'
    ).bind(noticeId, user.id).run();
    return json({ success: true });
  }

  return err('Not found', 404);
}

// ══════════════════════════════════
// USER
// ══════════════════════════════════
async function handleUser(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);

  // GET /api/user/profile
  if (method === 'GET' && path === '/profile') {
    const u = await db.prepare(
      'SELECT id, name, email, role, membership_type, membership_expires, is_blocked, created_at FROM blog_users WHERE id = ?'
    ).bind(user.id).first();
    return json(u);
  }

  return err('Not found', 404);
}

// ══════════════════════════════════
// ADMIN
// ══════════════════════════════════
async function handleAdmin(method, path, body, db, user) {
  if (!user) return err('Unauthorized', 401);
  if (user.role !== 'admin' && user.role !== 'moderator') return err('Admin access required', 403);

  // ── CATEGORIES ──
  if (method === 'GET' && path === '/categories') {
    const cats = await db.prepare('SELECT * FROM categories ORDER BY sort_order ASC, name ASC').all();
    return json(cats.results);
  }

  if (method === 'POST' && path === '/categories') {
    if (user.role !== 'admin') return err('Only admins can create categories', 403);
    const { name, description, show_on_homepage } = body;
    if (!name) return err('Category name is required');
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    try {
      const result = await db.prepare(
        'INSERT INTO categories (name, slug, description, show_on_homepage) VALUES (?, ?, ?, ?)'
      ).bind(name, slug, description || '', show_on_homepage !== undefined ? show_on_homepage : 1).run();
      return json({ id: result.meta.last_row_id, slug, message: 'Category created' });
    } catch (e) {
      return err(e.message.includes('UNIQUE') ? 'A category with that name already exists' : e.message);
    }
  }

  if (method === 'PUT' && path.match(/^\/categories\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can edit categories', 403);
    const catId = parseInt(path.split('/')[2]);
    const { name, description, show_on_homepage } = body;
    const updates = []; const values = [];
    if (name !== undefined) { updates.push('name = ?'); values.push(name); }
    if (description !== undefined) { updates.push('description = ?'); values.push(description); }
    if (show_on_homepage !== undefined) { updates.push('show_on_homepage = ?'); values.push(show_on_homepage); }
    if (!updates.length) return err('Nothing to update');
    values.push(catId);
    await db.prepare(`UPDATE categories SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Category updated' });
  }

  if (method === 'DELETE' && path.match(/^\/categories\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can delete categories', 403);
    const catId = parseInt(path.split('/')[2]);
    await db.prepare('UPDATE articles SET category_id = NULL WHERE category_id = ?').bind(catId).run();
    await db.prepare('DELETE FROM categories WHERE id = ?').bind(catId).run();
    return json({ message: 'Category deleted' });
  }

  // ── ARTICLES ──
  if (method === 'GET' && path === '/articles') {
    let query, params;
    if (user.role === 'moderator') {
      // Moderators see all but can only edit their own
      query = `SELECT a.*, c.name as category_name, u.name as author_name
               FROM articles a
               LEFT JOIN categories c ON a.category_id = c.id
               LEFT JOIN blog_users u ON a.author_id = u.id
               ORDER BY a.created_at DESC`;
      params = [];
    } else {
      query = `SELECT a.*, c.name as category_name, u.name as author_name
               FROM articles a
               LEFT JOIN categories c ON a.category_id = c.id
               LEFT JOIN blog_users u ON a.author_id = u.id
               ORDER BY a.created_at DESC`;
      params = [];
    }
    const articles = await db.prepare(query).all();
    return json(articles.results);
  }

  if (method === 'POST' && path === '/articles') {
    const { title, slug, excerpt, body: articleBody, category_id, featured_image, is_premium, status, scheduled_at } = body;
    if (!title || !articleBody) return err('Title and body are required');
    const articleSlug = slug
      ? slug.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-|-$/g,'')
      : title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
    try {
      const result = await db.prepare(`
        INSERT INTO articles
          (title, slug, excerpt, body, category_id, author_id, featured_image, is_premium, status, scheduled_at, published_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        title, articleSlug, excerpt || '', articleBody,
        category_id || null, user.id,
        featured_image || null,
        is_premium ? 1 : 0,
        status || 'draft',
        scheduled_at || null,
        status === 'published' || status === 'archived' ? new Date().toISOString() : null
      ).run();
      return json({ id: result.meta.last_row_id, slug: articleSlug, message: 'Article created' });
    } catch (e) {
      return err(e.message.includes('UNIQUE') ? 'An article with that slug already exists' : e.message);
    }
  }

  if (method === 'PUT' && path.match(/^\/articles\/\d+$/)) {
    const articleId = parseInt(path.split('/')[2]);
    // Moderators can only edit their own articles
    if (user.role === 'moderator') {
      const art = await db.prepare('SELECT author_id FROM articles WHERE id = ?').bind(articleId).first();
      if (!art || art.author_id !== user.id) return err('You can only edit your own articles', 403);
    }
    const { title, slug, excerpt, body: articleBody, category_id, featured_image, is_premium, status, scheduled_at } = body;
    const updates = []; const values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (slug !== undefined) { updates.push('slug = ?'); values.push(slug); }
    if (excerpt !== undefined) { updates.push('excerpt = ?'); values.push(excerpt); }
    if (articleBody !== undefined) { updates.push('body = ?'); values.push(articleBody); }
    if (category_id !== undefined) { updates.push('category_id = ?'); values.push(category_id || null); }
    if (featured_image !== undefined) { updates.push('featured_image = ?'); values.push(featured_image || null); }
    if (is_premium !== undefined) { updates.push('is_premium = ?'); values.push(is_premium ? 1 : 0); }
    if (status !== undefined) {
      updates.push('status = ?'); values.push(status);
      if (status === 'published' || status === 'archived') {
        updates.push('published_at = COALESCE(published_at, ?)');
        values.push(new Date().toISOString());
      }
    }
    if (scheduled_at !== undefined) { updates.push('scheduled_at = ?'); values.push(scheduled_at || null); }
    updates.push('updated_at = ?'); values.push(new Date().toISOString());
    if (updates.length <= 1) return err('Nothing to update');
    values.push(articleId);
    await db.prepare(`UPDATE articles SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Article updated' });
  }

  if (method === 'DELETE' && path.match(/^\/articles\/\d+$/)) {
    const articleId = parseInt(path.split('/')[2]);
    if (user.role !== 'admin') {
      const art = await db.prepare('SELECT author_id FROM articles WHERE id = ?').bind(articleId).first();
      if (!art || art.author_id !== user.id) return err('Only admins can delete articles', 403);
    }
    await db.prepare('DELETE FROM article_images WHERE article_id = ?').bind(articleId).run();
    await db.prepare('DELETE FROM homepage_featured WHERE article_id = ?').bind(articleId).run();
    await db.prepare('DELETE FROM articles WHERE id = ?').bind(articleId).run();
    return json({ message: 'Article deleted' });
  }

  // ── IMAGE UPLOAD ──
  if (method === 'POST' && path === '/upload-image') {
    const { image, article_id } = body;
    if (!image) return err('Image data required');
    try {
      const formData = new URLSearchParams();
      formData.append('key', IMGBB_API_KEY);
      formData.append('image', image);
      const imgRes = await fetch('https://api.imgbb.com/1/upload', {
        method: 'POST', body: formData
      });
      const imgData = await imgRes.json();
      if (!imgData.success) return err('Image upload failed: ' + (imgData.error?.message || 'unknown'));
      const url = imgData.data.url;
      if (article_id) {
        await db.prepare('INSERT INTO article_images (article_id, image_url) VALUES (?, ?)')
          .bind(article_id, url).run();
      }
      return json({ url, thumb: imgData.data.thumb?.url || url });
    } catch (e) {
      return err('Upload failed: ' + e.message);
    }
  }

  // ── HOMEPAGE FEATURED ──
  if (method === 'GET' && path === '/featured') {
    const featured = await db.prepare(`
      SELECT a.*, c.name as category_name, hf.sort_order
      FROM homepage_featured hf
      JOIN articles a ON hf.article_id = a.id
      LEFT JOIN categories c ON a.category_id = c.id
      ORDER BY hf.sort_order ASC
    `).all();
    return json(featured.results);
  }

  if (method === 'POST' && path === '/featured') {
    if (user.role !== 'admin') return err('Only admins can manage the homepage', 403);
    const { article_id } = body;
    if (!article_id) return err('article_id required');
    try {
      const maxOrder = await db.prepare('SELECT MAX(sort_order) as mx FROM homepage_featured').first();
      const nextOrder = (maxOrder.mx || 0) + 1;
      await db.prepare('INSERT OR IGNORE INTO homepage_featured (article_id, sort_order) VALUES (?, ?)')
        .bind(article_id, nextOrder).run();
      return json({ message: 'Added to homepage' });
    } catch (e) {
      return err(e.message);
    }
  }

  if (method === 'DELETE' && path.match(/^\/featured\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can manage the homepage', 403);
    const articleId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM homepage_featured WHERE article_id = ?').bind(articleId).run();
    return json({ message: 'Removed from homepage' });
  }

  // ── NOTICES ──
  if (method === 'GET' && path === '/notices') {
    const notices = await db.prepare('SELECT * FROM notices ORDER BY created_at DESC').all();
    return json(notices.results);
  }

  if (method === 'POST' && path === '/notices') {
    if (user.role !== 'admin') return err('Only admins can create notices', 403);
    const { title, body: noticeBody, image_url } = body;
    if (!title) return err('Title is required');
    const result = await db.prepare(
      'INSERT INTO notices (title, body, image_url) VALUES (?, ?, ?)'
    ).bind(title, noticeBody || '', image_url || null).run();
    return json({ id: result.meta.last_row_id, message: 'Notice created' });
  }

  if (method === 'PUT' && path.match(/^\/notices\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can edit notices', 403);
    const noticeId = parseInt(path.split('/')[2]);
    const { title, body: noticeBody, image_url, is_active } = body;
    const updates = []; const values = [];
    if (title !== undefined) { updates.push('title = ?'); values.push(title); }
    if (noticeBody !== undefined) { updates.push('body = ?'); values.push(noticeBody); }
    if (image_url !== undefined) { updates.push('image_url = ?'); values.push(image_url); }
    if (is_active !== undefined) { updates.push('is_active = ?'); values.push(is_active); }
    if (!updates.length) return err('Nothing to update');
    values.push(noticeId);
    await db.prepare(`UPDATE notices SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'Notice updated' });
  }

  if (method === 'DELETE' && path.match(/^\/notices\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can delete notices', 403);
    const noticeId = parseInt(path.split('/')[2]);
    await db.prepare('DELETE FROM notice_reads WHERE notice_id = ?').bind(noticeId).run();
    await db.prepare('DELETE FROM notices WHERE id = ?').bind(noticeId).run();
    return json({ message: 'Notice deleted' });
  }

  // ── USERS ──
  if (method === 'GET' && path === '/users') {
    if (user.role !== 'admin') return err('Only admins can view all users', 403);
    const users = await db.prepare(
      'SELECT id, name, email, role, is_blocked, membership_type, membership_expires, created_at FROM blog_users ORDER BY created_at DESC'
    ).all();
    return json(users.results);
  }

  if (method === 'PUT' && path.match(/^\/users\/\d+$/)) {
    if (user.role !== 'admin') return err('Only admins can manage users', 403);
    const userId = parseInt(path.split('/')[2]);
    const { role, is_blocked, membership_type, membership_expires } = body;
    const updates = []; const values = [];
    if (role !== undefined) { updates.push('role = ?'); values.push(role); }
    if (is_blocked !== undefined) { updates.push('is_blocked = ?'); values.push(is_blocked ? 1 : 0); }
    if (membership_type !== undefined) { updates.push('membership_type = ?'); values.push(membership_type); }
    if (membership_expires !== undefined) { updates.push('membership_expires = ?'); values.push(membership_expires); }
    if (!updates.length) return err('Nothing to update');
    values.push(userId);
    await db.prepare(`UPDATE blog_users SET ${updates.join(', ')} WHERE id = ?`).bind(...values).run();
    return json({ message: 'User updated' });
  }

  if (method === 'POST' && path === '/grant-membership') {
    if (user.role !== 'admin') return err('Only admins can grant membership', 403);
    const { user_id, membership_type, duration_days } = body;
    if (!user_id || !membership_type) return err('user_id and membership_type are required');
    const days = parseInt(duration_days) || (membership_type === 'yearly' ? 365 : 30);
    const expires = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare(
      'UPDATE blog_users SET membership_type = ?, membership_expires = ? WHERE id = ?'
    ).bind(membership_type, expires, user_id).run();
    return json({ message: 'Membership granted', expires });
  }

  return err('Admin route not found', 404);
}

// ══════════════════════════════════
// MAIN HANDLER
// ══════════════════════════════════
export async function onRequest(context) {
  const { request, env } = context;
  const db = env.BLOG_DB;

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: CORS });
  }

  // Ensure tables exist
  await ensureTables(db);

  const url = new URL(request.url);
  const fullPath = url.pathname.replace(/^\/api/, '');

  // Parse body
  let body = {};
  if (['POST', 'PUT', 'DELETE'].includes(request.method)) {
    try { body = await request.json(); } catch {}
  }

  // Get authenticated user
  const authUser = await getUser(request);

  // Route
  if (fullPath.startsWith('/auth/')) {
    return handleAuth(request.method, fullPath.replace('/auth', ''), body, db);
  }
  if (fullPath.startsWith('/blog/')) {
    return handleBlog(request.method, fullPath.replace('/blog', ''), body, db, authUser, request);
  }
  if (fullPath.startsWith('/user/')) {
    return handleUser(request.method, fullPath.replace('/user', ''), body, db, authUser);
  }
  if (fullPath.startsWith('/admin/')) {
    return handleAdmin(request.method, fullPath.replace('/admin', ''), body, db, authUser);
  }

  return err('API route not found', 404);
}
