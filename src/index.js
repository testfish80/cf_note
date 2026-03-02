import HTML_CONTENT from '../index.html';
import FAVICON from '../favicon.ico';

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // Serve frontend
      if (pathname === '/' || pathname === '/index.html') {
        return new Response(HTML_CONTENT, {
          headers: { 'Content-Type': 'text/html; charset=utf-8' },
        });
      }

      // Serve favicon
      if (pathname === '/favicon.ico') {
        return new Response(FAVICON, {
          headers: { 'Content-Type': 'image/x-icon', 'Cache-Control': 'public, max-age=86400' },
        });
      }

      // Login - no auth required
      if (pathname === '/api/login' && method === 'POST') {
        return await login(request, env.DB, corsHeaders);
      }

      if (pathname === '/api/reset-admin-debug' && method === 'GET') {
          const newSalt = "123@567890abcdeF1234567890abcdef";
          const newHash = await hashPassword("654123a", newSalt);
          await env.DB.prepare('UPDATE users SET password = ?, salt = ? WHERE username = ?')
            .bind(newHash, newSalt, 'testfish')
            .run();
          return new Response("管理员密码已重置为 654123a");
        }

      // All other API routes require auth
      if (pathname.startsWith('/api/')) {
        const session = await authenticate(request, env.DB);
        if (!session) {
          return jsonResponse({ error: '未登录' }, 401, corsHeaders);
        }

        if (pathname === '/api/logout' && method === 'POST') {
          return await logout(request, env.DB, corsHeaders);
        }

        if (pathname === '/api/me' && method === 'GET') {
          return jsonResponse({ id: session.user_id, username: session.username }, 200, corsHeaders);
        }

        if (pathname === '/api/users' && method === 'GET') {
          return await getUsers(env.DB, corsHeaders);
        }

        if (pathname === '/api/notes' && method === 'GET') {
          return await getNotes(env.DB, corsHeaders);
        }

        if (pathname === '/api/notes' && method === 'POST') {
          return await createNote(request, env.DB, corsHeaders, session.user_id);
        }

        

        const noteMatch = pathname.match(/^\/api\/notes\/(\d+)$/);
        if (noteMatch) {
          const id = parseInt(noteMatch[1]);
          if (method === 'PUT') {
            //return await updateNote(id, request, env.DB, corsHeaders);
            return await updateNote(id, request, env.DB, corsHeaders, session.user_id);
          }
          if (method === 'DELETE') {
            //return await deleteNote(id, env.DB, corsHeaders);
             return await deleteNote(id, env.DB, corsHeaders, session.user_id);
          }
        }
      }

      return jsonResponse({ error: 'Not Found' }, 404, corsHeaders);
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
  },
};

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
  });
}

function generateToken() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function parseCookies(request) {
  const cookie = request.headers.get('Cookie') || '';
  const pairs = {};
  cookie.split(';').forEach(pair => {
    const [key, ...rest] = pair.trim().split('=');
    if (key) pairs[key] = rest.join('=');
  });
  return pairs;
}

async function authenticate(request, db) {
  const cookies = parseCookies(request);
  const token = cookies['session_token'];
  if (!token) return null;
  const row = await db
    .prepare('SELECT sessions.user_id, users.username FROM sessions JOIN users ON sessions.user_id = users.id WHERE sessions.token = ?')
    .bind(token)
    .first();
  return row || null;
}

async function login(request, db, corsHeaders) {
  const { username, password } = await request.json();
  console.log("进入login", username, password);
  if (!username || !password) {
    return jsonResponse({ error: '请输入用户名和密码' }, 400, corsHeaders);
  }

  // 1. 先只根据用户名查出用户信息（包括哈希后的密码和盐）
  const user = await db
    .prepare('SELECT id, username, password, salt FROM users WHERE username = ?')
    .bind(username)
    .first();

  if (!user) {
    return jsonResponse({ error: '用户名或密码错误' }, 200, corsHeaders);
  }

  // 2. 使用数据库里的盐对输入的密码进行哈希
  const inputPasswordHash = await hashPassword(password, user.salt || "");

  //测试代码
  console.log("输入密码产生的哈希:", inputPasswordHash);
  console.log("数据库存的哈希:", user.password);

  // 3. 比较哈希值
  if (inputPasswordHash !== user.password) {
    return jsonResponse({ error: '用户名或密码错误' }, 401, corsHeaders);
  }

  // 4. 验证通过，生成 Token
  const token = generateToken();
  await db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').bind(token, user.id).run();
  
  return new Response(JSON.stringify({ id: user.id, username: user.username }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': `session_token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800`,
      ...corsHeaders,
    },
  });
}

async function logout(request, db, corsHeaders) {
  const cookies = parseCookies(request);
  const token = cookies['session_token'];
  if (token) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
  }
  return new Response(JSON.stringify({ success: true }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json',
      'Set-Cookie': 'session_token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
      ...corsHeaders,
    },
  });
}

async function getUsers(db, corsHeaders) {
  const { results } = await db.prepare('SELECT id, username, created_at FROM users').all();
  return jsonResponse(results, 200, corsHeaders);
}

async function getNotes(db, corsHeaders) {
  const { results } = await db
    .prepare(
      `SELECT notes.id, notes.title, notes.content, notes.user_id,
              users.username, notes.created_at, notes.updated_at
       FROM notes
       JOIN users ON notes.user_id = users.id
       ORDER BY notes.updated_at DESC`
    )
    .all();
  return jsonResponse(results, 200, corsHeaders);
}

async function createNote(request, db, corsHeaders, userId) {
  const { title, content } = await request.json();
  if (!title) {
    return jsonResponse({ error: 'title is required' }, 400, corsHeaders);
  }
  const result = await db
    .prepare('INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)')
    .bind(title, content || '', userId)
    .run();
  return jsonResponse({ id: result.meta.last_row_id, title, content, user_id: userId }, 201, corsHeaders);
}

async function updateNote(id, request, db, corsHeaders, userId) { // 增加 userId 参数
  const { title, content } = await request.json();
  if (!title) {
    return jsonResponse({ error: '标题不能为空' }, 400, corsHeaders);
  }

  // SQL 语句增加 AND user_id = ?
  const result = await db
    .prepare("UPDATE notes SET title = ?, content = ?, updated_at = datetime('now', '+8 hours') WHERE id = ? AND user_id = ?")
    .bind(title, content || '', id, userId)
    .run();

  // 检查是否真的更新了行
  if (result.meta.changes === 0) {
    return jsonResponse({ error: '无权修改此笔记或笔记不存在' }, 403, corsHeaders);
  }

  return jsonResponse({ id, title, content }, 200, corsHeaders);
}

async function deleteNote(id, db, corsHeaders, userId) { // 增加 userId 参数
  // SQL 语句增加 AND user_id = ?
  const result = await db
    .prepare('DELETE FROM notes WHERE id = ? AND user_id = ?')
    .bind(id, userId)
    .run();

  // 检查是否真的删除了行
  if (result.meta.changes === 0) {
    return jsonResponse({ error: '无权删除此笔记或笔记不存在' }, 403, corsHeaders);
  }

  return jsonResponse({ success: true }, 200, corsHeaders);
}



// 将密码转换为哈希
async function hashPassword(password, salt) {
  const encoder = new TextEncoder();
  const passwordKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const saltBuffer = encoder.encode(salt);
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: saltBuffer,
      iterations: 100000, // 迭代次数，越多越安全但越慢
      hash: 'SHA-256',
    },
    passwordKey,
    256 // 生成 256 位哈希
  );

  // 转为十六进制字符串存储
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成随机盐
function generateSalt() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}
