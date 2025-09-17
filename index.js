// --- 必要なモジュールのインポート ---
const express = require('express');
const pool = require('./db');      // データベース接続プール
const bcrypt = require('bcrypt');    // パスワードハッシュ化
const jwt = require('jsonwebtoken'); // JWT認証

// --- 初期設定 ---
const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'a_default_fallback_secret';

// --- グローバルミドルウェアの設定 ---
app.use(express.json()); // JSONリクエストボディを解析
app.use(express.static('public')); // 'public' ディレクトリ内の静的ファイルを提供

// --- 認証・認可ミドルウェアの定義 ---

// [認証] JWTを検証し、リクエストにユーザー情報を付与する
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401); // トークンがなければエラー

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // トークンが無効ならエラー
    req.user = user; // ユーザー情報をリクエストに格納
    next();
  });
}

// [認可] 管理者(admin)ロールを持っているかチェックする
function authorizeAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.sendStatus(403); // 管理者でなければエラー
  }
}

// --- APIエンドポイントの定義 ---

// ## 公開ルート (認証不要) ##

// [Create] 新規ユーザー登録
app.post('/users', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password || password.length < 8) {
    return res.status(400).json({ error: '名前、メールアドレス、8文字以上のパスワードは必須です。' });
  }

  const saltRounds = 10;
  let conn;
  try {
    conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const result = await conn.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );
    res.status(201).json({ id: result.insertId, name, email });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'そのメールアドレスは既に使用されています。' });
    }
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});

// [Login] ログインしてJWTを発行
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'emailとpasswordは必須です。' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const users = await conn.query("SELECT * FROM users WHERE email = ?", [email]);
    if (users.length === 0) {
      return res.status(401).json({ error: '認証に失敗しました。' });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (isMatch) {
      const payload = { id: user.id, email: user.email, role: user.role };
      const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });
      res.status(200).json({ message: 'ログイン成功', token: token });
    } else {
      res.status(401).json({ error: '認証に失敗しました。' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});

// ## 認証済みユーザールート ##

// [Update] ログイン中のユーザーが自身のパスワードを変更
app.put('/users/me/password', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'パスワードは8文字以上で入力してください。' });
  }

  const saltRounds = 10;
  let conn;
  try {
    conn = await pool.getConnection();
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await conn.query("UPDATE users SET password = ? WHERE id = ?", [hashedPassword, userId]);
    res.status(200).json({ message: 'パスワードが正常に更新されました。' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});

// ## 管理者専用ルート ##

// [Read] 全ユーザーを取得
app.get('/users', authenticateToken, authorizeAdmin, async (req, res) => {
  let conn;
  try {
    conn = await pool.getConnection();
    const rows = await conn.query("SELECT id, name, email, role FROM users");
    res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});

// [Update] 管理者が特定のユーザー情報を更新 (今回はフロントエンド未実装)
app.put('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, email, role } = req.body;
  if (!name || !email || !role) {
    return res.status(400).json({ error: 'name, email, roleは必須です。' });
  }

  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query(
      "UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?",
      [name, email, role, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '指定されたユーザーは見つかりません。' });
    }
    res.status(200).json({ id: Number(id), name, email, role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});

// [Delete] 管理者が特定のユーザーを削除
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  let conn;
  try {
    conn = await pool.getConnection();
    const result = await conn.query("DELETE FROM users WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '指定されたユーザーは見つかりません。' });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  } finally {
    if (conn) conn.release();
  }
});


// --- サーバーの起動 ---
app.listen(port, () => {
  console.log(`サーバーがポート ${port} で起動しました: http://localhost:${port}`);
});