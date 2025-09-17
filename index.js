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
app.use(express.json());
app.use(express.static('public'));

// --- 認証・認可ミドルウェアの定義 ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function authorizeAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.sendStatus(403);
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
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const result = await pool.query(
      "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
      [name, email, hashedPassword]
    );
    res.status(201).json({ id: result.rows[0].id, name, email });
  } catch (err) {
    if (err.code === '23505') { // PostgreSQLの重複エラーコード
      return res.status(409).json({ error: 'そのメールアドレスは既に使用されています。' });
    }
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  }
});

// [Login] ログインしてJWTを発行
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'emailとpasswordは必須です。' });
  }
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: '認証に失敗しました。' });
    }
    const user = result.rows[0];
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
  try {
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, userId]);
    res.status(200).json({ message: 'パスワードが正常に更新されました。' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  }
});

// ## 管理者専用ルート ##

// [Read] 全ユーザーを取得
app.get('/users', authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, email, role FROM users");
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  }
});

// [Delete] 管理者が特定のユーザーを削除
app.delete('/users/:id', authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("DELETE FROM users WHERE id = $1", [id]);
    if (result.rowCount === 0) {
      return res.status(404).json({ error: '指定されたユーザーは見つかりません。' });
    }
    res.status(204).send();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'サーバーエラーが発生しました。' });
  }
});

// --- サーバーの起動 ---
app.listen(port, () => {
  console.log(`サーバーがポート ${port} で起動しました: http://localhost:${port}`);
});