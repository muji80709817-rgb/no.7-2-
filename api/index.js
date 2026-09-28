const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

// 환경 변수 비밀키 (없을 시 기본값 사용)
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-pds-task7-key';

// 메모리 DB (서버 내 유저 및 할 일 보관)
const users = []; // { id, email, password }
const todos = []; // { id, userId, title, dueDate, priority, tag, estTime, completed }

// [미들웨어] 토큰 검증 및 인가 (401 / 403 처리)
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

  if (!token) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '유효하지 않거나 만료된 토큰입니다.' });
    }
    req.user = user; // { userId, email }
    next();
  });
}

// 1. 회원가입 (bcrypt 비밀번호 암호화 보관)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: '이메일과 비밀번호를 모두 입력해 주세요.' });
    }

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ error: '이미 존재하는 계정입니다.' });
    }

    // bcrypt 해싱 (Salt Round: 12)
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = { id: `user_${Date.now()}`, email, password: hashedPassword };
    users.push(newUser);

    return res.status(201).json({ message: '회원가입 완료', userId: newUser.id });
  } catch (err) {
    return res.status(500).json({ error: '회원가입 처리 중 서버 오류가 발생했습니다.' });
  }
});

// 2. 로그인 (JWT 토큰 발급 및 만료 설정)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 일치하지 않습니다.' });
    }

    // JWT 토큰 발급 (유효기간: 1시간)
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '1h' }
    );

    return res.json({
      message: '로그인 성공',
      token,
      user: { id: user.id, email: user.email }
    });
  } catch (err) {
    return res.status(500).json({ error: '로그인 처리 중 서버 오류가 발생했습니다.' });
  }
});

// 3. 내 자료 목록 조회 (타인 데이터 철저 격리)
app.get('/api/todos', authenticateToken, (req, res) => {
  const myTodos = todos.filter(t => t.userId === req.user.userId);
  return res.json(myTodos);
});

// 4. 내 자료 작성
app.post('/api/todos', authenticateToken, (req, res) => {
  const newTodo = {
    id: Date.now(),
    userId: req.user.userId,
    title: req.body.title,
    dueDate: req.body.dueDate || '2026-11-01',
    priority: req.body.priority || '보통',
    tag: req.body.tag || '기본',
    estTime: Number(req.body.estTime) || 60,
    completed: false
  };
  todos.push(newTodo);
  return res.status(201).json(newTodo);
});

// 5. 내 자료 삭제 (타인 자료 접근 시 403 차단)
app.delete('/api/todos/:id', authenticateToken, (req, res) => {
  const todoId = Number(req.params.id);
  const index = todos.findIndex(t => t.id === todoId);

  if (index === -1) {
    return res.status(404).json({ error: '자료를 찾을 수 없습니다.' });
  }

  // 타 유저 자료 변경 시도 검증
  if (todos[index].userId !== req.user.userId) {
    return res.status(403).json({ error: '타인의 자료는 삭제할 수 없습니다.' });
  }

  todos.splice(index, 1);
  return res.json({ message: '삭제 완료' });
});

module.exports = app;