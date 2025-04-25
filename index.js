const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const recordingsDir = path.join(__dirname, 'recordings');
if (!fs.existsSync(recordingsDir)) fs.mkdirSync(recordingsDir);
const upload = multer({ dest: recordingsDir });
const app = express();
const port = 5000;
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const db = new sqlite3.Database('./questions.db');

// Initialize database and ensure correct schema
const shouldReset = true; // set to true for development resets
db.serialize(() => {
  if (shouldReset) {
    // Reset exam-related tables for development
    db.run('DROP TABLE IF EXISTS exams');
    db.run('DROP TABLE IF EXISTS results');
  } else {
    // Migrations: add missing columns to existing tables
    db.all("PRAGMA table_info(exams)", [], (err, rows) => {
      if (!rows.find(c => c.name === 'webcamEnabled')) {
        db.run("ALTER TABLE exams ADD COLUMN webcamEnabled INTEGER DEFAULT 0");
      }
      if (!rows.find(c => c.name === 'audioEnabled')) {
        db.run("ALTER TABLE exams ADD COLUMN audioEnabled INTEGER DEFAULT 0");
      }
    });
    db.all("PRAGMA table_info(results)", [], (err, rows) => {
      if (!rows.find(c => c.name === 'recordingPath')) {
        db.run("ALTER TABLE results ADD COLUMN recordingPath TEXT");
      }
      if (!rows.find(c => c.name === 'userName')) {
        db.run("ALTER TABLE results ADD COLUMN userName TEXT");
      }
    });
  }

  // Create users table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      fullName TEXT,
      role TEXT
    )
  `);
  // Seed default users if none exist
  db.get("SELECT COUNT(*) as count FROM users", [], (err, row) => {
    if (!err && row.count === 0) {
      const defaultUsers = [
        { username: "admin", password: "admin123", fullName: "Default Admin", role: "admin" },
        { username: "student", password: "student123", fullName: "Default Student", role: "student" }
      ];
      defaultUsers.forEach(u => {
        const hash = bcrypt.hashSync(u.password, 10);
        db.run("INSERT INTO users (username, password, fullName, role) VALUES (?, ?, ?, ?)", [u.username, hash, u.fullName, u.role]);
      });
      console.log("Seeded default users");
    }
  });
  db.run(`
    CREATE TABLE IF NOT EXISTS questions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      question TEXT,
      type TEXT,
      options TEXT,
      answer TEXT
    );
  `);

  // Seed sample questions if empty
  db.get("SELECT COUNT(*) as count FROM questions", [], (err, row) => {
    if (!err && row.count === 0) {
      const sampleQuestions = [
        { question: "What is the capital of France?", type: "multiple_choice", options: ["London", "Paris", "Berlin", "Madrid"], answer: "Paris" },
        { question: "What is 2 + 2?", type: "multiple_choice", options: ["1", "2", "3", "4"], answer: "4" },
        { question: "Which planet is known as the Red Planet?", type: "multiple_choice", options: ["Mars", "Venus", "Jupiter", "Saturn"], answer: "Mars" },
        { question: "What is the largest ocean on Earth?", type: "multiple_choice", options: ["Atlantic", "Indian", "Arctic", "Pacific"], answer: "Pacific" },
        { question: "Who wrote 'Hamlet'?", type: "multiple_choice", options: ["Charles Dickens", "William Shakespeare", "J.K. Rowling", "Jane Austen"], answer: "William Shakespeare" }
      ];
      sampleQuestions.forEach(q => {
        db.run("INSERT INTO questions (question, type, options, answer) VALUES (?, ?, ?, ?)", [q.question, q.type, JSON.stringify(q.options), q.answer]);
      });
      console.log("Seeded sample questions");
    }
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS exams (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      duration INTEGER,
      questions TEXT,
      webcamEnabled INTEGER DEFAULT 0,
      audioEnabled INTEGER DEFAULT 0
    );
  `);

  // Seed sample exam if none exist
  db.get("SELECT COUNT(*) as count FROM exams", [], (err, row) => {
    if (!err && row.count === 0) {
      db.all("SELECT id FROM questions", [], (err, rows) => {
        if (!err) {
          const qIds = rows.map(r => r.id);
          db.run(
            "INSERT INTO exams (title, duration, questions, webcamEnabled, audioEnabled) VALUES (?, ?, ?, ?, ?)",
            ["Sample Exam", 5, JSON.stringify(qIds), 1, 1]
          );
          console.log("Seeded sample exam");
        }
      });
    }
  });

  db.run(`
    CREATE TABLE IF NOT EXISTS results (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      examId INTEGER,
      userName TEXT,
      score INTEGER,
      answers TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      recordingPath TEXT
    );
  `);

  // Create flags table for live proctoring
  db.run('CREATE TABLE IF NOT EXISTS flags (id INTEGER PRIMARY KEY AUTOINCREMENT, examId INTEGER, userName TEXT, event TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)');
});

// Authentication endpoints
app.post('/api/auth/register', async (req, res) => {
  console.log('Registration request received:', req.body);
  const { username, password, fullName } = req.body;
  
  if (!username || !password || !fullName) {
    console.log('Missing required fields:', { username: !!username, password: !!password, fullName: !!fullName });
    return res.status(400).json({ error: 'All fields are required' });
  }

  try {
    console.log('Hashing password...');
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed successfully');

    console.log('Inserting user into database...');
    db.run(
      'INSERT INTO users (username, password, fullName, role) VALUES (?, ?, ?, ?)',
      [username, hashedPassword, fullName, 'student'],
      function(err) {
        if (err) {
          console.error('Database error:', err);
          if (err.message.includes('UNIQUE')) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          return res.status(500).json({ error: 'Error creating user' });
        }
        console.log('User created successfully with ID:', this.lastID);
        const token = jwt.sign({ id: this.lastID, username, role: 'student' }, JWT_SECRET);
        console.log('JWT token generated');
        res.json({ token, username, fullName });
      }
    );
  } catch (err) {
    console.error('Error in registration:', err);
    res.status(500).json({ error: 'Error creating user: ' + err.message });
  }
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Error during login' });
    }
    if (!user) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    try {
      if (await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
          { id: user.id, username: user.username, role: user.role },
          JWT_SECRET
        );
        res.json({
          token,
          username: user.username,
          fullName: user.fullName,
          role: user.role
        });
      } else {
        res.status(401).json({ error: 'Invalid username or password' });
      }
    } catch (err) {
      res.status(500).json({ error: 'Error during login' });
    }
  });
});

// Protected routes
// Public: list questions for admin
app.get('/api/questions', (req, res) => {
  db.all("SELECT * FROM questions", [], (err, rows) => {
    if (err) return res.status(500).send(err);
    const formatted = rows.map(q => ({
      ...q,
      options: q.options ? JSON.parse(q.options) : []
    }));
    res.json(formatted);
  });
});

app.post('/api/submit', (req, res) => {
  console.log("Received submission:", req.body);
  res.json({ status: "submitted" });
});

app.post('/api/questions', (req, res) => {
  const { question, type, options, answer } = req.body;
  const optStr = options ? JSON.stringify(options) : null;
  db.run("INSERT INTO questions (question, type, options, answer) VALUES (?, ?, ?, ?)",
    [question, type, optStr, answer],
    function(err) {
      if (err) return res.status(500).send(err);
      res.json({ id: this.lastID });
    }
  );
});

app.put('/api/questions/:id', (req, res) => {
  const { question, type, options, answer } = req.body;
  const optStr = options ? JSON.stringify(options) : null;
  db.run("UPDATE questions SET question=?, type=?, options=?, answer=? WHERE id=?",
    [question, type, optStr, answer, req.params.id],
    function(err) {
      if (err) return res.status(500).send(err);
      res.json({ updated: this.changes });
    }
  );
});

app.delete('/api/questions/:id', (req, res) => {
  db.run("DELETE FROM questions WHERE id=?", [req.params.id], function(err) {
    if (err) return res.status(500).send(err);
    res.json({ deleted: this.changes });
  });
});

// Exam endpoints
app.post('/api/exams', (req, res) => {
  console.log('Received exam creation request:', req.body);
  const { title, duration, questions, webcamEnabled = false, audioEnabled = false } = req.body;
  if (!title || !duration || !questions) {
    console.log('Missing required fields');
    return res.status(400).json({ error: 'Missing required fields' });
  }
  const questionsStr = JSON.stringify(questions);
  console.log('Creating exam with:', { title, duration, questionsStr });
  db.run(
    "INSERT INTO exams (title, duration, questions, webcamEnabled, audioEnabled) VALUES (?, ?, ?, ?, ?)",
    [title, duration, questionsStr, webcamEnabled ? 1 : 0, audioEnabled ? 1 : 0],
    function(err) {
      if (err) {
        console.error('Exam creation error:', err.message);
        return res.status(500).json({ error: err.message });
      }
      console.log('Exam created with ID:', this.lastID);
      return res.json({ id: this.lastID });
    }
  );
});

app.get('/api/exams', (req, res) => {
  db.all("SELECT * FROM exams", [], (err, rows) => {
    if (err) return res.status(500).send(err);
    const formatted = rows.map(exam => ({
      ...exam,
      questions: JSON.parse(exam.questions),
      totalQuestions: JSON.parse(exam.questions).length
    }));
    res.json(formatted);
  });
});

app.get('/api/exams/:id', authenticateToken, (req, res) => {
  db.get("SELECT * FROM exams WHERE id = ?", [req.params.id], (err, exam) => {
    if (err) return res.status(500).send(err);
    if (!exam) return res.status(404).send('Exam not found');
    
    const examQuestions = JSON.parse(exam.questions);
    db.all("SELECT id, question, type, options FROM questions WHERE id IN (" + examQuestions.join(',') + ")", [], (err, questions) => {
      if (err) return res.status(500).send(err);
      res.json({
        ...exam,
        questions: questions.map(q => ({
          ...q,
          options: q.options ? JSON.parse(q.options) : []
        }))
      });
    });
  });
});

// Submit exam and get results
app.post('/api/exams/:id/submit', authenticateToken, (req, res) => {
  const { answers } = req.body;
  const examId = req.params.id;
  
  db.get("SELECT * FROM exams WHERE id = ?", [examId], (err, exam) => {
    if (err) return res.status(500).send(err);
    if (!exam) return res.status(404).send('Exam not found');
    
    const examQuestions = JSON.parse(exam.questions);
    db.all("SELECT id, answer FROM questions WHERE id IN (" + examQuestions.join(',') + ")", [], (err, questions) => {
      if (err) return res.status(500).send(err);
      
      let correct = 0;
      const total = questions.length;
      
      questions.forEach(q => {
        if (answers[q.id] === q.answer) correct++;
      });
      
      const score = Math.round((correct / total) * 100);
      
      db.run("INSERT INTO results (examId, userName, score, answers) VALUES (?, ?, ?, ?)",
        [examId, req.user.username, score, JSON.stringify(answers)],
        function(err) {
          if (err) return res.status(500).send(err);
          res.json({ 
            resultId: this.lastID,
            score,
            correct,
            total
          });
        }
      );
    });
  });
});

// Get exam result
app.get('/api/results/:id', (req, res) => {
  db.get("SELECT * FROM results WHERE id = ?", [req.params.id], (err, result) => {
    if (err) return res.status(500).send(err);
    if (!result) return res.status(404).send('Result not found');
    
    db.get("SELECT * FROM exams WHERE id = ?", [result.examId], (err, exam) => {
      if (err) return res.status(500).send(err);
      
      const examQuestions = JSON.parse(exam.questions);
      const answers = JSON.parse(result.answers);
      
      db.all("SELECT * FROM questions WHERE id IN (" + examQuestions.join(',') + ")", [], (err, questions) => {
        if (err) return res.status(500).send(err);
        
        const formattedQuestions = questions.map(q => ({
          id: q.id,
          question: q.question,
          userAnswer: answers[q.id],
          correctAnswer: q.answer,
          correct: answers[q.id] === q.answer
        }));
        
        res.json({
          id: result.id,
          examId: result.examId,
          score: result.score,
          questions: formattedQuestions,
          timestamp: result.timestamp,
          recordingPath: result.recordingPath
        });
      });
    });
  });
});

// Get all results for an exam
app.get('/api/exams/:id/results', (req, res) => {
  const examId = req.params.id;
  db.all("SELECT id, userName, score, timestamp FROM results WHERE examId = ?", [examId], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/results/:id/recording', authenticateToken, upload.single('recording'), (req, res) => {
  const resultId = req.params.id;
  const filename = req.file.filename;
  db.run("UPDATE results SET recordingPath=? WHERE id=?", [filename, resultId], function(err) {
    if (err) return res.status(500).send(err);
    res.json({ uploaded: true, path: `/recordings/${filename}` });
  });
});

app.use('/recordings', express.static(recordingsDir));

io.on('connection', socket => {
  console.log('Socket connected:', socket.id);
  socket.on('joinExam', examId => {
    socket.join(`exam_${examId}`);
  });
  socket.on('frame', data => {
    const { examId, image } = data;
    socket.to(`exam_${examId}`).emit('frame', data);
  });
  socket.on('flag', data => {
    const { examId, username, event } = data;
    // Persist flag event
    db.run('INSERT INTO flags (examId, userName, event) VALUES (?, ?, ?)', [examId, username, event]);
    // Broadcast flag to other clients (admins)
    socket.to(`exam_${examId}`).emit('flag', data);
  });
  socket.on('stopExam', examId => {
    // Broadcast stop command to students
    socket.to(`exam_${examId}`).emit('stopExam');
  });
});

// Admin can start the exam for students
app.post('/api/exams/:id/admin/start', (req, res) => {
  const examId = req.params.id;
  io.to(`exam_${examId}`).emit('startExam');
  res.json({ started: true });
});

// Admin can stop the exam for students
app.post('/api/exams/:id/admin/stop', (req, res) => {
  const examId = req.params.id;
  console.log('Admin stop route emit for exam', examId);
  io.to(`exam_${examId}`).emit('stopExam');
  res.json({ stopped: true });
});

// Endpoints for proctoring flags
app.post('/api/flags', (req, res) => {
  const { examId, username, event } = req.body;
  db.run('INSERT INTO flags (examId, userName, event) VALUES (?, ?, ?)', [examId, username, event], function(err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ id: this.lastID, examId, username, event });
  });
});

app.get('/api/exams/:id/flags', (req, res) => {
  db.all('SELECT * FROM flags WHERE examId = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

server.listen(port, () => {
  console.log(`Backend listening at http://localhost:${port}`);
});
