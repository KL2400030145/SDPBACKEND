require('dotenv').config();
const express = require('express');
const cors = require('cors');
const morgan = require('morgan');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors({ origin: 'http://localhost:5173', credentials: true }));
app.use(express.json());
app.use(morgan('dev'));

const port = Number(process.env.PORT || 8080);
const jwtSecret = process.env.JWT_SECRET || 'supersecretkey';
const dbName = process.env.DB_NAME || 'election_monitor';

const dbConfig = {
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: dbName,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

const elections = [
  { id: 1, name: 'City Council Election', status: 'Ongoing', votes: 2094, turnout: 54, anomalies: 2 },
  { id: 2, name: 'School Board Election', status: 'Pending', votes: 0, turnout: 0, anomalies: 0 },
  { id: 3, name: 'Mayor Election', status: 'Paused', votes: 4321, turnout: 62, anomalies: 4 }
];

const issues = [
  { id: 1, type: 'Accessibility', description: 'Voter information page not accessible on mobile.', status: 'Open', reporter: 'Citizen' },
  { id: 2, type: 'Delay', description: 'Counting center reports delayed updates.', status: 'Open', reporter: 'Observer' }
];

const observations = [
  { id: 1, electionId: 1, message: 'Unexpected vote spike at 11:30 AM.', severity: 'Medium' },
  { id: 2, electionId: 3, message: 'Server delay on polling station feed.', severity: 'High' }
];

let pool;

async function initializeDatabase() {
  const adminConnection = await mysql.createConnection({
    host: dbConfig.host,
    port: dbConfig.port,
    user: dbConfig.user,
    password: dbConfig.password,
  });

  await adminConnection.query(`CREATE DATABASE IF NOT EXISTS \`${dbName}\``);
  await adminConnection.end();

  pool = mysql.createPool(dbConfig);
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('Admin','Citizen','Observer','Analyst') NOT NULL DEFAULT 'Citizen',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);
}

function generateToken(user) {
  return jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, jwtSecret, { expiresIn: '2h' });
}

async function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Authentication required.' });
  }

  const token = authHeader.split(' ')[1];
  try {
    req.user = jwt.verify(token, jwtSecret);
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: 'Name, email, password, and role are required.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  try {
    const [result] = await pool.query('INSERT INTO users (name, email, password_hash, role) VALUES (?, ?, ?, ?)', [name, email, passwordHash, role]);
    const user = { id: result.insertId, name, email, role };
    const token = generateToken(user);
    return res.status(201).json({ user, token });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ message: 'An account with this email already exists.' });
    }
    console.error(error);
    res.status(500).json({ message: 'Unable to register user.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  const user = rows[0];
  if (!user) {
    return res.status(401).json({ message: 'Email or password is incorrect.' });
  }

  const validPassword = await bcrypt.compare(password, user.password_hash);
  if (!validPassword) {
    return res.status(401).json({ message: 'Email or password is incorrect.' });
  }

  const userProfile = { id: user.id, name: user.name, email: user.email, role: user.role };
  const token = generateToken(userProfile);
  res.json({ user: userProfile, token });
});

app.get('/api/auth/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

app.get('/api/elections', authenticateToken, (req, res) => {
  res.json(elections);
});

app.get('/api/reports', authenticateToken, (req, res) => {
  const report = {
    totalElections: elections.length,
    activeElections: elections.filter(e => e.status === 'Ongoing').length,
    totalIssues: issues.length,
    totalObservations: observations.length,
    averageTurnout: Math.round(elections.reduce((sum, item) => sum + item.turnout, 0) / elections.length)
  };
  res.json(report);
});

app.post('/api/issues', authenticateToken, (req, res) => {
  const { type, description, reporter } = req.body;
  if (!type || !description || !reporter) {
    return res.status(400).json({ message: 'Issue type, description, and reporter are required.' });
  }
  const nextId = issues.length ? Math.max(...issues.map(i => i.id)) + 1 : 1;
  const newIssue = { id: nextId, type, description, status: 'Open', reporter };
  issues.push(newIssue);
  res.status(201).json(newIssue);
});

app.post('/api/observations', authenticateToken, (req, res) => {
  const { electionId, message, severity } = req.body;
  if (!electionId || !message || !severity) {
    return res.status(400).json({ message: 'Election ID, message, and severity are required.' });
  }
  const nextId = observations.length ? Math.max(...observations.map(o => o.id)) + 1 : 1;
  const newObservation = { id: nextId, electionId, message, severity };
  observations.push(newObservation);
  res.status(201).json(newObservation);
});

app.post('/api/elections', authenticateToken, (req, res) => {
  const { name, status, votes, turnout } = req.body;
  if (!name || !status) {
    return res.status(400).json({ message: 'Election name and status are required.' });
  }
  const nextId = elections.length ? Math.max(...elections.map(e => e.id)) + 1 : 1;
  const newElection = {
    id: nextId,
    name,
    status,
    votes: votes || 0,
    turnout: turnout || 0,
    anomalies: 0
  };
  elections.push(newElection);
  res.status(201).json(newElection);
});

app.use((req, res) => {
  res.status(404).json({ message: 'Endpoint not found.' });
});

initializeDatabase()
  .then(() => {
    app.listen(port, () => {
      console.log(`Backend running at http://localhost:${port}`);
    });
  })
  .catch(error => {
    console.error('Database initialization failed:', error);
    process.exit(1);
  });
