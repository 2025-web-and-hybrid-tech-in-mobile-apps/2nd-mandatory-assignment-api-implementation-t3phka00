const express = require("express");
const { check, validationResult, body } = require('express-validator');
const jwt = require("jsonwebtoken");

const app = express();
const port = process.env.PORT || 3000;

const secretKey = process.env.SECRET_KEY || "mysecretkey";

app.use(express.json());

let users = []; 
let highScores = [];

app.post('/signup', [
  body('userHandle').isLength({ min: 6 }).withMessage('User handle must be at least 6 characters long'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long')
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userHandle, password } = req.body;
  users.push({ userHandle, password });
  res.status(201).send('signup success');
});

app.post('/login', [
  check('userHandle').isString().notEmpty().withMessage('User  handle is required'),
  check('password').isString().notEmpty().withMessage('Password is required'),
  body().custom(value => {
    const allowedFields = ['userHandle', 'password'];
    const invalidFields = Object.keys(value).filter(field => !allowedFields.includes(field));
    if (invalidFields.length > 0) {
      throw new Error(`Invalid fields: ${invalidFields.join(', ')}`);
    }
    return true;
  })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { userHandle, password } = req.body;
  const user = users.find(u => u.userHandle === userHandle && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ userHandle }, secretKey, { expiresIn: '1h' });
  res.status(200).json({ jsonWebToken: token }); 
});

const authenticateJWT = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    req.user = decoded;
    next();
  });
};

app.post("/high-scores", authenticateJWT, (req, res) => {
  const { level, userHandle, score, timestamp } = req.body;

  if (!level || !userHandle || !score || !timestamp) {
    return res.status(400).json({ error: "All fields are required: level, userHandle, score, timestamp" });
  }

  highScores.push({ level, userHandle, score, timestamp });
  return res.status(201).json({ message: "High score added successfully" });
});

app.get("/high-scores", (req, res) => {
  const { level, page = 1 } = req.query;
  const pageSize = 20;

  if (!level) {
    return res.status(400).json({ error: "Level is required" });
  }

  const filteredScores = highScores.filter(score => score.level === level);

  const start = (page - 1) * pageSize;
  const end = start + pageSize;

  const paginatedScores = filteredScores.slice(start, end);

  paginatedScores.sort((a, b) => b.score - a.score);

  return res.status(200).json(paginatedScores);
});

let serverInstance = null;
module.exports = {
  start: function () {
    serverInstance = app.listen(port, () => {
      console.log(`Example app listening at http://localhost:${port}`);
    });
  },
  close: function () {
    serverInstance.close();
  },
};