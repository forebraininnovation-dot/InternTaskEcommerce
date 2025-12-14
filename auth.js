const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./db");

/* ================= SIGNUP ================= */
exports.signup = async (req, res) => {
  const { fullName, email, password } = req.body;

  if (!fullName || !email || !password) {
    return res.status(400).json({ message: "All fields required" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const sql =
    "INSERT INTO users (full_name, email, password, provider) VALUES (?, ?, ?, 'local')";

  db.query(sql, [fullName, email, hashedPassword], (err) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY") {
        return res.status(400).json({ message: "Email already exists" });
      }
      return res.status(500).json({ message: "Database error" });
    }

    res.status(201).json({ message: "Signup successful" });
  });
};

/* ================= LOGIN ================= */
exports.login = (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ? AND provider = 'local'";
  db.query(sql, [email], async (err, result) => {
    if (err || result.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ message: "Login successful", token });
  });
};

/* ========= GOOGLE LOGIN (Firebase users) ========= */
exports.googleLogin = (req, res) => {
  const { fullName, email } = req.body;

  const checkSql = "SELECT * FROM users WHERE email = ?";
  db.query(checkSql, [email], (err, result) => {
    if (result.length === 0) {
      const insertSql =
        "INSERT INTO users (full_name, email, provider) VALUES (?, ?, 'google')";
      db.query(insertSql, [fullName, email]);
    }

    const token = jwt.sign(
      { email, provider: "google" },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({ message: "Google login successful", token });
  });
};
