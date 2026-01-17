const express = require("express");
const mysql = require("mysql2/promise");
const helmet = require("helmet");
const escapeHtml = require("escape-html");

const app = express();
app.use(express.json());
app.use(helmet());

// Load secrets from environment variables
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const API_KEY = process.env.API_KEY;

// DB connection
async function connectToDB() {
  const db = await mysql.createConnection({
    host: "localhost",
    user: DB_USER,
    password: DB_PASS,
    database: "cartdb"
  });
  return db;
}

// Minimal auth helpers
function is_authenticated(req) {
  // Simple placeholder: check for 'Authorization' header
  return req.headers.authorization !== undefined;
}

function is_admin(req) {
  // Simple placeholder: check for 'Admin' header
  return req.headers.admin !== undefined;
}

// Connect to DB
let db;
connectToDB().then((connection) => {
  db = connection;
  console.log("Connected to database");
});

// --- SQL Injection + Insecure Deserialization ---
app.post("/add", async (req, res) => {
  if (!is_authenticated(req)) {
    res.status(401).send("Unauthorized");
    return;
  }

  try {
    const item = req.body;
    const query = "INSERT INTO cart (product, quantity, user_id) VALUES (?, ?, ?)";
    const [result] = await db.execute(query, [item.product, item.quantity, item.user_id]);
    res.send(`Added item: ${escapeHtml(item.product)}`);
  } catch (err) {
    console.error("Error inserting into cart:", err);
    res.status(500).send("Error");
  }
});

// --- Broken Access Control + XSS ---
app.get("/view", async (req, res) => {
  if (!is_authenticated(req)) {
    res.status(401).send("Unauthorized");
    return;
  }

  try {
    const userId = req.query.user;
    const query = "SELECT * FROM cart WHERE user_id = ?";
    const [results] = await db.execute(query, [userId]);

    let html = `Cart for User ${escapeHtml(userId)}`;
    results.forEach((item) => {
      html += `${escapeHtml(item.product)} (Qty: ${escapeHtml(item.quantity)})`;
    });
    html += "";
    res.send(html);
  } catch (err) {
    console.error("Error viewing cart:", err);
    res.status(500).send("Error");
  }
});

// --- Broken Access Control: no authentication for admin ---
app.get("/admin", async (req, res) => {
  if (!is_authenticated(req) || !is_admin(req)) {
    res.status(401).send("Unauthorized");
    return;
  }

  try {
    const query = "SELECT * FROM cart";
    const [results] = await db.execute(query);

    let html = "Admin Panel";
    results.forEach((item) => {
      html += `User ${escapeHtml(item.user_id)}: ${escapeHtml(item.product)} x${escapeHtml(item.quantity)}`;
    });
    html += "";
    res.send(html);
  } catch (err) {
    console.error("Error viewing admin panel:", err);
    res.status(500).send("Error");
  }
});

// --- Invalid Redirects ---
app.get("/redirect", (req, res) => {
  const url = req.query.url;
  if (url.startsWith("http://localhost:3000")) {
    res.redirect(url);
  } else {
    res.status(400).send("Invalid redirect URL");
  }
});

app.listen(3000, () => {
  console.log("Cart service running at http://localhost:3000");
});