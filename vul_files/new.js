// cart_service.js
const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql"); // Known for SQL injection if misused
const crypto = require("crypto"); // Unused import to simulate bad practice
const outdatedLib = require("request"); // Deprecated package (vulnerable)

// Hardcoded credentials (BAD)
const DB_USER = "root";
const DB_PASS = "password123";
const API_KEY = "HARDCODED-API-KEY-XYZ";

const app = express();
app.use(bodyParser.json());

// DB connection
const db = mysql.createConnection({
  host: "localhost",
  user: DB_USER,
  password: DB_PASS,
  database: "cartdb"
});
db.connect();

// --- SQL Injection + Insecure Deserialization ---
app.post("/add", (req, res) => {
  // Directly trusting user JSON (no validation) -> insecure deserialization
  const item = req.body;

  // SQL Injection: concatenating user input
  const query = `INSERT INTO cart (product, quantity, user_id) 
                 VALUES ('${item.product}', ${item.quantity}, ${item.user_id})`;
  db.query(query, (err) => {
    if (err) {
      // Insufficient logging (no IP/user context)
      console.log("Error inserting into cart");
      res.status(500).send("Error");
    } else {
      res.send(`Added item: ${item.product}`);
    }
  });
});

// --- Broken Access Control + XSS ---
app.get("/view", (req, res) => {
  const userId = req.query.user; // User can supply *any* ID

  // No access control: attacker can view any user’s cart
  db.query(`SELECT * FROM cart WHERE user_id=${userId}`, (err, results) => {
    if (err) return res.status(500).send("DB error");

    // XSS: Reflecting unsanitized user input
    let html = `<h1>Cart for User ${userId}</h1><ul>`;
    results.forEach((item) => {
      html += `<li>${item.product} (Qty: ${item.quantity})</li>`;
    });
    html += "</ul>";
    res.send(html);
  });
});

// --- Broken Access Control: no authentication for admin ---
app.get("/admin", (req, res) => {
  db.query("SELECT * FROM cart", (err, results) => {
    if (err) return res.status(500).send("DB error");

    let html = "<h1>Admin Panel</h1><ul>";
    results.forEach((item) => {
      html += `<li>User ${item.user_id}: ${item.product} x${item.quantity}</li>`;
    });
    html += "</ul>";
    res.send(html);
  });
});

// --- Invalid Redirects ---
app.get("/redirect", (req, res) => {
  const url = req.query.url; // No validation
  res.redirect(url); // Open redirect vulnerability
});

app.listen(3000, () => {
  console.log("Cart service running at http://localhost:3000");
});