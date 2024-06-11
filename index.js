const express = require("express");
const jwt = require("jsonwebtoken");
const path = require("path");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const mysql = require("mysql");
const secretkey = "secretkey"; // Secret key for JWT token

const app = express();

app.set("view engine", "hbs"); // Set the view engine to handlebars
app.set("views", path.join(__dirname, "../sec/views")); // Set the views directory
app.use(express.static(path.join(__dirname, "../sec/public"))); // Set the static files directory
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(cookieParser()); // Parse cookies

const db = mysql.createConnection({
  host: "localhost",
  user: "your-username", // replace with your MySQL username
  password: "your-password", // replace with your MySQL password
  database: "userdb"
});

db.connect(err => {
  if (err) {
    console.error("Database connection failed: " + err.stack);
    return;
  }
  console.log("Connected to database.");
});

// Render the login form
app.get("/", (req, res) => {
  res.render("login");
});

// Handle login form submission
app.post("/", (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  // Query the database to check if the user exists
  db.query("SELECT * FROM users WHERE email = ? AND password = ?", [email, password], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    if (results.length > 0) {
      const user = results[0];
      const token = jwt.sign({ email: user.email, password: user.password }, secretkey);
      res.cookie("auth_token", token, { httpOnly: true });
      db.query("UPDATE users SET token = ? WHERE email = ?", [token, email]);
      console.log("Login completed");
      res.redirect("/profile");
    } else {
      console.log("Login failed");
      res.render("login");
    }
  });
});

// Render the registration form
app.get("/register", (req, res) => {
  res.render("register");
});

// Handle registration form submission
app.post("/register", (req, res) => {
  const first = req.body.first;
  const mid = req.body.mid;
  const surname = req.body.surname;
  const email = req.body.email;
  const password = req.body.password;
  const confirm = req.body.confirm;

  if (password === confirm) {
    const token = jwt.sign({ email: email, password: password }, secretkey);

    // Insert the new user into the database
    db.query(
      "INSERT INTO users (first, mid, surname, email, password, token) VALUES (?, ?, ?, ?, ?, ?)",
      [first, mid, surname, email, password, token],
      (err, results) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        res.cookie("auth_token", token, { httpOnly: true });
        console.log("User registered");
        res.redirect("/");
      }
    );
  } else {
    res.render("register");
  }
});

// Middleware to check if the user is authenticated
const authentic_token = (req, res, next) => {
  const token = req.cookies.auth_token;
  if (!token) {
    return res.redirect("/register");
  }
  try {
    const decode = jwt.verify(token, secretkey);
    req.user = decode;
    next();
  } catch (error) {
    res.redirect("/register");
  }
};

// Render the profile page
app.get("/profile", authentic_token, (req, res) => {
  res.render("profile");
});

// Render the user information page
app.get("/info", (req, res) => {
  // Query the database to get all users
  db.query("SELECT * FROM users", (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    res.render("info", { users: results });
  });
});

// Render the update information page
app.get("/update", (req, res) => {
  res.render("update");
});

// Handle update information form submission
app.post("/update", (req, res) => {
  const first = req.body.first;
  const mid = req.body.mid;
  const surname = req.body.surname;
  const email = req.body.email;

  // Update the user information in the database
  db.query(
    "UPDATE users SET first = ?, mid = ?, surname = ? WHERE email = ?",
    [first, mid, surname, email],
    (err, results) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      console.log("User information updated");
      res.redirect("/info");
    }
  );
});

// Start the server
app.listen(5000, () => {
  console.log("Server is working on port 5000");
});
