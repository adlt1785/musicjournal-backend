// index.js - Express server for Music Journal

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const session = require("express-session");
const MySQLStore = require("express-mysql-session")(session);
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");

const app = express();

// ---- DB OPTIONS ----
const dbOptions = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
};

// Reusable DB pool for queries
const pool = mysql.createPool(dbOptions);

// ---- CORS (allow your frontend to talk to the backend) ----
app.use(
  cors({
    origin: [
      "http://127.0.0.1:5500",
      "http://localhost:5500",
    ],
    credentials: true,
  })
);

// ---- BODY PARSING ----
app.use(express.json());

// ---- SESSION SETUP ----

// This creates a "sessions" table in your MariaDB (if it doesn't exist)
// and stores session data there.
const sessionStore = new MySQLStore(dbOptions);

app.use(
  session({
    name: "mj_session", // cookie name
    secret: process.env.SESSION_SECRET || "dev_secret_change_me",
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
      sameSite: "lax",
      httpOnly: true,
    },
  })
);

// ---- HELPER FUNCTIONS ----

async function findUserByUsername(username) {
  const [rows] = await pool.query(
    "SELECT * FROM users WHERE username = ?",
    [username]
  );
  return rows[0]; // undefined if not found
}

// Require the user to be logged in
function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  next();
}

// Password must be 8+ chars, one lower, one upper, one digit, one special char
function passwordMeetsRequirements(password) {
  const regex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
  return regex.test(password);
}

// Find existing album by external_id or create it, return album id
async function findOrCreateAlbum(externalId, title, artist, coverUrl) {
  const [existing] = await pool.query(
    "SELECT id FROM albums WHERE external_id = ?",
    [externalId]
  );
  if (existing.length > 0) {
    return existing[0].id;
  }

  const [result] = await pool.query(
    "INSERT INTO albums (external_id, title, artist, cover_url) VALUES (?, ?, ?, ?)",
    [externalId, title, artist, coverUrl]
  );
  return result.insertId;
}

// Ensure there is a row in user_albums for this user+album
async function ensureUserAlbum(userId, albumId) {
  await pool.query(
    "INSERT IGNORE INTO user_albums (user_id, album_id) VALUES (?, ?)",
    [userId, albumId]
  );
}

// ---- TEST ROUTES ----

app.get("/api/ping", (req, res) => {
  res.json({
    message: "pong",
    time: new Date().toISOString(),
  });
});

app.get("/api/session-test", (req, res) => {
  if (!req.session.views) {
    req.session.views = 1;
  } else {
    req.session.views += 1;
  }

  res.json({
    message: "session working",
    views: req.session.views,
  });
});

// ---- AUTH ROUTES ----

app.post("/api/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    // ✅ NEW: strong password rule
    if (!passwordMeetsRequirements(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 characters and include uppercase, lowercase, number, and special character.",
      });
    }

    const existing = await findUserByUsername(username);
    if (existing) {
      return res.status(400).json({ error: "Username already taken" });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const [result] = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES (?, ?)",
      [username, passwordHash]
    );

    const userId = result.insertId;

    req.session.userId = userId;
    req.session.username = username;

    res.json({
      success: true,
      user: { id: userId, username },
    });
  } catch (err) {
    console.error("Error in /api/register:", err);
    res.status(500).json({ error: "Server error during registration" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Username and password required" });
    }

    const user = await findUserByUsername(username);
    if (!user) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: "Invalid username or password" });
    }

    req.session.userId = user.id;
    req.session.username = user.username;

    res.json({
      success: true,
      user: { id: user.id, username: user.username },
    });
  } catch (err) {
    console.error("Error in /api/login:", err);
    res.status(500).json({ error: "Server error during login" });
  }
});

app.get("/api/me", async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.json({ user: null });
    }

    const [rows] = await pool.query(
      "SELECT id, username, created_at FROM users WHERE id = ?",
      [req.session.userId]
    );
    const user = rows[0];

    if (!user) {
      return res.json({ user: null });
    }

    res.json({ user });
  } catch (err) {
    console.error("Error in /api/me:", err);
    res.status(500).json({ error: "Server error fetching user" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      return res.status(500).json({ error: "Could not log out" });
    }
    res.clearCookie("mj_session");
    res.json({ success: true });
  });
});

// ---- USER ALBUM ROUTES ----

app.post("/api/user/albums", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { externalId, title, artist, coverUrl } = req.body;

    if (!externalId || !title || !artist) {
      return res.status(400).json({ error: "Missing album data" });
    }

    const albumId = await findOrCreateAlbum(
      externalId,
      title,
      artist,
      coverUrl || null
    );

    await ensureUserAlbum(userId, albumId);

    res.json({ success: true, albumId });
  } catch (err) {
    console.error("Error in POST /api/user/albums:", err);
    res.status(500).json({ error: "Server error saving album" });
  }
});

app.get("/api/user/albums", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;

    const [rows] = await pool.query(
      `
      SELECT 
        a.external_id,
        a.title,
        a.artist,
        a.cover_url,
        ua.created_at,
        ua.notes
      FROM user_albums ua
      JOIN albums a ON ua.album_id = a.id
      WHERE ua.user_id = ?
      ORDER BY ua.created_at DESC
      `,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error("Error in GET /api/user/albums:", err);
    res.status(500).json({ error: "Server error fetching user albums" });
  }
});

// ---- ALBUM NOTES ROUTE ----

app.post("/api/user/album-notes", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      albumExternalId,
      albumTitle,
      albumArtist,
      coverUrl,
      notes,
    } = req.body;

    if (!albumExternalId) {
      return res.status(400).json({ error: "Missing albumExternalId" });
    }

    const albumId = await findOrCreateAlbum(
      albumExternalId,
      albumTitle || "Unknown album",
      albumArtist || "Unknown artist",
      coverUrl || null
    );

    await ensureUserAlbum(userId, albumId);

    await pool.query(
      "UPDATE user_albums SET notes = ? WHERE user_id = ? AND album_id = ?",
      [notes || null, userId, albumId]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error in POST /api/user/album-notes:", err);
    res.status(500).json({ error: "Server error saving notes" });
  }
});

// ---- TRACK RATING ROUTES ----

app.post("/api/user/ratings", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const {
      albumExternalId,
      albumTitle,
      albumArtist,
      coverUrl,
      trackId,
      trackName,
      rating,
    } = req.body;

    if (!albumExternalId || !trackId || !trackName || rating == null) {
      return res.status(400).json({ error: "Missing rating data" });
    }

    const numericRating = Number(rating);
    if (
      !Number.isInteger(numericRating) ||
      numericRating < 1 ||
      numericRating > 5
    ) {
      return res
        .status(400)
        .json({ error: "Rating must be an integer between 1 and 5" });
    }

    const albumId = await findOrCreateAlbum(
      albumExternalId,
      albumTitle || "Unknown album",
      albumArtist || "Unknown artist",
      coverUrl || null
    );
    await ensureUserAlbum(userId, albumId);

    await pool.query(
      `
      INSERT INTO track_ratings (user_id, album_id, track_id, track_name, rating)
      VALUES (?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE rating = VALUES(rating), updated_at = CURRENT_TIMESTAMP
      `,
      [userId, albumId, trackId, trackName, numericRating]
    );

    res.json({ success: true });
  } catch (err) {
    console.error("Error in POST /api/user/ratings:", err);
    res.status(500).json({ error: "Server error saving rating" });
  }
});

app.get("/api/user/ratings/:externalId", requireLogin, async (req, res) => {
  try {
    const userId = req.session.userId;
    const { externalId } = req.params;

    const [albums] = await pool.query(
      "SELECT id FROM albums WHERE external_id = ?",
      [externalId]
    );

    if (albums.length === 0) {
      return res.json({});
    }

    const albumId = albums[0].id;

    const [rows] = await pool.query(
      "SELECT track_id, track_name, rating FROM track_ratings WHERE user_id = ? AND album_id = ?",
      [userId, albumId]
    );

    const map = {};
    for (const row of rows) {
      map[row.track_id] = {
        trackId: row.track_id,
        trackName: row.track_name,
        rating: row.rating,
      };
    }

    res.json(map);
  } catch (err) {
    console.error("Error in GET /api/user/ratings/:externalId:", err);
    res.status(500).json({ error: "Server error fetching ratings" });
  }
});

// ---- START SERVER ----

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ API server listening on http://localhost:${PORT}`);
});
