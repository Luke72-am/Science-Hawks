"use strict";

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const bcrypt = require("bcryptjs");

const ADMIN_USER = process.env.ADMIN_USER || "Luke";
const ADMIN_PASS = process.env.ADMIN_PASS || "3113";
const PORT = process.env.PORT || 3000;

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const VIDEOS_DIR = path.join(__dirname, "uploads", "videos");
const INTRO_DIR = path.join(__dirname, "uploads", "intro");

for (const dir of [DATA_DIR, VIDEOS_DIR, INTRO_DIR]) {
  fs.mkdirSync(dir, { recursive: true });
}

const DEFAULT_INTRO_TEXT = [
  "Hello, my name is Luke, and I have created this website to support the local community and provide free education for children, especially homeschoolers. This website provides free access to 30 minute videos, created by yours truly, of science, STEM, space and physics. All of my information comes directly from these PUBLIC DOMAIN TEXTBOOKS (enter names here). Every Tuesday and Thursday I release my videos, for you to watch and have complete access to forever.",
  "Every Tuesday I release a video covering chemistry and STEM related topics. First we will cover the bonds between atoms and molecules, how they all work. Then we will cover different kinds of popular chemical compounds and bonds, and their uses in later videos. Thursdays I release space and physics related videos. We will cover astronomy, how stars and black holes work, the true scale of the universe, and much more. Now I have much more content on chemistry though, and once I run out of space like content after a few months, maybe more, I will start covering chemistry in ALL released videos after that.",
  "Now keep in mind I am not qualified or certified for this, I am only a teen. But my sources are very reliable and these topics are my passion. Lastly, this is a strictly CLEAN, and Christian site, no language or inappropriate content, this website is meant to serve the community, and The Lord. If you have any questions, comments or concerns, watch the video below. Or you can reach me at Travelingtreasures12345@gmail.com, or you can leave a review highlighting your thoughts. Thank you God be with you all."
].join("\n\n");

// ---------- Data store (simple JSON file, fine for local/basic use) ----------
function loadDb() {
  if (!fs.existsSync(DB_FILE)) {
    return { users: {}, videos: [], reviews: [], introText: DEFAULT_INTRO_TEXT, introVideo: null };
  }
  try {
    const parsed = JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
    return {
      users: parsed.users || {},
      videos: parsed.videos || [],
      reviews: parsed.reviews || [],
      introText: parsed.introText || DEFAULT_INTRO_TEXT,
      introVideo: parsed.introVideo || null
    };
  } catch (e) {
    return { users: {}, videos: [], reviews: [], introText: DEFAULT_INTRO_TEXT, introVideo: null };
  }
}

let db = loadDb();
function saveDb() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

// ---------- Profanity filter (server-side, never trust the client) ----------
const BAD_WORDS = [
  "fuck", "shit", "bitch", "asshole", "bastard", "dick", "piss",
  "cunt", "cock", "pussy", "slut", "whore", "damn", "crap", "hell"
];
const BAD_WORDS_RE = new RegExp("\\b(" + BAD_WORDS.join("|") + ")\\b", "gi");
function censor(text) {
  return text.replace(BAD_WORDS_RE, (match) => "*".repeat(match.length));
}

// ---------- Release-schedule helpers ----------
function getReleaseDate(video) {
  if (!video.releaseDays || video.releaseDays.length === 0) return null;
  const start = new Date(video.uploadedAt);
  start.setHours(0, 0, 0, 0);
  for (let i = 0; i < 7; i++) {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    if (video.releaseDays.includes(d.getDay())) return d;
  }
  return start;
}
function isReleased(video) {
  const releaseDate = getReleaseDate(video);
  if (!releaseDate) return true;
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  return today >= releaseDate;
}

function publicVideo(v) {
  return {
    id: v.id,
    title: v.title,
    uploadedAt: v.uploadedAt,
    releaseDays: v.releaseDays,
    released: isReleased(v),
    releaseDate: getReleaseDate(v),
    url: `/uploads/videos/${v.filename}`
  };
}

// ---------- App setup ----------
const app = express();
app.use(express.json());
app.use(
  session({
    name: "sh_sid",
    secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax", maxAge: 30 * 24 * 60 * 60 * 1000 }
  })
);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: "Not signed in." });
  next();
}
function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  next();
}

// ---------- Auth ----------
app.get("/api/session", (req, res) => {
  res.json({ user: req.session.user || null });
});

app.post("/api/signup", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Please choose a username and password." });
  }
  if (username.toLowerCase() === ADMIN_USER.toLowerCase()) {
    return res.status(400).json({ error: "That username is reserved." });
  }
  if (db.users[username]) {
    return res.status(400).json({ error: "That username is already taken." });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  db.users[username] = { username, passwordHash };
  saveDb();
  req.session.user = { username, role: "viewer" };
  res.status(201).json({ user: req.session.user });
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Please enter a username and password." });
  }
  if (username === ADMIN_USER && password === ADMIN_PASS) {
    req.session.user = { username: ADMIN_USER, role: "admin" };
    return res.json({ user: req.session.user });
  }
  const record = db.users[username];
  if (!record || !(await bcrypt.compare(password, record.passwordHash))) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }
  req.session.user = { username, role: "viewer" };
  res.json({ user: req.session.user });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({}));
});

// ---------- Videos ----------
const videoUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, VIDEOS_DIR),
    filename: (req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(file.originalname)}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 } // 2GB
});

app.get("/api/videos", (req, res) => {
  const isAdmin = req.session.user && req.session.user.role === "admin";
  const videos = db.videos
    .filter((v) => isAdmin || isReleased(v))
    .sort((a, b) => b.uploadedAt - a.uploadedAt)
    .map(publicVideo);
  res.json({ videos });
});

app.post("/api/videos", requireAdmin, videoUpload.single("video"), (req, res) => {
  const title = (req.body.title || "").trim();
  if (!title || !req.file) {
    return res.status(400).json({ error: "Please add a title and choose a video file." });
  }
  let releaseDays = [];
  try {
    releaseDays = JSON.parse(req.body.releaseDays || "[]");
    if (!Array.isArray(releaseDays)) releaseDays = [];
  } catch (e) {
    releaseDays = [];
  }
  const video = {
    id: crypto.randomUUID(),
    title,
    filename: req.file.filename,
    uploadedAt: Date.now(),
    releaseDays: releaseDays.filter((d) => Number.isInteger(d) && d >= 0 && d <= 6)
  };
  db.videos.push(video);
  saveDb();
  res.status(201).json({ video: publicVideo(video) });
});

app.post("/api/videos/:id/release-now", requireAdmin, (req, res) => {
  const video = db.videos.find((v) => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: "Video not found." });
  video.releaseDays = [];
  saveDb();
  res.json({ video: publicVideo(video) });
});

app.delete("/api/videos/:id", requireAdmin, (req, res) => {
  const video = db.videos.find((v) => v.id === req.params.id);
  if (!video) return res.status(404).json({ error: "Video not found." });
  if (isReleased(video)) {
    return res.status(400).json({ error: "Released videos are permanent and can't be deleted." });
  }
  db.videos = db.videos.filter((v) => v.id !== video.id);
  saveDb();
  fs.unlink(path.join(VIDEOS_DIR, video.filename), () => {});
  res.json({});
});

// ---------- Reviews ----------
app.get("/api/reviews", (req, res) => {
  const reviews = db.reviews.slice().sort((a, b) => b.date - a.date);
  res.json({ reviews });
});

app.post("/api/reviews", requireAuth, (req, res) => {
  const text = (req.body.text || "").trim();
  if (!text) return res.status(400).json({ error: "Please write a review before posting." });
  const review = {
    id: crypto.randomUUID(),
    username: req.session.user.username,
    text: censor(text),
    date: Date.now()
  };
  db.reviews.push(review);
  saveDb();
  res.status(201).json({ review });
});

app.delete("/api/reviews/:id", requireAuth, (req, res) => {
  const review = db.reviews.find((r) => r.id === req.params.id);
  if (!review) return res.status(404).json({ error: "Review not found." });
  if (review.username !== req.session.user.username) {
    return res.status(403).json({ error: "You can only delete your own review." });
  }
  db.reviews = db.reviews.filter((r) => r.id !== review.id);
  saveDb();
  res.json({});
});

// ---------- Intro text ----------
app.get("/api/intro", (req, res) => {
  res.json({ text: db.introText });
});

app.put("/api/intro", requireAdmin, (req, res) => {
  const text = (req.body.text || "").trim();
  if (!text) return res.status(400).json({ error: "Description can't be empty." });
  db.introText = text;
  saveDb();
  res.json({ text: db.introText });
});

// ---------- Intro video ----------
const introUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, INTRO_DIR),
    filename: (req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(file.originalname)}`)
  }),
  limits: { fileSize: 2 * 1024 * 1024 * 1024 }
});

app.get("/api/intro-video", (req, res) => {
  res.json({ url: db.introVideo ? `/uploads/intro/${db.introVideo.filename}` : null });
});

app.post("/api/intro-video", requireAdmin, introUpload.single("video"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Please choose a video file." });
  const old = db.introVideo;
  db.introVideo = { filename: req.file.filename, uploadedAt: Date.now() };
  saveDb();
  if (old) fs.unlink(path.join(INTRO_DIR, old.filename), () => {});
  res.json({ url: `/uploads/intro/${db.introVideo.filename}` });
});

app.delete("/api/intro-video", requireAdmin, (req, res) => {
  if (db.introVideo) {
    fs.unlink(path.join(INTRO_DIR, db.introVideo.filename), () => {});
    db.introVideo = null;
    saveDb();
  }
  res.json({});
});

// ---------- Static files ----------
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "..")));

app.listen(PORT, () => {
  console.log(`Science Hound server running at http://localhost:${PORT}`);
});
