import express from "express";
import fs from "fs/promises";
import path from "path";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import { Server as IOServer } from "socket.io";
import http from "http";
import nodemailer from "nodemailer";
import csurf from "csurf";
import { v4 as uuidv4 } from "uuid";

dotenv.config();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.resolve("./data.json");
const PUBLIC_DIR = path.resolve("./"); // ✅ Serve current folder

const app = express();
const server = http.createServer(app);
const io = new IOServer(server, { cors: { origin: true, credentials: true } });

app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: [
    'http://localhost:3000',                        // Local testing
    'https://vinayakak2.github.io/QRRP/',     // Replace with your GitHub Pages link
    'https://qrrp-ipew.onrender.com'                // Backend itself
  ],
  credentials: true
}));

app.use(cookieParser());
app.use(express.static(PUBLIC_DIR));
// Protect admin pages
app.use("/secure", auth, express.static(path.join(PUBLIC_DIR, "secure")));
app.use("/secure", (req, res) => {
  res.redirect("/login.html");
});


const csrfProtection = csurf({ cookie: true });

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  message: { ok: false, message: "Too many requests" }
});
app.use("/api/orders/create", limiter);

// ---------- Utility ----------
async function readData() {
  const raw = await fs.readFile(DATA_FILE, "utf8");
  return JSON.parse(raw);
}
async function writeData(data) {
  await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
}
function dist(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = lat1 * Math.PI/180, φ2 = lat2 * Math.PI/180;
  const Δφ = (lat2 - lat1) * Math.PI/180, Δλ = (lon2 - lon1) * Math.PI/180;
  const a = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}
const JWT_SECRET = process.env.JWT_SECRET || "secret";
function signQr(payload, exp = "8h") {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: exp });
}
function verifyQr(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ---------- Mail ----------
const mailer = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: false,
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
});
async function sendMail(order) {
  if (!process.env.NOTIFY_EMAIL) return;
  await mailer.sendMail({
    from: process.env.SMTP_USER,
    to: process.env.NOTIFY_EMAIL,
    subject: `New order #${order.id} - Table ${order.tableId}`,
    text: order.items.map(i => `${i.name} x${i.qty}`).join("\n")
  }).catch(console.warn);
}

// ---------- Auth ----------
function auth(req, res, next) {
  const token = req.cookies.session;
  if (!token) return res.status(401).json({ ok: false });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ ok: false });
  }
}

// ---------- Init ----------
async function init() {
  const d = await readData();
  if (!d.admins || !d.admins[0] || !d.admins[0].passwordHash) {
    d.admin.passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
    for (let t of d.tables) {
      t.pinHash = bcrypt.hashSync(t.pinPlain || "1234", 10);
    }
    await writeData(d);
  }
}
await init();

// ---------- API ----------
app.post("https://qrrp-ipew.onrender.com/api/auth/login", async (req, res) => {

  const { username, password } = req.body;
  const d = await readData();
  if (username !== d.admin.username) return res.status(401).json({ ok: false });
  if (!bcrypt.compareSync(password, d.admin.passwordHash))
    return res.status(401).json({ ok: false });
  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "8h" });
  res.cookie("session", token, { httpOnly: true, sameSite: "lax" });
  res.json({ ok: true });
});

app.get("https://qrrp-ipew.onrender.com/api/auth/me", (req, res) => {
  try {
    const decoded = jwt.verify(req.cookies.session, JWT_SECRET);
    res.json({ ok: true, user: decoded, sessionExpiry: decoded.exp * 1000 });
  } catch {
    res.status(401).json({ ok: false, msg: "Invalid or expired session" });
  }
});

app.post("https://qrrp-ipew.onrender.com/api/admin/generate-qr", auth, csrfProtection, async (req, res) => {
  const { tableId } = req.body;
  const token = signQr({ tableId });
  const qrUrl = `${req.protocol}://${req.get("host")}/index.html?token=${encodeURIComponent(token)}`;
  res.json({ ok: true, qrUrl });
});

app.post("https://qrrp-ipew.onrender.com/api/validate-location", async (req, res) => {
  const { token, lat, lng } = req.body;
  const payload = verifyQr(token);
  if (!payload) return res.json({ ok: false, msg: "Invalid QR token" });

  if (!lat || !lng)
    return res.status(400).json({ ok: false, msg: "Location required" });

  const distance = dist(
    parseFloat(lat),
    parseFloat(lng),
    parseFloat(process.env.RESTAURANT_LAT),
    parseFloat(process.env.RESTAURANT_LNG)
  );

  const allowed = distance <= parseFloat(process.env.RESTAURANT_RADIUS_METERS);
  res.json({
    ok: allowed,
    inside: allowed,
    distance: Math.round(distance),
    msg: allowed
      ? "Inside restaurant radius"
      : "Outside restaurant area, cannot place order"
  });
});


app.post("https://qrrp-ipew.onrender.com/api/validate-pin", async (req, res) => {
  const { token, tableId, pin } = req.body;
  const payload = verifyQr(token);
  if (!payload) return res.json({ ok: false });
  const d = await readData();
  const t = d.tables.find(x => x.id == tableId);
  res.json({ ok: bcrypt.compareSync(pin, t.pinHash) });
});

app.post("https://qrrp-ipew.onrender.com/api/orders/create", limiter, async (req, res) => {
  const { token, tableId, items } = req.body;
  const payload = verifyQr(token);
  if (!payload) return res.status(401).json({ ok: false });
  const d = await readData();
  const order = { id: uuidv4(), tableId, items, createdAt: new Date().toISOString() };
  d.orders.push(order);
  await writeData(d);
  io.emit("orders:update", d.orders);
  sendMail(order);
  res.json({ ok: true });
});

app.get("https://qrrp-ipew.onrender.com/api/orders/summary", auth, async (req, res) => {
  const d = await readData();
  const orders = d.orders || [];

  const summary = {};

  // group by item name
  for (const order of orders) {
    for (const item of order.items) {
      const name = item.name;
      if (!summary[name]) {
        summary[name] = {
          itemName: name,
          totalQty: 0,
          tables: new Set()
        };
      }
      summary[name].totalQty += item.qty;
      summary[name].tables.add(order.tableId);
    }
  }

  // convert Set → Array for JSON
  const result = Object.values(summary).map(s => ({
    itemName: s.itemName,
    totalQty: s.totalQty,
    tables: Array.from(s.tables)
  }));

  res.json({ ok: true, data: result });
});

// ---------- Socket.IO ----------
io.on("connection", s => {
  readData().then(d => s.emit("orders:update", d.orders));
});

app.get('/health', (req, res) => {
  res.status(200).json({ ok: true, time: Date.now() });
});

// ---------- Start ----------
server.listen(PORT, () => console.log(`✅ Running on http://localhost:${PORT}`));




