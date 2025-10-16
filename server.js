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
import csrf from "csrf"; // Fixed: Replace csurf with csrf
import { v4 as uuidv4 } from "uuid";

dotenv.config();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.resolve("./data.json");
const PUBLIC_DIR = path.resolve("./"); // Serve current folder

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

// ---------- Utility ----------
async function readData() {
  try {
    const raw = await fs.readFile(DATA_FILE, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code === 'ENOENT') {  // Fixed: Handle if file not exist
      const defaultData = {
        admins: [{ 
          username: process.env.ADMIN_USERNAME || 'admin', 
          passwordHash: bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10) 
        }],
        tables: [],
        orders: []
      };
      await writeData(defaultData);  // Create file with default
      return defaultData;
    }
    console.error('ReadData Error:', err); // Fixed: Log error
    throw err;  // Other errors
  }
}
async function writeData(data) {
  try {
    await fs.writeFile(DATA_FILE, JSON.stringify(data, null, 2), "utf8");
  } catch (err) {
    console.error('WriteData Error:', err); // Fixed: Log error
  }
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
  try {
    const d = await readData();
    if (!d.admins || d.admins.length === 0) { // Fixed: Handle admins array
      d.admins = [{ username: process.env.ADMIN_USERNAME || 'admin' }];
    }
    const admin = d.admins[0];
    if (!admin.passwordHash) {
      admin.passwordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || 'admin123', 10);
    }
    for (let t of d.tables) {
      if (!t.pinHash) {
        t.pinHash = bcrypt.hashSync(t.pinPlain || "1234", 10);
      }
    }
    await writeData(d);
  } catch (err) {
    console.error('Init Error:', err); // Fixed: Log error
  }
}
await init();

// ---------- API ----------
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const d = await readData();
    const admin = d.admins ? d.admins.find(a => a.username === username) : null; // Fixed: Use admins array
    if (!admin) return res.status(401).json({ ok: false, msg: 'Invalid username' });
    if (!bcrypt.compareSync(password, admin.passwordHash))
      return res.status(401).json({ ok: false, msg: 'Invalid password' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "8h" });
    res.cookie("session", token, { httpOnly: true, sameSite: "lax" });
    res.json({ ok: true });
  } catch (err) {
    console.error('Login Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.get("/api/auth/me", (req, res) => {
  try {
    const decoded = jwt.verify(req.cookies.session, JWT_SECRET);
    res.json({ ok: true, user: decoded, sessionExpiry: decoded.exp * 1000 });
  } catch {
    res.status(401).json({ ok: false, msg: "Invalid or expired session" });
  }
});

app.post("/api/admin/generate-qr", auth, csrfProtection, async (req, res) => {
  try {
    const { tableId } = req.body;
    const token = signQr({ tableId });
    const qrUrl = `${req.protocol}://${req.get("host")}/index.html?token=${encodeURIComponent(token)}`;
    res.json({ ok: true, qrUrl });
  } catch (err) {
    console.error('QR Generate Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post("/api/validate-location", async (req, res) => {
  try {
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

    const allowed = distance <= parseFloat(process.env.RESTAURANT_RADIUS_METERS || 300);
    res.json({
      ok: allowed,
      inside: allowed,
      distance: Math.round(distance),
      msg: allowed
        ? "Inside restaurant radius"
        : "Outside restaurant area, cannot place order"
    });
  } catch (err) {
    console.error('Location Validate Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post("/api/validate-pin", async (req, res) => {
  try {
    const { token, tableId, pin } = req.body;
    const payload = verifyQr(token);
    if (!payload) return res.json({ ok: false });
    const d = await readData();
    const t = d.tables.find(x => x.id == tableId);
    if (!t) return res.json({ ok: false, msg: 'Table not found' });
    res.json({ ok: bcrypt.compareSync(pin, t.pinHash) });
  } catch (err) {
    console.error('Pin Validate Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.post("/api/orders/create", limiter, async (req, res) => {
  try {
    const { token, tableId, items } = req.body; // Fixed: items instead of items
    const payload = verifyQr(token);
    if (!payload) return res.status(401).json({ ok: false });
    const d = await readData();
    const order = { id: uuidv4(), tableId, items, createdAt: new Date().toISOString() };
    d.orders.push(order);
    await writeData(d);
    io.emit("orders:update", d.orders);
    sendMail(order);
    res.json({ ok: true });
  } catch (err) {
    console.error('Order Create Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
});

app.get("/api/orders/summary", auth, async (req, res) => {
  try {
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
  } catch (err) {
    console.error('Orders Summary Error:', err); // Fixed: Log error
    res.status(500).json({ ok: false, msg: 'Server error' });
  }
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
