// script/server.js
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = 3000;
const SECRET = process.env.JWT_SECRET || "seu_segredo_super_seguro";

// ===== MIDDLEWARES =====
app.use(cors({
  origin: ["http://localhost:3000", "http://localhost:5500"],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ===== CONEXÃO MONGO =====
mongoose.connect("mongodb://127.0.0.1:27017/blog_db", {
  serverSelectionTimeoutMS: 30000
})
  .then(() => console.log("✅ Conectado ao MongoDB"))
  .catch(err => console.error("❌ Erro ao conectar ao MongoDB:", err));

// ===== SCHEMAS =====
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: String
}, { timestamps: true });

const postSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User" }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);
const Post = mongoose.model("Post", postSchema);

// ===== AUTENTICAÇÃO =====
function authenticate(req, res, next) {
  const tokenFromCookie = req.cookies?.token;
  const authHeader = req.headers.authorization;
  const tokenFromHeader = authHeader && authHeader.split(" ")[1];
  const token = tokenFromCookie || tokenFromHeader;

  if (!token) return res.status(401).json({ erro: "Token ausente. Faça login primeiro!" });

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(403).json({ erro: "Token inválido ou expirado!" });
  }
}

// ===== SERVIR FRONT =====
const PUBLIC_DIR = path.join(__dirname, "..", "public");
app.use(express.static(PUBLIC_DIR));

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ===== AUTH =====
app.post("/registrar", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ erro: "Preencha todos os campos!" });

  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ erro: "E-mail já registrado!" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = new User({ name, email, password: hashed });
  await newUser.save();

  res.json({ mensagem: "Usuário registrado com sucesso!" });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ erro: "Usuário não encontrado!" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ erro: "Senha incorreta!" });

  const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, SECRET, { expiresIn: "2h" });

  res.cookie("token", token, {
    httpOnly: true,
    sameSite: "lax",
    maxAge: 2 * 60 * 60 * 1000
  });

  res.json({ mensagem: "Login realizado com sucesso!", token, redirect: "/willkommen.html" });
});

app.get("/willkommen", authenticate, (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "willkommen.html"));
});

app.get("/api/me", authenticate, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, name: req.user.name });
});

app.post("/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ mensagem: "Logout realizado com sucesso!" });
});

// ===== POSTS =====
app.post("/api/posts", authenticate, async (req, res) => {
  const { title, content } = req.body;
  if (!title || !content)
    return res.status(400).json({ erro: "Preencha título e conteúdo" });

  const post = new Post({ title, content, author: req.user.id });
  await post.save();

  res.json({ mensagem: "Post criado com sucesso!", post });
});

app.get("/api/posts", async (req, res) => {
  const posts = await Post.find().populate("author", "name").sort({ createdAt: -1 });
  res.json(posts);
});

app.delete("/api/posts/:id", authenticate, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ erro: "Post não encontrado" });
  if (post.author.toString() !== req.user.id)
    return res.status(403).json({ erro: "Sem permissão para deletar" });

  await post.deleteOne();
  res.json({ mensagem: "Post deletado com sucesso!" });
});

// ===== START =====
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});
