// assets/script/server.js
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

// Middlewares
app.use(cors({
  origin: ["http://localhost:3000", "http://localhost:5500"],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Conexão com MongoDB
mongoose.connect("mongodb://127.0.0.1:27017/blog_db", {
  serverSelectionTimeoutMS: 30000
})
  .then(() => console.log("✅ Conectado ao MongoDB"))
  .catch(err => console.error("❌ Erro ao conectar ao MongoDB:", err));

mongoose.connection.on('connected', () => {
  console.log('✅ Mongoose conectado ao MongoDB');
});
mongoose.connection.on('error', (err) => {
  console.error('❌ Erro na conexão com o MongoDB:', err);
});
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ Mongoose desconectado do MongoDB');
});

// Schema e model
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: String
}, { timestamps: true });
const User = mongoose.model("User", userSchema);

// Middleware de autenticação
function authenticate(req, res, next) {
  const tokenFromCookie = req.cookies && req.cookies.token;
  const authHeader = req.headers.authorization;
  const tokenFromHeader = authHeader && authHeader.split(" ")[1];
  const token = tokenFromCookie || tokenFromHeader;

  if (!token) {
    return res.status(401).json({ erro: "Token ausente. Faça login primeiro!" });
  }

  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ erro: "Token inválido ou expirado!" });
  }
}

// Servir arquivos estáticos
const PUBLIC_DIR = path.join(__dirname, "..", "public");
app.use(express.static(PUBLIC_DIR));

// Página inicial
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// Registro
app.post("/registrar", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ erro: "Preencha todos os campos!" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ erro: "E-mail já registrado!" });

    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashed });
    await newUser.save();

    return res.json({ mensagem: "Usuário registrado com sucesso!" });
  } catch (err) {
    console.error(err);
    if (err.code === 11000) return res.status(400).json({ erro: "E-mail já registrado!" });
    return res.status(500).json({ erro: "Erro ao registrar usuário" });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ erro: "Preencha todos os campos!" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ erro: "Usuário não encontrado!" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ erro: "Senha incorreta!" });

    const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, SECRET, { expiresIn: "2h" });

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 2 * 60 * 60 * 1000
    });

    return res.json({
      mensagem: "Login realizado com sucesso!",
      token,
      redirect: "/willkommen"
    });
  } catch (err) {
    console.error("Erro no login:", err);
    return res.status(500).json({ erro: "Erro no login" });
  }
});

// Página protegida
app.get("/willkommen", authenticate, (req, res) => {
  return res.sendFile(path.join(PUBLIC_DIR, "willkommen.html"));
});

// Dados do usuário logado
app.get("/api/me", authenticate, (req, res) => {
  return res.json({ id: req.user.id, email: req.user.email, name: req.user.name });
});

// Logout
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ mensagem: "Logout realizado com sucesso!" });
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});
