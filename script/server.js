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
  origin: ["http://localhost:3000", "http://localhost:5500"], // Adicionei uma origem extra comum para Live Server; ajuste se necessário
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Conexão com MongoDB (removidas opções obsoletas e adicionado timeout maior)
mongoose.connect("mongodb://127.0.0.1:27017/blog_db", {
  serverSelectionTimeoutMS: 30000 // Aumenta o timeout para 30 segundos
})
  .then(() => console.log("✅ Conectado ao MongoDB"))
  .catch(err => console.error("❌ Erro ao conectar ao MongoDB:", err));

// Logs adicionais para depuração da conexão
mongoose.connection.on('connected', () => {
  console.log('✅ Mongoose conectado ao MongoDB');
});
mongoose.connection.on('error', (err) => {
  console.error('❌ Erro na conexão com o MongoDB:', err);
});
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ Mongoose desconectado do MongoDB');
});

// --- Schema e model ---
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true, required: true },
  password: String
}, { timestamps: true });
const User = mongoose.model("User", userSchema);

// --- Middleware de autenticação com JWT (verifica cookie ou header) ---
function authenticate(req, res, next) {
  // 1) tenta cookie
  const tokenFromCookie = req.cookies && req.cookies.token;
  // 2) tenta header Authorization
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

// --- Servir arquivos estáticos PUBLIC (CSS, JS, imagens, index, login, registrar) ---
// public root é a pasta "assets" (um nível acima de __dirname)
const PUBLIC_DIR = path.join(__dirname, ".."); // points to .../assets
app.use("/assets", express.static(PUBLIC_DIR, {
  index: false,
  extensions: ["html", "css", "js"]
}));

// --- Rota inicial (página index na pasta assets) ---
app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// --- API: registrar ---
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

// --- API: login ---
// Ao logar: cria token, envia em JSON e também seta cookie httpOnly para navegações normais
app.post("/login", async (req, res) => {
  console.log("Requisição recebida em /login:", req.body);
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      console.log("Campos incompletos:", { email, password });
      return res.status(400).json({ erro: "Preencha todos os campos!" });
    }

    console.log("Buscando usuário com email:", email);
    const user = await User.findOne({ email });
    console.log("Resultado da busca:", user);
    if (!user) {
      console.log("Usuário não encontrado para email:", email);
      return res.status(400).json({ erro: "Usuário não encontrado!" });
    }

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      console.log("Senha incorreta para email:", email);
      return res.status(400).json({ erro: "Senha incorreta!" });
    }

    // Cria token JWT
    const token = jwt.sign({ id: user._id, email: user.email, name: user.name }, SECRET, { expiresIn: "2h" });
    console.log("Token gerado para usuário:", email);

    // Seta cookie seguro (httpOnly) para ser enviado automaticamente em navegações
    // Em dev, 'secure' deve ser false se não usar HTTPS
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,   // em produção com HTTPS => true
      sameSite: "lax",
      maxAge: 2 * 60 * 60 * 1000 // 2 horas
    });

    return res.json({
      mensagem: "Login realizado com sucesso!",
      token,                         // opcional (frontend pode usar localStorage também)
      redirect: "/willkommen"
    });
  } catch (err) {
    console.error("Erro no login:", err);
    return res.status(500).json({ erro: "Erro no login" });
  }
});

// --- Rota protegida: /willkommen (arquivo protegido, fora da pasta pública) ---
// IMPORTANTE: mova 'willkommen.html' para a raiz do projeto (um nível acima de assets)
app.get("/willkommen", authenticate, (req, res) => {
  // envia o HTML protegido que está em: LEASON2/willkommen.html
  return res.sendFile(path.join(__dirname, "..", "willkommen.html"));
});

// --- API para checar token (opcional, útil no front-end) ---
app.get("/api/me", authenticate, (req, res) => {
  // Retorna dados básicos do usuário (sem expor senha)
  return res.json({ id: req.user.id, email: req.user.email, name: req.user.name });
});

// --- Logout (limpa cookie) ---
app.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ mensagem: "Logout realizado com sucesso!" });
});

// --- Inicia o servidor ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});