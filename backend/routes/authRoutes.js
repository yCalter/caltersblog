import express from "express";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// Registro
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.create({ email, password });
    res.status(201).json({ message: "Usuário criado com sucesso", user });
  } catch (error) {
    res.status(400).json({ error: "Erro ao registrar usuário" });
  }
});

// Login
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "Usuário não encontrado" });

  const isMatch = await user.comparePassword(password);
  if (!isMatch) return res.status(400).json({ error: "Senha incorreta" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  res.json({ message: "Login bem-sucedido", token });
});

export default router;
