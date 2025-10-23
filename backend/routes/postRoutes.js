import express from "express";
import Post from "../models/Post.js";
import { authMiddleware } from "../middleware/authMiddleware.js";

const router = express.Router();

// Criar post
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { title, content } = req.body;
    const post = await Post.create({ title, content, author: req.user.id });
    res.status(201).json(post);
  } catch {
    res.status(500).json({ error: "Erro ao criar post" });
  }
});

// Listar todos os posts
router.get("/", async (req, res) => {
  const posts = await Post.find().populate("author", "email");
  res.json(posts);
});

// Ver post específico
router.get("/:id", async (req, res) => {
  const post = await Post.findById(req.params.id).populate("author", "email");
  if (!post) return res.status(404).json({ error: "Post não encontrado" });
  res.json(post);
});

// Atualizar post
router.put("/:id", authMiddleware, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: "Post não encontrado" });

  if (post.author.toString() !== req.user.id)
    return res.status(403).json({ error: "Acesso negado" });

  post.title = req.body.title || post.title;
  post.content = req.body.content || post.content;
  await post.save();
  res.json(post);
});

// Deletar post
router.delete("/:id", authMiddleware, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: "Post não encontrado" });

  if (post.author.toString() !== req.user.id)
    return res.status(403).json({ error: "Acesso negado" });

  await post.deleteOne();
  res.json({ message: "Post deletado com sucesso" });
});

export default router;
