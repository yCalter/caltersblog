import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import postRoutes from "./routes/postRoutes.js";
import authRoutes from "./routes/authRoutes.js";

app.use(cors());

dotenv.config();

const app = express();
app.use(express.json());

app.get("/", (req, res) => {
  res.send(" Api sucesso. bem vindo!");
});

app.use("/api/auth", authRoutes);
app.use("/api/posts", postRoutes);

mongoose

  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("connected on mongodb!");
    app.listen(3000, () => console.log("server running at port 3000"));
  })
  .catch((err) => console.error("error mongol connect:", err));

export default app; // 
