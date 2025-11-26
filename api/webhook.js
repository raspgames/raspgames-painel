import pkg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const { Pool } = pkg;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

export default async function handler(req, res) {
  if (req.method !== "POST")
    return res.status(405).json({ error: "Method not allowed" });

  let body = req.body;

  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch (e) {
      return res.status(400).json({ error: "Invalid JSON" });
    }
  }

  const { email, password } = body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0)
      return res.status(401).json({ error: "Usuário ou senha inválidos" });

    const user = result.rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok)
      return res.status(401).json({ error: "Usuário ou senha inválidos" });

    const token = jwt.sign(
      { id: user.id, role: user.role, name: user.name },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, name: user.name, role: user.role });
  } catch (err) {
    console.error("Erro login:", err);
    res.status(500).json({ error: "Erro no servidor" });
  }
}
