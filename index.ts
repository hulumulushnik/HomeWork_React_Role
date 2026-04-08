import express, { Request, Response } from "express";
import mysql from "mysql2/promise";
import cors from "cors";
import { RowDataPacket, ResultSetHeader } from "mysql2";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

// --------------------
// Тип студента
// --------------------
interface Student extends RowDataPacket {
  id: number;
  firstName: string;
  lastName: string;
  email: string;
  password: string;
  age: number;
  role: string;
}

// --------------------
// Конфігурація MySQL
// --------------------
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "123456789",
  database: "StudentDB",
  waitForConnections: true,
  connectionLimit: 10,
});

// --------------------
const app = express();
app.use(cors());
app.use(express.json());
const JWT_SECRET = "X7VOSROU5FS6DT0GJ9NWCV1IPZA8BL"; // у реальному проєкті в .env
// Генерація JWT
function generateToken(user: any) {
  return jwt.sign(
    {
      id: user.Id,
      email: user.Email,
      role: user.Role,
    },
    JWT_SECRET,
    { expiresIn: "1h" },
  );
}
//Перевірка валідності токена
function authMiddleware(req: any, res: any, next: any) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).send("No token");
  }

  const token = authHeader.split(" ")[1];

  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    return res.status(403).send("Invalid token");
  }
}
//Register user
app.post("/auth/register", async (req, res) => {
  try {
    const { firstName, lastName, email, age, password, role } = req.body;

    // Хешування пароля
    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await pool.query<ResultSetHeader>(
      "INSERT INTO Students (firstName, lastName, email, password, age, role) VALUES (?, ?, ?, ?, ?, ?)",
      [firstName, lastName, email, hashedPassword, age, role],
    );

    const [rows] = await pool.query<Student[]>(
      "SELECT * FROM Students WHERE Id = ?",
      [result.insertId],
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json(err);
  }
});

//Auth/Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const [rows] = await pool.query<Student[]>(
      "SELECT * FROM students WHERE email = ?",
      [email],
    );

    const student = rows[0];

    if (!student) {
      return res.status(404).send("User not found");
    }

    const isValid = await bcrypt.compare(password, student.password);

    if (!isValid) {
      return res.status(400).send("Wrong password");
    }

    const token = generateToken(student);

    res.json({ token });
  } catch (err) {
    res.status(500).json(err);
  }
});

// --------------------
// Тест підключення
// --------------------
async function testDB() {
  try {
    const [rows] = await pool.query<RowDataPacket[]>("SELECT 1");
    console.log("MySQL connected ✅", rows);
  } catch (err) {
    console.error("MySQL error ❌", err);
  }
}
testDB();

/*******************************************************************************************
 * GET ALL STUDENTS
 *******************************************************************************************/
app.get("/students", async (req: Request, res: Response) => {
  try {
    const [rows] = await pool.query<Student[]>("SELECT * FROM Students");
    res.json(rows);
  } catch (err) {
    res.status(500).json(err);
  }
});

/*******************************************************************************************
 * GET STUDENT BY ID
 *******************************************************************************************/
app.get("/students/:id", async (req: Request, res: Response) => {
  try {
    const [rows] = await pool.query<Student[]>(
      "SELECT * FROM Students WHERE Id = ?",
      [req.params.id],
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json(err);
  }
});

/*******************************************************************************************
 * CREATE STUDENT
 *******************************************************************************************/
app.post("/students", async (req: Request, res: Response) => {
  try {
    const { firstName, lastName, email, age } = req.body;

    const [result] = await pool.query<ResultSetHeader>(
      "INSERT INTO Students (FirstName, LastName, Email, Age) VALUES (?, ?, ?, ?)",
      [firstName, lastName, email, age],
    );

    const [rows] = await pool.query<Student[]>(
      "SELECT * FROM Students WHERE Id = ?",
      [result.insertId],
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json(err);
  }
});

/*******************************************************************************************
 * UPDATE STUDENT
 *******************************************************************************************/
app.put("/students/:id", async (req: Request, res: Response) => {
  try {
    const { firstName, lastName, email, age } = req.body;

    const [result] = await pool.query<ResultSetHeader>(
      `UPDATE Students 
       SET FirstName=?, LastName=?, Email=?, Age=? 
       WHERE Id=?`,
      [firstName, lastName, email, age, req.params.id],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Student not found" });
    }

    const [rows] = await pool.query<Student[]>(
      "SELECT * FROM Students WHERE Id = ?",
      [req.params.id],
    );

    res.json(rows[0]);
  } catch (err) {
    res.status(500).json(err);
  }
});

/*******************************************************************************************
 * DELETE STUDENT
 *******************************************************************************************/
app.delete("/students/:id", async (req: Request, res: Response) => {
  try {
    const [result] = await pool.query<ResultSetHeader>(
      "DELETE FROM Students WHERE Id = ?",
      [req.params.id],
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Student not found" });
    }

    res.sendStatus(204);
  } catch (err) {
    res.status(500).json(err);
  }
});

// --------------------
// Запуск сервера
// --------------------
app.listen(3001, () => {
  console.log("Server running on http://localhost:3001");
});
