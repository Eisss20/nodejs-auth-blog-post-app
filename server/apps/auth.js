import { Router } from "express";
import { db } from "../utils/db.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

const authRouter = Router();

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้
authRouter.post("/register", async (req, res) => {
  try {
    const user = {
      username: req.body.username,
      password: req.body.password,
      firstName: req.body.firstname,
      lastName: req.body.lastname,
    };

    const salt = await bcrypt.genSalt(10);

    user.password = await bcrypt.hash(user.password, salt);

    const collection = db.collection("users");
    await collection.insertOne(user);

    return res.status(201).json({
      message: "User has been created successfully",
    });
  } catch (e) {
    return res.status(500).json({
      message: `Status : 500 ${e.message}`,
    });
  }
});

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้
authRouter.post("/login", async (req, res) => {
  try {
    const user = await db.collection("users").findOne({
      username: req.body.username,
    });

    if (!user) {
      return res.status(404).json({
        message: "user not found",
      });
    }

    const isValidPassword = await bcrypt.compare(
      req.body.password,
      user.password
    );

    if (!isValidPassword) {
      return res.status(401).json({
        message: "password is not valid",
      });
    }

    // Create Token
    const token = jwt.sign(
      {
        id: user._id,
        firstname: user.firstName,
        lastname: user.lastName,
      },
      process.env.SECRET_KEY,
      {
        expiresIn: "900000",
      }
    );

    return res.json({
      message: "login successfully",
      token,
    });
  } catch (e) {
    return res.status(500).json({
      message: `Status : 500 ${e.message}`,
    });
  }
});

export default authRouter;
