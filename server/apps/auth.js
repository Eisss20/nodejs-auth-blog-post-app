import { Router } from "express";
import { db } from "../utils/db.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcrypt"

const authRouter = Router();

//api register 

// 🐨 Todo: Exercise #1
// ให้สร้าง API เพื่อเอาไว้ Register ตัว User แล้วเก็บข้อมูลไว้ใน Database ตามตารางที่ออกแบบไว้

authRouter.post("/register", async (req, res) => {
    try {
      const user = {
        username: req.body.username,
        password: req.body.password,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
      };
  
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(user.password, salt);
  
      const collection = db.collection("users");
      await collection.insertOne(user);
  
      return res.status(200).json({
        message: "User has been created successfully",
      });
    } catch (error) {
      return res.status(400).json({
        message: "User can't create a registration. ${error.message}",
      });
    }
  });

// 🐨 Todo: Exercise #3
// ให้สร้าง API เพื่อเอาไว้ Login ตัว User ตามตารางที่ออกแบบไว้

authRouter.post("/login", async (req, res) => {
  try {
    const collection = db.collection("users");

    const userLogin = await collection.findOne({ username: req.body.username });

    if (!userLogin) {
      return res.status(404).json({
        message: "User not found",
      });
    }

    const validateUserandPassword = await bcrypt.compare(
      req.body.password, //input
      userLogin.password // database
    );

    if (!validateUserandPassword) {
      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    const token = jwt.sign( ///นำมา gen token 
      { /// ข้อมูลที่ต้องการเก็บใน token 
        id: userLogin._id, 
        firstName: userLogin.firstName,
        lastName: userLogin.lastName,
      },
      process.env.SECRET_KEY, 
      {
        expiresIn: "15m", 
      }
    );
  
    return res.status(200).json({
      message: "Login successfully",
      token: token, 
    });

  } catch (error) {
    return res.status(400).json({
      message: "An error occurred during login.",
    });
  }


});


export default authRouter;
