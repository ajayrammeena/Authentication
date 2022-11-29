import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import transporter from "../config/emailConfig.js";

class UserController {
  static userRegistration = async (req, res) => {
    const name = String(req.body.name);
    const email = String(req.body.email);
    const password = String(req.body.password);
    const password_confirmation = String(req.body.password_confirmation);

    const user = await UserModel.findOne({ email: email });

    if (user) {
      res.send({ status: "failed", message: "Email is already exist" });
    } else {
      if (
        name !== "" &&
        email !== "" &&
        password !== "" &&
        password_confirmation !== ""
      ) {
        if (password === password_confirmation) {
          const salt = await bcrypt.genSalt(10);
          const hashPassword = await bcrypt.hash(password, salt);
          try {
            const doc = new UserModel({
              name: name,
              email: email,
              password: hashPassword,
            });
            await doc.save();
            const saved_user = await UserModel.findOne({ email: email });
            //Generate JWT Token
            const token = jwt.sign(
              { userID: saved_user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );
            res.status(201).send({
              status: "Success",
              message: "Registration sucess",
              token: token,
            });
          } catch (error) {
            res.send({ status: "failed", message: "Unable to register" });
          }
        } else {
          res.send({
            status: "failed",
            message: { password, password_confirmation },
          });
        }
      } else {
        res.send({
          status: "failed",
          message: req.body.name,
        });
      }
    }
  };

  static userLogin = async (req, res) => {
    try {
      const name = String(req.body.name);
      const password = String(req.body.password);
      if (name && password) {
        const user = await UserModel.findOne({ name: name });
        if (user != null) {
          const isMatch = await bcrypt.compare(password, user.password);
          if (user.name === name && isMatch) {
            //Generate JWT Token
            const token = jwt.sign(
              { userID: user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );
            res.send({
              status: "Success",
              message: "Login sucess",
              token: token,
            });
          } else {
            res.send({
              status: "failed",
              message: "Username or password is not Match",
            });
          }
        } else {
          res.send({
            status: "failed",
            message: "You are not a register user",
          });
        }
      } else {
        res.send({ status: "failed", message: "All fileds are required" });
      }
    } catch (error) {
      console.log(error);
      res.send({ status: "failed", message: "unable to login" });
    }
  };

  static changeUserPassword = async (req, res) => {
    const { password, password_confirmation } = req.body;
    if (password && password_confirmation) {
      if (password !== password_confirmation) {
        res.send({
          status: "failed",
          message: "New Password and Confirm New Password doesn't match",
        });
      } else {
        const salt = await bcrypt.genSalt(10);
        const newHashPassword = await bcrypt.hash(password, salt);
        await UserModel.findByIdAndUpdate(req.user._id, {
          $set: { password: newHashPassword },
        });
        res.send({
          status: "success",
          message: "Password changed succesfully",
        });
      }
    } else {
      res.send({ status: "failed", message: "All Fields are Required" });
    }
  };

  static loggedUser = async (req, res) => {
    res.send({ user: req.user });
  };

  static sendUserPasswordResetEmail = async (req, res) => {
    const email = String(req.body.email);
    if (email) {
      const user = await UserModel.findOne({ email: email });
      if (user) {
        const secret = user._id + process.env.JWT_SECRET_KEY;
        const token = jwt.sign({ userID: user._id }, secret, {
          expiresIn: "15m",
        });
        const link = `http://127.0.0.1:3000/api/user/reset/${user._id}/${token}`;
        console.log(link);
        // // Send Email
        let info = await transporter.sendMail({
          from: process.env.EMAIL_FROM,
          to: user.email,
          subject: "GeekShop - Password Reset Link",
          html: `<a href=${link}>Click Here</a> to Reset Your Password`,
        });
        res.send({
          status: "success",
          message: "Password Reset Email Sent... Please Check Your Email",
        });
      } else {
        res.send({ status: "failed", message: "Email doesn't exists" });
      }
    } else {
      res.send({ status: "failed", message: "Email Field is Required" });
    }
  };

  static userPasswordReset = async (req, res) => {
    const { password, password_confirmation } = req.body;
    const { id, token } = req.params;
    const user = await UserModel.findById(id);
    const new_secret = user._id + process.env.JWT_SECRET_KEY;
    try {
      jwt.verify(token, new_secret);
      if (password && password_confirmation) {
        if (password !== password_confirmation) {
          res.send({
            status: "failed",
            message: "New Password and Confirm New Password doesn't match",
          });
        } else {
          const salt = await bcrypt.genSalt(10);
          const newHashPassword = await bcrypt.hash(password, salt);
          await UserModel.findByIdAndUpdate(user._id, {
            $set: { password: newHashPassword },
          });
          res.send({
            status: "success",
            message: "Password Reset Successfully",
          });
        }
      } else {
        res.send({ status: "failed", message: "All Fields are Required" });
      }
    } catch (error) {
      console.log(error);
      res.send({ status: "failed", message: "Invalid Token" });
    }
  };
}

export default UserController;
