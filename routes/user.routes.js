const router = require("express").Router();
const bcrypt = require("bcryptjs");

const UserModel = require("../models/User.model");
const generateToken = require("../config/jwt.config");
const isAuthenticated = require("../middlewares/isAuthenticated");
const attachCurrentUser = require("../middlewares/attachCurrentUser");

const salt_rounds = 10;

router.post("/signup", async (req, res) => {
  console.log(req.body);

  try {
    const { password } = req.body;

    if (
      !password ||
      !password.match(
        /^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$ %^&*-]).{8,}$/
      )
    ) {
      return res.status(400).json({
        msg: "Password is required and must have at least 8 characters, uppercase and lowercase letters, numbers and special characters.",
      });
    }

    const salt = await bcrypt.genSalt(salt_rounds);

    const hashedPassword = await bcrypt.hash(password, salt);

    const result = await UserModel.create({
      ...req.body,
      passwordHash: hashedPassword,
    });

    return res.status(201).json(result);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await UserModel.findOne({ email });

    console.log(user);

    if (!user) {
      return res
        .status(400)
        .json({ msg: "This email is not yet registered in our website;" });
    }

    if (await bcrypt.compare(password, user.passwordHash)) {
      const token = generateToken(user);

      return res.status(200).json({
        user: {
          name: user.name,
          email: user.email,
          _id: user._id,
          role: user.role,
        },
        token,
      });
    } else {
      return res.status(401).json({ msg: "Wrong password or email" });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

router.get("/profile", isAuthenticated, attachCurrentUser, (req, res) => {
  console.log(req.headers);

  try {
    const loggedInUser = req.currentUser;

    if (loggedInUser) {
      return res.status(200).json(loggedInUser);
    } else {
      return res.status(404).json({ msg: "User not found." });
    }
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
});

router.patch(
  "/update",
  isAuthenticated,
  attachCurrentUser,
  async (req, res) => {
    try {
      const loggedInUser = req.currentUser;

      const updatedUser = await UserModel.findOneAndUpdate(
        { _id: loggedInUser._id },
        { ...req.body },
        { new: true, runValidators: true }
      );
      return res.status(200).json(updatedUser);
    } catch (err) {
      console.log(err);
      if (err.code === 11000) {
        return res.status(400).json(err.message ? err.message : err);
      }
      res.status(500).json(err);
    }
  }
);

router.delete(
  "/disable-account",
  isAuthenticated,
  attachCurrentUser,
  async (req, res) => {
    try {
      const loggedInUser = req.currentUser;
      console.log(loggedInUser)
      const deletedUser = await UserModel.deleteOne({
        _id: loggedInUser._id,
      });
      return res.status(200).json(deletedUser);
    } catch (err) {
      console.log(err);
      return res.status(500).json({ ...error });
    }
  }
);

module.exports = router;
