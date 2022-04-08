const UserModel = require("../models/User.model");

module.exports = async (req, res, next) => {
  try {
    const loggedInUser = req.user;

    const user = await UserModel.findOne(
      { _id: loggedInUser._id },
      { passwordHash: 0 } 
    );

    if (!user) {
      return res.status(400).json({ msg: "User does not exist." });
    }

    req.currentUser = user;
    return next();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ msg: JSON.stringify(err) });
  }
};
