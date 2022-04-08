const jwt = require("jsonwebtoken");

module.exports = function generateToken(user) {
  const { _id, name, email, role } = user;

  const signature = process.env.TOKEN_SIGN_SECRET;
  const expiration = "6h";

  return jwt.sign({ _id, name, email, role }, signature, {
    expiresIn: expiration,
  });
};
