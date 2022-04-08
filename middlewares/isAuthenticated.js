const jwt = require("express-jwt");

function extractTokenFromHeaders(req, res) {
  if (!req.headers.authorization) {
    console.error("Missing Auth Header");
    return res.status(400).json({ msg: "Missing Auth Header" });
  }

  return req.headers.authorization.split(" ")[1];
}

module.exports = jwt({
  secret: process.env.TOKEN_SIGN_SECRET,
  userProperty: "user",
  getToken: extractTokenFromHeaders,
  algorithms: ["HS256"],
});
