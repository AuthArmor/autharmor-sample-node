const JWT = require("jsonwebtoken");

const generateAccessToken = data => {
  return JWT.sign(data, process.env.SECRET, { expiresIn: "1800s" });
};

const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) return res.sendStatus(401);

  JWT.verify(token, process.env.SECRET, (err, user) => {
    console.log(err);

    if (err) return res.sendStatus(403);

    req.user = user;

    next();
  });
};

module.exports = {
  generateAccessToken,
  verifyToken
};
