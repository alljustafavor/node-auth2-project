const router = require("express").Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET, BCRYPT_ROUNDS } = require("../secrets");

const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password, role_name } = req.body;
  const hash = bcrypt.hashSync(password, BCRYPT_ROUNDS);

  User.add({ username, password: hash, role_name })
    .then(saved => {
      res.status(201).json(saved[0]);
    })
    .catch(next);
});

router.post("/login", checkUsernameExists , (req, res, next) => {
  let { username, password } = req.body;

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({
          subject: user.user_id,
          username: user.username,
          role_name: user.role_name
        }, JWT_SECRET, { expiresIn: '1d' });

        res.status(200).json({
          message: `${user.username} is back`,
          token,
        })
      } else {
        next({ status: 401, message: "invalid credentials" });
      }
    })
    .catch(next);
});

module.exports = router;
