const jwt = require("jsonwebtoken");

const User = require('../users/users-model');
const { JWT_SECRET } = require("../secrets");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: "token invalid"});
      } else {
        req.decodedJwt = decoded;
        next();
      }
    })
  } else {
    next({ status: 401, message: "token required" });
  }
}

const only = role_name => (req, res, next) => {
  if (req.decodedJwt.role_name === role_name) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" });
  }
};


const checkUsernameExists = async (req, res, next) => {
  const { username } = req.body;
  
  try {
    const user = await User.findBy({ username });
    if (user && user.length > 0) {
      next();
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (error) {
    next(error);
  }
}

const validateRoleName = (req, res, next) => {
  let { role_name } = req.body;
  
  if (role_name === undefined || role_name.trim() === '') {
    role_name = 'student';
  } else {
    role_name = role_name.trim();
  }

  if (role_name === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  } else if (role_name.length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  } else {
    req.body.role_name = role_name;
    next();
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
