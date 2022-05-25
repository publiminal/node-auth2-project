const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require("../secrets"); // use this secret!
const db = require('../users/users-model')

const restricted = async (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header:
    status 401
    {
      "message": "Token required"
    }

    If the provided token does not verify:
    status 401
    {
      "message": "Token invalid"
    }

    Put the decoded token in the req object, to make life easier for middlewares downstream!
  */

    // the server expect to find the toekn in authorization header.
    const token = req.headers.authorization

    if(token == null) {
      next({ status: 401, message: 'Token required' });
      return;
    }
  
    try {
      req.decodedJwt = await jwt.verify(token, JWT_SECRET);
      let user = await db.findById(req.decodedJwt.subject);
      if(req.decodedJwt.iat < user.logout_time) {
        next({ status: 401, message: 'Token invalid' });
        return;
      }
    } catch(err) {
      console.log('login err >>> ', err.message)
      next({ status: 401, message: 'Token invalid' });
      return;
    }

    next()
}

const only = role_name => (req, res, next) => {
  /*
    If the user does not provide a token in the Authorization header with a role_name
    inside its payload matching the role_name passed to this function as its argument:
    status 403
    {
      "message": "This is not for you"
    }

    Pull the decoded token from the req object, to avoid verifying it again!
  */
    if(req.decodedJwt.role_name === role_name){
      next()
    }else{
      next({status:403, message:'This is not for you'})
    }
}


const checkUsernameExists = (req, res, next) => {
  /*
    If the username in req.body does NOT exist in the database
    status 401
    {
      "message": "Invalid credentials"
    }
  */
    const {username} = req.body
    if(username == null){ res.status(401).json( {message:"Invalid credentials"} ); return; }

    next()
}


const validateRoleName = (req, res, next) => {
  /*
    If the role_name in the body is valid, set req.role_name to be the trimmed string and proceed.

    If role_name is missing from req.body, or if after trimming it is just an empty string,
    set req.role_name to be 'student' and allow the request to proceed.

    If role_name is 'admin' after trimming the string:
    status 422
    {
      "message": "Role name can not be admin"
    }

    If role_name is over 32 characters after trimming the string:
    status 422
    {
      "message": "Role name can not be longer than 32 chars"
    }
  */
 next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
