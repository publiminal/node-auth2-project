const router = require("express").Router();
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const db = require('../users/users-model')
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { findBy } = require('../users/users-model')
const { JWT_SECRET , BCRYPT_ROUNDS} = require("../secrets"); // use this secret!

function generateToken(user) {
  const payload = {
    subject:user.user_id, 
    username:user.username,
    role_name:user.role_name,
  }
  const options = { expiresIn: '1d' };
  return jwt.sign(payload, JWT_SECRET, options);
}


router.post("/register", validateRoleName, (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3, 
      "username": "anna",
      "role_name": "angel"
    }
   */
    let user = req.body
    // bcrypting the password before saving
    const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS)
    // never save the plain text password in the db
    user.password = hash
    console.log('user', user)
    db.add(user)
      .then(newUser => { res.status(201).json(newUser) })
      .catch(next) // our custom err handling middleware in server.js will trap this
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
    try {
      const {username, password} = req.body
      // validate username first
      const [user] = await findBy({username})  // return empty array if non exist user // it could be a middleware
      
      //if user exists tries find password otherwise return 
      if (user && bcrypt.compareSync(password, user.password)) {
          //user and pass are validated
         
         // THis is for session with cookies
         // console.log(req.session) // express-session enabled this obj.
         //req.session.user = user // a cookie will be set on the response at this point only. (action triggered by adding the user)
         //console.log('user in session', req.session) // express-session enabled this obj.

         //this is JWT
        //  console.log('user', user)
         const token = generateToken(user) 

          // res.status(200).json({ message: `You are now loged in  as ${username}`, token});
          res.status(200).json({ message:`${username} is back!`, token });
          // res.json(user)
      }else{
          next({status:401, message:'Invalid credentials'})
      }

  } catch (err) {
      next(err)
  }
});

module.exports = router;
