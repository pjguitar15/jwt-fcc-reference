const { verify } = require('jsonwebtoken')
const isAuth = (req) => {
  // grab data from header
  const authorization = req.headers['authorization']
  if (!authorization) return res.status(400).send('You need to log in')
  // Bearer sfgvodfnblrknblkdvuwvcdsvw123t345
  // take the index 1 use split method
  const token = authorization.split(' ')[1]
  const { userId } = verify(token, process.env.ACCESS_TOKEN_SECRET)
  return userId
}
module.exports = { isAuth }