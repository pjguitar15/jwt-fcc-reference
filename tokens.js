const { sign } = require('jsonwebtoken')
const createAccessToken = userId => {
  // creates a token/long encrypted string
  return sign({ userId }, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: '15m'
  })
}
const createRefreshToken = userId => {
  // creates a token/long encrypted string
  return sign({ userId }, process.env.REFRESH_TOKEN_SECRET, {
    expiresIn: '7d'
  })
}

// handles send token
const sendAccessToken = (req, res, accesstoken) => {
  res.status(200).send({
    accesstoken,
    email: req.body.email
  })
}
// idk why it doesn't have req as param
const sendRefreshToken = (res, refreshtoken) => {
  // this is a secret. string needs to be more secured
  res.cookie('refreshtoken', refreshtoken, {
    httpOnly: true, // disable client access to this cookie
    path: '/refresh_token', // not sure about this
  })
}

module.exports = { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken }