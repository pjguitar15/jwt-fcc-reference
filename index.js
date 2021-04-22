require('dotenv/config') // not sure about the difference
const express = require('express')
const cookieParser = require('cookie-parser')
const cors = require('cors')
const { verify } = require('jsonwebtoken')
const { hash, compare } = require('bcryptjs')
const { fakeDB } = require('./fakeDB')
const { createAccessToken, createRefreshToken, sendAccessToken, sendRefreshToken } = require('./tokens')
const { isAuth } = require('./isAuth')
// 1. Register a user
// 2. Login a user
// 3. Logout a user
// 4. Setup a protected route
// 5. Get a new access token with a refresh token

const app = express()

// for easier cookie handling
app.use(cookieParser())
app.use(cors())

// to read body data
app.use(express.json())
// supports url-encoded bodies
app.use(express.urlencoded({ extended: true }))


// 1. Register User
app.post('/register', async (req, res) => {
  const { email, password } = req.body
  try {
    // 1. Check if user exists from fake DB
    const user = fakeDB.find(user => user.email === email)

    // 2. return error if user exist
    if (user) return res.status(401).send('Email already exist')

    // 3. hash password for fake db
    const hashedPassword = await hash(password, 10)

    // 4. Insert the user in "database"
    fakeDB.push({
      id: fakeDB.length,
      email,
      password: hashedPassword
    })
    // 5. send message on success
    res.send('User created')
    console.log(fakeDB)
  } catch (error) {
    res.status(400).send(error)
  }
})
// 2. Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  try {
    // 1. Find user in array. If not exist, error
    const user = fakeDB.find(user => user.email === email)
    if (!user) return res.status(401).send('User does not exist')
    // 2. Compare crypted password and see if it checks out
    const valid = await compare(password, user.password) // compare from bcrypt
    if (!valid) return res.status(401).send('Invalid password')
    // 3. On login success, create refresh and access token
    const accesstoken = createAccessToken(user.id)
    const refreshtoken = createRefreshToken(user.id)
    // for simplicity, there's no revoke refresh tokens.
    // learn from here https://fusionauth.io/learn/expert-advice/tokens/revoking-jwts/

    // 4. Put the refreshtoken in the "database"
    user.refreshtoken = refreshtoken //creates a key with the token value
    console.log(fakeDB)

    // 5. Send token. RefreshToken as a cookie and AccessToken as a regular response
    sendRefreshToken(res, refreshtoken);
    sendAccessToken(req, res, accesstoken)

  } catch (error) {
    res.send(error)
  }
})

// 3. Logout a User
// underscore ignores the parameter when it's not used
app.post('/logout', async (_req, res) => {
  // path /refresh_token is on number 5 step
  res.clearCookie('refreshtoken', { path: '/refresh_token' })
  res.send('Logged out successfully')
})

// 4. Protected Route
app.post('/protected', async (req, res) => {
  try {
    const userId = isAuth(req)
    // if user is authenticated, send protected data as a response
    if (userId !== null) {
      res.send({
        data: 'This is a protected data'
      })
    }
  } catch (error) {
    res.status(400).send(error)
  }
})

// 5. Get a new access token with a refresh token
app.post('/refresh_token', (req, res) => {
  const token = req.cookies.refreshtoken
  // If we don't have a token in our request
  if (!token) return res.send('You got no tokens man!')
  // If token is not null, verify first!
  let payload = null
  try {
    payload = verify(token, process.env.REFRESH_TOKEN_SECRET)
  } catch (error) {
    return res.send('Youre not getting access token :P')
  }
  // If token is verified/valid, check if user exist
  const user = fakeDB.find(user => user.id === payload.userId
  )
  if (!user) return res.send('User doesnt exist, NO TOKENS :P')
  // if user exist, check if refresh token exist on user
  if (user.refreshtoken !== token) {
    return res.send('Still no TOKENS! :P')
  }
  // FINALLY, if token exist, create new Refresh and Access Tokens
  const accesstoken = createAccessToken(user.id)
  const refreshtoken = createRefreshToken(user.id)
  user.refreshtoken = refreshtoken
  // All good to go, send new refresh and access token
  sendRefreshToken(res, refreshtoken)
  return res.send({ accesstoken })
})

app.listen(process.env.PORT, () => {
  console.log(`Server is listening on port ${process.env.PORT}`)
})