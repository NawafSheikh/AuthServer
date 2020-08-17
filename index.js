require('dotenv').config()

const express = require('express')
var cors = require('cors');
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const port = 3000

app.use(express.json())
app.use(cors())
/*app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
  res.header("Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});
*/
users = []
refTokenList = []

app.get('/', (req, res) => {
  res.json('Hello')
})

app.get('/users/check', AuthToken, (req, res) => {
  users.filter(user => user.name === req.user.name)
  res.sendStatus(200)
})

app.get('/users/info', AuthToken, (req, res) => {
  res.json(users.filter(user => user.name === req.user.name))
})

app.post('/users/create', async (req, res) => {
  try {
    const hashpswd = await bcrypt.hash(req.body.password, 10);
    users.push({
      name: req.body.name,
      password: hashpswd
    });
    res.status(201).send();
  }
  catch{
    res.status(500).send();
  }
})

app.post('/users/login', async (req, res) =>
{
  const user = users.find(user => user.name === req.body.name)
  if (user == null)
  {
    res.status(400).send('Cannot find user')
  }
  try {
    if(await bcrypt.compare(req.body.password, user.password)){
      const accessToken = GenAccessToken(user)
      const refToken = jwt.sign(user, process.env.REFRESH_TOKEN)
      refTokenList.push(refToken)
      res.json({accessToken: accessToken, refToken: refToken})
    } else {
      res.send('Password Wrong')
    }
  } catch {
    res.status(500).send()
  }
})

app.post('/users/token', (req, res) => {
  const refToken = req.body.token
  if(refToken == null) return res.sendStatus(401)
  if(!refTokenList.includes(refToken)) return res.sendStatus(403)
  jwt.verify(refToken, process.env.REFRESH_TOKEN, (err, user) => {
    if(err) return res.sendStatus(403)
    const accessToken = GenAccessToken({name: user.name, password: user.password})
    res.json({accessToken: accessToken})
  })
})

function GenAccessToken (user)
{
  return jwt.sign(user, process.env.ACCESS_TOKEN, {expiresIn:'30s'})
}

function AuthToken (req, res, next)
{
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (token == null) return res.sendStatus(401)
  jwt.verify(token, process.env.ACCESS_TOKEN, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`)
})
