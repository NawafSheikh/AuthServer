require('dotenv').config()

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const port = 3000

app.use(express.json())

users = []

app.get('/', (req, res) => {
  res.send('Hello World!')
})

app.get('/users/info', AuthToken, (req, res) => {
  user = users.filter(user => user.name === req.user.name)

  res.json()
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
      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN)
      res.json(accessToken)
    } else {
      res.send('Password Wrong')
    }
  } catch {
    res.status(500).send()
  }
})

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
