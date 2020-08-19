require('dotenv').config()

const passport = require("passport");
const strategy = require("passport-facebook");
const express = require('express')
var cors = require('cors');
const app = express()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose')
const Account = require('./models/account')
const Data = require('./models/data')
const port = 3000
const FacebookStrategy = strategy.Strategy;

fbuser = null
refTokenList = []

mongoose.connect('mongodb://localhost/accounts', { useNewUrlParser: true, useUnifiedTopology: true }, () => {
  console.log("Successful connection")
}).catch(err => {
  console.log(err)
})

app.use(passport.initialize());

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["id", "name"]
    },
    function(accessToken, refreshToken, profile, done) {
      const { id, first_name, last_name } = profile._json;
      fbuser = {id: id, name: first_name + " " + last_name}
      done(null, profile)

    }
  )
);

app.use(express.json())
app.use(cors())
/*app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
  res.header("Access-Control-Allow-Methods: GET, POST, PATCH, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
  next();
});
*/

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: "http://localhost:3001/",
    failureRedirect: "/fail"
  })
);

app.get("/fail", (req, res) => {
  res.send("Failed attempt");
});

app.get("/users/data", AuthToken, async (req, res) => {
  try{
    const users = await Account.find({name: req.user.name})
    const user = users[0]
    const data = await Data.find({accountId: user._id})
    res.json(data)
  } catch (err) {
    res.status(500).send(err)
  }
})

app.post("/users/data", AuthToken, async (req, res) => {
  try{
    const users = await Account.find({name: req.user.name})
    const user = users[0]
    const newData = new Data({
    accountId: user._id,
    class: req.body.class,
    subject: req.body.subject,
    marks: req.body.marks})
    await newData.save();
    res.sendStatus(200);
  } catch (err) {
    res.status(500).send(err)
  }
})

app.patch("/users/data", AuthToken, async (req, res) => {
  try{
    const users = await Account.find({name: req.user.name})
    const user = users[0]
    await Data.updateOne({accountId: user._id, _id: req.body.id}, {$set: {
      class: req.body.class,
      subject: req.body.subject,
      marks: req.body.marks
    }})
    res.sendStatus(200)
  }
  catch (err) {
    res.status(500).send(err)
  }
})

app.delete("/users/data/:id", AuthToken, async (req, res) => {
  try {
    const users = await Account.find({name: req.user.name})
    const user = users[0]
    await Data.deleteMany({accountId: user._id, _id: req.params.id})
    res.status(200).send()
  }
  catch (err) {
    res.status(500).send(err)
  }
})

app.get('/', async (req, res) => {
  res.send("Hello")
})

app.get('/users/check', AuthToken, (req, res) => {
  res.sendStatus(200)
})

app.get('/users/info', AuthToken, async (req, res) => {
  if (fbuser == null)
  {
    try{
      const users = await Account.find({name: req.user.name})
      res.json({name: users[0].name, password: users[0].password})
    } catch {
      res.status(500).send()
    }
  }
  else
  {
    res.json({name: fbuser.name})
  }
})

app.post('/users/create', async (req, res) => {
  try {
    const users = await Account.find({name: req.body.name})
    if(users[0] == null)
    {
      const hashpswd = await bcrypt.hash(req.body.password, 10);
      const user = new Account({
        name: req.body.name,
        password: hashpswd
      })
      const savedUser = await user.save()
      res.status(201).send();
    }
    else{
      res.status(500).send()
    }
  }
  catch{
    res.status(500).send();
  }
})

app.post('/users/login', async (req, res) =>
{
  try {
    const users = await Account.find({name: req.body.name})
    const user = users[0]
    if (user == null)
    {
      res.status(400).send('Cannot find user')
    }
    if(await bcrypt.compare(req.body.password, user.password)){
      const accessToken = GenAccessToken({name: user.name, password: user.password})
      const refToken = jwt.sign({name: user.name, password: user.password}, process.env.REFRESH_TOKEN)
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
  return jwt.sign(user, process.env.ACCESS_TOKEN, {expiresIn:'60s'})
}

function AuthToken (req, res, next)
{ if (fbuser == null)
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
  else
  {
    next()
  }
}

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`)
})
