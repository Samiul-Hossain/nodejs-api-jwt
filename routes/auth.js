const router = require('express').Router()
const User = require('../model/User')
const { loginValidation, registerValidation } = require('../validation')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const auth = require('./verifyToken')

dotenv.config()

router.post('/register', async (req, res) => {
  const { error } = registerValidation(req.body)
  if (error) return res.status(400).send(error.details[0].message)

  const emailExist = await User.findOne({ email: req.body.email })
  if (emailExist) return res.status(400).send('Email already exists')

  const salt = await bcrypt.genSalt(10)
  const hashPassword = await bcrypt.hash(req.body.password, salt)

  const user = new User({
    name: req.body.name,
    email: req.body.email,
    password: hashPassword,
  })

  try {
    const savedUser = await user.save()
    const token = jwt.sign({ _id: user._id }, process.env.SECRET_KEY)
    res.header('auth', token).send({ token: token })
  } catch (err) {
    res.status(400).send(err)
  }
})

router.post('/login', async (req, res) => {
  const { error } = loginValidation(req.body)
  if (error) return res.status(400).send(error.details[0].message)

  const user = await User.findOne({ email: req.body.email })
  if (!user) return res.status(400).send('Email does not exist')

  const validPass = await bcrypt.compare(req.body.password, user.password)
  if (!validPass) return res.status(400).send('Invalid Password')

  const token = jwt.sign({ _id: user._id }, process.env.SECRET_KEY, {
    expiresIn: '1h',
  })
  res.header('token', token).send({ token: token })
})

router.get('/dashboard', auth, async (req, res) => {
  res.json({ posts: 'posts' })
})

module.exports = router
